//! Contabo DNS and firewall sync binary.
//!
//! Loads config from the environment, starts logging, serves a loopback
//! `GET /health` route, then runs DNS and firewall updates on a schedule.
//! Hover any `///` documented name in the editor to see the same rustdoc text
//! rust-analyzer shows (JSDoc-style).

mod config;
mod contabo;
mod dns;
mod error;
mod firewall;
mod health;
mod ip;
mod logsetup;
mod retry;
mod sync;

#[cfg(test)]
mod test_http;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Process entry: `health` probes the loopback route, otherwise start the sync loop.
///
/// Returns exit code 2 when required env is missing or invalid.
fn main() -> ExitCode {
    dispatch(health::mode(std::env::args_os()))
}

/// Runs the healthcheck probe or the sync process.
fn dispatch(mode: health::Mode) -> ExitCode {
    match mode {
        health::Mode::Probe => health::run_probe(),
        health::Mode::Serve => match config::Config::from_env() {
            Ok(cfg) => start(cfg, retry::backoff),
            Err(err) => config_error(&err),
        },
    }
}

/// Prints a startup failure to stderr.
fn console_error(prefix: &str, err: &error::Error) {
    eprintln!("{prefix}: {err}");
}

/// Prints a config failure to stderr and returns exit code 2.
fn config_error(err: &error::Error) -> ExitCode {
    console_error("config error", err);
    ExitCode::from(2)
}

/// Starts logging, then builds the HTTP client and runs the schedule.
///
/// Returns exit code 2 if the log directory cannot be created or written.
fn start(cfg: config::Config, delay: fn(u32) -> Duration) -> ExitCode {
    let _logger = match logsetup::init(&cfg.log) {
        Ok(handle) => handle,
        Err(err) => {
            console_error("log error", &err);
            return ExitCode::from(2);
        }
    };
    log::info!(
        "contabo-ddns run_on_start={} interval_seconds={} dry_run={} dns={} firewall={}",
        cfg.run_on_start,
        cfg.interval_seconds,
        cfg.dry_run,
        cfg.dns.is_some(),
        cfg.firewall.is_some()
    );

    after_log_init(cfg, delay)
}

/// Serves the loopback healthcheck, then builds the blocking HTTP client.
///
/// Returns exit code 1 when the listener or the client cannot be constructed.
fn after_log_init(cfg: config::Config, delay: fn(u32) -> Duration) -> ExitCode {
    let server = match health::serve_configured() {
        Ok(server) => server,
        Err(err) => {
            log::error!("healthcheck: {err}");
            return ExitCode::from(1);
        }
    };
    log::info!("healthcheck listening on {}", server.addr());
    let http = contabo::ReqwestHttp::new(cfg.tls_roots);
    let code = after_client(cfg, http, delay);
    drop(server);
    code
}

/// Continues with a built client, or exits 1 when construction failed.
fn after_client(
    cfg: config::Config,
    http: Result<contabo::ReqwestHttp, error::Error>,
    delay: fn(u32) -> Duration,
) -> ExitCode {
    match http {
        Ok(http) => run_after_http(cfg, &http, delay),
        Err(err) => after_http_client_error(&err),
    }
}

/// Logs an HTTP-client construction failure and returns exit code 1.
fn after_http_client_error(err: &error::Error) -> ExitCode {
    log::error!("http client: {err}");
    ExitCode::from(1)
}

/// Runs the sync schedule with the OS DNS resolver and an interruptible sleep.
fn run_after_http(
    cfg: config::Config,
    http: &dyn contabo::Http,
    delay: fn(u32) -> Duration,
) -> ExitCode {
    let resolver = ip::SystemResolver;
    let shutdown = install_shutdown();
    let client = contabo::ContaboClient::from_config(http, &cfg)
        .with_shutdown(&shutdown)
        .with_delay(delay);
    let firewall_state = crate::firewall::FirewallState::new();
    let mut cycle = || cycle_failed(&cfg, &client, &resolver, &firewall_state);
    let mut sleep = retry::interruptible_sleep;
    execute(&cfg, &mut cycle, &mut sleep, None, &shutdown)
}

/// Registers SIGINT and, on Unix, SIGTERM so `docker stop` ends the sleep.
fn install_shutdown() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        note_signal(
            signal_hook::consts::SIGTERM,
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&flag)),
        );
        note_signal(
            signal_hook::consts::SIGINT,
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag)),
        );
    }
    #[cfg(windows)]
    {
        note_signal(
            signal_hook::consts::SIGINT,
            signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag)),
        );
    }
    flag
}

/// Logs a failed signal registration. The process still runs, but stop may not interrupt sleep.
fn note_signal(signal: i32, result: Result<signal_hook::SigId, std::io::Error>) {
    if let Err(err) = result {
        log::warn!("signal {signal} handler: {err}");
    }
}

/// Runs sync cycles according to `run_on_start` and `interval_seconds`.
///
/// `cycle` returns true when a cycle failed. `sleep` is injected so tests can
/// skip a real wait. `max_iterations` stops the loop after N sleeps (tests).
/// A set `shutdown` flag exits 0 between cycles.
///
/// One-shot (`interval_seconds == 0`) returns 1 if the first cycle failed.
fn execute(
    cfg: &config::Config,
    cycle: &mut dyn FnMut() -> bool,
    sleep: &mut dyn FnMut(Duration, &AtomicBool),
    max_iterations: Option<u32>,
    shutdown: &AtomicBool,
) -> ExitCode {
    if cfg.run_on_start && cycle() && cfg.interval_seconds == 0 {
        return ExitCode::from(1);
    }
    if cfg.interval_seconds == 0 {
        return ExitCode::SUCCESS;
    }
    let mut finished = 0u32;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::info!("shutdown");
            return ExitCode::SUCCESS;
        }
        log::info!("sleeping {}s", cfg.interval_seconds);
        sleep(Duration::from_secs(cfg.interval_seconds), shutdown);
        if shutdown.load(Ordering::Relaxed) {
            log::info!("shutdown");
            return ExitCode::SUCCESS;
        }
        let _ = cycle();
        finished += 1;
        if max_iterations.is_some_and(|limit| finished >= limit) {
            return ExitCode::SUCCESS;
        }
    }
}

/// Runs one DNS+firewall cycle and returns true when it failed.
fn cycle_failed(
    cfg: &config::Config,
    client: &contabo::ContaboClient<'_>,
    resolver: &dyn ip::Resolver,
    firewall_state: &crate::firewall::FirewallState,
) -> bool {
    match sync::run_cycle(cfg, client, resolver, firewall_state) {
        Ok(()) => false,
        Err(err) => {
            log::error!("sync failed: {err}");
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        after_client, after_http_client_error, after_log_init, config_error, cycle_failed,
        dispatch, execute, run_after_http, start,
    };
    use crate::contabo::{ContaboClient, ReqwestHttp};
    use crate::error::Error;
    use crate::retry::interruptible_sleep;
    use crate::test_http::closing_endpoint;
    use std::process::ExitCode;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    fn running() -> AtomicBool {
        AtomicBool::new(false)
    }

    /// A `not(test)` cfg attribute is deleted from the test crate, so rust-analyzer marks it inactive.
    /// `cfg!(test)` keeps both branches in the source the editor checks.
    #[test]
    fn cfg_not_test_attribute_is_forbidden() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let hits = cfg_attribute_hits(&root);
        assert!(cfg_violation_message(&hits).is_none());
    }

    #[test]
    fn cfg_scanner_reports_a_nested_attribute() {
        let dir = crate::logsetup::unique_temp("contabo-ddns-cfg");
        let nested = dir.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(dir.join("note.txt"), "ignore").unwrap();
        std::fs::write(dir.join("noext"), "ignore").unwrap();
        let attr = ["#[", "cfg(not(test))]"].concat();
        let spaced = ["# [ cfg", " ( not ( test ) ) ]"].concat();
        std::fs::write(nested.join("bad.rs"), format!("fn x() {{ {attr} }}\n")).unwrap();
        std::fs::write(nested.join("spaced.rs"), spaced).unwrap();
        std::fs::write(nested.join("ok.rs"), "fn y() {}\n").unwrap();
        let hits = cfg_attribute_hits(&dir);
        let message = cfg_violation_message(&hits).unwrap();
        assert!(message.contains("bad.rs"));
        assert!(message.contains("spaced.rs"));
        assert!(!message.contains("ok.rs"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn cfg_attribute_hits(root: &std::path::Path) -> Vec<String> {
        let needle = ["#[", "cfg(not(test))]"].concat();
        let mut pending = vec![root.to_path_buf()];
        let mut hits = Vec::new();
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                for (index, line) in text.lines().enumerate() {
                    let compact: String = line.chars().filter(|ch| !ch.is_whitespace()).collect();
                    if compact.contains(&needle) {
                        hits.push(format!("{}:{}", path.display(), index + 1));
                    }
                }
            }
        }
        hits
    }

    fn cfg_violation_message(hits: &[String]) -> Option<String> {
        if hits.is_empty() {
            None
        } else {
            Some(format!(
                "use if cfg!(test) instead of a not(test) cfg attribute:\n{}",
                hits.join("\n")
            ))
        }
    }

    /// Minimal valid config used by schedule and startup tests.
    fn sample(interval: &str, run_on_start: &str) -> crate::config::Config {
        crate::config::Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com"),
            ("INTERVAL_SECONDS", interval),
            ("RUN_ON_START", run_on_start),
            ("LOG_DIR", ""),
            ("CONTABO_API_BASE", "https://api.example.test"),
            ("CONTABO_AUTH_URL", "https://auth.example.test/token"),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
            ("IP_ECHO_TIMEOUT_SECONDS", "1"),
        ])
        .unwrap()
    }

    /// Points every URL in `cfg` at a local endpoint that drops connections.
    fn against_closing_endpoint(mut cfg: crate::config::Config) -> crate::config::Config {
        let base = closing_endpoint();
        cfg.auth_url = format!("{base}/token");
        cfg.ip_echo_urls = vec![format!("{base}/plain")];
        cfg.api_base = base;
        cfg
    }

    /// Config parse failures exit 2.
    #[test]
    fn reports_config_errors() {
        let code = config_error(&Error::new("CONTABO_CLIENT_ID is required"));
        assert_eq!(code, ExitCode::from(2));
    }

    /// One-shot, idle, and bounded interval loops without a real sleep.
    #[test]
    fn one_shot_and_bounded_loop_follow_the_schedule() {
        let cfg = sample("0", "true");
        let mut cycle = quiet_cycle;
        let mut sleep = skip_sleep;
        assert_eq!(
            execute(&cfg, &mut cycle, &mut sleep, None, &running()),
            ExitCode::SUCCESS
        );
        let mut failing = || true;
        assert_eq!(
            execute(&cfg, &mut failing, &mut sleep, None, &running()),
            ExitCode::from(1)
        );

        let mut idle = sample("0", "true");
        idle.run_on_start = false;
        idle.interval_seconds = 0;
        let mut idle_cycle = || true;
        assert_eq!(
            execute(&idle, &mut idle_cycle, &mut sleep, None, &running()),
            ExitCode::SUCCESS
        );

        let looping = sample("30", "false");
        let mut cycles = 0;
        let mut looping_cycle = || {
            cycles += 1;
            false
        };
        assert_eq!(
            execute(
                &looping,
                &mut looping_cycle,
                &mut sleep,
                Some(1),
                &running()
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(cycles, 1);
    }

    /// Probe mode does not require Contabo credentials. A bad bind exits 1.
    #[test]
    fn dispatch_probes_and_rejects_a_public_bind() {
        assert_eq!(dispatch(crate::health::Mode::Probe), ExitCode::from(1));
        let _guard = crate::health::override_bind(Some("0.0.0.0:8080".into()));
        assert_eq!(
            after_log_init(sample("0", "true"), crate::retry::immediate),
            ExitCode::from(1)
        );
    }

    /// `main` exits 2 when thread-local test env has no credentials.
    #[test]
    fn main_exits_on_missing_config() {
        crate::config::with_test_env([] as [(&str, &str); 0], || {
            assert_eq!(super::main(), ExitCode::from(2));
        });
    }

    /// Scripted DNS cycle reports success through `cycle_failed`.
    #[test]
    fn cycle_success_reports_no_failure() {
        use crate::ip::MapResolver;
        use crate::sync::run_cycle;
        use std::sync::Mutex;

        let cfg = sample("0", "true");
        let http = crate::test_http::DnsCycleOk {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        let client = ContaboClient::from_config(&http, &cfg).with_delay(crate::retry::immediate);
        run_cycle(
            &cfg,
            &client,
            &resolver,
            &crate::firewall::FirewallState::new(),
        )
        .unwrap();
        assert!(!cycle_failed(
            &cfg,
            &client,
            &resolver,
            &crate::firewall::FirewallState::new()
        ));
        let broken = crate::test_http::Unscripted {
            calls: Mutex::new(Vec::new()),
        };
        assert!(cycle_failed(
            &cfg,
            &ContaboClient::from_config(&broken, &cfg).with_delay(crate::retry::immediate),
            &resolver,
            &crate::firewall::FirewallState::new()
        ));
    }

    /// Interval loop stops after `max_iterations` sleeps.
    #[test]
    fn bounded_loop_continues_until_limit() {
        let cfg = sample("60", "false");
        let mut cycles = 0;
        let mut cycle = || {
            cycles += 1;
            false
        };
        let mut sleep = skip_sleep;
        assert_eq!(
            execute(&cfg, &mut cycle, &mut sleep, Some(2), &running()),
            ExitCode::SUCCESS
        );
        assert_eq!(cycles, 2);
    }

    /// A set shutdown flag leaves the interval loop without running another cycle.
    #[test]
    fn shutdown_flag_stops_the_interval_loop() {
        let cfg = sample("30", "false");
        let stop = AtomicBool::new(true);
        let mut cycle = quiet_cycle;
        let mut sleep = interruptible_sleep;
        assert_eq!(
            execute(&cfg, &mut cycle, &mut sleep, None, &stop),
            ExitCode::SUCCESS
        );
        let during = AtomicBool::new(false);
        let mut arm = |_, flag: &AtomicBool| {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        };
        assert_eq!(
            execute(&cfg, &mut cycle, &mut arm, None, &during),
            ExitCode::SUCCESS
        );
    }

    fn quiet_cycle() -> bool {
        false
    }

    fn skip_sleep(_delay: Duration, _shutdown: &AtomicBool) {}

    /// Bad log dir exits 2; a client build error or a failed live cycle exits 1.
    #[test]
    fn startup_from_env_and_start() {
        let probe = crate::logsetup::unique_temp("contabo-ddns-logfile");
        let _ = std::fs::write(&probe, b"x");
        let mut bad_log = sample("0", "true");
        bad_log.log.dir = Some(probe.clone());
        bad_log.log.to_stdout = false;
        assert_eq!(start(bad_log, crate::retry::immediate), ExitCode::from(2));
        let _ = std::fs::remove_file(probe);

        assert_eq!(
            after_client(
                sample("0", "true"),
                Err(Error::new("build http client")),
                crate::retry::immediate,
            ),
            ExitCode::from(1)
        );
        assert_eq!(
            after_client(
                against_closing_endpoint(sample("0", "true")),
                ReqwestHttp::new(crate::config::TlsRoots::Both),
                crate::retry::immediate,
            ),
            ExitCode::from(1)
        );
        assert_eq!(
            after_log_init(
                against_closing_endpoint(sample("0", "true")),
                crate::retry::immediate,
            ),
            ExitCode::from(1)
        );
    }

    /// A failed signal registration is logged and does not stop startup.
    #[test]
    fn signal_registration_failure_is_logged() {
        super::note_signal(15, Err(std::io::Error::other("denied")));
    }

    /// HTTP-client helper maps any error to exit code 1.
    #[test]
    fn after_http_client_error_exits_one() {
        let code = after_http_client_error(&Error::new("build http client: injected"));
        assert_eq!(code, ExitCode::from(1));
    }

    /// `main` with thread-local env runs one cycle against a local endpoint and exits 1.
    #[test]
    fn main_with_minimal_env() {
        crate::logsetup::discard_output();
        let base = closing_endpoint();
        let pairs = [
            ("CONTABO_CLIENT_ID", "id".to_string()),
            ("CONTABO_CLIENT_SECRET", "secret".into()),
            ("CONTABO_API_USER", "user@example.com".into()),
            ("CONTABO_API_PASSWORD", "pw".into()),
            ("DNS_RECORDS", "home.example.com".into()),
            ("INTERVAL_SECONDS", "0".into()),
            ("LOG_DIR", "".into()),
            ("CONTABO_API_BASE", base.clone()),
            ("CONTABO_AUTH_URL", format!("{base}/token")),
            ("IP_ECHO_URL", format!("{base}/plain")),
            ("IP_ECHO_TIMEOUT_SECONDS", "1".into()),
        ];
        crate::config::with_test_env(pairs.clone(), || {
            let cfg = crate::config::Config::from_env().unwrap();
            assert_eq!(start(cfg, crate::retry::immediate), ExitCode::from(1));
        });
        let probe = crate::logsetup::unique_temp("contabo-ddns-main-log");
        let _ = std::fs::write(&probe, b"x");
        let mut blocked = pairs;
        blocked[6].1 = probe.display().to_string();
        crate::config::with_test_env(blocked, || {
            assert_eq!(super::main(), ExitCode::from(2));
        });
        let _ = std::fs::remove_file(&probe);
        let dup = crate::config::LogConfig {
            level: "info".into(),
            dir: None,
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 10,
            rotate_keep: 5,
            to_stdout: true,
        };
        assert!(crate::logsetup::init(&dup).is_ok());
    }

    /// `run_after_http` drives a scripted cycle with no OS sleep or network.
    #[test]
    fn run_after_http_completes_scripted_cycle() {
        use std::sync::Mutex;
        let cfg = sample("0", "true");
        let http = crate::test_http::DnsCycleOk {
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            run_after_http(cfg, &http, crate::retry::immediate),
            ExitCode::SUCCESS
        );
    }

    /// `RUN_ON_START` invokes the cycle callback once on a one-shot schedule.
    #[test]
    fn execute_runs_cycle_when_run_on_start_is_set() {
        let cfg = sample("0", "true");
        let mut called = false;
        let mut cycle = || {
            called = true;
            false
        };
        let mut sleep = interruptible_sleep;
        assert_eq!(
            execute(&cfg, &mut cycle, &mut sleep, None, &running()),
            ExitCode::SUCCESS
        );
        assert!(called);
    }
}
