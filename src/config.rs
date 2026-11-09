//! Environment-variable config for Contabo auth, DNS targets, firewall rules, and logging.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::error::Error;

const DEFAULT_API_BASE: &str = "https://api.contabo.com";
const DEFAULT_AUTH_URL: &str =
    "https://auth.contabo.com/auth/realms/contabo/protocol/openid-connect/token";
const DEFAULT_IP_ECHO_URL: &str = "https://ipecho.net/plain";
const DEFAULT_LOG_DIR: &str = "/var/log/contabo-ddns";
const DEFAULT_IP_ECHO_TIMEOUT_SECS: u64 = 10;
const DEFAULT_INTERVAL_SECS: u64 = 300;
/// Shortest loop interval, so a misconfiguration cannot hammer the Contabo API.
const MIN_INTERVAL_SECS: u64 = 30;
/// Upper bound on retained log files; also keeps the `usize` cast lossless.
const MAX_ROTATE_KEEP: u64 = 10_000;

/// File and stdout logging settings parsed from `LOG_*` env vars.
#[derive(Debug)]
pub struct LogConfig {
    pub level: String,
    pub dir: Option<PathBuf>,
    pub file: String,
    pub rotate_size_mb: u64,
    pub rotate_keep: usize,
    pub to_stdout: bool,
}

/// One DNS name to keep in sync: an exact FQDN or `*.parent` wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsTarget {
    Exact(String),
    Wildcard(String),
}

/// DNS sync settings: records, optional TTL, and create-missing.
#[derive(Debug)]
pub struct DnsConfig {
    pub records: Vec<DnsTarget>,
    pub ttl: Option<u64>,
    pub create_missing: bool,
}

/// One named inbound rule and the sources that should replace its address lists.
#[derive(Debug)]
pub struct FirewallRuleConfig {
    pub display_name: String,
    pub sources: Vec<String>,
}

/// Firewall lookup (id or name) plus the rules whose sources are rewritten.
#[derive(Debug)]
pub struct FirewallConfig {
    pub id: Option<String>,
    pub name: Option<String>,
    pub rules: Vec<FirewallRuleConfig>,
}

/// Which TLS root stores the HTTP client loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsRoots {
    /// Embedded Mozilla roots and the OS certificate bundle.
    Both,
    /// Embedded Mozilla roots only.
    Webpki,
    /// OS certificate bundle only (`ca-certificates` in the image).
    Native,
}

/// Runtime config: Contabo credentials, targets, schedule, and logging.
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub api_user: String,
    pub api_password: String,
    pub api_base: String,
    pub auth_url: String,
    pub ip_echo_urls: Vec<String>,
    pub ipv6: bool,
    pub ip_echo_timeout: Duration,
    pub dns: Option<DnsConfig>,
    pub firewall: Option<FirewallConfig>,
    pub run_on_start: bool,
    pub interval_seconds: u64,
    pub dry_run: bool,
    pub tls_roots: TlsRoots,
    pub log: LogConfig,
}

impl fmt::Debug for Config {
    /// Formats config with secrets replaced by `<redacted>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .field("api_user", &self.api_user)
            .field("api_password", &"<redacted>")
            .field("api_base", &self.api_base)
            .field("auth_url", &self.auth_url)
            .field("ip_echo_urls", &self.ip_echo_urls)
            .field("ipv6", &self.ipv6)
            .field("dns", &self.dns)
            .field("firewall", &self.firewall)
            .field("run_on_start", &self.run_on_start)
            .field("interval_seconds", &self.interval_seconds)
            .field("dry_run", &self.dry_run)
            .field("tls_roots", &self.tls_roots)
            .field("log", &self.log)
            .finish()
    }
}

impl Config {
    /// Loads config from the process environment.
    ///
    /// Tests can substitute a thread-local map via `with_test_env` so parallel
    /// cases do not rewrite the process environment.
    pub fn from_env() -> Result<Self, Error> {
        #[cfg(test)]
        if let Some(pairs) = TEST_ENV.with(|slot| slot.borrow().clone()) {
            return Self::from_pairs(pairs);
        }
        Self::from_pairs(std::env::vars())
    }

    /// Parses config from an iterator of key/value pairs (tests and `from_env`).
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map = pairs
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        Self::from_map(&map)
    }

    /// Validates required secrets, HTTPS URLs, DNS/firewall targets, and schedule.
    fn from_map(map: &HashMap<String, String>) -> Result<Self, Error> {
        let client_id = required(map, "CONTABO_CLIENT_ID")?.trim().to_string();
        let client_secret = required(map, "CONTABO_CLIENT_SECRET")?.to_string();
        let api_user = required(map, "CONTABO_API_USER")?.trim().to_string();
        let api_password = required(map, "CONTABO_API_PASSWORD")?.to_string();
        let api_base = optional(map, "CONTABO_API_BASE")
            .unwrap_or(DEFAULT_API_BASE)
            .trim()
            .trim_end_matches('/')
            .to_string();
        let auth_url = optional(map, "CONTABO_AUTH_URL")
            .unwrap_or(DEFAULT_AUTH_URL)
            .trim()
            .to_string();
        let ip_echo_urls =
            parse_ip_echo_urls(optional(map, "IP_ECHO_URL").unwrap_or(DEFAULT_IP_ECHO_URL))?;
        let ipv6 = match optional(map, "IPV6") {
            Some(value) => parse_bool("IPV6", value)?,
            None => false,
        };
        require_https("CONTABO_API_BASE", &api_base)?;
        require_https("CONTABO_AUTH_URL", &auth_url)?;

        let timeout_secs = match optional(map, "IP_ECHO_TIMEOUT_SECONDS") {
            Some(value) => parse_u64("IP_ECHO_TIMEOUT_SECONDS", value)?,
            None => DEFAULT_IP_ECHO_TIMEOUT_SECS,
        };
        if timeout_secs == 0 {
            return Err(Error::new("IP_ECHO_TIMEOUT_SECONDS must be >= 1"));
        }

        let dns = parse_dns(map)?;
        let firewall = parse_firewall(map)?;
        if dns.is_none() && firewall.is_none() {
            return Err(Error::new(
                "set DNS_RECORDS or FIREWALL_RULES, or enable one of them explicitly",
            ));
        }
        if !ipv6
            && firewall.as_ref().is_some_and(|firewall| {
                firewall.rules.iter().any(|rule| {
                    rule.sources
                        .iter()
                        .any(|source| source.trim() == "current6")
                })
            })
        {
            return Err(Error::new("current6 requires IPV6=true"));
        }

        let run_on_start = match optional(map, "RUN_ON_START") {
            Some(value) => parse_bool("RUN_ON_START", value)?,
            None => true,
        };
        let interval_seconds = match optional(map, "INTERVAL_SECONDS") {
            Some(value) => parse_u64("INTERVAL_SECONDS", value)?,
            None => DEFAULT_INTERVAL_SECS,
        };
        if interval_seconds != 0 && interval_seconds < MIN_INTERVAL_SECS {
            return Err(Error::new(format!(
                "INTERVAL_SECONDS must be 0 or >= {MIN_INTERVAL_SECS}"
            )));
        }
        if !run_on_start && interval_seconds == 0 {
            return Err(Error::new(
                "RUN_ON_START=false and INTERVAL_SECONDS=0 would never sync",
            ));
        }

        let dry_run = match optional(map, "DRY_RUN") {
            Some(value) => parse_bool("DRY_RUN", value)?,
            None => false,
        };
        let tls_roots = parse_tls_roots(optional(map, "TLS_ROOTS").unwrap_or("both"))?;

        Ok(Self {
            client_id,
            client_secret,
            api_user,
            api_password,
            api_base,
            auth_url,
            ip_echo_urls,
            ipv6,
            ip_echo_timeout: Duration::from_secs(timeout_secs),
            dns,
            firewall,
            run_on_start,
            interval_seconds,
            dry_run,
            tls_roots,
            log: parse_log(map)?,
        })
    }
}

/// Reads log level, directory, file name, rotation, and stdout duplication.
fn parse_log(map: &HashMap<String, String>) -> Result<LogConfig, Error> {
    let level = optional(map, "LOG_LEVEL")
        .unwrap_or("info")
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        level.as_str(),
        "error" | "warn" | "info" | "debug" | "trace"
    ) {
        return Err(Error::new(
            "LOG_LEVEL must be error, warn, info, debug, or trace",
        ));
    }
    let dir = match map.get("LOG_DIR").map(|value| value.trim()) {
        None => Some(PathBuf::from(DEFAULT_LOG_DIR)),
        Some("") => None,
        Some(path) => Some(PathBuf::from(path)),
    };
    let file = optional(map, "LOG_FILE")
        .unwrap_or("contabo-ddns.log")
        .trim()
        .to_string();
    if file.is_empty() || file.contains('/') || file.contains('\\') {
        return Err(Error::new("LOG_FILE must be a file name"));
    }
    let rotate_size_mb = match optional(map, "LOG_ROTATE_SIZE_MB") {
        Some(value) => parse_u64("LOG_ROTATE_SIZE_MB", value)?,
        None => 10,
    };
    if rotate_size_mb == 0 {
        return Err(Error::new("LOG_ROTATE_SIZE_MB must be >= 1"));
    }
    let rotate_keep = match optional(map, "LOG_ROTATE_KEEP") {
        Some(value) => parse_u64("LOG_ROTATE_KEEP", value)?,
        None => 5,
    };
    if rotate_keep == 0 || rotate_keep > MAX_ROTATE_KEEP {
        return Err(Error::new(format!(
            "LOG_ROTATE_KEEP must be between 1 and {MAX_ROTATE_KEEP}"
        )));
    }
    let to_stdout = match optional(map, "LOG_TO_STDOUT") {
        Some(value) => parse_bool("LOG_TO_STDOUT", value)?,
        None => true,
    };
    if dir.is_none() && !to_stdout {
        return Err(Error::new("LOG_TO_STDOUT=false requires LOG_DIR"));
    }
    Ok(LogConfig {
        level,
        dir,
        file,
        rotate_size_mb,
        rotate_keep: rotate_keep as usize,
        to_stdout,
    })
}

/// Parses DNS records, TTL, and create-missing flag. `None` if disabled.
fn parse_dns(map: &HashMap<String, String>) -> Result<Option<DnsConfig>, Error> {
    let records_raw = optional(map, "DNS_RECORDS")
        .unwrap_or("")
        .trim()
        .to_string();
    let enabled = match optional(map, "DNS_ENABLED") {
        Some(value) => parse_bool("DNS_ENABLED", value)?,
        None => !records_raw.is_empty(),
    };
    if !enabled {
        return Ok(None);
    }
    if records_raw.is_empty() {
        return Err(Error::new("DNS_ENABLED=true requires DNS_RECORDS"));
    }
    let ttl = match optional(map, "DNS_TTL") {
        Some(value) if !value.trim().is_empty() => Some(parse_u64("DNS_TTL", value)?),
        _ => None,
    };
    if ttl == Some(0) {
        return Err(Error::new("DNS_TTL must be >= 1"));
    }
    let create_missing = match optional(map, "DNS_CREATE_MISSING") {
        Some(value) => parse_bool("DNS_CREATE_MISSING", value)?,
        None => false,
    };
    Ok(Some(DnsConfig {
        records: parse_targets(&records_raw)?,
        ttl,
        create_missing,
    }))
}

/// Splits a comma-separated `IP_ECHO_URL` list. Every entry must be https.
fn parse_ip_echo_urls(raw: &str) -> Result<Vec<String>, Error> {
    let urls: Vec<String> = raw
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect();
    if urls.is_empty() {
        return Err(Error::new("IP_ECHO_URL is empty"));
    }
    for url in &urls {
        require_https("IP_ECHO_URL", url)?;
    }
    Ok(urls)
}

/// Splits `DNS_RECORDS` into exact FQDNs and `*.parent` wildcards.
fn parse_targets(raw: &str) -> Result<Vec<DnsTarget>, Error> {
    let mut targets = Vec::new();
    for part in raw.split(',') {
        let name = part.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if let Some(parent) = name.strip_prefix("*.") {
            if parent.is_empty() || parent.contains('*') || parent.starts_with('.') {
                return Err(Error::new(format!("bad DNS wildcard: {name}")));
            }
            if !crate::ip::is_hostname(parent) {
                return Err(Error::new(format!("bad DNS name: {parent}")));
            }
            targets.push(DnsTarget::Wildcard(parent.to_string()));
        } else if name.contains('*') || !crate::ip::is_hostname(&name) {
            return Err(Error::new(format!("bad DNS name: {name}")));
        } else {
            targets.push(DnsTarget::Exact(name));
        }
    }
    if targets.is_empty() {
        return Err(Error::new("DNS_RECORDS is empty"));
    }
    Ok(targets)
}

#[derive(Deserialize)]
struct FirewallRuleFile {
    #[serde(rename = "displayName")]
    display_name: String,
    sources: Vec<String>,
}

/// Parses firewall JSON rules and exactly one of `FIREWALL_ID` / `FIREWALL_NAME`.
fn parse_firewall(map: &HashMap<String, String>) -> Result<Option<FirewallConfig>, Error> {
    let rules_raw = optional(map, "FIREWALL_RULES")
        .unwrap_or("")
        .trim()
        .to_string();
    let enabled = match optional(map, "FIREWALL_ENABLED") {
        Some(value) => parse_bool("FIREWALL_ENABLED", value)?,
        None => !rules_raw.is_empty(),
    };
    if !enabled {
        return Ok(None);
    }
    if rules_raw.is_empty() {
        return Err(Error::new("FIREWALL_ENABLED=true requires FIREWALL_RULES"));
    }
    let parsed: Vec<FirewallRuleFile> = serde_json::from_str(&rules_raw)
        .map_err(|err| Error::new(format!("FIREWALL_RULES is not valid JSON: {err}")))?;
    if parsed.is_empty() {
        return Err(Error::new("FIREWALL_RULES is empty"));
    }

    let mut order = Vec::new();
    let mut grouped: HashMap<String, (Vec<String>, HashSet<String>)> = HashMap::new();
    for rule in parsed {
        let display_name = rule.display_name.trim().to_string();
        if display_name.is_empty() {
            return Err(Error::new("firewall rule displayName is empty"));
        }
        if rule.sources.is_empty() {
            return Err(Error::new(format!(
                "firewall rule {display_name} has no sources"
            )));
        }
        let slot = grouped.entry(display_name.clone()).or_insert_with(|| {
            order.push(display_name.clone());
            (Vec::new(), HashSet::new())
        });
        for source in rule.sources {
            let source = source.trim().to_string();
            if source.is_empty() {
                return Err(Error::new(format!(
                    "firewall rule {display_name} has an empty source"
                )));
            }
            if !valid_firewall_source(&source) {
                return Err(Error::new(format!(
                    "firewall source {source} is not an IP address, CIDR, hostname, current, or current6"
                )));
            }
            if slot.1.insert(source.clone()) {
                slot.0.push(source);
            }
        }
    }
    let rules = order
        .into_iter()
        .map(|display_name| {
            let (sources, _) = grouped.remove(&display_name).unwrap_or_default();
            FirewallRuleConfig {
                display_name,
                sources,
            }
        })
        .collect();

    let id = optional(map, "FIREWALL_ID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let name = optional(map, "FIREWALL_NAME")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    match (&id, &name) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => {
            return Err(Error::new(
                "set exactly one of FIREWALL_ID or FIREWALL_NAME",
            ));
        }
    }
    Ok(Some(FirewallConfig { id, name, rules }))
}

/// `current`, `current6`, an IPv4 or IPv6 address or CIDR, or a hostname.
fn valid_firewall_source(source: &str) -> bool {
    source == "current"
        || source == "current6"
        || crate::ip::normalize_ipv4(source).is_ok()
        || crate::ip::normalize_ipv6(source).is_ok()
        || crate::ip::is_hostname(source)
}

/// `both`, `webpki`, or `native`.
fn parse_tls_roots(value: &str) -> Result<TlsRoots, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "both" => Ok(TlsRoots::Both),
        "webpki" => Ok(TlsRoots::Webpki),
        "native" => Ok(TlsRoots::Native),
        _ => Err(Error::new("TLS_ROOTS must be both, webpki, or native")),
    }
}

/// Returns the raw env value for `key` when present (including empty strings).
fn optional<'a>(map: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    map.get(key).map(String::as_str)
}

/// Requires a value for `key` that is not empty or whitespace. Returns it untrimmed.
fn required<'a>(map: &'a HashMap<String, String>, key: &str) -> Result<&'a str, Error> {
    match map.get(key).map(String::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(Error::new(format!("{key} is required"))),
    }
}

/// Parses true/false/yes/no/on/off/1/0 for a named env key.
fn parse_bool(key: &str, value: &str) -> Result<bool, Error> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(Error::new(format!("{key} must be true or false"))),
    }
}

/// Parses an unsigned integer for a named env key.
fn parse_u64(key: &str, value: &str) -> Result<u64, Error> {
    value
        .trim()
        .parse()
        .map_err(|_| Error::new(format!("{key} must be an integer")))
}

/// Rejects API, auth, and ipecho URLs that are not `https://`.
fn require_https(key: &str, url: &str) -> Result<(), Error> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(Error::new(format!("{key} must start with https://")))
    }
}

// Per-thread stand-in for the process environment. Absent from the release binary.
#[cfg(test)]
thread_local! {
    static TEST_ENV: std::cell::RefCell<Option<Vec<(String, String)>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` with a thread-local env map so `from_env` / `main` stay parallel-safe.
#[cfg(test)]
pub(crate) fn with_test_env<I, K, V, T>(pairs: I, f: impl FnOnce() -> T) -> T
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_ENV.with(|slot| *slot.borrow_mut() = None);
        }
    }
    let pairs: Vec<_> = pairs
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    TEST_ENV.with(|slot| *slot.borrow_mut() = Some(pairs));
    let _reset = Reset;
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimum env pairs that parse into a DNS-only one-shot config.
    fn base() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com,*.Example.com."),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
        ]
    }

    #[test]
    fn parses_defaults_and_targets() {
        let cfg = Config::from_pairs(base()).unwrap();
        assert!(cfg.run_on_start);
        assert_eq!(cfg.interval_seconds, 0);
        assert!(!cfg.dry_run);
        assert!(cfg.log.dir.is_none());
        assert!(cfg.log.to_stdout);
        assert_eq!(cfg.log.rotate_size_mb, 10);
        assert_eq!(cfg.log.rotate_keep, 5);
        assert_eq!(cfg.log.file, "contabo-ddns.log");
        assert_eq!(cfg.tls_roots, TlsRoots::Both);
        assert_eq!(cfg.ip_echo_urls, vec![DEFAULT_IP_ECHO_URL.to_string()]);
        assert!(!cfg.ipv6);
        let dns = cfg.dns.as_ref().unwrap();
        assert_eq!(
            dns.records,
            vec![
                DnsTarget::Exact("home.example.com".into()),
                DnsTarget::Wildcard("example.com".into()),
            ]
        );
        assert!(!dns.create_missing);
        assert!(cfg.firewall.is_none());
    }

    #[test]
    fn default_log_dir_and_interval() {
        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "LOG_DIR" && *key != "INTERVAL_SECONDS");
        let cfg = Config::from_pairs(pairs).unwrap();
        assert_eq!(cfg.log.dir.unwrap(), PathBuf::from(DEFAULT_LOG_DIR));
        assert_eq!(cfg.interval_seconds, 300);
    }

    #[test]
    fn rejects_missing_secret_and_idle_schedule() {
        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "CONTABO_API_PASSWORD");
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("CONTABO_API_PASSWORD")
        );

        let mut pairs = base();
        pairs.push(("RUN_ON_START", "false"));
        let err = Config::from_pairs(pairs).unwrap_err().to_string();
        assert!(err.contains("never sync"));

        let mut pairs = base();
        pairs.push(("CONTABO_CLIENT_SECRET", "   "));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("CONTABO_CLIENT_SECRET is required")
        );
    }

    #[test]
    fn rejects_bad_names_ttl_and_tls_roots() {
        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "home example.com"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("bad DNS name")
        );

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "*.-bad.example"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_TTL", "0"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("DNS_TTL")
        );

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["10.0.0.0/24","not a host"]}]"#,
        ));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("not a host")
        );

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["10.0.0.0/24"]}]"#,
        ));
        assert!(Config::from_pairs(pairs).is_ok());

        for (value, roots) in [
            ("webpki", TlsRoots::Webpki),
            ("native", TlsRoots::Native),
            ("BOTH", TlsRoots::Both),
        ] {
            let mut pairs = base();
            pairs.push(("TLS_ROOTS", value));
            assert_eq!(Config::from_pairs(pairs).unwrap().tls_roots, roots);
        }
        let mut pairs = base();
        pairs.push(("TLS_ROOTS", "custom"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("TLS_ROOTS")
        );
    }

    #[test]
    fn interval_must_be_zero_or_at_least_minimum() {
        for (value, ok) in [("0", true), ("1", false), ("29", false), ("30", true)] {
            let mut pairs = base();
            pairs.push(("INTERVAL_SECONDS", value));
            let result = Config::from_pairs(pairs);
            assert_eq!(result.is_ok(), ok, "INTERVAL_SECONDS={value}");
            if !ok {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("must be 0 or >= 30")
                );
            }
        }
    }

    #[test]
    fn rejects_bad_log_settings() {
        let mut pairs = base();
        pairs.push(("LOG_LEVEL", "loud"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("LOG_ROTATE_SIZE_MB", "0"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("LOG_ROTATE_KEEP", "0"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("LOG_ROTATE_KEEP", "10001"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("between 1 and 10000")
        );

        let mut pairs = base();
        pairs.push(("LOG_ROTATE_KEEP", "10000"));
        assert_eq!(Config::from_pairs(pairs).unwrap().log.rotate_keep, 10_000);

        let mut pairs = base();
        pairs.push(("LOG_TO_STDOUT", "false"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("LOG_DIR")
        );
    }

    #[test]
    fn parses_firewall_and_merges_duplicate_names() {
        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["203.0.113.5","203.0.113.5","current"]},{"displayName":"SSH","sources":["home.example.net","203.0.113.5"]}]"#,
        ));
        let cfg = Config::from_pairs(pairs).unwrap();
        assert!(cfg.dns.is_none());
        let firewall = cfg.firewall.unwrap();
        assert_eq!(firewall.id.as_deref(), Some("fw-1"));
        assert_eq!(firewall.rules.len(), 1);
        assert_eq!(firewall.rules[0].display_name, "SSH");
        assert_eq!(
            firewall.rules[0].sources,
            vec!["203.0.113.5", "current", "home.example.net"]
        );
    }

    #[test]
    fn rejects_both_firewall_selectors_and_http_urls() {
        let mut pairs = base();
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push(("FIREWALL_NAME", "edge"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["203.0.113.5"]}]"#,
        ));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("IP_ECHO_URL", "http://ipecho.test/plain"));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("https://")
        );
    }

    #[test]
    fn rejects_nothing_to_do() {
        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        assert!(Config::from_pairs(pairs).is_err());
    }

    #[test]
    fn debug_redacts_secrets() {
        let cfg = Config::from_pairs(base()).unwrap();
        let text = format!("{cfg:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains(": \"secret\""));
        assert!(!text.contains(": \"pw\""));
    }

    #[test]
    fn parses_optional_flags_and_dns_ttl() {
        let mut pairs = base();
        pairs.push(("DRY_RUN", "yes"));
        pairs.push(("DNS_TTL", "120"));
        pairs.push(("DNS_CREATE_MISSING", "on"));
        let cfg = Config::from_pairs(pairs).unwrap();
        assert!(cfg.dry_run);
        assert_eq!(cfg.dns.as_ref().unwrap().ttl, Some(120));
        assert!(cfg.dns.as_ref().unwrap().create_missing);

        let mut pairs = base();
        pairs.push(("LOG_FILE", "sync.log"));
        pairs.push(("LOG_DIR", "/tmp/contabo-logs"));
        let cfg = Config::from_pairs(pairs).unwrap();
        assert_eq!(cfg.log.file, "sync.log");
        assert_eq!(cfg.log.dir.unwrap(), PathBuf::from("/tmp/contabo-logs"));
    }

    #[test]
    fn rejects_invalid_dns_and_firewall_env() {
        let mut pairs = base();
        pairs.push(("IP_ECHO_TIMEOUT_SECONDS", "0"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_ENABLED", "true"));
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push((
            "IP_ECHO_URL",
            "https://one.test/plain, https://two.test/plain",
        ));
        assert_eq!(Config::from_pairs(pairs).unwrap().ip_echo_urls.len(), 2);

        let mut pairs = base();
        pairs.push(("IPV6", "yes"));
        assert!(Config::from_pairs(pairs).unwrap().ipv6);

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["2001:db8::1","current6"]}]"#,
        ));
        assert!(
            Config::from_pairs(pairs)
                .unwrap_err()
                .to_string()
                .contains("current6 requires IPV6=true")
        );

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("IPV6", "true"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["2001:db8::1","current6"]}]"#,
        ));
        let firewall = Config::from_pairs(pairs).unwrap().firewall.unwrap();
        assert_eq!(
            firewall.rules[0].sources,
            vec!["2001:db8::1".to_string(), "current6".to_string()]
        );

        let mut pairs = base();
        pairs.push(("IP_ECHO_URL", "  "));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("IP_ECHO_URL", "http://ipecho.test/plain,https://ok.test/ip"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "  ,  "));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "*.,"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "*."));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "*..example.com"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("DNS_RECORDS", "bad*name.example.com"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ENABLED", "true"));
        pairs.retain(|(key, _)| *key != "FIREWALL_RULES");
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push(("FIREWALL_RULES", "not-json"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push(("FIREWALL_RULES", "[]"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"","sources":["1.1.1.1"]}]"#,
        ));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":[""]}]"#,
        ));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("DNS_ENABLED", "false"));
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push(("FIREWALL_RULES", r#"[{"displayName":"SSH","sources":[]}]"#));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("LOG_FILE", "logs/sync.log"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("RUN_ON_START", "maybe"));
        assert!(Config::from_pairs(pairs).is_err());

        let mut pairs = base();
        pairs.push(("LOG_ROTATE_KEEP", "99999999999999999999"));
        assert!(Config::from_pairs(pairs).is_err());

        for (key, value) in [
            ("CONTABO_CLIENT_ID", ""),
            ("CONTABO_CLIENT_SECRET", ""),
            ("CONTABO_API_USER", ""),
            ("CONTABO_API_BASE", "http://api.test"),
            ("CONTABO_AUTH_URL", "http://auth.test/token"),
            ("IP_ECHO_TIMEOUT_SECONDS", "nope"),
            ("INTERVAL_SECONDS", "nope"),
            ("DRY_RUN", "maybe"),
            ("LOG_ROTATE_SIZE_MB", "nope"),
            ("LOG_TO_STDOUT", "maybe"),
            ("DNS_ENABLED", "maybe"),
            ("DNS_TTL", "nope"),
            ("DNS_CREATE_MISSING", "maybe"),
            ("FIREWALL_ENABLED", "maybe"),
            ("IPV6", "maybe"),
        ] {
            let mut pairs = base();
            if pairs.iter().any(|(existing, _)| *existing == key) {
                pairs.retain(|(existing, _)| *existing != key);
            }
            pairs.push((key, value));
            assert!(
                Config::from_pairs(pairs).is_err(),
                "{key}={value} should fail"
            );
        }
    }

    #[test]
    fn firewall_only_and_dns_disabled_explicitly() {
        let mut pairs = base();
        pairs.push(("DNS_ENABLED", "false"));
        pairs.retain(|(key, _)| *key != "DNS_RECORDS");
        pairs.push(("FIREWALL_ID", "fw-1"));
        pairs.push((
            "FIREWALL_RULES",
            r#"[{"displayName":"SSH","sources":["1.1.1.1"]}]"#,
        ));
        let cfg = Config::from_pairs(pairs).unwrap();
        assert!(cfg.dns.is_none());
        assert!(cfg.firewall.is_some());
    }

    /// `from_env` reads the thread-local map instead of process env.
    #[test]
    fn from_env_without_thread_local_override_reads_process_env() {
        let _ = Config::from_env();
    }

    #[test]
    fn from_env_when_minimum_vars_present() {
        super::with_test_env(
            [
                ("CONTABO_CLIENT_ID", "id"),
                ("CONTABO_CLIENT_SECRET", "secret"),
                ("CONTABO_API_USER", "user@example.com"),
                ("CONTABO_API_PASSWORD", "pw"),
                ("DNS_RECORDS", "home.example.com"),
                ("INTERVAL_SECONDS", "0"),
                ("LOG_DIR", ""),
            ],
            || {
                let cfg = Config::from_env().unwrap();
                assert_eq!(cfg.client_id, "id");
            },
        );
    }
}
