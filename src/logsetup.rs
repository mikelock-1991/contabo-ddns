//! flexi_logger setup: stdout and optional rotating files.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use flexi_logger::{
    Cleanup, Criterion, Duplicate, FileSpec, Logger, LoggerHandle, Naming, WriteMode,
};

use crate::config::LogConfig;
use crate::error::Error;

/// Wraps a flexi_logger parse/start error in the crate `Error` type.
fn flexi_parse_err(err: impl ToString) -> Error {
    Error::new(err.to_string())
}

/// Formats a log-directory create or write failure.
fn log_dir_err(dir: &Path, action: &str, err: impl std::fmt::Display) -> Error {
    Error::new(format!("{action} log dir {}: {err}", dir.display()))
}

/// Builds a `Logger` (file+rotate or stdout) without starting the global logger.
pub fn prepare(log: &LogConfig) -> Result<Logger, Error> {
    let spec = log.level.as_str();
    if let Some(dir) = &log.dir {
        if let Err(err) = fs::create_dir_all(dir) {
            return Err(log_dir_err(dir, "create", err));
        }
        let probe = dir.join(".contabo-ddns-write-test");
        if let Err(err) = fs::write(&probe, b"") {
            return Err(log_dir_err(dir, "log dir not writable", err));
        }
        let _ = fs::remove_file(&probe);

        let (basename, suffix) = split_log_file(&log.file);
        let files = FileSpec::default()
            .directory(dir)
            .basename(basename)
            .suffix(suffix);
        let parsed = Logger::try_with_str(spec).map_err(flexi_parse_err)?;
        let mut logger = parsed
            .log_to_file(files)
            .rotate(
                Criterion::Size(log.rotate_size_mb.saturating_mul(1024 * 1024)),
                Naming::Numbers,
                Cleanup::KeepLogFiles(log.rotate_keep),
            )
            .write_mode(WriteMode::Direct);
        if log.to_stdout {
            logger = logger.duplicate_to_stdout(Duplicate::All);
        }
        Ok(logger)
    } else {
        let logger = Logger::try_with_str(spec)
            .map_err(flexi_parse_err)?
            .log_to_stdout()
            .write_mode(WriteMode::Direct);
        Ok(logger)
    }
}

/// Display path for logs, or `"(stdout)"` when file logging is off.
fn log_dir_label(dir: Option<&PathBuf>) -> String {
    match dir {
        Some(path) => path.display().to_string(),
        None => "(stdout)".into(),
    }
}

/// Process-wide slot so `init` can reuse a started logger from parallel tests.
fn logger_slot() -> &'static Mutex<Option<LoggerHandle>> {
    static SLOT: OnceLock<Mutex<Option<LoggerHandle>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

static INIT_LOCK: Mutex<()> = Mutex::new(());

/// Starts the global logger once, then clones the handle for later callers.
///
/// A second `Logger::start` would fail. The stored handle makes a later `init`
/// return the logger that is already running.
pub fn init(log: &LogConfig) -> Result<LoggerHandle, Error> {
    let _guard = INIT_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    start_prepared(log)
}

fn start_prepared(log: &LogConfig) -> Result<LoggerHandle, Error> {
    install(prepare(log)?, log)
}

/// Starts `prepared` unless a logger handle is already stored.
fn install(prepared: Logger, log: &LogConfig) -> Result<LoggerHandle, Error> {
    let mut slot = logger_slot().lock().unwrap_or_else(|err| err.into_inner());
    if let Some(handle) = slot.as_ref() {
        return Ok(handle.clone());
    }
    let handle = finish_start(prepared.start())?;
    *slot = Some(handle.clone());
    drop(slot);

    log::info!(
        "logging level={} dir={} file={} rotate_size_mb={} keep={}",
        log.level,
        log_dir_label(log.dir.as_ref()),
        log.file,
        log.rotate_size_mb,
        log.rotate_keep
    );
    Ok(handle)
}

/// Starts a process-wide logger that drops every record, including flexi_logger's own errors.
///
/// Tests call this before `init` so a later `init` reuses the handle instead of writing to stderr.
#[cfg(test)]
pub(crate) fn discard_output() {
    let _guard = INIT_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    if logger_slot()
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .is_some()
    {
        return;
    }
    let prepared = Logger::try_with_str("trace")
        .expect("trace spec")
        .do_not_log()
        .error_channel(flexi_logger::ErrorChannel::DevNull);
    let log = LogConfig {
        level: "info".into(),
        dir: None,
        file: "contabo-ddns.log".into(),
        rotate_size_mb: 1,
        rotate_keep: 1,
        to_stdout: true,
    };
    install(prepared, &log).expect("discard logger");
}

/// Maps a flexi_logger start failure onto the crate error type.
fn finish_start(
    result: Result<LoggerHandle, impl std::fmt::Display>,
) -> Result<LoggerHandle, Error> {
    result.map_err(flexi_parse_err)
}

/// Splits `contabo-ddns.log` into basename + suffix; missing suffix becomes `"log"`.
pub fn split_log_file(file: &str) -> (String, String) {
    match Path::new(file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(file)
        .rsplit_once('.')
    {
        Some((basename, suffix)) if !basename.is_empty() && !suffix.is_empty() => {
            (basename.to_string(), suffix.to_string())
        }
        _ => (file.to_string(), "log".to_string()),
    }
}

#[cfg(test)]
/// Unique temp path (`prefix-pid-n`) so parallel tests do not share files.
pub(crate) fn unique_temp(prefix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "{}-{}-{}",
        prefix,
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        finish_start, flexi_parse_err, init, log_dir_label, prepare, split_log_file, unique_temp,
    };
    use crate::config::LogConfig;

    #[test]
    fn logging_init_and_prepare_paths() {
        let dir = unique_temp("contabo-ddns-logsetup");
        let _ = std::fs::remove_dir_all(&dir);
        let file_log = LogConfig {
            level: "info".into(),
            dir: Some(dir.clone()),
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: true,
        };
        assert!(prepare(&file_log).is_ok());
        let quiet = LogConfig {
            level: "info".into(),
            dir: Some(dir.clone()),
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: false,
        };
        assert!(prepare(&quiet).is_ok());
        let bad_level = LogConfig {
            level: "crate1::mod1=wrong, crate2=warn".into(),
            dir: Some(dir.clone()),
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: false,
        };
        assert!(prepare(&bad_level).is_err());
        let bad_stdout = LogConfig {
            level: "crate1::mod1=wrong, crate2=warn".into(),
            dir: None,
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: true,
        };
        assert!(prepare(&bad_stdout).is_err());

        let stdout = LogConfig {
            level: "info".into(),
            dir: None,
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: true,
        };
        assert!(prepare(&stdout).is_ok());
        assert_eq!(log_dir_label(None), "(stdout)");
        assert_eq!(log_dir_label(Some(&dir)), dir.display().to_string());

        let probe = unique_temp("contabo-ddns-logfile");
        let _ = std::fs::write(&probe, b"x");
        let bad_dir = LogConfig {
            level: "info".into(),
            dir: Some(probe.clone()),
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: false,
        };
        assert!(prepare(&bad_dir).is_err());

        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::create_dir_all(dir.join(".contabo-ddns-write-test"));
        let blocked_write = LogConfig {
            level: "info".into(),
            dir: Some(dir.clone()),
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: false,
        };
        assert!(prepare(&blocked_write).is_err());
        let _ = std::fs::remove_dir_all(&dir);

        let _ = std::fs::remove_file(probe);
    }

    #[test]
    fn flexi_parse_wraps_messages() {
        let err = flexi_parse_err("level is invalid");
        assert!(err.to_string().contains("level"));
    }

    #[test]
    fn init_reuses_started_logger_and_can_inject_start_failure() {
        super::discard_output();
        super::discard_output();
        let stdout = LogConfig {
            level: "info".into(),
            dir: None,
            file: "contabo-ddns.log".into(),
            rotate_size_mb: 1,
            rotate_keep: 2,
            to_stdout: true,
        };
        assert!(init(&stdout).is_ok());
        assert!(init(&stdout).is_ok());
        {
            let _guard = super::INIT_LOCK.lock().unwrap();
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _slot = super::logger_slot().lock().unwrap();
                panic!("poison logger");
            }));
            assert!(super::start_prepared(&stdout).is_ok());
            let saved = super::logger_slot()
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .clone();
            *super::logger_slot()
                .lock()
                .unwrap_or_else(|err| err.into_inner()) = None;
            assert!(super::start_prepared(&stdout).is_err());
            *super::logger_slot()
                .lock()
                .unwrap_or_else(|err| err.into_inner()) = saved;
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = super::INIT_LOCK.lock().unwrap();
            panic!("poison init lock");
        }));
        assert!(init(&stdout).is_ok());
        let failed = finish_start(Err::<flexi_logger::LoggerHandle, &str>(
            "injected start failure",
        ));
        assert!(
            failed
                .err()
                .unwrap()
                .to_string()
                .contains("injected start failure")
        );
    }

    #[test]
    fn splits_log_file_name() {
        assert_eq!(
            split_log_file("contabo-ddns.log"),
            ("contabo-ddns".into(), "log".into())
        );
        assert_eq!(
            split_log_file("contabo-ddns"),
            ("contabo-ddns".into(), "log".into())
        );
        assert_eq!(split_log_file("a.b.log"), ("a.b".into(), "log".into()));
    }
}
