//! Single error type used across config, HTTP, DNS, and firewall code.

use std::fmt;

/// Owned error message. Displayed as-is in logs and process exit paths.
#[derive(Debug)]
pub struct Error(pub String);

impl Error {
    /// Builds an error from a complete message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// Builds `"context: cause"` for wrapping an underlying failure.
    pub fn wrap(context: impl fmt::Display, err: impl fmt::Display) -> Self {
        Self::new(format!("{context}: {err}"))
    }
}

impl fmt::Display for Error {
    /// Writes the inner message with no extra prefix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;

    /// `Error::wrap` joins context and cause with `": "`.
    #[test]
    fn wrap_joins_context_and_cause() {
        let err = Error::wrap("resolve example.com", "timeout");
        assert_eq!(err.to_string(), "resolve example.com: timeout");
    }
}
