//! Shared HTTP fixtures for unit tests (one fallthrough path for coverage).
#![cfg(test)]

use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;

use crate::contabo::{ContaboClient, Http, HttpRequest, HttpResponse};
use crate::error::Error;

/// Errors on unmatched URLs so scripted tests fail closed instead of hanging.
pub fn reject(request: &HttpRequest) -> Result<HttpResponse, Error> {
    Err(Error::new(format!(
        "unexpected {} {}",
        request.method, request.url
    )))
}

/// HTTP double that records every call and always rejects.
pub struct Unscripted {
    pub calls: Mutex<Vec<HttpRequest>>,
}

impl Http for Unscripted {
    /// Stores the request, then returns an unexpected-URL error.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.calls.lock().unwrap().push(request.clone());
        reject(request)
    }
}

/// Scripted token + ipecho + DNS GET responses for an unchanged A record.
pub struct DnsCycleOk {
    pub calls: Mutex<Vec<String>>,
}

impl Http for DnsCycleOk {
    /// Serves token, ipecho, zones, and records; anything else is rejected.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.calls.lock().unwrap().push(request.url.clone());
        if request.url.contains("/token") {
            return Ok(HttpResponse {
                status: 200,
                body: TOKEN_BODY.as_bytes().to_vec(),
            });
        }
        if request.url.contains("ipecho") {
            return Ok(HttpResponse {
                status: 200,
                body: b"203.0.113.10".to_vec(),
            });
        }
        if request.method == "GET" && request.url.contains("/records") {
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"data":[{"recordId":1,"name":"home","type":"A","ttl":60,"prio":0,"data":"203.0.113.10"}]}"#
                    .to_vec(),
            });
        }
        if request.method == "GET" && request.url.contains("/v1/dns/zones") {
            return Ok(HttpResponse {
                status: 200,
                body: br#"{"data":[{"zoneName":"example.com"}]}"#.to_vec(),
            });
        }
        reject(request)
    }
}

/// Route-table HTTP double. First matching method+url substring wins.
pub struct Scripted {
    routes: Vec<(String, String, u16, String)>,
    pub calls: Mutex<Vec<HttpRequest>>,
}

impl Scripted {
    /// Builds a double from `(method, url needle, status, body)` rows.
    pub fn new<I, A, B, C>(routes: I) -> Self
    where
        I: IntoIterator<Item = (A, B, u16, C)>,
        A: Into<String>,
        B: Into<String>,
        C: Into<String>,
    {
        Self {
            routes: routes
                .into_iter()
                .map(|(method, needle, status, body)| {
                    (method.into(), needle.into(), status, body.into())
                })
                .collect(),
            calls: Mutex::new(Vec::new()),
        }
    }
}

impl Http for Scripted {
    /// Records the request and returns the first matching scripted response.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.calls
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(request.clone());
        for (method, needle, status, body) in &self.routes {
            if request.method == *method && request.url.contains(needle) {
                return Ok(HttpResponse {
                    status: *status,
                    body: body.as_bytes().to_vec(),
                });
            }
        }
        reject(request)
    }
}

/// Pops scripted responses from the end of the queue (last pushed is next).
pub struct Sequence {
    pub calls: Mutex<Vec<HttpRequest>>,
    pub responses: Mutex<Vec<HttpResponse>>,
}

impl Sequence {
    /// Builds a queue that answers with `(status, body)` rows in the given order.
    pub fn in_order(rows: &[(u16, &str)]) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(
                rows.iter()
                    .rev()
                    .map(|(status, body)| HttpResponse {
                        status: *status,
                        body: body.as_bytes().to_vec(),
                    })
                    .collect(),
            ),
        }
    }
}

/// Successful token response body used by the scripted fixtures.
pub const TOKEN_BODY: &str = r#"{"access_token":"tok","expires_in":3600}"#;

/// Scripted route that answers the token POST.
pub fn token_route() -> (&'static str, &'static str, u16, String) {
    ("POST", "/token", 200, TOKEN_BODY.into())
}

/// API client against the `example.test` endpoints with fixed test credentials.
pub fn client(http: &dyn Http) -> ContaboClient<'_> {
    // Enable log arguments before exercising API paths, regardless of test order.
    crate::logsetup::discard_output();
    ContaboClient::new(
        http,
        "https://api.example.test",
        "https://auth.example.test/token",
        "id",
        "secret",
        "user@example.com",
        "s3cret-password",
    )
    .with_delay(crate::retry::immediate)
}

/// Local endpoint that accepts and immediately drops every connection.
///
/// Real reqwest clients fail fast against it, without waiting on a refused port
/// (slow on Windows) or reaching the network. Returns an `https://` base URL.
pub fn closing_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            drop(stream);
        }
    });
    format!("https://{addr}")
}

impl Http for Sequence {
    /// Records the request and returns the next queued response.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        self.calls
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(request.clone());
        match self
            .responses
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pop()
        {
            Some(response) => Ok(response),
            None => Err(Error::new("no scripted response left")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_cycle_fixture_rejects_unmatched() {
        let http = DnsCycleOk {
            calls: Mutex::new(Vec::new()),
        };
        let err = http
            .send(&HttpRequest {
                method: "DELETE".into(),
                url: "https://example.test/unknown".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn reject_formats_unmatched_requests() {
        let req = HttpRequest {
            method: "PATCH".into(),
            url: "https://example.test/none".into(),
            headers: vec![],
            body: None,
            timeout: None,
            max_body: None,
        };
        assert!(reject(&req).unwrap_err().to_string().contains("unexpected"));
    }

    #[test]
    fn scripted_locks_recover_after_poison() {
        let http = Scripted::new(vec![("GET", "/x", 200u16, "ok")]);
        let request = HttpRequest {
            method: "GET".into(),
            url: "https://example.test/x".into(),
            headers: vec![],
            body: None,
            timeout: None,
            max_body: None,
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = http.calls.lock().unwrap();
            panic!("poison calls");
        }));
        assert!(http.send(&request).is_ok());

        let sequence = Sequence {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(vec![HttpResponse {
                status: 200,
                body: b"ok".to_vec(),
            }]),
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sequence.calls.lock().unwrap();
            panic!("poison calls");
        }));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sequence.responses.lock().unwrap();
            panic!("poison responses");
        }));
        assert!(sequence.send(&request).is_ok());
    }
}
