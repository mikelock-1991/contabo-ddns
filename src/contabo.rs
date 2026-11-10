//! Blocking HTTP trait, reqwest client, and authenticated Contabo JSON API.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::Value;
use uuid::Uuid;

use crate::config::Config;
use crate::error::Error;
use crate::retry;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;
const PAGE_SIZE: u64 = 100;
const MAX_PAGES: u64 = 1000;
const TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(60);
/// Token lifetime assumed when the auth response omits `expires_in`.
const DEFAULT_TOKEN_LIFETIME_SECS: u64 = 300;
const SNIPPET_CHARS: usize = 300;
/// Largest Contabo JSON body kept in memory.
pub const MAX_API_BODY: usize = 8 * 1024 * 1024;
/// Largest ipecho body. A public address fits in far less.
pub const MAX_ECHO_BODY: usize = 1024;

/// One outbound HTTP request used by both production reqwest and test doubles.
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    /// Response body cap. `None` uses `MAX_API_BODY`.
    pub max_body: Option<usize>,
}

/// Status and raw body from an HTTP round-trip.
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Address family for an echo lookup. `V4` is curl `-4`; `V6` is curl `-6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

/// Thread-safe HTTP sender. DNS and firewall sync call this from parallel threads.
pub trait Http: Send + Sync {
    /// Performs one request and returns status plus body bytes.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error>;

    /// Same as `send`, restricted to one IP family. The default ignores the family.
    fn send_family(&self, request: &HttpRequest, family: IpFamily) -> Result<HttpResponse, Error> {
        let _ = family;
        self.send(request)
    }
}

/// Production HTTP client: reqwest blocking + rustls, 30s default timeout.
///
/// API calls use `client`. Echo lookups use `v4` or `v6`, which bind the local
/// socket to one family so DNS answers of the other family are not dialed.
pub struct ReqwestHttp {
    client: Client,
    v4: Client,
    v6: Option<Client>,
}

/// Wraps an invalid HTTP method string.
fn http_method_err(err: impl std::fmt::Display) -> Error {
    Error::wrap("http method", err)
}

/// Wraps a transport error for `url`.
fn http_request_err(url: &str, err: reqwest::Error) -> Error {
    Error::wrap(format!("http {url}"), err)
}

/// Wraps a failure reading the response body.
fn http_body_err(err: impl std::fmt::Display) -> Error {
    Error::wrap("read http body", err)
}

/// Reads at most `max` response bytes. One extra byte detects an over-long body.
fn read_response_body(response: reqwest::blocking::Response, max: usize) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let mut body = Vec::new();
    let mut limited = response.take(max as u64 + 1);
    if let Err(err) = limited.read_to_end(&mut body) {
        return Err(http_body_err(err));
    }
    if body.len() > max {
        return Err(Error::new(format!("http body exceeds {max} bytes")));
    }
    Ok(body)
}

impl ReqwestHttp {
    /// Builds the API client and the IPv4 echo client. The IPv6 echo client exists only when `ipv6` is set.
    ///
    /// `roots` selects the embedded Mozilla store, the OS bundle, or both.
    pub fn new(roots: crate::config::TlsRoots, ipv6: bool) -> Result<Self, Error> {
        let v6 = if ipv6 {
            build_client(roots, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED))).map(Some)
        } else {
            Ok(None)
        };
        assemble(
            build_client(roots, None),
            build_client(roots, Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))),
            v6,
        )
    }
}

fn assemble(
    client: Result<Client, Error>,
    v4: Result<Client, Error>,
    v6: Result<Option<Client>, Error>,
) -> Result<ReqwestHttp, Error> {
    Ok(ReqwestHttp {
        client: client?,
        v4: v4?,
        v6: v6?,
    })
}

fn build_client(roots: crate::config::TlsRoots, local: Option<IpAddr>) -> Result<Client, Error> {
    use crate::config::TlsRoots;
    // reqwest 0.13 with rustls-no-provider panics unless a process-wide provider
    // is installed. ring keeps the static musl image off aws-lc.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = Client::builder()
        .user_agent("contabo-ddns")
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS));
    builder = match roots {
        TlsRoots::Native => builder,
        TlsRoots::Webpki => builder.tls_certs_only(mozilla_roots()),
        TlsRoots::Both => builder.tls_certs_merge(mozilla_roots()),
    };
    if let Some(addr) = local {
        builder = builder.local_address(addr);
    }
    // Share the native Rust DNS resolver with firewall hostname lookups.
    finish_with_resolver(builder, crate::resolve::HostResolver::system())
}

fn finish_with_resolver(
    builder: reqwest::blocking::ClientBuilder,
    resolver: Result<crate::resolve::HostResolver, Error>,
) -> Result<Client, Error> {
    let resolver = resolver?;
    finish_build(builder.dns_resolver(std::sync::Arc::new(resolver)).build())
}

/// Embedded Mozilla roots. `from_der` only stores the bytes when rustls is the TLS backend.
fn mozilla_roots() -> Vec<reqwest::Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .filter_map(|der| reqwest::Certificate::from_der(der).ok())
        .collect()
}

fn finish_build(result: Result<Client, reqwest::Error>) -> Result<Client, Error> {
    result.map_err(|err| Error::wrap("build http client", err))
}

fn send_with(client: &Client, request: &HttpRequest) -> Result<HttpResponse, Error> {
    let method = match reqwest::Method::from_bytes(request.method.as_bytes()) {
        Ok(method) => method,
        Err(err) => return Err(http_method_err(err)),
    };
    let mut builder = client.request(method, &request.url);
    if let Some(timeout) = request.timeout {
        builder = builder.timeout(timeout);
    }
    for (name, value) in &request.headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }
    let response = match builder.send() {
        Ok(response) => response,
        Err(err) => return Err(http_request_err(&request.url, err)),
    };
    let status = response.status().as_u16();
    let max = request.max_body.unwrap_or(MAX_API_BODY);
    let body = read_response_body(response, max)?;
    Ok(HttpResponse { status, body })
}

impl Http for ReqwestHttp {
    /// Sends `request` on the unrestricted API client.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
        send_with(&self.client, request)
    }

    /// Sends an echo request on the IPv4-only or IPv6-only client.
    fn send_family(&self, request: &HttpRequest, family: IpFamily) -> Result<HttpResponse, Error> {
        let client = match family {
            IpFamily::V4 => &self.v4,
            IpFamily::V6 => self
                .v6
                .as_ref()
                .ok_or_else(|| Error::new("IPV6 is disabled"))?,
        };
        send_with(client, request)
    }
}

/// Access token plus the Instant after which it should be refreshed.
struct CachedToken {
    access_token: String,
    refresh_at: Instant,
}

/// Authenticated Contabo API client. Token cache is a mutex for parallel DNS/firewall.
pub struct ContaboClient<'a> {
    http: &'a dyn Http,
    api_base: &'a str,
    auth_url: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    api_user: &'a str,
    api_password: &'a str,
    shutdown: &'a AtomicBool,
    delay: fn(u32) -> std::time::Duration,
    token: Mutex<Option<CachedToken>>,
}

impl<'a> ContaboClient<'a> {
    /// Client for the endpoints and credentials in `cfg`.
    pub fn from_config(http: &'a dyn Http, cfg: &'a Config) -> Self {
        Self::new(
            http,
            &cfg.api_base,
            &cfg.auth_url,
            &cfg.client_id,
            &cfg.client_secret,
            &cfg.api_user,
            &cfg.api_password,
        )
    }

    /// Stores API endpoints and credentials; token is fetched on first use.
    pub fn new(
        http: &'a dyn Http,
        api_base: &'a str,
        auth_url: &'a str,
        client_id: &'a str,
        client_secret: &'a str,
        api_user: &'a str,
        api_password: &'a str,
    ) -> Self {
        Self {
            http,
            api_base,
            auth_url,
            client_id,
            client_secret,
            api_user,
            api_password,
            shutdown: &retry::NO_SHUTDOWN,
            delay: retry::backoff,
            token: Mutex::new(None),
        }
    }

    /// Stops retry backoff early once `shutdown` is set.
    pub fn with_shutdown(mut self, shutdown: &'a AtomicBool) -> Self {
        self.shutdown = shutdown;
        self
    }

    /// Replaces the pause between transient retries. Production uses `retry::backoff`.
    pub fn with_delay(mut self, delay: fn(u32) -> std::time::Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Shared HTTP transport. Callers reuse this client so the token cache survives cycles.
    pub fn http(&self) -> &'a dyn Http {
        self.http
    }

    /// Shutdown flag checked between retries.
    pub fn shutdown(&self) -> &'a AtomicBool {
        self.shutdown
    }

    /// Pause function used between transient retries.
    pub fn retry_delay(&self) -> fn(u32) -> std::time::Duration {
        self.delay
    }

    /// Walks `_pagination.totalPages` and concatenates each page's `data` array.
    pub fn list(&self, path: &str) -> Result<Vec<Value>, Error> {
        let mut page = 1u64;
        let mut all = Vec::new();
        loop {
            let mut body = self.get_json(&with_page(path, page))?;
            if let Some(Value::Array(items)) = body.get_mut("data").map(Value::take) {
                all.extend(items);
            }
            let total = body
                .get("_pagination")
                .and_then(|page_info| page_info.get("totalPages"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            if total == 0 || page >= total {
                break;
            }
            if page >= MAX_PAGES {
                return Err(Error::new(format!(
                    "pagination exceeded {MAX_PAGES} pages for {path}"
                )));
            }
            page += 1;
        }
        Ok(all)
    }

    /// Authenticated GET; empty body becomes JSON `null`.
    pub fn get_json(&self, path: &str) -> Result<Value, Error> {
        self.send_json("GET", path, None)
    }

    /// Authenticated POST of a JSON value.
    pub fn post_json(&self, path: &str, body: &Value) -> Result<Value, Error> {
        self.send_json("POST", path, Some(body))
    }

    /// Authenticated PATCH of a JSON value (DNS record updates).
    pub fn patch_json(&self, path: &str, body: &Value) -> Result<Value, Error> {
        self.send_json("PATCH", path, Some(body))
    }

    /// Authenticated PUT of a JSON value (firewall rewrite).
    pub fn put_json(&self, path: &str, body: &Value) -> Result<Value, Error> {
        self.send_json("PUT", path, Some(body))
    }

    /// Encodes optional JSON, sends with a bearer token, and parses the body.
    fn send_json(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, Error> {
        let bytes =
            body.map(|value| serde_json::to_vec(value).expect("serde_json::Value always encodes"));
        let response = self.send_authed(method, path, bytes)?;
        if response.body.is_empty() {
            return Ok(Value::Null);
        }
        match serde_json::from_slice(&response.body) {
            Ok(value) => Ok(value),
            Err(err) => Err(Error::wrap(format!("json from {path}"), err)),
        }
    }

    /// Sends one authed request and requires a 2xx. Refreshes the token once after 401.
    fn send_authed(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<HttpResponse, Error> {
        let mut request = HttpRequest {
            method: method.to_string(),
            url: format!("{}{}", self.api_base.trim_end_matches('/'), path),
            headers: Vec::new(),
            body,
            timeout: Some(HTTP_TIMEOUT),
            max_body: Some(MAX_API_BODY),
        };
        let mut response = self.send_with_token(&mut request, path, false)?;
        if response.status == 401 {
            *self.lock_token() = None;
            response = self.send_with_token(&mut request, path, true)?;
        }
        if !(200..300).contains(&response.status) {
            return Err(Error::new(format!(
                "{method} {path} failed with status {} {}",
                response.status,
                snippet(&response.body)
            )));
        }
        Ok(response)
    }

    /// Sets bearer headers on `request` and sends it with transient retries.
    ///
    /// POST creates resources, so it retries only on 429; other methods also retry
    /// transport errors and 5xx. Each attempt gets a fresh `x-request-id`.
    fn send_with_token(
        &self,
        request: &mut HttpRequest,
        path: &str,
        force_token: bool,
    ) -> Result<HttpResponse, Error> {
        let token = self.access_token(force_token)?;
        let bearer = format!("Bearer {token}");
        let label = format!("{} {path}", request.method);
        let idempotent = request.method != "POST";
        log::debug!("{label}");
        retry::send(&label, idempotent, self.shutdown, self.delay, || {
            request.headers = vec![
                ("authorization".into(), bearer.clone()),
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into()),
                ("x-request-id".into(), Uuid::new_v4().to_string()),
            ];
            self.http.send(request)
        })
    }

    /// Returns a cached token, or fetches a new one while holding the mutex.
    fn lock_token(&self) -> std::sync::MutexGuard<'_, Option<CachedToken>> {
        self.token.lock().unwrap_or_else(|err| err.into_inner())
    }

    fn access_token(&self, force: bool) -> Result<String, Error> {
        let mut guard = self.lock_token();
        if !force
            && let Some(token) = guard.as_ref()
            && Instant::now() < token.refresh_at
        {
            return Ok(token.access_token.clone());
        }
        log::debug!("requesting access token");
        let fresh = self.fetch_token()?;
        let access = fresh.access_token.clone();
        *guard = Some(fresh);
        Ok(access)
    }

    /// POSTs the password grant to `auth_url` (secret is form-encoded, not logged).
    fn fetch_token(&self) -> Result<CachedToken, Error> {
        let body = form_encode(&[
            ("client_id", self.client_id),
            ("client_secret", self.client_secret),
            ("username", self.api_user),
            ("password", self.api_password),
            ("grant_type", "password"),
        ]);
        let request = HttpRequest {
            method: "POST".into(),
            url: self.auth_url.to_string(),
            headers: vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("accept".into(), "application/json".into()),
                ("x-request-id".into(), Uuid::new_v4().to_string()),
            ],
            body: Some(body.into_bytes()),
            timeout: Some(HTTP_TIMEOUT),
            max_body: Some(MAX_API_BODY),
        };
        // The password grant has no side effects, so it is safe to retry like a GET.
        let response = retry::send("POST token", true, self.shutdown, self.delay, || {
            self.http.send(&request)
        })?;
        if !(200..300).contains(&response.status) {
            return Err(Error::new(format!(
                "token request failed with status {}",
                response.status
            )));
        }
        let value: Value = match serde_json::from_slice(&response.body) {
            Ok(value) => value,
            Err(err) => return Err(Error::wrap("token json", err)),
        };
        let access = value
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::new("token response missing access_token"))?;
        let expires = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TOKEN_LIFETIME_SECS);
        Ok(CachedToken {
            access_token: access.to_string(),
            refresh_at: Instant::now()
                + Duration::from_secs(expires).saturating_sub(TOKEN_REFRESH_SKEW),
        })
    }
}

/// Percent-encodes a path segment for Contabo URLs (ids, names, zones).
pub fn encode_path_segment(value: &str) -> String {
    percent_encode(value)
}

/// Appends `page` and `size=100` to a list path.
fn with_page(path: &str, page: u64) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}page={page}&size={PAGE_SIZE}")
}

/// `application/x-www-form-urlencoded` body for the token request.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC 3986 unreserved bytes as-is; everything else as `%HH`.
fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// First 300 chars of a response body for error messages.
fn snippet(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(SNIPPET_CHARS)
        .collect::<String>()
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{Scripted, Sequence, TOKEN_BODY, client};
    use std::sync::Mutex;

    #[test]
    fn post_retries_only_rate_limits() {
        use serde_json::json;
        let http = Sequence::in_order(&[(200, TOKEN_BODY), (503, "busy")]);
        assert!(client(&http).post_json("/v1/x", &json!({})).is_err());
        assert_eq!(http.calls.lock().unwrap().len(), 2);

        let http = Sequence::in_order(&[(200, TOKEN_BODY), (429, "slow"), (201, "{}")]);
        client(&http).post_json("/v1/x", &json!({})).unwrap();
        assert_eq!(http.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn failed_token_refresh_after_unauthorized_is_an_error() {
        let http = Sequence::in_order(&[(200, TOKEN_BODY), (401, "expired"), (403, "denied")]);
        let err = client(&http).get_json("/v1/x").unwrap_err();
        assert!(
            err.to_string()
                .contains("token request failed with status 403")
        );
    }

    #[test]
    fn token_request_retries_server_errors() {
        let http = Sequence::in_order(&[(502, "down"), (200, TOKEN_BODY), (200, "{}")]);
        client(&http).get_json("/v1/x").unwrap();
        assert_eq!(http.calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn shutdown_skips_retries() {
        let stop = AtomicBool::new(true);
        let http = Sequence::in_order(&[(200, TOKEN_BODY), (500, "down"), (200, "{}")]);
        let api = client(&http).with_shutdown(&stop);
        assert!(std::ptr::eq(api.shutdown(), &stop));
        assert!(api.get_json("/v1/x").is_err());
        assert_eq!(http.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn encodes_form_secrets() {
        let body = form_encode(&[("password", "a b&c")]);
        assert_eq!(body, "password=a%20b%26c");
        assert!(!body.contains(' '));
        assert!(!body.contains('&'));
    }

    #[test]
    fn caches_token_and_pages() {
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            (
                "GET",
                "page=2",
                200,
                r#"{"_pagination":{"page":2,"totalPages":2},"data":[{"zoneName":"b.example"}]}"#,
            ),
            (
                "GET",
                "/v1/dns/zones",
                200,
                r#"{"_pagination":{"page":1,"totalPages":2},"data":[{"zoneName":"example.com"}]}"#,
            ),
        ]);
        let api = client(&http);
        let zones = api.list("/v1/dns/zones").unwrap();
        assert_eq!(zones.len(), 2);
        {
            let calls = http.calls.lock().unwrap();
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call.url.contains("/token"))
                    .count(),
                1
            );
            assert!(
                calls[1]
                    .headers
                    .iter()
                    .any(|(name, value)| name == "authorization" && value == "Bearer tok")
            );
            assert!(
                calls[1]
                    .headers
                    .iter()
                    .any(|(name, _)| name == "x-request-id")
            );
        }
        api.list("/v1/dns/zones").unwrap();
        let calls = http.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.url.contains("/token"))
                .count(),
            1
        );
    }

    #[test]
    fn refreshes_token_after_unauthorized() {
        let http = Sequence::in_order(&[
            (200, r#"{"access_token":"first","expires_in":3600}"#),
            (401, r#"{"message":"expired"}"#),
            (200, r#"{"access_token":"second","expires_in":3600}"#),
            (200, r#"{"data":[]}"#),
        ]);
        let api = client(&http);
        api.get_json("/v1/dns/zones?page=1&size=100").unwrap();
        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls[0].url.contains("/token"));
        assert!(calls[2].url.contains("/token"));
    }

    #[test]
    fn token_error_hides_secret() {
        let http = Scripted::new(vec![("POST", "/token", 401, "invalid s3cret-password")]);
        let api = client(&http);
        let err = api.get_json("/v1/dns/zones").unwrap_err().to_string();
        assert!(err.contains("status 401"));
        assert!(!err.contains("s3cret-password"));
    }

    #[test]
    fn empty_response_body_parses_as_null() {
        use serde_json::json;
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            ("PUT", "/v1/firewalls/fw-1", 200, ""),
        ]);
        let api = client(&http);
        assert!(
            api.put_json("/v1/firewalls/fw-1", &json!({}))
                .unwrap()
                .is_null()
        );
    }

    #[test]
    fn api_error_includes_response_snippet() {
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            ("GET", "/v1/missing", 500, "line1\nline2"),
        ]);
        let api = client(&http);
        let err = api.get_json("/v1/missing").unwrap_err();
        assert!(err.to_string().contains("500"));
        assert!(err.to_string().contains("line1"));
    }

    #[test]
    fn expired_token_is_requested_again() {
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"a","expires_in":0}"#,
            ),
            ("GET", "/v1/dns/zones", 200, r#"{"data":[]}"#),
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"b","expires_in":3600}"#,
            ),
            ("GET", "/v1/dns/zones", 200, r#"{"data":[]}"#),
        ]);
        let api = client(&http);
        api.get_json("/v1/dns/zones?page=1&size=100").unwrap();
        api.get_json("/v1/dns/zones?page=1&size=100").unwrap();
        let calls = http.calls.lock().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.url.contains("/token"))
                .count(),
            2
        );
    }

    #[test]
    fn reqwest_client_reads_local_response() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = br#"{"ok":true}"#;
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let http = ReqwestHttp::new(crate::config::TlsRoots::Both, false).unwrap();
        let response = http
            .send(&HttpRequest {
                method: "POST".into(),
                url: format!("http://{addr}/"),
                headers: vec![("accept".into(), "application/json".into())],
                body: Some(br#"{"x":1}"#.to_vec()),
                timeout: None,
                max_body: None,
            })
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, body.to_vec());

        let err = http
            .send(&HttpRequest {
                method: "\n".into(),
                url: format!("http://{addr}/"),
                headers: vec![],
                body: None,
                timeout: Some(Duration::from_secs(1)),
                max_body: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("http method"));
    }

    #[test]
    fn posts_patches_and_lists_empty_pages() {
        use serde_json::json;
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            ("POST", "/v1/dns/zones/example.com/records", 200, ""),
            ("PATCH", "/v1/dns/zones/example.com/records/9", 200, ""),
            (
                "GET",
                "/v1/dns/zones",
                200,
                r#"{"_pagination":{"totalPages":0},"data":[{"zoneName":"z"}]}"#,
            ),
        ]);
        let api = client(&http);
        assert!(
            api.post_json("/v1/dns/zones/example.com/records", &json!({"type": "A"}))
                .unwrap()
                .is_null()
        );
        assert!(
            api.patch_json(
                "/v1/dns/zones/example.com/records/9",
                &json!({"data": "1.1.1.1"})
            )
            .unwrap()
            .is_null()
        );
        assert_eq!(api.list("/v1/dns/zones").unwrap().len(), 1);
    }

    #[test]
    fn rejects_invalid_token_and_api_json() {
        let http = Scripted::new(vec![("POST", "/token", 200, "not-json")]);
        let err = client(&http)
            .get_json("/v1/dns/zones")
            .unwrap_err()
            .to_string();
        assert!(err.contains("token json"));

        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            ("GET", "/v1/zones", 200, "{not-json"),
        ]);
        let err = client(&http).get_json("/v1/zones").unwrap_err().to_string();
        assert!(err.contains("json from"));
    }

    #[test]
    fn scripted_falls_through_when_unmatched() {
        let http = Scripted::new(Vec::<(&str, &str, u16, &str)>::new());
        let err = http
            .send(&HttpRequest {
                method: "GET".into(),
                url: "https://example.test/nope".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("unexpected"));
    }

    #[test]
    fn sequence_errors_when_exhausted() {
        let http = Sequence {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(Vec::new()),
        };
        let err = http
            .send(&HttpRequest {
                method: "GET".into(),
                url: "https://example.test".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err();
        assert!(err.to_string().contains("no scripted response"));
    }

    #[test]
    fn retries_transient_status_then_succeeds() {
        let http = Sequence::in_order(&[
            (200, TOKEN_BODY),
            (500, "later"),
            (429, "slow"),
            (200, r#"{"data":[]}"#),
        ]);
        client(&http).get_json("/v1/dns/zones").unwrap();

        let http = Sequence::in_order(&[(200, TOKEN_BODY), (400, "bad")]);
        let api = client(&http);
        assert!(api.get_json("/v1/dns/zones").is_err());
        assert_eq!(http.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn pagination_over_the_page_cap_is_an_error() {
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            (
                "GET",
                "/v1/dns/zones",
                200,
                r#"{"data":[],"_pagination":{"totalPages":1001}}"#,
            ),
        ]);
        let err = client(&http).list("/v1/dns/zones").unwrap_err();
        assert!(err.to_string().contains("pagination"));
    }

    #[test]
    fn tls_root_modes_build_a_client() {
        use crate::config::TlsRoots;
        assert!(ReqwestHttp::new(TlsRoots::Both, false).is_ok());
        assert!(ReqwestHttp::new(TlsRoots::Webpki, false).is_ok());
        assert!(ReqwestHttp::new(TlsRoots::Native, true).is_ok());
    }

    #[test]
    fn echo_clients_are_bound_to_one_family() {
        let request = |url: &str| HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: vec![],
            body: None,
            timeout: Some(Duration::from_millis(200)),
            max_body: Some(64),
        };
        let v4 = ReqwestHttp::new(crate::config::TlsRoots::Both, false).unwrap();
        assert!(
            v4.send_family(&request("http://127.0.0.1:1/"), IpFamily::V4)
                .is_err()
        );
        assert!(
            v4.send_family(&request("http://[::1]:1/"), IpFamily::V6)
                .unwrap_err()
                .to_string()
                .contains("IPV6 is disabled")
        );
        let both = ReqwestHttp::new(crate::config::TlsRoots::Both, true).unwrap();
        assert!(
            both.send_family(&request("http://[::1]:1/"), IpFamily::V6)
                .is_err()
        );

        let client = build_client(crate::config::TlsRoots::Both, None).unwrap();
        let err = Error::new("build http client");
        assert!(assemble(Err(err), Ok(client.clone()), Ok(None)).is_err());
        assert!(
            assemble(
                Ok(client.clone()),
                Err(Error::new("build http client")),
                Ok(None),
            )
            .is_err()
        );
        assert!(
            assemble(
                Ok(client.clone()),
                Ok(client),
                Err(Error::new("build http client")),
            )
            .is_err()
        );
    }

    #[test]
    fn http_error_helpers() {
        let err = finish_with_resolver(Client::builder(), Err(Error::new("DNS setup failed")))
            .err()
            .unwrap();
        assert_eq!(err.to_string(), "DNS setup failed");
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let http = ReqwestHttp::new(crate::config::TlsRoots::Both, false).unwrap();
        let sink = crate::test_http::closing_endpoint();
        let dropped = http
            .send(&HttpRequest {
                method: "GET".into(),
                url: sink.clone(),
                headers: vec![],
                body: None,
                timeout: Some(Duration::from_secs(3)),
                max_body: None,
            })
            .unwrap_err();
        assert!(dropped.to_string().contains(&format!("http {sink}")));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n");
        });
        let short = http
            .send(&HttpRequest {
                method: "GET".into(),
                url: format!("http://{addr}/short"),
                headers: vec![],
                body: None,
                timeout: Some(Duration::from_secs(3)),
                max_body: None,
            })
            .unwrap_err();
        assert!(short.to_string().contains("read http body"));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\n0123456789abcdef",
            );
        });
        let huge = http
            .send(&HttpRequest {
                method: "GET".into(),
                url: format!("http://{addr}/huge"),
                headers: vec![],
                body: None,
                timeout: Some(Duration::from_secs(3)),
                max_body: Some(8),
            })
            .unwrap_err();
        assert!(huge.to_string().contains("exceeds 8 bytes"));

        let transport = Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
            .get(&sink)
            .send()
            .unwrap_err();
        let err = finish_build(Err(transport)).err().unwrap();
        assert!(err.to_string().contains("build http client"));
    }

    #[test]
    fn list_without_data_and_token_failures() {
        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            (
                "GET",
                "/v1/dns/zones",
                200,
                r#"{"_pagination":{"totalPages":1}}"#,
            ),
        ]);
        assert!(client(&http).list("/v1/dns/zones").unwrap().is_empty());

        let http = Scripted::new(vec![("POST", "/token", 200, "{}")]);
        assert!(
            client(&http)
                .get_json("/v1/dns/zones")
                .unwrap_err()
                .to_string()
                .contains("access_token")
        );

        let http = Scripted::new(Vec::<(&str, &str, u16, &str)>::new());
        assert!(client(&http).get_json("/v1/dns/zones").is_err());

        let http = Scripted::new(vec![
            (
                "POST",
                "/token",
                200,
                r#"{"access_token":"tok","expires_in":3600}"#,
            ),
            ("GET", "/v1/dns/zones", 200, r#"{"data":[]}"#),
        ]);
        let api = client(&http);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = api.token.lock().unwrap();
            panic!("poison token");
        }));
        assert!(api.get_json("/v1/dns/zones").is_ok());
    }
}
