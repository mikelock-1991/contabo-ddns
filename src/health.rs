//! Loopback `GET /health` for the container healthcheck.
//!
//! The static image has no shell and no HTTP client. The long-running process
//! listens on a loopback address, and `contabo-ddns health` performs the GET
//! from the Docker `HEALTHCHECK` instruction.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::Error;

const PATH: &str = "/health";
const BODY: &str = "ok";
const MAX_REQUEST: usize = 2048;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// `contabo-ddns health` probes the listener. Any other argv serves it.
#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    /// Long-running sync process.
    Serve,
    /// One GET, then exit.
    Probe,
}

/// Selects probe mode only when the sole argument is `health`.
pub fn mode<I, S>(args: I) -> Mode
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    match args.next() {
        Some(arg) if arg.as_ref() == "health" && args.next().is_none() => Mode::Probe,
        _ => Mode::Serve,
    }
}

/// Accepts a loopback socket address. Port 0 is allowed only for ephemeral test binds.
pub fn parse_bind(value: &str, ephemeral: bool) -> Result<SocketAddr, Error> {
    let trimmed = value.trim();
    let addr: SocketAddr = match trimmed.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(reject_bind(trimmed)),
    };
    if !is_loopback(addr.ip()) {
        return Err(Error::new("HEALTHCHECK_BIND must use a loopback address"));
    }
    if addr.port() == 0 && !ephemeral {
        return Err(Error::new("HEALTHCHECK_BIND port must be 1-65535"));
    }
    Ok(addr)
}

/// Loopback IPv4 (127.0.0.0/8) or IPv6 `::1`. Mapped and unspecified addresses are rejected.
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

/// Error text for a value that is not a socket address. The preview is capped.
fn reject_bind(value: &str) -> Error {
    let mut shown: String = value.chars().take(64).collect();
    if value.chars().count() > 64 {
        shown.push('…');
    }
    Error::new(format!(
        "HEALTHCHECK_BIND must be a loopback socket address, not {shown}"
    ))
}

/// Resolves the process bind address from `HEALTHCHECK_BIND` or the default.
fn bind_from(
    value: Result<String, std::env::VarError>,
    ephemeral: bool,
) -> Result<SocketAddr, Error> {
    let default = if ephemeral {
        "127.0.0.1:0"
    } else {
        DEFAULT_BIND
    };
    match value {
        Ok(value) => parse_bind(&value, ephemeral),
        Err(std::env::VarError::NotPresent) => parse_bind(default, ephemeral),
        Err(err) => Err(Error::wrap("HEALTHCHECK_BIND", err)),
    }
}

/// Bind address for this process. Tests use an ephemeral port unless overridden.
fn configured_bind() -> Result<SocketAddr, Error> {
    #[cfg(test)]
    if let Some(value) = BIND_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return parse_bind(&value, true);
    }
    select_bind(std::env::var("HEALTHCHECK_BIND"), cfg!(test))
}

/// Ephemeral binds keep parallel tests off port 8080. A real process uses `HEALTHCHECK_BIND`.
fn select_bind(
    value: Result<String, std::env::VarError>,
    ephemeral: bool,
) -> Result<SocketAddr, Error> {
    if ephemeral {
        return parse_bind("127.0.0.1:0", true);
    }
    bind_from(value, false)
}

/// Background listener. Dropping it stops the accept thread.
pub struct Server {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Address the listener actually bound, including an ephemeral port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    /// Unblocks `accept` and waits for the thread to leave the loop.
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, IO_TIMEOUT);
        join_thread(self.thread.take());
    }
}

/// Waits for the accept thread. `None` is the already-joined case.
fn join_thread(thread: Option<JoinHandle<()>>) {
    if let Some(thread) = thread {
        let _ = thread.join();
    }
}

/// Starts the loopback listener.
pub fn serve(addr: SocketAddr) -> Result<Server, Error> {
    if !is_loopback(addr.ip()) {
        return Err(Error::new("healthcheck address must be loopback"));
    }
    let listener = TcpListener::bind(addr).map_err(|err| Error::wrap("bind healthcheck", err))?;
    let bound = published_addr(listener.local_addr(), addr);
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&shutdown);
    let thread = thread::spawn(move || accept_loop(listener, flag));
    Ok(Server {
        addr: bound,
        shutdown,
        thread: Some(thread),
    })
}

/// Uses the bound address when the OS reports it, otherwise the requested one.
fn published_addr(local: io::Result<SocketAddr>, requested: SocketAddr) -> SocketAddr {
    match local {
        Ok(addr) => addr,
        Err(_) => requested,
    }
}

/// Listens until shutdown. One connection is handled at a time.
fn accept_loop(listener: TcpListener, shutdown: Arc<AtomicBool>) {
    loop {
        if handle_accept(&shutdown, listener.accept()) == Loop::Stop {
            break;
        }
    }
}

/// Continue after a handled connection or an interrupted accept. Stop on shutdown or a real error.
fn handle_accept(shutdown: &AtomicBool, accepted: io::Result<(TcpStream, SocketAddr)>) -> Loop {
    if shutdown.load(Ordering::Acquire) {
        return Loop::Stop;
    }
    match accepted {
        Ok((stream, _)) => {
            let _ = respond(stream);
            Loop::Continue
        }
        Err(err) if err.kind() == ErrorKind::Interrupted => Loop::Continue,
        Err(err) => {
            log::warn!("healthcheck accept: {err}");
            Loop::Stop
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Loop {
    Continue,
    Stop,
}

/// Starts the listener from the process configuration.
pub fn serve_configured() -> Result<Server, Error> {
    serve(configured_bind()?)
}

/// Reads one request and writes one response, then the caller closes the socket.
fn respond(mut stream: TcpStream) -> io::Result<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_nodelay(true);
    respond_io(&mut stream)
}

/// Serves one request on any reader and writer.
fn respond_io(stream: &mut (impl Read + Write)) -> io::Result<()> {
    let decision = match read_until(stream, MAX_REQUEST, b"\r\n\r\n") {
        Ok(buf) => match std::str::from_utf8(&buf) {
            Ok(text) => route(text),
            Err(_) => Decision::BadRequest,
        },
        Err(_) => Decision::BadRequest,
    };
    stream.write_all(&encode(decision))
}

/// `GET /health` is the only successful request. Nothing from the request is copied into the response.
fn route(raw: &str) -> Decision {
    let Some(line) = raw.lines().next() else {
        return Decision::BadRequest;
    };
    let (method, target, version, extra) = request_parts(line.split(' '));
    if extra || (version != "HTTP/1.0" && version != "HTTP/1.1") {
        return Decision::BadRequest;
    }
    if method != "GET" {
        return Decision::MethodNotAllowed;
    }
    if target != PATH {
        return Decision::NotFound;
    }
    Decision::Ok
}

/// Method, path, version, and whether a fourth token was present.
fn request_parts<'a, I>(mut parts: I) -> (&'a str, &'a str, &'a str, bool)
where
    I: Iterator<Item = &'a str>,
{
    (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().is_some(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    Ok,
    NotFound,
    MethodNotAllowed,
    BadRequest,
}

/// Fixed response bytes. Headers do not echo the request.
fn encode(decision: Decision) -> Vec<u8> {
    let (status, reason, extra, body) = match decision {
        Decision::Ok => (200, "OK", "", BODY),
        Decision::NotFound => (404, "Not Found", "", ""),
        Decision::MethodNotAllowed => (405, "Method Not Allowed", "Allow: GET\r\n", ""),
        Decision::BadRequest => (400, "Bad Request", "", ""),
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {len}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n{extra}Connection: close\r\n\r\n{body}",
        len = body.len(),
    )
    .into_bytes()
}

/// Reads until `marker` or `limit` bytes. A request without the header terminator is rejected.
fn read_until(
    reader: &mut (impl Read + ?Sized),
    limit: usize,
    marker: &[u8],
) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; limit];
    let mut filled = 0;
    loop {
        if filled >= limit {
            return Err(io::Error::new(ErrorKind::InvalidData, "request too large"));
        }
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "request closed early",
                ));
            }
            Ok(n) => {
                filled += n;
                if buf[..filled]
                    .windows(marker.len())
                    .any(|window| window == marker)
                {
                    buf.truncate(filled);
                    return Ok(buf);
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
}

/// GETs `/health` on a loopback address and requires `200` with body `ok`.
pub fn probe(addr: SocketAddr) -> Result<(), Error> {
    if !is_loopback(addr.ip()) {
        return Err(Error::new("healthcheck address must be loopback"));
    }
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .map_err(|err| Error::wrap("connect healthcheck", err))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    exchange(&mut stream)
}

/// Sends `GET /health` and accepts only the exact success response.
fn exchange(stream: &mut dyn ProbeIo) -> Result<(), Error> {
    send_probe(stream)?;
    let bytes = recv_probe(stream)?;
    let (status, body) = split_response(&bytes)?;
    assess(status, body)
}

/// One stream used for both directions of the healthcheck probe.
trait ProbeIo: Read + Write {}

impl<T: Read + Write> ProbeIo for T {}

/// Writes the single healthcheck request.
fn send_probe(stream: &mut dyn Write) -> Result<(), Error> {
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|err| Error::wrap("write healthcheck", err))
}

/// Reads one HTTP response from the healthcheck listener.
fn recv_probe(stream: &mut dyn Read) -> Result<Vec<u8>, Error> {
    read_message(stream).map_err(|err| Error::wrap("read healthcheck", err))
}

/// Index of the header terminator, if the buffer contains one.
fn header_end(buf: &[u8]) -> Result<usize, io::Error> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "missing header end"))
}

/// `Content-Length` from a header block, compared without regard to case.
fn content_length(head: &str) -> Result<usize, io::Error> {
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse()
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "bad content-length"));
        }
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        "missing content-length",
    ))
}

/// Reads the headers and exactly `Content-Length` body bytes.
fn read_message(reader: &mut (impl Read + ?Sized)) -> io::Result<Vec<u8>> {
    let buf = read_until(reader, MAX_REQUEST, b"\r\n\r\n")?;
    finish_message(buf, reader)
}

/// Completes a header buffer with the declared body.
fn finish_message(mut buf: Vec<u8>, reader: &mut (impl Read + ?Sized)) -> io::Result<Vec<u8>> {
    let marker = header_end(&buf)?;
    let head = std::str::from_utf8(&buf[..marker])
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "headers are not utf-8"))?;
    let length = content_length(head)?;
    let total = marker
        .checked_add(4)
        .and_then(|headers| headers.checked_add(length))
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "response too large"))?;
    if total > MAX_REQUEST {
        return Err(io::Error::new(ErrorKind::InvalidData, "response too large"));
    }
    while buf.len() < total {
        let mut tmp = [0u8; 256];
        match reader.read(&mut tmp) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "body closed early",
                ));
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    buf.truncate(total);
    Ok(buf)
}

/// Status line and body split on the header terminator.
fn split_response(bytes: &[u8]) -> Result<(u16, &str), Error> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::new("healthcheck response is not utf-8"))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| Error::new("healthcheck response has no header end"))?;
    let status_line = head.lines().next().unwrap_or("");
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(Error::new("healthcheck response has a bad status line"));
    }
    let status = code
        .parse()
        .map_err(|_| Error::new("healthcheck response has a bad status code"))?;
    Ok((status, body))
}

/// Success is only HTTP 200 with the exact body.
fn assess(status: u16, body: &str) -> Result<(), Error> {
    if status != 200 {
        return Err(Error::new(format!("healthcheck returned {status}")));
    }
    if body != BODY {
        return Err(Error::new("healthcheck returned an unexpected body"));
    }
    Ok(())
}

/// Probes the configured address. Exit 0 on success, 1 on failure.
pub fn run_probe() -> ExitCode {
    exit_from_probe(configured_bind().and_then(probe))
}

/// Maps a probe result to a process exit code and prints a failure on stderr.
fn exit_from_probe(result: Result<(), Error>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("healthcheck: {err}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
thread_local! {
    static BIND_OVERRIDE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Sets the bind address used by [`configured_bind`] on this thread.
#[cfg(test)]
pub(crate) struct BindOverride;

#[cfg(test)]
pub(crate) fn override_bind(value: Option<String>) -> BindOverride {
    BIND_OVERRIDE.with(|slot| *slot.borrow_mut() = value);
    BindOverride
}

#[cfg(test)]
impl Drop for BindOverride {
    fn drop(&mut self) {
        BIND_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_BIND, Decision, Loop, Mode, assess, bind_from, content_length, encode, exchange,
        exit_from_probe, finish_message, handle_accept, header_end, is_loopback, join_thread, mode,
        parse_bind, probe, published_addr, read_message, read_until, recv_probe, request_parts,
        respond_io, route, run_probe, select_bind, send_probe, serve, serve_configured,
        split_response,
    };
    use crate::error::Error;
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Script {
        reads: Vec<io::Result<Vec<u8>>>,
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.reads.is_empty() {
                return Ok(0);
            }
            match self.reads.remove(0) {
                Err(err) => Err(err),
                Ok(bytes) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
            }
        }
    }

    struct Mem {
        read: Script,
        fail_write: bool,
        written: Vec<u8>,
    }

    impl Read for Mem {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read.read(buf)
        }
    }

    impl Write for Mem {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::other("full"));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn request(raw: &str) -> Mem {
        Mem {
            read: Script {
                reads: vec![Ok(raw.as_bytes().to_vec())],
            },
            fail_write: false,
            written: Vec::new(),
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn mode_is_probe_only_for_a_single_health_argument() {
        assert_eq!(mode(["contabo-ddns", "health"]), Mode::Probe);
        assert_eq!(mode(std::iter::empty::<&str>()), Mode::Serve);
        assert_eq!(mode(["contabo-ddns"]), Mode::Serve);
        assert_eq!(mode(["contabo-ddns", "sync"]), Mode::Serve);
        assert_eq!(mode(["contabo-ddns", "health", "now"]), Mode::Serve);
    }

    #[test]
    fn parse_bind_accepts_only_loopback() {
        assert_eq!(
            parse_bind(" 127.0.0.1:8080 ", false).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            parse_bind("[::1]:8080", false).unwrap(),
            "[::1]:8080".parse().unwrap()
        );
        assert!(parse_bind("127.0.0.1:0", true).is_ok());
        assert!(is_loopback(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_loopback(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)));
        let public = parse_bind("192.0.2.10:8080", false).unwrap_err();
        assert_eq!(
            public.to_string(),
            "HEALTHCHECK_BIND must use a loopback address"
        );
        assert!(parse_bind("0.0.0.0:8080", false).is_err());
        assert!(parse_bind("[::]:8080", false).is_err());
        assert!(parse_bind("127.0.0.1:0", false).is_err());
        let missing = parse_bind("127.0.0.1", false).unwrap_err();
        assert!(missing.to_string().contains("not 127.0.0.1"));
        let long = "x".repeat(65);
        assert!(
            parse_bind(&long, false)
                .unwrap_err()
                .to_string()
                .contains('…')
        );
        assert_eq!(
            select_bind(Err(std::env::VarError::NotPresent), false)
                .unwrap()
                .to_string(),
            DEFAULT_BIND
        );
        assert_eq!(
            select_bind(Err(std::env::VarError::NotPresent), true)
                .unwrap()
                .port(),
            0
        );
    }

    #[test]
    fn bind_from_uses_the_default_or_the_env_value() {
        assert_eq!(
            bind_from(Ok("127.0.0.1:9".into()), false).unwrap(),
            "127.0.0.1:9".parse().unwrap()
        );
        assert_eq!(
            bind_from(Err(std::env::VarError::NotPresent), false)
                .unwrap()
                .to_string(),
            DEFAULT_BIND
        );
        assert_eq!(
            bind_from(Err(std::env::VarError::NotPresent), true)
                .unwrap()
                .port(),
            0
        );
        assert!(bind_from(Ok("nope".into()), false).is_err());
        let unicode = bind_from(
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "a",
            ))),
            false,
        )
        .unwrap_err();
        assert!(unicode.to_string().starts_with("HEALTHCHECK_BIND:"));
    }

    #[test]
    fn route_allows_only_get_health() {
        assert_eq!(route("GET /health HTTP/1.1\r\n\r\n"), Decision::Ok);
        assert_eq!(
            route("GET /health HTTP/1.0\r\nHost: x\r\n\r\n"),
            Decision::Ok
        );
        assert_eq!(
            route("POST /health HTTP/1.1\r\n\r\n"),
            Decision::MethodNotAllowed
        );
        assert_eq!(
            route("get /health HTTP/1.1\r\n\r\n"),
            Decision::MethodNotAllowed
        );
        assert_eq!(route("GET / HTTP/1.1\r\n\r\n"), Decision::NotFound);
        assert_eq!(
            route("GET /health?x=1 HTTP/1.1\r\n\r\n"),
            Decision::NotFound
        );
        assert_eq!(
            route("GET http://127.0.0.1/health HTTP/1.1\r\n\r\n"),
            Decision::NotFound
        );
        assert_eq!(route("GET /health HTTP/2\r\n\r\n"), Decision::BadRequest);
        assert_eq!(route("GET /health\r\n\r\n"), Decision::BadRequest);
        assert_eq!(
            route("GET /health HTTP/1.1 extra\r\n\r\n"),
            Decision::BadRequest
        );
        assert_eq!(route(""), Decision::BadRequest);
        assert_eq!(request_parts(std::iter::empty()), ("", "", "", false));
        assert_eq!(
            request_parts(["GET", "/health", "HTTP/1.1"].into_iter()),
            ("GET", "/health", "HTTP/1.1", false)
        );
        assert_eq!(
            request_parts(["GET", "/health", "HTTP/1.1", "extra"].into_iter()),
            ("GET", "/health", "HTTP/1.1", true)
        );
    }

    #[test]
    fn encoded_responses_do_not_echo_the_request() {
        let mut ok = request("GET /health HTTP/1.1\r\nX-Secret: hunter2\r\n\r\n");
        respond_io(&mut ok).unwrap();
        ok.flush().unwrap();
        let ok_text = text(&ok.written);
        assert!(ok_text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(ok_text.ends_with("\r\n\r\nok"));
        assert!(ok_text.contains("Cache-Control: no-store"));
        assert!(ok_text.contains("X-Content-Type-Options: nosniff"));
        assert!(!ok_text.contains("hunter2"));
        assert!(!ok_text.contains("Server:"));

        let mut missing = request("GET /other HTTP/1.1\r\n\r\n");
        respond_io(&mut missing).unwrap();
        assert!(text(&missing.written).starts_with("HTTP/1.1 404 Not Found\r\n"));

        let mut method = request("POST /health HTTP/1.1\r\n\r\n");
        respond_io(&mut method).unwrap();
        let method_text = text(&method.written);
        assert!(method_text.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(method_text.contains("Allow: GET\r\n"));

        let mut bad = request("");
        respond_io(&mut bad).unwrap();
        assert!(text(&bad.written).starts_with("HTTP/1.1 400 Bad Request\r\n"));

        let mut binary = Mem {
            read: Script {
                reads: vec![Ok(vec![0xff, b'\r', b'\n', b'\r', b'\n'])],
            },
            fail_write: false,
            written: Vec::new(),
        };
        respond_io(&mut binary).unwrap();
        assert!(text(&binary.written).starts_with("HTTP/1.1 400 Bad Request\r\n"));

        let mut full = request("GET /health HTTP/1.1\r\n\r\n");
        full.fail_write = true;
        assert!(respond_io(&mut full).is_err());
        assert_eq!(
            encode(Decision::NotFound).windows(3).next(),
            Some(b"HTT".as_ref())
        );
    }

    #[test]
    fn read_until_stops_at_the_marker_and_rejects_bad_streams() {
        let raw = b"GET /health HTTP/1.1\r\n\r\n";
        let mut reader = Script {
            reads: vec![
                Err(io::Error::new(ErrorKind::Interrupted, "again")),
                Ok(raw.to_vec()),
            ],
        };
        assert_eq!(read_until(&mut reader, 64, b"\r\n\r\n").unwrap(), raw);

        let mut closed = Script { reads: vec![] };
        let eof = read_until(&mut closed, 64, b"\r\n\r\n").unwrap_err();
        assert_eq!(eof.kind(), ErrorKind::UnexpectedEof);

        let mut huge = Script {
            reads: vec![Ok(vec![b'a'; 80])],
        };
        let large = read_until(&mut huge, 8, b"\r\n\r\n").unwrap_err();
        assert_eq!(large.kind(), ErrorKind::InvalidData);

        let mut timed = Script {
            reads: vec![Err(io::Error::new(ErrorKind::TimedOut, "slow"))],
        };
        assert_eq!(
            read_until(&mut timed, 64, b"\r\n\r\n").unwrap_err().kind(),
            ErrorKind::TimedOut
        );
    }

    #[test]
    fn message_reader_requires_a_complete_body() {
        let whole = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut one = Script {
            reads: vec![Ok(whole.to_vec())],
        };
        assert_eq!(read_message(&mut one).unwrap(), whole);

        let mut split = Script {
            reads: vec![
                Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec()),
                Err(io::Error::new(ErrorKind::Interrupted, "again")),
                Ok(b"ok-extra".to_vec()),
            ],
        };
        assert_eq!(read_message(&mut split).unwrap(), whole);

        let mut closed = Script {
            reads: vec![Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec())],
        };
        assert_eq!(
            read_message(&mut closed).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        let mut slow = Script {
            reads: vec![
                Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec()),
                Err(io::Error::new(ErrorKind::TimedOut, "slow")),
            ],
        };
        assert_eq!(
            read_message(&mut slow).unwrap_err().kind(),
            ErrorKind::TimedOut
        );

        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".to_vec();
        assert!(header_end(&headers).is_ok());
        assert!(header_end(b"none").is_err());
        assert_eq!(
            content_length("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nnote\r\n").unwrap(),
            2
        );
        assert!(content_length("HTTP/1.1 200 OK\r\nContent-Length: no\r\n").is_err());
        assert!(content_length("HTTP/1.1 200 OK\r\n\r\n").is_err());
        let bad_headers = vec![0xff, b'\r', b'\n', b'\r', b'\n'];
        assert!(finish_message(bad_headers, &mut Script { reads: vec![] }).is_err());
        assert!(finish_message(b"no marker".to_vec(), &mut Script { reads: vec![] }).is_err());
        let huge = b"HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n".to_vec();
        assert!(finish_message(huge, &mut Script { reads: vec![] }).is_err());
        let overflow = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", usize::MAX);
        assert!(finish_message(overflow.into_bytes(), &mut Script { reads: vec![] }).is_err());
        assert!(
            finish_message(
                b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
                &mut Script { reads: vec![] }
            )
            .is_err()
        );
    }

    #[test]
    fn listener_answers_get_and_stops_on_drop() {
        let server = serve(parse_bind("127.0.0.1:0", true).unwrap()).unwrap();
        probe(server.addr()).unwrap();
        let mut client = std::net::TcpStream::connect(server.addr()).unwrap();
        client.write_all(b"POST /health HTTP/1.1\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).unwrap();
        assert!(text(&buf).starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        let addr = server.addr();
        drop(server);
        let refused = probe(addr).unwrap_err();
        assert!(refused.to_string().contains("connect healthcheck"));
    }

    #[test]
    fn probe_rejects_non_loopback_and_bad_responses() {
        let remote: SocketAddr = "192.0.2.10:80".parse().unwrap();
        assert!(probe(remote).unwrap_err().to_string().contains("loopback"));
        assert!(serve(remote).is_err());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let occupied = listener.local_addr().unwrap();
        let mut saw_bind_error = false;
        let _ = serve(occupied).inspect_err(|err| {
            saw_bind_error = err.to_string().contains("bind healthcheck");
        });
        assert!(saw_bind_error);
        assert_eq!(published_addr(Ok(occupied), remote), occupied);
        assert_eq!(
            published_addr(Err(io::Error::other("missing")), remote),
            remote
        );

        let (status, body) = split_response(b"HTTP/1.1 200 OK\r\n\r\nok").unwrap();
        assert_eq!((status, body), (200, "ok"));
        assert!(split_response(&[0xff]).is_err());
        assert!(split_response(b"HTTP/1.1 200 OK").is_err());
        assert!(split_response(b"NOTHTTP 200 OK\r\n\r\nok").is_err());
        assert!(split_response(b"HTTP/1.1 xyz OK\r\n\r\nok").is_err());
        assert!(assess(503, "ok").is_err());
        assert!(assess(200, "no").is_err());
        assert!(assess(200, "ok").is_ok());
        assert_eq!(exit_from_probe(Ok(())), ExitCode::SUCCESS);
        assert_eq!(exit_from_probe(Err(Error::new("down"))), ExitCode::from(1));
    }

    #[test]
    fn accept_classification_stops_on_shutdown_and_errors() {
        crate::logsetup::discard_output();
        let stop = AtomicBool::new(true);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let accepted = listener.accept().unwrap();
        assert_eq!(handle_accept(&stop, Ok(accepted)), Loop::Stop);
        stop.store(false, Ordering::Release);
        assert_eq!(
            handle_accept(&stop, Err(io::Error::new(ErrorKind::Interrupted, "signal"))),
            Loop::Continue
        );
        assert_eq!(
            handle_accept(&stop, Err(io::Error::other("closed"))),
            Loop::Stop
        );
        join_thread(None);
        join_thread(Some(std::thread::spawn(|| {})));
        let mut sink = Mem {
            read: Script { reads: vec![] },
            fail_write: true,
            written: Vec::new(),
        };
        assert!(send_probe(&mut sink).is_err());
        assert!(exchange(&mut sink).is_err());
        let mut closed = Mem {
            read: Script { reads: vec![] },
            fail_write: false,
            written: Vec::new(),
        };
        assert!(exchange(&mut closed).is_err());
        let mut bad = Mem {
            read: Script {
                reads: vec![Ok(b"NOTHTTP 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec())],
            },
            fail_write: false,
            written: Vec::new(),
        };
        assert!(exchange(&mut bad).is_err());
        let mut closed_read = Script { reads: vec![] };
        assert!(recv_probe(&mut closed_read).is_err());
    }

    #[test]
    fn configured_server_is_probed_by_the_health_command() {
        let server = serve_configured().unwrap();
        let _guard = super::override_bind(Some(server.addr().to_string()));
        assert_eq!(run_probe(), ExitCode::SUCCESS);
        drop(server);
        assert_eq!(run_probe(), ExitCode::from(1));
    }
}
