//! Public-IP fetch and firewall source resolution (CIDR, hostname, `current`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::contabo::{Http, HttpRequest, IpFamily};
use crate::error::Error;
use crate::retry;

/// Addresses learned from the echo services for one cycle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicIps {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

/// IPv4 and IPv6 CIDR strings for one firewall rule.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SourceLists {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

/// Looks up A and AAAA records for a hostname. Must be safe to call from DNS/firewall threads.
pub trait Resolver: Send + Sync {
    /// Returns unique IPv4 addresses for `host`, or an error if lookup fails.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error>;
    /// Returns unique IPv6 addresses for `host`, or an error if lookup fails.
    fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error>;
}

/// Resolver that uses the OS `getaddrinfo` / `ToSocketAddrs` path.
pub struct SystemResolver;

/// Keeps unique IPv4 addresses from a socket-addr iterator; errors if none remain.
pub(crate) fn ipv4_from_addresses(
    host: &str,
    addresses: Vec<std::net::SocketAddr>,
) -> Result<Vec<Ipv4Addr>, Error> {
    let mut found = Vec::new();
    for address in addresses {
        if let IpAddr::V4(ip) = address.ip()
            && !found.contains(&ip)
        {
            found.push(ip);
        }
    }
    if found.is_empty() {
        Err(Error::new(format!("no A record for {host}")))
    } else {
        Ok(found)
    }
}

/// Keeps unique IPv6 addresses from a socket-addr iterator; errors if none remain.
pub(crate) fn ipv6_from_addresses(
    host: &str,
    addresses: Vec<std::net::SocketAddr>,
) -> Result<Vec<Ipv6Addr>, Error> {
    let mut found = Vec::new();
    for address in addresses {
        if let IpAddr::V6(ip) = address.ip()
            && !found.contains(&ip)
        {
            found.push(ip);
        }
    }
    if found.is_empty() {
        Err(Error::new(format!("no AAAA record for {host}")))
    } else {
        Ok(found)
    }
}

impl Resolver for SystemResolver {
    /// Resolves `host` through the operating system and filters to IPv4.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
        let addresses = lookup_socket_addrs(host)?;
        ipv4_from_addresses(host, addresses)
    }

    /// Resolves `host` through the operating system and filters to IPv6.
    fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error> {
        let addresses = lookup_socket_addrs(host)?;
        ipv6_from_addresses(host, addresses)
    }
}

fn lookup_socket_addrs(host: &str) -> Result<Vec<std::net::SocketAddr>, Error> {
    (host, 0u16)
        .to_socket_addrs()
        .map(|addresses| addresses.collect())
        .map_err(|err| Error::new(format!("resolve {host}: {err}")))
}

/// Tries each IPv4 echo URL in order. Skips answers that `is_publishable` rejects.
pub fn fetch_public_ip(
    http: &dyn Http,
    urls: &[String],
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
) -> Result<Ipv4Addr, Error> {
    fetch_parsed(
        http,
        urls,
        timeout,
        shutdown,
        delay,
        EchoLabels {
            empty: "IP_ECHO_URL",
            failure: "public ip lookup failed",
            family: IpFamily::V4,
        },
        &decide_v4,
    )
}

/// Tries each echo URL over IPv6 only. Skips answers that `is_publishable_v6` rejects.
pub fn fetch_public_ipv6(
    http: &dyn Http,
    urls: &[String],
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
) -> Result<Ipv6Addr, Error> {
    fetch_parsed(
        http,
        urls,
        timeout,
        shutdown,
        delay,
        EchoLabels {
            empty: "IP_ECHO_URL",
            failure: "public ipv6 lookup failed",
            family: IpFamily::V6,
        },
        &decide_v6,
    )
}

enum Parsed<T> {
    Keep(T),
    Refuse(String),
}

fn decide_v4(body: &str) -> Result<Parsed<Ipv4Addr>, Error> {
    let ip = parse_public_ip(body)?;
    if is_publishable(ip) {
        Ok(Parsed::Keep(ip))
    } else {
        Ok(Parsed::Refuse(ip.to_string()))
    }
}

fn decide_v6(body: &str) -> Result<Parsed<Ipv6Addr>, Error> {
    let ip = parse_public_ipv6(body)?;
    if is_publishable_v6(ip) {
        Ok(Parsed::Keep(ip))
    } else {
        Ok(Parsed::Refuse(ip.to_string()))
    }
}

struct EchoLabels<'a> {
    empty: &'a str,
    failure: &'a str,
    family: IpFamily,
}

fn fetch_parsed<T>(
    http: &dyn Http,
    urls: &[String],
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
    labels: EchoLabels<'_>,
    decide: &dyn Fn(&str) -> Result<Parsed<T>, Error>,
) -> Result<T, Error> {
    if urls.is_empty() {
        return Err(Error::new(format!("{} is empty", labels.empty)));
    }
    let mut errors = Vec::new();
    for url in urls {
        match fetch_one_body(http, url, timeout, shutdown, delay, labels.family) {
            Ok(body) => match decide(&body) {
                Ok(Parsed::Keep(ip)) => return Ok(ip),
                Ok(Parsed::Refuse(ip)) => {
                    errors.push(format!("{url}: refused non-public address {ip}"));
                }
                Err(err) => errors.push(format!("{url}: {err}")),
            },
            Err(err) => errors.push(format!("{url}: {err}")),
        }
    }
    Err(Error::new(format!(
        "{}: {}",
        labels.failure,
        errors.join("; ")
    )))
}

/// True when an address is safe to publish.
///
/// Rejects private, loopback, unspecified, link-local, broadcast, multicast,
/// carrier-grade NAT (100.64.0.0/10), and benchmarking (198.18.0.0/15) addresses.
pub fn is_publishable(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    let shared = first == 100 && (64..128).contains(&second);
    let benchmarking = first == 198 && (second == 18 || second == 19);
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && !shared
        && !benchmarking
}

/// GETs one echo URL with transient retries and returns the trimmed body.
fn fetch_one_body(
    http: &dyn Http,
    url: &str,
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
    family: IpFamily,
) -> Result<String, Error> {
    let request = HttpRequest {
        method: "GET".into(),
        url: url.to_string(),
        headers: vec![("accept".into(), "text/plain".into())],
        body: None,
        timeout: Some(timeout),
        max_body: Some(crate::contabo::MAX_ECHO_BODY),
    };
    let response = retry::send(&format!("GET {url}"), true, shutdown, delay, || {
        http.send_family(&request, family)
    })?;
    if !(200..300).contains(&response.status) {
        return Err(Error::new(format!("ipecho status {}", response.status)));
    }
    Ok(String::from_utf8_lossy(&response.body).into_owned())
}

/// Parses a trimmed IPv4 address from an ipecho-style body.
pub fn parse_public_ip(body: &str) -> Result<Ipv4Addr, Error> {
    let text = body.trim();
    text.parse::<Ipv4Addr>()
        .map_err(|_| Error::new(format!("ipecho returned {:?}", truncate(text, 80))))
}

/// Parses a trimmed IPv6 address from an ipecho-style body.
pub fn parse_public_ipv6(body: &str) -> Result<Ipv6Addr, Error> {
    let text = body.trim();
    text.parse::<Ipv6Addr>()
        .map_err(|_| Error::new(format!("ipecho returned {:?}", truncate(text, 80))))
}

/// True when an IPv6 address is safe to publish.
///
/// Rejects loopback, unspecified, multicast, link-local, unique-local,
/// documentation (`2001:db8::/32`), benchmarking (`2001:2::/48`), discard-only
/// (`100::/64`), and IPv4-mapped addresses.
pub fn is_publishable_v6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_unicast_link_local()
        && !ip.is_unique_local()
        && !is_ipv6_documentation(ip)
        && !is_ipv6_benchmarking(ip)
        && !is_ipv6_discard(ip)
        && !is_ipv4_mapped(ip)
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();
    first == 0x2001 && second == 0x0db8
}

fn is_ipv4_mapped(ip: Ipv6Addr) -> bool {
    let [a, b, c, d, e, f, _, _] = ip.segments();
    a == 0 && b == 0 && c == 0 && d == 0 && e == 0 && f == 0xffff
}

fn is_ipv6_benchmarking(ip: Ipv6Addr) -> bool {
    let [first, second, third, ..] = ip.segments();
    first == 0x2001 && second == 0x0002 && third == 0
}

fn is_ipv6_discard(ip: Ipv6Addr) -> bool {
    let [first, second, third, fourth, ..] = ip.segments();
    first == 0x0100 && second == 0 && third == 0 && fourth == 0
}

/// Turns configured sources into unique CIDR strings, split by family.
///
/// Accepts IPv4, IPv6, CIDR, `current`, `current6`, or a hostname. A hostname
/// contributes one `/32` per A record and one `/128` per AAAA record. A family
/// with no resolved sources is left empty so the caller can keep that firewall
/// list unchanged. An empty result fails closed.
pub fn resolve_sources(
    sources: &[String],
    current: PublicIps,
    resolver: &dyn Resolver,
) -> Result<SourceLists, Error> {
    let mut resolved = SourceLists::default();
    for source in sources {
        let source = source.trim();
        if source.is_empty() {
            return Err(Error::new("empty firewall source"));
        }
        if source == "current" {
            let ip = current
                .v4
                .ok_or_else(|| Error::new("current source used without a public IP"))?;
            push_unique(&mut resolved.v4, format!("{ip}/32"));
            continue;
        }
        if source == "current6" {
            let ip = current
                .v6
                .ok_or_else(|| Error::new("current6 source used without a public IPv6"))?;
            push_unique(&mut resolved.v6, format!("{ip}/128"));
            continue;
        }
        if source.contains(':') {
            push_unique(&mut resolved.v6, normalize_ipv6(source)?);
            continue;
        }
        if source.contains('/') || source.parse::<Ipv4Addr>().is_ok() {
            push_unique(&mut resolved.v4, normalize_ipv4(source)?);
            continue;
        }
        let v4 = addresses_or_missing(resolver.lookup_v4(source));
        let v6 = addresses_or_missing(resolver.lookup_v6(source));
        let v4 = v4?;
        let v6 = v6?;
        if v4.is_empty() && v6.is_empty() {
            return Err(Error::new(format!("no address for {source}")));
        }
        for ip in v4 {
            push_unique(&mut resolved.v4, format!("{ip}/32"));
        }
        for ip in v6 {
            push_unique(&mut resolved.v6, format!("{ip}/128"));
        }
    }
    if resolved.v4.is_empty() && resolved.v6.is_empty() {
        return Err(Error::new("firewall source list is empty"));
    }
    resolved.v4.sort();
    resolved.v6.sort();
    Ok(resolved)
}

/// Turns a missing-record error into an empty list. Other lookup errors stay errors.
fn addresses_or_missing<T>(result: Result<Vec<T>, Error>) -> Result<Vec<T>, Error> {
    match result {
        Ok(ips) => Ok(ips),
        Err(err) if is_missing_record(&err) => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn is_missing_record(err: &Error) -> bool {
    let text = err.to_string();
    text.starts_with("no A record") || text.starts_with("no AAAA record")
}

/// True for a DNS hostname: labels of `[a-z0-9-]`, 1–63 chars, no leading or trailing `-`, at most 253 chars.
pub fn is_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    !labels.is_empty()
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Normalizes `a.b.c.d` or `a.b.c.d/n` into a canonical CIDR string.
pub(crate) fn normalize_ipv4(value: &str) -> Result<String, Error> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => {
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| Error::new(format!("bad CIDR prefix: {value}")))?;
            if prefix > 32 {
                return Err(Error::new(format!("bad CIDR prefix: {value}")));
            }
            (address, prefix)
        }
        None => (value, 32),
    };
    let ip: Ipv4Addr = address
        .parse()
        .map_err(|_| Error::new(format!("bad IPv4 address: {value}")))?;
    Ok(format!("{ip}/{prefix}"))
}

/// Normalizes an IPv6 address or CIDR into a canonical `address/prefix` string.
pub(crate) fn normalize_ipv6(value: &str) -> Result<String, Error> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => {
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| Error::new(format!("bad CIDR prefix: {value}")))?;
            if prefix > 128 {
                return Err(Error::new(format!("bad CIDR prefix: {value}")));
            }
            (address, prefix)
        }
        None => (value, 128),
    };
    if address.contains('%') {
        return Err(Error::new(format!("bad IPv6 address: {value}")));
    }
    let ip: Ipv6Addr = address
        .parse()
        .map_err(|_| Error::new(format!("bad IPv6 address: {value}")))?;
    Ok(format!("{ip}/{prefix}"))
}

/// Appends `value` when it is not already in `out`.
fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

/// Truncates `value` to `max` Unicode scalars for error messages.
fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// Test resolver that returns scripted A and AAAA records from maps.
#[cfg(test)]
#[derive(Default)]
pub struct MapResolver {
    pub values: std::collections::HashMap<String, Vec<Ipv4Addr>>,
    pub v6: std::collections::HashMap<String, Vec<Ipv6Addr>>,
}

#[cfg(test)]
impl Resolver for MapResolver {
    /// Returns mapped IPv4 addresses, or `"no A record"` when the host is missing or empty.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
        self.values
            .get(host)
            .cloned()
            .filter(|ips| !ips.is_empty())
            .ok_or_else(|| Error::new(format!("no A record for {host}")))
    }

    /// Returns mapped IPv6 addresses, or `"no AAAA record"` when the host is missing or empty.
    fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error> {
        self.v6
            .get(host)
            .cloned()
            .filter(|ips| !ips.is_empty())
            .ok_or_else(|| Error::new(format!("no AAAA record for {host}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contabo::{Http, HttpResponse};
    use crate::retry::NO_SHUTDOWN;
    use std::sync::Mutex;

    struct Echo {
        body: &'static str,
        status: u16,
        calls: Mutex<u32>,
    }

    impl Http for Echo {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            *self.calls.lock().unwrap() += 1;
            assert!(request.url.contains("ipecho"));
            assert_eq!(request.timeout, Some(Duration::from_secs(10)));
            Ok(HttpResponse {
                status: self.status,
                body: self.body.as_bytes().to_vec(),
            })
        }
    }

    #[test]
    fn parses_ipecho_body() {
        assert_eq!(
            parse_public_ip("  203.0.113.10\n").unwrap(),
            Ipv4Addr::new(203, 0, 113, 10)
        );
        assert!(parse_public_ip("not an ip").is_err());
        assert!(parse_public_ip("203.0.113.10 extra").is_err());
    }

    #[test]
    fn fetches_public_ip() {
        let http = Echo {
            body: "198.51.100.8\n",
            status: 200,
            calls: Mutex::new(0),
        };
        let ip = fetch_public_ip(
            &http,
            &["https://ipecho.test/plain".into()],
            Duration::from_secs(10),
            &NO_SHUTDOWN,
            crate::retry::immediate,
        )
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(198, 51, 100, 8));
    }

    #[test]
    fn resolves_cidr_hostname_and_current() {
        let mut values = std::collections::HashMap::new();
        values.insert(
            "home.example.net".into(),
            vec![Ipv4Addr::new(203, 0, 113, 9), Ipv4Addr::new(203, 0, 113, 8)],
        );
        let resolver = MapResolver {
            values,
            ..MapResolver::default()
        };
        let sources = resolve_sources(
            &[
                "203.0.113.5".into(),
                "10.1.2.0/24".into(),
                "home.example.net".into(),
                "current".into(),
                "203.0.113.5".into(),
            ],
            PublicIps {
                v4: Some(Ipv4Addr::new(198, 51, 100, 4)),
                v6: None,
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(
            sources.v4,
            vec![
                "10.1.2.0/24".to_string(),
                "198.51.100.4/32".to_string(),
                "203.0.113.5/32".to_string(),
                "203.0.113.8/32".to_string(),
                "203.0.113.9/32".to_string(),
            ]
        );
        assert!(sources.v6.is_empty());
    }

    #[test]
    fn refuses_failed_or_empty_resolution() {
        let resolver = MapResolver::default();
        let err = resolve_sources(&["missing.example".into()], PublicIps::default(), &resolver)
            .unwrap_err();
        assert!(err.to_string().contains("no address"));
        assert!(resolve_sources(&["current".into()], PublicIps::default(), &resolver).is_err());
        assert!(resolve_sources(&["current6".into()], PublicIps::default(), &resolver).is_err());
        assert!(normalize_ipv4("10.0.0.1/99").is_err());
        assert!(normalize_ipv4("10.0.0.1/x").is_err());
        assert!(resolve_sources(&["10.0.0.1/99".into()], PublicIps::default(), &resolver).is_err());
        assert!(normalize_ipv4("not-an-ip").is_err());
        assert!(resolve_sources(&["".into()], PublicIps::default(), &resolver).is_err());
        assert!(normalize_ipv6("2001:db8::/129").is_err());
        assert!(normalize_ipv6("2001:db8::/x").is_err());
        assert!(normalize_ipv6("fe80::1%eth0").is_err());
        assert!(
            resolve_sources(&["2001:db8::/129".into()], PublicIps::default(), &resolver).is_err()
        );
        assert!(resolve_sources(&[], PublicIps::default(), &resolver).is_err());
    }

    struct EmptyList;

    impl Resolver for EmptyList {
        fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
            let _ = host;
            Ok(Vec::new())
        }

        fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error> {
            let _ = host;
            Ok(Vec::new())
        }
    }

    #[test]
    fn system_resolver_uses_os_lookup() {
        let resolver = SystemResolver;
        let ips = resolver.lookup_v4("127.0.0.1").unwrap();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
        assert!(
            resolver
                .lookup_v4("[")
                .unwrap_err()
                .to_string()
                .contains("resolve")
        );

        use std::net::SocketAddr;
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        assert_eq!(
            ipv4_from_addresses("dup", vec![v4, v4]).unwrap(),
            vec![Ipv4Addr::LOCALHOST]
        );
        assert!(
            ipv4_from_addresses("ipv6-only", vec![v6])
                .unwrap_err()
                .to_string()
                .contains("no A record")
        );
        assert_eq!(
            ipv6_from_addresses("dup6", vec![v6, v6]).unwrap(),
            vec![Ipv6Addr::LOCALHOST]
        );
        assert!(
            ipv6_from_addresses("v4-only", vec![v4])
                .unwrap_err()
                .to_string()
                .contains("no AAAA record")
        );
        let v6_ips = resolver.lookup_v6("::1").unwrap();
        assert!(v6_ips.iter().any(|ip| ip.is_loopback()));
        assert!(
            resolver
                .lookup_v6("[")
                .unwrap_err()
                .to_string()
                .contains("resolve")
        );
        assert!(
            resolve_sources(&["gap.example".into()], PublicIps::default(), &EmptyList)
                .unwrap_err()
                .to_string()
                .contains("no address")
        );
    }

    #[test]
    fn rejects_shared_and_benchmark_ranges() {
        assert!(!is_publishable(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_publishable(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(is_publishable(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(is_publishable(Ipv4Addr::new(100, 128, 0, 1)));
        assert!(!is_publishable(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_publishable(Ipv4Addr::new(198, 19, 255, 1)));
        assert!(is_publishable(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(is_publishable(Ipv4Addr::new(203, 0, 113, 7)));
        assert!(is_hostname("home.example.net"));
        assert!(is_hostname("a"));
        assert!(!is_hostname(""));
        assert!(!is_hostname("home example.com"));
        assert!(!is_hostname("-bad.example"));
        assert!(!is_hostname("bad-.example"));
        assert!(!is_hostname("bad..example"));
        assert!(!is_hostname(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn fetch_public_ip_rejects_bad_status() {
        let http = Echo {
            body: "nope",
            status: 503,
            calls: Mutex::new(0),
        };
        assert!(
            fetch_public_ip(
                &http,
                &["https://ipecho.test/plain".into()],
                Duration::from_secs(10),
                &NO_SHUTDOWN,
                crate::retry::immediate,
            )
            .is_err()
        );
        assert!(*http.calls.lock().unwrap() >= 2);
    }

    /// Skips a private answer and a failing URL, then keeps a public address.
    #[test]
    fn fetch_public_ip_falls_back_across_urls() {
        struct ByUrl;
        impl Http for ByUrl {
            fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
                let body: &[u8] = if request.url.contains("private") {
                    b"192.168.1.9"
                } else if request.url.contains("down") {
                    return Ok(HttpResponse {
                        status: 500,
                        body: Vec::new(),
                    });
                } else {
                    b"1.1.1.1"
                };
                Ok(HttpResponse {
                    status: 200,
                    body: body.to_vec(),
                })
            }
        }
        assert!(!is_publishable(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_publishable(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_publishable(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_publishable(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_publishable(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!is_publishable(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_publishable(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(
            fetch_public_ip(
                &ByUrl,
                &[],
                Duration::from_secs(1),
                &NO_SHUTDOWN,
                crate::retry::immediate,
            )
            .is_err()
        );
        let ip = fetch_public_ip(
            &ByUrl,
            &[
                "https://private.test/plain".into(),
                "https://down.test/plain".into(),
                "https://ok.test/plain".into(),
            ],
            Duration::from_secs(1),
            &NO_SHUTDOWN,
            crate::retry::immediate,
        )
        .unwrap();
        assert_eq!(ip, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn resolves_ipv6_sources_and_keeps_families_apart() {
        let mut values = std::collections::HashMap::new();
        values.insert(
            "dual.example.net".into(),
            vec![Ipv4Addr::new(203, 0, 113, 8)],
        );
        let mut v6 = std::collections::HashMap::new();
        v6.insert(
            "dual.example.net".into(),
            vec![
                "2606:4700:4700::1111".parse().unwrap(),
                "2606:4700:4700::1001".parse().unwrap(),
            ],
        );
        v6.insert(
            "v6only.example.net".into(),
            vec!["2606:4700:4700::64".parse().unwrap()],
        );
        let resolver = MapResolver { values, v6 };
        let sources = resolve_sources(
            &[
                "2001:0db8:0000::1".into(),
                "2001:db8::/32".into(),
                "2001:db8::1".into(),
                "current6".into(),
                "dual.example.net".into(),
                "v6only.example.net".into(),
            ],
            PublicIps {
                v4: None,
                v6: Some("2606:4700:4700::10".parse().unwrap()),
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(sources.v4, vec!["203.0.113.8/32".to_string()]);
        assert_eq!(
            sources.v6,
            vec![
                "2001:db8::/32".to_string(),
                "2001:db8::1/128".to_string(),
                "2606:4700:4700::10/128".to_string(),
                "2606:4700:4700::1001/128".to_string(),
                "2606:4700:4700::1111/128".to_string(),
                "2606:4700:4700::64/128".to_string(),
            ]
        );
        assert_eq!(normalize_ipv6("::1").unwrap(), "::1/128");
    }

    struct LookupDown;

    impl Resolver for LookupDown {
        fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
            Err(Error::new(format!("resolve {host}: down")))
        }

        fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error> {
            let _ = host;
            Ok(vec![Ipv6Addr::LOCALHOST])
        }
    }

    struct V6Down;

    impl Resolver for V6Down {
        fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
            let _ = host;
            Ok(vec![Ipv4Addr::new(203, 0, 113, 1)])
        }

        fn lookup_v6(&self, host: &str) -> Result<Vec<Ipv6Addr>, Error> {
            Err(Error::new(format!("resolve {host}: down")))
        }
    }

    #[test]
    fn hostname_lookup_failure_fails_closed() {
        let err = resolve_sources(&["home.example".into()], PublicIps::default(), &LookupDown)
            .unwrap_err();
        assert!(err.to_string().contains("resolve home.example"));
        let err =
            resolve_sources(&["home.example".into()], PublicIps::default(), &V6Down).unwrap_err();
        assert!(err.to_string().contains("resolve home.example"));
    }

    #[test]
    fn fetches_public_ipv6_and_rejects_special_ranges() {
        assert!(!is_publishable_v6(Ipv6Addr::LOCALHOST));
        assert!(!is_publishable_v6(Ipv6Addr::UNSPECIFIED));
        assert!(!is_publishable_v6("ff02::1".parse().unwrap()));
        assert!(!is_publishable_v6("fe80::1".parse().unwrap()));
        assert!(!is_publishable_v6("fc00::1".parse().unwrap()));
        assert!(!is_publishable_v6("fd00::1".parse().unwrap()));
        assert!(!is_publishable_v6("2001:db8::1".parse().unwrap()));
        assert!(!is_publishable_v6("2001:2::1".parse().unwrap()));
        assert!(!is_publishable_v6("100::1".parse().unwrap()));
        assert!(!is_publishable_v6("::ffff:192.0.2.1".parse().unwrap()));
        let global: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert!(is_publishable_v6(global));
        assert_eq!(
            parse_public_ipv6("  2606:4700:4700::1111\n").unwrap(),
            global
        );
        assert!(parse_public_ipv6("not-an-ip").is_err());
        assert!(parse_public_ipv6("2606:4700:4700::1111 extra").is_err());

        struct V6Echo;
        impl Http for V6Echo {
            fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
                let body: &[u8] = if request.url.contains("private") {
                    b"fd00::9"
                } else if request.url.contains("down") {
                    return Ok(HttpResponse {
                        status: 500,
                        body: Vec::new(),
                    });
                } else if request.url.contains("garbage") {
                    b"not-an-ip"
                } else {
                    b"2606:4700:4700::1111\n"
                };
                Ok(HttpResponse {
                    status: 200,
                    body: body.to_vec(),
                })
            }
        }
        assert!(
            fetch_public_ipv6(
                &V6Echo,
                &[],
                Duration::from_secs(1),
                &NO_SHUTDOWN,
                crate::retry::immediate,
            )
            .is_err()
        );
        assert!(
            fetch_public_ip(
                &V6Echo,
                &["https://garbage.test/plain".into()],
                Duration::from_secs(1),
                &NO_SHUTDOWN,
                crate::retry::immediate,
            )
            .unwrap_err()
            .to_string()
            .contains("ipecho returned")
        );
        assert!(
            fetch_public_ipv6(
                &V6Echo,
                &["https://garbage.test/plain".into()],
                Duration::from_secs(1),
                &NO_SHUTDOWN,
                crate::retry::immediate,
            )
            .unwrap_err()
            .to_string()
            .contains("ipecho returned")
        );
        let ip = fetch_public_ipv6(
            &V6Echo,
            &[
                "https://private.test/plain".into(),
                "https://down.test/plain".into(),
                "https://ok.test/plain".into(),
            ],
            Duration::from_secs(1),
            &NO_SHUTDOWN,
            crate::retry::immediate,
        )
        .unwrap();
        assert_eq!(ip, global);
    }
}
