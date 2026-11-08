//! Public-IP fetch and firewall source resolution (CIDR, hostname, `current`).

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::contabo::{Http, HttpRequest};
use crate::error::Error;
use crate::retry;

/// Looks up A records for a hostname. Must be safe to call from DNS/firewall threads.
pub trait Resolver: Send + Sync {
    /// Returns unique IPv4 addresses for `host`, or an error if lookup fails.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error>;
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
        if let IpAddr::V4(ip) = address.ip() {
            if !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    if found.is_empty() {
        Err(Error::new(format!("no A record for {host}")))
    } else {
        Ok(found)
    }
}

impl Resolver for SystemResolver {
    /// Resolves `host` through the operating system and filters to IPv4.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
        let addresses = (host, 0u16)
            .to_socket_addrs()
            .map_err(|err| Error::new(format!("resolve {host}: {err}")))?;
        ipv4_from_addresses(host, addresses.collect())
    }
}

/// Tries each echo URL in order. Skips answers that `is_publishable` rejects.
pub fn fetch_public_ip(
    http: &dyn Http,
    urls: &[String],
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
) -> Result<Ipv4Addr, Error> {
    if urls.is_empty() {
        return Err(Error::new("IP_ECHO_URL is empty"));
    }
    let mut errors = Vec::new();
    for url in urls {
        match fetch_one(http, url, timeout, shutdown, delay) {
            Ok(ip) if is_publishable(ip) => return Ok(ip),
            Ok(ip) => errors.push(format!("{url}: refused non-public address {ip}")),
            Err(err) => errors.push(format!("{url}: {err}")),
        }
    }
    Err(Error::new(format!(
        "public ip lookup failed: {}",
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

/// GETs one echo URL with transient retries and parses the IPv4 body.
fn fetch_one(
    http: &dyn Http,
    url: &str,
    timeout: Duration,
    shutdown: &AtomicBool,
    delay: fn(u32) -> Duration,
) -> Result<Ipv4Addr, Error> {
    let request = HttpRequest {
        method: "GET".into(),
        url: url.to_string(),
        headers: vec![("accept".into(), "text/plain".into())],
        body: None,
        timeout: Some(timeout),
        max_body: Some(crate::contabo::MAX_ECHO_BODY),
    };
    let response = retry::send(&format!("GET {url}"), true, shutdown, delay, || {
        http.send(&request)
    })?;
    if !(200..300).contains(&response.status) {
        return Err(Error::new(format!("ipecho status {}", response.status)));
    }
    parse_public_ip(&String::from_utf8_lossy(&response.body))
}

/// Parses a trimmed IPv4 address from an ipecho-style body.
pub fn parse_public_ip(body: &str) -> Result<Ipv4Addr, Error> {
    let text = body.trim();
    text.parse::<Ipv4Addr>()
        .map_err(|_| Error::new(format!("ipecho returned {:?}", truncate(text, 80))))
}

/// Turns configured sources into unique `a.b.c.d/prefix` strings.
///
/// Accepts IPv4, CIDR, `current` (the ipecho address), or a hostname (every A
/// record becomes `/32`). IPv6 and empty lists fail closed.
pub fn resolve_sources(
    sources: &[String],
    current: Option<Ipv4Addr>,
    resolver: &dyn Resolver,
) -> Result<Vec<String>, Error> {
    let mut resolved = Vec::new();
    for source in sources {
        let source = source.trim();
        if source.is_empty() {
            return Err(Error::new("empty firewall source"));
        }
        if source == "current" {
            let ip =
                current.ok_or_else(|| Error::new("current source used without a public IP"))?;
            push_unique(&mut resolved, format!("{ip}/32"));
            continue;
        }
        if source.parse::<std::net::Ipv6Addr>().is_ok() {
            return Err(Error::new(format!(
                "ipv6 source is not written into ipv4 sources: {source}"
            )));
        }
        if source.contains('/') || source.parse::<Ipv4Addr>().is_ok() {
            push_unique(&mut resolved, normalize_ipv4(source)?);
            continue;
        }
        let ips = resolver.lookup_v4(source)?;
        for ip in ips {
            push_unique(&mut resolved, format!("{ip}/32"));
        }
    }
    if resolved.is_empty() {
        return Err(Error::new("firewall source list is empty"));
    }
    resolved.sort();
    Ok(resolved)
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

/// Test resolver that returns scripted A records from a map.
#[cfg(test)]
pub struct MapResolver {
    pub values: std::collections::HashMap<String, Vec<Ipv4Addr>>,
}

#[cfg(test)]
impl Resolver for MapResolver {
    /// Returns mapped IPs, or `"no A record"` when the host is missing or empty.
    fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
        self.values
            .get(host)
            .cloned()
            .filter(|ips| !ips.is_empty())
            .ok_or_else(|| Error::new(format!("no A record for {host}")))
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
        let resolver = MapResolver { values };
        let sources = resolve_sources(
            &[
                "203.0.113.5".into(),
                "10.1.2.0/24".into(),
                "home.example.net".into(),
                "current".into(),
                "203.0.113.5".into(),
            ],
            Some(Ipv4Addr::new(198, 51, 100, 4)),
            &resolver,
        )
        .unwrap();
        assert_eq!(
            sources,
            vec![
                "10.1.2.0/24".to_string(),
                "198.51.100.4/32".to_string(),
                "203.0.113.5/32".to_string(),
                "203.0.113.8/32".to_string(),
                "203.0.113.9/32".to_string(),
            ]
        );
    }

    #[test]
    fn refuses_failed_or_empty_resolution() {
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        let err = resolve_sources(&["missing.example".into()], None, &resolver).unwrap_err();
        assert!(err.to_string().contains("no A record"));
        assert!(resolve_sources(&["current".into()], None, &resolver).is_err());
        assert!(normalize_ipv4("10.0.0.1/99").is_err());
        assert!(normalize_ipv4("10.0.0.1/x").is_err());
        assert!(resolve_sources(&["10.0.0.1/99".into()], None, &resolver).is_err());
        assert!(normalize_ipv4("not-an-ip").is_err());
        assert!(resolve_sources(&["".into()], None, &resolver).is_err());
        assert!(resolve_sources(&["::1".into()], None, &resolver).is_err());
    }

    struct EmptyList;

    impl Resolver for EmptyList {
        fn lookup_v4(&self, host: &str) -> Result<Vec<Ipv4Addr>, Error> {
            let _ = host;
            Ok(Vec::new())
        }
    }

    #[test]
    fn system_resolver_uses_os_lookup() {
        let resolver = SystemResolver;
        let ips = resolver.lookup_v4("127.0.0.1").unwrap();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
        assert!(resolver
            .lookup_v4("[")
            .unwrap_err()
            .to_string()
            .contains("resolve"));

        use std::net::{Ipv6Addr, SocketAddr};
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        assert_eq!(
            ipv4_from_addresses("dup", vec![v4, v4]).unwrap(),
            vec![Ipv4Addr::LOCALHOST]
        );
        assert!(ipv4_from_addresses(
            "ipv6-only",
            vec![SocketAddr::from((Ipv6Addr::LOCALHOST, 0))]
        )
        .unwrap_err()
        .to_string()
        .contains("no A record"));
        assert!(resolve_sources(&["gap.example".into()], None, &EmptyList)
            .unwrap_err()
            .to_string()
            .contains("empty"));
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
        assert!(fetch_public_ip(
            &http,
            &["https://ipecho.test/plain".into()],
            Duration::from_secs(10),
            &NO_SHUTDOWN,
            crate::retry::immediate,
        )
        .is_err());
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
        assert!(fetch_public_ip(
            &ByUrl,
            &[],
            Duration::from_secs(1),
            &NO_SHUTDOWN,
            crate::retry::immediate,
        )
        .is_err());
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
}
