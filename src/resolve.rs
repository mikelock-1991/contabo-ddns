//! DNS shared by reqwest and firewall source lookups.
//!
//! DNS_SERVERS overrides system DNS. Otherwise, system DNS is tried first,
//! falling back to 1.1.1.1,8.8.8.8 on failure.
//! Hickory handles UDP/TCP, peer validation, caching, and the hosts file.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, ResolverBuilder};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::runtime::{Builder, Runtime};
use tokio::task::{JoinError, JoinHandle};

use crate::error::Error;

const DEFAULT_DNS_SERVERS: &str = "1.1.1.1,8.8.8.8";
// Leave time for fallback within the default ten-second IP echo request.
const SYSTEM_DNS_TIMEOUT: Duration = Duration::from_secs(2);
type DnsResolver = Resolver<TokioRuntimeProvider>;
type LookupTask = JoinHandle<Result<LookupIp, NetError>>;

static SYSTEM: OnceLock<Result<HostResolver, Error>> = OnceLock::new();

#[derive(Clone)]
struct Fallback {
    resolver: DnsResolver,
    description: String,
}

impl Fallback {
    fn from_servers(servers: Option<&str>) -> Result<Self, Error> {
        let configured = servers.filter(|value| !value.trim().is_empty());
        let servers = configured.unwrap_or(DEFAULT_DNS_SERVERS);
        let nameservers = servers
            .split(',')
            .map(|server| {
                server
                    .trim()
                    .parse::<IpAddr>()
                    .map(NameServerConfig::udp_and_tcp)
                    .map_err(|_| {
                        NetError::Message("DNS_SERVERS must contain comma-separated IP addresses")
                    })
            })
            .collect::<Result<Vec<_>, NetError>>()
            .map_err(dns_config_error)?;
        let mut builder = DnsResolver::builder_with_config(
            ResolverConfig::from_parts(None, vec![], nameservers),
            TokioRuntimeProvider::default(),
        );
        builder.options_mut().ndots = 0;
        let description = if configured.is_some() {
            format!("configured DNS_SERVERS={servers}")
        } else {
            format!(
                "fallback default DNS_SERVERS={DEFAULT_DNS_SERVERS}; override with the DNS_SERVERS environment variable"
            )
        };
        prepare(builder)
            .map(|resolver| Self {
                resolver,
                description,
            })
            .map_err(dns_config_error)
    }
}

/// Shared, cached DNS clients on a dedicated runtime for HTTP and firewall workers.
#[derive(Clone)]
pub(crate) struct HostResolver {
    resolver: Option<DnsResolver>,
    fallback: Fallback,
    runtime: Arc<Runtime>,
}

impl HostResolver {
    pub(crate) fn system() -> Result<Self, Error> {
        system_from(&SYSTEM)
    }

    fn query(&self, host: &str) -> LookupTask {
        let resolver = self.resolver.clone();
        let fallback = self.fallback.clone();
        let host = host.to_owned();
        self.runtime.spawn(async move {
            if let Some(resolver) = resolver {
                let result = tokio::time::timeout(SYSTEM_DNS_TIMEOUT, resolver.lookup_ip(&host))
                    .await
                    .unwrap_or(Err(NetError::Timeout));
                match result {
                    Ok(ips) => return Ok(ips),
                    // An authoritative negative answer is not a DNS outage.
                    Err(err) if err.is_no_records_found() => return Err(err),
                    Err(err) => log::warn!(
                        "system DNS lookup failed for {host} ({err}); using {}",
                        fallback.description
                    ),
                }
            }
            fallback.resolver.lookup_ip(host).await
        })
    }

    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        finish_lookup(host, self.runtime.block_on(self.query(host)))
    }
}

fn system_from(cache: &OnceLock<Result<HostResolver, Error>>) -> Result<HostResolver, Error> {
    match cache.get_or_init(|| {
        let servers = std::env::var("DNS_SERVERS").unwrap_or_default();
        configured_from(
            &servers,
            || DnsResolver::builder(TokioRuntimeProvider::default()),
            Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("dns")
                .enable_all()
                .build(),
        )
    }) {
        Ok(resolver) => Ok(resolver.clone()),
        Err(err) => Err(Error::new(err.to_string())),
    }
}

/// Explicit nameservers bypass even reading system configuration.
fn configured_from(
    servers: &str,
    system: impl FnOnce() -> Result<ResolverBuilder<TokioRuntimeProvider>, NetError>,
    runtime: io::Result<Runtime>,
) -> Result<HostResolver, Error> {
    Fallback::from_servers(Some(servers)).and_then(|fallback| {
        if servers.trim().is_empty() {
            build(system(), fallback, runtime)
        } else {
            log::info!("using {}; system DNS disabled", fallback.description);
            assemble(Ok(None), fallback, runtime)
        }
    })
}

fn prepare(mut builder: ResolverBuilder<TokioRuntimeProvider>) -> Result<DnsResolver, NetError> {
    let options = builder.options_mut();
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.try_tcp_on_error = true;
    builder.build()
}

fn build(
    builder: Result<ResolverBuilder<TokioRuntimeProvider>, NetError>,
    fallback: Fallback,
    runtime: io::Result<Runtime>,
) -> Result<HostResolver, Error> {
    assemble(builder.and_then(prepare).map(Some), fallback, runtime)
}

fn dns_config_error(err: NetError) -> Error {
    Error::wrap("DNS configuration (DNS_SERVERS)", err)
}

fn assemble(
    resolver: Result<Option<DnsResolver>, NetError>,
    fallback: Fallback,
    runtime: io::Result<Runtime>,
) -> Result<HostResolver, Error> {
    let runtime = runtime.map_err(|err| Error::wrap("DNS runtime", err))?;
    let resolver = match resolver {
        Ok(resolver) => resolver,
        Err(err) => {
            log::warn!(
                "system DNS configuration failed ({err}); using {}",
                fallback.description
            );
            None
        }
    };
    Ok(HostResolver {
        resolver,
        fallback,
        runtime: Arc::new(runtime),
    })
}

/// Resolves both families; the caller filters the addresses it needs.
pub(crate) fn lookup(host: &str) -> Result<Vec<IpAddr>, Error> {
    HostResolver::system().and_then(|resolver| resolver.lookup(host))
}

fn finish_lookup(
    host: &str,
    result: Result<Result<LookupIp, NetError>, JoinError>,
) -> Result<Vec<IpAddr>, Error> {
    match result {
        Ok(Ok(ips)) => Ok(ips.iter().collect()),
        Ok(Err(err)) if err.is_no_records_found() => Ok(Vec::new()),
        Ok(Err(err)) => Err(Error::wrap(
            format!("resolve {host} (check DNS_SERVERS)"),
            err,
        )),
        Err(err) => Err(Error::wrap(format!("resolve {host}: DNS task"), err)),
    }
}

impl Resolve for HostResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let task = self.query(&host);
        Box::pin(async move {
            let ips = finish_lookup(&host, task.await)?;
            let addrs: Addrs = Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::Hosts;
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name as DnsName, RData, Record, RecordType};
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket as StdUdpSocket};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn runtime() -> Runtime {
        Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
    }

    fn config(addr: SocketAddr, tcp: bool) -> ResolverConfig {
        let mut server = if tcp {
            NameServerConfig::udp_and_tcp(addr.ip())
        } else {
            NameServerConfig::udp(addr.ip())
        };
        for connection in &mut server.connections {
            connection.port = addr.port();
        }
        ResolverConfig::from_parts(None, vec![], vec![server])
    }

    fn local_resolver(addr: SocketAddr) -> HostResolver {
        let mut builder =
            DnsResolver::builder_with_config(config(addr, true), TokioRuntimeProvider::default());
        // Allow the two-family TCP fixture to run alongside the coverage suite.
        builder.options_mut().timeout = Duration::from_secs(2);
        builder.options_mut().attempts = 1;
        let resolver = prepare(builder).unwrap();
        HostResolver {
            resolver: Some(resolver.clone()),
            fallback: Fallback {
                resolver,
                description: "fallback local DNS fixture".into(),
            },
            runtime: Arc::new(runtime()),
        }
    }

    fn expected_ips() -> Vec<IpAddr> {
        vec![
            "203.0.113.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ]
    }

    fn answer(query: &Message) -> Message {
        let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
        reply.metadata.recursion_available = true;
        reply.queries = query.queries.clone();
        let question = &query.queries[0];
        if question.name().to_utf8() == "missing.example." {
            reply.metadata.response_code = ResponseCode::NXDomain;
            return reply;
        }
        for ip in expected_ips() {
            let data = RData::from(ip);
            if data.record_type() == question.query_type() {
                reply.add_answer(Record::from_rdata(question.name().clone(), 60, data));
            }
        }
        reply
    }

    struct DnsServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        queries: Arc<Mutex<Vec<bool>>>,
        workers: Vec<std::thread::JoinHandle<()>>,
    }

    impl DnsServer {
        fn spawn(truncated: bool) -> Self {
            let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = tcp.local_addr().unwrap();
            tcp.set_nonblocking(true).unwrap();
            let udp = StdUdpSocket::bind(addr).unwrap();
            udp.set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let queries = Arc::new(Mutex::new(Vec::new()));
            let stopped = Arc::clone(&stop);
            let seen = Arc::clone(&queries);
            let udp_worker = std::thread::spawn(move || {
                let mut buf = [0; 4096];
                while !stopped.load(Ordering::Relaxed) {
                    if let Ok((len, source)) = udp.recv_from(&mut buf) {
                        seen.lock().unwrap().push(false);
                        let mut reply = answer(&Message::from_vec(&buf[..len]).unwrap());
                        if truncated {
                            reply.metadata.truncation = true;
                            reply.answers.clear();
                        }
                        udp.send_to(&reply.to_vec().unwrap(), source).unwrap();
                    }
                }
            });
            let stopped = Arc::clone(&stop);
            let seen = Arc::clone(&queries);
            let tcp_worker = std::thread::spawn(move || {
                // A and AAAA can use separate persistent TCP connections.
                std::thread::scope(|scope| {
                    while !stopped.load(Ordering::Relaxed) {
                        match tcp.accept() {
                            Ok((mut stream, _)) => {
                                let seen = Arc::clone(&seen);
                                scope.spawn(move || {
                                    stream
                                        .set_read_timeout(Some(Duration::from_secs(2)))
                                        .unwrap();
                                    let mut size = [0; 2];
                                    while stream.read_exact(&mut size).is_ok() {
                                        let mut buf =
                                            vec![0; usize::from(u16::from_be_bytes(size))];
                                        stream.read_exact(&mut buf).unwrap();
                                        seen.lock().unwrap().push(true);
                                        let reply = answer(&Message::from_vec(&buf).unwrap())
                                            .to_vec()
                                            .unwrap();
                                        stream
                                            .write_all(&(reply.len() as u16).to_be_bytes())
                                            .unwrap();
                                        stream.write_all(&reply).unwrap();
                                    }
                                });
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(2)),
                        }
                    }
                });
            });
            Self {
                addr,
                stop,
                queries,
                workers: vec![udp_worker, tcp_worker],
            }
        }
    }

    impl Drop for DnsServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            for worker in self.workers.drain(..) {
                worker.join().unwrap();
            }
        }
    }

    #[test]
    fn real_udp_and_truncated_tcp_fallback_resolve_both_families() {
        for truncated in [false, true] {
            let server = DnsServer::spawn(truncated);
            let resolver = local_resolver(server.addr);
            assert_eq!(resolver.lookup("host.example.").unwrap(), expected_ips());
            let protocols = server.queries.lock().unwrap().clone();
            assert!(protocols.contains(&false));
            assert_eq!(protocols.contains(&true), truncated);
        }
    }

    #[test]
    fn hosts_file_answers_and_reqwest_adapter_use_the_same_resolver() {
        let server = DnsServer::spawn(false);
        let mut resolver = local_resolver(server.addr);
        let mut hosts = Hosts::default();
        hosts
            .read_hosts_conf(&b"192.0.2.10 extra.test\n2001:db8::20 extra.test\n"[..])
            .unwrap();
        resolver
            .resolver
            .as_mut()
            .unwrap()
            .set_hosts(Arc::new(hosts));
        let expected: Vec<IpAddr> = vec![
            "192.0.2.10".parse().unwrap(),
            "2001:db8::20".parse().unwrap(),
        ];
        assert_eq!(resolver.lookup("extra.test").unwrap(), expected);
        let result = resolver
            .runtime
            .block_on(resolver.resolve("extra.test".parse().unwrap()))
            .unwrap();
        assert_eq!(result.map(|addr| addr.ip()).collect::<Vec<_>>(), expected);
        assert!(server.queries.lock().unwrap().is_empty());
        assert!(
            resolver
                .runtime
                .block_on(resolver.resolve("[".parse().unwrap()))
                .is_err()
        );
    }

    #[test]
    fn initialization_and_lookup_failures_keep_their_context() {
        let cache = OnceLock::from(Err(Error::new("injected system config error")));
        assert!(
            system_from(&cache)
                .err()
                .unwrap()
                .to_string()
                .contains("system config")
        );
        let fallback = Fallback::from_servers(None).unwrap();
        assert!(
            build(
                Err(NetError::Message("missing config")),
                fallback.clone(),
                Ok(runtime())
            )
            .unwrap()
            .resolver
            .is_none()
        );
        assert!(
            assemble(
                Err(NetError::Message("bad config")),
                fallback.clone(),
                Ok(runtime())
            )
            .unwrap()
            .resolver
            .is_none()
        );
        assert!(
            assemble(
                Err(NetError::Message("bad config")),
                fallback,
                Err(io::Error::other("no runtime"))
            )
            .err()
            .unwrap()
            .to_string()
            .contains("DNS runtime")
        );
        assert!(
            finish_lookup("test", Ok(Err(NetError::Timeout)))
                .unwrap_err()
                .to_string()
                .contains("resolve test")
        );
        let query = Query::query(
            DnsName::from_ascii("missing.example.").unwrap(),
            RecordType::A,
        );
        assert!(
            finish_lookup(
                "test",
                Ok(Err(NoRecords::new(query, ResponseCode::NXDomain).into()))
            )
            .unwrap()
            .is_empty()
        );
        let rt = runtime();
        let task: LookupTask = rt.spawn(async { panic!("injected lookup task failure") });
        assert!(
            finish_lookup("test", rt.block_on(task))
                .unwrap_err()
                .to_string()
                .contains("DNS task")
        );
    }

    #[test]
    fn fallback_servers_use_defaults_or_validate_the_environment_override() {
        for servers in [None, Some(""), Some("  ")] {
            let fallback = Fallback::from_servers(servers).unwrap();
            assert!(fallback.description.contains("1.1.1.1,8.8.8.8"));
            assert!(
                fallback
                    .description
                    .contains("override with the DNS_SERVERS environment variable")
            );
        }
        let fallback = Fallback::from_servers(Some(" 1.1.1.1, 2606:4700:4700::1111 ")).unwrap();
        assert_eq!(
            fallback.description,
            "configured DNS_SERVERS= 1.1.1.1, 2606:4700:4700::1111 "
        );
        for value in [
            "invalid",
            "1.1.1.1,",
            ",8.8.8.8",
            "1.1.1.1,,8.8.8.8",
            "1.1.1.1:53",
            "[::1]",
            "1.1.1.1,invalid",
        ] {
            let error = Fallback::from_servers(Some(value))
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("DNS_SERVERS"), "{value}: {error}");
        }
    }

    #[test]
    fn system_dns_wins_and_failures_use_the_fallback_for_both_callers() {
        let primary = DnsServer::spawn(false);
        let secondary = DnsServer::spawn(true);
        let mut resolver = local_resolver(primary.addr);
        resolver.fallback = local_resolver(secondary.addr).fallback;
        assert_eq!(resolver.lookup("host.example.").unwrap(), expected_ips());
        assert!(secondary.queries.lock().unwrap().is_empty());

        // A closed local endpoint produces a transport error without external DNS.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        resolver.resolver = local_resolver(addr).resolver;
        assert_eq!(resolver.lookup("host.example.").unwrap(), expected_ips());
        let ips = resolver
            .runtime
            .block_on(resolver.resolve("host.example".parse().unwrap()))
            .unwrap();
        assert_eq!(
            ips.map(|addr| addr.ip()).collect::<Vec<_>>(),
            expected_ips()
        );
        assert!(secondary.queries.lock().unwrap().contains(&true));

        let resolver = build(
            Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
            local_resolver(secondary.addr).fallback,
            Ok(runtime()),
        )
        .unwrap();
        assert_eq!(resolver.lookup("host.example.").unwrap(), expected_ips());
    }

    #[test]
    fn negative_answers_do_not_trigger_fallback() {
        let server = DnsServer::spawn(false);
        let mut resolver = local_resolver(server.addr);
        let fallback = DnsServer::spawn(false);
        resolver.fallback = local_resolver(fallback.addr).fallback;
        assert!(resolver.lookup("missing.example.").unwrap().is_empty());
        assert!(fallback.queries.lock().unwrap().is_empty());
    }

    #[test]
    fn stalled_system_dns_is_bounded_before_fallback() {
        let secondary = DnsServer::spawn(false);
        let mut resolver = local_resolver(secondary.addr);
        // Hold a UDP endpoint open without answering; Hickory's own timeout is longer.
        let silent = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        let mut builder = DnsResolver::builder_with_config(
            config(silent.local_addr().unwrap(), false),
            TokioRuntimeProvider::default(),
        );
        builder.options_mut().timeout = Duration::from_secs(30);
        resolver.resolver = Some(prepare(builder).unwrap());
        let started = std::time::Instant::now();
        assert_eq!(resolver.lookup("host.example.").unwrap(), expected_ips());
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!secondary.queries.lock().unwrap().is_empty());
    }

    #[test]
    fn explicit_servers_skip_system_configuration_while_blank_keeps_default_fallback() {
        let reads = std::cell::Cell::new(0);
        let system = || {
            reads.set(reads.get() + 1);
            Err(NetError::Message("unreadable system configuration"))
        };
        let explicit = configured_from("127.0.0.1", system, Ok(runtime())).unwrap();
        assert_eq!(reads.get(), 0);
        assert!(explicit.resolver.is_none());
        assert_eq!(
            explicit.fallback.description,
            "configured DNS_SERVERS=127.0.0.1"
        );
        assert!(
            explicit
                .lookup("[")
                .unwrap_err()
                .to_string()
                .contains("DNS_SERVERS")
        );
        for servers in ["", "   "] {
            let resolver = configured_from(servers, system, Ok(runtime())).unwrap();
            assert!(resolver.fallback.description.contains(DEFAULT_DNS_SERVERS));
            assert!(
                resolver
                    .fallback
                    .description
                    .contains("override with the DNS_SERVERS environment variable")
            );
        }
        assert_eq!(reads.get(), 2);
    }
}
