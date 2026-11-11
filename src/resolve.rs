//! Hickory DNS shared by reqwest and firewall source lookups.
//!
//! Uses the system nameservers, search domains, and hosts file. UDP replies to
//! Docker's `127.0.0.11:53` may come from another port on that same address. Only
//! that peer gets a port exception; Hickory still checks the random query ID,
//! question, and records. All other nameservers keep strict peer checks.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::{Resolver, ResolverBuilder};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};
use tokio::task::{JoinError, JoinHandle};

use crate::error::Error;

const DOCKER_DNS: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 11), 53));

type DnsResolver = Resolver<DockerRuntime>;
type LookupTask = JoinHandle<Result<LookupIp, NetError>>;

static SYSTEM: OnceLock<Result<HostResolver, Error>> = OnceLock::new();

/// Cached resolver on a dedicated runtime, shared across blocking HTTP clients
/// and the synchronous DNS/firewall worker threads.
#[derive(Clone)]
pub(crate) struct HostResolver {
    resolver: DnsResolver,
    runtime: Arc<Runtime>,
}

impl HostResolver {
    /// Uses the OS configuration, or Docker's resolver if its file is unreadable.
    pub(crate) fn system() -> Result<Self, Error> {
        system_from(&SYSTEM)
    }

    fn query(&self, host: &str) -> LookupTask {
        let resolver = self.resolver.clone();
        let host = host.to_owned();
        self.runtime
            .spawn(async move { resolver.lookup_ip(host).await })
    }

    fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        finish_lookup(host, self.runtime.block_on(self.query(host)))
    }
}

fn system_from(cache: &OnceLock<Result<HostResolver, Error>>) -> Result<HostResolver, Error> {
    match cache.get_or_init(|| {
        build(
            system_builder(
                DnsResolver::builder(DockerRuntime::default()),
                std::path::Path::new("/.dockerenv").is_file(),
            ),
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

/// A Docker-managed resolver file can be inaccessible to the image's nonroot
/// user. Only that access error inside Docker selects the known local stub;
/// missing/invalid configuration and errors outside Docker remain fatal.
fn system_builder(
    builder: Result<ResolverBuilder<DockerRuntime>, NetError>,
    docker: bool,
) -> Result<ResolverBuilder<DockerRuntime>, NetError> {
    match builder {
        Err(NetError::Io(err)) if docker && err.kind() == io::ErrorKind::PermissionDenied => {
            log::warn!(
                "cannot read /etc/resolv.conf; using Docker DNS {DOCKER_DNS}; search domains are unavailable"
            );
            let (config, options) = docker_config();
            Ok(
                DnsResolver::builder_with_config(config, DockerRuntime::default())
                    .with_options(options),
            )
        }
        other => other,
    }
}

fn docker_config() -> (ResolverConfig, ResolverOpts) {
    let config = ResolverConfig::from_parts(
        None,
        vec![],
        vec![NameServerConfig::udp_and_tcp(DOCKER_DNS.ip())],
    );
    let mut options = ResolverOpts::default();
    options.ndots = 0;
    (config, options)
}

fn build(
    builder: Result<ResolverBuilder<DockerRuntime>, NetError>,
    runtime: io::Result<Runtime>,
) -> Result<HostResolver, Error> {
    let mut builder = builder.map_err(dns_config_error)?;
    let options = builder.options_mut();
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.try_tcp_on_error = true;
    assemble(builder.build(), runtime)
}

fn dns_config_error(err: NetError) -> Error {
    Error::wrap("DNS configuration", err)
}

fn assemble(
    resolver: Result<DnsResolver, NetError>,
    runtime: io::Result<Runtime>,
) -> Result<HostResolver, Error> {
    let resolver = resolver.map_err(dns_config_error)?;
    let runtime = runtime.map_err(|err| Error::wrap("DNS runtime", err))?;
    Ok(HostResolver {
        resolver,
        runtime: Arc::new(runtime),
    })
}

/// Resolves both families. An absent family is handled by the caller's filter.
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
        Ok(Err(err)) => Err(Error::wrap(format!("resolve {host}"), err)),
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

/// Delegates all I/O to Tokio, wrapping UDP to handle Docker's loopback peer.
#[derive(Clone, Default)]
struct DockerRuntime(TokioRuntimeProvider);

impl RuntimeProvider for DockerRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    type Udp = DockerUdp;

    fn create_handle(&self) -> Self::Handle {
        self.0.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        local: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tcp>> + Send>> {
        self.0.connect_tcp(server, local, timeout)
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
        let bound = self.0.bind_udp(local, server);
        Box::pin(async move {
            Ok(DockerUdp {
                socket: bound.await?,
                server,
            })
        })
    }
}

struct DockerUdp<S = UdpSocket> {
    socket: S,
    server: SocketAddr,
}

impl<S: DnsUdpSocket> DnsUdpSocket for DockerUdp<S> {
    type Time = S::Time;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        DnsUdpSocket::poll_recv_from(&self.socket, cx, buf)
            .map_ok(|(len, source)| (len, reply_source(self.server, source)))
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        DnsUdpSocket::poll_send_to(&self.socket, cx, buf, target)
    }
}

/// Only the exact Docker nameserver may reply from another port on the same IP.
fn reply_source(server: SocketAddr, source: SocketAddr) -> SocketAddr {
    if server == DOCKER_DNS && source.ip() == server.ip() {
        server
    } else {
        source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::Hosts;
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Message, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name as DnsName, RData, Record, RecordType};
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket as StdUdpSocket};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

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
            DnsResolver::builder_with_config(config(addr, true), DockerRuntime::default());
        builder.options_mut().timeout = Duration::from_millis(300);
        builder.options_mut().attempts = 1;
        build(Ok(builder), Ok(runtime())).unwrap()
    }

    #[test]
    fn port_exception_is_limited_to_the_exact_docker_peer() {
        let docker_high = "127.0.0.11:49152".parse().unwrap();
        assert_eq!(reply_source(DOCKER_DNS, docker_high), DOCKER_DNS);
        assert_eq!(reply_source(DOCKER_DNS, DOCKER_DNS), DOCKER_DNS);
        for source in [
            "127.0.0.1:49152",
            "127.0.0.12:53",
            "192.0.2.1:53",
            "[::1]:53",
        ] {
            let source = source.parse().unwrap();
            assert_eq!(reply_source(DOCKER_DNS, source), source);
        }
        for server in [
            "127.0.0.11:5353",
            "127.0.0.1:53",
            "192.0.2.1:53",
            "[::1]:53",
        ] {
            assert_eq!(
                reply_source(server.parse().unwrap(), docker_high),
                docker_high
            );
        }
    }

    /// Scripted transport exercises the real Hickory request validator without
    /// requiring a privileged port or a Linux loopback alias on the test host.
    #[derive(Clone)]
    struct ScriptedRuntime {
        inner: TokioRuntimeProvider,
        source: SocketAddr,
        queries: Arc<Mutex<Vec<Message>>>,
    }

    impl RuntimeProvider for ScriptedRuntime {
        type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
        type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
        type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
        type Udp = DockerUdp<ScriptedUdp>;

        fn create_handle(&self) -> Self::Handle {
            self.inner.create_handle()
        }

        fn connect_tcp(
            &self,
            server: SocketAddr,
            local: Option<SocketAddr>,
            timeout: Option<Duration>,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Tcp>> + Send>> {
            self.inner.connect_tcp(server, local, timeout)
        }

        fn bind_udp(
            &self,
            _local: SocketAddr,
            server: SocketAddr,
        ) -> Pin<Box<dyn Future<Output = io::Result<Self::Udp>> + Send>> {
            let socket = ScriptedUdp {
                source: self.source,
                pending: Mutex::new(VecDeque::new()),
                queries: Arc::clone(&self.queries),
            };
            Box::pin(async move { Ok(DockerUdp { socket, server }) })
        }
    }

    struct ScriptedUdp {
        source: SocketAddr,
        pending: Mutex<VecDeque<Vec<u8>>>,
        queries: Arc<Mutex<Vec<Message>>>,
    }

    impl DnsUdpSocket for ScriptedUdp {
        type Time = <UdpSocket as DnsUdpSocket>::Time;

        fn poll_recv_from(
            &self,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<(usize, SocketAddr)>> {
            match self.pending.lock().unwrap().pop_front() {
                Some(packet) => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Poll::Ready(Ok((packet.len(), self.source)))
                }
                None => Poll::Pending,
            }
        }

        fn poll_send_to(
            &self,
            _cx: &mut Context<'_>,
            buf: &[u8],
            _target: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            let query = Message::from_vec(buf).unwrap();
            self.queries.lock().unwrap().push(query.clone());
            let valid = answer(&query);
            let mut wrong_id = valid.clone();
            wrong_id.metadata.id = wrong_id.metadata.id.wrapping_add(1);
            let forged: IpAddr = if query.queries[0].query_type() == RecordType::A {
                "192.0.2.99".parse().unwrap()
            } else {
                "2001:db8::99".parse().unwrap()
            };
            wrong_id.answers = vec![Record::from_rdata(
                query.queries[0].name().clone(),
                60,
                RData::from(forged),
            )];
            let mut wrong_question = wrong_id.clone();
            wrong_question.metadata.id = valid.metadata.id;
            wrong_question.queries[0] = Query::query(
                DnsName::from_ascii("forged.example.").unwrap(),
                query.queries[0].query_type(),
            );
            let mut pending = self.pending.lock().unwrap();
            for packet in [wrong_id, wrong_question, valid] {
                pending.push_back(packet.to_vec().unwrap());
            }
            Poll::Ready(Ok(buf.len()))
        }
    }

    #[test]
    fn docker_udp_keeps_hickory_id_and_question_validation_and_caching() {
        let rt = runtime();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let provider = ScriptedRuntime {
            inner: TokioRuntimeProvider::default(),
            source: "127.0.0.11:49152".parse().unwrap(),
            queries: Arc::clone(&queries),
        };
        let mut builder =
            Resolver::builder_with_config(config(DOCKER_DNS, false), provider.clone());
        builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let resolver = builder.build().unwrap();
        rt.block_on(async {
            for _ in 0..2 {
                let ips: Vec<_> = resolver
                    .lookup_ip("host.example.")
                    .await
                    .unwrap()
                    .iter()
                    .collect();
                assert_eq!(ips, expected_ips());
            }
        });
        assert_eq!(queries.lock().unwrap().len(), 2);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        assert!(
            rt.block_on(provider.connect_tcp(closed, None, Some(Duration::from_millis(30))))
                .is_err()
        );
    }

    #[test]
    fn udp_rejects_wrong_ips_and_port_mismatches_for_other_nameservers() {
        let rt = runtime();
        for (server, source) in [
            (DOCKER_DNS, "127.0.0.1:49152"),
            ("127.0.0.1:53".parse().unwrap(), "127.0.0.1:49152"),
            ("192.0.2.1:53".parse().unwrap(), "192.0.2.1:49152"),
            ("127.0.0.11:5353".parse().unwrap(), "127.0.0.11:49152"),
        ] {
            let provider = ScriptedRuntime {
                inner: TokioRuntimeProvider::default(),
                source: source.parse().unwrap(),
                queries: Arc::default(),
            };
            let mut builder = Resolver::builder_with_config(config(server, false), provider);
            builder.options_mut().timeout = Duration::from_millis(30);
            builder.options_mut().attempts = 1;
            let resolver = builder.build().unwrap();
            assert!(rt.block_on(resolver.lookup_ip("host.example.")).is_err());
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
                while !stopped.load(Ordering::Relaxed) {
                    match tcp.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(50)))
                                .unwrap();
                            let mut size = [0; 2];
                            while stream.read_exact(&mut size).is_ok() {
                                let mut buf = vec![0; usize::from(u16::from_be_bytes(size))];
                                stream.read_exact(&mut buf).unwrap();
                                seen.lock().unwrap().push(true);
                                let reply =
                                    answer(&Message::from_vec(&buf).unwrap()).to_vec().unwrap();
                                stream
                                    .write_all(&(reply.len() as u16).to_be_bytes())
                                    .unwrap();
                                stream.write_all(&reply).unwrap();
                            }
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(2)),
                    }
                }
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
        resolver.resolver.set_hosts(Arc::new(hosts));
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
        assert!(
            build(Err(NetError::Message("missing config")), Ok(runtime()))
                .err()
                .unwrap()
                .to_string()
                .contains("DNS configuration")
        );
        assert!(
            assemble(Err(NetError::Message("bad config")), Ok(runtime()))
                .err()
                .unwrap()
                .to_string()
                .contains("DNS configuration")
        );
        let builder =
            DnsResolver::builder_with_config(config(DOCKER_DNS, false), DockerRuntime::default());
        assert!(
            assemble(builder.build(), Err(io::Error::other("no runtime")))
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
        rt.block_on(async {
            let bound = StdUdpSocket::bind("127.0.0.1:0").unwrap();
            assert!(
                DockerRuntime::default()
                    .bind_udp(bound.local_addr().unwrap(), DOCKER_DNS)
                    .await
                    .is_err()
            );
        });
    }

    #[test]
    fn unreadable_config_uses_only_dockers_local_resolver_inside_docker() {
        let denied = || Err(io::Error::from(io::ErrorKind::PermissionDenied).into());
        let (fallback, options) = docker_config();
        assert_eq!(fallback.name_servers.len(), 1);
        let server = &fallback.name_servers[0];
        assert_eq!(server.ip, DOCKER_DNS.ip());
        assert_eq!(server.connections.len(), 2);
        assert!(
            server
                .connections
                .iter()
                .all(|connection| connection.port == 53)
        );
        use hickory_resolver::config::ProtocolConfig;
        assert_eq!(server.connections[0].protocol, ProtocolConfig::Udp);
        assert_eq!(server.connections[1].protocol, ProtocolConfig::Tcp);
        assert_eq!(options.ndots, 0);
        assert!(fallback.search.is_empty());

        let mut builder = system_builder(denied(), true).unwrap();
        assert_eq!(builder.options_mut().ndots, 0);
        assert!(builder.build().is_ok());
        assert!(system_builder(denied(), false).is_err());
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::InvalidData] {
            let error = io::Error::from(kind);
            assert!(system_builder(Err(error.into()), true).is_err());
        }
        assert!(system_builder(Err(NetError::Message("bad config")), true).is_err());

        let config = config("192.0.2.53:5353".parse().unwrap(), true);
        let mut options = ResolverOpts::default();
        options.ndots = 3;
        let original = DnsResolver::builder_with_config(config, DockerRuntime::default())
            .with_options(options);
        let mut builder = system_builder(Ok(original), true).unwrap();
        assert_eq!(builder.options_mut().ndots, 3);
    }
}
