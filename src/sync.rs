//! One sync cycle: fetch public IP, then update DNS and firewall in parallel.

use std::thread;

use crate::config::Config;
use crate::contabo::ContaboClient;
use crate::error::Error;
use crate::firewall::FirewallState;
use crate::ip::{fetch_public_ip, Resolver};

/// Fetches the public IP when needed, then runs DNS and firewall sync on threads.
///
/// DNS and firewall share one token-caching `ContaboClient`. A failed IP lookup
/// skips DNS and any firewall that uses `current`, but a firewall with only literal
/// or hostname sources still syncs. Errors from every step are joined with `"; "`.
pub fn run_cycle(
    cfg: &Config,
    client: &ContaboClient<'_>,
    resolver: &dyn Resolver,
    firewall_state: &FirewallState,
) -> Result<(), Error> {
    log::info!("sync start");
    if cfg.dry_run {
        log::info!("dry-run: PATCH and PUT are disabled");
    }
    let firewall_needs_ip = cfg.firewall.as_ref().is_some_and(|firewall| {
        firewall
            .rules
            .iter()
            .any(|rule| rule.sources.iter().any(|source| source.trim() == "current"))
    });
    let mut errors = Vec::new();
    let ip = if cfg.dns.is_some() || firewall_needs_ip {
        match fetch_public_ip(
            client.http(),
            &cfg.ip_echo_urls,
            cfg.ip_echo_timeout,
            client.shutdown(),
            client.retry_delay(),
        ) {
            Ok(ip) => {
                log::info!("public ip {ip}");
                Some(ip)
            }
            Err(err) => {
                errors.push(err.to_string());
                None
            }
        }
    } else {
        None
    };
    let firewall = cfg.firewall.as_ref();
    let firewall = if firewall_needs_ip && ip.is_none() {
        log::warn!("firewall skipped: a rule uses current and the public ip is unknown");
        None
    } else {
        firewall
    };

    thread::scope(|scope| {
        let dns_job =
            cfg.dns.as_ref().zip(ip).map(|(dns, ip)| {
                scope.spawn(move || crate::dns::sync(client, dns, ip, cfg.dry_run))
            });
        let firewall_job = firewall.map(|firewall| {
            scope.spawn(|| {
                crate::firewall::sync(client, firewall, ip, resolver, cfg.dry_run, firewall_state)
            })
        });
        if let Some(job) = dns_job {
            if let Err(err) = join_job(job.join(), "dns") {
                errors.push(err.to_string());
            }
        }
        if let Some(job) = firewall_job {
            if let Err(err) = join_job(job.join(), "firewall") {
                errors.push(err.to_string());
            }
        }
    });
    if errors.is_empty() {
        log::info!("sync done");
        Ok(())
    } else {
        Err(Error::new(errors.join("; ")))
    }
}

/// Unwraps a scoped-thread join: inner `Err` stays, a panic becomes `{label} thread panicked`.
fn join_job<T>(result: thread::Result<Result<T, Error>>, label: &str) -> Result<T, Error> {
    match result {
        Ok(value) => value,
        Err(_) => Err(Error::new(format!("{label} thread panicked"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contabo::{Http, HttpRequest, HttpResponse};
    use crate::ip::MapResolver;
    use std::sync::Mutex;
    use std::time::Duration;

    fn api<'a>(cfg: &'a Config, http: &'a dyn Http) -> ContaboClient<'a> {
        ContaboClient::from_config(http, cfg).with_delay(crate::retry::immediate)
    }

    fn firewall_cfg(dns_records: &str, sources: &str) -> Config {
        let rules = format!(r#"[{{"displayName":"SSH","sources":[{sources}]}}]"#);
        Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", dns_records),
            (
                "DNS_ENABLED",
                if dns_records.is_empty() {
                    "false"
                } else {
                    "true"
                },
            ),
            ("FIREWALL_ID", "fw-1"),
            ("FIREWALL_RULES", rules.as_str()),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap()
    }

    #[test]
    fn ip_failure_still_syncs_literal_firewall() {
        let cfg = firewall_cfg("home.example.com", r#""203.0.113.5""#);
        let http = Scripted {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        let err = run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap_err();
        assert!(err.to_string().contains("public ip lookup failed"));
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().any(|url| url.contains("/v1/firewalls/fw-1")));
        assert!(calls.iter().all(|url| !url.contains("/v1/dns/")));
    }

    #[test]
    fn ip_failure_skips_firewall_that_uses_current() {
        let cfg = firewall_cfg("", r#""current""#);
        let http = Scripted {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        let err = run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap_err();
        assert!(err.to_string().contains("public ip lookup failed"));
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().all(|url| !url.contains("/v1/firewalls/")));
    }

    struct Scripted {
        calls: Mutex<Vec<String>>,
    }

    impl Http for Scripted {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
            self.calls.lock().unwrap().push(request.url.clone());
            if request.url.contains("ipecho") {
                return Err(Error::new("ipecho should not be called"));
            }
            if request.url.contains("/token") {
                return Ok(HttpResponse {
                    status: 200,
                    body: br#"{"access_token":"tok","expires_in":3600}"#.to_vec(),
                });
            }
            if request.method == "GET" && request.url.contains("/v1/firewalls/") {
                let body = r#"{
                    "data": [{
                        "firewallId": "fw-1",
                        "rules": {"inbound": [{
                            "protocol": "tcp",
                            "destPorts": ["22"],
                            "srcCidr": {"ipv4": ["203.0.113.5/32"], "ipv6": ["AnyIPv6"]},
                            "action": "accept",
                            "status": "active",
                            "displayName": "SSH"
                        }]}
                    }]
                }"#;
                return Ok(HttpResponse {
                    status: 200,
                    body: body.as_bytes().to_vec(),
                });
            }
            crate::test_http::reject(request)
        }
    }

    #[test]
    fn dry_run_cycle_fetches_ip_and_collects_errors() {
        let cfg = Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com"),
            ("FIREWALL_ID", "fw-1"),
            (
                "FIREWALL_RULES",
                r#"[{"displayName":"SSH","sources":["current"]}]"#,
            ),
            ("DRY_RUN", "true"),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap();
        struct Chain {
            step: Mutex<u8>,
        }
        impl Http for Chain {
            fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
                let mut step = self.step.lock().unwrap();
                *step += 1;
                if request.url.contains("ipecho") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: b"203.0.113.44".to_vec(),
                    });
                }
                if request.url.contains("/token") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: br#"{"access_token":"tok","expires_in":3600}"#.to_vec(),
                    });
                }
                if request.method == "GET" && request.url.contains("/v1/dns/zones?") {
                    return Err(Error::new("dns list down"));
                }
                if request.method == "GET" && request.url.contains("/v1/firewalls/") {
                    return Err(Error::new("firewall read down"));
                }
                crate::test_http::reject(request)
            }
        }
        let http = Chain {
            step: Mutex::new(0),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        let err = run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap_err();
        assert!(err.to_string().contains("dns list down"));
        assert!(err.to_string().contains("firewall read down"));
        assert!(http
            .send(&HttpRequest {
                method: "PATCH".into(),
                url: "https://api.example.test/leftover".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err()
            .to_string()
            .contains("unexpected"));
    }

    #[test]
    fn join_job_maps_panic_and_inner_error() {
        let panicked: std::thread::Result<Result<(), Error>> = Err(Box::new("boom"));
        assert!(join_job(panicked, "dns")
            .unwrap_err()
            .to_string()
            .contains("dns thread panicked"));
        assert!(join_job::<()>(Ok(Err(Error::new("dns list down"))), "dns")
            .unwrap_err()
            .to_string()
            .contains("dns list down"));
        join_job::<()>(Ok(Ok(())), "dns").unwrap();
    }

    #[test]
    fn skips_ipecho_when_only_literal_firewall_sources() {
        let cfg = Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_ENABLED", "false"),
            ("FIREWALL_ID", "fw-1"),
            (
                "FIREWALL_RULES",
                r#"[{"displayName":"SSH","sources":["203.0.113.5"]}]"#,
            ),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap();
        let http = Scripted {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap();
        {
            let calls = http.calls.lock().unwrap();
            assert!(calls.iter().all(|url| !url.contains("ipecho")));
        }
        assert!(cfg.ip_echo_timeout == Duration::from_secs(10));
        assert!(http
            .send(&HttpRequest {
                method: "GET".into(),
                url: "https://ipecho.test/plain".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err()
            .to_string()
            .contains("ipecho"));
        assert!(http
            .send(&HttpRequest {
                method: "PATCH".into(),
                url: "https://api.example.test/unexpected".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err()
            .to_string()
            .contains("unexpected"));
    }

    #[test]
    fn run_cycle_succeeds_when_dns_is_unchanged() {
        let cfg = Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com"),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap();
        let http = crate::test_http::DnsCycleOk {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap();
    }

    #[test]
    fn run_cycle_surfaces_unexpected_http() {
        let cfg = Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com"),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap();
        let http = crate::test_http::Unscripted {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        assert!(run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).is_err());
    }

    #[test]
    fn dry_run_firewall_and_dns_success() {
        let cfg = Config::from_pairs([
            ("CONTABO_CLIENT_ID", "id"),
            ("CONTABO_CLIENT_SECRET", "secret"),
            ("CONTABO_API_USER", "user@example.com"),
            ("CONTABO_API_PASSWORD", "pw"),
            ("DNS_RECORDS", "home.example.com"),
            ("FIREWALL_ID", "fw-1"),
            (
                "FIREWALL_RULES",
                r#"[{"displayName":"SSH","sources":["203.0.113.5"]}]"#,
            ),
            ("DRY_RUN", "true"),
            ("INTERVAL_SECONDS", "0"),
            ("LOG_DIR", ""),
            ("IP_ECHO_URL", "https://ipecho.test/plain"),
        ])
        .unwrap();
        struct Both {
            calls: Mutex<Vec<String>>,
        }
        impl Http for Both {
            fn send(&self, request: &HttpRequest) -> Result<HttpResponse, Error> {
                self.calls.lock().unwrap().push(request.url.clone());
                if request.url.contains("ipecho") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: b"203.0.113.10".to_vec(),
                    });
                }
                if request.url.contains("/token") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: br#"{"access_token":"tok","expires_in":3600}"#.to_vec(),
                    });
                }
                if request.method == "GET" && request.url.contains("/v1/dns/zones?") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: br#"{"data":[{"zoneName":"example.com"}]}"#.to_vec(),
                    });
                }
                if request.method == "GET" && request.url.contains("/records") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: br#"{"data":[{"recordId":1,"name":"home","type":"A","ttl":60,"prio":0,"data":"203.0.113.11"}]}"#.to_vec(),
                    });
                }
                if request.method == "GET" && request.url.contains("/v1/firewalls/") {
                    return Ok(HttpResponse {
                        status: 200,
                        body: br#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[{"displayName":"SSH","srcCidr":{"ipv4":["203.0.113.5/32"]}}]}}]}"#.to_vec(),
                    });
                }
                crate::test_http::reject(request)
            }
        }
        let http = Both {
            calls: Mutex::new(Vec::new()),
        };
        let resolver = MapResolver {
            values: std::collections::HashMap::new(),
        };
        run_cycle(&cfg, &api(&cfg, &http), &resolver, &FirewallState::new()).unwrap();
        {
            let calls = http.calls.lock().unwrap();
            assert!(calls.iter().all(|url| !url.contains("PUT")));
            assert!(calls.iter().all(|url| !url.contains("PATCH")));
        }
        assert!(http
            .send(&HttpRequest {
                method: "POST".into(),
                url: "https://api.example.test/unexpected".into(),
                headers: vec![],
                body: None,
                timeout: None,
                max_body: None,
            })
            .unwrap_err()
            .to_string()
            .contains("unexpected"));
    }
}
