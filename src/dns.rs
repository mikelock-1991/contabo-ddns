//! PATCH existing A records (and optionally POST missing exact names) to the current IP.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use serde_json::{json, Value};

use crate::config::{DnsConfig, DnsTarget};
use crate::contabo::{encode_path_segment, ContaboClient};
use crate::error::Error;

/// TTL for created records when `DNS_TTL` is unset.
const DEFAULT_CREATE_TTL: u64 = 300;

/// Updates matching A records to `ip`; optionally creates missing exact names.
///
/// Wildcards only touch existing A records. TXT and other types are skipped.
pub fn sync(
    client: &ContaboClient<'_>,
    cfg: &DnsConfig,
    ip: Ipv4Addr,
    dry_run: bool,
) -> Result<(), Error> {
    let ip_text = ip.to_string();
    let zones = zone_names(client)?;
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    let mut matched_targets = HashSet::new();

    let zones: Vec<String> = zones
        .into_iter()
        .filter(|zone| zone_overlaps(zone, &cfg.records))
        .collect();
    for zone in &zones {
        let records = match client.list(&format!(
            "/v1/dns/zones/{}/records",
            encode_path_segment(zone)
        )) {
            Ok(records) => records,
            Err(err) => {
                errors.push(format!("list {zone}: {err}"));
                continue;
            }
        };
        for record in records {
            let record_type = record
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_uppercase();
            if record_type != "A" {
                continue;
            }
            let Some(name) = record.get("name").and_then(Value::as_str) else {
                log::warn!("A record in {zone} has no name");
                continue;
            };
            let fqdn = record_fqdn(name, zone);
            if !target_matches(&fqdn, &cfg.records) {
                continue;
            }
            seen.insert(fqdn.clone());
            mark_targets(&fqdn, &cfg.records, &mut matched_targets);
            let current = record
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if current == ip_text {
                log::info!("dns unchanged {fqdn} {ip_text}");
                continue;
            }
            let record_id = match json_id(record.get("recordId")) {
                Some(id) => id,
                None => {
                    errors.push(format!("A record {fqdn} has no recordId"));
                    continue;
                }
            };
            let ttl = cfg
                .ttl
                .or_else(|| record.get("ttl").and_then(Value::as_u64));
            let Some(ttl) = ttl else {
                errors.push(format!("A record {fqdn} has no ttl"));
                continue;
            };
            let prio = record.get("prio").and_then(Value::as_i64).unwrap_or(0);
            log::info!("dns update {fqdn} {current} -> {ip_text}");
            if dry_run {
                log::info!("dry-run: skip PATCH {fqdn}");
                continue;
            }
            let path = format!(
                "/v1/dns/zones/{}/records/{record_id}",
                encode_path_segment(zone)
            );
            let body = json!({
                "ttl": ttl,
                "prio": prio,
                "type": "A",
                "data": ip_text,
            });
            if let Err(err) = client.patch_json(&path, &body) {
                errors.push(format!("patch {fqdn}: {err}"));
            }
        }
    }

    if cfg.create_missing {
        for target in &cfg.records {
            let DnsTarget::Exact(host) = target else {
                continue;
            };
            if seen.contains(host) {
                continue;
            }
            let Some(zone) = longest_zone(host, &zones) else {
                errors.push(format!("no zone for {host}"));
                continue;
            };
            let name = relative_name(host, zone);
            let ttl = cfg.ttl.unwrap_or(DEFAULT_CREATE_TTL);
            log::info!("dns create {host} -> {ip_text}");
            if dry_run {
                log::info!("dry-run: skip POST {host}");
                continue;
            }
            let body = json!({
                "name": name,
                "type": "A",
                "ttl": ttl,
                "prio": 0,
                "data": ip_text,
            });
            let path = format!("/v1/dns/zones/{}/records", encode_path_segment(zone));
            if let Err(err) = client.post_json(&path, &body) {
                errors.push(format!("create {host}: {err}"));
            }
        }
    } else {
        for target in &cfg.records {
            if let DnsTarget::Exact(host) = target {
                if !seen.contains(host) {
                    log::warn!("no A record for {host}");
                }
            }
        }
    }
    for target in &cfg.records {
        if let DnsTarget::Wildcard(parent) = target {
            if !matched_targets.contains(&format!("*.{parent}")) {
                log::warn!("wildcard *.{parent} matched no A records");
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::new(errors.join("; ")))
    }
}

/// Lists unique lowercase zone names from `GET /v1/dns/zones`.
fn zone_names(client: &ContaboClient<'_>) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for zone in client.list("/v1/dns/zones")? {
        if let Some(name) = zone.get("zoneName").and_then(Value::as_str) {
            let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Builds a lowercase FQDN from a record name (`@`, relative, or already-qualified).
fn record_fqdn(name: &str, zone: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let zone = zone.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name == "@" || name == zone {
        zone
    } else if is_under(&name, &zone) {
        name
    } else {
        format!("{name}.{zone}")
    }
}

/// True when `fqdn` equals an exact target or sits under a wildcard parent.
fn hits(fqdn: &str, target: &DnsTarget) -> bool {
    match target {
        DnsTarget::Exact(host) => fqdn == host,
        DnsTarget::Wildcard(parent) => fqdn == parent || is_under(fqdn, parent),
    }
}

/// True when `name` is a strict subdomain of `parent` (`a.example.com` under `example.com`).
fn is_under(name: &str, parent: &str) -> bool {
    name.strip_suffix(parent)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// True when `fqdn` is an exact target or under a configured wildcard parent.
fn target_matches(fqdn: &str, targets: &[DnsTarget]) -> bool {
    targets.iter().any(|target| hits(fqdn, target))
}

/// Records which configured targets actually matched an existing A record.
fn mark_targets(fqdn: &str, targets: &[DnsTarget], matched: &mut HashSet<String>) {
    for target in targets {
        if hits(fqdn, target) {
            matched.insert(match target {
                DnsTarget::Exact(host) => host.clone(),
                DnsTarget::Wildcard(parent) => format!("*.{parent}"),
            });
        }
    }
}

/// Picks the longest zone suffix that contains `host` (for create-missing).
fn longest_zone<'a>(host: &str, zones: &'a [String]) -> Option<&'a str> {
    zones
        .iter()
        .filter(|zone| *zone == host || is_under(host, zone))
        .max_by_key(|zone| zone.len())
        .map(String::as_str)
}

/// Relative label to POST when creating `host` inside `zone`. The apex is `@`.
fn relative_name(host: &str, zone: &str) -> String {
    if host == zone {
        return "@".into();
    }
    host.strip_suffix(zone)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .filter(|label| !label.is_empty())
        .unwrap_or("@")
        .to_string()
}

/// True when a zone can hold an A record for one of the configured targets.
///
/// An exact name matches its own zone and every parent zone. A wildcard matches
/// the parent zone, a zone under that parent, and a zone that contains the parent.
fn zone_overlaps(zone: &str, targets: &[DnsTarget]) -> bool {
    targets.iter().any(|target| match target {
        DnsTarget::Exact(host) => host == zone || is_under(host, zone),
        DnsTarget::Wildcard(parent) => {
            zone == parent || is_under(zone, parent) || is_under(parent, zone)
        }
    })
}

/// Reads a JSON id that may be a number or a string.
fn json_id(value: Option<&Value>) -> Option<String> {
    value.and_then(|item| {
        item.as_u64()
            .map(|id| id.to_string())
            .or_else(|| item.as_str().map(str::to_string))
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_id_accepts_number_or_string() {
        assert_eq!(super::json_id(Some(&json!(7))), Some("7".into()));
        assert_eq!(super::json_id(Some(&json!("abc"))), Some("abc".into()));
        assert_eq!(super::json_id(Some(&json!(true))), None);
        assert_eq!(super::json_id(None), None);
    }

    use super::*;
    use crate::contabo::HttpRequest;
    use crate::test_http::{client, token_route, Scripted};

    fn zones(body: &str) -> (&'static str, &'static str, u16, String) {
        ("GET", "/v1/dns/zones?", 200, body.into())
    }

    fn cfg(records: Vec<DnsTarget>, create_missing: bool, ttl: Option<u64>) -> DnsConfig {
        DnsConfig {
            records,
            ttl,
            create_missing,
        }
    }

    fn calls_of(http: &Scripted) -> Vec<HttpRequest> {
        http.calls.lock().unwrap().clone()
    }

    #[test]
    fn fqdn_forms() {
        assert_eq!(record_fqdn("home", "example.com"), "home.example.com");
        assert_eq!(
            record_fqdn("home.example.com.", "example.com"),
            "home.example.com"
        );
        assert_eq!(record_fqdn("@", "example.com"), "example.com");
        assert_eq!(record_fqdn("example.com", "example.com"), "example.com");
        assert_eq!(
            record_fqdn("badexample.com", "example.com"),
            "badexample.com.example.com"
        );
        assert!(!is_under("badexample.com", "example.com"));
        assert!(is_under("a.example.com", "example.com"));
        assert_eq!(
            relative_name("bar.foo.example.com", "foo.example.com"),
            "bar"
        );
        assert_eq!(relative_name("example.com", "example.com"), "@");
        assert!(zone_overlaps(
            "example.com",
            &[DnsTarget::Exact("home.example.com".into())]
        ));
        assert!(zone_overlaps(
            "foo.example.com",
            &[DnsTarget::Wildcard("example.com".into())]
        ));
        assert!(zone_overlaps(
            "example.com",
            &[DnsTarget::Wildcard("foo.example.com".into())]
        ));
        assert!(!zone_overlaps(
            "other.test",
            &[DnsTarget::Exact("home.example.com".into())]
        ));
        assert!(target_matches(
            "a.example.com",
            &[DnsTarget::Wildcard("example.com".into())]
        ));
        assert!(target_matches(
            "example.com",
            &[DnsTarget::Wildcard("example.com".into())]
        ));
        assert!(!target_matches(
            "example.org",
            &[DnsTarget::Wildcard("example.com".into())]
        ));
    }

    #[test]
    fn patches_changed_a_record_and_skips_same_and_txt() {
        let records = r#"{"_pagination":{"page":1,"totalPages":1},"data":[
            {"recordId":1,"name":"home","type":"A","ttl":3600,"prio":0,"data":"1.1.1.1"},
            {"recordId":2,"name":"www","type":"A","ttl":120,"prio":0,"data":"203.0.113.10"},
            {"recordId":3,"name":"home","type":"TXT","ttl":120,"prio":0,"data":"keep"}
        ]}"#;
        let http = Scripted::new(vec![
            token_route(),
            zones(
                r#"{"_pagination":{"page":1,"totalPages":1},"data":[{"zoneName":"example.com"}]}"#,
            ),
            ("GET", "/records", 200, records.into()),
            ("PATCH", "/records/1", 200, r#"{"data":[]}"#.into()),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(
                vec![
                    DnsTarget::Exact("home.example.com".into()),
                    DnsTarget::Exact("www.example.com".into()),
                ],
                false,
                Some(60),
            ),
            Ipv4Addr::new(203, 0, 113, 10),
            false,
        )
        .unwrap();
        let calls = calls_of(&http);
        let patches: Vec<_> = calls.iter().filter(|call| call.method == "PATCH").collect();
        assert_eq!(patches.len(), 1);
        let body: Value = serde_json::from_slice(patches[0].body.as_ref().unwrap()).unwrap();
        assert_eq!(body["data"], "203.0.113.10");
        assert_eq!(body["ttl"], 60);
        assert_eq!(body["type"], "A");
        assert!(calls.iter().all(|call| !call.url.contains("/records/3")));
    }

    #[test]
    fn dry_run_and_wildcard_do_not_create() {
        let records = r#"{"_pagination":{"page":1,"totalPages":1},"data":[
            {"recordId":9,"name":"@","type":"A","ttl":300,"prio":0,"data":"0.0.0.0"}
        ]}"#;
        let http = Scripted::new(vec![
            token_route(),
            zones(
                r#"{"_pagination":{"page":1,"totalPages":1},"data":[{"zoneName":"example.com"},{"zoneName":"foo.example.com"}]}"#,
            ),
            (
                "GET",
                "zones/foo.example.com/records",
                200,
                r#"{"data":[]}"#.into(),
            ),
            ("GET", "/records", 200, records.into()),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(vec![DnsTarget::Wildcard("example.com".into())], true, None),
            Ipv4Addr::new(203, 0, 113, 7),
            true,
        )
        .unwrap();
        let calls = calls_of(&http);
        assert!(calls
            .iter()
            .filter(|call| call.url.contains("/records"))
            .all(|call| call.method == "GET"));
    }

    #[test]
    fn creates_missing_exact_name_in_longest_zone() {
        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"},{"zoneName":"foo.example.com"}]}"#),
            ("GET", "/records", 200, r#"{"data":[]}"#.into()),
            (
                "POST",
                "zones/foo.example.com/records",
                200,
                r#"{"data":[]}"#.into(),
            ),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(
                vec![DnsTarget::Exact("bar.foo.example.com".into())],
                true,
                None,
            ),
            Ipv4Addr::new(203, 0, 113, 4),
            false,
        )
        .unwrap();
        let calls = calls_of(&http);
        let post = calls
            .iter()
            .find(|call| call.method == "POST" && call.url.contains("/records"))
            .unwrap();
        assert!(post.url.contains("/v1/dns/zones/foo.example.com/records"));
        let body: Value = serde_json::from_slice(post.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["name"], "bar");
        assert_eq!(body["data"], "203.0.113.4");
    }

    #[test]
    fn creates_apex_and_skips_unrelated_zones() {
        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"},{"zoneName":"other.test"}]}"#),
            (
                "GET",
                "zones/example.com/records",
                200,
                r#"{"data":[]}"#.into(),
            ),
            ("POST", "/records", 200, r#"{"data":[]}"#.into()),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(vec![DnsTarget::Exact("example.com".into())], true, None),
            Ipv4Addr::new(203, 0, 113, 4),
            false,
        )
        .unwrap();
        let calls = calls_of(&http);
        assert!(calls.iter().all(|call| !call.url.contains("other.test")));
        let post = calls
            .iter()
            .find(|call| call.method == "POST" && call.url.contains("/records"))
            .unwrap();
        let body: Value = serde_json::from_slice(post.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["name"], "@");
    }

    #[test]
    fn reports_api_and_record_problems() {
        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"},{"zoneName":""}]}"#),
            ("GET", "/records", 500, "broken".into()),
        ]);
        let api = client(&http);
        let err = sync(
            &api,
            &cfg(
                vec![DnsTarget::Exact("home.example.com".into())],
                false,
                None,
            ),
            Ipv4Addr::new(1, 2, 3, 4),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("list example.com"));

        let records = r#"{"data":[
            {"recordId":1,"name":"","type":"A","ttl":60,"data":"1.1.1.1"},
            {"name":"other","type":"A","ttl":60,"data":"1.1.1.1"},
            {"recordId":2,"name":"home","type":"A","data":"1.1.1.1"},
            {"recordId":3,"name":"www","type":"A","ttl":60,"data":"1.1.1.1"},
            {"recordId":4,"name":"bad","type":"A","ttl":60,"data":"0.0.0.0"}
        ]}"#;
        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"}]}"#),
            ("GET", "/records", 200, records.into()),
            ("PATCH", "/records/4", 500, "no".into()),
        ]);
        let api = client(&http);
        let err = sync(
            &api,
            &cfg(
                vec![
                    DnsTarget::Exact("home.example.com".into()),
                    DnsTarget::Exact("www.example.com".into()),
                    DnsTarget::Exact("missing.example.com".into()),
                    DnsTarget::Wildcard("example.com".into()),
                    DnsTarget::Exact("bad.example.com".into()),
                ],
                false,
                None,
            ),
            Ipv4Addr::new(203, 0, 113, 99),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("recordId"));
        assert!(err.to_string().contains("ttl"));
        assert!(err.to_string().contains("patch bad.example.com"));

        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"}]}"#),
            ("GET", "/records", 200, r#"{"data":[]}"#.into()),
            ("POST", "/records", 500, "no".into()),
        ]);
        let api = client(&http);
        let err = sync(
            &api,
            &cfg(
                vec![DnsTarget::Exact("new.example.com".into())],
                true,
                Some(60),
            ),
            Ipv4Addr::new(9, 9, 9, 9),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("create new.example.com"));

        sync(
            &api,
            &cfg(
                vec![DnsTarget::Exact("orphan.example.net".into())],
                true,
                None,
            ),
            Ipv4Addr::new(1, 1, 1, 1),
            true,
        )
        .unwrap_err();

        sync(
            &api,
            &cfg(
                vec![DnsTarget::Wildcard("nope.example".into())],
                false,
                None,
            ),
            Ipv4Addr::new(8, 8, 8, 8),
            true,
        )
        .unwrap();
    }

    #[test]
    fn skips_unlisted_records_and_dry_run_create() {
        let records = r#"{"data":[
            {"type":"A","ttl":60,"data":"1.1.1.1"},
            {"recordId":2,"name":"other","type":"A","ttl":60,"data":"1.1.1.1"},
            {"recordId":3,"name":"home","type":"A","ttl":60,"data":"1.1.1.1"}
        ]}"#;
        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"zoneName":"example.com"},{"zoneName":""}]}"#),
            ("GET", "/records", 200, records.into()),
            ("POST", "/records", 200, "{}".into()),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(
                vec![
                    DnsTarget::Exact("home.example.com".into()),
                    DnsTarget::Exact("new.example.com".into()),
                ],
                true,
                Some(120),
            ),
            Ipv4Addr::new(198, 51, 100, 1),
            true,
        )
        .unwrap();
        let calls = calls_of(&http);
        assert!(calls
            .iter()
            .filter(|call| call.url.contains("/dns/zones/") && call.url.contains("/records"))
            .all(|call| call.method != "POST"));

        let http = Scripted::new(vec![
            token_route(),
            zones(r#"{"data":[{"other":"skip"},{"zoneName":""},{"zoneName":"example.com"}]}"#),
            (
                "GET",
                "/records",
                200,
                r#"{"data":[{"recordId":1,"name":"home","type":"A","ttl":60,"data":"1.1.1.1"}]}"#
                    .into(),
            ),
            ("PATCH", "/records/1", 200, "{}".into()),
        ]);
        let api = client(&http);
        sync(
            &api,
            &cfg(
                vec![DnsTarget::Exact("home.example.com".into())],
                false,
                None,
            ),
            Ipv4Addr::new(198, 51, 100, 7),
            false,
        )
        .unwrap();
    }
}
