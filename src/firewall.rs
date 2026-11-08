//! Rewrite IPv4 sources on named Contabo firewall inbound rules.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use serde_json::{Value, json};

use crate::config::FirewallConfig;
use crate::contabo::{ContaboClient, encode_path_segment};
use crate::error::Error;
use crate::ip::{Resolver, resolve_sources};

/// Remembers a firewall id looked up by name for the life of the process.
pub struct FirewallState {
    id: Mutex<Option<String>>,
}

impl FirewallState {
    /// Empty cache.
    pub fn new() -> Self {
        Self {
            id: Mutex::new(None),
        }
    }

    fn cached(&self) -> Option<String> {
        self.id
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    fn store(&self, id: String) {
        *self.id.lock().unwrap_or_else(|err| err.into_inner()) = Some(id);
    }

    fn clear(&self) {
        *self.id.lock().unwrap_or_else(|err| err.into_inner()) = None;
    }

    #[cfg(test)]
    fn poison_cache(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.id.lock().unwrap();
            panic!("poison firewall id");
        }));
    }
}

/// Resolves planned sources, then PUTs inbound rules when IPv4 lists changed.
///
/// Fail-closed: missing rule names, empty resolved lists, or lookup errors skip PUT.
/// A 404 on a name-looked-up id clears `state` and looks the name up once more.
pub fn sync(
    client: &ContaboClient<'_>,
    cfg: &FirewallConfig,
    current: Option<Ipv4Addr>,
    resolver: &dyn Resolver,
    dry_run: bool,
    state: &FirewallState,
) -> Result<(), Error> {
    let mut planned = Vec::new();
    for rule in &cfg.rules {
        planned.push((
            rule.display_name.clone(),
            resolve_sources(&rule.sources, current, resolver)?,
        ));
    }

    let (firewall_id, mut updated) = load_inbound(client, cfg, state)?;
    for (name, _) in &planned {
        let matches = updated
            .iter()
            .filter(|rule| display_name(rule) == Some(name))
            .count();
        if matches == 0 {
            return Err(Error::new(format!("no firewall rule named {name}")));
        }
    }

    let mut changed = false;
    for rule in &mut updated {
        let Some(name) = display_name(rule) else {
            continue;
        };
        let Some((_, sources)) = planned
            .iter()
            .find(|(planned_name, _)| planned_name == name)
        else {
            continue;
        };
        let old = ipv4_list(rule)?;
        if same_set(&old, sources) {
            log::info!("firewall unchanged {name}");
            continue;
        }
        log::info!("firewall update {name} {old:?} -> {sources:?}");
        set_ipv4(rule, sources)?;
        changed = true;
    }
    if !changed {
        return Ok(());
    }
    if dry_run {
        log::info!("dry-run: skip PUT firewall {firewall_id}");
        return Ok(());
    }
    let payload = json!({ "rules": { "inbound": updated } });
    client.put_json(
        &format!("/v1/firewalls/{}", encode_path_segment(&firewall_id)),
        &payload,
    )?;
    log::info!("firewall updated {firewall_id}");
    Ok(())
}

/// GETs inbound rules, retrying a name lookup once when the cached id is gone.
fn load_inbound(
    client: &ContaboClient<'_>,
    cfg: &FirewallConfig,
    state: &FirewallState,
) -> Result<(String, Vec<Value>), Error> {
    let mut id = firewall_id(client, cfg, state)?;
    match client.get_json(&firewall_path(&id)) {
        Ok(body) => Ok((id, inbound_rules(body)?)),
        Err(err) if is_not_found(&err) && cfg.id.is_none() => {
            state.clear();
            id = firewall_id(client, cfg, state)?;
            let body = client.get_json(&firewall_path(&id))?;
            Ok((id, inbound_rules(body)?))
        }
        Err(err) => Err(err),
    }
}

fn firewall_path(id: &str) -> String {
    format!("/v1/firewalls/{}", encode_path_segment(id))
}

fn is_not_found(err: &Error) -> bool {
    err.to_string().contains("status 404")
}

/// Returns `FIREWALL_ID`, or looks up a unique firewall by exact name.
fn firewall_id(
    client: &ContaboClient<'_>,
    cfg: &FirewallConfig,
    state: &FirewallState,
) -> Result<String, Error> {
    if let Some(id) = &cfg.id {
        return Ok(id.clone());
    }
    if let Some(id) = state.cached() {
        return Ok(id);
    }
    let Some(name) = cfg.name.as_deref() else {
        return Err(Error::new("firewall name is missing"));
    };
    let listed = client.list(&format!("/v1/firewalls?name={}", encode_path_segment(name)))?;
    let matches: Vec<&Value> = listed
        .iter()
        .filter(|item| item.get("name").and_then(Value::as_str) == Some(name))
        .collect();
    if matches.len() != 1 {
        return Err(Error::new(format!(
            "expected one firewall named {name}, found {}",
            matches.len()
        )));
    }
    matches[0]
        .get("firewallId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::new(format!("firewall {name} has no firewallId")))
        .inspect(|id| state.store(id.clone()))
}

/// Extracts `data[0].rules.inbound`, moving the array out of the body.
fn inbound_rules(mut body: Value) -> Result<Vec<Value>, Error> {
    body.get_mut("data")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("rules"))
        .and_then(|rules| rules.get_mut("inbound"))
        .map(Value::take)
        .and_then(|value| match value {
            Value::Array(items) => Some(items),
            _ => None,
        })
        .ok_or_else(|| Error::new("firewall response missing inbound rules"))
}

/// Reads `displayName` from one inbound rule object.
fn display_name(rule: &Value) -> Option<&str> {
    rule.get("displayName").and_then(Value::as_str)
}

/// Reads `srcCidr.ipv4` strings; missing `srcCidr` is an empty list.
fn ipv4_list(rule: &Value) -> Result<Vec<String>, Error> {
    let Some(ipv4) = rule.get("srcCidr").and_then(|src| src.get("ipv4")) else {
        return Ok(Vec::new());
    };
    let items = ipv4
        .as_array()
        .ok_or_else(|| Error::new("srcCidr.ipv4 is not an array"))?;
    let mut values = Vec::new();
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| Error::new("srcCidr.ipv4 entry is not a string"))?;
        values.push(text.to_string());
    }
    Ok(values)
}

/// Replaces `srcCidr.ipv4` on a rule, creating `srcCidr` if needed.
fn set_ipv4(rule: &mut Value, sources: &[String]) -> Result<(), Error> {
    let object = rule
        .as_object_mut()
        .ok_or_else(|| Error::new("firewall rule is not an object"))?;
    let src = object.entry("srcCidr").or_insert_with(|| json!({}));
    let src_object = src
        .as_object_mut()
        .ok_or_else(|| Error::new("srcCidr is not an object"))?;
    src_object.insert("ipv4".into(), json!(sources));
    Ok(())
}

/// Order-independent equality of two IPv4 source lists.
fn same_set(left: &[String], right: &[String]) -> bool {
    left.iter().map(String::as_str).collect::<BTreeSet<_>>()
        == right.iter().map(String::as_str).collect::<BTreeSet<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FirewallRuleConfig;
    use crate::ip::MapResolver;
    use crate::test_http::{Scripted, Sequence, TOKEN_BODY, client, token_route};
    use std::net::Ipv4Addr;

    fn sample_firewall() -> String {
        r#"{
            "data": [{
                "firewallId": "fw-1",
                "name": "edge",
                "rules": {"inbound": [
                    {
                        "protocol": "tcp",
                        "destPorts": ["22"],
                        "srcCidr": {"ipv4": ["1.1.1.1/32"], "ipv6": ["2001:db8::/64"]},
                        "action": "accept",
                        "status": "active",
                        "displayName": "SSH",
                        "extra": "keep-me"
                    },
                    {
                        "protocol": "tcp",
                        "destPorts": ["80"],
                        "srcCidr": {"ipv4": ["0.0.0.0/0"]},
                        "action": "accept",
                        "status": "active",
                        "displayName": "HTTP"
                    }
                ]}
            }]
        }"#
        .into()
    }

    fn cfg(sources: Vec<&str>) -> FirewallConfig {
        FirewallConfig {
            id: Some("fw-1".into()),
            name: None,
            rules: vec![FirewallRuleConfig {
                display_name: "SSH".into(),
                sources: sources.into_iter().map(str::to_string).collect(),
            }],
        }
    }

    fn resolver() -> MapResolver {
        let mut values = std::collections::HashMap::new();
        values.insert(
            "home.example.net".into(),
            vec![Ipv4Addr::new(203, 0, 113, 9), Ipv4Addr::new(203, 0, 113, 8)],
        );
        MapResolver { values }
    }

    #[test]
    fn logs_after_successful_put() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 200, r#"{"data":[]}"#.into()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["203.0.113.5"]),
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();
        assert!(
            http.calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.method == "PUT")
        );
        let denied = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 400, "no".into()),
        ]);
        assert!(
            sync(
                &client(&denied),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .is_err()
        );
    }

    #[test]
    fn rewrites_only_named_rule_and_keeps_other_fields() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 200, r#"{"data":[]}"#.into()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["home.example.net", "current"]),
            Some(Ipv4Addr::new(198, 51, 100, 4)),
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();
        let calls = http.calls.lock().unwrap();
        let put = calls.iter().find(|call| call.method == "PUT").unwrap();
        let body: Value = serde_json::from_slice(put.body.as_ref().unwrap()).unwrap();
        let inbound = body["rules"]["inbound"].as_array().unwrap();
        assert_eq!(inbound.len(), 2);
        assert_eq!(inbound[0]["extra"], "keep-me");
        assert_eq!(inbound[0]["destPorts"], json!(["22"]));
        assert_eq!(inbound[0]["srcCidr"]["ipv6"], json!(["2001:db8::/64"]));
        assert_eq!(
            inbound[0]["srcCidr"]["ipv4"],
            json!(["198.51.100.4/32", "203.0.113.8/32", "203.0.113.9/32"])
        );
        assert_eq!(inbound[1]["displayName"], "HTTP");
        assert_eq!(inbound[1]["srcCidr"]["ipv4"], json!(["0.0.0.0/0"]));
        assert!(body.get("name").is_none());
    }

    #[test]
    fn skips_put_when_sources_match() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["1.1.1.1"]),
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().all(|call| call.method != "PUT"));
    }

    #[test]
    fn does_not_put_when_resolution_fails_or_name_is_missing() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 200, "{}".into()),
        ]);
        let err = sync(
            &client(&http),
            &cfg(vec!["missing.example"]),
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no A record"));
        let mut named = cfg(vec!["203.0.113.5"]);
        named.rules[0].display_name = "VPN".into();
        let err = sync(
            &client(&http),
            &named,
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no firewall rule named VPN"));
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().all(|call| call.method != "PUT"));
    }

    #[test]
    fn dry_run_skips_put() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 200, "{}".into()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["203.0.113.5"]),
            None,
            &resolver(),
            true,
            &FirewallState::new(),
        )
        .unwrap();
        let calls = http.calls.lock().unwrap();
        assert!(calls.iter().all(|call| call.method != "PUT"));
    }

    #[test]
    fn looks_up_firewall_by_exact_name() {
        let listed = r#"{"data":[
            {"firewallId":"other","name":"edge-old"},
            {"firewallId":"fw-1","name":"edge"}
        ]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "name=", 200, listed.into()),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
        ]);
        let mut named = cfg(vec!["1.1.1.1"]);
        named.id = None;
        named.name = Some("edge".into());
        sync(
            &client(&http),
            &named,
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();
        {
            let calls = http.calls.lock().unwrap();
            assert!(calls.iter().any(|call| call.url.contains("name=edge")));
            assert!(calls.iter().all(|call| call.method != "PUT"));
        }

        let state = FirewallState::new();
        sync(&client(&http), &named, None, &resolver(), false, &state).unwrap();
        let listed_once = http
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.url.contains("name=edge"))
            .count();
        sync(&client(&http), &named, None, &resolver(), false, &state).unwrap();
        let listed_twice = http
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.url.contains("name=edge"))
            .count();
        assert_eq!(listed_twice, listed_once);
    }

    #[test]
    fn forgotten_firewall_id_is_looked_up_again() {
        let gone = r#"{"data":[{"firewallId":"old","name":"edge"}]}"#;
        let found = r#"{"data":[{"firewallId":"fw-1","name":"edge"}]}"#;
        let current = sample_firewall();
        let http = Sequence::in_order(&[
            (200, TOKEN_BODY),
            (200, gone),
            (404, "gone"),
            (200, found),
            (200, current.as_str()),
        ]);
        let mut named = cfg(vec!["1.1.1.1"]);
        named.id = None;
        named.name = Some("edge".into());
        let state = FirewallState::new();
        sync(&client(&http), &named, None, &resolver(), false, &state).unwrap();
        assert_eq!(state.cached().as_deref(), Some("fw-1"));
        state.poison_cache();
        assert_eq!(state.cached().as_deref(), Some("fw-1"));
        state.store("fw-1".into());
        state.clear();
        assert!(state.cached().is_none());
    }

    #[test]
    fn forgotten_id_retry_reports_lookup_get_and_body_failures() {
        let gone = r#"{"data":[{"firewallId":"old","name":"edge"}]}"#;
        let found = r#"{"data":[{"firewallId":"fw-1","name":"edge"}]}"#;
        let missing = r#"{"data":[]}"#;
        let cases = [
            vec![
                (200, TOKEN_BODY),
                (200, gone),
                (404, "gone"),
                (200, r#"{"data":[]}"#),
            ],
            vec![
                (200, TOKEN_BODY),
                (200, gone),
                (404, "gone"),
                (200, found),
                (404, "still gone"),
            ],
            vec![
                (200, TOKEN_BODY),
                (200, gone),
                (404, "gone"),
                (200, found),
                (200, missing),
            ],
        ];
        for rows in cases {
            let http = Sequence::in_order(&rows);
            let mut named = cfg(vec!["1.1.1.1"]);
            named.id = None;
            named.name = Some("edge".into());
            assert!(
                sync(
                    &client(&http),
                    &named,
                    None,
                    &resolver(),
                    false,
                    &FirewallState::new(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_lookup_mismatch_and_bad_rule_shapes() {
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, sample_firewall()),
            ("PUT", "/v1/firewalls/fw-1", 200, r#"{"data":[]}"#.into()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["203.0.113.5"]),
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();
        let calls = http.calls.lock().unwrap();
        let put = calls.iter().find(|call| call.method == "PUT").unwrap();
        assert!(put.body.is_some());

        let no_name = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[
            {"protocol":"tcp","destPorts":["22"],"srcCidr":{"ipv4":["203.0.113.5/32"]},"displayName":"SSH"},
            {"protocol":"tcp","destPorts":["22"],"srcCidr":{"ipv4":["2.2.2.2/32"]}}
        ]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, no_name.into()),
        ]);
        sync(
            &client(&http),
            &cfg(vec!["203.0.113.5"]),
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap();

        let mut broken = cfg(vec!["203.0.113.5"]);
        broken.id = None;
        broken.name = None;
        let err = sync(
            &client(&http),
            &broken,
            None,
            &resolver(),
            false,
            &FirewallState::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("firewall name is missing"));

        let listed_none = r#"{"data":[]}"#;
        let listed_two = r#"{"data":[
            {"firewallId":"a","name":"edge"},
            {"firewallId":"b","name":"edge"}
        ]}"#;
        let listed_id = r#"{"data":[{"name":"edge"}]}"#;
        for (body, message) in [
            (listed_none, "found 0"),
            (listed_two, "found 2"),
            (listed_id, "firewallId"),
        ] {
            let http = Scripted::new(vec![token_route(), ("GET", "name=edge", 200, body.into())]);
            let mut named = cfg(vec!["203.0.113.5"]);
            named.id = None;
            named.name = Some("edge".into());
            let err = sync(
                &client(&http),
                &named,
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .unwrap_err();
            assert!(err.to_string().contains(message));
        }

        let bad_ipv4 = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[
            {"displayName":"SSH","srcCidr":{"ipv4":"not-array"}}
        ]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, bad_ipv4.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .is_err()
        );

        let bad_rule = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":["x"]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, bad_rule.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .is_err()
        );

        let bad_src = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[
            {"displayName":"SSH","srcCidr":"text"}
        ]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, bad_src.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .is_err()
        );

        let missing = r#"{"data":[{"firewallId":"fw-1","rules":{}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, missing.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .unwrap_err()
            .to_string()
            .contains("inbound")
        );

        let inbound_object = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":{}}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, inbound_object.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .unwrap_err()
            .to_string()
            .contains("inbound")
        );

        let number_entry = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[
            {"displayName":"SSH","srcCidr":{"ipv4":[1]}}
        ]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, number_entry.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .unwrap_err()
            .to_string()
            .contains("not a string")
        );

        let no_src = r#"{"data":[{"firewallId":"fw-1","rules":{"inbound":[
            {"displayName":"SSH","protocol":"tcp"}
        ]}}]}"#;
        let http = Scripted::new(vec![
            token_route(),
            ("GET", "/v1/firewalls/fw-1", 200, no_src.into()),
            ("PUT", "/v1/firewalls/fw-1", 200, r#"{"data":[]}"#.into()),
        ]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .is_ok()
        );

        assert!(set_ipv4(&mut json!("nope"), &["203.0.113.5".into()]).is_err());
        let http = Scripted::new(vec![token_route(), ("GET", "name=edge", 400, "no".into())]);
        let mut named = cfg(vec!["203.0.113.5"]);
        named.id = None;
        named.name = Some("edge".into());
        assert!(
            sync(
                &client(&http),
                &named,
                None,
                &resolver(),
                false,
                &FirewallState::new()
            )
            .is_err()
        );

        let http = Scripted::new(vec![token_route()]);
        assert!(
            sync(
                &client(&http),
                &cfg(vec!["203.0.113.5"]),
                None,
                &resolver(),
                false,
                &FirewallState::new(),
            )
            .unwrap_err()
            .to_string()
            .contains("unexpected")
        );
    }
}
