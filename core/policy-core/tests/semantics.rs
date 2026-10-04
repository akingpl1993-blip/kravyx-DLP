use policy_core::{Bundle, Enforcement, TraceMode};
use serde_json::{json, Value};
use time::macros::datetime;

const BUNDLE: &str = include_str!("../../../tests/fixtures/bundle-example.json");

fn bundle() -> Bundle {
    Bundle::from_json(BUNDLE).expect("example bundle compiles")
}

fn now() -> time::OffsetDateTime {
    datetime!(2026-10-04 09:00 UTC)
}

fn cards(medium_or_high: u64) -> Value {
    json!({ "hits": [{ "detector": "credit_card", "count": medium_or_high,
        "count_by_confidence": { "low": 0, "medium": medium_or_high, "high": 0 } }] })
}

#[test]
fn brief_example_1_restricted_to_genai_is_blocked_with_incident() {
    let ctx = json!({
        "user": { "id": "u1", "groups": ["finance"] },
        "channel": "genai_prompt",
        "classification": "Restricted",
        "destination": { "category": "generative_ai", "app": "chatgpt-consumer", "external": true }
    });
    let v = bundle().evaluate(&ctx, now(), TraceMode::Fast);
    assert_eq!(v.action, Enforcement::Block);
    assert_eq!(
        v.decided_by.as_ref().unwrap().policy,
        "pol_genai_restricted"
    );
    let kinds: Vec<_> = v
        .side_effects
        .iter()
        .map(|e| serde_json::to_value(e.action).unwrap())
        .collect();
    assert!(kinds.contains(&json!("notify_user")) && kinds.contains(&json!("create_incident")));
}

#[test]
fn sanctioned_ai_is_not_blocked() {
    let ctx = json!({
        "user": { "id": "u1" }, "channel": "genai_prompt", "classification": "Restricted",
        "destination": { "category": "generative_ai", "app": "claude-enterprise" }
    });
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Allow
    );
}

#[test]
fn unknown_ai_app_fails_closed() {
    // destination.app missing: NOT(app in sanctioned) is true, so we block.
    let ctx = json!({
        "user": { "id": "u1" }, "channel": "genai_prompt", "classification": "Restricted",
        "destination": { "category": "generative_ai" }
    });
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Block
    );
}

#[test]
fn brief_example_2_ten_cards_external_is_blocked_fewer_is_justify() {
    let mut ctx = json!({ "user": { "id": "u2" }, "channel": "web_upload", "destination": { "external": true } });
    ctx["inspection"] = cards(10);
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Block
    );
    ctx["inspection"] = cards(3);
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Justify
    );
}

#[test]
fn low_confidence_cards_do_not_count_toward_threshold() {
    let ctx = json!({ "user": { "id": "u2" }, "channel": "web_upload", "destination": { "external": true },
        "inspection": { "hits": [{ "detector": "credit_card", "count_by_confidence": { "low": 50, "medium": 0, "high": 0 } }] } });
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Allow
    );
}

#[test]
fn most_restrictive_wins_and_lesser_matches_are_reported() {
    let mut ctx = json!({ "user": { "id": "u2" }, "channel": "web_upload", "destination": { "external": true } });
    ctx["inspection"] = cards(12);
    let v = bundle().evaluate(&ctx, now(), TraceMode::Fast);
    assert_eq!(v.action, Enforcement::Block);
    assert_eq!(v.matched.len(), 2); // r1 (block) and r2 (justify) both matched
    assert!(v.explanation.contains("less restrictive"));
    let incidents: Vec<_> = v
        .side_effects
        .iter()
        .filter(|e| serde_json::to_value(e.action).unwrap() == json!("create_incident"))
        .collect();
    assert_eq!(incidents.len(), 1, "one event, one incident");
    assert_eq!(
        incidents[0].params["severity"],
        json!("high"),
        "severity comes from the deciding rule"
    );
}

#[test]
fn exception_carves_out_lower_priority_block_for_scoped_group_only() {
    let mut ctx = json!({ "user": { "id": "u3", "groups": ["payments-ops"] }, "channel": "sftp",
        "destination": { "external": true, "domain": "sftp.acquirer.example" } });
    ctx["inspection"] = cards(500);
    let v = bundle().evaluate(&ctx, now(), TraceMode::Fast);
    assert_eq!(v.action, Enforcement::Allow);
    assert!(v
        .matched
        .iter()
        .filter(|m| !m.exception)
        .all(|m| m.overridden));
    assert!(v
        .side_effects
        .iter()
        .all(|e| e.policy == "pol_finance_payments_exception"));
    assert!(v.explanation.contains("Exception overrode"));

    // Same transfer by someone outside payments-ops is still blocked.
    ctx["user"] = json!({ "id": "u4", "groups": ["marketing"] });
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Block
    );
}

#[test]
fn monitor_mode_reports_but_never_enforces() {
    let ctx = json!({ "user": { "id": "u5" }, "channel": "clipboard",
        "inspection": { "hits": [{ "detector": "private_key", "count_by_confidence": { "low": 0, "medium": 0, "high": 1 } }] } });
    let v = bundle().evaluate(&ctx, now(), TraceMode::Fast);
    assert_eq!(v.action, Enforcement::Allow);
    assert_eq!(v.monitor_matches.len(), 1);
}

#[test]
fn channel_scoping_applies() {
    let ctx = json!({ "user": { "id": "u6" }, "channel": "print", "classification": "Restricted",
        "destination": { "category": "generative_ai", "app": "x" } });
    assert_eq!(
        bundle().evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Allow
    );
}

#[test]
fn usb_trusted_device_allowed_untrusted_blocked() {
    let base =
        json!({ "user": { "id": "u7" }, "channel": "usb_write", "classification": "Confidential" });
    let mut trusted = base.clone();
    trusted["destination"] = json!({ "device": { "trusted": true } });
    assert_eq!(
        bundle().evaluate(&trusted, now(), TraceMode::Fast).action,
        Enforcement::Allow
    );
    let mut untrusted = base;
    untrusted["destination"] = json!({ "device": { "trusted": false, "vid": "0781" } });
    assert_eq!(
        bundle().evaluate(&untrusted, now(), TraceMode::Fast).action,
        Enforcement::Block
    );
}

#[test]
fn full_trace_records_every_condition_for_the_simulator() {
    let ctx = json!({ "user": { "id": "u1" }, "channel": "genai_prompt", "classification": "Internal",
        "destination": { "category": "generative_ai", "app": "chatgpt-consumer" } });
    let v = bundle().evaluate(&ctx, now(), TraceMode::Full);
    assert_eq!(v.action, Enforcement::Allow);
    let genai = v
        .trace
        .iter()
        .find(|t| t.policy == "pol_genai_restricted")
        .unwrap();
    let r1 = &genai.rules[0];
    assert!(!r1.matched);
    assert_eq!(r1.conditions.len(), 3, "full mode evaluates all leaves");
    assert!(
        !r1.conditions[0].result,
        "classification Internal < Restricted"
    );
    assert_eq!(r1.conditions[2].list.as_deref(), Some("sanctioned_ai"));
    let usb = v
        .trace
        .iter()
        .find(|t| t.policy == "pol_usb_confidential")
        .unwrap();
    assert!(usb.skipped_reason.as_deref().unwrap().contains("channel"));
}

#[test]
fn fast_and_full_modes_agree_on_decisions() {
    let contexts = [
        json!({ "user": { "id": "a" }, "channel": "genai_prompt", "classification": "Restricted", "destination": { "category": "generative_ai" } }),
        json!({ "user": { "id": "b" }, "channel": "usb_write", "classification": "Public" }),
        json!({ "user": { "id": "c", "groups": ["payments-ops"] }, "channel": "sftp", "destination": { "external": true, "domain": "sftp.acquirer.example" }, "inspection": cards(20) }),
        json!({}),
    ];
    let b = bundle();
    for c in &contexts {
        assert_eq!(
            b.evaluate(c, now(), TraceMode::Fast).action,
            b.evaluate(c, now(), TraceMode::Full).action,
            "{c}"
        );
    }
}

#[test]
fn scheduled_policy_respects_activation_and_expiry() {
    let raw = BUNDLE.replacen("\"priority\": 80,", "\"priority\": 80, \"schedule\": { \"activate_at\": \"2026-11-01T00:00:00Z\", \"expire_at\": \"2027-01-01T00:00:00Z\" },", 1);
    let b = Bundle::from_json(&raw).unwrap();
    let ctx =
        json!({ "user": { "id": "u7" }, "channel": "usb_write", "classification": "Restricted" });
    assert_eq!(
        b.evaluate(&ctx, now(), TraceMode::Fast).action,
        Enforcement::Allow
    );
    assert_eq!(
        b.evaluate(&ctx, datetime!(2026-12-01 00:00 UTC), TraceMode::Fast)
            .action,
        Enforcement::Block
    );
    assert_eq!(
        b.evaluate(&ctx, datetime!(2027-01-01 00:00 UTC), TraceMode::Fast)
            .action,
        Enforcement::Allow
    );
}

#[test]
fn unknown_classification_label_is_diagnosed_not_matched() {
    let ctx =
        json!({ "user": { "id": "u" }, "channel": "usb_write", "classification": "TopSecret" });
    let v = bundle().evaluate(&ctx, now(), TraceMode::Fast);
    assert_eq!(v.action, Enforcement::Allow);
    assert!(v.diagnostics.iter().any(|d| d.contains("TopSecret")));
}

fn compile_err(patch: impl Fn(&mut Value)) -> String {
    let mut doc: Value = serde_json::from_str(BUNDLE).unwrap();
    patch(&mut doc);
    match Bundle::from_json(&doc.to_string()) {
        Ok(_) => panic!("expected a compile error"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn compile_rejects_bad_policies_with_precise_messages() {
    assert!(compile_err(
        |d| d["policies"][0]["rules"][0]["when"]["all"][0]["field"] = json!("clasification")
    )
    .contains("unknown field"));
    assert!(
        compile_err(|d| d["policies"][0]["rules"][0]["when"]["all"][0]["op"] = json!("like"))
            .contains("unknown op")
    );
    assert!(compile_err(
        |d| d["policies"][0]["rules"][0]["when"]["all"][2]["not"]["value"] =
            json!({"list": "nope"})
    )
    .contains("unknown list"));
    assert!(
        compile_err(|d| d["policies"][3]["rules"][0]["then"][0] = json!({"action": "block"}))
            .contains("exception rule may only")
    );
    assert!(
        compile_err(|d| d["policies"][1]["rules"][1]["id"] = json!("r1"))
            .contains("duplicate rule")
    );
    assert!(
        compile_err(|d| d["policies"][1]["id"] = json!("pol_genai_restricted"))
            .contains("duplicate policy")
    );
    assert!(compile_err(
        |d| d["policies"][0]["rules"][0]["then"] = json!([{"action":"block"},{"action":"warn"}])
    )
    .contains("at most one enforcement"));
    assert!(
        compile_err(|d| d["policies"][1]["rules"][0]["when"]["all"][0]["op"] = json!("eq"))
            .contains("sit.*")
    );
    assert!(compile_err(|d| d["schema_version"] = json!("2.0")).contains("schema_version"));
    assert!(compile_err(|d| d["policies"][0]["bogus"] = json!(1)).contains("unknown field"));
}

#[test]
fn deeply_nested_conditions_are_rejected() {
    let mut c = json!({ "field": "channel", "op": "eq", "value": "x" });
    for _ in 0..20 {
        c = json!({ "not": c });
    }
    let msg = compile_err(|d| d["policies"][0]["rules"][0]["when"] = c.clone());
    assert!(msg.contains("nesting"));
}

#[test]
fn evaluation_never_panics_on_hostile_context() {
    let b = bundle();
    for ctx in [
        json!(null),
        json!([1, 2]),
        json!({"user": 5, "channel": {"x": 1}, "classification": [1], "inspection": {"hits": "nope"}}),
    ] {
        let _ = b.evaluate(&ctx, now(), TraceMode::Full);
    }
}
