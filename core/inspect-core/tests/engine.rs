use inspect_core::{Budget, Confidence, Engine};

fn engine() -> Engine {
    Engine::with_builtin().expect("builtin pack compiles")
}

#[test]
fn builtin_pack_passes_self_test() {
    let n = engine().self_test().expect("self-test");
    assert!(n >= 30, "expected at least 30 test vectors, ran {n}");
}

#[test]
fn counts_distinct_values_not_repetitions() {
    let text = "card 4526 0181 5908 3012\n".repeat(50) + "and 5396030824628190";
    let r = engine().inspect(&text, Budget::default());
    let cc = r.hits.iter().find(|h| h.detector == "credit_card").unwrap();
    assert_eq!(cc.count, 2);
    assert_eq!(cc.max_confidence, Confidence::High);
    assert_eq!(cc.samples[0].masked, "452601******3012");
}

#[test]
fn zero_width_evasion_is_defeated() {
    let text = "4526\u{200B}0181\u{200B}5908\u{200B}3012";
    let r = engine().inspect(text, Budget::default());
    assert!(r.hits.iter().any(|h| h.detector == "credit_card"));
}

#[test]
fn fullwidth_digit_evasion_is_defeated() {
    let r = engine().inspect("４５２６０１８１５９０８３０１２", Budget::default());
    assert!(r.hits.iter().any(|h| h.detector == "credit_card"));
}

#[test]
fn test_cards_are_low_confidence() {
    let r = engine().inspect("4111111111111111", Budget::default());
    let cc = r.hits.iter().find(|h| h.detector == "credit_card").unwrap();
    assert_eq!(cc.max_confidence, Confidence::Low);
    assert_eq!(cc.count_by_confidence.at_least(Confidence::Medium), 0);
}

#[test]
fn raw_values_never_appear_in_result() {
    // Synthetic value, assembled from parts so no credential-shaped literal
    // exists in the source (secret scanners would flag it).
    let key = concat!("Zq3vT8pLm2Xr9sKd4Wn7", "Yb1Hc6Gf0Jt5Ua+e/RiO");
    let secret = format!(
        "{}={key} card 4526018159083012",
        concat!("aws_secret", "_access_key")
    );
    let r = engine().inspect(&secret, Budget::default());
    assert!(
        r.hits.iter().any(|h| h.detector == "aws_secret_access_key"),
        "secret must be detected"
    );
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains(key));
    assert!(!json.contains("4526018159083012"));
}

#[test]
fn truncation_is_reported_not_panicked() {
    let big = "x".repeat(10_000);
    let r = engine().inspect(
        &big,
        Budget {
            max_text_bytes: 1_000,
            ..Budget::default()
        },
    );
    assert!(r.truncated);
    assert_eq!(r.bytes_inspected, 1_000);
}

#[test]
fn clean_business_text_has_no_findings() {
    let text = include_str!("../../../tests/corpus/negative/business-memo.txt");
    let r = engine().inspect(text, Budget::default());
    let above_low: Vec<_> = r
        .hits
        .iter()
        .filter(|h| h.max_confidence > Confidence::Low)
        .map(|h| &h.detector)
        .collect();
    assert!(above_low.is_empty(), "false positives: {above_low:?}");
}

#[test]
fn custom_tenant_pack_loads_and_rejects_duplicates() {
    let custom = r#"{"pack":"acme","version":"1","detectors":[{"id":"acme_project","name":"Project codename","category":"ip","pattern":"\\bPROJECT-(?:ORION|VEGA)\\b","base_confidence":"high"}]}"#;
    let e = Engine::from_packs(&[inspect_core::BUILTIN_PACK, custom]).unwrap();
    let r = e.inspect("roadmap for PROJECT-ORION", Budget::default());
    assert!(r.hits.iter().any(|h| h.detector == "acme_project"));

    let dup = r#"{"pack":"x","version":"1","detectors":[{"id":"credit_card","name":"x","category":"x","pattern":"x"}]}"#;
    assert!(Engine::from_packs(&[inspect_core::BUILTIN_PACK, dup]).is_err());
}

#[test]
fn pathological_pattern_cannot_hang() {
    // Classic catastrophic-backtracking pattern; the regex crate is linear-time.
    let pack = r#"{"pack":"evil","version":"1","detectors":[{"id":"evil","name":"evil","category":"x","pattern":"(a+)+b"}]}"#;
    let e = Engine::from_packs(&[pack]).unwrap();
    let start = std::time::Instant::now();
    let _ = e.inspect(&"a".repeat(100_000), Budget::default());
    assert!(start.elapsed().as_secs() < 2);
}

#[test]
fn vendor_published_example_credentials_are_low_confidence() {
    // AWS's documentation example keys, assembled from parts (secret scanners
    // flag the literals). The pack stores them only as SHA-256 hashes.
    let key_id = concat!("AKIAIOSFODNN7", "EXAMPLE");
    let secret = concat!("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCYEXAMPLEKEY");
    let text = format!(
        "aws_access_key_id = {key_id}\n{} = {secret}",
        concat!("aws_secret", "_access_key")
    );
    let r = engine().inspect(&text, Budget::default());
    for id in ["aws_access_key_id", "aws_secret_access_key"] {
        let hit = r
            .hits
            .iter()
            .find(|h| h.detector == id)
            .unwrap_or_else(|| panic!("{id} not detected"));
        assert_eq!(
            hit.max_confidence,
            Confidence::Low,
            "{id} example must be Low"
        );
    }
    // A non-example key of the same shape stays High.
    let real_shape = concat!("AKIAQ3EGRV7Z", "LTNK4XHD");
    let r = engine().inspect(real_shape, Budget::default());
    let hit = r
        .hits
        .iter()
        .find(|h| h.detector == "aws_access_key_id")
        .unwrap();
    assert_eq!(hit.max_confidence, Confidence::High);
}

#[test]
fn malformed_hash_test_value_is_rejected() {
    let pack = r#"{"pack":"x","version":"1","detectors":[{"id":"x","name":"x","category":"x","pattern":"x","test_values":["sha256:nothex"]}]}"#;
    assert!(Engine::from_packs(&[pack]).is_err());
}
