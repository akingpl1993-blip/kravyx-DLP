//! dlpctl — the policy simulator's engine, as a CLI.
//!
//!   dlpctl inspect <file>                                   inspection result (masked)
//!   dlpctl detectors                                        list detectors and run pack self-test
//!   dlpctl validate <bundle.json>                           compile a policy bundle, report errors
//!   dlpctl simulate <bundle.json> <context.json> [<file>]   full verdict with trace
//!
//! The same code paths back `POST /api/v1/policies/simulate` (via FFI in Phase 1b).
//! Exit codes: 0 ok, 1 usage, 2 invalid input, 3 blocked (simulate only, for scripting).

#![forbid(unsafe_code)]

use inspect_core::{Budget, Engine};
use policy_core::{Bundle, Enforcement, TraceMode};
use std::process::ExitCode;

const MAX_INPUT: u64 = 50 * 1024 * 1024;

fn read(path: &str) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if meta.len() > MAX_INPUT {
        return Err(format!("{path}: larger than {MAX_INPUT} bytes"));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    // Non-UTF-8 input is inspected lossily; binary formats need Phase 2 extractors.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn print(v: &impl serde::Serialize) {
    println!("{}", serde_json::to_string_pretty(v).expect("serialisable"));
}

fn run(args: &[String]) -> Result<ExitCode, (u8, String)> {
    let usage = || {
        (1u8, "usage: dlpctl inspect <file> | detectors | validate <bundle> | simulate <bundle> <context> [<file>]".to_string())
    };
    let bad = |e: String| (2u8, e);
    let engine = || Engine::with_builtin().map_err(|e| (2u8, e.to_string()));
    match args.first().map(String::as_str) {
        Some("inspect") => {
            let path = args.get(1).ok_or_else(usage)?;
            let text = read(path).map_err(bad)?;
            print(&engine()?.inspect(&text, Budget::default()));
            Ok(ExitCode::SUCCESS)
        }
        Some("detectors") => {
            let e = engine()?;
            let n = e.self_test().map_err(|e| (2u8, e.to_string()))?;
            for id in e.detector_ids() {
                println!("{id}");
            }
            eprintln!("self-test: {n} vectors passed");
            Ok(ExitCode::SUCCESS)
        }
        Some("validate") => {
            let raw = read(args.get(1).ok_or_else(usage)?).map_err(bad)?;
            let b = Bundle::from_json(&raw).map_err(|e| bad(e.to_string()))?;
            println!("ok: bundle {} compiles", b.version());
            Ok(ExitCode::SUCCESS)
        }
        Some("simulate") => {
            let bundle_raw = read(args.get(1).ok_or_else(usage)?).map_err(bad)?;
            let ctx_raw = read(args.get(2).ok_or_else(usage)?).map_err(bad)?;
            let bundle = Bundle::from_json(&bundle_raw).map_err(|e| bad(e.to_string()))?;
            let mut ctx: serde_json::Value =
                serde_json::from_str(&ctx_raw).map_err(|e| bad(format!("context: {e}")))?;
            if !ctx.is_object() {
                return Err(bad("context must be a JSON object".into()));
            }
            let mut inspection = None;
            if let Some(file) = args.get(3) {
                let text = read(file).map_err(bad)?;
                let r = engine()?.inspect(&text, Budget::default());
                ctx["inspection"] = serde_json::to_value(&r).expect("serialisable");
                inspection = Some(r);
            }
            let now = match ctx.get("time").and_then(|t| t.as_str()) {
                Some(t) => {
                    time::OffsetDateTime::parse(t, &time::format_description::well_known::Rfc3339)
                        .map_err(|e| bad(format!("context.time: {e}")))?
                }
                None => time::OffsetDateTime::now_utc(),
            };
            let verdict = bundle.evaluate(&ctx, now, TraceMode::Full);
            print(&serde_json::json!({ "inspection": inspection, "verdict": verdict }));
            Ok(if verdict.action == Enforcement::Block {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            })
        }
        _ => Err(usage()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(c) => c,
        Err((code, msg)) => {
            eprintln!("dlpctl: {msg}");
            ExitCode::from(code)
        }
    }
}
