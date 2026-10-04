//! C ABI for Go services (ADR-006).
//!
//! Contract:
//! * All inputs are NUL-terminated UTF-8 JSON strings (or a pointer+length for content).
//! * Every function returns a heap-allocated NUL-terminated JSON string:
//!   `{"ok":true,"result":...}` or `{"ok":false,"error":{"code":"...","message":"..."}}`.
//!   The caller MUST release it with `kx_free`. Functions never return NULL.
//! * No function panics across the boundary: bodies run under `catch_unwind`
//!   (the workspace builds with `panic = "unwind"` for this reason).
//! * Functions are thread-safe; the detector engine is built once and shared.
//!
//! This is the only crate in the workspace allowed to use `unsafe`.

use inspect_core::{Budget, Engine};
use policy_core::{Bundle, TraceMode};
use serde_json::{json, Value};
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

/// Upper bound on any JSON input crossing the boundary.
const MAX_JSON: usize = 8 * 1024 * 1024;
/// Upper bound on content handed to inspection via simulate.
const MAX_CONTENT: usize = 10 * 1024 * 1024;

fn engine() -> Result<&'static Engine, String> {
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    ENGINE
        .get_or_init(|| Engine::with_builtin().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

fn ok(result: Value) -> Value {
    json!({ "ok": true, "result": result })
}

fn fail(code: &str, message: impl Into<String>) -> Value {
    json!({ "ok": false, "error": { "code": code, "message": message.into() } })
}

fn into_c(v: Value) -> *mut c_char {
    // serde_json escapes control characters, so interior NULs cannot occur.
    CString::new(v.to_string())
        .unwrap_or_else(|_| {
            CString::new(r#"{"ok":false,"error":{"code":"internal","message":"nul in output"}}"#)
                .expect("static")
        })
        .into_raw()
}

/// # Safety
/// `p` must be NULL or point to a NUL-terminated string valid for reads.
unsafe fn read_json(p: *const c_char, what: &str) -> Result<Value, Value> {
    if p.is_null() {
        return Err(fail("invalid_input", format!("{what} is null")));
    }
    let bytes = CStr::from_ptr(p).to_bytes();
    if bytes.len() > MAX_JSON {
        return Err(fail(
            "too_large",
            format!("{what} exceeds {MAX_JSON} bytes"),
        ));
    }
    let s = std::str::from_utf8(bytes)
        .map_err(|_| fail("invalid_input", format!("{what} is not UTF-8")))?;
    serde_json::from_str(s).map_err(|e| fail("invalid_input", format!("{what}: {e}")))
}

fn guarded(f: impl FnOnce() -> Value) -> *mut c_char {
    let v =
        catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| fail("internal", "engine panicked"));
    into_c(v)
}

/// Compile a policy bundle. Result: `{"bundle_version": "..."}`.
///
/// # Safety
/// `bundle_json` must be NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn kx_policy_validate(bundle_json: *const c_char) -> *mut c_char {
    guarded(|| {
        let doc = match read_json(bundle_json, "bundle") {
            Ok(v) => v,
            Err(e) => return e,
        };
        match serde_json::from_value(doc)
            .map_err(|e| e.to_string())
            .and_then(|d| Bundle::compile(d).map_err(|e| e.to_string()))
        {
            Ok(b) => ok(json!({ "bundle_version": b.version() })),
            Err(msg) => fail("invalid_bundle", msg),
        }
    })
}

/// Inspect optional content, then evaluate the bundle with a full trace.
/// `content` may be NULL (context-only simulation). `now_unix` = evaluation time.
/// Result: `{"inspection": InspectionResult|null, "verdict": Verdict}`.
///
/// # Safety
/// JSON pointers must be NULL or valid NUL-terminated strings; `content` must be
/// NULL or valid for `content_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn kx_policy_simulate(
    bundle_json: *const c_char,
    context_json: *const c_char,
    content: *const u8,
    content_len: usize,
    now_unix: i64,
) -> *mut c_char {
    let content_slice = if content.is_null() || content_len == 0 {
        None
    } else if content_len > MAX_CONTENT {
        return into_c(fail(
            "too_large",
            format!("content exceeds {MAX_CONTENT} bytes"),
        ));
    } else {
        Some(std::slice::from_raw_parts(content, content_len))
    };
    guarded(|| {
        let bundle_doc = match read_json(bundle_json, "bundle") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let mut ctx = match read_json(context_json, "context") {
            Ok(v) if v.is_object() => v,
            Ok(_) => return fail("invalid_input", "context must be a JSON object"),
            Err(e) => return e,
        };
        let bundle = match serde_json::from_value(bundle_doc)
            .map_err(|e| e.to_string())
            .and_then(|d| Bundle::compile(d).map_err(|e| e.to_string()))
        {
            Ok(b) => b,
            Err(msg) => return fail("invalid_bundle", msg),
        };
        let now = match time::OffsetDateTime::from_unix_timestamp(now_unix) {
            Ok(t) => t,
            Err(_) => return fail("invalid_input", "now_unix out of range"),
        };
        let mut inspection = Value::Null;
        if let Some(bytes) = content_slice {
            let eng = match engine() {
                Ok(e) => e,
                Err(msg) => return fail("internal", msg),
            };
            let text = String::from_utf8_lossy(bytes);
            let r = eng.inspect(&text, Budget::default());
            inspection = serde_json::to_value(&r).unwrap_or(Value::Null);
            ctx["inspection"] = inspection.clone();
        }
        let verdict = bundle.evaluate(&ctx, now, TraceMode::Full);
        ok(json!({ "inspection": inspection, "verdict": verdict }))
    })
}

/// Engine and pack versions, for /version endpoints.
#[no_mangle]
pub extern "C" fn kx_engine_info() -> *mut c_char {
    guarded(|| match engine() {
        Ok(e) => ok(json!({
            "ffi_version": env!("CARGO_PKG_VERSION"),
            "detectors": e.detector_ids().collect::<Vec<_>>(),
        })),
        Err(msg) => fail("internal", msg),
    })
}

/// Release a string returned by any `kx_*` function. NULL is a no-op.
///
/// # Safety
/// `p` must be NULL or a pointer previously returned by a `kx_*` function, freed once.
#[no_mangle]
pub unsafe extern "C" fn kx_free(p: *mut c_char) {
    if !p.is_null() {
        drop(CString::from_raw(p));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(p: *mut c_char) -> Value {
        let v = unsafe { serde_json::from_str(CStr::from_ptr(p).to_str().unwrap()).unwrap() };
        unsafe { kx_free(p) };
        v
    }

    #[test]
    fn null_inputs_are_errors_not_crashes() {
        let v = call(unsafe { kx_policy_validate(std::ptr::null()) });
        assert_eq!(v["error"]["code"], "invalid_input");
        let v = call(unsafe {
            kx_policy_simulate(std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, 0)
        });
        assert_eq!(v["ok"], false);
    }

    #[test]
    fn invalid_bundle_reports_compiler_message() {
        let b = CString::new(r#"{"schema_version":"2.0","tenant_id":"t","bundle_version":"x","classifications":["A"],"policies":[]}"#).unwrap();
        let v = call(unsafe { kx_policy_validate(b.as_ptr()) });
        assert_eq!(v["error"]["code"], "invalid_bundle");
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("schema_version"));
    }

    #[test]
    fn simulate_round_trip_with_content() {
        let bundle =
            CString::new(include_str!("../../../tests/fixtures/bundle-example.json")).unwrap();
        let ctx = CString::new(
            r#"{"user":{"id":"u"},"channel":"web_upload","destination":{"external":true}}"#,
        )
        .unwrap();
        let content = include_bytes!("../../../tests/corpus/positive/card-export-12.csv");
        let v = call(unsafe {
            kx_policy_simulate(
                bundle.as_ptr(),
                ctx.as_ptr(),
                content.as_ptr(),
                content.len(),
                1_791_100_800,
            )
        });
        assert_eq!(v["ok"], true);
        assert_eq!(v["result"]["verdict"]["action"], "block");
        assert_eq!(v["result"]["inspection"]["hits"][0]["count"], 12);
    }

    #[test]
    fn oversized_content_is_rejected_before_reading() {
        let v = call(unsafe {
            kx_policy_simulate(
                std::ptr::null(),
                std::ptr::null(),
                1 as *const u8,
                MAX_CONTENT + 1,
                0,
            )
        });
        assert_eq!(v["error"]["code"], "too_large");
    }
}
