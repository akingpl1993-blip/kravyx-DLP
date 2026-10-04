//! `policy-core`: the deterministic DLP policy evaluator.
//!
//! Semantics (ADR-004):
//! 1. Policies in scope (enabled, scheduled-active, channel, user/group scope) are evaluated.
//! 2. Every matching enforce-mode rule contributes its enforcement action.
//! 3. Exception rules (Allow only) at priority P carve out matches with priority < P.
//! 4. The most restrictive remaining action wins:
//!    allow < audit < warn < justify < request_approval < encrypt < quarantine < block.
//! 5. Side effects (notify, create_incident, tag) of non-carved matches are unioned.
//! 6. Monitor-mode policies are reported but never affect the decision.
//! 7. Missing facts make a leaf false (so NOT(...) over a missing fact is true: fail-closed).

#![forbid(unsafe_code)]

pub mod condition;
pub mod eval;
pub mod model;

pub use eval::{Bundle, CompileError, TraceMode, Verdict};
pub use model::Enforcement;
