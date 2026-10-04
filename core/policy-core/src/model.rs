//! Policy bundle model: what the Policy Service compiles and signs, and what
//! every enforcement point loads. JSON shape is mirrored in
//! `packages/schemas/policy-bundle.schema.json`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Enforcement actions, ordered least to most restrictive. Declaration order
/// defines `Ord`, which implements "most restrictive wins".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Allow,
    Audit,
    Warn,
    Justify,
    RequestApproval,
    Encrypt,
    Quarantine,
    Block,
}

/// Non-enforcing actions: they never change the decision, they are unioned.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectKind {
    NotifyUser,
    NotifyAdmin,
    CreateIncident,
    Tag,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ActionKind {
    Enforce(Enforcement),
    Effect(SideEffectKind),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionSpec {
    pub action: ActionKind,
    /// Action parameters (severity, template, tag name, ...). Opaque here.
    #[serde(flatten)]
    pub params: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Enforce,
    /// Evaluated and reported, never contributes to the decision.
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Empty `users` and `groups` = everyone in the tenant.
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub exclude_users: Vec<String>,
    #[serde(default)]
    pub exclude_groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// RFC 3339 timestamps; null = unbounded.
    pub activate_at: Option<String>,
    pub expire_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDoc {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// An exception rule may only Allow; when it matches at a higher priority
    /// than a restrictive rule, it carves that rule out.
    #[serde(default)]
    pub exception: bool,
    pub when: Value,
    pub then: Vec<ActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: Scope,
    /// Empty = all channels.
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub schedule: Option<Schedule>,
    pub rules: Vec<RuleDoc>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleDoc {
    pub schema_version: String,
    pub tenant_id: String,
    pub bundle_version: String,
    /// Classification labels, least to most sensitive.
    pub classifications: Vec<String>,
    /// Destination-app lists referenced by name, e.g. `sanctioned_ai`.
    #[serde(default)]
    pub lists: Map<String, Value>,
    #[serde(default = "default_action")]
    pub default_action: Enforcement,
    pub policies: Vec<PolicyDoc>,
}

fn default_action() -> Enforcement {
    Enforcement::Allow
}
