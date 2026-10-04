use crate::condition::{self, Condition, ConditionError, Leaf, MinConfidence, Op};
use crate::model::*;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("bundle is not valid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported schema_version `{0}` (expected 1.x)")]
    Schema(String),
    #[error("policy {0}: duplicate policy id")]
    DuplicatePolicy(String),
    #[error("policy {policy} rule {rule}: duplicate rule id")]
    DuplicateRule { policy: String, rule: String },
    #[error("policy {policy} rule {rule}: {source}")]
    Condition {
        policy: String,
        rule: String,
        source: ConditionError,
    },
    #[error("policy {policy} rule {rule}: {msg}")]
    Rule {
        policy: String,
        rule: String,
        msg: String,
    },
    #[error("policy {policy}: invalid schedule: {msg}")]
    Schedule { policy: String, msg: String },
    #[error("classifications must be a non-empty list of unique labels")]
    Classifications,
}

struct CRule {
    doc: RuleDoc,
    cond: Condition,
    enforcement: Option<Enforcement>,
}

struct CPolicy {
    doc: PolicyDoc,
    rules: Vec<CRule>,
    activate_at: Option<OffsetDateTime>,
    expire_at: Option<OffsetDateTime>,
}

/// A validated, ready-to-evaluate bundle. Construction is the only place that
/// can fail; evaluation is total (never errors, never panics on input).
pub struct Bundle {
    tenant_id: String,
    version: String,
    classifications_lc: Vec<String>,
    default_action: Enforcement,
    policies: Vec<CPolicy>,
}

fn parse_ts(policy: &str, s: &Option<String>) -> Result<Option<OffsetDateTime>, CompileError> {
    s.as_deref()
        .map(|t| {
            OffsetDateTime::parse(t, &Rfc3339).map_err(|e| CompileError::Schedule {
                policy: policy.into(),
                msg: e.to_string(),
            })
        })
        .transpose()
}

impl Bundle {
    pub fn from_json(raw: &str) -> Result<Self, CompileError> {
        Self::compile(serde_json::from_str(raw)?)
    }

    pub fn compile(doc: BundleDoc) -> Result<Self, CompileError> {
        if !doc.schema_version.starts_with("1.") {
            return Err(CompileError::Schema(doc.schema_version));
        }
        let classifications_lc: Vec<String> = doc
            .classifications
            .iter()
            .map(|c| c.to_lowercase())
            .collect();
        let uniq: HashSet<_> = classifications_lc.iter().collect();
        if classifications_lc.is_empty() || uniq.len() != classifications_lc.len() {
            return Err(CompileError::Classifications);
        }
        let mut seen = HashSet::new();
        let mut policies = Vec::new();
        for p in doc.policies {
            if !seen.insert(p.id.clone()) {
                return Err(CompileError::DuplicatePolicy(p.id));
            }
            let (activate_at, expire_at) = match &p.schedule {
                Some(s) => (
                    parse_ts(&p.id, &s.activate_at)?,
                    parse_ts(&p.id, &s.expire_at)?,
                ),
                None => (None, None),
            };
            let mut rule_ids = HashSet::new();
            let mut rules = Vec::new();
            for r in &p.rules {
                let rerr = |msg: &str| CompileError::Rule {
                    policy: p.id.clone(),
                    rule: r.id.clone(),
                    msg: msg.into(),
                };
                if !rule_ids.insert(r.id.clone()) {
                    return Err(CompileError::DuplicateRule {
                        policy: p.id.clone(),
                        rule: r.id.clone(),
                    });
                }
                let mut leaves = 0;
                let cond = condition::parse(&r.when, &doc.lists, "when", 0, &mut leaves).map_err(
                    |source| CompileError::Condition {
                        policy: p.id.clone(),
                        rule: r.id.clone(),
                        source,
                    },
                )?;
                let enf: Vec<Enforcement> = r
                    .then
                    .iter()
                    .filter_map(|a| match a.action {
                        ActionKind::Enforce(e) => Some(e),
                        ActionKind::Effect(_) => None,
                    })
                    .collect();
                if enf.len() > 1 {
                    return Err(rerr("a rule may have at most one enforcement action"));
                }
                if r.then.is_empty() {
                    return Err(rerr("rule has no actions"));
                }
                if r.exception && enf.first().is_some_and(|e| *e != Enforcement::Allow) {
                    return Err(rerr(
                        "an exception rule may only use the `allow` enforcement action",
                    ));
                }
                let enforcement = if r.exception {
                    Some(Enforcement::Allow)
                } else {
                    enf.first().copied()
                };
                rules.push(CRule {
                    doc: r.clone(),
                    cond,
                    enforcement,
                });
            }
            policies.push(CPolicy {
                doc: p,
                rules,
                activate_at,
                expire_at,
            });
        }
        Ok(Self {
            tenant_id: doc.tenant_id,
            version: doc.bundle_version,
            classifications_lc,
            default_action: doc.default_action,
            policies,
        })
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuleRef {
    pub policy: String,
    pub policy_name: String,
    pub rule: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleMatch {
    #[serde(flatten)]
    pub rule: RuleRef,
    pub exception: bool,
    pub enforcement: Option<Enforcement>,
    /// True if an exception rule at higher priority carved this match out.
    pub overridden: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SideEffect {
    pub action: SideEffectKind,
    pub params: Map<String, Value>,
    pub policy: String,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CondTrace {
    pub path: String,
    pub field: String,
    pub op: Op,
    pub expected: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list: Option<String>,
    pub actual: Value,
    pub result: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleTrace {
    pub rule: String,
    pub matched: bool,
    pub conditions: Vec<CondTrace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyTrace {
    pub policy: String,
    pub evaluated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped_reason: Option<String>,
    pub rules: Vec<RuleTrace>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub tenant_id: String,
    pub bundle_version: String,
    pub action: Enforcement,
    pub decided_by: Option<RuleRef>,
    pub matched: Vec<RuleMatch>,
    pub monitor_matches: Vec<RuleMatch>,
    pub side_effects: Vec<SideEffect>,
    pub explanation: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub trace: Vec<PolicyTrace>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceMode {
    /// Short-circuit evaluation, no trace. Used on agents and gateways.
    Fast,
    /// Evaluate every condition and record it. Used by the policy simulator.
    Full,
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

struct Eval<'a> {
    bundle: &'a Bundle,
    ctx: &'a Value,
    diagnostics: Vec<String>,
}

fn lookup<'v>(ctx: &'v Value, path: &str) -> Option<&'v Value> {
    path.split('.')
        .try_fold(ctx, |v, k| v.get(k))
        .filter(|v| !v.is_null())
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_lowercase)
            .collect(),
        Some(Value::String(s)) => vec![s.to_lowercase()],
        _ => vec![],
    }
}

fn loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x.eq_ignore_ascii_case(y),
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

impl<'a> Eval<'a> {
    fn rank(&self, v: &Value) -> Option<usize> {
        let s = v.as_str()?.to_lowercase();
        self.bundle.classifications_lc.iter().position(|c| *c == s)
    }

    /// Count of distinct matches for `sit.<id>` at or above `min`.
    fn sit_count(&self, field: &str, min: MinConfidence) -> u64 {
        let id = &field["sit.".len()..];
        let Some(hits) = lookup(self.ctx, "inspection.hits").and_then(Value::as_array) else {
            return 0;
        };
        hits.iter()
            .filter(|h| id == "any" || h.get("detector").and_then(Value::as_str) == Some(id))
            .map(|h| {
                let c = h.get("count_by_confidence");
                let g = |k: &str| {
                    c.and_then(|c| c.get(k))
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                };
                match min {
                    MinConfidence::Low => g("low") + g("medium") + g("high"),
                    MinConfidence::Medium => g("medium") + g("high"),
                    MinConfidence::High => g("high"),
                }
            })
            .sum()
    }

    fn compare(
        &mut self,
        field: &str,
        actual: &Value,
        expected: &Value,
    ) -> Option<std::cmp::Ordering> {
        if let (Some(a), Some(b)) = (actual.as_f64(), expected.as_f64()) {
            return a.partial_cmp(&b);
        }
        if field == "classification" || field.ends_with(".classification") {
            match (self.rank(actual), self.rank(expected)) {
                (Some(a), Some(b)) => return Some(a.cmp(&b)),
                _ => {
                    self.diagnostics.push(format!(
                        "{field}: label not in bundle classifications ({actual} vs {expected})"
                    ));
                    return None;
                }
            }
        }
        self.diagnostics
            .push(format!("{field}: cannot order {actual} against {expected}"));
        None
    }

    fn leaf(&mut self, l: &Leaf) -> (bool, Value) {
        if l.field.starts_with("sit.") {
            let n = self.sit_count(&l.field, l.min_confidence);
            let ok = match l.op {
                Op::CountGte => n >= l.value.as_u64().unwrap_or(u64::MAX),
                Op::Exists => n > 0,
                _ => false,
            };
            return (ok, Value::from(n));
        }
        let actual = lookup(self.ctx, &l.field).cloned().unwrap_or(Value::Null);
        if actual.is_null() {
            // Missing facts make the leaf false. Under `not`, that becomes true:
            // e.g. NOT(destination.app in sanctioned) blocks unknown apps (fail-closed).
            return (false, Value::Null);
        }
        let ok = match l.op {
            Op::Exists => true,
            Op::Eq => loose_eq(&actual, &l.value),
            Op::Ne => !loose_eq(&actual, &l.value),
            Op::In | Op::NotIn => {
                let list = l.value.as_array().map(Vec::as_slice).unwrap_or(&[]);
                // An array-valued fact (e.g. user.groups) matches if any element is in the list.
                let any = match &actual {
                    Value::Array(items) => {
                        items.iter().any(|i| list.iter().any(|x| loose_eq(i, x)))
                    }
                    v => list.iter().any(|x| loose_eq(v, x)),
                };
                if l.op == Op::In {
                    any
                } else {
                    !any
                }
            }
            Op::Gt | Op::Gte | Op::Lt | Op::Lte => {
                match self.compare(&l.field, &actual, &l.value) {
                    Some(o) => match l.op {
                        Op::Gt => o.is_gt(),
                        Op::Gte => o.is_ge(),
                        Op::Lt => o.is_lt(),
                        _ => o.is_le(),
                    },
                    None => false,
                }
            }
            Op::Contains => match (&actual, &l.value) {
                (Value::String(a), Value::String(b)) => {
                    a.to_lowercase().contains(&b.to_lowercase())
                }
                (Value::Array(a), b) => a.iter().any(|x| loose_eq(x, b)),
                _ => false,
            },
            Op::StartsWith | Op::EndsWith => match (actual.as_str(), l.value.as_str()) {
                (Some(a), Some(b)) => {
                    let (a, b) = (a.to_lowercase(), b.to_lowercase());
                    if l.op == Op::StartsWith {
                        a.starts_with(&b)
                    } else {
                        a.ends_with(&b)
                    }
                }
                _ => false,
            },
            Op::CountGte => false, // rejected at compile time for non-sit fields
        };
        (ok, actual)
    }

    fn cond(&mut self, c: &Condition, path: &str, trace: &mut Option<Vec<CondTrace>>) -> bool {
        match c {
            Condition::All(items) => {
                let mut res = true;
                for (i, it) in items.iter().enumerate() {
                    res &= self.cond(it, &format!("{path}.all[{i}]"), trace);
                    if !res && trace.is_none() {
                        return false;
                    }
                }
                res
            }
            Condition::Any(items) => {
                let mut res = false;
                for (i, it) in items.iter().enumerate() {
                    res |= self.cond(it, &format!("{path}.any[{i}]"), trace);
                    if res && trace.is_none() {
                        return true;
                    }
                }
                res
            }
            Condition::Not(inner) => !self.cond(inner, &format!("{path}.not"), trace),
            Condition::Leaf(l) => {
                let (result, actual) = self.leaf(l);
                if let Some(t) = trace {
                    t.push(CondTrace {
                        path: path.to_string(),
                        field: l.field.clone(),
                        op: l.op,
                        expected: l.value.clone(),
                        list: l.list_ref.clone(),
                        actual,
                        result,
                    });
                }
                result
            }
        }
    }

    fn in_scope(&self, p: &CPolicy) -> Result<(), String> {
        let d = &p.doc;
        if !d.enabled {
            return Err("disabled".into());
        }
        if !d.channels.is_empty() {
            let ch = lookup(self.ctx, "channel")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !d.channels.iter().any(|c| c.eq_ignore_ascii_case(ch)) {
                return Err(format!("channel `{ch}` not in policy channels"));
            }
        }
        let user = lookup(self.ctx, "user.id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let groups = str_list(lookup(self.ctx, "user.groups"));
        let lc = |v: &Vec<String>| v.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();
        let s = &d.scope;
        if lc(&s.exclude_users).contains(&user)
            || lc(&s.exclude_groups).iter().any(|g| groups.contains(g))
        {
            return Err("user excluded by scope".into());
        }
        if !(s.users.is_empty() && s.groups.is_empty())
            && !lc(&s.users).contains(&user)
            && !lc(&s.groups).iter().any(|g| groups.contains(g))
        {
            return Err("user not in policy scope".into());
        }
        Ok(())
    }
}

fn active(p: &CPolicy, now: OffsetDateTime) -> Result<(), String> {
    if p.activate_at.is_some_and(|a| now < a) {
        return Err("scheduled, not yet active".into());
    }
    if p.expire_at.is_some_and(|e| now >= e) {
        return Err("expired".into());
    }
    Ok(())
}

impl Bundle {
    /// Evaluate the bundle against a context (facts about the user, device,
    /// channel, destination, file, and `inspection` results).
    pub fn evaluate(&self, ctx: &Value, now: OffsetDateTime, mode: TraceMode) -> Verdict {
        let mut ev = Eval {
            bundle: self,
            ctx,
            diagnostics: Vec::new(),
        };
        let mut matched: Vec<RuleMatch> = Vec::new();
        let mut monitor: Vec<RuleMatch> = Vec::new();
        let mut effects: Vec<SideEffect> = Vec::new();
        let mut traces = Vec::new();

        for p in &self.policies {
            let gate = active(p, now).and_then(|()| ev.in_scope(p));
            let mut ptrace = PolicyTrace {
                policy: p.doc.id.clone(),
                evaluated: gate.is_ok(),
                skipped_reason: gate.clone().err(),
                rules: vec![],
            };
            if gate.is_ok() {
                for r in &p.rules {
                    let mut t = (mode == TraceMode::Full).then(Vec::new);
                    let ok = ev.cond(&r.cond, "when", &mut t);
                    if let Some(conditions) = t {
                        ptrace.rules.push(RuleTrace {
                            rule: r.doc.id.clone(),
                            matched: ok,
                            conditions,
                        });
                    }
                    if !ok {
                        continue;
                    }
                    let m = RuleMatch {
                        rule: RuleRef {
                            policy: p.doc.id.clone(),
                            policy_name: p.doc.name.clone(),
                            rule: r.doc.id.clone(),
                            priority: p.doc.priority,
                        },
                        exception: r.doc.exception,
                        enforcement: r.enforcement,
                        overridden: false,
                    };
                    if p.doc.mode == Mode::Monitor {
                        monitor.push(m);
                        continue;
                    }
                    for a in &r.doc.then {
                        if let ActionKind::Effect(k) = a.action {
                            effects.push(SideEffect {
                                action: k,
                                params: a.params.clone(),
                                policy: p.doc.id.clone(),
                                rule: r.doc.id.clone(),
                            });
                        }
                    }
                    matched.push(m);
                }
            }
            if mode == TraceMode::Full {
                traces.push(ptrace);
            }
        }

        // Exceptions at priority P carve out restrictive matches with priority < P.
        let ex_prio = matched
            .iter()
            .filter(|m| m.exception)
            .map(|m| m.rule.priority)
            .max();
        if let Some(px) = ex_prio {
            for m in matched
                .iter_mut()
                .filter(|m| !m.exception && m.rule.priority < px)
            {
                m.overridden = true;
            }
        }
        // Side effects of carved-out rules are dropped too.
        let overridden: HashSet<(String, String)> = matched
            .iter()
            .filter(|m| m.overridden)
            .map(|m| (m.rule.policy.clone(), m.rule.rule.clone()))
            .collect();
        effects.retain(|e| !overridden.contains(&(e.policy.clone(), e.rule.clone())));

        // Most restrictive wins; ties broken by higher priority, then the later rule in bundle order.
        let winner = matched
            .iter()
            .filter(|m| !m.exception && !m.overridden)
            .filter_map(|m| m.enforcement.map(|e| (e, m)))
            .max_by(|(ea, a), (eb, b)| ea.cmp(eb).then(a.rule.priority.cmp(&b.rule.priority)));

        let exception_used = matched
            .iter()
            .find(|m| m.exception && Some(m.rule.priority) == ex_prio);
        let (action, decided_by) = match (winner, exception_used) {
            (Some((e, m)), _) => (e, Some(m.rule.clone())),
            (None, Some(x)) => (Enforcement::Allow, Some(x.rule.clone())),
            (None, None) => (self.default_action, None),
        };

        // One event produces at most one incident: keep the deciding rule's
        // create_incident (its severity), else the first one raised.
        let incident_keep = effects
            .iter()
            .position(|e| {
                e.action == SideEffectKind::CreateIncident
                    && decided_by
                        .as_ref()
                        .is_some_and(|d| d.policy == e.policy && d.rule == e.rule)
            })
            .or_else(|| {
                effects
                    .iter()
                    .position(|e| e.action == SideEffectKind::CreateIncident)
            });
        let mut idx = 0;
        effects.retain(|e| {
            let keep = e.action != SideEffectKind::CreateIncident || Some(idx) == incident_keep;
            idx += 1;
            keep
        });

        let explanation = explain(
            action,
            decided_by.as_ref(),
            &matched,
            &monitor,
            self.default_action,
        );
        let mut diagnostics = ev.diagnostics;
        diagnostics.dedup();
        Verdict {
            tenant_id: self.tenant_id.clone(),
            bundle_version: self.version.clone(),
            action,
            decided_by,
            matched,
            monitor_matches: monitor,
            side_effects: effects,
            explanation,
            trace: traces,
            diagnostics,
        }
    }
}

fn explain(
    action: Enforcement,
    by: Option<&RuleRef>,
    matched: &[RuleMatch],
    monitor: &[RuleMatch],
    default: Enforcement,
) -> String {
    let name = |e: Enforcement| {
        serde_json::to_value(e)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let mut s = match by {
        Some(r) => format!(
            "{} by policy \"{}\" (rule {}, priority {}).",
            name(action).to_uppercase(),
            r.policy_name,
            r.rule,
            r.priority
        ),
        None => format!(
            "{}: no policy matched; bundle default applies.",
            name(default).to_uppercase()
        ),
    };
    let carved: Vec<_> = matched
        .iter()
        .filter(|m| m.overridden)
        .map(|m| format!("\"{}\"/{}", m.rule.policy_name, m.rule.rule))
        .collect();
    if !carved.is_empty() {
        s.push_str(&format!(" Exception overrode: {}.", carved.join(", ")));
    }
    let others = matched
        .iter()
        .filter(|m| !m.overridden && !m.exception && Some(&m.rule) != by)
        .count();
    if others > 0 {
        s.push_str(&format!(
            " {others} other matching rule(s) were less restrictive."
        ));
    }
    if !monitor.is_empty() {
        s.push_str(&format!(
            " {} monitor-mode rule(s) also matched (not enforced).",
            monitor.len()
        ));
    }
    s
}
