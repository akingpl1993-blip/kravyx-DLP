//! Condition trees: `{"all":[..]}`, `{"any":[..]}`, `{"not":{..}}` and leaves
//! `{"field":..,"op":..,"value":..}`. Parsed by hand for precise error messages.

use serde::Serialize;
use serde_json::Value;

pub const MAX_DEPTH: usize = 16;
pub const MAX_LEAVES: usize = 256;

/// Allowed field roots. Unknown roots are rejected at compile time so a typo
/// (`destnation.category`) cannot silently produce a never-matching rule.
pub const FIELD_ROOTS: &[&str] = &[
    "user",
    "device",
    "app",
    "channel",
    "destination",
    "file",
    "classification",
    "sit",
    "network",
    "risk",
    "volume",
    "time",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Eq,
    Ne,
    In,
    NotIn,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    StartsWith,
    EndsWith,
    Exists,
    CountGte,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MinConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone)]
pub struct Leaf {
    pub field: String,
    pub op: Op,
    pub value: Value,
    pub min_confidence: MinConfidence,
    /// `{"list":"sanctioned_ai"}` values are resolved against bundle lists at compile time.
    pub list_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Condition {
    All(Vec<Condition>),
    Any(Vec<Condition>),
    Not(Box<Condition>),
    Leaf(Leaf),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ConditionError {
    #[error("{path}: {msg}")]
    Invalid { path: String, msg: String },
}

fn err(path: &str, msg: impl Into<String>) -> ConditionError {
    ConditionError::Invalid {
        path: path.to_string(),
        msg: msg.into(),
    }
}

pub fn parse(
    v: &Value,
    lists: &serde_json::Map<String, Value>,
    path: &str,
    depth: usize,
    leaves: &mut usize,
) -> Result<Condition, ConditionError> {
    if depth > MAX_DEPTH {
        return Err(err(path, format!("nesting deeper than {MAX_DEPTH}")));
    }
    let obj = v
        .as_object()
        .ok_or_else(|| err(path, "condition must be an object"))?;
    let mut group = |key: &str| -> Result<Vec<Condition>, ConditionError> {
        let arr = obj[key]
            .as_array()
            .ok_or_else(|| err(path, format!("`{key}` must be an array")))?;
        if arr.is_empty() {
            return Err(err(path, format!("`{key}` must not be empty")));
        }
        arr.iter()
            .enumerate()
            .map(|(i, c)| parse(c, lists, &format!("{path}.{key}[{i}]"), depth + 1, leaves))
            .collect()
    };
    if obj.len() == 1 && obj.contains_key("all") {
        return Ok(Condition::All(group("all")?));
    }
    if obj.len() == 1 && obj.contains_key("any") {
        return Ok(Condition::Any(group("any")?));
    }
    if obj.len() == 1 && obj.contains_key("not") {
        return Ok(Condition::Not(Box::new(parse(
            &obj["not"],
            lists,
            &format!("{path}.not"),
            depth + 1,
            leaves,
        )?)));
    }

    *leaves += 1;
    if *leaves > MAX_LEAVES {
        return Err(err(
            path,
            format!("more than {MAX_LEAVES} conditions in one rule"),
        ));
    }
    for k in obj.keys() {
        if !matches!(k.as_str(), "field" | "op" | "value" | "min_confidence") {
            return Err(err(path, format!("unknown key `{k}`")));
        }
    }
    let field = obj
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| err(path, "leaf needs a string `field`"))?;
    let root = field.split('.').next().unwrap_or("");
    if !FIELD_ROOTS.contains(&root) {
        return Err(err(path, format!("unknown field `{field}`")));
    }
    let op_str = obj
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| err(path, "leaf needs a string `op`"))?;
    let op = match op_str {
        "eq" => Op::Eq,
        "ne" => Op::Ne,
        "in" => Op::In,
        "not_in" => Op::NotIn,
        "gt" => Op::Gt,
        "gte" => Op::Gte,
        "lt" => Op::Lt,
        "lte" => Op::Lte,
        "contains" => Op::Contains,
        "starts_with" => Op::StartsWith,
        "ends_with" => Op::EndsWith,
        "exists" => Op::Exists,
        "count_gte" => Op::CountGte,
        other => return Err(err(path, format!("unknown op `{other}`"))),
    };
    let min_confidence = match obj.get("min_confidence").and_then(Value::as_str) {
        None | Some("medium") => MinConfidence::Medium,
        Some("low") => MinConfidence::Low,
        Some("high") => MinConfidence::High,
        Some(o) => return Err(err(path, format!("unknown min_confidence `{o}`"))),
    };
    let raw = obj.get("value").cloned().unwrap_or(Value::Null);

    // Resolve named lists: {"list": "sanctioned_ai"}.
    let (value, list_ref) = match raw
        .as_object()
        .and_then(|o| o.get("list"))
        .and_then(Value::as_str)
    {
        Some(name) => {
            let l = lists
                .get(name)
                .ok_or_else(|| err(path, format!("unknown list `{name}`")))?;
            if !l.is_array() {
                return Err(err(path, format!("list `{name}` is not an array")));
            }
            (l.clone(), Some(name.to_string()))
        }
        None => (raw, None),
    };

    match op {
        Op::Exists if !value.is_null() => return Err(err(path, "`exists` takes no value")),
        Op::In | Op::NotIn if !value.is_array() => {
            return Err(err(path, "`in`/`not_in` need an array or list"))
        }
        Op::CountGte => {
            if !field.starts_with("sit.") {
                return Err(err(
                    path,
                    "`count_gte` applies only to `sit.<detector>` fields",
                ));
            }
            if !value.as_u64().is_some_and(|n| n >= 1) {
                return Err(err(path, "`count_gte` needs a positive integer"));
            }
        }
        Op::Exists => {}
        _ if value.is_null() => return Err(err(path, format!("`{op_str}` needs a value"))),
        _ => {}
    }
    if field.starts_with("sit.") && !matches!(op, Op::CountGte | Op::Exists) {
        return Err(err(
            path,
            "`sit.*` fields support only `count_gte` and `exists`",
        ));
    }
    Ok(Condition::Leaf(Leaf {
        field: field.to_string(),
        op,
        value,
        min_confidence,
        list_ref,
    }))
}
