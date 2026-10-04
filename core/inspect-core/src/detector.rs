//! Detectors are data, not code: a pack is a signed JSON document (signing is
//! enforced by the Policy Service / agent loader, not here) containing
//! `DetectorSpec`s. Built-in packs and tenant custom detectors share this format.

use crate::mask::MaskStyle;
use crate::validators::{shannon_entropy, Validator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorSpec {
    pub id: String,
    pub name: String,
    pub category: String,
    pub pattern: String,
    #[serde(default = "default_validator")]
    pub validator: Validator,
    /// Case-insensitive context words; a keyword within `proximity` chars raises confidence.
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_proximity")]
    pub proximity: usize,
    /// If true, a match without a nearby keyword is discarded entirely.
    #[serde(default)]
    pub require_keyword: bool,
    #[serde(default = "default_base")]
    pub base_confidence: Confidence,
    #[serde(default = "default_kw")]
    pub keyword_confidence: Confidence,
    /// Minimum Shannon entropy (bits/char) of the match, for secret-like detectors.
    #[serde(default)]
    pub min_entropy: Option<f64>,
    /// Known dummy/test values (compared after removing spaces and dashes);
    /// matches are kept but downgraded to Low confidence.
    #[serde(default)]
    pub test_values: Vec<String>,
    #[serde(default)]
    pub mask: MaskStyle,
    #[serde(default)]
    pub tests: Option<DetectorTests>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorTests {
    #[serde(default, rename = "match")]
    pub must_match: Vec<String>,
    #[serde(default)]
    pub no_match: Vec<String>,
}

fn default_validator() -> Validator {
    Validator::None
}
fn default_proximity() -> usize {
    64
}
fn default_base() -> Confidence {
    Confidence::Medium
}
fn default_kw() -> Confidence {
    Confidence::High
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorPack {
    pub pack: String,
    pub version: String,
    pub detectors: Vec<DetectorSpec>,
}

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("pack is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("detector {id}: invalid pattern: {source}")]
    Pattern { id: String, source: regex::Error },
    #[error("detector {0}: duplicate id")]
    Duplicate(String),
    #[error("detector {0}: require_keyword set but no keywords given")]
    NoKeywords(String),
    #[error("detector {id}: pattern too large (compiled size limit)")]
    TooLarge { id: String },
    #[error("detector {id}: invalid b64: test value or vector")]
    Vector { id: String },
}

/// Test values and vectors may be written as `b64:<base64>` so that
/// credential-shaped fixtures never appear literally in the repository (they
/// would trip GitHub push protection and customers' own secret scanners).
/// Decoded only in memory.
pub fn decode_vector(s: &str) -> Option<String> {
    use base64::Engine as _;
    match s.strip_prefix("b64:") {
        None => Some(s.to_string()),
        Some(enc) => base64::engine::general_purpose::STANDARD
            .decode(enc)
            .ok()
            .and_then(|b| String::from_utf8(b).ok()),
    }
}

pub(crate) struct Compiled {
    pub spec: DetectorSpec,
    pub re: Regex,
    pub keywords_lc: Vec<String>,
    pub test_values: HashSet<String>,
}

/// Strip separators so "4111-1111 1111 1111" and "4111111111111111" compare equal.
pub(crate) fn canon(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.'))
        .collect::<String>()
        .to_ascii_uppercase()
}

impl Compiled {
    pub fn new(spec: DetectorSpec) -> Result<Self, PackError> {
        if spec.require_keyword && spec.keywords.is_empty() {
            return Err(PackError::NoKeywords(spec.id));
        }
        // Bounded compiled size: a tenant-supplied pattern must not exhaust memory.
        // The regex crate guarantees linear-time matching (no catastrophic backtracking).
        let re = regex::RegexBuilder::new(&spec.pattern)
            .size_limit(2 * 1024 * 1024)
            .dfa_size_limit(4 * 1024 * 1024)
            .build()
            .map_err(|e| match e {
                regex::Error::CompiledTooBig(_) => PackError::TooLarge {
                    id: spec.id.clone(),
                },
                other => PackError::Pattern {
                    id: spec.id.clone(),
                    source: other,
                },
            })?;
        Ok(Self {
            keywords_lc: spec.keywords.iter().map(|k| k.to_lowercase()).collect(),
            test_values: spec
                .test_values
                .iter()
                .map(|v| decode_vector(v).map(|d| canon(&d)))
                .collect::<Option<_>>()
                .ok_or_else(|| PackError::Vector {
                    id: spec.id.clone(),
                })?,
            re,
            spec,
        })
    }

    /// Validate a candidate and decide its confidence. `None` = discard.
    pub fn assess(&self, text: &str, start: usize, end: usize) -> Option<Confidence> {
        let m = &text[start..end];
        if !self.spec.validator.check(m) {
            return None;
        }
        if let Some(min) = self.spec.min_entropy {
            if shannon_entropy(m) < min {
                return None;
            }
        }
        let has_kw = !self.keywords_lc.is_empty() && self.keyword_near(text, start, end);
        if self.spec.require_keyword && !has_kw {
            return None;
        }
        if self.test_values.contains(&canon(m)) {
            return Some(Confidence::Low);
        }
        Some(if has_kw {
            self.spec.keyword_confidence
        } else {
            self.spec.base_confidence
        })
    }

    fn keyword_near(&self, text: &str, start: usize, end: usize) -> bool {
        let lo = floor_char(text, start.saturating_sub(self.spec.proximity));
        let hi = ceil_char(text, (end + self.spec.proximity).min(text.len()));
        let window = text[lo..hi].to_lowercase();
        self.keywords_lc.iter().any(|k| window.contains(k.as_str()))
    }
}

fn floor_char(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Key for counting distinct matches: separators removed, case preserved
/// (secrets differing only in case are different secrets).
pub(crate) fn dedup_key(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, ' ' | '-')).collect()
}
