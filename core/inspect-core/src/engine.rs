use crate::detector::{Compiled, Confidence, DetectorPack, PackError};
use crate::mask::mask;
use crate::normalize::normalize;
use serde::Serialize;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Resource budget for one inspected object. Exceeding a budget never panics;
/// it marks the result `truncated` and policy decides fail-open vs fail-closed.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max_text_bytes: usize,
    pub max_matches_per_detector: usize,
    pub max_samples_per_detector: usize,
    pub max_wall_time: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_text_bytes: 20 * 1024 * 1024,
            max_matches_per_detector: 10_000,
            max_samples_per_detector: 5,
            max_wall_time: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Sample {
    /// Byte offsets into the normalised text.
    pub start: usize,
    pub end: usize,
    pub masked: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub detector: String,
    pub name: String,
    pub category: String,
    /// Distinct matches at or above Low confidence.
    pub count: usize,
    pub count_by_confidence: CountByConfidence,
    pub max_confidence: Confidence,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, Copy, Serialize, Default)]
pub struct CountByConfidence {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
}

impl CountByConfidence {
    /// Number of matches at or above `min`.
    pub fn at_least(&self, min: Confidence) -> usize {
        match min {
            Confidence::Low => self.low + self.medium + self.high,
            Confidence::Medium => self.medium + self.high,
            Confidence::High => self.high,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InspectionResult {
    pub engine_version: &'static str,
    pub packs: Vec<String>,
    pub bytes_inspected: usize,
    pub truncated: bool,
    pub timed_out: bool,
    pub hits: Vec<Hit>,
}

pub struct Engine {
    detectors: Vec<Compiled>,
    packs: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("detector {detector}: self-test failed: {reason}")]
pub struct SelfTestError {
    pub detector: String,
    pub reason: String,
}

impl Engine {
    /// The built-in core pack shipped with the engine.
    pub fn with_builtin() -> Result<Self, PackError> {
        Self::from_packs(&[crate::BUILTIN_PACK])
    }

    pub fn from_packs(packs_json: &[&str]) -> Result<Self, PackError> {
        let mut detectors = Vec::new();
        let mut ids = HashSet::new();
        let mut packs = Vec::new();
        for raw in packs_json {
            let pack: DetectorPack = serde_json::from_str(raw)?;
            packs.push(format!("{}@{}", pack.pack, pack.version));
            for spec in pack.detectors {
                if !ids.insert(spec.id.clone()) {
                    return Err(PackError::Duplicate(spec.id));
                }
                detectors.push(Compiled::new(spec)?);
            }
        }
        Ok(Self { detectors, packs })
    }

    pub fn detector_ids(&self) -> impl Iterator<Item = &str> {
        self.detectors.iter().map(|d| d.spec.id.as_str())
    }

    pub fn inspect(&self, input: &str, budget: Budget) -> InspectionResult {
        let started = Instant::now();
        let (text, truncated) = normalize(input, budget.max_text_bytes);
        let mut hits = Vec::new();
        let mut timed_out = false;

        for d in &self.detectors {
            if started.elapsed() > budget.max_wall_time {
                timed_out = true;
                break;
            }
            let mut counts = CountByConfidence::default();
            let mut seen = HashSet::new();
            let mut samples = Vec::new();
            for m in d.re.find_iter(&text).take(budget.max_matches_per_detector) {
                let Some(conf) = d.assess(&text, m.start(), m.end()) else {
                    continue;
                };
                // Count distinct values: the same card pasted 50 times is one card.
                if !seen.insert(crate::detector::dedup_key(m.as_str())) {
                    continue;
                }
                match conf {
                    Confidence::Low => counts.low += 1,
                    Confidence::Medium => counts.medium += 1,
                    Confidence::High => counts.high += 1,
                }
                if samples.len() < budget.max_samples_per_detector {
                    samples.push(Sample {
                        start: m.start(),
                        end: m.end(),
                        masked: mask(m.as_str(), d.spec.mask),
                        confidence: conf,
                    });
                }
            }
            let count = counts.at_least(Confidence::Low);
            if count > 0 {
                let max_confidence = if counts.high > 0 {
                    Confidence::High
                } else if counts.medium > 0 {
                    Confidence::Medium
                } else {
                    Confidence::Low
                };
                hits.push(Hit {
                    detector: d.spec.id.clone(),
                    name: d.spec.name.clone(),
                    category: d.spec.category.clone(),
                    count,
                    count_by_confidence: counts,
                    max_confidence,
                    samples,
                });
            }
        }

        InspectionResult {
            engine_version: env!("CARGO_PKG_VERSION"),
            packs: self.packs.clone(),
            bytes_inspected: text.len(),
            truncated,
            timed_out,
            hits,
        }
    }

    /// Run every detector's embedded test vectors. Packs failing self-test must
    /// not be published (enforced in CI and by the Policy Service on upload).
    pub fn self_test(&self) -> Result<usize, SelfTestError> {
        let mut n = 0;
        for d in &self.detectors {
            let Some(t) = &d.spec.tests else { continue };
            for raw in &t.must_match {
                let s = crate::detector::decode_vector(raw).ok_or_else(|| SelfTestError {
                    detector: d.spec.id.clone(),
                    reason: format!("invalid b64: vector {raw:?}"),
                })?;
                let (text, _) = normalize(&s, usize::MAX);
                let ok = d.re.find_iter(&text).any(|m| {
                    d.assess(&text, m.start(), m.end())
                        .is_some_and(|c| c > Confidence::Low)
                });
                if !ok {
                    return Err(SelfTestError {
                        detector: d.spec.id.clone(),
                        reason: format!("expected a match in {raw:?}"),
                    });
                }
                n += 1;
            }
            for raw in &t.no_match {
                let s = crate::detector::decode_vector(raw).ok_or_else(|| SelfTestError {
                    detector: d.spec.id.clone(),
                    reason: format!("invalid b64: vector {raw:?}"),
                })?;
                let (text, _) = normalize(&s, usize::MAX);
                let bad = d.re.find_iter(&text).any(|m| {
                    d.assess(&text, m.start(), m.end())
                        .is_some_and(|c| c > Confidence::Low)
                });
                if bad {
                    return Err(SelfTestError {
                        detector: d.spec.id.clone(),
                        reason: format!("unexpected match in {raw:?}"),
                    });
                }
                n += 1;
            }
        }
        Ok(n)
    }
}
