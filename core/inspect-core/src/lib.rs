//! `inspect-core`: the single content-inspection library embedded in the
//! endpoint agent, gateways, discovery scanners and the cloud Inspection Service.
//!
//! Scope in Phase 1: text inspection (normalisation, data-driven detectors with
//! validators, proximity, confidence, masking, budgets). File-format extraction,
//! archives, OCR, EDM and IDM arrive in Phase 2 behind the same `Engine` API.

#![forbid(unsafe_code)]

pub mod detector;
pub mod engine;
pub mod mask;
pub mod normalize;
pub mod validators;

pub use detector::{Confidence, DetectorPack, DetectorSpec, PackError};
pub use engine::{Budget, Engine, Hit, InspectionResult, Sample};

/// Built-in detector pack. Shipped signed in production builds.
pub const BUILTIN_PACK: &str = include_str!("../packs/core.json");
