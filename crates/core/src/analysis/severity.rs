//! Severity scoring for vulnerability findings.
//!
//! Produces a numeric severity score (0.0 – 10.0) aligned with CVSS
//! conventions given a vulnerability's characteristics.

use serde::{Deserialize, Serialize};

/// Input characteristics for severity scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityInput {
    pub attack_vector: AttackVector,
    pub requires_auth: bool,
    pub data_impact: DataImpact,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DataImpact {
    None,
    Low,
    High,
}

/// Compute a severity score in the range 0.0–10.0.
pub fn compute_severity(input: &SeverityInput) -> f64 {
    let base = match input.attack_vector {
        AttackVector::Network => 8.0,
        AttackVector::Adjacent => 6.0,
        AttackVector::Local => 4.0,
        AttackVector::Physical => 2.0,
    };

    let auth_modifier = if input.requires_auth { -1.5 } else { 0.0 };

    let impact = match input.data_impact {
        DataImpact::High => 2.0,
        DataImpact::Low => 1.0,
        DataImpact::None => 0.0,
    };

    let score: f64 = base + auth_modifier + impact;
    score.clamp(0.0, 10.0)
}
