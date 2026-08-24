use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    Error, Result,
    crypto::{
        Ed25519Signer, canonical_json, encode_verifying_key, is_sha256_digest, sha256_digest,
        verify_domain_signature,
    },
    domain::{AttemptId, AutonomyLevel, ClosureTarget, RepositoryId, RiskClass, WorkItemId},
};

const SAMPLE_SCHEMA: &str = "asf.autonomy-evaluation-sample/v1";
const POLICY_SCHEMA: &str = "asf.autonomy-threshold-policy/v1";
const REPORT_SCHEMA: &str = "asf.autonomy-evaluation-report/v1";
const APPROVAL_SCHEMA: &str = "asf.autonomy-promotion-approval/v1";
const APPROVAL_SIGNATURE_DOMAIN: &str = "asf.autonomy-promotion-approval/v1";
const GRANT_SCHEMA: &str = "asf.autonomy-promotion-grant/v1";
const MAX_WORK_CLASS_BYTES: usize = 64;
const MAX_EVALUATION_SAMPLES: usize = 10_000;
const MAX_INCIDENT_SNAPSHOTS: usize = 10_000;
const MAX_WINDOW_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_PROMOTION_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_CYCLE_TIME_SECONDS: u64 = 10 * 366 * 24 * 60 * 60;
const MAX_COST_MICROUNITS: u64 = 1_000_000_000_000_000;
const BASIS_POINTS: u64 = 10_000;

/// A policy-defined, canonical work-class identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkClass(String);

impl WorkClass {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_work_class(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<()> {
        validate_work_class(&self.0)
    }
}

impl fmt::Display for WorkClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn validate_work_class(value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= MAX_WORK_CLASS_BYTES
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
    if valid {
        Ok(())
    } else {
        Err(Error::Validation(
            "work class must be a 1..=64 byte lowercase ASCII slug".into(),
        ))
    }
}

/// The exact scope to which evidence and an autonomy decision apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSegment {
    pub repository_id: RepositoryId,
    pub work_class: WorkClass,
    pub risk_class: RiskClass,
    pub target: ClosureTarget,
}

impl EvaluationSegment {
    pub fn validate(&self) -> Result<()> {
        self.work_class.validate()
    }
}

/// Closed-open evaluation interval: `start <= sample < end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl EvaluationWindow {
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self> {
        let value = Self { start, end };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(self) -> Result<()> {
        let seconds = self.end.signed_duration_since(self.start).num_seconds();
        if seconds <= 0 || !u64::try_from(seconds).is_ok_and(|value| value <= MAX_WINDOW_SECONDS) {
            return Err(Error::Validation(
                "evaluation window must be positive and at most 366 days".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn contains(self, timestamp: DateTime<Utc>) -> bool {
        timestamp >= self.start && timestamp < self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicabilityOutcome {
    NotApplicable,
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    #[must_use]
    pub const fn is_high_severity(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityAssessment {
    Clean,
    LowSeverityViolation,
    HighSeverityViolation,
    CriticalViolation,
}

impl SecurityAssessment {
    #[must_use]
    pub const fn is_clean(self) -> bool {
        matches!(self, Self::Clean)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SevereViolation {
    AuthorityExpansion,
    EvidenceIntegrity,
    SandboxEscape,
    CredentialExposure,
    UnaccountableExternalEffect,
    PolicyBypass,
}

/// Every required §29 quality signal for one immutable work outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityMeasurements {
    pub correct: bool,
    pub acceptance_criteria_met: bool,
    pub scope_respected: bool,
    pub verification_correct: bool,
    pub false_green: bool,
    pub reviewer_independent: bool,
    pub human_rework_required: bool,
    pub refusal_or_escalation: ApplicabilityOutcome,
    pub recovery: ApplicabilityOutcome,
    pub security: SecurityAssessment,
    pub severe_violation: Option<SevereViolation>,
    pub cycle_time_seconds: u64,
    pub cost_microunits: u64,
}

impl QualityMeasurements {
    fn validate(&self) -> Result<()> {
        if self.false_green && self.verification_correct {
            return Err(Error::Validation(
                "a false-green sample cannot claim correct verification".into(),
            ));
        }
        if self.cycle_time_seconds > MAX_CYCLE_TIME_SECONDS {
            return Err(Error::Validation(
                "sample cycle time exceeds the evaluation bound".into(),
            ));
        }
        if self.cost_microunits > MAX_COST_MICROUNITS {
            return Err(Error::Validation(
                "sample cost exceeds the evaluation bound".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationSampleContent {
    schema_version: String,
    sample_id: Uuid,
    segment: EvaluationSegment,
    work_item_id: WorkItemId,
    attempt_id: Option<AttemptId>,
    evaluated_at: DateTime<Utc>,
    measurements: QualityMeasurements,
}

/// Content-addressed evaluation evidence. The engine recomputes `digest`
/// before using a deserialized sample, so mutation is detected fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSample {
    content: EvaluationSampleContent,
    digest: String,
}

impl EvaluationSample {
    pub fn new(
        sample_id: Uuid,
        segment: EvaluationSegment,
        work_item_id: WorkItemId,
        attempt_id: Option<AttemptId>,
        evaluated_at: DateTime<Utc>,
        measurements: QualityMeasurements,
    ) -> Result<Self> {
        let content = EvaluationSampleContent {
            schema_version: SAMPLE_SCHEMA.into(),
            sample_id,
            segment,
            work_item_id,
            attempt_id,
            evaluated_at,
            measurements,
        };
        validate_sample_content(&content)?;
        let digest = digest_canonical(&content)?;
        Ok(Self { content, digest })
    }

    #[must_use]
    pub const fn sample_id(&self) -> Uuid {
        self.content.sample_id
    }

    #[must_use]
    pub fn segment(&self) -> &EvaluationSegment {
        &self.content.segment
    }

    #[must_use]
    pub const fn evaluated_at(&self) -> DateTime<Utc> {
        self.content.evaluated_at
    }

    #[must_use]
    pub fn measurements(&self) -> &QualityMeasurements {
        &self.content.measurements
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify(&self) -> Result<()> {
        validate_sample_content(&self.content)?;
        if !is_sha256_digest(&self.digest) || digest_canonical(&self.content)? != self.digest {
            return Err(Error::Validation(format!(
                "evaluation sample {} failed its immutable digest",
                self.content.sample_id
            )));
        }
        Ok(())
    }
}

fn validate_sample_content(content: &EvaluationSampleContent) -> Result<()> {
    if content.schema_version != SAMPLE_SCHEMA || content.sample_id.is_nil() {
        return Err(Error::Validation(
            "evaluation sample has an unsupported schema or nil identity".into(),
        ));
    }
    content.segment.validate()?;
    content.measurements.validate()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentKind {
    Quality,
    FalseGreen,
    Security,
    SeverePolicyViolation,
}

/// Point-in-time incident state included in a canonical evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationIncident {
    pub incident_id: Uuid,
    pub segment: EvaluationSegment,
    pub kind: IncidentKind,
    pub severity: IncidentSeverity,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

impl EvaluationIncident {
    pub fn validate(&self, observed_at: DateTime<Utc>) -> Result<()> {
        if self.incident_id.is_nil() {
            return Err(Error::Validation("incident identity cannot be nil".into()));
        }
        self.segment.validate()?;
        if self.opened_at > observed_at
            || self
                .resolved_at
                .is_some_and(|resolved| resolved < self.opened_at || resolved > observed_at)
        {
            return Err(Error::Validation(
                "incident timestamps are inconsistent with the evaluation".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn unresolved_at(&self, observed_at: DateTime<Utc>) -> bool {
        self.resolved_at
            .is_none_or(|resolved| resolved > observed_at)
    }

    #[must_use]
    pub const fn is_safety_incident(&self) -> bool {
        matches!(
            self.kind,
            IncidentKind::FalseGreen | IncidentKind::Security | IncidentKind::SeverePolicyViolation
        )
    }
}

/// All configurable gates are integer-valued and explicitly bounded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionThresholds {
    pub min_samples: u32,
    pub max_samples: u32,
    pub min_correctness_bps: u16,
    pub min_acceptance_criteria_bps: u16,
    pub min_scope_bps: u16,
    pub min_verification_bps: u16,
    pub min_reviewer_independence_bps: u16,
    pub max_human_rework_bps: u16,
    pub min_refusal_or_escalation_observations: u32,
    pub min_refusal_or_escalation_bps: u16,
    pub min_recovery_observations: u32,
    pub min_recovery_bps: u16,
    pub min_security_clean_bps: u16,
    pub max_mean_cycle_time_seconds: u64,
    pub max_mean_cost_microunits: u64,
    pub max_evaluation_age_seconds: u64,
    pub max_promotion_seconds: u64,
}

/// Versioned threshold policy whose canonical digest is approval-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionThresholdPolicy {
    schema_version: String,
    pub thresholds: PromotionThresholds,
}

impl PromotionThresholdPolicy {
    pub fn new(thresholds: PromotionThresholds) -> Result<Self> {
        let value = Self {
            schema_version: POLICY_SCHEMA.into(),
            thresholds,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        let value = &self.thresholds;
        let maximum =
            u32::try_from(MAX_EVALUATION_SAMPLES).expect("maximum evaluation samples fits u32");
        if self.schema_version != POLICY_SCHEMA
            || value.min_samples == 0
            || value.min_samples > value.max_samples
            || value.max_samples > maximum
            || value.min_refusal_or_escalation_observations > value.max_samples
            || value.min_recovery_observations > value.max_samples
        {
            return Err(Error::Validation(
                "promotion sample thresholds are outside bounded limits".into(),
            ));
        }
        for basis_points in [
            value.min_correctness_bps,
            value.min_acceptance_criteria_bps,
            value.min_scope_bps,
            value.min_verification_bps,
            value.min_reviewer_independence_bps,
            value.max_human_rework_bps,
            value.min_refusal_or_escalation_bps,
            value.min_recovery_bps,
            value.min_security_clean_bps,
        ] {
            if u64::from(basis_points) > BASIS_POINTS {
                return Err(Error::Validation(
                    "promotion rate thresholds must be in 0..=10000 basis points".into(),
                ));
            }
        }
        if value.max_mean_cycle_time_seconds == 0
            || value.max_mean_cycle_time_seconds > MAX_CYCLE_TIME_SECONDS
            || value.max_mean_cost_microunits == 0
            || value.max_mean_cost_microunits > MAX_COST_MICROUNITS
            || value.max_evaluation_age_seconds == 0
            || value.max_evaluation_age_seconds > MAX_WINDOW_SECONDS
            || value.max_promotion_seconds == 0
            || value.max_promotion_seconds > MAX_PROMOTION_SECONDS
        {
            return Err(Error::Validation(
                "promotion time or cost thresholds are outside bounded limits".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest_canonical(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationRate {
    pub passed: u32,
    pub observed: u32,
    pub basis_points: u16,
}

impl EvaluationRate {
    fn from_counts(passed: usize, observed: usize) -> Result<Option<Self>> {
        if observed == 0 {
            return Ok(None);
        }
        let passed = u32::try_from(passed)
            .map_err(|_| Error::Validation("evaluation pass count is too large".into()))?;
        let observed = u32::try_from(observed)
            .map_err(|_| Error::Validation("evaluation observation count is too large".into()))?;
        let points = u64::from(passed)
            .saturating_mul(BASIS_POINTS)
            .checked_div(u64::from(observed))
            .ok_or_else(|| Error::Validation("evaluation rate has no observations".into()))?;
        let basis_points = u16::try_from(points)
            .map_err(|_| Error::Validation("evaluation rate is outside basis points".into()))?;
        Ok(Some(Self {
            passed,
            observed,
            basis_points,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationAggregate {
    pub sample_count: u32,
    pub correctness: Option<EvaluationRate>,
    pub acceptance_criteria: Option<EvaluationRate>,
    pub scope: Option<EvaluationRate>,
    pub verification: Option<EvaluationRate>,
    pub reviewer_independence: Option<EvaluationRate>,
    pub human_rework: Option<EvaluationRate>,
    pub refusal_or_escalation: Option<EvaluationRate>,
    pub recovery: Option<EvaluationRate>,
    pub security_clean: Option<EvaluationRate>,
    pub false_green_count: u32,
    pub security_violation_count: u32,
    pub severe_violation_count: u32,
    pub mean_cycle_time_seconds: Option<u64>,
    pub mean_cost_microunits: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityMetric {
    Correctness,
    AcceptanceCriteria,
    Scope,
    Verification,
    ReviewerIndependence,
    HumanRework,
    RefusalOrEscalation,
    Recovery,
    Security,
    CycleTime,
    Cost,
}

/// Stable reasons that prevent promotion. A report stores these in enum order,
/// independent of input row ordering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum PromotionHoldReason {
    DuplicateSample {
        sample_id: Uuid,
    },
    InvalidSample {
        sample_id: Uuid,
    },
    SampleSegmentMismatch {
        sample_id: Uuid,
    },
    SampleOutsideWindow {
        sample_id: Uuid,
    },
    SampleCountBelowMinimum {
        required: u32,
        observed: u32,
    },
    SampleCountAboveMaximum {
        maximum: u32,
        observed: u32,
    },
    MetricBelowMinimum {
        metric: QualityMetric,
        required_bps: u16,
        observed_bps: u16,
    },
    MetricAboveMaximum {
        metric: QualityMetric,
        maximum_bps: u16,
        observed_bps: u16,
    },
    ApplicableObservationsBelowMinimum {
        metric: QualityMetric,
        required: u32,
        observed: u32,
    },
    MeanAboveMaximum {
        metric: QualityMetric,
        maximum: u64,
        observed: u64,
    },
    FalseGreenObserved {
        sample_id: Uuid,
    },
    SecurityViolationObserved {
        sample_id: Uuid,
    },
    SevereViolationObserved {
        sample_id: Uuid,
    },
    DuplicateIncident {
        incident_id: Uuid,
    },
    InvalidIncident {
        incident_id: Uuid,
    },
    IncidentSegmentMismatch {
        incident_id: Uuid,
    },
    SafetyIncidentObserved {
        incident_id: Uuid,
    },
    UnresolvedHighSeverityIncident {
        incident_id: Uuid,
    },
    ReportIntegrityMismatch,
    PolicyDigestMismatch,
    EvaluationExpired,
    NonAdjacentPromotion,
    HighRiskGuardedMergeForbidden,
    InvalidPromotionWindow,
    MissingOwnerApproval,
    OwnerApprovalIdentityMismatch,
    OwnerApprovalBindingMismatch,
    OwnerApprovalSignatureInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleDigestReference {
    sample_id: Uuid,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationReportContent {
    schema_version: String,
    segment: EvaluationSegment,
    window: EvaluationWindow,
    generated_at: DateTime<Utc>,
    policy_digest: String,
    samples: Vec<SampleDigestReference>,
    incidents: Vec<EvaluationIncident>,
    aggregate: EvaluationAggregate,
    hold_reasons: Vec<PromotionHoldReason>,
}

/// Canonical, content-addressed evaluation used by owner approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationReport {
    content: EvaluationReportContent,
    digest: String,
}

impl EvaluationReport {
    #[must_use]
    pub fn segment(&self) -> &EvaluationSegment {
        &self.content.segment
    }

    #[must_use]
    pub const fn window(&self) -> EvaluationWindow {
        self.content.window
    }

    #[must_use]
    pub const fn generated_at(&self) -> DateTime<Utc> {
        self.content.generated_at
    }

    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.content.policy_digest
    }

    #[must_use]
    pub fn aggregate(&self) -> &EvaluationAggregate {
        &self.content.aggregate
    }

    #[must_use]
    pub fn hold_reasons(&self) -> &[PromotionHoldReason] {
        &self.content.hold_reasons
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify(&self) -> Result<()> {
        if self.content.schema_version != REPORT_SCHEMA
            || !is_sha256_digest(&self.digest)
            || digest_canonical(&self.content)? != self.digest
        {
            return Err(Error::Validation(
                "autonomy evaluation report failed its canonical digest".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct QualityEvaluationEngine;

impl QualityEvaluationEngine {
    pub fn evaluate(
        &self,
        segment: &EvaluationSegment,
        window: EvaluationWindow,
        generated_at: DateTime<Utc>,
        policy: &PromotionThresholdPolicy,
        samples: &[EvaluationSample],
        incidents: &[EvaluationIncident],
    ) -> Result<EvaluationReport> {
        segment.validate()?;
        window.validate()?;
        policy.validate()?;
        if window.end > generated_at {
            return Err(Error::Validation(
                "evaluation window must be closed before report generation".into(),
            ));
        }
        if samples.len() > MAX_EVALUATION_SAMPLES || incidents.len() > MAX_INCIDENT_SNAPSHOTS {
            return Err(Error::Validation(
                "evaluation input exceeds the absolute processing bound".into(),
            ));
        }

        let mut reasons = BTreeSet::new();
        let mut ordered_samples = samples.iter().collect::<Vec<_>>();
        ordered_samples.sort_by_key(|sample| (sample.sample_id(), sample.digest().to_owned()));
        let sample_counts = ordered_samples
            .iter()
            .fold(BTreeMap::new(), |mut counts, sample| {
                *counts.entry(sample.sample_id()).or_insert(0_usize) += 1;
                counts
            });
        let mut sample_references = Vec::with_capacity(ordered_samples.len());
        let mut valid_samples = Vec::new();
        for sample in ordered_samples {
            sample_references.push(SampleDigestReference {
                sample_id: sample.sample_id(),
                digest: sample.digest().into(),
            });
            if sample_counts
                .get(&sample.sample_id())
                .copied()
                .unwrap_or_default()
                > 1
            {
                reasons.insert(PromotionHoldReason::DuplicateSample {
                    sample_id: sample.sample_id(),
                });
                continue;
            }
            if sample.verify().is_err() {
                reasons.insert(PromotionHoldReason::InvalidSample {
                    sample_id: sample.sample_id(),
                });
                continue;
            }
            if sample.segment() != segment {
                reasons.insert(PromotionHoldReason::SampleSegmentMismatch {
                    sample_id: sample.sample_id(),
                });
                continue;
            }
            if !window.contains(sample.evaluated_at()) {
                reasons.insert(PromotionHoldReason::SampleOutsideWindow {
                    sample_id: sample.sample_id(),
                });
                continue;
            }
            valid_samples.push(sample);
        }

        let aggregate = aggregate_samples(&valid_samples)?;
        apply_thresholds(&aggregate, &policy.thresholds, &mut reasons);
        for sample in &valid_samples {
            let measurements = sample.measurements();
            if measurements.false_green {
                reasons.insert(PromotionHoldReason::FalseGreenObserved {
                    sample_id: sample.sample_id(),
                });
            }
            if !measurements.security.is_clean() {
                reasons.insert(PromotionHoldReason::SecurityViolationObserved {
                    sample_id: sample.sample_id(),
                });
            }
            if measurements.severe_violation.is_some() {
                reasons.insert(PromotionHoldReason::SevereViolationObserved {
                    sample_id: sample.sample_id(),
                });
            }
        }

        let mut ordered_incidents = incidents
            .iter()
            .map(|incident| {
                digest_canonical(incident)
                    .map(|digest| (incident.incident_id, digest, incident.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        ordered_incidents
            .sort_by(|left, right| (left.0, left.1.as_str()).cmp(&(right.0, right.1.as_str())));
        let ordered_incidents = ordered_incidents
            .into_iter()
            .map(|(_, _, incident)| incident)
            .collect::<Vec<_>>();
        let incident_counts = ordered_incidents
            .iter()
            .fold(BTreeMap::new(), |mut counts, item| {
                *counts.entry(item.incident_id).or_insert(0_usize) += 1;
                counts
            });
        for incident in &ordered_incidents {
            if incident_counts
                .get(&incident.incident_id)
                .copied()
                .unwrap_or_default()
                > 1
            {
                reasons.insert(PromotionHoldReason::DuplicateIncident {
                    incident_id: incident.incident_id,
                });
                continue;
            }
            if incident.validate(generated_at).is_err() {
                reasons.insert(PromotionHoldReason::InvalidIncident {
                    incident_id: incident.incident_id,
                });
                continue;
            }
            if &incident.segment != segment {
                reasons.insert(PromotionHoldReason::IncidentSegmentMismatch {
                    incident_id: incident.incident_id,
                });
                continue;
            }
            if incident.severity.is_high_severity() && incident.unresolved_at(generated_at) {
                reasons.insert(PromotionHoldReason::UnresolvedHighSeverityIncident {
                    incident_id: incident.incident_id,
                });
            }
            if incident.is_safety_incident() && window.contains(incident.opened_at) {
                reasons.insert(PromotionHoldReason::SafetyIncidentObserved {
                    incident_id: incident.incident_id,
                });
            }
        }

        let content = EvaluationReportContent {
            schema_version: REPORT_SCHEMA.into(),
            segment: segment.clone(),
            window,
            generated_at,
            policy_digest: policy.digest()?,
            samples: sample_references,
            incidents: ordered_incidents,
            aggregate,
            hold_reasons: reasons.into_iter().collect(),
        };
        let digest = digest_canonical(&content)?;
        Ok(EvaluationReport { content, digest })
    }
}

fn aggregate_samples(samples: &[&EvaluationSample]) -> Result<EvaluationAggregate> {
    let count = samples.len();
    let bool_rate = |predicate: fn(&QualityMeasurements) -> bool| {
        EvaluationRate::from_counts(
            samples
                .iter()
                .filter(|sample| predicate(sample.measurements()))
                .count(),
            count,
        )
    };
    let applicable_rate = |select: fn(&QualityMeasurements) -> ApplicabilityOutcome| {
        let observed = samples
            .iter()
            .filter(|sample| select(sample.measurements()) != ApplicabilityOutcome::NotApplicable)
            .count();
        let passed = samples
            .iter()
            .filter(|sample| select(sample.measurements()) == ApplicabilityOutcome::Pass)
            .count();
        EvaluationRate::from_counts(passed, observed)
    };
    let mean = |select: fn(&QualityMeasurements) -> u64| -> Result<Option<u64>> {
        if samples.is_empty() {
            return Ok(None);
        }
        let total = samples.iter().fold(0_u128, |total, sample| {
            total.saturating_add(u128::from(select(sample.measurements())))
        });
        let denominator = u128::try_from(samples.len())
            .map_err(|_| Error::Validation("evaluation sample count is too large".into()))?;
        let value = total / denominator;
        u64::try_from(value)
            .map(Some)
            .map_err(|_| Error::Validation("evaluation mean is too large".into()))
    };
    Ok(EvaluationAggregate {
        sample_count: u32::try_from(count)
            .map_err(|_| Error::Validation("evaluation sample count is too large".into()))?,
        correctness: bool_rate(|measurements| measurements.correct)?,
        acceptance_criteria: bool_rate(|measurements| measurements.acceptance_criteria_met)?,
        scope: bool_rate(|measurements| measurements.scope_respected)?,
        verification: bool_rate(|measurements| measurements.verification_correct)?,
        reviewer_independence: bool_rate(|measurements| measurements.reviewer_independent)?,
        human_rework: bool_rate(|measurements| measurements.human_rework_required)?,
        refusal_or_escalation: applicable_rate(|measurements| measurements.refusal_or_escalation)?,
        recovery: applicable_rate(|measurements| measurements.recovery)?,
        security_clean: bool_rate(|measurements| measurements.security.is_clean())?,
        false_green_count: count_matching(samples, |measurements| measurements.false_green)?,
        security_violation_count: count_matching(samples, |measurements| {
            !measurements.security.is_clean()
        })?,
        severe_violation_count: count_matching(samples, |measurements| {
            measurements.severe_violation.is_some()
        })?,
        mean_cycle_time_seconds: mean(|measurements| measurements.cycle_time_seconds)?,
        mean_cost_microunits: mean(|measurements| measurements.cost_microunits)?,
    })
}

fn count_matching(
    samples: &[&EvaluationSample],
    predicate: fn(&QualityMeasurements) -> bool,
) -> Result<u32> {
    u32::try_from(
        samples
            .iter()
            .filter(|sample| predicate(sample.measurements()))
            .count(),
    )
    .map_err(|_| Error::Validation("evaluation event count is too large".into()))
}

fn apply_thresholds(
    aggregate: &EvaluationAggregate,
    thresholds: &PromotionThresholds,
    reasons: &mut BTreeSet<PromotionHoldReason>,
) {
    if aggregate.sample_count < thresholds.min_samples {
        reasons.insert(PromotionHoldReason::SampleCountBelowMinimum {
            required: thresholds.min_samples,
            observed: aggregate.sample_count,
        });
    }
    if aggregate.sample_count > thresholds.max_samples {
        reasons.insert(PromotionHoldReason::SampleCountAboveMaximum {
            maximum: thresholds.max_samples,
            observed: aggregate.sample_count,
        });
    }
    for (metric, rate, minimum) in [
        (
            QualityMetric::Correctness,
            aggregate.correctness,
            thresholds.min_correctness_bps,
        ),
        (
            QualityMetric::AcceptanceCriteria,
            aggregate.acceptance_criteria,
            thresholds.min_acceptance_criteria_bps,
        ),
        (
            QualityMetric::Scope,
            aggregate.scope,
            thresholds.min_scope_bps,
        ),
        (
            QualityMetric::Verification,
            aggregate.verification,
            thresholds.min_verification_bps,
        ),
        (
            QualityMetric::ReviewerIndependence,
            aggregate.reviewer_independence,
            thresholds.min_reviewer_independence_bps,
        ),
        (
            QualityMetric::Security,
            aggregate.security_clean,
            thresholds.min_security_clean_bps,
        ),
    ] {
        require_minimum_rate(metric, rate, minimum, reasons);
    }
    if let Some(rate) = aggregate.human_rework
        && rate.basis_points > thresholds.max_human_rework_bps
    {
        reasons.insert(PromotionHoldReason::MetricAboveMaximum {
            metric: QualityMetric::HumanRework,
            maximum_bps: thresholds.max_human_rework_bps,
            observed_bps: rate.basis_points,
        });
    }
    apply_applicable_threshold(
        QualityMetric::RefusalOrEscalation,
        aggregate.refusal_or_escalation,
        thresholds.min_refusal_or_escalation_observations,
        thresholds.min_refusal_or_escalation_bps,
        reasons,
    );
    apply_applicable_threshold(
        QualityMetric::Recovery,
        aggregate.recovery,
        thresholds.min_recovery_observations,
        thresholds.min_recovery_bps,
        reasons,
    );
    for (metric, observed, maximum) in [
        (
            QualityMetric::CycleTime,
            aggregate.mean_cycle_time_seconds,
            thresholds.max_mean_cycle_time_seconds,
        ),
        (
            QualityMetric::Cost,
            aggregate.mean_cost_microunits,
            thresholds.max_mean_cost_microunits,
        ),
    ] {
        if let Some(observed) = observed
            && observed > maximum
        {
            reasons.insert(PromotionHoldReason::MeanAboveMaximum {
                metric,
                maximum,
                observed,
            });
        }
    }
}

fn require_minimum_rate(
    metric: QualityMetric,
    rate: Option<EvaluationRate>,
    minimum: u16,
    reasons: &mut BTreeSet<PromotionHoldReason>,
) {
    if let Some(rate) = rate
        && rate.basis_points < minimum
    {
        reasons.insert(PromotionHoldReason::MetricBelowMinimum {
            metric,
            required_bps: minimum,
            observed_bps: rate.basis_points,
        });
    }
}

fn apply_applicable_threshold(
    metric: QualityMetric,
    rate: Option<EvaluationRate>,
    minimum_observations: u32,
    minimum_bps: u16,
    reasons: &mut BTreeSet<PromotionHoldReason>,
) {
    let observed = rate.map_or(0, |value| value.observed);
    if observed < minimum_observations {
        reasons.insert(PromotionHoldReason::ApplicableObservationsBelowMinimum {
            metric,
            required: minimum_observations,
            observed,
        });
    }
    require_minimum_rate(metric, rate, minimum_bps, reasons);
}

#[derive(Debug, Clone)]
pub struct TrustedRepositoryOwner {
    owner_id: String,
    key_id: String,
    verifying_key: VerifyingKey,
}

impl TrustedRepositoryOwner {
    pub fn new(
        owner_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self> {
        let value = Self {
            owner_id: owner_id.into(),
            key_id: key_id.into(),
            verifying_key,
        };
        if value.owner_id.trim().is_empty() || value.key_id.trim().is_empty() {
            return Err(Error::Validation(
                "trusted repository owner and key identities are required".into(),
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn encoded_verifying_key(&self) -> String {
        encode_verifying_key(&self.verifying_key)
    }
}

/// Exact statement signed by the trusted repository owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionApprovalBinding {
    pub schema_version: String,
    pub repository_owner: String,
    pub owner_key_id: String,
    pub segment: EvaluationSegment,
    pub evaluation_window: EvaluationWindow,
    pub evaluation_digest: String,
    pub policy_digest: String,
    pub current_rung: AutonomyLevel,
    pub requested_rung: AutonomyLevel,
    pub effective_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub rollback_rung: AutonomyLevel,
}

impl PromotionApprovalBinding {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }

    pub fn digest(&self) -> Result<String> {
        digest_canonical(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryOwnerApproval {
    pub binding: PromotionApprovalBinding,
    pub signature: String,
}

impl RepositoryOwnerApproval {
    pub fn sign(binding: PromotionApprovalBinding, signer: &Ed25519Signer) -> Result<Self> {
        if signer.key_id() != binding.owner_key_id {
            return Err(Error::Validation(
                "approval signer does not match the binding key identity".into(),
            ));
        }
        let signature = signer.sign_domain(APPROVAL_SIGNATURE_DOMAIN, &binding.canonical_bytes()?);
        Ok(Self { binding, signature })
    }
}

#[derive(Debug)]
pub struct PromotionRequest<'a> {
    pub report: &'a EvaluationReport,
    pub policy: &'a PromotionThresholdPolicy,
    pub current_rung: AutonomyLevel,
    pub requested_rung: AutonomyLevel,
    pub effective_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decided_at: DateTime<Utc>,
    pub approval: Option<&'a RepositoryOwnerApproval>,
    pub trusted_owner: &'a TrustedRepositoryOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionGrant {
    pub schema_version: String,
    pub segment: EvaluationSegment,
    pub evaluation_window: EvaluationWindow,
    pub evaluation_digest: String,
    pub policy_digest: String,
    pub previous_rung: AutonomyLevel,
    pub promoted_rung: AutonomyLevel,
    pub rollback_rung: AutonomyLevel,
    pub effective_from: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub repository_owner: String,
    pub owner_key_id: String,
    pub approval_binding_digest: String,
}

impl PromotionGrant {
    pub fn validate(&self) -> Result<()> {
        self.segment.validate()?;
        self.evaluation_window.validate()?;
        if self.schema_version != GRANT_SCHEMA
            || !is_sha256_digest(&self.evaluation_digest)
            || !is_sha256_digest(&self.policy_digest)
            || !is_sha256_digest(&self.approval_binding_digest)
            || self.repository_owner.trim().is_empty()
            || self.owner_key_id.trim().is_empty()
            || self.previous_rung != self.rollback_rung
            || next_autonomy_rung(self.previous_rung) != Some(self.promoted_rung)
            || self.effective_from >= self.expires_at
        {
            return Err(Error::Validation(
                "promotion grant is malformed or does not describe one adjacent rung".into(),
            ));
        }
        if matches!(
            self.segment.risk_class,
            RiskClass::High | RiskClass::Critical
        ) && self.promoted_rung == AutonomyLevel::GuardedMergeEnabled
        {
            return Err(Error::Validation(
                "high- and critical-risk segments cannot hold guarded merge authority".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        digest_canonical(self)
    }

    pub fn effective_rung_at(&self, at: DateTime<Utc>) -> Result<AutonomyLevel> {
        self.validate()?;
        Ok(if at >= self.effective_from && at < self.expires_at {
            self.promoted_rung
        } else {
            self.rollback_rung
        })
    }

    pub fn expiration_rollback(&self, at: DateTime<Utc>) -> Result<Option<DemotionDecision>> {
        self.validate()?;
        if at < self.expires_at {
            return Ok(None);
        }
        Ok(Some(DemotionDecision {
            segment: self.segment.clone(),
            from_rung: self.promoted_rung,
            to_rung: self.rollback_rung,
            effective_at: at,
            cause: DemotionCause::PromotionExpired {
                grant_digest: self.digest()?,
            },
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "decision")]
pub enum PromotionDecision {
    Granted(PromotionGrant),
    Held {
        evaluation_digest: String,
        reasons: Vec<PromotionHoldReason>,
    },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AutonomyPromotionEngine;

impl AutonomyPromotionEngine {
    pub fn approval_binding(request: &PromotionRequest<'_>) -> Result<PromotionApprovalBinding> {
        Ok(PromotionApprovalBinding {
            schema_version: APPROVAL_SCHEMA.into(),
            repository_owner: request.trusted_owner.owner_id.clone(),
            owner_key_id: request.trusted_owner.key_id.clone(),
            segment: request.report.segment().clone(),
            evaluation_window: request.report.window(),
            evaluation_digest: request.report.digest().into(),
            policy_digest: request.policy.digest()?,
            current_rung: request.current_rung,
            requested_rung: request.requested_rung,
            effective_from: request.effective_from,
            expires_at: request.expires_at,
            rollback_rung: request.current_rung,
        })
    }

    pub fn decide(&self, request: &PromotionRequest<'_>) -> Result<PromotionDecision> {
        request.policy.validate()?;
        let mut reasons = request
            .report
            .hold_reasons()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if request.report.verify().is_err() {
            reasons.insert(PromotionHoldReason::ReportIntegrityMismatch);
        }
        let policy_digest = request.policy.digest()?;
        if request.report.policy_digest() != policy_digest {
            reasons.insert(PromotionHoldReason::PolicyDigestMismatch);
        }
        let report_age = request
            .decided_at
            .signed_duration_since(request.report.generated_at())
            .num_seconds();
        if report_age < 0
            || !u64::try_from(report_age)
                .is_ok_and(|age| age <= request.policy.thresholds.max_evaluation_age_seconds)
        {
            reasons.insert(PromotionHoldReason::EvaluationExpired);
        }
        if next_autonomy_rung(request.current_rung) != Some(request.requested_rung) {
            reasons.insert(PromotionHoldReason::NonAdjacentPromotion);
        }
        if matches!(
            request.report.segment().risk_class,
            RiskClass::High | RiskClass::Critical
        ) && request.requested_rung == AutonomyLevel::GuardedMergeEnabled
        {
            reasons.insert(PromotionHoldReason::HighRiskGuardedMergeForbidden);
        }
        if !valid_promotion_window(
            request.effective_from,
            request.expires_at,
            request.decided_at,
            request.policy.thresholds.max_promotion_seconds,
        ) {
            reasons.insert(PromotionHoldReason::InvalidPromotionWindow);
        }

        let expected_binding = Self::approval_binding(request)?;
        match request.approval {
            None => {
                reasons.insert(PromotionHoldReason::MissingOwnerApproval);
            }
            Some(approval) => {
                if approval.binding.repository_owner != request.trusted_owner.owner_id
                    || approval.binding.owner_key_id != request.trusted_owner.key_id
                {
                    reasons.insert(PromotionHoldReason::OwnerApprovalIdentityMismatch);
                }
                if approval.binding != expected_binding {
                    reasons.insert(PromotionHoldReason::OwnerApprovalBindingMismatch);
                }
                if verify_domain_signature(
                    &request.trusted_owner.verifying_key,
                    APPROVAL_SIGNATURE_DOMAIN,
                    &approval.binding.canonical_bytes()?,
                    &approval.signature,
                )
                .is_err()
                {
                    reasons.insert(PromotionHoldReason::OwnerApprovalSignatureInvalid);
                }
            }
        }

        if !reasons.is_empty() {
            return Ok(PromotionDecision::Held {
                evaluation_digest: request.report.digest().into(),
                reasons: reasons.into_iter().collect(),
            });
        }
        let approval = request
            .approval
            .expect("a missing approval produces a hold before grant construction");
        Ok(PromotionDecision::Granted(PromotionGrant {
            schema_version: GRANT_SCHEMA.into(),
            segment: request.report.segment().clone(),
            evaluation_window: request.report.window(),
            evaluation_digest: request.report.digest().into(),
            policy_digest,
            previous_rung: request.current_rung,
            promoted_rung: request.requested_rung,
            rollback_rung: request.current_rung,
            effective_from: request.effective_from,
            expires_at: request.expires_at,
            repository_owner: request.trusted_owner.owner_id.clone(),
            owner_key_id: request.trusted_owner.key_id.clone(),
            approval_binding_digest: approval.binding.digest()?,
        }))
    }
}

fn valid_promotion_window(
    effective_from: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    decided_at: DateTime<Utc>,
    maximum_seconds: u64,
) -> bool {
    let seconds = expires_at
        .signed_duration_since(effective_from)
        .num_seconds();
    effective_from <= decided_at
        && decided_at < expires_at
        && seconds > 0
        && u64::try_from(seconds).is_ok_and(|value| value <= maximum_seconds)
}

#[must_use]
pub const fn next_autonomy_rung(level: AutonomyLevel) -> Option<AutonomyLevel> {
    match level {
        AutonomyLevel::Observe => Some(AutonomyLevel::SupervisedPullRequest),
        AutonomyLevel::SupervisedPullRequest => Some(AutonomyLevel::AutomaticVerifiedPullRequest),
        AutonomyLevel::AutomaticVerifiedPullRequest => Some(AutonomyLevel::GuardedMergeCandidate),
        AutonomyLevel::GuardedMergeCandidate => Some(AutonomyLevel::GuardedMergeEnabled),
        AutonomyLevel::GuardedMergeEnabled => None,
    }
}

#[must_use]
pub const fn previous_autonomy_rung(level: AutonomyLevel) -> Option<AutonomyLevel> {
    match level {
        AutonomyLevel::Observe => None,
        AutonomyLevel::SupervisedPullRequest => Some(AutonomyLevel::Observe),
        AutonomyLevel::AutomaticVerifiedPullRequest => Some(AutonomyLevel::SupervisedPullRequest),
        AutonomyLevel::GuardedMergeCandidate => Some(AutonomyLevel::AutomaticVerifiedPullRequest),
        AutonomyLevel::GuardedMergeEnabled => Some(AutonomyLevel::GuardedMergeCandidate),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DemotionCause {
    ExplicitRollback {
        actor: String,
        reason: String,
    },
    PromotionExpired {
        grant_digest: String,
    },
    AutomaticSafety {
        reasons: Vec<ImmediateDemotionReason>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemotionDecision {
    pub segment: EvaluationSegment,
    pub from_rung: AutonomyLevel,
    pub to_rung: AutonomyLevel,
    pub effective_at: DateTime<Utc>,
    pub cause: DemotionCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitRollback {
    pub segment: EvaluationSegment,
    pub current_rung: AutonomyLevel,
    pub requested_rung: AutonomyLevel,
    pub actor: String,
    pub reason: String,
    pub effective_at: DateTime<Utc>,
}

impl AutonomyPromotionEngine {
    pub fn explicit_rollback(request: ExplicitRollback) -> Result<DemotionDecision> {
        request.segment.validate()?;
        if request.actor.trim().is_empty() || request.reason.trim().is_empty() {
            return Err(Error::Validation(
                "explicit rollback requires an actor and reason".into(),
            ));
        }
        if previous_autonomy_rung(request.current_rung) != Some(request.requested_rung) {
            return Err(Error::Validation(
                "explicit rollback must move down exactly one autonomy rung".into(),
            ));
        }
        Ok(DemotionDecision {
            segment: request.segment,
            from_rung: request.current_rung,
            to_rung: request.requested_rung,
            effective_at: request.effective_at,
            cause: DemotionCause::ExplicitRollback {
                actor: request.actor,
                reason: request.reason,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "code")]
pub enum ImmediateDemotionReason {
    InvalidSample { sample_id: Uuid },
    FalseGreen { sample_id: Uuid },
    SecurityViolation { sample_id: Uuid },
    SevereViolation { sample_id: Uuid },
    SafetyIncident { incident_id: Uuid },
    UnresolvedHighSeverityIncident { incident_id: Uuid },
    HighRiskGuardedMerge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "decision")]
pub enum ImmediateSafetyDecision {
    Retain,
    FrozenAtObserve {
        reasons: Vec<ImmediateDemotionReason>,
    },
    Demote(DemotionDecision),
}

impl AutonomyPromotionEngine {
    pub fn immediate_safety_decision(
        segment: &EvaluationSegment,
        current_rung: AutonomyLevel,
        observed_at: DateTime<Utc>,
        samples: &[EvaluationSample],
        incidents: &[EvaluationIncident],
    ) -> Result<ImmediateSafetyDecision> {
        segment.validate()?;
        if samples.len() > MAX_EVALUATION_SAMPLES || incidents.len() > MAX_INCIDENT_SNAPSHOTS {
            return Err(Error::Validation(
                "safety input exceeds the absolute processing bound".into(),
            ));
        }
        let mut reasons = BTreeSet::new();
        for sample in samples {
            if sample.segment() != segment || sample.evaluated_at() > observed_at {
                return Err(Error::Validation(
                    "safety samples must match the exact segment and observation time".into(),
                ));
            }
            if sample.verify().is_err() {
                reasons.insert(ImmediateDemotionReason::InvalidSample {
                    sample_id: sample.sample_id(),
                });
                continue;
            }
            if sample.measurements().false_green {
                reasons.insert(ImmediateDemotionReason::FalseGreen {
                    sample_id: sample.sample_id(),
                });
            }
            if !sample.measurements().security.is_clean() {
                reasons.insert(ImmediateDemotionReason::SecurityViolation {
                    sample_id: sample.sample_id(),
                });
            }
            if sample.measurements().severe_violation.is_some() {
                reasons.insert(ImmediateDemotionReason::SevereViolation {
                    sample_id: sample.sample_id(),
                });
            }
        }
        for incident in incidents {
            incident.validate(observed_at)?;
            if &incident.segment != segment {
                return Err(Error::Validation(
                    "safety incidents must match the exact segment".into(),
                ));
            }
            if incident.is_safety_incident() {
                reasons.insert(ImmediateDemotionReason::SafetyIncident {
                    incident_id: incident.incident_id,
                });
            }
            if incident.severity.is_high_severity() && incident.unresolved_at(observed_at) {
                reasons.insert(ImmediateDemotionReason::UnresolvedHighSeverityIncident {
                    incident_id: incident.incident_id,
                });
            }
        }
        if matches!(segment.risk_class, RiskClass::High | RiskClass::Critical)
            && current_rung == AutonomyLevel::GuardedMergeEnabled
        {
            reasons.insert(ImmediateDemotionReason::HighRiskGuardedMerge);
        }
        if reasons.is_empty() {
            return Ok(ImmediateSafetyDecision::Retain);
        }
        let reasons = reasons.into_iter().collect::<Vec<_>>();
        let Some(to_rung) = previous_autonomy_rung(current_rung) else {
            return Ok(ImmediateSafetyDecision::FrozenAtObserve { reasons });
        };
        Ok(ImmediateSafetyDecision::Demote(DemotionDecision {
            segment: segment.clone(),
            from_rung: current_rung,
            to_rung,
            effective_at: observed_at,
            cause: DemotionCause::AutomaticSafety { reasons },
        }))
    }
}

fn digest_canonical<T: Serialize>(value: &T) -> Result<String> {
    canonical_json(value).map(|bytes| sha256_digest(&bytes))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone as _};
    use proptest::prelude::*;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn segment(risk_class: RiskClass) -> EvaluationSegment {
        EvaluationSegment {
            repository_id: RepositoryId::from_uuid(Uuid::from_u128(7)),
            work_class: WorkClass::new("bug-fix").expect("valid work class"),
            risk_class,
            target: ClosureTarget::PullRequest,
        }
    }

    fn clean_measurements() -> QualityMeasurements {
        QualityMeasurements {
            correct: true,
            acceptance_criteria_met: true,
            scope_respected: true,
            verification_correct: true,
            false_green: false,
            reviewer_independent: true,
            human_rework_required: false,
            refusal_or_escalation: ApplicabilityOutcome::NotApplicable,
            recovery: ApplicabilityOutcome::NotApplicable,
            security: SecurityAssessment::Clean,
            severe_violation: None,
            cycle_time_seconds: 600,
            cost_microunits: 100_000,
        }
    }

    fn sample(
        id: u128,
        segment: &EvaluationSegment,
        evaluated_at: DateTime<Utc>,
        measurements: QualityMeasurements,
    ) -> EvaluationSample {
        EvaluationSample::new(
            Uuid::from_u128(id),
            segment.clone(),
            WorkItemId::from_uuid(Uuid::from_u128(id + 10_000)),
            None,
            evaluated_at,
            measurements,
        )
        .expect("valid sample")
    }

    fn policy(min_samples: u32) -> PromotionThresholdPolicy {
        PromotionThresholdPolicy::new(PromotionThresholds {
            min_samples,
            max_samples: 100,
            min_correctness_bps: 9_000,
            min_acceptance_criteria_bps: 9_000,
            min_scope_bps: 9_000,
            min_verification_bps: 10_000,
            min_reviewer_independence_bps: 10_000,
            max_human_rework_bps: 1_000,
            min_refusal_or_escalation_observations: 0,
            min_refusal_or_escalation_bps: 9_000,
            min_recovery_observations: 0,
            min_recovery_bps: 9_000,
            min_security_clean_bps: 10_000,
            max_mean_cycle_time_seconds: 3_600,
            max_mean_cost_microunits: 1_000_000,
            max_evaluation_age_seconds: 24 * 60 * 60,
            max_promotion_seconds: 30 * 24 * 60 * 60,
        })
        .expect("valid policy")
    }

    fn window() -> EvaluationWindow {
        EvaluationWindow::new(now() - Duration::days(7), now() - Duration::hours(1))
            .expect("valid window")
    }

    fn clean_report(
        risk_class: RiskClass,
        promotion_policy: &PromotionThresholdPolicy,
    ) -> EvaluationReport {
        let exact_segment = segment(risk_class);
        let samples = (1..=promotion_policy.thresholds.min_samples)
            .map(|index| {
                sample(
                    u128::from(index),
                    &exact_segment,
                    window().start + Duration::hours(i64::from(index)),
                    clean_measurements(),
                )
            })
            .collect::<Vec<_>>();
        QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                promotion_policy,
                &samples,
                &[],
            )
            .expect("clean report")
    }

    fn held_reasons(decision: PromotionDecision) -> Vec<PromotionHoldReason> {
        match decision {
            PromotionDecision::Held { reasons, .. } => reasons,
            PromotionDecision::Granted(_) => panic!("expected held promotion"),
        }
    }

    #[test]
    fn immutable_sample_digest_detects_any_content_change() {
        let exact_segment = segment(RiskClass::Low);
        let original = sample(
            1,
            &exact_segment,
            window().start + Duration::hours(1),
            clean_measurements(),
        );
        original.verify().expect("original sample verifies");
        let recreated = sample(
            1,
            &exact_segment,
            window().start + Duration::hours(1),
            clean_measurements(),
        );
        assert_eq!(original.digest(), recreated.digest());

        let mut mutated = original;
        mutated.content.measurements.cost_microunits += 1;
        assert!(mutated.verify().is_err());
    }

    #[test]
    fn evaluation_is_canonical_and_independent_of_input_order() {
        let promotion_policy = policy(3);
        let exact_segment = segment(RiskClass::Low);
        let mut samples = (1_u128..=3)
            .map(|id| {
                sample(
                    id,
                    &exact_segment,
                    window().start + Duration::hours(i64::try_from(id).expect("small id")),
                    clean_measurements(),
                )
            })
            .collect::<Vec<_>>();
        let forward = QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &samples,
                &[],
            )
            .expect("forward evaluation");
        samples.reverse();
        let reverse = QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &samples,
                &[],
            )
            .expect("reverse evaluation");
        assert_eq!(forward.digest(), reverse.digest());
        assert!(forward.hold_reasons().is_empty());
        assert_eq!(forward.aggregate().sample_count, 3);
        assert_eq!(
            forward
                .aggregate()
                .correctness
                .map(|rate| rate.basis_points),
            Some(10_000)
        );
    }

    #[test]
    fn every_quality_dimension_produces_deterministic_holds() {
        let promotion_policy = policy(2);
        let exact_segment = segment(RiskClass::Low);
        let mut bad = clean_measurements();
        bad.correct = false;
        bad.acceptance_criteria_met = false;
        bad.scope_respected = false;
        bad.verification_correct = false;
        bad.false_green = true;
        bad.reviewer_independent = false;
        bad.human_rework_required = true;
        bad.refusal_or_escalation = ApplicabilityOutcome::Fail;
        bad.recovery = ApplicabilityOutcome::Fail;
        bad.security = SecurityAssessment::LowSeverityViolation;
        bad.severe_violation = Some(SevereViolation::PolicyBypass);
        bad.cycle_time_seconds = 7_200;
        bad.cost_microunits = 2_000_000;
        let bad_sample = sample(1, &exact_segment, window().start + Duration::hours(1), bad);
        let report = QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &[bad_sample],
                &[],
            )
            .expect("evaluation holds rather than inventing eligibility");
        let reasons = report.hold_reasons();
        assert!(matches!(
            reasons.first(),
            Some(PromotionHoldReason::SampleCountBelowMinimum { .. })
                | Some(PromotionHoldReason::MetricBelowMinimum { .. })
        ));
        for metric in [
            QualityMetric::Correctness,
            QualityMetric::AcceptanceCriteria,
            QualityMetric::Scope,
            QualityMetric::Verification,
            QualityMetric::ReviewerIndependence,
            QualityMetric::RefusalOrEscalation,
            QualityMetric::Recovery,
            QualityMetric::Security,
            QualityMetric::CycleTime,
            QualityMetric::Cost,
        ] {
            assert!(reasons.iter().any(|reason| match reason {
                PromotionHoldReason::MetricBelowMinimum { metric: actual, .. }
                | PromotionHoldReason::MetricAboveMaximum { metric: actual, .. }
                | PromotionHoldReason::MeanAboveMaximum { metric: actual, .. } => *actual == metric,
                _ => false,
            }));
        }
        assert!(reasons.iter().any(|reason| matches!(
            reason,
            PromotionHoldReason::MetricAboveMaximum {
                metric: QualityMetric::HumanRework,
                ..
            }
        )));
        assert!(reasons.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn unresolved_high_incident_blocks_but_resolved_quality_incident_does_not() {
        let promotion_policy = policy(1);
        let exact_segment = segment(RiskClass::Low);
        let clean = sample(
            1,
            &exact_segment,
            window().start + Duration::hours(1),
            clean_measurements(),
        );
        let incident_id = Uuid::from_u128(55);
        let unresolved = EvaluationIncident {
            incident_id,
            segment: exact_segment.clone(),
            kind: IncidentKind::Quality,
            severity: IncidentSeverity::High,
            opened_at: window().start,
            resolved_at: None,
        };
        let report = QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                std::slice::from_ref(&clean),
                std::slice::from_ref(&unresolved),
            )
            .expect("unresolved incident report");
        assert!(
            report
                .hold_reasons()
                .contains(&PromotionHoldReason::UnresolvedHighSeverityIncident { incident_id })
        );

        let resolved = EvaluationIncident {
            resolved_at: Some(now() - Duration::minutes(1)),
            ..unresolved
        };
        let resolved_report = QualityEvaluationEngine
            .evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &[clean],
                &[resolved],
            )
            .expect("resolved incident report");
        assert!(resolved_report.hold_reasons().is_empty());
    }

    #[test]
    fn repository_owner_signature_is_bound_to_every_promotion_coordinate() {
        let promotion_policy = policy(1);
        let report = clean_report(RiskClass::Low, &promotion_policy);
        let signer = Ed25519Signer::generate("owner-key");
        let owner = TrustedRepositoryOwner::new(
            "repository-owner",
            signer.key_id(),
            signer.verifying_key(),
        )
        .expect("trusted owner");
        let unsigned = PromotionRequest {
            report: &report,
            policy: &promotion_policy,
            current_rung: AutonomyLevel::Observe,
            requested_rung: AutonomyLevel::SupervisedPullRequest,
            effective_from: now() - Duration::minutes(1),
            expires_at: now() + Duration::days(7),
            decided_at: now(),
            approval: None,
            trusted_owner: &owner,
        };
        let binding = AutonomyPromotionEngine::approval_binding(&unsigned)
            .expect("canonical approval binding");
        let approval = RepositoryOwnerApproval::sign(binding, &signer).expect("owner signature");
        let signed = PromotionRequest {
            approval: Some(&approval),
            ..unsigned
        };
        let grant = match AutonomyPromotionEngine
            .decide(&signed)
            .expect("promotion decision")
        {
            PromotionDecision::Granted(grant) => grant,
            PromotionDecision::Held { reasons, .. } => panic!("unexpected holds: {reasons:?}"),
        };
        assert_eq!(grant.rollback_rung, AutonomyLevel::Observe);
        assert!(is_sha256_digest(&grant.approval_binding_digest));

        let mismatched_rung = PromotionRequest {
            requested_rung: AutonomyLevel::AutomaticVerifiedPullRequest,
            ..signed
        };
        let reasons = held_reasons(
            AutonomyPromotionEngine
                .decide(&mismatched_rung)
                .expect("held decision"),
        );
        assert!(reasons.contains(&PromotionHoldReason::NonAdjacentPromotion));
        assert!(reasons.contains(&PromotionHoldReason::OwnerApprovalBindingMismatch));

        let mut tampered_approval = approval.clone();
        tampered_approval.binding.segment.target = ClosureTarget::Merge;
        let tampered = PromotionRequest {
            approval: Some(&tampered_approval),
            ..signed
        };
        let reasons = held_reasons(
            AutonomyPromotionEngine
                .decide(&tampered)
                .expect("tampered decision"),
        );
        assert!(reasons.contains(&PromotionHoldReason::OwnerApprovalBindingMismatch));
        assert!(reasons.contains(&PromotionHoldReason::OwnerApprovalSignatureInvalid));
    }

    #[test]
    fn promotion_expires_to_explicit_adjacent_rollback() {
        let promotion_policy = policy(1);
        let report = clean_report(RiskClass::Low, &promotion_policy);
        let signer = Ed25519Signer::generate("owner-key");
        let owner = TrustedRepositoryOwner::new(
            "repository-owner",
            signer.key_id(),
            signer.verifying_key(),
        )
        .expect("trusted owner");
        let unsigned = PromotionRequest {
            report: &report,
            policy: &promotion_policy,
            current_rung: AutonomyLevel::SupervisedPullRequest,
            requested_rung: AutonomyLevel::AutomaticVerifiedPullRequest,
            effective_from: now(),
            expires_at: now() + Duration::days(1),
            decided_at: now(),
            approval: None,
            trusted_owner: &owner,
        };
        let approval = RepositoryOwnerApproval::sign(
            AutonomyPromotionEngine::approval_binding(&unsigned).expect("binding"),
            &signer,
        )
        .expect("approval");
        let decision = AutonomyPromotionEngine
            .decide(&PromotionRequest {
                approval: Some(&approval),
                ..unsigned
            })
            .expect("decision");
        let PromotionDecision::Granted(grant) = decision else {
            panic!("expected promotion grant");
        };
        assert_eq!(
            grant
                .effective_rung_at(now() + Duration::hours(1))
                .expect("valid grant"),
            AutonomyLevel::AutomaticVerifiedPullRequest
        );
        let expired = grant
            .expiration_rollback(now() + Duration::days(1))
            .expect("expiry decision")
            .expect("expired grant rolls back");
        assert_eq!(expired.to_rung, AutonomyLevel::SupervisedPullRequest);

        let explicit = AutonomyPromotionEngine::explicit_rollback(ExplicitRollback {
            segment: segment(RiskClass::Low),
            current_rung: AutonomyLevel::GuardedMergeCandidate,
            requested_rung: AutonomyLevel::AutomaticVerifiedPullRequest,
            actor: "repository-owner".into(),
            reason: "quality regression".into(),
            effective_at: now(),
        })
        .expect("adjacent explicit rollback");
        assert_eq!(
            explicit.to_rung,
            AutonomyLevel::AutomaticVerifiedPullRequest
        );
        assert!(
            AutonomyPromotionEngine::explicit_rollback(ExplicitRollback {
                requested_rung: AutonomyLevel::Observe,
                ..ExplicitRollback {
                    segment: segment(RiskClass::Low),
                    current_rung: AutonomyLevel::GuardedMergeCandidate,
                    requested_rung: AutonomyLevel::AutomaticVerifiedPullRequest,
                    actor: "repository-owner".into(),
                    reason: "skip".into(),
                    effective_at: now(),
                }
            })
            .is_err()
        );
    }

    #[test]
    fn high_and_critical_segments_never_receive_guarded_merge_authority() {
        let promotion_policy = policy(1);
        for risk in [RiskClass::High, RiskClass::Critical] {
            let report = clean_report(risk, &promotion_policy);
            let signer = Ed25519Signer::generate("owner-key");
            let owner = TrustedRepositoryOwner::new(
                "repository-owner",
                signer.key_id(),
                signer.verifying_key(),
            )
            .expect("trusted owner");
            let unsigned = PromotionRequest {
                report: &report,
                policy: &promotion_policy,
                current_rung: AutonomyLevel::GuardedMergeCandidate,
                requested_rung: AutonomyLevel::GuardedMergeEnabled,
                effective_from: now(),
                expires_at: now() + Duration::days(1),
                decided_at: now(),
                approval: None,
                trusted_owner: &owner,
            };
            let approval = RepositoryOwnerApproval::sign(
                AutonomyPromotionEngine::approval_binding(&unsigned).expect("binding"),
                &signer,
            )
            .expect("approval");
            let reasons = held_reasons(
                AutonomyPromotionEngine
                    .decide(&PromotionRequest {
                        approval: Some(&approval),
                        ..unsigned
                    })
                    .expect("decision"),
            );
            assert!(reasons.contains(&PromotionHoldReason::HighRiskGuardedMergeForbidden));
        }
    }

    #[test]
    fn malformed_policy_and_noncanonical_work_class_fail_closed() {
        assert!(WorkClass::new("Feature Work").is_err());
        let mut invalid = policy(1);
        invalid.thresholds.min_samples = 0;
        assert!(invalid.validate().is_err());
        invalid = policy(1);
        invalid.thresholds.min_security_clean_bps = 10_001;
        assert!(invalid.validate().is_err());
    }

    proptest! {
        #[test]
        fn automatic_safety_events_demote_exactly_one_rung(
            rung in 1_u8..=4,
            signal in 0_u8..3,
        ) {
            let current = match rung {
                1 => AutonomyLevel::SupervisedPullRequest,
                2 => AutonomyLevel::AutomaticVerifiedPullRequest,
                3 => AutonomyLevel::GuardedMergeCandidate,
                _ => AutonomyLevel::GuardedMergeEnabled,
            };
            let exact_segment = segment(RiskClass::Low);
            let mut measurements = clean_measurements();
            match signal {
                0 => {
                    measurements.false_green = true;
                    measurements.verification_correct = false;
                }
                1 => measurements.security = SecurityAssessment::LowSeverityViolation,
                _ => measurements.severe_violation = Some(SevereViolation::PolicyBypass),
            }
            let evidence = sample(
                1,
                &exact_segment,
                now() - Duration::minutes(1),
                measurements,
            );
            let decision = AutonomyPromotionEngine::immediate_safety_decision(
                &exact_segment,
                current,
                now(),
                &[evidence],
                &[],
            )
            .expect("safety decision");
            let ImmediateSafetyDecision::Demote(demotion) = decision else {
                prop_assert!(false, "safety event must demote a non-observe rung");
                return Ok(());
            };
            prop_assert_eq!(demotion.from_rung, current);
            prop_assert_eq!(Some(demotion.to_rung), previous_autonomy_rung(current));
        }

        #[test]
        fn aggregate_rate_and_digest_are_order_independent(outcomes in prop::collection::vec(any::<bool>(), 1..64)) {
            let promotion_policy = PromotionThresholdPolicy::new(PromotionThresholds {
                min_samples: 1,
                max_samples: 100,
                min_correctness_bps: 0,
                min_acceptance_criteria_bps: 0,
                min_scope_bps: 0,
                min_verification_bps: 0,
                min_reviewer_independence_bps: 0,
                max_human_rework_bps: 10_000,
                min_refusal_or_escalation_observations: 0,
                min_refusal_or_escalation_bps: 0,
                min_recovery_observations: 0,
                min_recovery_bps: 0,
                min_security_clean_bps: 0,
                max_mean_cycle_time_seconds: 3_600,
                max_mean_cost_microunits: 1_000_000,
                max_evaluation_age_seconds: 24 * 60 * 60,
                max_promotion_seconds: 30 * 24 * 60 * 60,
            }).expect("valid permissive policy");
            let exact_segment = segment(RiskClass::Low);
            let mut samples = outcomes
                .iter()
                .enumerate()
                .map(|(index, correct)| {
                    let mut measurements = clean_measurements();
                    measurements.correct = *correct;
                    sample(
                        u128::try_from(index + 1).expect("bounded index"),
                        &exact_segment,
                        window().start + Duration::seconds(i64::try_from(index).expect("bounded index")),
                        measurements,
                    )
                })
                .collect::<Vec<_>>();
            let forward = QualityEvaluationEngine.evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &samples,
                &[],
            ).expect("forward evaluation");
            samples.reverse();
            let reverse = QualityEvaluationEngine.evaluate(
                &exact_segment,
                window(),
                now(),
                &promotion_policy,
                &samples,
                &[],
            ).expect("reverse evaluation");
            let passed = outcomes.iter().filter(|value| **value).count();
            let expected = u16::try_from(
                u64::try_from(passed).expect("bounded passed count") * BASIS_POINTS
                    / u64::try_from(outcomes.len()).expect("nonempty bounded sample count")
            ).expect("basis points");
            prop_assert_eq!(forward.digest(), reverse.digest());
            prop_assert_eq!(
                forward.aggregate().correctness.map(|rate| rate.basis_points),
                Some(expected)
            );
        }
    }
}
