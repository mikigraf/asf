use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Error, Result,
    crypto::{canonical_json, is_sha256_digest, sha256_digest},
    domain::{AttemptId, EventId, TenantId, WorkItemId},
    security::reject_sensitive_fields,
};

pub const AUDIT_CHAIN_EXPORT_FORMAT: &str = "asf.audit-chain.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventContent {
    pub id: EventId,
    pub tenant_id: TenantId,
    pub work_item_id: Option<WorkItemId>,
    pub attempt_id: Option<AttemptId>,
    pub actor_type: String,
    pub actor_id: String,
    pub action: String,
    pub subject_type: String,
    pub subject_id: String,
    pub correlation_id: String,
    pub trace_id: Option<String>,
    pub policy_digest: Option<String>,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub previous_event_hash: Option<String>,
    pub details: Value,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashedAuditEvent {
    pub content: AuditEventContent,
    pub event_hash: String,
}

impl HashedAuditEvent {
    pub fn create(content: AuditEventContent) -> Result<Self> {
        validate_content(&content)?;
        let event_hash = sha256_digest(&canonical_json(&content)?);
        Ok(Self {
            content,
            event_hash,
        })
    }

    pub fn verify(&self) -> Result<()> {
        validate_content(&self.content)?;
        if sha256_digest(&canonical_json(&self.content)?) != self.event_hash {
            return Err(Error::Crypto("audit event hash mismatch".into()));
        }
        Ok(())
    }
}

/// Integrity metadata for a verified, genesis-to-head tenant audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuditChain {
    pub tenant_id: TenantId,
    pub event_count: u64,
    pub genesis_event_id: Option<EventId>,
    pub genesis_event_hash: Option<String>,
    pub head_event_id: Option<EventId>,
    pub head_event_hash: Option<String>,
}

/// Portable canonical representation of one complete tenant audit chain.
///
/// Events are ordered by their hash links, from the genesis event to the
/// current head. `occurred_at` remains the time of the underlying fact and is
/// deliberately not used as chain order: delayed fact ingestion is valid.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditChainExport {
    pub format: String,
    pub tenant_id: TenantId,
    pub event_count: u64,
    pub genesis_event_hash: Option<String>,
    pub head_event_hash: Option<String>,
    pub events: Vec<HashedAuditEvent>,
}

impl AuditChainExport {
    pub fn create(tenant_id: TenantId, events: Vec<HashedAuditEvent>) -> Result<Self> {
        let verified = verify_audit_chain(tenant_id, &events)?;
        Ok(Self {
            format: AUDIT_CHAIN_EXPORT_FORMAT.into(),
            tenant_id,
            event_count: verified.event_count,
            genesis_event_hash: verified.genesis_event_hash,
            head_event_hash: verified.head_event_hash,
            events,
        })
    }

    pub fn verify(&self) -> Result<VerifiedAuditChain> {
        if self.format != AUDIT_CHAIN_EXPORT_FORMAT {
            return Err(Error::Validation(format!(
                "unsupported audit-chain export format {:?}",
                self.format
            )));
        }

        let verified = verify_audit_chain(self.tenant_id, &self.events)?;
        if self.event_count != verified.event_count {
            return Err(Error::Validation(
                "audit-chain export event count does not match its events".into(),
            ));
        }
        if self.genesis_event_hash != verified.genesis_event_hash {
            return Err(Error::Validation(
                "audit-chain export genesis hash does not match its events".into(),
            ));
        }
        if self.head_event_hash != verified.head_event_hash {
            return Err(Error::Validation(
                "audit-chain export head hash does not match its events".into(),
            ));
        }
        Ok(verified)
    }

    /// Serialize a verified export using RFC 8785 JSON canonicalization.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?;
        canonical_json(self)
    }

    /// Parse an export and reject valid JSON that is not in canonical form.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let export: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::Serialization(error.to_string()))?;
        export.verify()?;
        if canonical_json(&export)?.as_slice() != bytes {
            return Err(Error::Validation(
                "audit-chain export is not canonical JSON".into(),
            ));
        }
        Ok(export)
    }

    /// A stable reference suitable for an independently signed manifest.
    pub fn digest(&self) -> Result<String> {
        self.to_canonical_bytes().map(|bytes| sha256_digest(&bytes))
    }
}

/// Verify a complete tenant chain in genesis-to-head order.
///
/// The first event must be a genesis event, every later event must name the
/// immediately preceding canonical event hash, and event IDs/hashes must be
/// unique. Consequently a missing, duplicated, or reordered row fails closed.
pub fn verify_audit_chain(
    tenant_id: TenantId,
    events: &[HashedAuditEvent],
) -> Result<VerifiedAuditChain> {
    let mut event_ids = BTreeSet::new();
    let mut event_hashes = BTreeSet::new();
    let mut expected_previous_hash: Option<&str> = None;

    for (index, event) in events.iter().enumerate() {
        event.verify()?;
        if event.content.tenant_id != tenant_id {
            return Err(Error::Validation(format!(
                "audit event at index {index} belongs to a different tenant"
            )));
        }
        if !event_ids.insert(event.content.id) {
            return Err(Error::Validation(format!(
                "audit chain contains duplicate event ID at index {index}"
            )));
        }
        if !event_hashes.insert(event.event_hash.as_str()) {
            return Err(Error::Validation(format!(
                "audit chain contains duplicate event hash at index {index}"
            )));
        }
        if event.content.previous_event_hash.as_deref() != expected_previous_hash {
            return Err(Error::Validation(format!(
                "audit chain is out of order or has a gap at index {index}"
            )));
        }
        expected_previous_hash = Some(&event.event_hash);
    }

    let event_count = u64::try_from(events.len())
        .map_err(|_| Error::Validation("audit chain contains too many events".into()))?;
    Ok(VerifiedAuditChain {
        tenant_id,
        event_count,
        genesis_event_id: events.first().map(|event| event.content.id),
        genesis_event_hash: events.first().map(|event| event.event_hash.clone()),
        head_event_id: events.last().map(|event| event.content.id),
        head_event_hash: events.last().map(|event| event.event_hash.clone()),
    })
}

fn validate_content(content: &AuditEventContent) -> Result<()> {
    for (name, value) in [
        ("actor type", content.actor_type.as_str()),
        ("actor ID", content.actor_id.as_str()),
        ("action", content.action.as_str()),
        ("subject type", content.subject_type.as_str()),
        ("subject ID", content.subject_id.as_str()),
        ("correlation ID", content.correlation_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(Error::Validation(format!(
                "audit event {name} must be non-empty"
            )));
        }
    }
    for digest in [
        content.policy_digest.as_deref(),
        content.before_digest.as_deref(),
        content.after_digest.as_deref(),
        content.previous_event_hash.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !is_sha256_digest(digest) {
            return Err(Error::Validation(
                "audit digest fields must use lowercase sha256".into(),
            ));
        }
    }
    reject_sensitive_fields(&content.details)
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use chrono::TimeZone;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    fn content() -> AuditEventContent {
        AuditEventContent {
            id: EventId::new(),
            tenant_id: TenantId::new(),
            work_item_id: Some(WorkItemId::new()),
            attempt_id: None,
            actor_type: "user".into(),
            actor_id: "operator:1".into(),
            action: "work.accept".into(),
            subject_type: "work_item".into(),
            subject_id: "item".into(),
            correlation_id: "request".into(),
            trace_id: None,
            policy_digest: None,
            before_digest: None,
            after_digest: None,
            previous_event_hash: None,
            details: json!({"state": "ACCEPTED"}),
            occurred_at: Utc::now().trunc_subsecs(6),
        }
    }

    fn fixed_tenant(value: u128) -> TenantId {
        TenantId::from_uuid(Uuid::from_u128(value))
    }

    fn fixed_event_id(sequence: u128) -> EventId {
        EventId::from_uuid(Uuid::from_u128(
            0x0189_0000_0000_7000_8000_0000_0000_0000 + sequence,
        ))
    }

    fn fixed_work_item_id() -> WorkItemId {
        WorkItemId::from_uuid(Uuid::from_u128(0x0189_0000_0000_7000_8000_0000_0000_0100))
    }

    fn fixed_attempt_id() -> AttemptId {
        AttemptId::from_uuid(Uuid::from_u128(0x0189_0000_0000_7000_8000_0000_0000_0200))
    }

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn append_event(
        events: &mut Vec<HashedAuditEvent>,
        tenant_id: TenantId,
        sequence: u32,
        action: &str,
        details: Value,
    ) {
        let previous_event_hash = events.last().map(|event| event.event_hash.clone());
        let occurred_at = Utc
            .timestamp_opt(1_700_000_000 + i64::from(sequence), 0)
            .single()
            .unwrap();
        let content = AuditEventContent {
            id: fixed_event_id(u128::from(sequence)),
            tenant_id,
            work_item_id: Some(fixed_work_item_id()),
            attempt_id: Some(fixed_attempt_id()),
            actor_type: "control_plane".into(),
            actor_id: "asf:reactor".into(),
            action: action.into(),
            subject_type: "work_item".into(),
            subject_id: fixed_work_item_id().to_string(),
            correlation_id: "correlation:vertical-slice".into(),
            trace_id: Some("trace:vertical-slice".into()),
            policy_digest: Some(digest('a')),
            before_digest: None,
            after_digest: Some(digest('b')),
            previous_event_hash,
            details,
            occurred_at,
        };
        events.push(HashedAuditEvent::create(content).unwrap());
    }

    fn three_event_chain(tenant_id: TenantId) -> Vec<HashedAuditEvent> {
        let mut events = Vec::new();
        append_event(
            &mut events,
            tenant_id,
            1,
            "work.accepted",
            json!({"approval_ref": "approval:1"}),
        );
        append_event(
            &mut events,
            tenant_id,
            2,
            "run.dispatched",
            json!({"run_ref": "run:1"}),
        );
        append_event(
            &mut events,
            tenant_id,
            3,
            "work.closed",
            json!({"evidence_ref": "evidence:1"}),
        );
        events
    }

    #[test]
    fn audit_hash_detects_tampering() {
        let mut event = HashedAuditEvent::create(content()).unwrap();
        event.content.action = "policy.override".into();
        assert!(event.verify().is_err());
    }

    #[test]
    fn audit_details_reject_secret_fields() {
        let mut input = content();
        input.details = json!({"api_key": "nope"});
        assert!(HashedAuditEvent::create(input).is_err());
    }

    #[test]
    fn complete_chain_exports_canonically_and_round_trips() {
        let tenant_id = fixed_tenant(1);
        let events = three_event_chain(tenant_id);
        let export = AuditChainExport::create(tenant_id, events.clone()).unwrap();

        let verified = export.verify().unwrap();
        assert_eq!(verified.event_count, 3);
        assert_eq!(verified.genesis_event_id, Some(events[0].content.id));
        assert_eq!(verified.head_event_id, Some(events[2].content.id));
        assert_eq!(
            export.genesis_event_hash,
            Some(events[0].event_hash.clone())
        );
        assert_eq!(export.head_event_hash, Some(events[2].event_hash.clone()));

        let bytes = export.to_canonical_bytes().unwrap();
        assert_eq!(bytes, export.to_canonical_bytes().unwrap());
        assert_eq!(
            AuditChainExport::from_canonical_bytes(&bytes).unwrap(),
            export
        );
        assert_eq!(export.digest().unwrap(), sha256_digest(&bytes));

        let pretty = serde_json::to_vec_pretty(&export).unwrap();
        assert!(AuditChainExport::from_canonical_bytes(&pretty).is_err());
    }

    #[test]
    fn chain_verifier_rejects_tampering_gaps_wrong_tenant_duplicates_and_ordering() {
        let tenant_id = fixed_tenant(1);
        let valid = three_event_chain(tenant_id);
        verify_audit_chain(tenant_id, &valid).unwrap();

        let mut tampered_content = valid.clone();
        tampered_content[1].content.action = "run.cancelled".into();

        let mut tampered_hash = valid.clone();
        tampered_hash[1].event_hash = digest('f');

        let missing_middle = vec![valid[0].clone(), valid[2].clone()];

        let mut reordered = valid.clone();
        reordered.swap(1, 2);

        let mut wrong_tenant = valid.clone();
        wrong_tenant[1].content.tenant_id = fixed_tenant(2);
        wrong_tenant[1] = HashedAuditEvent::create(wrong_tenant[1].content.clone()).unwrap();

        let mut duplicate_id = valid.clone();
        duplicate_id[2].content.id = duplicate_id[1].content.id;
        duplicate_id[2] = HashedAuditEvent::create(duplicate_id[2].content.clone()).unwrap();

        let mut non_genesis_start = valid[1..].to_vec();
        non_genesis_start[0] =
            HashedAuditEvent::create(non_genesis_start[0].content.clone()).unwrap();

        for (case, events) in [
            ("content tamper", tampered_content),
            ("hash tamper", tampered_hash),
            ("missing middle", missing_middle),
            ("reordered", reordered),
            ("foreign tenant", wrong_tenant),
            ("duplicate ID", duplicate_id),
            ("missing genesis", non_genesis_start),
        ] {
            assert!(
                verify_audit_chain(tenant_id, &events).is_err(),
                "{case} unexpectedly verified"
            );
        }
    }

    #[test]
    fn export_manifest_rejects_metadata_and_tail_tampering() {
        let tenant_id = fixed_tenant(1);
        let export = AuditChainExport::create(tenant_id, three_event_chain(tenant_id)).unwrap();

        let mut wrong_format = export.clone();
        wrong_format.format = "asf.audit-chain.v2".into();
        assert!(wrong_format.verify().is_err());

        let mut wrong_count = export.clone();
        wrong_count.event_count += 1;
        assert!(wrong_count.verify().is_err());

        let mut wrong_genesis = export.clone();
        wrong_genesis.genesis_event_hash = Some(digest('c'));
        assert!(wrong_genesis.verify().is_err());

        let mut truncated_tail = export.clone();
        truncated_tail.events.pop();
        truncated_tail.event_count -= 1;
        assert!(truncated_tail.verify().is_err());

        let empty = AuditChainExport::create(tenant_id, Vec::new()).unwrap();
        assert_eq!(empty.event_count, 0);
        assert!(empty.genesis_event_hash.is_none());
        assert!(empty.head_event_hash.is_none());
        empty.verify().unwrap();
    }

    #[test]
    fn canonical_export_retains_reconstruction_references_without_secrets() {
        let tenant_id = fixed_tenant(1);
        let mut events = Vec::new();
        append_event(
            &mut events,
            tenant_id,
            1,
            "work.accepted",
            json!({
                "approval_ref": "approval:change-control-42",
                "authority_scope_digest": digest('c'),
                "owner_ref": "team:factory-operations"
            }),
        );
        append_event(
            &mut events,
            tenant_id,
            2,
            "identities.bound",
            json!({
                "product_identity_profile_ref": "ctxlane-profile:product-v1",
                "reviewer_identity_profile_ref": "ctxlane-profile:reviewer-v1",
                "delivery_identity_profile_ref": "ctxlane-profile:delivery-v1"
            }),
        );
        append_event(
            &mut events,
            tenant_id,
            3,
            "candidate.verified",
            json!({
                "repository_ref": "github:acme/widget",
                "base_commit_sha": "1111111111111111111111111111111111111111",
                "candidate_commit_sha": "2222222222222222222222222222222222222222",
                "pull_request_ref": "github:acme/widget#17",
                "work_order_digest": digest('d')
            }),
        );
        append_event(
            &mut events,
            tenant_id,
            4,
            "effect.reconciled",
            json!({
                "effect_ref": "effect:github-pr-17",
                "effect_request_digest": digest('e'),
                "idempotency_key": "effect:work-1:attempt-1:pr",
                "logical_effect_count": 1
            }),
        );
        append_event(
            &mut events,
            tenant_id,
            5,
            "work.closed",
            json!({
                "evidence_ref": "evidence:bundle-9",
                "evidence_digest": digest('f'),
                "ci_check_suite_ref": "github:checks:9001",
                "source_closure_receipt_ref": "linear:issue:ASF-42:closed",
                "closure_reason": "verified_exact_candidate"
            }),
        );

        let export = AuditChainExport::create(tenant_id, events).unwrap();
        let bytes = export.to_canonical_bytes().unwrap();
        let decoded = AuditChainExport::from_canonical_bytes(&bytes).unwrap();
        let portable_value = serde_json::to_value(&decoded).unwrap();
        reject_sensitive_fields(&portable_value).unwrap();

        let rendered = String::from_utf8(bytes).unwrap();
        for required_reference in [
            "approval:change-control-42",
            "ctxlane-profile:product-v1",
            "ctxlane-profile:reviewer-v1",
            "ctxlane-profile:delivery-v1",
            "github:acme/widget#17",
            "2222222222222222222222222222222222222222",
            "effect:github-pr-17",
            "evidence:bundle-9",
            "linear:issue:ASF-42:closed",
        ] {
            assert!(rendered.contains(required_reference));
        }
        assert_eq!(decoded.verify().unwrap().event_count, 5);
    }
}
