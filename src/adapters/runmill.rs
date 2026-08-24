use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use chrono::Utc;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::{
    contracts::{EVIDENCE_ENVELOPE_SCHEMA_V1, ProductEvent, SignedEvidenceBundle},
    crypto::{canonical_json, sha256_digest},
    domain::{AttemptId, EventId, RunId},
    ports::runmill::{
        ACKNOWLEDGE_OUTCOME_RECEIPT_SCHEMA_V1, AcknowledgeOutcomeReceipt,
        AcknowledgeOutcomeRequest, AcknowledgementDisposition, CANCEL_RUN_RECEIPT_SCHEMA_V1,
        CancelRunReceipt, CancelRunRequest, CancellationDisposition, CapabilityNegotiationRequest,
        CapabilityNegotiationRequestV2, EventCursor, GET_EVIDENCE_RECEIPT_SCHEMA_V1,
        GET_RUN_RECEIPT_SCHEMA_V1, GetEvidenceReceipt, GetEvidenceRequest, GetRunEventsRequest,
        GetRunReceipt, GetRunRequest, LookupQualifiedSubmissionReceipt,
        LookupQualifiedSubmissionRequest, RUN_EVENT_PAGE_SCHEMA_V1, RUN_SNAPSHOT_SCHEMA_V1,
        RunEventPage, RunLookup, RunSnapshot, RunmillCapabilities, RunmillCapabilitiesV2,
        RunmillGateway, RunmillGatewayError, RunmillOperation, RunmillResult, RunmillRunState,
        SUBMIT_WORK_ORDER_RECEIPT_SCHEMA_V1, SubmissionDisposition, SubmitWorkOrderReceipt,
        SubmitWorkOrderRequest,
    },
};

const UNAVAILABLE_CONTRACT: &str =
    "the installed Runmill has not published compatible MCP schemas or semantic operation bindings";

/// Prospective production MCP adapter.
///
/// Runmill's current released/source contract exposes no ASF-compatible MCP
/// schema. This adapter therefore performs no process spawn and no guessed tool
/// call. It will remain fail-closed until capability negotiation can be backed
/// by a published, conformance-tested transport binding.
#[derive(Debug, Clone, Default)]
pub struct RunmillMcpAdapter;

impl RunmillMcpAdapter {
    fn unsupported(operation: RunmillOperation) -> RunmillGatewayError {
        RunmillGatewayError::UnsupportedContract {
            detail: format!("{operation:?}: {UNAVAILABLE_CONTRACT}"),
        }
    }
}

#[async_trait]
impl RunmillGateway for RunmillMcpAdapter {
    async fn negotiate(
        &self,
        request: &CapabilityNegotiationRequest,
    ) -> RunmillResult<RunmillCapabilities> {
        request.validate()?;
        Err(RunmillGatewayError::UnsupportedContract {
            detail: UNAVAILABLE_CONTRACT.into(),
        })
    }

    async fn submit_work_order(
        &self,
        request: &SubmitWorkOrderRequest,
    ) -> RunmillResult<SubmitWorkOrderReceipt> {
        request.validate()?;
        Err(Self::unsupported(RunmillOperation::SubmitWorkOrder))
    }

    async fn get_run(&self, request: &GetRunRequest) -> RunmillResult<GetRunReceipt> {
        request.validate()?;
        Err(Self::unsupported(RunmillOperation::GetRun))
    }

    async fn get_run_events(&self, _request: &GetRunEventsRequest) -> RunmillResult<RunEventPage> {
        Err(Self::unsupported(RunmillOperation::GetRunEvents))
    }

    async fn cancel_run(&self, request: &CancelRunRequest) -> RunmillResult<CancelRunReceipt> {
        request.validate()?;
        Err(Self::unsupported(RunmillOperation::CancelRun))
    }

    async fn get_evidence(
        &self,
        request: &GetEvidenceRequest,
    ) -> RunmillResult<GetEvidenceReceipt> {
        request.validate()?;
        Err(Self::unsupported(RunmillOperation::GetEvidence))
    }

    async fn acknowledge_outcome(
        &self,
        request: &AcknowledgeOutcomeRequest,
    ) -> RunmillResult<AcknowledgeOutcomeReceipt> {
        request.validate()?;
        Err(Self::unsupported(RunmillOperation::AcknowledgeOutcome))
    }

    async fn negotiate_v2(
        &self,
        request: &CapabilityNegotiationRequestV2,
    ) -> RunmillResult<RunmillCapabilitiesV2> {
        request.validate()?;
        Err(RunmillGatewayError::UnsupportedContract {
            detail: UNAVAILABLE_CONTRACT.into(),
        })
    }

    async fn lookup_qualified_submission(
        &self,
        request: &LookupQualifiedSubmissionRequest,
    ) -> RunmillResult<LookupQualifiedSubmissionReceipt> {
        request.validate()?;
        Err(RunmillGatewayError::UnsupportedContract {
            detail: UNAVAILABLE_CONTRACT.into(),
        })
    }
}

#[derive(Debug, Clone)]
struct SubmissionRecord {
    receipt: SubmitWorkOrderReceipt,
    qualification: crate::ports::runmill::QualifiedSubmissionIdentityV1,
}

#[derive(Debug, Clone)]
struct CancellationRecord {
    request: CancelRunRequest,
    receipt: CancelRunReceipt,
}

#[derive(Debug, Clone)]
struct AcknowledgementRecord {
    request: AcknowledgeOutcomeRequest,
    receipt: AcknowledgeOutcomeReceipt,
}

#[derive(Debug, Clone)]
struct FakeRunRecord {
    snapshot: RunSnapshot,
    events: Vec<ProductEvent>,
    evidence: Option<SignedEvidenceBundle>,
}

#[derive(Debug, Default)]
struct FakeState {
    submissions: HashMap<String, SubmissionRecord>,
    runs: HashMap<RunId, FakeRunRecord>,
    run_by_attempt: HashMap<AttemptId, RunId>,
    event_ids: HashSet<EventId>,
    cancellations: HashMap<(RunId, String), CancellationRecord>,
    acknowledgements: HashMap<(RunId, String), AcknowledgementRecord>,
}

/// In-memory conformance fake for workflow and failure-injection tests.
///
/// It models the prospective contract rather than the current Runmill CLI. In
/// particular, a repeated submission adopts the existing run if and only if
/// both its idempotency key and Work Order digest match.
#[derive(Debug, Clone)]
pub struct InMemoryRunmillGateway {
    capabilities: RunmillCapabilities,
    capabilities_v2: RunmillCapabilitiesV2,
    state: Arc<Mutex<FakeState>>,
}

impl Default for InMemoryRunmillGateway {
    fn default() -> Self {
        Self::new(crate::domain::WorkerId::new(), 1)
    }
}

impl InMemoryRunmillGateway {
    #[must_use]
    pub fn new(worker_id: crate::domain::WorkerId, worker_generation: u64) -> Self {
        Self {
            capabilities: RunmillCapabilities::prospective_v1(worker_id, worker_generation),
            capabilities_v2: RunmillCapabilitiesV2::prospective_v2(worker_id, worker_generation),
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    #[must_use]
    pub fn declared_capabilities(&self) -> &RunmillCapabilities {
        &self.capabilities
    }

    #[must_use]
    pub fn declared_capabilities_v2(&self) -> &RunmillCapabilitiesV2 {
        &self.capabilities_v2
    }

    pub async fn run_count(&self) -> usize {
        self.state.lock().await.runs.len()
    }

    /// Append a worker event while enforcing run binding, global event-ID
    /// uniqueness, and contiguous aggregate versions.
    pub async fn append_event(
        &self,
        run_id: RunId,
        event: ProductEvent,
    ) -> RunmillResult<EventCursor> {
        let mut state = self.state.lock().await;
        if state.event_ids.contains(&event.event_id) {
            return Err(RunmillGatewayError::InvalidRequest(format!(
                "duplicate event ID {}",
                event.event_id
            )));
        }
        let record = state
            .runs
            .get(&run_id)
            .ok_or(RunmillGatewayError::RunNotFound(run_id))?;
        if event.run_id != Some(run_id) {
            return Err(RunmillGatewayError::InvalidRequest(
                "event is not bound to the requested run".into(),
            ));
        }
        let expected_version = record
            .snapshot
            .aggregate_version
            .checked_add(1)
            .ok_or_else(|| {
                RunmillGatewayError::InvalidRequest("run aggregate version overflowed".into())
            })?;
        if event.aggregate_version != expected_version {
            return Err(RunmillGatewayError::InvalidRequest(format!(
                "event aggregate version must be {expected_version}, got {}",
                event.aggregate_version
            )));
        }

        state.event_ids.insert(event.event_id);
        let record = state
            .runs
            .get_mut(&run_id)
            .expect("run existence checked while holding the same lock");
        record.events.push(event);
        let cursor = cursor_for(run_id, record.events.len());
        record.snapshot.aggregate_version = expected_version;
        record.snapshot.last_event_cursor = Some(cursor.clone());
        record.snapshot.updated_at = Utc::now();
        Ok(cursor)
    }

    /// Install worker-produced evidence for fake workflow tests.
    ///
    /// The fake checks canonical digest and run/attempt/worker bindings. It does
    /// not pretend to own the worker's private signing key; independent evidence
    /// signature verification remains the evidence verifier's responsibility.
    pub async fn attach_evidence(
        &self,
        run_id: RunId,
        evidence: SignedEvidenceBundle,
    ) -> RunmillResult<()> {
        if evidence.envelope_schema != EVIDENCE_ENVELOPE_SCHEMA_V1
            || evidence.algorithm != "EdDSA"
            || evidence.key_id.trim().is_empty()
            || evidence.signature.trim().is_empty()
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "evidence envelope is incomplete or unsupported".into(),
            ));
        }
        let digest = sha256_digest(&canonical_json(&evidence.payload).map_err(|error| {
            RunmillGatewayError::InvalidRequest(format!("invalid evidence payload: {error}"))
        })?);
        if digest != evidence.payload_digest {
            return Err(RunmillGatewayError::InvalidRequest(
                "evidence payload digest mismatch".into(),
            ));
        }

        let mut state = self.state.lock().await;
        let record = state
            .runs
            .get_mut(&run_id)
            .ok_or(RunmillGatewayError::RunNotFound(run_id))?;
        if evidence.payload.run_id != run_id
            || evidence.payload.attempt_id != record.snapshot.attempt_id
            || evidence.payload.work_order_digest != record.snapshot.work_order_digest
            || evidence.payload.worker_id != record.snapshot.worker_id
            || evidence.payload.worker_generation != record.snapshot.worker_generation
        {
            return Err(RunmillGatewayError::InvalidRequest(
                "evidence is not bound to the adopted run and worker generation".into(),
            ));
        }

        record.snapshot.evidence_digest = Some(digest);
        if evidence.payload.target_satisfied {
            record.snapshot.state = RunmillRunState::TargetReached;
        }
        record.snapshot.aggregate_version = record
            .snapshot
            .aggregate_version
            .checked_add(1)
            .ok_or_else(|| {
                RunmillGatewayError::InvalidRequest("run aggregate version overflowed".into())
            })?;
        record.snapshot.updated_at = Utc::now();
        record.evidence = Some(evidence);
        Ok(())
    }
}

#[async_trait]
impl RunmillGateway for InMemoryRunmillGateway {
    async fn negotiate(
        &self,
        request: &CapabilityNegotiationRequest,
    ) -> RunmillResult<RunmillCapabilities> {
        self.capabilities.satisfy(request)?;
        Ok(self.capabilities.clone())
    }

    async fn submit_work_order(
        &self,
        request: &SubmitWorkOrderRequest,
    ) -> RunmillResult<SubmitWorkOrderReceipt> {
        request.validate()?;
        let mut state = self.state.lock().await;

        if let Some(existing) = state.submissions.get(&request.idempotency_key) {
            if existing.qualification.work_order_digest != request.work_order_digest {
                return Err(RunmillGatewayError::IdempotencyConflict {
                    idempotency_key: request.idempotency_key.clone(),
                    existing_digest: existing.qualification.work_order_digest.clone(),
                    submitted_digest: request.work_order_digest.clone(),
                });
            }
            let mut receipt = existing.receipt.clone();
            receipt.disposition = SubmissionDisposition::Adopted;
            return Ok(receipt);
        }

        let attempt_id = request.work_order.payload.attempt_id;
        if let Some(existing_run_id) = state.run_by_attempt.get(&attempt_id) {
            return Err(RunmillGatewayError::InvalidRequest(format!(
                "attempt {attempt_id} is already adopted by run {existing_run_id}"
            )));
        }

        let run_id = RunId::new();
        let now = Utc::now();
        let receipt = SubmitWorkOrderReceipt {
            schema: SUBMIT_WORK_ORDER_RECEIPT_SCHEMA_V1.into(),
            run_id,
            attempt_id,
            idempotency_key: request.idempotency_key.clone(),
            work_order_digest: request.work_order_digest.clone(),
            disposition: SubmissionDisposition::Accepted,
            accepted_at: now,
        };
        let snapshot = RunSnapshot {
            schema: RUN_SNAPSHOT_SCHEMA_V1.into(),
            run_id,
            attempt_id,
            idempotency_key: request.idempotency_key.clone(),
            work_order_digest: request.work_order_digest.clone(),
            worker_id: self.capabilities.worker_id,
            worker_generation: self.capabilities.worker_generation,
            state: RunmillRunState::Accepted,
            aggregate_version: 1,
            last_event_cursor: None,
            evidence_digest: None,
            outcome_acknowledged: false,
            accepted_at: now,
            updated_at: now,
        };

        let qualification =
            crate::ports::runmill::QualifiedSubmissionIdentityV1::from_submit_work_order_request(
                request,
            )?;

        state.run_by_attempt.insert(attempt_id, run_id);
        state.runs.insert(
            run_id,
            FakeRunRecord {
                snapshot,
                events: Vec::new(),
                evidence: None,
            },
        );
        state.submissions.insert(
            request.idempotency_key.clone(),
            SubmissionRecord {
                receipt: receipt.clone(),
                qualification,
            },
        );

        Ok(receipt)
    }

    async fn get_run(&self, request: &GetRunRequest) -> RunmillResult<GetRunReceipt> {
        request.validate()?;
        let state = self.state.lock().await;
        let run_id = match &request.lookup {
            RunLookup::RunId(run_id) => Some(*run_id),
            RunLookup::AttemptId(attempt_id) => state.run_by_attempt.get(attempt_id).copied(),
            RunLookup::IdempotencyKey(key) => state
                .submissions
                .get(key)
                .map(|submission| submission.receipt.run_id),
        };
        let run = run_id.and_then(|run_id| {
            state
                .runs
                .get(&run_id)
                .map(|record| record.snapshot.clone())
        });
        Ok(GetRunReceipt {
            schema: GET_RUN_RECEIPT_SCHEMA_V1.into(),
            run,
        })
    }

    async fn get_run_events(&self, request: &GetRunEventsRequest) -> RunmillResult<RunEventPage> {
        request.validate(self.capabilities.max_event_page_size)?;
        let state = self.state.lock().await;
        let record = state
            .runs
            .get(&request.run_id)
            .ok_or(RunmillGatewayError::RunNotFound(request.run_id))?;
        let offset = request.after.as_ref().map_or(Ok(0), |cursor| {
            parse_cursor(cursor, request.run_id, record.events.len())
        })?;
        let limit = usize::try_from(request.limit).map_err(|_| {
            RunmillGatewayError::InvalidRequest("event page limit cannot fit this platform".into())
        })?;
        let end = offset.saturating_add(limit).min(record.events.len());
        let next_cursor = (end > 0).then(|| cursor_for(request.run_id, end));

        Ok(RunEventPage {
            schema: RUN_EVENT_PAGE_SCHEMA_V1.into(),
            run_id: request.run_id,
            after: request.after.clone(),
            events: record.events[offset..end].to_vec(),
            next_cursor,
            has_more: end < record.events.len(),
            snapshot: record.snapshot.clone(),
        })
    }

    async fn cancel_run(&self, request: &CancelRunRequest) -> RunmillResult<CancelRunReceipt> {
        request.validate()?;
        let mut state = self.state.lock().await;
        let key = (request.run_id, request.idempotency_key.clone());
        if let Some(existing) = state.cancellations.get(&key) {
            if existing.request != *request {
                return Err(idempotency_conflict(
                    &request.idempotency_key,
                    &existing.request,
                    request,
                ));
            }
            let mut receipt = existing.receipt.clone();
            receipt.disposition = CancellationDisposition::Adopted;
            return Ok(receipt);
        }

        let record = state
            .runs
            .get_mut(&request.run_id)
            .ok_or(RunmillGatewayError::RunNotFound(request.run_id))?;
        let disposition = if record.snapshot.state.is_terminal() {
            CancellationDisposition::AlreadyTerminal
        } else {
            record.snapshot.state = RunmillRunState::CancelRequested;
            record.snapshot.aggregate_version = record
                .snapshot
                .aggregate_version
                .checked_add(1)
                .ok_or_else(|| {
                    RunmillGatewayError::InvalidRequest("run aggregate version overflowed".into())
                })?;
            record.snapshot.updated_at = Utc::now();
            CancellationDisposition::Requested
        };
        let receipt = CancelRunReceipt {
            schema: CANCEL_RUN_RECEIPT_SCHEMA_V1.into(),
            run_id: request.run_id,
            idempotency_key: request.idempotency_key.clone(),
            disposition,
            state: record.snapshot.state,
            aggregate_version: record.snapshot.aggregate_version,
            recorded_at: Utc::now(),
        };
        state.cancellations.insert(
            key,
            CancellationRecord {
                request: request.clone(),
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    async fn get_evidence(
        &self,
        request: &GetEvidenceRequest,
    ) -> RunmillResult<GetEvidenceReceipt> {
        request.validate()?;
        let state = self.state.lock().await;
        let record = state
            .runs
            .get(&request.run_id)
            .ok_or(RunmillGatewayError::RunNotFound(request.run_id))?;
        Ok(GetEvidenceReceipt {
            schema: GET_EVIDENCE_RECEIPT_SCHEMA_V1.into(),
            run_id: request.run_id,
            evidence: record.evidence.clone(),
        })
    }

    async fn acknowledge_outcome(
        &self,
        request: &AcknowledgeOutcomeRequest,
    ) -> RunmillResult<AcknowledgeOutcomeReceipt> {
        request.validate()?;
        let mut state = self.state.lock().await;
        let key = (request.run_id, request.idempotency_key.clone());
        if let Some(existing) = state.acknowledgements.get(&key) {
            if existing.request != *request {
                return Err(idempotency_conflict(
                    &request.idempotency_key,
                    &existing.request,
                    request,
                ));
            }
            let mut receipt = existing.receipt.clone();
            receipt.disposition = AcknowledgementDisposition::Adopted;
            return Ok(receipt);
        }

        let record = state
            .runs
            .get_mut(&request.run_id)
            .ok_or(RunmillGatewayError::RunNotFound(request.run_id))?;
        let evidence = record.evidence.as_ref().ok_or_else(|| {
            RunmillGatewayError::EvidenceUnavailable(format!(
                "run {} has not produced evidence",
                request.run_id
            ))
        })?;
        if evidence.payload_digest != request.evidence_digest {
            return Err(RunmillGatewayError::EvidenceUnavailable(
                "acknowledgement digest does not match the run evidence".into(),
            ));
        }

        record.snapshot.outcome_acknowledged = true;
        record.snapshot.aggregate_version = record
            .snapshot
            .aggregate_version
            .checked_add(1)
            .ok_or_else(|| {
                RunmillGatewayError::InvalidRequest("run aggregate version overflowed".into())
            })?;
        record.snapshot.updated_at = Utc::now();
        let receipt = AcknowledgeOutcomeReceipt {
            schema: ACKNOWLEDGE_OUTCOME_RECEIPT_SCHEMA_V1.into(),
            run_id: request.run_id,
            idempotency_key: request.idempotency_key.clone(),
            evidence_digest: request.evidence_digest.clone(),
            disposition: AcknowledgementDisposition::Recorded,
            aggregate_version: record.snapshot.aggregate_version,
            recorded_at: Utc::now(),
        };
        state.acknowledgements.insert(
            key,
            AcknowledgementRecord {
                request: request.clone(),
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    async fn negotiate_v2(
        &self,
        request: &CapabilityNegotiationRequestV2,
    ) -> RunmillResult<RunmillCapabilitiesV2> {
        self.capabilities_v2.satisfy(request)?;
        Ok(self.capabilities_v2.clone())
    }

    async fn lookup_qualified_submission(
        &self,
        request: &LookupQualifiedSubmissionRequest,
    ) -> RunmillResult<LookupQualifiedSubmissionReceipt> {
        request.validate()?;
        let state = self.state.lock().await;

        if let Some(submission) = state
            .submissions
            .get(&request.qualification.idempotency_key)
            && submission.qualification == request.qualification
            && let Some(run_id) = state
                .run_by_attempt
                .get(&request.qualification.attempt_id)
                .copied()
            && let Some(record) = state.runs.get(&run_id)
        {
            let snapshot = record.snapshot.clone();
            let admission_worker = crate::ports::runmill::QualifiedSubmissionAdmissionWorkerV1 {
                worker_id: snapshot.worker_id,
                worker_generation: snapshot.worker_generation,
            };
            let receipt = LookupQualifiedSubmissionReceipt {
                schema: crate::ports::runmill::LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
                outcome: crate::ports::runmill::LookupQualifiedSubmissionOutcome::Found(Box::new(
                    crate::ports::runmill::QualifiedSubmissionFound {
                        qualification: request.qualification.clone(),
                        run: snapshot,
                        admission_worker,
                    },
                )),
            };
            receipt.validate_against(request)?;
            return Ok(receipt);
        }

        Ok(LookupQualifiedSubmissionReceipt {
            schema: crate::ports::runmill::LOOKUP_QUALIFIED_SUBMISSION_RECEIPT_SCHEMA_V1.into(),
            outcome: crate::ports::runmill::LookupQualifiedSubmissionOutcome::NotFound,
        })
    }
}

fn cursor_for(run_id: RunId, offset: usize) -> EventCursor {
    EventCursor::from_opaque(format!("v1:{run_id}:{offset}"))
        .expect("generated event cursors are non-empty")
}

fn parse_cursor(cursor: &EventCursor, run_id: RunId, event_count: usize) -> RunmillResult<usize> {
    let expected_prefix = format!("v1:{run_id}:");
    let offset = cursor
        .as_str()
        .strip_prefix(&expected_prefix)
        .ok_or_else(|| {
            RunmillGatewayError::InvalidCursor("cursor belongs to another run or schema".into())
        })?
        .parse::<usize>()
        .map_err(|_| RunmillGatewayError::InvalidCursor("cursor position is malformed".into()))?;
    if offset > event_count {
        return Err(RunmillGatewayError::InvalidCursor(
            "cursor is ahead of the durable event stream".into(),
        ));
    }
    Ok(offset)
}

fn idempotency_conflict<T: Serialize>(
    idempotency_key: &str,
    existing: &T,
    submitted: &T,
) -> RunmillGatewayError {
    let digest = |value: &T| {
        canonical_json(value)
            .map_or_else(|_| "unserializable".into(), |bytes| sha256_digest(&bytes))
    };
    RunmillGatewayError::IdempotencyConflict {
        idempotency_key: idempotency_key.into(),
        existing_digest: digest(existing),
        submitted_digest: digest(submitted),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, Utc};
    use serde_json::json;

    use crate::{
        contracts::{
            CheckConclusion, CheckEvidence, CheckRequirements, ContractDigests, EVIDENCE_SCHEMA_V1,
            EvidenceBundleV1, EvidenceExpectation, ProductEvent, PullRequestEvidence,
            RepositoryTarget, ReviewEvidence, RoleIdentityEvidence, RoleOutcomeConclusion,
            RoleOutcomeEvidence, RuntimeDigestEvidence, SideEffectEvidence, SideEffectStatus,
            SignedEvidenceBundle, SignedWorkOrder, UsageEvidence, WORK_ORDER_SCHEMA_V1,
            WorkOrderV1,
        },
        crypto::{Ed25519Signer, canonical_json, sha256_digest},
        domain::{
            AttemptId, BudgetLimits, ClosureTarget, CtxlaneProfileRef, DeliveryPermission,
            EffectAuthority, EvidenceId, ExecutionAuthority, IdentityRole, PathAuthority,
            RepositoryId, RiskAssessment, RiskClass, SourceSystem, TenantId, ToolAuthority,
            WorkItemId, WorkOrderId, WorkOrderIdentities, WorkerId,
        },
        ports::runmill::{
            ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1, AcknowledgeOutcomeRequest,
            AcknowledgementDisposition, CANCEL_RUN_REQUEST_SCHEMA_V1, CancelRunRequest,
            CancellationDisposition, CapabilityNegotiationRequest,
            GET_RUN_EVENTS_REQUEST_SCHEMA_V1, GetEvidenceRequest, GetRunEventsRequest,
            GetRunRequest, PRODUCT_EVENT_SCHEMA_V1, QualifiedSubmissionIdentityV1, RunmillGateway,
            RunmillGatewayError, SubmissionDisposition, SubmitWorkOrderRequest,
        },
    };

    use super::{InMemoryRunmillGateway, RunmillMcpAdapter};

    fn signed_work_order(idempotency_key: &str, objective: &str) -> SignedWorkOrder {
        let now = Utc::now();
        let payload = WorkOrderV1 {
            schema: WORK_ORDER_SCHEMA_V1.into(),
            work_order_id: WorkOrderId::new(),
            tenant_id: TenantId::new(),
            work_item_id: WorkItemId::new(),
            attempt_id: AttemptId::new(),
            idempotency_key: idempotency_key.into(),
            source_system: SourceSystem::Api,
            source_external_id: "request-1".into(),
            source_snapshot_digest: sha256_digest(b"source"),
            source_reference: "api://request-1".into(),
            repository: RepositoryTarget {
                repository_id: RepositoryId::new(),
                forge: "github".into(),
                owner: "acme".into(),
                name: "app".into(),
                base_ref: "refs/heads/main".into(),
                base_sha: "0123456789012345678901234567890123456789".into(),
            },
            objective: objective.into(),
            acceptance_criteria: vec!["the change is verified".into()],
            non_goals: vec![],
            checks: CheckRequirements {
                local_check_ids: BTreeSet::from(["test".into()]),
                remote_ci_contexts: BTreeSet::from(["ci".into()]),
            },
            risk: RiskAssessment {
                class: RiskClass::Low,
                reasons: vec!["test fixture".into()],
                matched_rules: BTreeSet::from(["low-risk-test-rule".into()]),
            },
            identities: WorkOrderIdentities {
                implementer: "codex:implementer".parse::<CtxlaneProfileRef>().unwrap(),
                local_reviewer: "claude:local-reviewer"
                    .parse::<CtxlaneProfileRef>()
                    .unwrap(),
                pr_reviewer: "claude:pr-reviewer".parse::<CtxlaneProfileRef>().unwrap(),
            },
            authority: ExecutionAuthority {
                paths: PathAuthority {
                    allowed: BTreeSet::from(["**".into()]),
                    forbidden: BTreeSet::from([".git/**".into()]),
                },
                tools: ToolAuthority {
                    allowed_tools: BTreeSet::new(),
                    allowed_commands: BTreeSet::new(),
                    network_destinations: BTreeSet::new(),
                },
                effects: EffectAuthority {
                    delivery: DeliveryPermission::PullRequest,
                    may_comment: false,
                    may_update_checks: false,
                    deployment_environment: None,
                },
                budgets: BudgetLimits {
                    max_cost_microunits: 1_000_000,
                    max_input_tokens: 10_000,
                    max_output_tokens: 10_000,
                    max_implementer_invocations: 1,
                    max_reviewer_invocations: 2,
                    max_fix_iterations: 1,
                    max_wall_time_seconds: 600,
                    max_external_api_calls: 100,
                },
                required_approval_types: BTreeSet::new(),
                sandbox_policy_ref: "sandbox:v1".into(),
            },
            closure_target: ClosureTarget::PullRequest,
            digests: ContractDigests {
                policy: sha256_digest(b"policy"),
                repository_policy: sha256_digest(b"repo-policy"),
                planner: sha256_digest(b"planner"),
                harness: sha256_digest(b"harness"),
            },
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::hours(1),
        };
        SignedWorkOrder::sign(payload, &Ed25519Signer::generate("asf-test")).unwrap()
    }

    fn product_event(run_id: crate::domain::RunId, aggregate_version: u64) -> ProductEvent {
        let now = Utc::now();
        ProductEvent {
            schema: PRODUCT_EVENT_SCHEMA_V1.into(),
            event_id: crate::domain::EventId::new(),
            tenant_id: TenantId::new(),
            work_item_id: None,
            attempt_id: None,
            work_order_digest: None,
            run_id: Some(run_id),
            aggregate_version,
            occurred_at: now,
            ingested_at: now,
            actor: "runmill:test-worker".into(),
            event_type: "run.progressed".into(),
            payload: json!({"step": aggregate_version}),
            policy_digest: None,
            trace_id: "trace-1".into(),
            correlation_id: "correlation-1".into(),
        }
    }

    fn signed_evidence(
        request: &SubmitWorkOrderRequest,
        receipt: &crate::ports::runmill::SubmitWorkOrderReceipt,
        worker_id: WorkerId,
        worker_generation: u64,
    ) -> SignedEvidenceBundle {
        let candidate = "abcdefabcdefabcdefabcdefabcdefabcdefabcd".to_owned();
        let base_sha = request.work_order.payload.repository.base_sha.clone();
        let identities = &request.work_order.payload.identities;
        let payload = EvidenceBundleV1 {
            schema: EVIDENCE_SCHEMA_V1.into(),
            evidence_id: EvidenceId::new(),
            work_item_id: request.work_order.payload.work_item_id,
            attempt_id: receipt.attempt_id,
            run_id: receipt.run_id,
            worker_id,
            worker_generation,
            work_order_digest: receipt.work_order_digest.clone(),
            work_order: request.work_order.clone(),
            work_order_signature_verified_by_worker: true,
            source_snapshot_digest: request.work_order.payload.source_snapshot_digest.clone(),
            policy_input_digests: std::collections::BTreeMap::from([
                (
                    "tenant".into(),
                    request.work_order.payload.digests.policy.clone(),
                ),
                (
                    "repository".into(),
                    request.work_order.payload.digests.repository_policy.clone(),
                ),
                ("forge".into(), sha256_digest(b"forge-policy")),
            ]),
            repository: "acme/app".into(),
            base_ref: request.work_order.payload.repository.base_ref.clone(),
            base_sha: base_sha.clone(),
            candidate_sha: candidate.clone(),
            remote_head_sha: candidate.clone(),
            merge_sha: None,
            changed_paths: BTreeSet::from(["src/lib.rs".into()]),
            diff_digest: sha256_digest(b"diff"),
            identity_attribution: vec![
                RoleIdentityEvidence {
                    role: IdentityRole::Implementer,
                    provider: "codex".into(),
                    profile_ref: identities.implementer.clone(),
                    principal_ref: "service:implementer".into(),
                    lease_id: "lease-implementer".into(),
                    model: "test-model".into(),
                    isolation: "credential-isolated".into(),
                },
                RoleIdentityEvidence {
                    role: IdentityRole::LocalReviewer,
                    provider: "claude".into(),
                    profile_ref: identities.local_reviewer.clone(),
                    principal_ref: "service:reviewer".into(),
                    lease_id: "lease-local-reviewer".into(),
                    model: "test-model".into(),
                    isolation: "credential-isolated".into(),
                },
                RoleIdentityEvidence {
                    role: IdentityRole::PrReviewer,
                    provider: "claude".into(),
                    profile_ref: identities.pr_reviewer.clone(),
                    principal_ref: "service:reviewer".into(),
                    lease_id: "lease-pr-reviewer".into(),
                    model: "test-model".into(),
                    isolation: "credential-isolated".into(),
                },
            ],
            runtime_digests: RuntimeDigestEvidence {
                harness: sha256_digest(b"harness"),
                tool_policy: sha256_digest(b"tool-policy"),
                sandbox: sha256_digest(b"sandbox"),
                dependencies: sha256_digest(b"dependencies"),
                runtime: sha256_digest(b"runtime"),
            },
            role_outcomes: vec![
                RoleOutcomeEvidence {
                    role: IdentityRole::Implementer,
                    candidate_sha: Some(candidate.clone()),
                    conclusion: RoleOutcomeConclusion::Completed,
                    summary_digest: sha256_digest(b"implementation-summary"),
                },
                RoleOutcomeEvidence {
                    role: IdentityRole::LocalReviewer,
                    candidate_sha: Some(candidate.clone()),
                    conclusion: RoleOutcomeConclusion::Completed,
                    summary_digest: sha256_digest(b"local-review-summary"),
                },
                RoleOutcomeEvidence {
                    role: IdentityRole::PrReviewer,
                    candidate_sha: Some(candidate.clone()),
                    conclusion: RoleOutcomeConclusion::Completed,
                    summary_digest: sha256_digest(b"pr-review-summary"),
                },
            ],
            findings: Vec::new(),
            requested_target: ClosureTarget::PullRequest,
            target_satisfied: true,
            checks: vec![CheckEvidence {
                check_id: "test".into(),
                candidate_sha: candidate.clone(),
                conclusion: CheckConclusion::Passed,
                artifact_digest: None,
            }],
            review: ReviewEvidence {
                reviewer_profile: identities.pr_reviewer.to_string(),
                reviewer_principal: "service:reviewer".into(),
                candidate_sha: candidate.clone(),
                independent: true,
                approved: true,
                report_digest: sha256_digest(b"review"),
            },
            pull_request: Some(PullRequestEvidence {
                repository: "acme/app".into(),
                number: 7,
                url: "https://github.test/acme/app/pull/7".into(),
                base_sha,
                head_sha: candidate.clone(),
                required_ci_contexts: BTreeSet::from(["ci".into()]),
                successful_ci_contexts: BTreeSet::from(["ci".into()]),
            }),
            side_effects: vec![SideEffectEvidence {
                effect_type: "pull_request.create".into(),
                idempotency_key: "pr-effect".into(),
                intent_digest: sha256_digest(b"pr-intent"),
                status: SideEffectStatus::Confirmed,
                observation_digest: Some(sha256_digest(b"pr-observation")),
                candidate_sha: Some(candidate),
            }],
            approvals: Vec::new(),
            cancellation: None,
            artifacts: Vec::new(),
            usage: UsageEvidence {
                cost_microunits: 1,
                input_tokens: 1,
                output_tokens: 1,
                implementer_invocations: 1,
                reviewer_invocations: 2,
                fix_iterations: 0,
                wall_time_seconds: 1,
            },
            stop_reason: "target_satisfied".into(),
            produced_at: Utc::now(),
        };
        SignedEvidenceBundle::sign(payload, &Ed25519Signer::generate("worker-test")).unwrap()
    }

    #[tokio::test]
    async fn production_adapter_fails_closed_without_a_negotiated_contract() {
        let adapter = RunmillMcpAdapter;
        let error = adapter
            .negotiate(&CapabilityNegotiationRequest::asf_v1())
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RunmillGatewayError::UnsupportedContract { .. }
        ));

        let submit =
            SubmitWorkOrderRequest::new(signed_work_order("dispatch-1", "change it")).unwrap();
        let error = adapter.submit_work_order(&submit).await.unwrap_err();
        assert!(matches!(
            error,
            RunmillGatewayError::UnsupportedContract { .. }
        ));
    }

    #[tokio::test]
    async fn fake_negotiates_every_required_semantic_capability() {
        let fake = InMemoryRunmillGateway::default();
        let required = CapabilityNegotiationRequest::asf_v1();
        let capabilities = fake.negotiate(&required).await.unwrap();
        capabilities.satisfy(&required).unwrap();
        assert!(
            required
                .required_operations
                .is_subset(&capabilities.operations)
        );
        assert!(capabilities.asf_owns_source_mutations);
    }

    #[tokio::test]
    async fn same_submission_key_and_digest_adopts_but_a_different_digest_conflicts() {
        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("dispatch-1", "first")).unwrap();

        let accepted = fake.submit_work_order(&request).await.unwrap();
        assert_eq!(accepted.disposition, SubmissionDisposition::Accepted);
        let adopted = fake.submit_work_order(&request).await.unwrap();
        assert_eq!(adopted.disposition, SubmissionDisposition::Adopted);
        assert_eq!(adopted.run_id, accepted.run_id);
        assert_eq!(adopted.accepted_at, accepted.accepted_at);
        assert_eq!(fake.run_count().await, 1);

        let changed =
            SubmitWorkOrderRequest::new(signed_work_order("dispatch-1", "different")).unwrap();
        let error = fake.submit_work_order(&changed).await.unwrap_err();
        assert!(matches!(
            error,
            RunmillGatewayError::IdempotencyConflict { .. }
        ));
        assert_eq!(fake.run_count().await, 1);

        let run = fake
            .get_run(&GetRunRequest::by_idempotency_key("dispatch-1"))
            .await
            .unwrap()
            .run
            .unwrap();
        assert_eq!(run.run_id, accepted.run_id);
    }

    #[tokio::test]
    async fn event_pages_use_exclusive_stable_run_scoped_cursors() {
        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("dispatch-1", "first")).unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();
        fake.append_event(receipt.run_id, product_event(receipt.run_id, 2))
            .await
            .unwrap();
        fake.append_event(receipt.run_id, product_event(receipt.run_id, 3))
            .await
            .unwrap();

        let first_request = GetRunEventsRequest::first_page(receipt.run_id, 1);
        let first = fake.get_run_events(&first_request).await.unwrap();
        let repeated = fake.get_run_events(&first_request).await.unwrap();
        assert_eq!(first.events, repeated.events);
        assert_eq!(first.next_cursor, repeated.next_cursor);
        assert!(first.has_more);

        let second = fake
            .get_run_events(&GetRunEventsRequest {
                schema: GET_RUN_EVENTS_REQUEST_SCHEMA_V1.into(),
                run_id: receipt.run_id,
                after: first.next_cursor,
                limit: 1,
            })
            .await
            .unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].aggregate_version, 3);
        assert!(!second.has_more);
    }

    #[tokio::test]
    async fn cancellation_and_evidence_acknowledgement_are_idempotent() {
        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("dispatch-1", "first")).unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();
        let cancel = CancelRunRequest {
            schema: CANCEL_RUN_REQUEST_SCHEMA_V1.into(),
            run_id: receipt.run_id,
            idempotency_key: "cancel-1".into(),
            reason: "operator request".into(),
            requested_at: Utc::now(),
        };
        assert_eq!(
            fake.cancel_run(&cancel).await.unwrap().disposition,
            CancellationDisposition::Requested
        );
        assert_eq!(
            fake.cancel_run(&cancel).await.unwrap().disposition,
            CancellationDisposition::Adopted
        );
        let mut conflicting_cancel = cancel.clone();
        conflicting_cancel.reason = "different operator request".into();
        assert!(matches!(
            fake.cancel_run(&conflicting_cancel).await.unwrap_err(),
            RunmillGatewayError::IdempotencyConflict { .. }
        ));

        let worker = fake.declared_capabilities();
        let evidence = signed_evidence(
            &request,
            &receipt,
            worker.worker_id,
            worker.worker_generation,
        );
        fake.attach_evidence(receipt.run_id, evidence.clone())
            .await
            .unwrap();
        let fetched = fake
            .get_evidence(&GetEvidenceRequest::for_run(receipt.run_id))
            .await
            .unwrap();
        assert_eq!(fetched.evidence, Some(evidence.clone()));

        let acknowledge = AcknowledgeOutcomeRequest {
            schema: ACKNOWLEDGE_OUTCOME_REQUEST_SCHEMA_V1.into(),
            run_id: receipt.run_id,
            idempotency_key: "ack-1".into(),
            evidence_digest: evidence.payload_digest,
            acknowledged_at: Utc::now(),
        };
        assert_eq!(
            fake.acknowledge_outcome(&acknowledge)
                .await
                .unwrap()
                .disposition,
            AcknowledgementDisposition::Recorded
        );
        assert_eq!(
            fake.acknowledge_outcome(&acknowledge)
                .await
                .unwrap()
                .disposition,
            AcknowledgementDisposition::Adopted
        );
        let mut conflicting_acknowledgement = acknowledge;
        conflicting_acknowledgement.evidence_digest = "sha256:different-evidence".into();
        assert!(matches!(
            fake.acknowledge_outcome(&conflicting_acknowledgement)
                .await
                .unwrap_err(),
            RunmillGatewayError::IdempotencyConflict { .. }
        ));
    }

    #[tokio::test]
    async fn signed_evidence_verifies_exact_candidate_and_rejects_tampering() {
        let fake = InMemoryRunmillGateway::default();
        let asf_signer = Ed25519Signer::generate("asf-test");
        let initial = signed_work_order("dispatch-evidence", "change it");
        let order = SignedWorkOrder::sign(initial.payload, &asf_signer).unwrap();
        let request = SubmitWorkOrderRequest::new(order).unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();
        let worker = fake.declared_capabilities();
        let unsigned = signed_evidence(
            &request,
            &receipt,
            worker.worker_id,
            worker.worker_generation,
        )
        .payload;
        let worker_signer = Ed25519Signer::generate("worker-test");
        let signed = SignedEvidenceBundle::sign(unsigned, &worker_signer).unwrap();
        let asf_key = asf_signer.verifying_key();
        let worker_key = worker_signer.verifying_key();
        let local_checks = BTreeSet::from(["test".into()]);
        let remote_checks = BTreeSet::from(["ci".into()]);
        let candidate_sha = signed.payload.candidate_sha.clone();
        let independent_pr = signed
            .payload
            .pull_request
            .as_ref()
            .expect("fixture has pull-request evidence")
            .clone();
        let expectation = EvidenceExpectation {
            asf_work_order_key: &asf_key,
            asf_work_order_key_id: "asf-test",
            worker_key_id: "worker-test",
            work_item_id: request.work_order.payload.work_item_id,
            attempt_id: receipt.attempt_id,
            run_id: receipt.run_id,
            worker_id: worker.worker_id,
            work_order_digest: &receipt.work_order_digest,
            repository: "acme/app",
            base_sha: &request.work_order.payload.repository.base_sha,
            candidate_sha: &candidate_sha,
            target: ClosureTarget::PullRequest,
            required_local_checks: &local_checks,
            required_ci_contexts: &remote_checks,
            current_worker_generation: worker.worker_generation,
            independently_observed_pull_request: Some(&independent_pr),
        };
        signed.verify(&worker_key, &expectation).unwrap();

        let mut tampered = signed.clone();
        tampered.payload.remote_head_sha = "1111111111111111111111111111111111111111".into();
        assert!(tampered.verify(&worker_key, &expectation).is_err());
    }

    #[tokio::test]
    async fn v1_operations_count_is_exactly_six() {
        use crate::ports::runmill::RunmillOperation;
        assert_eq!(RunmillOperation::all().len(), 6);
    }

    #[tokio::test]
    async fn v2_capability_negotiation_requires_both_lookup_schemas() {
        use crate::ports::runmill::{
            CapabilityNegotiationRequestV2, LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1,
        };

        let request = CapabilityNegotiationRequestV2::asf_v2();
        assert!(request.validate().is_ok());
        assert!(
            request
                .supported_lookup_schemas
                .contains(LOOKUP_QUALIFIED_SUBMISSION_REQUEST_SCHEMA_V1)
        );

        let mut malformed = request.clone();
        malformed.supported_lookup_schemas.clear();
        assert!(malformed.validate().is_err());
    }

    #[tokio::test]
    async fn v2_capabilities_satisfy_negotiation_request() {
        use crate::ports::runmill::CapabilityNegotiationRequestV2;

        let fake = InMemoryRunmillGateway::default();
        let request = CapabilityNegotiationRequestV2::asf_v2();
        let caps = fake.negotiate_v2(&request).await.unwrap();
        assert!(caps.satisfy(&request).is_ok());
    }

    #[tokio::test]
    async fn lookup_qualified_submission_exact_match_returns_found() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("lookup-test-1", "change it")).unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        match &result.outcome {
            LookupQualifiedSubmissionOutcome::Found(found) => {
                assert_eq!(found.qualification, qualification);
                assert_eq!(found.run.run_id, receipt.run_id);
            }
            LookupQualifiedSubmissionOutcome::NotFound => panic!("expected Found"),
        }

        assert_eq!(fake.run_count().await, 1);
    }

    #[tokio::test]
    async fn lookup_qualified_submission_returns_not_found_for_mismatched_identity() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("lookup-test-2", "change it")).unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let mut qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        qualification.idempotency_key = "different-key".into();
        let lookup = LookupQualifiedSubmissionRequest::new(qualification).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        match result.outcome {
            LookupQualifiedSubmissionOutcome::NotFound => {}
            LookupQualifiedSubmissionOutcome::Found(_) => panic!("expected NotFound"),
        }
    }

    #[tokio::test]
    async fn lookup_qualified_submission_validates_receipt_against_request() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("lookup-test-3", "change it")).unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        assert!(result.validate_against(&lookup).is_ok());

        let mut invalid_receipt = result.clone();
        if let LookupQualifiedSubmissionOutcome::Found(ref mut found) = invalid_receipt.outcome {
            found.qualification.idempotency_key = "tampered".into();
        }
        assert!(invalid_receipt.validate_against(&lookup).is_err());
    }

    #[tokio::test]
    async fn mcp_adapter_returns_unsupported_for_v2_operations() {
        use crate::ports::runmill::CapabilityNegotiationRequestV2;

        let adapter = RunmillMcpAdapter;
        let request = CapabilityNegotiationRequestV2::asf_v2();
        let error = adapter.negotiate_v2(&request).await.unwrap_err();
        assert!(matches!(
            error,
            RunmillGatewayError::UnsupportedContract { .. }
        ));
    }

    #[tokio::test]
    async fn identity_validate_rejects_blank_idempotency_key() {
        use crate::ports::runmill::QualifiedSubmissionIdentityV1;

        let tenant_id = TenantId::new();
        let work_order_id = WorkOrderId::new();
        let work_item_id = uuid::Uuid::new_v4();
        let attempt_id = AttemptId::new();

        let mut identity = QualifiedSubmissionIdentityV1 {
            tenant_id,
            work_order_id,
            work_item_id: WorkItemId::from_uuid(work_item_id),
            attempt_id,
            idempotency_key: "valid-key".into(),
            work_order_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            request_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
        };

        assert!(identity.validate().is_ok());

        identity.idempotency_key = "   ".into();
        assert!(identity.validate().is_err());

        identity.idempotency_key = String::new();
        assert!(identity.validate().is_err());
    }

    #[tokio::test]
    async fn identity_validate_rejects_non_hex_digest() {
        use crate::ports::runmill::QualifiedSubmissionIdentityV1;

        let tenant_id = TenantId::new();
        let work_order_id = WorkOrderId::new();
        let work_item_id = WorkItemId::new();
        let attempt_id = AttemptId::new();

        let identity = QualifiedSubmissionIdentityV1 {
            tenant_id,
            work_order_id,
            work_item_id,
            attempt_id,
            idempotency_key: "valid-key".into(),
            work_order_digest:
                "sha256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".into(),
            request_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
        };

        assert!(identity.validate().is_err());

        let identity2 = QualifiedSubmissionIdentityV1 {
            tenant_id,
            work_order_id,
            work_item_id,
            attempt_id,
            idempotency_key: "valid-key".into(),
            work_order_digest: "sha256:1234567890abcdef".into(),
            request_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
        };

        assert!(identity2.validate().is_err());
    }

    #[tokio::test]
    async fn derived_identity_exactly_matches_signed_payload() {
        use crate::ports::runmill::QualifiedSubmissionIdentityV1;

        let request =
            SubmitWorkOrderRequest::new(signed_work_order("derived-match", "change it")).unwrap();

        let derived =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        assert_eq!(derived.tenant_id, request.work_order.payload.tenant_id);
        assert_eq!(
            derived.work_order_id,
            request.work_order.payload.work_order_id
        );
        assert_eq!(
            derived.work_item_id,
            request.work_order.payload.work_item_id
        );
        assert_eq!(derived.attempt_id, request.work_order.payload.attempt_id);
        assert_eq!(derived.idempotency_key, request.idempotency_key);
        assert_eq!(derived.work_order_digest, request.work_order_digest);
        assert!(!derived.request_digest.is_empty());
        let canonical = canonical_json(&request.work_order).unwrap();
        assert_eq!(derived.request_digest, sha256_digest(&canonical));
    }

    #[tokio::test]
    async fn identity_from_request_validates_all_required_fields() {
        use crate::ports::runmill::QualifiedSubmissionIdentityV1;

        let request =
            SubmitWorkOrderRequest::new(signed_work_order("all-fields", "change it")).unwrap();

        let identity =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        assert!(!identity.tenant_id.as_uuid().is_nil());
        assert!(!identity.work_order_id.as_uuid().is_nil());
        assert!(!identity.work_item_id.as_uuid().is_nil());
        assert!(!identity.attempt_id.as_uuid().is_nil());
        assert!(!identity.idempotency_key.is_empty());
        assert!(!identity.request_digest.is_empty());
    }

    #[tokio::test]
    async fn identity_validate_rejects_malformed_request_digest() {
        use crate::ports::runmill::QualifiedSubmissionIdentityV1;

        let tenant_id = TenantId::new();
        let work_order_id = WorkOrderId::new();
        let work_item_id = WorkItemId::new();
        let attempt_id = AttemptId::new();

        let mut identity = QualifiedSubmissionIdentityV1 {
            tenant_id,
            work_order_id,
            work_item_id,
            attempt_id,
            idempotency_key: "valid-key".into(),
            work_order_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            request_digest:
                "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
        };

        assert!(identity.validate().is_ok());

        identity.request_digest =
            "sha256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".into();
        assert!(identity.validate().is_err());

        identity.request_digest = "sha256:tooshort".into();
        assert!(identity.validate().is_err());

        identity.request_digest = String::new();
        assert!(identity.validate().is_err());
    }

    #[tokio::test]
    async fn lookup_qualified_submission_rejects_mismatched_request_digest() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
            QualifiedSubmissionIdentityV1,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("lookup-digest-test", "change it"))
                .unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let mut qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let original_digest = qualification.request_digest.clone();
        qualification.request_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        match result.outcome {
            LookupQualifiedSubmissionOutcome::NotFound => {}
            LookupQualifiedSubmissionOutcome::Found(_) => {
                panic!("expected NotFound for mismatched digest")
            }
        }

        qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();
        assert_eq!(qualification.request_digest, original_digest);
    }

    #[tokio::test]
    async fn lookup_receipt_binds_request_digest() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("receipt-binding", "change it")).unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        match &result.outcome {
            LookupQualifiedSubmissionOutcome::Found(found) => {
                assert_eq!(
                    found.qualification.request_digest,
                    qualification.request_digest
                );
                assert_eq!(found.run.run_id, receipt.run_id);
                assert_eq!(found.qualification.idempotency_key, receipt.idempotency_key);
            }
            LookupQualifiedSubmissionOutcome::NotFound => {
                panic!("expected Found with matching request_digest")
            }
        }
    }

    #[tokio::test]
    async fn lookup_receipt_rejects_mismatched_admission_worker_id() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("worker-id-test", "change it")).unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        assert!(result.validate_against(&lookup).is_ok());

        let mut invalid_receipt = result.clone();
        if let LookupQualifiedSubmissionOutcome::Found(ref mut found) = invalid_receipt.outcome {
            found.admission_worker.worker_id = WorkerId::new();
        }
        assert!(invalid_receipt.validate_against(&lookup).is_err());
    }

    #[tokio::test]
    async fn lookup_receipt_rejects_mismatched_admission_worker_generation() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("worker-gen-test", "change it")).unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        assert!(result.validate_against(&lookup).is_ok());

        let mut invalid_receipt = result.clone();
        if let LookupQualifiedSubmissionOutcome::Found(ref mut found) = invalid_receipt.outcome {
            found.admission_worker.worker_generation = 999;
        }
        assert!(invalid_receipt.validate_against(&lookup).is_err());
    }

    #[tokio::test]
    async fn lookup_receipt_rejects_zero_worker_generation() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("worker-gen-zero", "change it")).unwrap();
        let _receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        assert!(result.validate_against(&lookup).is_ok());

        let mut invalid_receipt = result.clone();
        if let LookupQualifiedSubmissionOutcome::Found(ref mut found) = invalid_receipt.outcome {
            found.admission_worker.worker_generation = 0;
        }
        assert!(invalid_receipt.validate_against(&lookup).is_err());
    }

    #[tokio::test]
    async fn lookup_receipt_admission_worker_exactly_matches_run_snapshot() {
        use crate::ports::runmill::{
            LookupQualifiedSubmissionOutcome, LookupQualifiedSubmissionRequest,
        };

        let fake = InMemoryRunmillGateway::default();
        let request =
            SubmitWorkOrderRequest::new(signed_work_order("worker-snapshot-match", "change it"))
                .unwrap();
        let receipt = fake.submit_work_order(&request).await.unwrap();

        let qualification =
            QualifiedSubmissionIdentityV1::from_submit_work_order_request(&request).unwrap();

        let lookup = LookupQualifiedSubmissionRequest::new(qualification.clone()).unwrap();
        let result = fake.lookup_qualified_submission(&lookup).await.unwrap();

        match &result.outcome {
            LookupQualifiedSubmissionOutcome::Found(found) => {
                assert_eq!(
                    found.admission_worker.worker_id, found.run.worker_id,
                    "admission worker ID must match run worker ID"
                );
                assert_eq!(
                    found.admission_worker.worker_generation, found.run.worker_generation,
                    "admission worker generation must match run worker generation"
                );
                assert_eq!(found.run.run_id, receipt.run_id);
            }
            LookupQualifiedSubmissionOutcome::NotFound => {
                panic!("expected Found with matching worker proof")
            }
        }
    }
}
