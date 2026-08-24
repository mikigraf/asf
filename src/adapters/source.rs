use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    domain::{SourceSnapshot, SourceSystem, TenantId},
    ports::source::{
        CloseSourceRequest, ObserveSourceRequest, ReconcileSourceCloseRequest,
        SOURCE_CLOSE_RECEIPT_SCHEMA_V1, SOURCE_INTAKE_PAGE_SCHEMA_V1, SOURCE_OBSERVATION_SCHEMA_V1,
        SourceCloseDisposition, SourceCloseEffect, SourceCloseReceipt, SourceCloseReconciliation,
        SourceCursor, SourceGateway, SourceGatewayError, SourceIntakePage, SourceIntakeRequest,
        SourceItemRef, SourceLifecycle, SourceObservation, SourceResult,
    },
};

// Preserve the original adapter module path while the production implementation
// lives in its own provider-specific module.
pub use super::linear::{
    LinearApiAdapter, LinearApiConfig, LinearAuthentication, LinearTeamMapping,
};

#[derive(Debug, Clone)]
struct LinearItemRecord {
    history: Vec<SourceSnapshot>,
    current: SourceSnapshot,
    lifecycle: SourceLifecycle,
    applied_closure: Option<SourceCloseReceipt>,
}

#[derive(Debug, Clone)]
struct CloseRecord {
    effect: SourceCloseEffect,
    receipt: SourceCloseReceipt,
}

#[derive(Debug, Default)]
struct LinearFakeState {
    items: BTreeMap<(TenantId, String), LinearItemRecord>,
    closes_by_idempotency_key: BTreeMap<String, CloseRecord>,
    idempotency_key_by_marker: BTreeMap<String, String>,
    logical_close_effects: BTreeMap<(TenantId, String), u64>,
    lose_next_close_response: bool,
}

/// Deterministic in-memory Linear adapter for workflow and failure-injection
/// tests. Callers provide immutable normalized snapshots and timestamps; the
/// fake never reads a wall clock.
#[derive(Debug, Clone, Default)]
pub struct InMemoryLinearGateway {
    state: Arc<Mutex<LinearFakeState>>,
}

impl InMemoryLinearGateway {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Make a normalized Linear snapshot the current external revision.
    /// Earlier revisions remain in the fake's immutable history.
    pub async fn upsert_snapshot(&self, snapshot: SourceSnapshot) -> SourceResult<()> {
        validate_linear_snapshot(&snapshot)?;
        let key = snapshot_key(&snapshot);
        let mut state = self.state.lock().await;
        match state.items.get_mut(&key) {
            None => {
                state.items.insert(
                    key,
                    LinearItemRecord {
                        history: Vec::new(),
                        current: snapshot,
                        lifecycle: SourceLifecycle::Active,
                        applied_closure: None,
                    },
                );
            }
            Some(record)
                if record.current.content.source_revision == snapshot.content.source_revision =>
            {
                if record.current.content_digest != snapshot.content_digest {
                    return Err(SourceGatewayError::SourceStateConflict);
                }
            }
            Some(record) => {
                if record.applied_closure.is_some() {
                    return Err(SourceGatewayError::SourceStateConflict);
                }
                record.history.push(record.current.clone());
                record.current = snapshot;
                record.lifecycle = SourceLifecycle::Active;
            }
        }
        Ok(())
    }

    /// Inject one timeout after, rather than before, the next new close effect.
    /// The applied provider state and idempotency record are retained.
    pub async fn lose_next_close_response(&self) {
        self.state.lock().await.lose_next_close_response = true;
    }

    #[must_use]
    pub async fn logical_close_effect_count(&self, item: &SourceItemRef) -> u64 {
        self.state
            .lock()
            .await
            .logical_close_effects
            .get(&(item.tenant_id, item.external_id.clone()))
            .copied()
            .unwrap_or(0)
    }

    #[must_use]
    pub async fn snapshot_history(&self, item: &SourceItemRef) -> Vec<SourceSnapshot> {
        self.state
            .lock()
            .await
            .items
            .get(&(item.tenant_id, item.external_id.clone()))
            .map_or_else(Vec::new, |record| {
                let mut snapshots = record.history.clone();
                snapshots.push(record.current.clone());
                snapshots
            })
    }
}

#[async_trait]
impl SourceGateway for InMemoryLinearGateway {
    async fn intake(&self, request: &SourceIntakeRequest) -> SourceResult<SourceIntakePage> {
        request.validate()?;
        let state = self.state.lock().await;
        let snapshots: Vec<SourceSnapshot> = state
            .items
            .iter()
            .filter(|((tenant_id, _), record)| {
                *tenant_id == request.tenant_id
                    && record.lifecycle == SourceLifecycle::Active
                    && record
                        .current
                        .content
                        .labels
                        .contains(&request.opt_in_label)
            })
            .map(|(_, record)| record.current.clone())
            .collect();

        let offset = request.after.as_ref().map_or(Ok(0), |cursor| {
            parse_intake_cursor(cursor, request.tenant_id, snapshots.len())
        })?;
        let limit = usize::try_from(request.limit).map_err(|_| {
            SourceGatewayError::InvalidRequest("source page limit cannot fit this platform".into())
        })?;
        let end = offset.saturating_add(limit).min(snapshots.len());
        let has_more = end < snapshots.len();
        let next_cursor = has_more
            .then(|| source_cursor(request.tenant_id, end))
            .transpose()?;

        Ok(SourceIntakePage {
            schema: SOURCE_INTAKE_PAGE_SCHEMA_V1.into(),
            snapshots: snapshots[offset..end].to_vec(),
            next_cursor,
            has_more,
        })
    }

    async fn observe_source(
        &self,
        request: &ObserveSourceRequest,
    ) -> SourceResult<SourceObservation> {
        request.validate()?;
        require_linear(&request.item)?;
        let state = self.state.lock().await;
        let record = state
            .items
            .get(&(request.item.tenant_id, request.item.external_id.clone()))
            .ok_or(SourceGatewayError::ItemNotFound)?;
        let observed_at = record
            .applied_closure
            .as_ref()
            .map_or(record.current.captured_at, |closure| closure.recorded_at);
        Ok(SourceObservation {
            schema: SOURCE_OBSERVATION_SCHEMA_V1.into(),
            item: request.item.clone(),
            lifecycle: record.lifecycle,
            current_snapshot: Some(record.current.clone()),
            applied_closure: record.applied_closure.clone(),
            observed_at,
        })
    }

    async fn close_source(&self, request: &CloseSourceRequest) -> SourceResult<SourceCloseReceipt> {
        request.validate()?;
        require_linear(&request.effect.item)?;
        let mut state = self.state.lock().await;

        if let Some(existing) = state
            .closes_by_idempotency_key
            .get(&request.idempotency_key)
        {
            if existing.receipt.effect_digest != request.effect_digest {
                return Err(idempotency_conflict(
                    &request.idempotency_key,
                    &existing.receipt.effect_digest,
                    &request.effect_digest,
                ));
            }
            if existing.effect != request.effect {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            let mut receipt = existing.receipt.clone();
            receipt.disposition = SourceCloseDisposition::Adopted;
            return Ok(receipt);
        }

        if let Some(existing_key) = state
            .idempotency_key_by_marker
            .get(&request.effect.correlation_marker)
        {
            let existing_digest = state
                .closes_by_idempotency_key
                .get(existing_key)
                .map_or("unknown", |record| record.receipt.effect_digest.as_str());
            return Err(idempotency_conflict(
                &request.idempotency_key,
                existing_digest,
                &request.effect_digest,
            ));
        }

        let key = (
            request.effect.item.tenant_id,
            request.effect.item.external_id.clone(),
        );
        let record = state
            .items
            .get_mut(&key)
            .ok_or(SourceGatewayError::ItemNotFound)?;
        if record.lifecycle != SourceLifecycle::Active
            || record.current.content.source_revision != request.effect.expected_source_revision
            || record.current.content_digest != request.effect.expected_snapshot_digest
        {
            return Err(SourceGatewayError::SourceStateConflict);
        }

        let provider_revision = closed_revision(
            &record.current.content.source_revision,
            &request.effect_digest,
        );
        let mut closed_content = record.current.content.clone();
        closed_content
            .source_revision
            .clone_from(&provider_revision);
        closed_content.source_state = "completed".into();
        closed_content.source_updated_at = request.requested_at;
        let closed_snapshot = SourceSnapshot::create(
            record.current.tenant_id,
            record.current.repository_id,
            closed_content,
            record.current.connector_identity.clone(),
            request.requested_at,
        )
        .map_err(|_| {
            SourceGatewayError::InvalidRequest(
                "normalized closed source snapshot could not be constructed".into(),
            )
        })?;

        let receipt = SourceCloseReceipt {
            schema: SOURCE_CLOSE_RECEIPT_SCHEMA_V1.into(),
            item: request.effect.item.clone(),
            idempotency_key: request.idempotency_key.clone(),
            effect_digest: request.effect_digest.clone(),
            correlation_marker: request.effect.correlation_marker.clone(),
            disposition: SourceCloseDisposition::Applied,
            provider_revision,
            recorded_at: request.requested_at,
        };

        record.history.push(record.current.clone());
        record.current = closed_snapshot;
        record.lifecycle = SourceLifecycle::Completed;
        record.applied_closure = Some(receipt.clone());
        state
            .logical_close_effects
            .entry(key)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        state.idempotency_key_by_marker.insert(
            request.effect.correlation_marker.clone(),
            request.idempotency_key.clone(),
        );
        state.closes_by_idempotency_key.insert(
            request.idempotency_key.clone(),
            CloseRecord {
                effect: request.effect.clone(),
                receipt: receipt.clone(),
            },
        );

        if state.lose_next_close_response {
            state.lose_next_close_response = false;
            return Err(SourceGatewayError::AmbiguousEffect {
                idempotency_key: request.idempotency_key.clone(),
                effect_digest: request.effect_digest.clone(),
            });
        }
        Ok(receipt)
    }

    async fn reconcile_source_close(
        &self,
        request: &ReconcileSourceCloseRequest,
    ) -> SourceResult<SourceCloseReconciliation> {
        request.validate()?;
        require_linear(&request.item)?;
        let state = self.state.lock().await;
        let Some(existing) = state
            .closes_by_idempotency_key
            .get(&request.idempotency_key)
        else {
            if state
                .idempotency_key_by_marker
                .contains_key(&request.correlation_marker)
            {
                return Err(SourceGatewayError::SourceStateConflict);
            }
            return Ok(SourceCloseReconciliation::NotObserved);
        };
        if existing.receipt.item != request.item
            || existing.receipt.effect_digest != request.effect_digest
            || existing.receipt.correlation_marker != request.correlation_marker
        {
            return Err(idempotency_conflict(
                &request.idempotency_key,
                &existing.receipt.effect_digest,
                &request.effect_digest,
            ));
        }
        let mut receipt = existing.receipt.clone();
        receipt.disposition = SourceCloseDisposition::Reconciled;
        Ok(SourceCloseReconciliation::Applied(receipt))
    }
}

fn validate_linear_snapshot(snapshot: &SourceSnapshot) -> SourceResult<()> {
    snapshot.content.validate().map_err(|_| {
        SourceGatewayError::InvalidRequest("normalized source snapshot is invalid".into())
    })?;
    if snapshot.content.source != SourceSystem::Linear
        || snapshot.connector_identity.trim().is_empty()
        || snapshot.content.digest().map_err(|_| {
            SourceGatewayError::InvalidRequest("source snapshot digest cannot be computed".into())
        })? != snapshot.content_digest
        || snapshot.content.source_url.as_ref().is_some_and(|url| {
            !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
        })
    {
        return Err(SourceGatewayError::InvalidRequest(
            "snapshot is not a safe normalized Linear snapshot".into(),
        ));
    }
    Ok(())
}

fn require_linear(item: &SourceItemRef) -> SourceResult<()> {
    if item.source != SourceSystem::Linear {
        return Err(SourceGatewayError::InvalidRequest(
            "Linear adapter accepts only Linear source items".into(),
        ));
    }
    Ok(())
}

fn snapshot_key(snapshot: &SourceSnapshot) -> (TenantId, String) {
    (snapshot.tenant_id, snapshot.content.external_id.clone())
}

fn source_cursor(tenant_id: TenantId, offset: usize) -> SourceResult<SourceCursor> {
    SourceCursor::from_opaque(format!("linear:v1:{tenant_id}:{offset}"))
}

fn parse_intake_cursor(
    cursor: &SourceCursor,
    tenant_id: TenantId,
    item_count: usize,
) -> SourceResult<usize> {
    let prefix = format!("linear:v1:{tenant_id}:");
    let offset = cursor
        .as_str()
        .strip_prefix(&prefix)
        .ok_or_else(|| {
            SourceGatewayError::InvalidCursor(
                "cursor belongs to another tenant or connector".into(),
            )
        })?
        .parse::<usize>()
        .map_err(|_| SourceGatewayError::InvalidCursor("cursor position is malformed".into()))?;
    if offset > item_count {
        return Err(SourceGatewayError::InvalidCursor(
            "cursor is ahead of the current normalized result set".into(),
        ));
    }
    Ok(offset)
}

fn closed_revision(source_revision: &str, effect_digest: &str) -> String {
    let suffix: String = effect_digest
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .collect();
    format!("{source_revision}+asf-close-{suffix}")
}

fn idempotency_conflict(
    idempotency_key: &str,
    existing_digest: &str,
    submitted_digest: &str,
) -> SourceGatewayError {
    SourceGatewayError::IdempotencyConflict {
        idempotency_key: idempotency_key.into(),
        existing_digest: existing_digest.into(),
        submitted_digest: submitted_digest.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{TimeZone, Utc};
    use url::Url;

    use crate::{
        contracts::PullRequestEvidence,
        domain::{
            ClosureTarget, EvidenceId, SourceSnapshot, SourceSnapshotContent, TenantId, WorkItemId,
        },
        ports::source::{
            CloseSourceRequest, ObserveSourceRequest, ReconcileSourceCloseRequest,
            SourceCloseDisposition, SourceCloseEffect, SourceCloseReconciliation, SourceClosure,
            SourceGateway, SourceGatewayError, SourceIntakeRequest, SourceItemRef,
        },
    };

    use super::InMemoryLinearGateway;

    fn timestamp(minute: u32) -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 21, 10, minute, 0)
            .single()
            .unwrap()
    }

    fn snapshot(
        tenant_id: TenantId,
        external_id: &str,
        revision: &str,
        title: &str,
        opted_in: bool,
        captured_minute: u32,
    ) -> SourceSnapshot {
        let mut labels = BTreeSet::new();
        if opted_in {
            labels.insert("asf-ready".into());
        }
        SourceSnapshot::create(
            tenant_id,
            None,
            SourceSnapshotContent {
                source: crate::domain::SourceSystem::Linear,
                external_id: external_id.into(),
                source_revision: revision.into(),
                source_url: Some(
                    Url::parse(&format!("https://linear.test/issue/{external_id}")).unwrap(),
                ),
                title: title.into(),
                objective: "make the requested verified change".into(),
                acceptance_criteria: vec!["required tests pass".into()],
                non_goals: vec!["do not deploy".into()],
                labels,
                normalized_priority: 50,
                source_state: "started".into(),
                assignee: Some("team-platform".into()),
                repository_hint: Some("acme/app".into()),
                source_updated_at: timestamp(captured_minute),
            },
            "linear:fixture-connector".into(),
            timestamp(captured_minute),
        )
        .unwrap()
    }

    fn source_ref(snapshot: &SourceSnapshot) -> SourceItemRef {
        SourceItemRef {
            tenant_id: snapshot.tenant_id,
            source: snapshot.content.source,
            external_id: snapshot.content.external_id.clone(),
        }
    }

    fn close_request(snapshot: &SourceSnapshot, key: &str, summary: &str) -> CloseSourceRequest {
        let candidate = "candidate-sha".to_owned();
        let closure = SourceClosure {
            work_item_id: WorkItemId::new(),
            target: ClosureTarget::PullRequest,
            pull_request: Some(PullRequestEvidence {
                repository: "acme/app".into(),
                number: 7,
                url: "https://github.test/acme/app/pull/7".into(),
                base_sha: "base-sha".into(),
                head_sha: candidate,
                required_ci_contexts: BTreeSet::from(["ci".into()]),
                successful_ci_contexts: BTreeSet::from(["ci".into()]),
            }),
            evidence_id: EvidenceId::new(),
            evidence_digest: "sha256:evidence".into(),
            final_outcome_summary: summary.into(),
            cost_microunits: Some(100),
            wall_time_seconds: Some(30),
        };
        let effect = SourceCloseEffect::new(
            source_ref(snapshot),
            snapshot.content.source_revision.clone(),
            snapshot.content_digest.clone(),
            format!("asf-close:{key}"),
            closure,
        )
        .unwrap();
        CloseSourceRequest::new(key, effect, timestamp(30)).unwrap()
    }

    #[tokio::test]
    async fn intake_returns_only_opted_in_normalized_snapshots_and_keeps_history_immutable() {
        let tenant = TenantId::new();
        let fake = InMemoryLinearGateway::new();
        let first_revision = snapshot(tenant, "ASF-1", "1", "Original", true, 1);
        let ignored = snapshot(tenant, "ASF-2", "1", "Not opted in", false, 2);
        fake.upsert_snapshot(first_revision.clone()).await.unwrap();
        fake.upsert_snapshot(ignored).await.unwrap();

        let request = SourceIntakeRequest::first_page(tenant, "asf-ready", 10);
        let first_page = fake.intake(&request).await.unwrap();
        assert_eq!(first_page.snapshots, vec![first_revision.clone()]);
        assert!(!first_page.has_more);

        let changed = snapshot(tenant, "ASF-1", "2", "Revised", true, 3);
        fake.upsert_snapshot(changed.clone()).await.unwrap();
        let next_page = fake.intake(&request).await.unwrap();
        assert_eq!(next_page.snapshots, vec![changed]);
        assert_eq!(first_page.snapshots[0], first_revision);
        let history = fake.snapshot_history(&source_ref(&first_revision)).await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].content.title, "Original");
        assert_eq!(history[1].content.title, "Revised");
    }

    #[tokio::test]
    async fn applied_but_response_lost_reconciles_to_one_logical_source_effect() {
        let tenant = TenantId::new();
        let fake = InMemoryLinearGateway::new();
        let snapshot = snapshot(tenant, "ASF-1", "1", "Close me", true, 1);
        let item = source_ref(&snapshot);
        fake.upsert_snapshot(snapshot.clone()).await.unwrap();
        let request = close_request(&snapshot, "source-close-1", "verified PR delivered");

        fake.lose_next_close_response().await;
        let error = fake.close_source(&request).await.unwrap_err();
        assert!(matches!(error, SourceGatewayError::AmbiguousEffect { .. }));

        let observation = fake
            .observe_source(&ObserveSourceRequest::new(item.clone()))
            .await
            .unwrap();
        assert_eq!(
            observation.lifecycle,
            crate::ports::source::SourceLifecycle::Completed
        );
        assert_eq!(
            observation
                .applied_closure
                .as_ref()
                .map(|receipt| receipt.effect_digest.as_str()),
            Some(request.effect_digest.as_str())
        );

        let reconciliation = fake
            .reconcile_source_close(&ReconcileSourceCloseRequest::from_close(&request))
            .await
            .unwrap();
        let SourceCloseReconciliation::Applied(reconciled) = reconciliation else {
            panic!("the applied effect must be found by reconciliation")
        };
        assert_eq!(reconciled.disposition, SourceCloseDisposition::Reconciled);

        let adopted = fake.close_source(&request).await.unwrap();
        assert_eq!(adopted.disposition, SourceCloseDisposition::Adopted);
        assert_eq!(fake.logical_close_effect_count(&item).await, 1);
        assert_eq!(fake.snapshot_history(&item).await.len(), 2);
    }

    #[tokio::test]
    async fn reused_source_idempotency_key_with_changed_effect_conflicts() {
        let tenant = TenantId::new();
        let fake = InMemoryLinearGateway::new();
        let snapshot = snapshot(tenant, "ASF-1", "1", "Close me", true, 1);
        let item = source_ref(&snapshot);
        fake.upsert_snapshot(snapshot.clone()).await.unwrap();
        let first = close_request(&snapshot, "source-close-1", "first outcome");
        fake.close_source(&first).await.unwrap();
        let changed = close_request(&snapshot, "source-close-1", "different outcome");
        assert!(matches!(
            fake.close_source(&changed).await.unwrap_err(),
            SourceGatewayError::IdempotencyConflict { .. }
        ));
        assert_eq!(fake.logical_close_effect_count(&item).await, 1);
    }
}
