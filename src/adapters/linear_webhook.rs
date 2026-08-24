//! Authentication and normalization for Linear issue webhook deliveries.
//!
//! Signature verification is deliberately performed against the exact raw
//! request body before JSON parsing. The verified delivery ID is the stable
//! key callers must persist before enqueueing intake reconciliation work.

use std::{fmt, time::Duration};

use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use thiserror::Error;
use uuid::{Uuid, Version};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONFIGURED_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_TIMESTAMP_SKEW: Duration = Duration::from_mins(1);

type HmacSha256 = Hmac<Sha256>;

/// Linear headers and exact bytes received by the HTTP ingress layer.
#[derive(Clone, Copy)]
pub struct LinearWebhookRequest<'a> {
    pub delivery: &'a str,
    pub event: &'a str,
    pub signature: &'a str,
    pub timestamp: &'a str,
    pub raw_body: &'a [u8],
}

impl fmt::Debug for LinearWebhookRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearWebhookRequest")
            .field("delivery", &self.delivery)
            .field("event", &self.event)
            .field("signature", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("raw_body_bytes", &self.raw_body.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearWebhookAction {
    Create,
    Update,
    Remove,
}

/// Credential-free, authenticated information safe to hand to intake logic.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedLinearIssueDelivery {
    pub delivery_id: Uuid,
    pub action: LinearWebhookAction,
    pub issue_id: String,
    pub created_at: DateTime<Utc>,
    pub webhook_timestamp: DateTime<Utc>,
    pub data: Value,
    pub updated_from: Option<Value>,
}

#[derive(Clone)]
pub struct LinearWebhookVerifier {
    signing_secret: SecretString,
    max_timestamp_skew: Duration,
    max_body_bytes: usize,
}

impl fmt::Debug for LinearWebhookVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinearWebhookVerifier")
            .field("signing_secret", &"[REDACTED]")
            .field("max_timestamp_skew", &self.max_timestamp_skew)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

impl LinearWebhookVerifier {
    /// Construct the verifier with Linear's recommended one-minute replay
    /// window and a bounded one-megabyte body.
    pub fn new(signing_secret: SecretString) -> Result<Self, LinearWebhookError> {
        Self::with_limits(
            signing_secret,
            DEFAULT_MAX_TIMESTAMP_SKEW,
            DEFAULT_MAX_BODY_BYTES,
        )
    }

    pub fn with_limits(
        signing_secret: SecretString,
        max_timestamp_skew: Duration,
        max_body_bytes: usize,
    ) -> Result<Self, LinearWebhookError> {
        if signing_secret.expose_secret().is_empty() {
            return Err(LinearWebhookError::InvalidConfiguration(
                "webhook signing secret must be non-empty".into(),
            ));
        }
        if max_timestamp_skew < Duration::from_secs(1)
            || max_timestamp_skew > Duration::from_mins(5)
        {
            return Err(LinearWebhookError::InvalidConfiguration(
                "webhook timestamp skew must be within 1 second and 5 minutes".into(),
            ));
        }
        if !(1..=MAX_CONFIGURED_BODY_BYTES).contains(&max_body_bytes) {
            return Err(LinearWebhookError::InvalidConfiguration(format!(
                "webhook body limit must be within 1..={MAX_CONFIGURED_BODY_BYTES} bytes"
            )));
        }
        Ok(Self {
            signing_secret,
            max_timestamp_skew,
            max_body_bytes,
        })
    }

    /// Authenticate and normalize one Linear `Issue` delivery.
    ///
    /// The raw body is authenticated before it is parsed. Callers must claim
    /// `delivery_id` in durable, tenant-scoped idempotency storage before
    /// applying or enqueueing the event.
    pub fn verify_at(
        &self,
        request: LinearWebhookRequest<'_>,
        now: DateTime<Utc>,
    ) -> Result<VerifiedLinearIssueDelivery, LinearWebhookError> {
        if request.raw_body.len() > self.max_body_bytes {
            return Err(LinearWebhookError::BodyTooLarge);
        }
        verify_signature(
            self.signing_secret.expose_secret().as_bytes(),
            request.raw_body,
            request.signature,
        )?;

        let payload: LinearWebhookPayload = serde_json::from_slice(request.raw_body)
            .map_err(|_| LinearWebhookError::InvalidPayload)?;
        let delivery_id = parse_delivery_id(request.delivery)?;
        if request.event != "Issue" || payload.event_type != "Issue" {
            return Err(LinearWebhookError::UnsupportedEvent);
        }
        let header_timestamp = request
            .timestamp
            .parse::<i64>()
            .map_err(|_| LinearWebhookError::InvalidTimestamp)?;
        if header_timestamp != payload.webhook_timestamp {
            return Err(LinearWebhookError::InvalidTimestamp);
        }
        let webhook_timestamp = DateTime::from_timestamp_millis(payload.webhook_timestamp)
            .ok_or(LinearWebhookError::InvalidTimestamp)?;
        let allowed_skew = TimeDelta::from_std(self.max_timestamp_skew)
            .map_err(|_| LinearWebhookError::InvalidTimestamp)?;
        if now.signed_duration_since(webhook_timestamp).abs() > allowed_skew {
            return Err(LinearWebhookError::StaleDelivery);
        }
        if !payload.data.is_object()
            || payload
                .updated_from
                .as_ref()
                .is_some_and(|value| !value.is_object())
        {
            return Err(LinearWebhookError::InvalidPayload);
        }
        let issue_id = payload
            .data
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or(LinearWebhookError::InvalidPayload)?
            .to_owned();

        Ok(VerifiedLinearIssueDelivery {
            delivery_id,
            action: payload.action,
            issue_id,
            created_at: payload.created_at,
            webhook_timestamp,
            data: payload.data,
            updated_from: payload.updated_from,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinearWebhookPayload {
    action: LinearWebhookAction,
    #[serde(rename = "type")]
    event_type: String,
    created_at: DateTime<Utc>,
    webhook_timestamp: i64,
    data: Value,
    updated_from: Option<Value>,
}

impl<'de> Deserialize<'de> for LinearWebhookAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "create" => Ok(Self::Create),
            "update" => Ok(Self::Update),
            "remove" => Ok(Self::Remove),
            _ => Err(serde::de::Error::custom("unsupported Linear action")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LinearWebhookError {
    #[error("invalid Linear webhook verifier configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Linear webhook body exceeds the configured limit")]
    BodyTooLarge,
    #[error("Linear webhook signature is invalid")]
    InvalidSignature,
    #[error("Linear webhook timestamp is invalid")]
    InvalidTimestamp,
    #[error("Linear webhook is outside the permitted replay window")]
    StaleDelivery,
    #[error("Linear webhook delivery identity is invalid")]
    InvalidDelivery,
    #[error("Linear webhook event is not supported by the V1 intake connector")]
    UnsupportedEvent,
    #[error("Linear webhook payload is invalid")]
    InvalidPayload,
}

fn verify_signature(secret: &[u8], body: &[u8], signature: &str) -> Result<(), LinearWebhookError> {
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LinearWebhookError::InvalidSignature);
    }
    let supplied = hex::decode(signature).map_err(|_| LinearWebhookError::InvalidSignature)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|_| LinearWebhookError::InvalidConfiguration("invalid signing secret".into()))?;
    mac.update(body);
    let expected = mac.finalize().into_bytes();
    if bool::from(expected.as_slice().ct_eq(supplied.as_slice())) {
        Ok(())
    } else {
        Err(LinearWebhookError::InvalidSignature)
    }
}

fn parse_delivery_id(value: &str) -> Result<Uuid, LinearWebhookError> {
    let delivery_id = Uuid::parse_str(value).map_err(|_| LinearWebhookError::InvalidDelivery)?;
    if delivery_id.get_version() == Some(Version::Random) {
        Ok(delivery_id)
    } else {
        Err(LinearWebhookError::InvalidDelivery)
    }
}

#[cfg(test)]
mod tests {
    use chrono::SubsecRound as _;

    use hmac::Mac as _;
    use serde_json::json;

    use super::*;

    const SECRET: &str = "fixture-linear-webhook-secret";

    fn millisecond_now() -> DateTime<Utc> {
        DateTime::from_timestamp_millis(Utc::now().trunc_subsecs(6).timestamp_millis())
            .expect("current timestamp fits")
    }

    fn body(at: DateTime<Utc>) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "action": "update",
            "type": "Issue",
            "createdAt": at,
            "webhookTimestamp": at.timestamp_millis(),
            "data": {"id": "55acfe8c-1800-4b87-b2ac-a2b0262d1190", "title": "ship ASF"},
            "updatedFrom": {"title": "draft ASF"}
        }))
        .expect("serialize webhook fixture")
    }

    fn signature(body: &[u8]) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(SECRET.as_bytes())
            .expect("fixture secret is valid");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn request<'a>(
        body: &'a [u8],
        signature: &'a str,
        timestamp: &'a str,
    ) -> LinearWebhookRequest<'a> {
        LinearWebhookRequest {
            delivery: "234d1a4e-b617-4388-90fe-adc3633d6b72",
            event: "Issue",
            signature,
            timestamp,
            raw_body: body,
        }
    }

    #[test]
    fn verifies_exact_raw_body_and_returns_idempotent_delivery_identity() {
        let now = millisecond_now();
        let body = body(now);
        let signature = signature(&body);
        let timestamp = now.timestamp_millis().to_string();
        let verifier =
            LinearWebhookVerifier::new(SecretString::from(SECRET)).expect("construct verifier");
        let delivery = verifier
            .verify_at(request(&body, &signature, &timestamp), now)
            .expect("verify signed delivery");
        assert_eq!(delivery.action, LinearWebhookAction::Update);
        assert_eq!(delivery.issue_id, "55acfe8c-1800-4b87-b2ac-a2b0262d1190");
        assert_eq!(delivery.webhook_timestamp, now);

        let mut changed = body.clone();
        changed.push(b' ');
        assert_eq!(
            verifier.verify_at(request(&changed, &signature, &timestamp), now),
            Err(LinearWebhookError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_replay_and_future_delivery_outside_the_window() {
        let now = millisecond_now();
        let verifier =
            LinearWebhookVerifier::new(SecretString::from(SECRET)).expect("construct verifier");
        for sent_at in [now - TimeDelta::seconds(61), now + TimeDelta::seconds(61)] {
            let body = body(sent_at);
            let signature = signature(&body);
            let timestamp = sent_at.timestamp_millis().to_string();
            assert_eq!(
                verifier.verify_at(request(&body, &signature, &timestamp), now),
                Err(LinearWebhookError::StaleDelivery)
            );
        }
    }

    #[test]
    fn authenticates_before_parsing_and_never_debugs_secrets() {
        let verifier =
            LinearWebhookVerifier::new(SecretString::from(SECRET)).expect("construct verifier");
        let malformed = b"{";
        let invalid_signature = "0".repeat(64);
        assert_eq!(
            verifier.verify_at(
                LinearWebhookRequest {
                    delivery: "234d1a4e-b617-4388-90fe-adc3633d6b72",
                    event: "Issue",
                    signature: &invalid_signature,
                    timestamp: "0",
                    raw_body: malformed,
                },
                Utc::now().trunc_subsecs(6),
            ),
            Err(LinearWebhookError::InvalidSignature)
        );
        let debug = format!("{verifier:?}");
        assert!(!debug.contains(SECRET));
        assert!(debug.contains("[REDACTED]"));
    }
}
