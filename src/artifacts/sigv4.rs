//! AWS Signature Version 4 request signing, reduced to what artifact storage
//! needs.
//!
//! ASF signs exactly two shapes of request — a single-shot `PUT` and a
//! single-shot `GET` of one content-addressed object — so this implementation
//! deliberately supports only that: no chunked payloads, no presigned URLs, no
//! query-string signing. Every request carries the SHA-256 of its own payload,
//! so a proxy cannot substitute bytes without invalidating the signature.
//!
//! The algorithm is a fixed, published construction. It is implemented here
//! against the crate's existing HMAC and SHA-256 primitives rather than pulled
//! in as a vendor SDK, so the exact bytes that get signed stay readable and
//! testable beside everything else ASF signs.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub(super) const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const TERMINATOR: &str = "aws4_request";

type HmacSha256 = Hmac<Sha256>;

/// One signing identity for one S3-compatible endpoint.
///
/// The secret is held as a [`SecretString`] and never rendered: a credential
/// that reaches a log or an evidence document is a credential that has to be
/// rotated.
#[derive(Clone)]
pub(super) struct SigningIdentity {
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    pub region: String,
    pub service: String,
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SigningIdentity")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("region", &self.region)
            .field("service", &self.service)
            .finish()
    }
}

/// The exact request being signed. Headers are supplied already lowercased by
/// the caller; every one of them is signed, so nothing that reaches the wire is
/// outside the signature.
#[derive(Debug, Clone)]
pub(super) struct CanonicalRequest<'a> {
    pub method: &'a str,
    /// Absolute path, already percent-encoded as it will appear on the wire.
    pub path: &'a str,
    /// Lowercase header name and value pairs, in any order.
    pub headers: &'a [(String, String)],
    pub payload_sha256: &'a str,
}

/// Sign one request and return its `Authorization` header value.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when the identity is unusable or the HMAC
/// primitive rejects the derived key material.
pub(super) fn authorization_header(
    identity: &SigningIdentity,
    request: &CanonicalRequest<'_>,
    signed_at: DateTime<Utc>,
) -> Result<String> {
    if identity.access_key_id.trim().is_empty()
        || identity.secret_access_key.expose_secret().trim().is_empty()
        || identity.region.trim().is_empty()
        || identity.service.trim().is_empty()
    {
        return Err(Error::Crypto(
            "artifact storage signing identity is incomplete".into(),
        ));
    }

    let date = signed_at.format("%Y%m%d").to_string();
    let timestamp = signed_at.format("%Y%m%dT%H%M%SZ").to_string();
    let scope = format!(
        "{date}/{}/{}/{TERMINATOR}",
        identity.region, identity.service
    );

    let (canonical_headers, signed_headers) = canonical_headers(request.headers);
    let canonical_request = format!(
        "{}\n{}\n\n{canonical_headers}\n{signed_headers}\n{}",
        request.method, request.path, request.payload_sha256
    );
    let string_to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = signing_key(identity, &date)?;
    let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes())?);
    Ok(format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        identity.access_key_id
    ))
}

/// Derive the date/region/service-scoped signing key. Each step keys the next,
/// so a key leaked for one day, region, or service cannot sign for another.
fn signing_key(identity: &SigningIdentity, date: &str) -> Result<Vec<u8>> {
    let initial = format!("AWS4{}", identity.secret_access_key.expose_secret());
    let dated = hmac(initial.as_bytes(), date.as_bytes())?;
    let regioned = hmac(&dated, identity.region.as_bytes())?;
    let serviced = hmac(&regioned, identity.service.as_bytes())?;
    hmac(&serviced, TERMINATOR.as_bytes())
}

fn hmac(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| Error::Crypto(format!("derive artifact signing key: {error}")))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Canonical headers are sorted by name, trimmed, and terminated by a newline
/// each; the signed-header list is the same names joined by semicolons.
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_ascii_lowercase(),
                value.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));

    let mut canonical = String::new();
    for (name, value) in &sorted {
        let _ = writeln!(canonical, "{name}:{value}");
    }
    let signed = sorted
        .iter()
        .map(|(name, _value)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
}

/// Percent-encode one path segment exactly as S3 expects: unreserved
/// characters pass through, everything else becomes uppercase hex. The object
/// keys ASF writes are lowercase hex and slashes, so this is the identity
/// mapping for them; it exists so an unexpected key can never be signed as one
/// string and sent as another.
pub(super) fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            other => {
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> SigningIdentity {
        SigningIdentity {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            ),
            region: "us-east-1".into(),
            service: "s3".into(),
        }
    }

    /// Golden derivation for the AWS example credential. The value was
    /// cross-checked against an independent HMAC implementation rather than
    /// taken from this code, so it catches a regression in the chaining order
    /// or the literals rather than merely restating them.
    #[test]
    fn signing_key_derivation_is_pinned() {
        let identity = SigningIdentity {
            region: "us-east-1".into(),
            service: "iam".into(),
            ..identity()
        };
        let key = signing_key(&identity, "20120215").expect("derive signing key");
        assert_eq!(
            hex::encode(key),
            "004aa806e13dae88b9032d9261bcb04c67d023afadd221e6b0d206e1760e0b5e"
        );
    }

    /// Each of the four chained HMACs must actually key the next one: a key
    /// that ignored any step would sign across days, regions, or services.
    #[test]
    fn every_scoping_step_changes_the_signing_key() {
        let base = signing_key(&identity(), "20130524").expect("derive");
        assert_eq!(base.len(), 32);
        assert_ne!(
            base,
            signing_key(&identity(), "20130525").expect("another day")
        );
        assert_ne!(
            base,
            signing_key(
                &SigningIdentity {
                    region: "eu-west-1".into(),
                    ..identity()
                },
                "20130524"
            )
            .expect("another region")
        );
        assert_ne!(
            base,
            signing_key(
                &SigningIdentity {
                    service: "iam".into(),
                    ..identity()
                },
                "20130524"
            )
            .expect("another service")
        );
        assert_ne!(
            base,
            signing_key(
                &SigningIdentity {
                    secret_access_key: SecretString::from("another-secret".to_owned()),
                    ..identity()
                },
                "20130524"
            )
            .expect("another secret")
        );
    }

    #[test]
    fn canonical_headers_are_sorted_lowercased_and_whitespace_folded() {
        let (canonical, signed) = canonical_headers(&[
            ("X-Amz-Date".into(), "20130524T000000Z".into()),
            ("Host".into(), "examplebucket.s3.amazonaws.com".into()),
            ("Range".into(), "bytes=0-9   ".into()),
        ]);
        assert_eq!(
            canonical,
            "host:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-date:20130524T000000Z\n"
        );
        assert_eq!(signed, "host;range;x-amz-date");
    }

    #[test]
    fn authorization_is_stable_and_scoped_to_its_date_region_and_service() {
        let signed_at: DateTime<Utc> = "2013-05-24T00:00:00Z".parse().unwrap();
        let headers = vec![
            (
                "host".to_owned(),
                "examplebucket.s3.amazonaws.com".to_owned(),
            ),
            ("x-amz-date".to_owned(), "20130524T000000Z".to_owned()),
        ];
        let request = CanonicalRequest {
            method: "GET",
            path: "/test.txt",
            headers: &headers,
            payload_sha256: &hex::encode(Sha256::digest(b"")),
        };

        let header = authorization_header(&identity(), &request, signed_at).expect("sign");
        assert!(header.starts_with(ALGORITHM));
        assert!(
            header.contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request")
        );
        assert!(header.contains("SignedHeaders=host;x-amz-date"));
        // Signing is deterministic for a fixed request and instant.
        assert_eq!(
            header,
            authorization_header(&identity(), &request, signed_at).expect("sign again")
        );

        // A different region, day, or payload must not reuse the signature.
        let other_region = SigningIdentity {
            region: "eu-west-1".into(),
            ..identity()
        };
        assert_ne!(
            header,
            authorization_header(&other_region, &request, signed_at).expect("sign")
        );
        let next_day: DateTime<Utc> = "2013-05-25T00:00:00Z".parse().unwrap();
        assert_ne!(
            header,
            authorization_header(&identity(), &request, next_day).expect("sign")
        );
        let other_payload = CanonicalRequest {
            payload_sha256: &hex::encode(Sha256::digest(b"different")),
            ..request.clone()
        };
        assert_ne!(
            header,
            authorization_header(&identity(), &other_payload, signed_at).expect("sign")
        );
    }

    #[test]
    fn an_incomplete_identity_can_never_sign() {
        let signed_at: DateTime<Utc> = "2013-05-24T00:00:00Z".parse().unwrap();
        let headers = vec![("host".to_owned(), "example".to_owned())];
        let request = CanonicalRequest {
            method: "GET",
            path: "/object",
            headers: &headers,
            payload_sha256: &hex::encode(Sha256::digest(b"")),
        };
        for broken in [
            SigningIdentity {
                access_key_id: "  ".into(),
                ..identity()
            },
            SigningIdentity {
                secret_access_key: SecretString::from(String::new()),
                ..identity()
            },
            SigningIdentity {
                region: String::new(),
                ..identity()
            },
        ] {
            assert!(authorization_header(&broken, &request, signed_at).is_err());
        }
    }

    #[test]
    fn path_encoding_passes_object_keys_through_and_escapes_everything_else() {
        assert_eq!(encode_path_segment("0a1b2c"), "0a1b2c");
        assert_eq!(encode_path_segment("a b"), "a%20b");
        assert_eq!(encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(encode_path_segment("a~-._"), "a~-._");
    }

    #[test]
    fn a_signing_identity_never_renders_its_credentials() {
        let rendered = format!("{:?}", identity());
        assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rendered.contains("wJalrXUtnFEMI"));
        assert!(rendered.contains("REDACTED"));
    }
}
