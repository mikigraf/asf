use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[must_use]
pub fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|error| Error::Serialization(error.to_string()))
}

#[derive(Debug)]
pub struct Ed25519Signer {
    key_id: String,
    signing_key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_base64_seed(key_id: impl Into<String>, seed: &str) -> Result<Self> {
        let decoded = Zeroizing::new(decode_signing_seed(seed)?);
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::Crypto("Ed25519 signing seed must be 32 bytes".into()))?;
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&bytes),
        })
    }

    #[must_use]
    pub fn generate(key_id: impl Into<String>) -> Self {
        let mut rng = rand_core::OsRng;
        Self {
            key_id: key_id.into(),
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.sign(message).to_bytes())
    }

    /// Sign a protocol message with an unambiguous domain separator.
    #[must_use]
    pub fn sign_domain(&self, domain: &str, message: &[u8]) -> String {
        self.sign(&domain_separated_message(domain, message))
    }
}

fn decode_signing_seed(seed: &str) -> Result<Vec<u8>> {
    // Deployment secret stores commonly emit either RFC 4648 alphabet and
    // may retain or remove padding. Accept those four encodings, but never
    // trim or otherwise normalize input: hidden whitespace must fail closed.
    for engine in [&URL_SAFE_NO_PAD, &URL_SAFE, &STANDARD_NO_PAD, &STANDARD] {
        if let Ok(decoded) = engine.decode(seed) {
            return Ok(decoded);
        }
    }
    Err(Error::Crypto("invalid base64 signing seed".into()))
}

pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.as_bytes())
}

pub fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| Error::Crypto(format!("invalid verifying key: {error}")))?;
    let bytes: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("Ed25519 verifying key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|error| Error::Crypto(format!("invalid Ed25519 verifying key: {error}")))
}

pub fn verify_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| Error::Crypto(format!("invalid signature encoding: {error}")))?;
    let signature = Signature::from_slice(&decoded)
        .map_err(|error| Error::Crypto(format!("invalid signature: {error}")))?;
    key.verify(message, &signature)
        .map_err(|_| Error::Crypto("signature does not match".into()))
}

pub fn verify_domain_signature(
    key: &VerifyingKey,
    domain: &str,
    message: &[u8],
    encoded: &str,
) -> Result<()> {
    verify_signature(key, &domain_separated_message(domain, message), encoded)
}

fn domain_separated_message(domain: &str, message: &[u8]) -> Vec<u8> {
    let mut separated = Vec::with_capacity(domain.len() + 1 + message.len());
    separated.extend_from_slice(domain.as_bytes());
    separated.push(0);
    separated.extend_from_slice(message);
    separated
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[derive(Serialize)]
    struct Fixture {
        z: u8,
        a: &'static str,
    }

    #[test]
    fn canonical_json_orders_object_keys() {
        let bytes = canonical_json(&Fixture { z: 1, a: "x" }).unwrap();
        assert_eq!(bytes, br#"{"a":"x","z":1}"#);
    }

    #[test]
    fn ed25519_round_trip_and_tamper_detection() {
        let signer = Ed25519Signer::generate("test");
        let signature = signer.sign(b"authority");
        verify_signature(&signer.verifying_key(), b"authority", &signature).unwrap();
        assert!(verify_signature(&signer.verifying_key(), b"wider authority", &signature).is_err());
    }

    #[test]
    fn signing_seed_accepts_documented_standard_base64_and_url_safe_base64() {
        let seed = [0xfb_u8; 32];
        let standard = STANDARD.encode(seed);
        let url_safe = URL_SAFE_NO_PAD.encode(seed);

        let standard_signer = Ed25519Signer::from_base64_seed("standard", &standard).unwrap();
        let url_safe_signer = Ed25519Signer::from_base64_seed("url-safe", &url_safe).unwrap();
        assert_eq!(
            standard_signer.verifying_key(),
            url_safe_signer.verifying_key()
        );

        assert!(Ed25519Signer::from_base64_seed("short", &STANDARD.encode([0_u8; 31])).is_err());
        assert!(Ed25519Signer::from_base64_seed("space", &format!("{standard}\n")).is_err());
    }
}
