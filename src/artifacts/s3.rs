//! Content-addressed artifact storage on an S3-compatible endpoint.
//!
//! Evidence artifacts are the bytes an independent verifier re-reads, so this
//! store is deliberately narrow: one object per SHA-256 digest, written once,
//! read back and re-digested before it is handed to anything that trusts it.
//! A store that returned different bytes than it was given would otherwise let
//! a signed manifest describe content nobody can check.
//!
//! Requests are signed with `SigV4` over their own payload hash, plaintext
//! transport is refused outside loopback, and server-side encryption is part of
//! the configuration rather than an afterthought.

use std::{fmt, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use reqwest::{Client, StatusCode};
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use url::Url;

use super::{
    ArtifactStore, StoredArtifact,
    sigv4::{CanonicalRequest, SigningIdentity, authorization_header, encode_path_segment},
};
use crate::{Error, Result, crypto::sha256_digest};

const MIN_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const SERVICE: &str = "s3";

/// How the endpoint must protect objects at rest.
///
/// This is configuration, not a default: an operator states which protection
/// the bucket enforces, and ASF sends exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3ServerSideEncryption {
    /// The bucket itself enforces encryption; ASF sends no override.
    BucketManaged,
    /// Endpoint-managed keys.
    Aes256,
    /// A named KMS key.
    AwsKms { key_id: String },
}

impl S3ServerSideEncryption {
    fn headers(&self) -> Vec<(String, String)> {
        match self {
            Self::BucketManaged => Vec::new(),
            Self::Aes256 => vec![(
                "x-amz-server-side-encryption".to_owned(),
                "AES256".to_owned(),
            )],
            Self::AwsKms { key_id } => vec![
                (
                    "x-amz-server-side-encryption".to_owned(),
                    "aws:kms".to_owned(),
                ),
                (
                    "x-amz-server-side-encryption-aws-kms-key-id".to_owned(),
                    key_id.clone(),
                ),
            ],
        }
    }
}

/// Everything needed to reach one bucket, with the credential kept secret.
#[derive(Clone)]
pub struct S3ArtifactStoreSettings {
    pub endpoint: Url,
    pub region: String,
    pub bucket: String,
    /// Key prefix for every stored object. Objects are addressed only by their
    /// digest beneath it.
    pub prefix: String,
    pub access_key_id: String,
    pub secret_access_key: SecretString,
    /// Path-style addressing (`{endpoint}/{bucket}/{key}`) is what `MinIO` and
    /// most S3-compatible endpoints expect; virtual-hosted style puts the
    /// bucket in the endpoint host instead.
    pub path_style: bool,
    pub server_side_encryption: S3ServerSideEncryption,
    pub timeout: Duration,
}

impl fmt::Debug for S3ArtifactStoreSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ArtifactStoreSettings")
            .field("endpoint", &self.endpoint.as_str())
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field("path_style", &self.path_style)
            .field("server_side_encryption", &self.server_side_encryption)
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// An S3-compatible content-addressed artifact store.
#[derive(Clone)]
pub struct S3ArtifactStore {
    settings: S3ArtifactStoreSettings,
    identity: SigningIdentity,
    client: Client,
}

impl fmt::Debug for S3ArtifactStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3ArtifactStore")
            .field("settings", &self.settings)
            .field("identity", &self.identity)
            .field("client", &"Client([REDACTED])")
            .finish()
    }
}

impl S3ArtifactStore {
    /// Construct a store, refusing a configuration that could not protect
    /// artifacts in transit or address them unambiguously.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Validation`] for a non-HTTPS endpoint outside loopback,
    /// a malformed bucket, prefix, region, or credential, or a timeout outside
    /// `1ms..=300s`.
    pub fn new(settings: S3ArtifactStoreSettings) -> Result<Self> {
        validate(&settings)?;
        let client = Client::builder()
            .timeout(settings.timeout)
            .build()
            .map_err(|error| {
                Error::Validation(format!("construct artifact storage client: {error}"))
            })?;
        let identity = SigningIdentity {
            access_key_id: settings.access_key_id.clone(),
            secret_access_key: settings.secret_access_key.clone(),
            region: settings.region.clone(),
            service: SERVICE.to_owned(),
        };
        Ok(Self {
            settings,
            identity,
            client,
        })
    }

    /// The object path for one digest, already percent-encoded.
    ///
    /// Content addressing is the whole storage model: the same bytes are always
    /// the same object, so a write is idempotent and a read cannot be
    /// redirected to different content by anything but a broken endpoint, which
    /// [`ArtifactStore::get`] then catches.
    fn object_path(&self, digest: &str) -> Result<String> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Validation("artifact digest must use sha256".into()))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Validation("invalid artifact digest".into()));
        }
        let mut segments = Vec::new();
        if self.settings.path_style {
            segments.push(encode_path_segment(&self.settings.bucket));
        }
        for segment in self
            .settings
            .prefix
            .split('/')
            .filter(|part| !part.is_empty())
        {
            segments.push(encode_path_segment(segment));
        }
        segments.push(encode_path_segment(&hex[..2]));
        segments.push(encode_path_segment(&hex[2..]));
        Ok(format!("/{}", segments.join("/")))
    }

    fn request_url(&self, path: &str) -> Url {
        let mut url = self.settings.endpoint.clone();
        url.set_path(path);
        url
    }

    fn host_header(&self) -> Result<String> {
        let host = self
            .settings
            .endpoint
            .host_str()
            .ok_or_else(|| Error::Validation("artifact storage endpoint has no host".into()))?;
        Ok(match self.settings.endpoint.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_owned(),
        })
    }

    /// Sign and send one request, returning its status and body.
    async fn send(
        &self,
        method: &str,
        path: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let payload_sha256 = hex::encode(Sha256::digest(&body));
        let signed_at = Utc::now();
        let mut signed_headers = headers;
        signed_headers.push(("host".to_owned(), self.host_header()?));
        signed_headers.push((
            "x-amz-date".to_owned(),
            signed_at.format("%Y%m%dT%H%M%SZ").to_string(),
        ));
        signed_headers.push(("x-amz-content-sha256".to_owned(), payload_sha256.clone()));

        let authorization = authorization_header(
            &self.identity,
            &CanonicalRequest {
                method,
                path,
                headers: &signed_headers,
                payload_sha256: &payload_sha256,
            },
            signed_at,
        )?;

        let mut request = self
            .client
            .request(
                method
                    .parse()
                    .map_err(|_| Error::Validation("unsupported artifact storage method".into()))?,
                self.request_url(path),
            )
            .header("authorization", authorization);
        for (name, value) in &signed_headers {
            // `host` is set by the transport from the URL; sending it twice is
            // what would make the signature and the wire disagree.
            if name != "host" {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        if !body.is_empty() {
            request = request.body(body);
        }

        let response = request.send().await.map_err(|error| {
            // The endpoint URL is operator-supplied and non-secret; the error's
            // own text is not echoed further than this.
            Error::ExternalUnavailable(format!("artifact storage request failed: {error}"))
        })?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|error| {
            Error::ExternalUnavailable(format!("read artifact storage response: {error}"))
        })?;
        Ok((status, bytes.to_vec()))
    }
}

#[async_trait]
impl ArtifactStore for S3ArtifactStore {
    async fn put(
        &self,
        bytes: &[u8],
        media_type: &str,
        producer: &str,
        retention_class: &str,
    ) -> Result<StoredArtifact> {
        if media_type.trim().is_empty()
            || producer.trim().is_empty()
            || retention_class.trim().is_empty()
        {
            return Err(Error::Validation(
                "artifact metadata fields must be non-empty".into(),
            ));
        }
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(Error::Validation(
                "artifact exceeds the supported single-request size".into(),
            ));
        }

        let digest = sha256_digest(bytes);
        let path = self.object_path(&digest)?;
        let mut headers = vec![("content-type".to_owned(), media_type.to_owned())];
        headers.extend(self.settings.server_side_encryption.headers());

        let (status, _body) = self.send("PUT", &path, headers, bytes.to_vec()).await?;
        if !status.is_success() {
            return Err(storage_failure("store artifact", status));
        }

        Ok(StoredArtifact {
            digest,
            media_type: media_type.into(),
            size: bytes.len() as u64,
            producer: producer.into(),
            retention_class: retention_class.into(),
            stored_at: Utc::now(),
        })
    }

    async fn get(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.object_path(digest)?;
        let (status, body) = self.send("GET", &path, Vec::new(), Vec::new()).await?;
        if status == StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!("artifact {digest}")));
        }
        if !status.is_success() {
            return Err(storage_failure("read artifact", status));
        }
        // Content addressing is only a guarantee if it is checked. Anything
        // that reads an artifact is about to trust it as evidence.
        if sha256_digest(&body) != digest {
            return Err(Error::Persistence(format!(
                "artifact storage returned content that is not {digest}"
            )));
        }
        Ok(body)
    }
}

/// Storage failures name the operation and the status, never the response body:
/// an endpoint's error document can carry keys, paths, or request identifiers.
fn storage_failure(operation: &str, status: StatusCode) -> Error {
    Error::ExternalUnavailable(format!(
        "artifact storage refused to {operation} (HTTP {})",
        status.as_u16()
    ))
}

fn validate(settings: &S3ArtifactStoreSettings) -> Result<()> {
    let host = settings
        .endpoint
        .host_str()
        .ok_or_else(|| Error::Validation("artifact storage endpoint has no host".into()))?;
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "::1";
    if settings.endpoint.scheme() != "https" && !loopback {
        return Err(Error::Validation(
            "artifact storage endpoint must use HTTPS outside loopback".into(),
        ));
    }
    if settings.endpoint.scheme() != "https" && settings.endpoint.scheme() != "http" {
        return Err(Error::Validation(
            "artifact storage endpoint must be an HTTP(S) URL".into(),
        ));
    }
    if settings.endpoint.query().is_some() || !settings.endpoint.username().is_empty() {
        return Err(Error::Validation(
            "artifact storage endpoint must carry no query or credentials".into(),
        ));
    }
    if !valid_bucket(&settings.bucket) {
        return Err(Error::Validation(
            "artifact storage bucket is not a valid S3 bucket name".into(),
        ));
    }
    if !valid_prefix(&settings.prefix) {
        return Err(Error::Validation(
            "artifact storage prefix must be non-empty path segments".into(),
        ));
    }
    if settings.region.trim().is_empty() || settings.access_key_id.trim().is_empty() {
        return Err(Error::Validation(
            "artifact storage region and access key are required".into(),
        ));
    }
    if let S3ServerSideEncryption::AwsKms { key_id } = &settings.server_side_encryption
        && key_id.trim().is_empty()
    {
        return Err(Error::Validation(
            "artifact storage KMS encryption requires a key ID".into(),
        ));
    }
    if settings.timeout < MIN_TIMEOUT || settings.timeout > MAX_TIMEOUT {
        return Err(Error::Validation(
            "artifact storage timeout must be within 1ms..=300s".into(),
        ));
    }
    Ok(())
}

fn valid_bucket(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !bucket.starts_with('-')
        && !bucket.ends_with('-')
}

fn valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && !prefix.starts_with('/')
        && !prefix.ends_with('/')
        && prefix.split('/').all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
                })
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpListener, TcpStream},
    };

    use super::*;

    fn settings(endpoint: &str) -> S3ArtifactStoreSettings {
        S3ArtifactStoreSettings {
            endpoint: Url::parse(endpoint).expect("endpoint"),
            region: "us-east-1".into(),
            bucket: "asf-artifacts".into(),
            prefix: "sha256".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: SecretString::from(
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            ),
            path_style: true,
            server_side_encryption: S3ServerSideEncryption::Aes256,
            timeout: Duration::from_secs(10),
        }
    }

    fn store(endpoint: &str) -> S3ArtifactStore {
        S3ArtifactStore::new(settings(endpoint)).expect("construct store")
    }

    #[test]
    fn plaintext_transport_is_refused_outside_loopback() {
        assert!(S3ArtifactStore::new(settings("http://storage.invalid")).is_err());
        assert!(S3ArtifactStore::new(settings("https://storage.invalid")).is_ok());
        // A local MinIO is how this is exercised before a bucket exists.
        assert!(S3ArtifactStore::new(settings("http://127.0.0.1:9000")).is_ok());
    }

    #[test]
    fn an_unusable_configuration_is_refused_at_construction() {
        for broken in [
            S3ArtifactStoreSettings {
                bucket: "no".into(),
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                bucket: "Not-Lowercase".into(),
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                prefix: "/leading".into(),
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                prefix: String::new(),
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                region: "  ".into(),
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                server_side_encryption: S3ServerSideEncryption::AwsKms {
                    key_id: String::new(),
                },
                ..settings("https://storage.invalid")
            },
            S3ArtifactStoreSettings {
                timeout: Duration::from_mins(10),
                ..settings("https://storage.invalid")
            },
        ] {
            assert!(S3ArtifactStore::new(broken).is_err());
        }
    }

    #[test]
    fn object_paths_are_content_addressed_and_prefix_scoped() {
        let store = store("https://storage.invalid");
        let digest = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            store.object_path(&digest).unwrap(),
            format!("/asf-artifacts/sha256/ab/{}", "ab".repeat(31))
        );

        // Virtual-hosted addressing puts the bucket in the host instead.
        let virtual_hosted = S3ArtifactStore::new(S3ArtifactStoreSettings {
            path_style: false,
            ..settings("https://asf-artifacts.s3.us-east-1.amazonaws.com")
        })
        .expect("construct store");
        assert_eq!(
            virtual_hosted.object_path(&digest).unwrap(),
            format!("/sha256/ab/{}", "ab".repeat(31))
        );
    }

    #[test]
    fn a_digest_that_is_not_sha256_can_never_address_an_object() {
        let store = store("https://storage.invalid");
        for invalid in [
            "blake3:aa".to_owned(),
            format!("sha256:{}", "z".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            "sha256:".to_owned(),
        ] {
            assert!(store.object_path(&invalid).is_err());
        }
    }

    #[test]
    fn encryption_headers_state_exactly_what_the_operator_configured() {
        assert!(S3ServerSideEncryption::BucketManaged.headers().is_empty());
        assert_eq!(
            S3ServerSideEncryption::Aes256.headers(),
            vec![(
                "x-amz-server-side-encryption".to_owned(),
                "AES256".to_owned()
            )]
        );
        let kms = S3ServerSideEncryption::AwsKms {
            key_id: "arn:aws:kms:us-east-1:1:key/abc".into(),
        };
        assert_eq!(kms.headers().len(), 2);
    }

    #[test]
    fn settings_and_store_never_render_their_credentials() {
        let rendered = format!("{:?}", store("https://storage.invalid"));
        assert!(!rendered.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rendered.contains("wJalrXUtnFEMI"));
        assert!(rendered.contains("REDACTED"));
    }

    /// One captured request: method, path, and its lowercased headers.
    type CapturedRequest = (String, String, BTreeMap<String, String>);

    /// A minimal S3-compatible endpoint: one request per connection, an
    /// in-memory object map, and every received request captured so the wire
    /// itself can be asserted on.
    struct StubEndpoint {
        base: String,
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
    }

    impl StubEndpoint {
        async fn start(corrupt_reads: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
            let base = format!("http://{}", listener.local_addr().expect("stub address"));
            let objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>> =
                Arc::new(Mutex::new(BTreeMap::new()));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let served_objects = Arc::clone(&objects);
            let served_requests = Arc::clone(&requests);

            tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (method, path, headers, body) = read_request(&mut stream).await;
                    served_requests.lock().expect("capture request").push((
                        method.clone(),
                        path.clone(),
                        headers,
                    ));

                    let response = match method.as_str() {
                        "PUT" => {
                            served_objects
                                .lock()
                                .expect("store object")
                                .insert(path, body);
                            respond(200, &[])
                        }
                        "GET" => {
                            let stored = served_objects
                                .lock()
                                .expect("read object")
                                .get(&path)
                                .cloned();
                            match stored {
                                Some(_bytes) if corrupt_reads => respond(200, b"tampered"),
                                Some(bytes) => respond(200, &bytes),
                                None => respond(404, b"<Error/>"),
                            }
                        }
                        _ => respond(405, &[]),
                    };
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                }
            });

            Self {
                base,
                objects,
                requests,
            }
        }

        fn store(&self) -> S3ArtifactStore {
            S3ArtifactStore::new(settings(&self.base)).expect("construct store")
        }

        fn requests(&self) -> Vec<CapturedRequest> {
            self.requests.lock().expect("read requests").clone()
        }
    }

    async fn read_request(
        stream: &mut TcpStream,
    ) -> (String, String, BTreeMap<String, String>, Vec<u8>) {
        let mut buffer = Vec::new();
        let mut byte = [0_u8; 1];
        while !buffer.ends_with(b"\r\n\r\n") {
            let read = stream.read(&mut byte).await.expect("read stub request");
            if read == 0 {
                break;
            }
            buffer.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&buffer).to_string();
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();

        let mut headers = BTreeMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
            }
        }
        let length: usize = headers
            .get("content-length")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; length];
        if length > 0 {
            stream.read_exact(&mut body).await.expect("read stub body");
        }
        (method, path, headers, body)
    }

    fn respond(status: u16, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    #[tokio::test]
    async fn stores_and_reads_one_content_addressed_artifact() {
        let endpoint = StubEndpoint::start(false).await;
        let store = endpoint.store();

        let stored = store
            .put(b"evidence bytes", "application/json", "runmill", "portable")
            .await
            .expect("store artifact");
        assert_eq!(stored.digest, sha256_digest(b"evidence bytes"));
        assert_eq!(stored.size, 14);

        let read = store.get(&stored.digest).await.expect("read artifact");
        assert_eq!(read, b"evidence bytes");

        // The same bytes are one object: storing twice writes the same key.
        store
            .put(b"evidence bytes", "application/json", "runmill", "portable")
            .await
            .expect("store artifact again");
        assert_eq!(endpoint.objects.lock().expect("objects").len(), 1);
    }

    #[tokio::test]
    async fn every_request_is_signed_over_its_own_payload() {
        let endpoint = StubEndpoint::start(false).await;
        let store = endpoint.store();
        store
            .put(b"evidence bytes", "application/json", "runmill", "portable")
            .await
            .expect("store artifact");

        let requests = endpoint.requests();
        let (method, path, headers) = requests.first().expect("one captured request");
        assert_eq!(method, "PUT");
        assert!(path.starts_with("/asf-artifacts/sha256/"));

        let authorization = headers.get("authorization").expect("signed request");
        assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential="));
        assert!(authorization.contains("/us-east-1/s3/aws4_request"));
        // The payload hash is both sent and signed, so a proxy cannot swap the
        // bytes without invalidating the signature.
        assert!(authorization.contains("x-amz-content-sha256"));
        assert_eq!(
            headers.get("x-amz-content-sha256"),
            Some(&hex::encode(Sha256::digest(b"evidence bytes")))
        );
        assert_eq!(
            headers.get("x-amz-server-side-encryption"),
            Some(&"AES256".to_owned())
        );
        assert_eq!(
            headers.get("content-type"),
            Some(&"application/json".to_owned())
        );
    }

    #[tokio::test]
    async fn an_absent_artifact_is_not_found_rather_than_unavailable() {
        let endpoint = StubEndpoint::start(false).await;
        let store = endpoint.store();
        let missing = format!("sha256:{}", "cd".repeat(32));
        assert!(matches!(store.get(&missing).await, Err(Error::NotFound(_))));
    }

    #[tokio::test]
    async fn content_that_is_not_what_was_asked_for_is_refused() {
        let endpoint = StubEndpoint::start(true).await;
        let store = endpoint.store();
        let stored = store
            .put(b"evidence bytes", "application/json", "runmill", "portable")
            .await
            .expect("store artifact");

        // The endpoint returns different bytes than the digest names. Nothing
        // downstream may treat that as evidence.
        let error = store
            .get(&stored.digest)
            .await
            .expect_err("tampered content is refused");
        assert!(matches!(error, Error::Persistence(_)), "{error}");
    }

    #[tokio::test]
    async fn oversized_and_incomplete_artifacts_are_refused_before_any_request() {
        let endpoint = StubEndpoint::start(false).await;
        let store = endpoint.store();
        assert!(
            store
                .put(b"bytes", "", "runmill", "portable")
                .await
                .is_err()
        );
        assert!(
            store
                .put(b"bytes", "application/json", "  ", "portable")
                .await
                .is_err()
        );
        assert!(
            store
                .put(b"bytes", "application/json", "runmill", "")
                .await
                .is_err()
        );
        assert!(endpoint.requests().is_empty());
    }
}
