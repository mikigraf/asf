use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

mod s3;
mod sigv4;

pub use s3::{S3ArtifactStore, S3ArtifactStoreSettings, S3ServerSideEncryption};

use crate::{Error, Result, crypto::sha256_digest};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredArtifact {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub producer: String,
    pub retention_class: String,
    pub stored_at: DateTime<Utc>,
}

#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn put(
        &self,
        bytes: &[u8],
        media_type: &str,
        producer: &str,
        retention_class: &str,
    ) -> Result<StoredArtifact>;

    async fn get(&self, digest: &str) -> Result<Vec<u8>>;
}

/// Development/test content-addressed storage. Production can supply an S3 implementation.
#[derive(Debug, Clone)]
pub struct FileArtifactStore {
    root: PathBuf,
}

impl FileArtifactStore {
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|error| Error::Persistence(format!("create artifact root: {error}")))?;
        Ok(Self { root })
    }

    fn path_for(&self, digest: &str) -> Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .ok_or_else(|| Error::Validation("artifact digest must use sha256".into()))?;
        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::Validation("invalid artifact digest".into()));
        }
        Ok(self.root.join(&hex[..2]).join(&hex[2..]))
    }
}

#[async_trait]
impl ArtifactStore for FileArtifactStore {
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
        let digest = sha256_digest(bytes);
        let path = self.path_for(&digest)?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::Persistence("artifact path has no parent".into()))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| Error::Persistence(format!("create artifact prefix: {error}")))?;

        if !path.exists() {
            let temporary = temporary_path(&path);
            let mut file = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .await
                .map_err(|error| Error::Persistence(format!("create artifact: {error}")))?;
            file.write_all(bytes)
                .await
                .map_err(|error| Error::Persistence(format!("write artifact: {error}")))?;
            file.flush()
                .await
                .map_err(|error| Error::Persistence(format!("flush artifact: {error}")))?;
            drop(file);
            match tokio::fs::rename(&temporary, &path).await {
                Ok(()) => {}
                Err(_error) if path.exists() => {
                    let _ = tokio::fs::remove_file(&temporary).await;
                    let existing = tokio::fs::read(&path).await.map_err(|read_error| {
                        Error::Persistence(format!("read raced artifact: {read_error}"))
                    })?;
                    if sha256_digest(&existing) != digest {
                        return Err(Error::Persistence(
                            "content-addressed artifact collision".into(),
                        ));
                    }
                }
                Err(error) => {
                    let _ = tokio::fs::remove_file(&temporary).await;
                    return Err(Error::Persistence(format!("commit artifact: {error}")));
                }
            }
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
        tokio::fs::read(self.path_for(digest)?)
            .await
            .map_err(|error| Error::NotFound(format!("artifact {digest}: {error}")))
    }
}

fn temporary_path(final_path: &Path) -> PathBuf {
    let mut value = final_path.as_os_str().to_os_string();
    value.push(format!(".{}.tmp", uuid::Uuid::now_v7()));
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_once_by_content_digest() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileArtifactStore::open(directory.path()).await.unwrap();
        let first = store
            .put(b"evidence", "application/json", "test", "audit")
            .await
            .unwrap();
        let second = store
            .put(b"evidence", "application/json", "test", "audit")
            .await
            .unwrap();
        assert_eq!(first.digest, second.digest);
        assert_eq!(store.get(&first.digest).await.unwrap(), b"evidence");
    }

    #[tokio::test]
    async fn rejects_path_like_digest() {
        let directory = tempfile::tempdir().unwrap();
        let store = FileArtifactStore::open(directory.path()).await.unwrap();
        assert!(store.get("sha256:../../secret").await.is_err());
    }
}
