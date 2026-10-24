//! Storage for encrypted attachment blobs (G2).
//!
//! Blobs are opaque ciphertext (see `passbox_core::file_crypto`); the
//! database only keeps their size and owner. [`BlobStore`] is the seam for
//! other backends; this version ships the disk store (`PASSBOX_BLOB_DIR`).
//! An S3-compatible backend is not included yet: no small, audited S3
//! client crate fit the dependency policy, and a mounted volume (or an S3
//! FUSE mount, for those who need one) covers self-hosting today.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use anyhow::Context;
use axum::body::Body;
use http_body_util::BodyExt;
use tokio::io::AsyncWriteExt;

pub type BlobFuture<'a, T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send + 'a>>;

/// Result of storing a blob.
#[derive(Debug, PartialEq, Eq)]
pub enum PutOutcome {
    /// Stored with this many bytes.
    Stored(u64),
    /// The body was longer than allowed; nothing was stored.
    TooLarge,
}

/// Where encrypted blobs live.
pub trait BlobStore: Send + Sync {
    /// Stores the request body under `id`, reading at most `max_len` bytes.
    fn put<'a>(&'a self, id: &'a str, body: Body, max_len: u64) -> BlobFuture<'a, PutOutcome>;
    /// The blob's size and a streaming body, if it exists.
    fn get<'a>(&'a self, id: &'a str) -> BlobFuture<'a, Option<(u64, Body)>>;
    /// Removes a blob (no error if it does not exist).
    fn delete<'a>(&'a self, id: &'a str) -> BlobFuture<'a, ()>;
    /// Every stored blob ID with its age in milliseconds (for cleanup).
    fn list<'a>(&'a self) -> BlobFuture<'a, Vec<(String, u64)>>;
}

/// Blobs as files: `{dir}/{first two characters}/{id}`. Uploads go to
/// `{dir}/tmp` first and are renamed when complete, so readers never see
/// partial files.
pub struct DiskBlobStore {
    dir: PathBuf,
}

impl DiskBlobStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// A store in a new directory under the system's temporary directory
    /// (tests, and `AppState::load` before the configuration is applied).
    pub fn temporary() -> Self {
        let suffix = passbox_core::id::new_id().unwrap_or_else(|_| "blobs".into());
        Self::new(std::env::temp_dir().join(format!("passbox-blobs-{suffix}")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &str) -> anyhow::Result<PathBuf> {
        // IDs are validated by the API; this keeps the path safe regardless.
        anyhow::ensure!(passbox_core::id::is_valid_id(id), "invalid blob id {id:?}");
        Ok(self.dir.join(&id[..2]).join(id))
    }
}

impl BlobStore for DiskBlobStore {
    fn put<'a>(&'a self, id: &'a str, body: Body, max_len: u64) -> BlobFuture<'a, PutOutcome> {
        Box::pin(async move {
            let path = self.path(id)?;
            let tmp_dir = self.dir.join("tmp");
            tokio::fs::create_dir_all(&tmp_dir)
                .await
                .with_context(|| format!("cannot create {}", tmp_dir.display()))?;
            let tmp = tmp_dir.join(format!("{id}.{}", passbox_core::id::new_id()?));
            let mut file = tokio::fs::File::create(&tmp).await?;
            let mut body = body;
            let mut written: u64 = 0;
            let result: anyhow::Result<PutOutcome> = async {
                while let Some(frame) = body.frame().await {
                    let frame = frame.context("upload interrupted")?;
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    written += data.len() as u64;
                    if written > max_len {
                        return Ok(PutOutcome::TooLarge);
                    }
                    file.write_all(&data).await?;
                }
                file.flush().await?;
                file.sync_all().await?;
                Ok(PutOutcome::Stored(written))
            }
            .await;
            drop(file);
            match result {
                Ok(PutOutcome::Stored(size)) => {
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tokio::fs::rename(&tmp, &path).await?;
                    Ok(PutOutcome::Stored(size))
                }
                other => {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    other
                }
            }
        })
    }

    fn get<'a>(&'a self, id: &'a str) -> BlobFuture<'a, Option<(u64, Body)>> {
        Box::pin(async move {
            let path = self.path(id)?;
            let file = match tokio::fs::File::open(&path).await {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            let size = file.metadata().await?.len();
            let stream = tokio_util::io::ReaderStream::with_capacity(file, 256 * 1024);
            Ok(Some((size, Body::from_stream(stream))))
        })
    }

    fn delete<'a>(&'a self, id: &'a str) -> BlobFuture<'a, ()> {
        Box::pin(async move {
            match tokio::fs::remove_file(self.path(id)?).await {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
                _ => Ok(()),
            }
        })
    }

    fn list<'a>(&'a self) -> BlobFuture<'a, Vec<(String, u64)>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let mut shards = match tokio::fs::read_dir(&self.dir).await {
                Ok(dir) => dir,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(e.into()),
            };
            let now = std::time::SystemTime::now();
            while let Some(shard) = shards.next_entry().await? {
                let name = shard.file_name().to_string_lossy().into_owned();
                if name.len() != 2 || !shard.file_type().await?.is_dir() {
                    continue;
                }
                let mut files = tokio::fs::read_dir(shard.path()).await?;
                while let Some(file) = files.next_entry().await? {
                    let id = file.file_name().to_string_lossy().into_owned();
                    if !passbox_core::id::is_valid_id(&id) {
                        continue;
                    }
                    let age = file
                        .metadata()
                        .await?
                        .modified()
                        .ok()
                        .and_then(|m| now.duration_since(m).ok())
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    out.push((id, age));
                }
            }
            Ok(out)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stores_reads_limits_and_deletes() {
        let store = DiskBlobStore::temporary();
        let id = passbox_core::id::new_id().unwrap();
        assert_eq!(
            store.put(&id, Body::from(vec![1u8; 10]), 5).await.unwrap(),
            PutOutcome::TooLarge
        );
        assert!(store.get(&id).await.unwrap().is_none());
        assert_eq!(
            store.put(&id, Body::from(vec![1u8; 10]), 10).await.unwrap(),
            PutOutcome::Stored(10)
        );
        let (size, body) = store.get(&id).await.unwrap().unwrap();
        assert_eq!(size, 10);
        let bytes = body.collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], &[1u8; 10]);
        assert_eq!(store.list().await.unwrap().len(), 1);
        store.delete(&id).await.unwrap();
        store.delete(&id).await.unwrap();
        assert!(store.get(&id).await.unwrap().is_none());
        assert!(store.get("../etc/passwd").await.is_err());
        let _ = std::fs::remove_dir_all(store.dir());
    }
}
