//! Shared mutable state plumbing. Backed by `Arc<RwLock<KeystoreContents>>`
//! so the listener task, per-connection tasks, and the (future) revoke
//! retry queue can all coordinate through one persistence surface.

use std::sync::Arc;

use tokio::sync::RwLock;
use wake_my_pc_core::crypto::DeviceIdentity;

use crate::config::Config;
use crate::keystore::KeystoreContents;

/// Cheaply-cloneable handle. All clones see the same in-memory state.
#[derive(Clone, Debug)]
pub struct SharedState {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    contents: RwLock<KeystoreContents>,
    identity: DeviceIdentity,
    config: Config,
}

impl SharedState {
    /// Construct from freshly-loaded keystore contents + the parsed
    /// device identity.
    #[must_use]
    pub fn new(contents: KeystoreContents, identity: DeviceIdentity, config: Config) -> Self {
        Self {
            inner: Arc::new(Inner {
                contents: RwLock::new(contents),
                identity,
                config,
            }),
        }
    }

    /// Daemon's device identity (key + cert + SPKI). Cheap clone-by-ref
    /// of the underlying Arc'd Inner.
    #[must_use]
    pub fn identity(&self) -> &DeviceIdentity {
        &self.inner.identity
    }

    /// Daemon config (bind addr, paths). Read-only.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// Read-lock the keystore contents. Use [`snapshot`] for cases
    /// where you want a `Clone` instead of holding the lock.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, KeystoreContents> {
        self.inner.contents.read().await
    }

    /// Write-lock for mutations. Caller is responsible for persisting
    /// via [`SharedState::save`] when the change is durable.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, KeystoreContents> {
        self.inner.contents.write().await
    }

    /// Clone a snapshot of the current contents. Useful for "give me
    /// the values, I'll go think about them" callsites.
    pub async fn snapshot(&self) -> KeystoreContents {
        self.inner.contents.read().await.clone()
    }

    /// Persist the current contents to disk via the keystore module.
    pub async fn save(&self) -> Result<(), crate::error::KeystoreError> {
        let snap = self.snapshot().await;
        crate::keystore::save(&self.inner.config.keystore_path(), &snap).await
    }
}
