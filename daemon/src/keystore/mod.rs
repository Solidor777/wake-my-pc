//! Keystore: device identity + pairings, persisted encrypted on disk.
//!
//! Layered:
//! - **Plaintext layer** ([`KeystoreContents`]): postcard-encoded struct
//!   versioned by a leading format byte. Adding a field is a non-breaking
//!   bump (postcard tolerates new optional fields by failing-decode, so
//!   we bump the format byte and keep migration explicit).
//! - **Cipher layer** (per-platform): wraps the postcard bytes with the
//!   OS-native keystore. Windows: DPAPI `CryptProtectData`. macOS:
//!   Keychain `SecItem` (M2 follow-up). Linux: libsecret OR encrypted file
//!   keyed off `/etc/machine-id` (M2 follow-up; PRINCIPLES.md §1 caveat).
//!
//! Atomic write: tempfile in the same directory, then rename. Preserves
//! the previous keystore on partial-write crash.

mod platform;

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{debug, info};
use wake_my_pc_core::crypto::DeviceIdentityBytes;

use crate::error::KeystoreError;
use crate::pairings::PairingRecord;

/// Format byte at the head of every keystore file. Bumped on
/// wire-incompatible plaintext-layer changes.
pub const KEYSTORE_FORMAT_VERSION: u8 = 1;

/// The plaintext keystore layout. Postcard-encoded; wrapped by the
/// per-platform encryption layer before hitting disk.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeystoreContents {
    /// PKCS#8 DER of the daemon's Ed25519 private key. Sensitive.
    pub key_pkcs8_der: Vec<u8>,
    /// X.509 DER of the daemon's self-signed cert. Public.
    pub cert_der: Vec<u8>,
    /// Active + revoked pairings. Lookups go through helper methods to
    /// keep the live set / revocation queue ordering explicit.
    pub pairings: Vec<PairingRecord>,
    /// Configured re-auth interval in days (matches PROTOCOL.md
    /// `ReauthInterval` semantics). 7 by default.
    pub reauth_interval_days: u8,
    /// Unix-ms of most recent successful credential prompt. `0` until
    /// `reauth-now` runs once. Re-auth state machine reads this.
    pub last_authenticated_at_unix_ms: u64,
}

impl KeystoreContents {
    /// Construct from a freshly-generated daemon identity. `pairings`
    /// is empty; `reauth_interval_days = 7` per PRINCIPLES.md §3 default.
    #[must_use]
    pub fn from_identity(identity: &DeviceIdentityBytes) -> Self {
        Self {
            key_pkcs8_der: identity.key_pkcs8_der.clone(),
            cert_der: identity.cert_der.clone(),
            pairings: Vec::new(),
            reauth_interval_days: 7,
            last_authenticated_at_unix_ms: 0,
        }
    }

    /// Borrow the daemon identity bytes for [`wake_my_pc_core::crypto::DeviceIdentity::from_bytes`].
    #[must_use]
    pub fn device_identity_bytes(&self) -> DeviceIdentityBytes {
        DeviceIdentityBytes {
            key_pkcs8_der: self.key_pkcs8_der.clone(),
            cert_der: self.cert_der.clone(),
        }
    }

    /// Live pairing for a given client SPKI (i.e. paired AND not revoked).
    /// `None` ⇒ daemon should reject the connection / command.
    #[must_use]
    pub fn active_pairing(
        &self,
        client_spki: &wake_my_pc_core::crypto::SpkiHash,
    ) -> Option<&PairingRecord> {
        self.pairings
            .iter()
            .find(|p| p.is_active() && p.client_spki == *client_spki)
    }
}

/// Load the keystore from disk and decrypt it. Returns `Ok(None)` if the
/// file does not exist (caller treats this as "fresh install — generate
/// a new identity").
pub async fn load(path: &Path) -> Result<Option<KeystoreContents>, KeystoreError> {
    let cipher = match fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(KeystoreError::Io(e)),
    };

    let plain = platform::decrypt(&cipher).map_err(KeystoreError::Encryption)?;

    let format = match plain.first() {
        Some(&b) => b,
        None => return Err(KeystoreError::Decode("empty plaintext".into())),
    };
    if format != KEYSTORE_FORMAT_VERSION {
        return Err(KeystoreError::FormatVersion {
            got: format,
            expected: KEYSTORE_FORMAT_VERSION,
        });
    }
    let payload = plain.get(1..).unwrap_or(&[]);
    let contents: KeystoreContents =
        postcard::from_bytes(payload).map_err(|e| KeystoreError::Decode(e.to_string()))?;
    debug!("keystore loaded: {} pairings", contents.pairings.len());
    Ok(Some(contents))
}

/// Encrypt + atomically save the keystore. Caller is expected to ensure
/// the parent directory exists (use [`ensure_data_dir`]).
pub async fn save(path: &Path, contents: &KeystoreContents) -> Result<(), KeystoreError> {
    let mut plain = Vec::with_capacity(1 + 1024);
    plain.push(KEYSTORE_FORMAT_VERSION);
    let encoded =
        postcard::to_allocvec(contents).map_err(|e| KeystoreError::Decode(e.to_string()))?;
    plain.extend_from_slice(&encoded);

    let cipher = platform::encrypt(&plain).map_err(KeystoreError::Encryption)?;

    // Atomic write: write to a sibling tempfile then rename over.
    let parent = path
        .parent()
        .ok_or_else(|| KeystoreError::Io(std::io::Error::other("keystore path has no parent")))?;
    let tmp = parent.join(format!("keystore.bin.tmp.{}", std::process::id()));
    fs::write(&tmp, &cipher).await?;
    fs::rename(&tmp, path).await?;
    info!("keystore saved: {} pairings", contents.pairings.len());
    Ok(())
}

/// Make sure the daemon's data directory exists. Cheap on every startup.
pub async fn ensure_data_dir(dir: &Path) -> Result<(), KeystoreError> {
    fs::create_dir_all(dir).await.map_err(KeystoreError::Io)
}
