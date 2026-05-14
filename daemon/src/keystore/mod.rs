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
use crate::pairings::{PairingRecord, PairingRecordV1};

/// Format byte at the head of every keystore file. Bumped on
/// wire-incompatible plaintext-layer changes.
///
/// - **v1** (M2 baseline): pre-`last_known_address`. Read with
///   [`PairingRecordV1`]; migrated to v2 in-memory on load.
/// - **v2** (2026-05-08): adds [`PairingRecord::last_known_address`]
///   for the uninstall-time Revoke broadcast.
pub const KEYSTORE_FORMAT_VERSION: u8 = 2;

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
    let payload = plain.get(1..).unwrap_or(&[]);

    let contents = match format {
        1 => {
            // Migrate v1 → v2: PairingRecord gains `last_known_address`,
            // initialized to `None`. KeystoreContents itself is layout-
            // compatible across the two versions; only the pairings
            // vector type differs.
            let v1: KeystoreContentsV1 =
                postcard::from_bytes(payload).map_err(|e| KeystoreError::Decode(e.to_string()))?;
            info!("keystore on disk is v1; migrating to v{KEYSTORE_FORMAT_VERSION} in-memory");
            KeystoreContents::from(v1)
        }
        2 => postcard::from_bytes(payload).map_err(|e| KeystoreError::Decode(e.to_string()))?,
        other => {
            return Err(KeystoreError::FormatVersion {
                got: other,
                expected: KEYSTORE_FORMAT_VERSION,
            });
        }
    };
    debug!("keystore loaded: {} pairings", contents.pairings.len());
    Ok(Some(contents))
}

/// v1 plaintext layout. Used only by [`load`] to migrate older
/// keystores forward; never written.
#[derive(Deserialize)]
struct KeystoreContentsV1 {
    key_pkcs8_der: Vec<u8>,
    cert_der: Vec<u8>,
    pairings: Vec<PairingRecordV1>,
    reauth_interval_days: u8,
    last_authenticated_at_unix_ms: u64,
}

impl From<KeystoreContentsV1> for KeystoreContents {
    fn from(v: KeystoreContentsV1) -> Self {
        Self {
            key_pkcs8_der: v.key_pkcs8_der,
            cert_der: v.cert_der,
            pairings: v.pairings.into_iter().map(PairingRecord::from).collect(),
            reauth_interval_days: v.reauth_interval_days,
            last_authenticated_at_unix_ms: v.last_authenticated_at_unix_ms,
        }
    }
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

#[cfg(test)]
mod tests {
    //! Coverage focuses on the v1 → v2 migration path and the
    //! last_known_address roundtrip. Exercises `platform::encrypt` /
    //! `platform::decrypt` end-to-end (real DPAPI on Windows).

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::net::SocketAddr;

    use serde::Serialize;
    use wake_my_pc_core::crypto::{DeviceIdentity, SpkiHash};

    use super::*;

    /// v1-shape KeystoreContents for synthesizing legacy keystores in
    /// tests. Mirrors the on-disk v1 layout exactly.
    #[derive(Serialize)]
    struct KeystoreContentsV1Wire {
        key_pkcs8_der: Vec<u8>,
        cert_der: Vec<u8>,
        pairings: Vec<PairingRecordV1Wire>,
        reauth_interval_days: u8,
        last_authenticated_at_unix_ms: u64,
    }

    #[derive(Serialize)]
    struct PairingRecordV1Wire {
        phone_name: String,
        client_spki: SpkiHash,
        paired_at_unix_ms: u64,
        last_authenticated_at_unix_ms: u64,
        revoked: bool,
        revoke_pending: bool,
    }

    #[tokio::test]
    async fn v1_keystore_loads_with_last_known_address_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.bin");

        let identity = DeviceIdentity::generate().unwrap();
        let v1 = KeystoreContentsV1Wire {
            key_pkcs8_der: identity.to_bytes().key_pkcs8_der,
            cert_der: identity.to_bytes().cert_der,
            pairings: vec![PairingRecordV1Wire {
                phone_name: "legacy-phone".into(),
                client_spki: SpkiHash([0x42; 32]),
                paired_at_unix_ms: 1_000,
                last_authenticated_at_unix_ms: 1_000,
                revoked: false,
                revoke_pending: false,
            }],
            reauth_interval_days: 7,
            last_authenticated_at_unix_ms: 0,
        };

        // Hand-write a format-byte-1 plaintext + encrypt + drop on disk.
        let mut plain = vec![1u8];
        plain.extend_from_slice(&postcard::to_allocvec(&v1).unwrap());
        let cipher = super::platform::encrypt(&plain).unwrap();
        tokio::fs::write(&path, &cipher).await.unwrap();

        let loaded = load(&path).await.unwrap().expect("v1 keystore loads");
        assert_eq!(loaded.pairings.len(), 1);
        assert_eq!(loaded.pairings[0].phone_name, "legacy-phone");
        // Migration default for the new field.
        assert_eq!(loaded.pairings[0].last_known_address, None);
    }

    #[tokio::test]
    async fn last_known_address_round_trips_through_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.bin");

        let identity = DeviceIdentity::generate().unwrap();
        let mut contents = KeystoreContents::from_identity(&identity.to_bytes());
        let addr: SocketAddr = "192.168.1.42:51820".parse().unwrap();
        contents.pairings.push(PairingRecord {
            phone_name: "kitchen-phone".into(),
            client_spki: SpkiHash([0x11; 32]),
            paired_at_unix_ms: 5_000,
            last_authenticated_at_unix_ms: 5_000,
            revoked: false,
            revoke_pending: false,
            last_known_address: Some(addr),
        });

        save(&path, &contents).await.unwrap();
        let loaded = load(&path).await.unwrap().unwrap();

        assert_eq!(loaded.pairings.len(), 1);
        assert_eq!(loaded.pairings[0].last_known_address, Some(addr));
    }

    #[tokio::test]
    async fn unsupported_format_byte_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keystore.bin");

        let plain = vec![99u8, 0, 1, 2]; // bogus future format
        let cipher = super::platform::encrypt(&plain).unwrap();
        tokio::fs::write(&path, &cipher).await.unwrap();

        match load(&path).await {
            Err(KeystoreError::FormatVersion { got, expected }) => {
                assert_eq!(got, 99);
                assert_eq!(expected, KEYSTORE_FORMAT_VERSION);
            }
            other => panic!("expected FormatVersion error, got {other:?}"),
        }
    }
}
