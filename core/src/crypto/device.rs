//! Per-device identity: Ed25519 keypair + self-signed X.509 cert wrapping it.
//! PROTOCOL.md §6.
//!
//! Generated once at install / first-launch on every device (daemon + each
//! phone). Stored in the platform keystore (Principle 1). Identity is bound
//! to the SPKI hash, not the cert itself — re-issuing a cert under the same
//! key keeps the pin valid.
//!
//! No identifying info goes into the cert subject (Principle 1, CLAUDE.md
//! rule 0). Subject is the static literal `"wake-my-pc-device"`.

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, SignatureAlgorithm};

use super::Error;
use crate::protocol::SpkiHash;

/// In-memory device identity: keypair + DER cert + precomputed SPKI hash.
/// Build via [`Self::generate`] (new install) or [`Self::from_bytes`]
/// (load from keystore).
#[derive(Debug)]
pub struct DeviceIdentity {
    /// PKCS#8 DER private key bytes. Store in platform keystore. **Never log.**
    key_pkcs8_der: Vec<u8>,
    /// X.509 DER cert bytes. Safe to expose at TLS handshake.
    cert_der: Vec<u8>,
    /// SHA-256 of SPKI. Cached; recomputable from `cert_der`.
    spki_hash: SpkiHash,
}

impl DeviceIdentity {
    /// Generate a fresh Ed25519 keypair + matching self-signed cert.
    /// Subject is the static literal `"wake-my-pc-device"`; no SAN, no
    /// identifying fields per Principle 1.
    pub fn generate() -> Result<Self, Error> {
        let key_pair = KeyPair::generate_for(ed25519_alg())
            .map_err(|e| Error::CertGeneration(e.to_string()))?;
        Self::build_from_keypair(key_pair)
    }

    /// Reconstruct an identity from its stored bytes (PKCS#8 DER key + cert
    /// DER). Used at daemon startup and phone app launch when the keystore
    /// already has an identity. Verifies the keypair parses and the cert's
    /// SPKI extracts; does NOT verify cert-key pairing match (rustls
    /// surfaces that at handshake time if it's wrong).
    pub fn from_bytes(bytes: &DeviceIdentityBytes) -> Result<Self, Error> {
        // Parse the keypair as a sanity check — keystore corruption surfaces
        // here rather than at first TLS handshake.
        let _key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls_pki_types::PrivatePkcs8KeyDer::from(bytes.key_pkcs8_der.clone()),
            ed25519_alg(),
        )
        .map_err(|e| Error::IdentityLoad(e.to_string()))?;

        let spki_hash = super::spki::extract_spki_hash(&bytes.cert_der)?;

        Ok(Self {
            key_pkcs8_der: bytes.key_pkcs8_der.clone(),
            cert_der: bytes.cert_der.clone(),
            spki_hash,
        })
    }

    /// PKCS#8 DER private key. Caller stores in keystore; never write to
    /// disk in plaintext.
    #[must_use]
    pub fn key_pkcs8_der(&self) -> &[u8] {
        &self.key_pkcs8_der
    }

    /// X.509 DER cert. Used as the leaf cert in the rustls config.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// SHA-256 of this device's SPKI. Shared at pairing time (in the QR
    /// payload or printed for the 6-digit fallback).
    #[must_use]
    pub const fn spki_hash(&self) -> SpkiHash {
        self.spki_hash
    }

    /// Bytes-form for keystore round-trip.
    #[must_use]
    pub fn to_bytes(&self) -> DeviceIdentityBytes {
        DeviceIdentityBytes {
            key_pkcs8_der: self.key_pkcs8_der.clone(),
            cert_der: self.cert_der.clone(),
        }
    }

    fn build_from_keypair(key_pair: KeyPair) -> Result<Self, Error> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| Error::CertGeneration(e.to_string()))?;
        // Static subject CN per Principle 1: do not embed hostname / user
        // / device-name in the cert. The cert's only purpose is to wrap
        // the keypair for TLS; SPKI pin is the identity.
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "wake-my-pc-device");

        let certificate = params
            .self_signed(&key_pair)
            .map_err(|e| Error::CertGeneration(e.to_string()))?;

        let cert_der = certificate.der().as_ref().to_vec();
        let spki_hash = super::spki::extract_spki_hash(&cert_der)?;
        let key_pkcs8_der = key_pair.serialize_der();

        Ok(Self {
            key_pkcs8_der,
            cert_der,
            spki_hash,
        })
    }
}

/// Serialized device identity. Two byte blobs intended for keystore storage:
/// the private key (sensitive) and the cert (public). Caller composes them
/// in whatever container the platform keystore wants.
#[derive(Clone, Debug)]
pub struct DeviceIdentityBytes {
    /// PKCS#8 DER private key bytes.
    pub key_pkcs8_der: Vec<u8>,
    /// X.509 DER cert bytes.
    pub cert_der: Vec<u8>,
}

const fn ed25519_alg() -> &'static SignatureAlgorithm {
    &PKCS_ED25519
}
