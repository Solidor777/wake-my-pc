//! SubjectPublicKeyInfo (SPKI) extraction + hashing. PROTOCOL.md §6: the pin
//! is SHA-256 over the DER-encoded SPKI of the leaf cert. CA chain, hostname,
//! expiry — all unused.
//!
//! Why SPKI rather than full-cert hash: re-issuing the same key under a new
//! self-signed cert produces a new full-cert hash but the same SPKI hash.
//! Locking the pin to the SPKI lets us re-issue the cert (e.g. after expiry,
//! though we don't enforce expiry) without requiring re-pairing.

use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use super::Error;
use crate::protocol::SpkiHash;

/// Compute SHA-256 over the DER-encoded SPKI bytes provided directly.
/// The caller already extracted the SPKI block (e.g. from a known-good cert).
#[must_use]
pub fn compute_spki_hash(spki_der: &[u8]) -> SpkiHash {
    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SpkiHash(out)
}

/// Parse an X.509 certificate (DER) and return the SHA-256 of its SPKI.
/// Used at three points:
///   - device-identity setup (compute our own pin to share at pairing),
///   - rustls cert verifier (compute peer's pin to compare against pinset),
///   - QR / 6-digit pairing display (render hex of pin to user).
pub fn extract_spki_hash(cert_der: &[u8]) -> Result<SpkiHash, Error> {
    let (_rest, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| Error::X509Parse(format!("{e}")))?;
    let spki_der = cert.tbs_certificate.subject_pki.raw;
    Ok(compute_spki_hash(spki_der))
}
