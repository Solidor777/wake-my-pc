//! SPKI-pinning rustls verifiers. PROTOCOL.md §6.
//!
//! Both verifiers ignore CA chain, hostname, expiry, OCSP. The only check
//! that matters is: does the leaf cert's SPKI hash appear in our pinset?
//! Handshake signature verification still uses rustls's default Ed25519
//! support (delegated to `rustls::crypto::verify_tls13_signature`).
//!
//! `PinSet` is `Arc`-shared and immutable per TLS-config build. To hot-add
//! a pairing the daemon (M2) rebuilds the rustls config — fine on the
//! pairing path which is rare.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};

use super::spki::extract_spki_hash;
use crate::protocol::SpkiHash;

/// Immutable set of pinned SPKIs. `BTreeSet` rather than `HashSet` for
/// deterministic iteration in tests + audit logs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PinSet {
    pins: BTreeSet<SpkiHash>,
}

impl PinSet {
    /// Empty pinset. Useful as a starting point for daemon startup before
    /// any pairings are loaded.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from an iterator of pins. Used by daemon at startup
    /// after loading pairings from the keystore.
    pub fn with_pins<I: IntoIterator<Item = SpkiHash>>(iter: I) -> Self {
        Self {
            pins: iter.into_iter().collect(),
        }
    }

    /// Returns `true` if `pin` is in the set.
    #[must_use]
    pub fn contains(&self, pin: &SpkiHash) -> bool {
        self.pins.contains(pin)
    }

    /// Number of pinned identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// `true` if no pins are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// Iterate over pins. Order is sorted (BTree property).
    pub fn iter(&self) -> impl Iterator<Item = &SpkiHash> {
        self.pins.iter()
    }
}

/// rustls server-cert verifier that approves only pinned daemon SPKIs.
/// Used by clients (phones, desktop-ui) to authenticate the daemon.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    pinset: Arc<PinSet>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl PinnedServerVerifier {
    /// Build a verifier from a pinset and the rustls crypto provider whose
    /// signature schemes will be used to validate the handshake signature.
    /// Pass `provider = rustls::crypto::ring::default_provider()` (or its
    /// `Arc`-shared form via [`CryptoProvider::get_default`]).
    #[must_use]
    pub fn new(pinset: Arc<PinSet>, provider: &CryptoProvider) -> Self {
        Self {
            pinset,
            supported_algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let pin = extract_spki_hash(end_entity.as_ref())
            .map_err(|e| rustls::Error::General(format!("spki extract: {e}")))?;
        if self.pinset.contains(&pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server SPKI not pinned".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.2 is rejected at config time (`min_version = TLS13`); this
        // is required by the trait but should never be called.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// rustls client-cert verifier that approves only pinned client SPKIs.
/// Used by the daemon to authenticate phones / desktop-ui clients.
///
/// Two construction modes:
/// - [`Self::pinned`] — the running mode; only listed clients pass.
/// - [`Self::pairing_window`] — used only inside [`super::PairingHandshake`]
///   when the daemon is actively in `Awaiting` state. Accepts any client
///   cert (the SPKI is captured at the protocol layer instead, gated by
///   the one-time `pairing_code`).
#[derive(Debug)]
pub struct PinnedClientVerifier {
    mode: VerifierMode,
    supported_algs: WebPkiSupportedAlgorithms,
}

#[derive(Debug)]
enum VerifierMode {
    Pinned(Arc<PinSet>),
    PairingWindow,
}

impl PinnedClientVerifier {
    /// Production verifier — only clients with SPKIs in `pinset` pass.
    #[must_use]
    pub fn pinned(pinset: Arc<PinSet>, provider: &CryptoProvider) -> Self {
        Self {
            mode: VerifierMode::Pinned(pinset),
            supported_algs: provider.signature_verification_algorithms,
        }
    }

    /// Pairing-window verifier — accepts any TLS-valid client cert. Used
    /// only by [`super::PairingHandshake`]; the application layer rejects
    /// the connection if `Pair{pairing_code}` doesn't match.
    #[must_use]
    pub fn pairing_window(provider: &CryptoProvider) -> Self {
        Self {
            mode: VerifierMode::PairingWindow,
            supported_algs: provider.signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match &self.mode {
            VerifierMode::Pinned(pinset) => {
                let pin = extract_spki_hash(end_entity.as_ref())
                    .map_err(|e| rustls::Error::General(format!("spki extract: {e}")))?;
                if pinset.contains(&pin) {
                    Ok(ClientCertVerified::assertion())
                } else {
                    Err(rustls::Error::General("client SPKI not pinned".into()))
                }
            }
            VerifierMode::PairingWindow => {
                // Validate the cert parses cleanly (catches obvious junk),
                // but do NOT pin-check. The pairing-code check at the
                // protocol layer is what gates this path.
                extract_spki_hash(end_entity.as_ref())
                    .map_err(|e| rustls::Error::General(format!("spki extract: {e}")))?;
                Ok(ClientCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}
