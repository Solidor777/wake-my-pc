# Wire Protocol v1 (DRAFT)

Status: **draft, unfrozen.** Freezes at **v1.0** at start of M4 (mobile = second consumer; PRINCIPLES.md §4).

Source of truth for `core::protocol` and `core::crypto`. Implementation keys off this doc; doc updates lead, code follows.

---

## 1. Layering

```
+----------------------------------------+
| application: ClientFrame / DaemonFrame |  <- §3, §5  (postcard)
+----------------------------------------+
| framing: u32 len + Envelope            |  <- §4
+----------------------------------------+
| TLS 1.3 (mutual auth, SPKI-pinned)     |  <- §6
+----------------------------------------+
| TCP                                    |
+----------------------------------------+
```

TLS does handshake, AEAD, KDF, record-layer replay. The protocol layer adds:
- a versioned envelope (forward-compat),
- a monotonic per-direction nonce (defense in depth + cross-session replay),
- typed message enums encoded with [postcard](https://docs.rs/postcard) (compact, deterministic, serde-based, no_std).

**Wake is not a protocol message.** A sleeping/off PC has no daemon listening; wake is a Wake-on-LAN magic packet sent UDP/9 broadcast (M3, `core::wol`). Locked decision (PLAN.md).

**Unlock is not in v1.0.** Reserved opcode `0x10` left unused; lands in M11 post-v1.

---

## 2. Versioning

- Single `u8` version byte at the head of every Envelope (§4).
- v1 = `0x01`. Unknown version → receiver responds with `VersionMismatch` (§7) and closes.
- v1.x is wire-compatible: only additive changes (new optional message variants, new error codes). Wire-breaking changes bump the major version → new envelope tag → new connection-establishment path.
- Receivers MUST reject unknown enum variants in v1 with `Unsupported` rather than silently dropping the frame.

---

## 3. Message catalogue

### Client → Daemon (`ClientFrame`)

| Variant         | Tag (postcard) | Purpose                                                                                                                                       |
|-----------------|----------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `Pair`          | 0              | First-contact pairing message. Carries `phone_name` (`String<=64`), `pairing_code` (`u32`, see §8). Sent only during pairing handshake (§8). |
| `Sleep`         | 1              | Request daemon to put PC to sleep.                                                                                                            |
| `Lock`          | 2              | Request daemon to lock the active session. v1 is one-way (no remote unlock).                                                                 |
| `PowerOff`      | 3              | Request daemon to shut down PC.                                                                                                               |
| `StateProbe`    | 4              | Request a fresh `StateReport` (§5). Idempotent.                                                                                              |
| `ReauthStatus`  | 5              | Query re-auth window: returns `last_authenticated_at`, `interval_days`, `expires_at`.                                                         |
| `ReauthConfig`  | 6              | Set `pc_reauth_interval_days` (`Off | OneDay | SevenDays | ThirtyDays`). Triggers credential prompt on daemon if interval shortens past now.  |
| `RevokeAck`     | 7              | Acknowledges a daemon-pushed `Revoke` (§5). Phone has wiped its pairing.                                                                      |

### Daemon → Client (`DaemonFrame`)

| Variant         | Tag (postcard) | Purpose                                                                                                                                                                                                |
|-----------------|----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `Ack`           | 0              | Generic positive acknowledgement for state-changing commands. Carries the `request_nonce` echoed back so the client can correlate.                                                                     |
| `StateReport`   | 1              | 5-state enum (§5). Sent unsolicited on state change AND in response to `StateProbe`.                                                                                                                   |
| `Revoke`        | 2              | Daemon-initiated pairing revocation. Carries `daemon_spki_hash` and a fresh `revoke_nonce` so the client can verify it came from the right daemon. Client wipes pairing and returns `RevokeAck`.       |
| `Error`         | 3              | Typed error response. Always includes `request_nonce` (or `0` if uncorrelatable).                                                                                                                      |
| `ReauthInfo`    | 4              | Response to `ReauthStatus`. Mirrors §3.                                                                                                                                                                |

Reserved tags: `0x10` (Unlock, M11), `0x20–0x2F` (M7 internet wake), `0x30+` (future). Implementations MUST reject unknown tags as `Unsupported` per §2.

---

## 4. Framing

Each direction is a stream of length-prefixed frames over the TLS connection.

```
frame := len:u32 (big-endian) || envelope:[u8; len]
envelope := version:u8 || nonce:u64 (big-endian) || payload:[u8]
payload := postcard(ClientFrame | DaemonFrame)
```

Constants:
- `MAX_FRAME_LEN = 65_536` bytes (envelope size, not counting the len prefix). Frames over this are rejected with `MalformedFrame` and the connection closed.
- `MIN_FRAME_LEN = 1 (version) + 8 (nonce) + 1 (smallest postcard discriminant) = 10` bytes.

Receivers parse defensively: any bytes beyond `len` after a successful decode close the connection with `MalformedFrame` (Principle 2). Truncated frames at EOF return `Eof`, not panic.

---

## 5. Nonces & replay

Each direction maintains an independent monotonic `u64` send counter, both starting at `0` at session establishment (post-TLS-handshake).

- Sender: pre-increment, then send. First frame's `nonce = 1`.
- Receiver: tracks `last_seen` (init `0`). Frame is accepted iff `nonce > last_seen`. On accept, `last_seen ← nonce`.
- Out-of-order delivery is impossible over TLS (record layer is in-order); strict-monotonic is therefore safe and the simplest invariant.
- Wraparound is not a concern: u64 at 1 frame/ms = 584 million years.

Cross-session: nonce state is per-session and discarded on disconnect. TLS resumption is **not used** in v1 (rustls config: `resumption: ResumptionStore::disabled()`); every reconnect = fresh handshake = fresh `last_seen = 0`. This eliminates a class of cross-session replay risk at the cost of one extra handshake per reconnect — acceptable on a one-button-LAN-app.

`Revoke` carries its own `revoke_nonce` (separate u64) so a captured Revoke from a prior session can't be replayed at the phone.

---

## 6. Transport & auth

TLS 1.3 mutual authentication via [rustls](https://docs.rs/rustls). Crypto provider = `ring` (default; not aws-lc-rs — overkill for owner-only-LAN per security review).

Both sides:
- Generate one Ed25519 keypair at install/first-launch ([ed25519-dalek](https://docs.rs/ed25519-dalek)).
- Wrap it in a self-signed X.509 cert via [rcgen](https://docs.rs/rcgen). Cert has no CA path, no expiry-based trust — only the SPKI is used.

**SPKI pinning, not CA validation.** A custom `ServerCertVerifier` and `ClientCertVerifier` extract the leaf cert's `SubjectPublicKeyInfo`, hash it with SHA-256, and compare against the pinned hash stored at pairing time. CA chain, hostname, expiry — all unused. The pin is the auth.

Pinning lookup:
- Client side: one pinned daemon SPKI per pairing (post-§8).
- Daemon side: a set of pinned client SPKIs, one per active (non-revoked) pairing.

A connection where either side fails SPKI lookup is dropped at the TLS handshake; no application bytes flow. From the client's perspective this surfaces as a `NotPaired` connection error at `core::transport` (M2); from the daemon's perspective, a logged audit event.

Cipher suite: rustls's default TLS 1.3 set (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256). No TLS 1.2 fallback — `min_version = TLS_1_3` (PRINCIPLES.md §1: "no plaintext fallback, no downgrade path").

---

## 7. Error codes

`enum ProtocolError`:

| Code              | Meaning                                                              | Connection closes? |
|-------------------|----------------------------------------------------------------------|--------------------|
| `NotPaired`       | Client SPKI not in daemon's pairing set.                             | yes                |
| `Revoked`         | Pairing was revoked (`revoked = true`).                              | yes                |
| `RequiresReauth`  | Daemon is in `NeedsReauth` state; only `ReauthStatus` is allowed.    | no                 |
| `VersionMismatch` | Envelope version not understood.                                     | yes                |
| `MalformedFrame`  | Length / encoding / bounds violation.                                | yes                |
| `NonceReplay`     | Nonce ≤ `last_seen`.                                                 | yes                |
| `Unsupported`     | Known version, unknown message tag.                                  | no                 |
| `Internal`        | Daemon-side failure that isn't the client's fault. Carries no detail (Principle 1: no info leakage in errors). | no |

`Error` frames carry `request_nonce: u64` to correlate back to the offending request, plus `code: ProtocolError`. No free-form strings — Principle 1's no-info-leak rule rules out variable error text on the wire.

---

## 8. Pairing handshake

Pairing is the only flow that creates new SPKI pins. Out-of-band (QR or 6-digit) is required because TLS pinning bootstraps from a pre-shared identity.

**State machine** (`core::crypto::pairing`):

```
Idle ──advertise()──▶ Awaiting ──Pair{code}──▶ Paired
                          │ │
                          │ └─wrong code ×N or out-of-range ×N──▶ Idle
                          └──timeout (5 min)──▶ Idle
```

**QR path** (default):

QR payload (postcard-encoded, base32-rendered):
```text
struct QrPayload {
    daemon_spki: [u8; 32],     // SHA-256 of daemon SPKI
    lan_hint: SocketAddrV4,    // first-guess address; mDNS still authoritative
    pairing_code: u32,         // 6-digit (0..1_000_000); valid only this Awaiting window
    phone_name_hint: Option<String>, // optional; daemon may suggest from device name
}
```

1. User runs `wake-my-pc-daemon pair`. Daemon generates fresh 6-digit `pairing_code` (rejection-sampled from `getrandom` to avoid modulo bias), advertises mDNS (`_wake-my-pc._tcp.local`), prints QR + the same 6-digit code (zero-padded) to stdout. The displayed code and the wire `pairing_code` field are the same value — there is no separate "internal" representation.
2. Phone scans QR → pins `daemon_spki` immediately → connects via TLS to `lan_hint` (or mDNS).
3. TLS handshake: phone verifies daemon SPKI against pin from QR. Daemon, in `Awaiting` state, accepts any client SPKI for now (it's about to learn one).
4. Phone sends `ClientFrame::Pair { phone_name, pairing_code }` as the first application frame.
5. Daemon verifies `pairing_code` is in range AND matches the in-window value → records `(client_spki, phone_name, paired_at = now, last_authenticated_at = now)` → transitions to `Paired` → returns `DaemonFrame::Ack`.
6. Daemon disarms pairing window. Subsequent connections from this client are normal-flow auth'd commands.

**6-digit fallback** (headless daemon, no QR display):

The daemon prints the 6-digit `pairing_code` and the SPKI hash hex. The phone:

1. User picks "Enter manually" on phone, types the 6-digit code AND the SPKI hash.
2. Phone pins SPKI hash from manual entry, then proceeds as steps 2–6 above.

**Brute-force bound (state-machine-enforced):**
- Per-window attempt budget: `MAX_PAIRING_ATTEMPTS = 5`. Wrong-code rejections (and out-of-range codes — values `>= 1_000_000`) increment the counter; hitting the cap forces the state machine to `Idle` and the user must re-run `daemon-cli pair`.
- 5 guesses against a 10⁶ search space ⇒ ≤ 5×10⁻⁶ success per window, regardless of how fast the attacker can probe within the 5-minute TTL. Caller (M2 daemon) does not need to add additional rate limiting; defaults are sound out of the box.

**Cryptographic strength:**
- QR path: pin is the full 256-bit SHA-256. MITM at pairing time would need to forge the QR display — physical-access threat, out of scope.
- 6-digit fallback alone (without SPKI hash entry): not supported. The 6-digit code is a one-time pairing PIN, NOT a hash commitment. Without the SPKI hash typed in, an active LAN MITM could substitute their own cert. v1 requires the SPKI alongside the 6-digit code in the headless path. The home-LAN threat model accepts this — most users use the QR path.

The pairing window expires after 5 minutes, after `MAX_PAIRING_ATTEMPTS` failures, or one accepted `Pair` (whichever first). A subsequent pairing requires a fresh `daemon-cli pair`.

---

## 9. Re-auth interaction

`ReauthStatus`/`ReauthInfo` and `ReauthConfig` are protocol-level surfaces for the M2 daemon-side state machine and M4 phone-side timer. The protocol contributes:

- `ReauthStatus → ReauthInfo { last_authenticated_at: u64 (unix ms), interval_days: ReauthInterval, expires_at: u64 (unix ms) }`.
- `ReauthConfig { interval: ReauthInterval }` → `Ack` on success.
- `ReauthInterval` enum: `Off | OneDay | SevenDays | ThirtyDays`.
- When daemon is in `NeedsReauth`, it responds to `Sleep`/`Lock`/`PowerOff` with `Error { code: RequiresReauth, .. }`. `ReauthStatus` and `RevokeAck` still succeed.

Behavior of credential prompts (Windows Hello, Touch ID, polkit) is daemon-local — not in protocol scope.

---

## 10. KAT vectors

`core/tests/kat.rs` (M1 task #6) ships a frozen set: one valid encoding per variant, tested both ways (`encode → match bytes`, `bytes → decode → match struct`). Vectors are committed verbatim — any wire change without bumping the version byte must fail the KAT, surfacing the breakage at PR review.

KAT vectors are deliberately hand-rolled, not regenerated from the encoder, so a buggy encoder cannot rubber-stamp itself.

---

## 11. Out of scope for v1.0

- `Unlock` opcode (M11 post-v1).
- TLS 1.2 / cipher negotiation (locked: TLS 1.3 only).
- Internet-side wake / NAT traversal (M7).
- Multi-phone authorization model beyond per-pairing pin (M9).
- Compression (no zip-bomb surface; messages are tiny anyway).
- Streaming responses (every request is one-shot request/response except `StateReport` which can also push unsolicited).
