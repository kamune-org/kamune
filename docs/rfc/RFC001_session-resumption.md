# RFC: Session Resumption

**Status:** Draft — for discussion, not yet merged into SPEC.md

**Target:** Kamune Protocol Specification v0.6.0

**Relates to:** §6 (Protocol Flow), §7 (Encryption and Key Derivation),
§11 (Storage and Persistence)

---

## 1. Abstract

This RFC proposes a session resumption mechanism that allows two peers to
re-establish a previously authenticated session without re-running the
Introduction phase, while still performing a full, fresh cryptographic
handshake.

Resumption is **not** a lightweight reconnect of a live session. The `Transport`
object and all its in-memory state (ciphers, sequence counters, ratchet state)
are destroyed whenever the underlying connection drops, for any reason.
Resumption is a **new session** — new MLKEM exchange, new symmetric keys, new
sequence numbers from 1 — distinguished from a cold Introduction only by:

1. Skipping the remote-verifier callback (the peer is already known), and
2. Reusing the original session ID, so the message log continues in the same
   storage bucket instead of starting a new one.

Resumption tokens are derived solely from the initial MLKEM shared secret.

## 2. Motivation

Today, any dropped connection — Wi-Fi blip, app backgrounding, server restart —
forces the full Introduction → Handshake → Challenge flow, including the
interactive peer-verification prompt (§6.2, step 2 of the spec). For two peers
who have already verified each other, this is unnecessary friction on every
reconnect.

## 3. Terminology

| Term                  | Definition                                                                                          |
| --------------------- | --------------------------------------------------------------------------------------------------- |
| **Resumption Root**   | A per-session secret derived once at handshake completion, used solely to derive resumption tokens. |
| **Resumption Token**  | A single-use 32-byte value derived from the Resumption Root; presented to authorize resumption.     |
| **Resumption Window** | The time period after a session's establishment during which its tokens remain valid.               |

## 4. Token Derivation

At the end of every successful Challenge Exchange (§6.4) — i.e. when a session
enters `Established` — both peers independently derive:

```
resumptionRoot = HKDF-SHA512(sharedSecret, sessionID, "kamune/resumption-root/v1")

token_n = HKDF-SHA512(resumptionRoot, nil, "kamune/resumption/token/" || uint32_be(n))
  for n in [0, N)
```

Where `sharedSecret` is the MLKEM768 shared secret from _that session's_
handshake (§6.3), and `N` is the configured token count (see §10).

Both sides compute the same `N` tokens without any additional message exchange —
this mirrors the existing pattern where challenge tokens (§7.3) are derived
independently rather than transmitted.

## 5. Token Lifecycle

- **Single-use, any-order.** Each token may be consumed exactly once. There is
  no requirement to consume `token_0` before `token_1`. This avoids a
  synchronization hazard: if a resumption completes on one side before the
  other side's "advance to next token" state update is durable, a
  sequence-enforced scheme could desync. An any-order, mark-on-use scheme has no
  such dependency.
- **Regeneration on success.** When a resumption completes (i.e. the resumed
  session reaches `Established`), both peers discard the entire previous token
  set and derive a fresh set of `N` tokens from the new session's shared secret,
  per §4. This gives the token mechanism forward secrecy: a token stolen from
  session _k_ is worthless after session _k+1_'s handshake completes, since it
  isn't derivable from the new shared secret.
- **Expiration.** A session's tokens become invalid after the Resumption
  Window elapses from the session's `Established` timestamp, regardless of
  how many tokens remain unused. A session with no unused tokens, or past its
  window, is **unresumeable** — the peer must fall back to a full Introduction.

## 6. New Routes

Two routes are added, continuing the existing enum (§5):

```
ROUTE_RESUME_REQUEST = 11;  // Initiator -> Responder
ROUTE_RESUME_ACCEPT  = 12;  // Responder -> Initiator
```

Both are sent inside the HPKE-encrypted tunnel established during the
Exchange phase (§6.1) — the same tunnel that already protects Introduction
and Handshake messages. The raw token value is therefore never sent in the
clear.

```
ResumeRequest {
  string SessionID = 1;   // the original session ID being resumed
  bytes  Token      = 2;  // one unused resumption token for that session
}

ResumeAccept {
  bool   Accepted = 1;
  string Reason   = 2;    // populated only when Accepted == false
}
```

### 6.1 Responder Validation

On receiving `ResumeRequest`, the responder:

1. Looks up `SessionID` in persistent storage. If not found, reject.
2. Checks the resumption window hasn't elapsed. If expired, reject.
3. Checks `Token` is present in the unused token set for that session. If not
   found (already used, or never valid), reject.
4. On success: marks the token used, sends `ResumeAccept{Accepted: true}`,
   and proceeds directly into the Handshake phase (SPEC.md§9) — **skipping the
   Introduction phase and the remote-verifier callback entirely.**
5. On any rejection: sends `ResumeAccept{Accepted: false, Reason: ...}` and the
   connection falls back to a normal Introduction flow (§6.2), subject to the
   application's own retry policy.

## 7. Protocol Flow

```
Initiator                                   Responder
    |                                            |
    |  ------- Exchange (HPKE tunnel) -------->  |   (§6.1, unchanged)
    |                                            |
    |  ---- SignedTransport[RESUME_REQUEST] -->  |
    |        ResumeRequest {                     |
    |          SessionID: <original ID>          |
    |          Token: token_n                    |
    |        }                                   |
    |                                            |
    |  <--- SignedTransport[RESUME_ACCEPT] ----  |
    |        ResumeAccept { Accepted: true }     |
    |                                            |
    |  ---- SignedTransport[REQUEST_HS] ------>  |   (§6.3, SessionKey
    |        Handshake {                         |    fields carry the
    |          SessionKey: <original prefix>     |    ORIGINAL prefix/
    |        }                                   |    suffix instead of
    |                                            |    fresh random ones)
    |  <--- SignedTransport[ACCEPT_HS] --------  |
    |        Handshake {                         |
    |          SessionKey: <original suffix>     |
    |        }                                   |
    |                                            |
    |  ============ Challenge Exchange =======>  |   (§6.4, unchanged)
    |                                            |
    |       [Both: Established]                  |
    |       [Both: regenerate token set]         |
```

Everything from the Handshake phase onward is **identical** to a cold session:
fresh MLKEM ephemeral keys, fresh symmetric ciphers, sequence numbers from 1.
The only structural difference from §6.3 is that `SessionKey` is predetermined
rather than randomly generated by each side, so the resulting `sessionID`
matches the one being resumed.

## 8. Session ID Semantics

The session ID continues to mean exactly what it means today: the cryptographic
handle for one Transport's lifetime, assembled from prefix + suffix (§6.3).
Resumption does not change this — it just lets both sides agree on its value in
advance instead of generating it randomly.

The practical effect of the shared session ID is purely at the storage layer:
the application's session message log (§11.3) keys on session ID, so messages
from the resumed session append to the same log entry rather than opening a new
one.

## 9. Storage and Persistence

New per-session stored state, encrypted under the DEK like all other sensitive
entities (§11.2):

| Field           | Type         | Notes                                   |
| --------------- | ------------ | --------------------------------------- |
| `sessionID`     | string       | Key for this record.                    |
| `unusedTokens`  | set of bytes | Remaining single-use resumption tokens. |
| `establishedAt` | timestamp    | Start of the resumption window.         |

The `resumptionRoot` itself does not need to be stored — only the derived token
set, since tokens are derived once at `Established` and never re-derived from
the root later. This limits exposure: a stored-data compromise reveals only the
remaining unused tokens for sessions within their window, not a generator
capable of producing tokens for future sessions.

## 10. Security Considerations

**Token confidentiality.** Tokens are 32-byte HKDF-SHA512 outputs, transmitted
only inside the HPKE-encrypted Exchange tunnel. Brute-forcing a valid token is
computationally infeasible.

**What a stolen token does _not_ grant.** Token + session ID together authorize
establishing a transport and skipping the verifier callback. They do **not**
allow forging application messages, since every message remains signed with the
sender's long-term Ed25519 identity key (§6.5, §8.1). An attacker holding a
stolen token cannot impersonate the peer's _replies_ in a way the victim would
accept.

**What a stolen token _does_ grant.** If an attacker possesses both the session
ID and an unused token (practically: has compromised the local encrypted
database and its passphrase), they can complete a resumption as the known peer.
The victim, believing they're reconnecting to their contact, would encrypt
messages to the attacker's session keys — one-directional eavesdropping on
future messages until the legitimate peer also reconnects and the mismatch
becomes apparent through normal session identity checks.

This scenario requires the same compromise (DB + passphrase) that already
exposes the full plaintext message history via the DEK (§11.2). Resumption
tokens add a narrow, forward-looking exposure window on top of an already-
total compromise; they do not introduce a new compromise category. The existing
DB encryption hierarchy remains the actual security boundary — this RFC doesn't
change that, and no further mitigation is proposed here beyond what §11.2
already provides.

**Forward secrecy of tokens.** Regenerating the entire token set on every
successful resumption (§7) means a token compromised from session _k_ cannot be
used once session _k+1_ exists, since it isn't derivable from the new shared
secret.

## 11. New Error Conditions

To be added to §14:

| Condition                                                     | Action                                                      |
| ------------------------------------------------------------- | ----------------------------------------------------------- |
| `ResumeRequest.SessionID` does not match any stored session.  | `ResumeAccept{Accepted: false}`; fall back to Introduction. |
| The resumption window has elapsed for the referenced session. | `ResumeAccept{Accepted: false}`; fall back to Introduction. |
| The presented token is not in the session's unused token set. | `ResumeAccept{Accepted: false}`; fall back to Introduction. |
| A session has no unused tokens remaining.                     | Surfaced as unresumable; caller must use Introduction.      |

## 12. Open Questions

1. **Token count `N`.** Needs a concrete default. Given that every reconnect —
   including brief network blips — consumes a token, a small count (e.g. 5)
   risks exhaustion under flaky connectivity. A larger count (proposed range:
   20–50) trades a small amount of storage for resilience.
2. **Resumption window duration.** How long should tokens remain valid after
   `Established`? Needs to balance reconnect convenience against the exposure
   window discussed in §10.
3. **Rate limiting / probing resistance.** Should repeated failed `ResumeRequest`
   attempts against a given session ID be throttled, to harden against an
   attacker who has the session ID but not a valid token from blindly probing?
   Token brute-force itself is computationally infeasible, so this is a
   defense-in-depth question rather than a structural requirement.
4. **Role assignment on resumption.** Either peer may initiate the new
   connection regardless of their role in the original session. Confirm this is
   fine as-is (no constraint needed), since the Handshake phase doesn't care
   which side originally was initiator vs. responder, only that both sides agree
   on the resulting session ID.
