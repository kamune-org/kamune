# RFC: Extend Signature Coverage to Metadata

**Status:** Draft

**Target:** Kamune Protocol Specification v0.7.0

**Relates to:** §8.4 (Multi-Layer Integrity), §12.2 (Integrity)

## 1. Summary

Extend the `SignedTransport.Signature` field to cover `Metadata` in addition to
`Data`. Currently the Ed25519 signature authenticates only the inner message
bytes; `Metadata` (message ID, timestamp, sequence number, route) is
structurally present in the same envelope but is not itself signed.

## 2. Current Behavior

Per §4.2, `SignedTransport` has four fields: `Data`, `Signature`, `Metadata`,
`Padding`. Per §8.1:

> Every `SignedTransport` message includes a digital signature over the `Data`
> field.

Concretely: `Signature = Ed25519.Sign(identityKey, Data)`. `Metadata` — `ID`,
`Timestamp`, `Sequence`, `Route` — and `Padding` are not part of the signed
content. Once a session is established, the entire serialized `SignedTransport`
(all four fields) is AEAD-encrypted (§4.3), so `Metadata` and `Padding` are
currently authenticated only by the Poly1305 tag, not by the sender's identity
key.

## 3. Problem Statement

§8.4 describes three independent integrity layers: AEAD tag, digital signature,
sequence number. In the current design, two of those three layers — the AEAD tag
and, trivially, the sequence-number check itself — are what actually protect
`Metadata`. The signature layer contributes nothing to `Metadata` integrity.
This narrows the intended defense-in-depth specifically for the fields most
relevant to message _meaning_ (which route, which sequence position, when it was
claimed to be sent):

- **Signature portability.** A valid `(Data, Signature)` pair is not
  cryptographically bound to a particular `Sequence`, `Route`, `Timestamp`, or
  `ID`. Nothing in the signature itself proves which sequence position or
  protocol phase the sender intended. Today this is masked because the whole
  envelope travels inside a single AEAD-encrypted frame — but it means that
  guarantee lives entirely at the transport layer, not at the identity-signing
  layer. Any future use of the signature independent of that specific AEAD
  context (local verification of the stored session message log per §11.3,
  export, dispute resolution between the two peers) would not actually prove
  metadata authenticity.
- **Route confusion.** `Route` is not signed. The signature over `Data` alone
  provides no cryptographic guarantee that the sender intended that `Data` for
  the specific route/phase it was delivered under. Protobuf messages are not
  self-describing on the wire; nothing but the (unsigned, AEAD-only)
  `Metadata.Route` field currently ties a signed payload to its intended phase.

Neither issue is currently exploitable by a network attacker without the
session's AEAD key (§9.3's relay is blind and forwards ciphertext only), so this
is a hardening change, not a fix for an active vulnerability. It closes the gap
between what §8.4 claims (three independent layers) and what the signature layer
actually covers today.

## 4. Requirements

- R1: The Ed25519 signature MUST cover `Metadata` (`ID`, `Timestamp`,
  `Sequence`, `Route`) in addition to `Data`.
- R2: The bytes fed into signing and verification MUST be identical on both
  sides. This MUST be achieved by carrying `Metadata` on the wire as its own
  pre-serialized byte string, not by having the verifier independently
  re-marshal a decoded struct — see R3.
- R3: `SignedTransport.Metadata` changes from a structured nested message field
  to an opaque `bytes` field, mirroring the existing `Data` field. The sender
  marshals `Metadata` once; those exact bytes are both the wire value and the
  signing input. This is a deliberate wire format change: relying on
  decode-then-re-encode determinism across independent marshal calls (possibly
  across protobuf library versions over the project's lifetime) is a fragile
  foundation for signature verification, and avoidable at negligible cost pre-v1.
- R4: The signing input SHOULD include a domain-separation label, consistent
  with the existing convention used elsewhere in the protocol (e.g.
  `"kamune/handshake/client-to-server/v1"` in §7.2, `"kamune/handshake/v1"` in
  §6.3's transcript hash), to prevent a signature produced for a
  `SignedTransport` from being reinterpreted in a different signing context that
  reuses the same identity key (Introduction, Handshake).
- R5: `Padding` remains out of scope — see §5.3 for why this is a structural
  constraint, not an oversight.
- R6: This is a breaking change to verification semantics (not to the wire
  schema) and MUST be accompanied by a spec version bump, so that mismatched
  peers hard-reject per the existing pre-1.0 policy (§6.2) rather than silently
  failing every signature check against each other.

## 5. Proposed Design

### 5.1 Signing input

```
SigningInput = "kamune/transport-sign/v1" || MetadataBytes || Data
Signature    = Ed25519.Sign(identityKey, SigningInput)
```

Where `MetadataBytes` is the serialized `Metadata` message (`ID`, `Timestamp`,
`Sequence`, `Route`) — marshaled once by the sender.

Verification uses the exact same bytes the sender produced, taken directly from
the wire — not a re-derivation:

```
MetadataBytes = SignedTransport.Metadata   // raw bytes, as received
valid = Ed25519.Verify(senderPublicKey, "kamune/transport-sign/v1" || MetadataBytes || Data, Signature)
```

`Metadata` is then unmarshaled from those same bytes for application use
(reading `Sequence`, `Route`, etc.).

### 5.2 Metadata becomes a wire-level `bytes` field

`SignedTransport.Metadata` changes from a structured nested message field to
`bytes`:

```
bytes metadata = 3;  // pre-serialized Metadata message
```

This is the load-bearing part of the design. The alternative — keep `Metadata`
structured, and have the verifier independently re-marshal the decoded struct to
reconstruct `MetadataBytes` — depends on decode-then-re-encode producing
byte-identical output across two independent marshal calls, potentially on
different protobuf library versions over the project's lifetime. `Metadata` has
no `repeated` or `map` fields, so this would work in practice today, but it's
verifying a signature against a _reconstruction_ of the original bytes rather
than the original bytes themselves — a fragile foundation to build signature
verification on when the fix is a one-field schema change and the project is
pre-v1. Making `Metadata` opaque `bytes` (identical in spirit to how `Data`
already works) removes the dependency on marshal-call determinism entirely: the
bytes that were signed are the same bytes that arrive on the wire, full stop.

### 5.3 Why `Padding` stays out of scope

`Padding` is sized last, to bring the total marshaled envelope up to the target
bucket size (§12.7). Its size depends on the total serialized size of `Data`,
`Metadata`, and `Signature` combined. Including `Padding` in the signed content
would create a circular dependency: `Padding`'s size depends on `Signature`'s
size, and `Signature` would depend on `Padding`. `Padding` therefore remains
outside the signed scope and continues to rely solely on the AEAD tag for
integrity, same as today. This is acceptable because `Padding` carries no
semantic content — it is discarded on receipt and never interpreted.

### 5.4 Updated §4.2 (Envelope Fields)

`Metadata` field description becomes:

> Pre-serialized `Metadata` message (ID, timestamp, sequence, route), carried as
> opaque bytes. Serialized once by the sender; those same bytes are used both on
> the wire and as part of the signature input.

`Signature` field description becomes:

> Ed25519 signature over `"kamune/transport-sign/v1" || Metadata || Data`, where
> `Metadata` is the raw bytes of the field above, produced with the sender's
> identity private key. Binds the message's metadata (ID, timestamp, sequence,
> route) to its content.

### 5.5 Updated §6.5 (Communication) — Sending a message

The signing step moves later in the sequence, since it now depends on `Metadata`
being finalized first:

1. The sender increments its send counter (starting from 0; the first message is
   sequence 1).
2. The application message is serialized (`Data`).
3. `Metadata` is assembled (`ID`, `Timestamp`, `Sequence`, `Route`) and marshaled
   once to `MetadataBytes`.
4. The signature is computed over `"kamune/transport-sign/v1" || MetadataBytes || Data`,
   using the sender's identity key.
5. The signature, `Data`, `MetadataBytes`, and random padding are assembled
   into a `SignedTransport` envelope — `MetadataBytes` is placed directly into
   the `metadata` field as-is, not re-marshaled.
6. The entire `SignedTransport` is serialized to bytes.
7. The bytes are encrypted using the sender's outbound cipher (unchanged).
8. The ciphertext is written to the connection using length-prefixed framing
   (unchanged).

### 5.6 Updated §6.5 — Receiving a message

Step 4 (signature verification) changes from "verify against `Data`" to "verify
against `SignedTransport.metadata` (raw bytes, as received) `|| Data`". Only
after verification succeeds is `metadata` unmarshaled into a `Metadata` struct
for use. No change to position relative to sequence validation (step 5).

## 6. Security Considerations

- This change is additive to integrity, not confidentiality. `Metadata` was
  already confidentiality-protected (encrypted as part of the whole envelope);
  this only changes what the identity-signature layer authenticates.
- Closes the signature-portability gap described in §3: a `(Data, Signature)`
  pair can no longer be paired with different `Sequence`/`Route`/`Timestamp`/`ID`
  values without invalidating the signature, independent of whether the AEAD
  context is still in play.
- Extends non-repudiation (§8.1) from "the sender signed this content" to "the
  sender signed this content for this sequence position and this route" —
  relevant to the stored session message log (§11.3) if it is ever locally
  re-verified outside the live session.
- No change to the threat model of §8.3/§12.6: an attacker without the AEAD key
  still cannot produce a validly-decrypting frame at all, so this hardening is
  defense-in-depth on top of an already-encrypted channel, not a fix for a
  currently reachable attack.
- The domain-separation label (R4) prevents a signature computed under this
  scheme from being confused with a signature computed for `Introduce` (§6.2) or
  `Handshake` (§6.3) messages, which reuse the same identity key but currently
  sign different, unprefixed content. This RFC does not change the Introduction
  or Handshake signing schemes; it only notes the inconsistency as a candidate
  for a separate follow-up.

## 7. Compatibility

This changes both the wire schema (`Metadata` becomes `bytes`) and verification
semantics. A peer running the old scheme and a peer running the new scheme
cannot interoperate at all — different field type, different signing input. This
MUST ship as a minor version bump (spec is pre-1.0, currently 0.5.0), which
triggers the existing hard-reject path in §6.2's version-compatibility table
(pre-1.0 minor mismatch → hard reject) rather than producing a confusing wall of
per-message decode or signature failures.

## 8. Open Questions

- Exact domain-separation string — `"kamune/transport-sign/v1"` is a placeholder
  following the existing naming convention; confirm before merging.
- Whether `Introduce` and `Handshake` signing should be brought under the same
  domain-separation convention in a follow-up RFC (flagged in §6, not addressed
  here).
- Developer ergonomics: since `Metadata` is no longer directly a typed field on
  `SignedTransport`, code that currently reads `signedTransport.Metadata.Sequence`
  etc. needs either an accessor helper or an explicit unmarshal step at each
  read site. Worth deciding on a helper pattern before implementation to avoid
  scattered ad-hoc unmarshaling.
