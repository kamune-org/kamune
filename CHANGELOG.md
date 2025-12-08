
## v0.1.0 - Initial Release

Kamune is a secure, peer-to-peer communication library for real-time messaging
over untrusted networks. This first release delivers an experimental foundation
for quantum-resistant, authenticated, and encrypted messaging, with a custom
protocol designed for minimal latency and overhead.

### Features & Technical Highlights

**Security & Cryptography**
- **Hybrid Cipher Suite:**  
  - Ed25519 for digital signatures and identity verification  
  - ML-KEM-768 for quantum-resistant key encapsulation (PQ KEM)  
  - HKDF-SHA512 for session key derivation  
  - ChaCha20-Poly1305X for authenticated symmetric encryption  
  - Optional ML-DSA for post-quantum digital signatures  
- **Forward Secrecy:**  
  - Double Ratchet algorithm and ECDH key exchange ensure session keys are
    regularly refreshed. Past communications remain secure even if long-term
    keys are compromised.
- **Ephemeral Keys:**  
  - Each session uses one-time-use keys for handshake and encryption,
    minimizing exposure.

**Protocol Flow**
- **Introduction Phase:**  
  - Clients and servers exchange public keys and verify identities using
    digital signatures and fingerprinting (emoji/hex).
- **Handshake Phase:**  
  - Ephemeral ML-KEM keys are exchanged, and both sides derive a shared secret.
  - Session IDs are constructed from random prefixes/suffixes.
  - Mutual challenge-response ensures both parties possess the correct keys.
- **Communication Phase:**  
  - Messages are signed, encrypted, and transmitted with metadata (timestamp,
    sequence number).
  - Integrity checks and replay protection are enforced.
  - Transport supports chunked reads/writes and message size limits.

**Transport & Networking**
- **TCP and UDP Support:**  
  - Custom protocol implemented over both TCP and UDP sockets  
  - Direct peer-to-peer connections; no central server required  
  - Relay server available for IP discovery and NAT traversal (experimental)  
- **Timeouts & Deadlines:**  
  - Configurable read/write timeouts for robust connection management

**Messaging & Storage**
- **Protobuf Encoding:**  
  - Efficient binary serialization for all protocol messages  
- **Chat History:**  
  - Encrypted chat history is stored per session, with support for retrieval
    and replay  
  - Storage uses per-session buckets and random key suffixes to avoid
    collisions  
- **Peer Management:**  
  - Peer identities are stored with expiration; expired peers are
    automatically purged  
  - Peer verification prompts with fingerprint display
