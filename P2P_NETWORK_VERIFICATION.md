# SARAL POC — P2P Network, Daemon Transport & Vault Verification

**Author:** Principal P2P Networking & Distributed Systems Engineer  
**Date:** November 18, 2026  

---

## 1. P2P Architecture Overview

The SARAL threshold architecture relies on independent, isolated node daemons communicating directly over a secure, framed peer-to-peer TCP transport layer. Nodes run as standalone Operating System processes or Docker containers, with each node maintaining its own persistent identity, encrypted disk vault, and ephemeral session memory.

```
+-----------------------------------------------------------------------------------------+
|                                    P2P NETWORK TOPOLOGY                                 |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|    +------------------------+                    +------------------------+             |
|    |  Node Daemon 1 (F1)    |                    |  Node Daemon 2 (P1)    |             |
|    |  Endpoint: :19101      |                    |  Endpoint: :19102      |             |
|    |  Vault: /vault/node-1/ |                    |  Vault: /vault/node-2/ |             |
|    |  Identity: Priv_1/Pub_1|                    |  Identity: Priv_2/Pub_2|             |
|    +-----------+------------+                    +-----------+------------+             |
|                ^                                             ^                          |
|                |   Framed TCP (4-byte length prefix)         |                          |
|                |   Mutual secp256k1 Envelope Signatures      |                          |
|                |   AES-256-GCM (ECDH + HKDF-SHA256)          |                          |
|                v                                             v                          |
|    +------------------------------------------------------------------+                 |
|    |               P2P Transport Layer (`P2PTransport.ts`)           |                 |
|    |               - 4-Byte Framing    - Socket Pool & Reconnect      |                 |
|    |               - Envelope Signing  - AES-256-GCM Ciphers          |                 |
|    +------------------------------------------------------------------+                 |
|                                                                                         |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Message Envelope Specification

Every P2P message transmitted across nodes is packaged inside a strongly typed, authenticated, and optionally encrypted envelope:

```typescript
export interface P2PMessageEnvelope {
  protocol: 'FROST_ED25519' | 'FROST_TAPROOT' | 'CGGMP21' | 'HYBRID_DKG';
  sessionId: string;
  fromNodeId: string;
  toNodeId: string;
  timestamp: number;
  nonce: string;        // 16-byte cryptographically random hex
  encrypted: boolean;   // True if payload is AES-256-GCM ciphertext
  payload: string;      // UTF-8 JSON string or ciphertext hex
  signatureHex: string; // 64-byte secp256k1 compact signature by sender
}
```

### Authentication & Non-Repudiation
1. **Signing:** The sender calculates:
   $$\text{hash} = \text{SHA-256}(\text{protocol} \parallel \text{sessionId} \parallel \text{from} \parallel \text{to} \parallel \text{timestamp} \parallel \text{nonce} \parallel \text{payload})$$
   and produces a compact 64-byte signature with its registered node identity private key.
2. **Verification:** The receiving daemon parses the sender's identity public key from its trusted peer table, hashes the envelope fields, and verifies the secp256k1 signature before processing or decrypting the payload.
3. **Replay Rejection:** Timestamps exceeding 30 seconds drift or duplicate `(sessionId, nonce)` tuples are rejected immediately.

### Confidentiality (AES-256-GCM)
When `encrypted = true`:
1. Sender and recipient compute ECDH shared secret: $S = \text{secp256k1.getSharedSecret}(priv_{\text{sender}}, pub_{\text{recipient}})$.
2. An ephemeral 256-bit AES key is derived using HKDF-SHA256:
   $$K_{\text{AES}} = \text{HKDF-SHA256}(\text{ikm} = S, \text{salt} = sessionId, \text{info} = \text{"SARAL-P2P-ENCRYPTION-v1"}, \text{len} = 32)$$
3. The JSON payload is encrypted with AES-256-GCM using a 12-byte random IV.
4. Output wire format: `IV (12 bytes) || Auth Tag (16 bytes) || Ciphertext`.

---

## 3. TCP Framing & Synchronous RPC

To prevent stream fragmentation and packet boundary issues over streaming TCP, `P2PTransport` enforces **4-byte big-endian length prefix framing**:

```
+-----------------------------------+---------------------------------------------+
| Frame Header (4 Bytes, Big Endian)|             Payload Buffer                  |
| 0x00 0x00 0x01 0x4A (e.g. 330 B)  |       UTF-8 Encoded Envelope JSON String    |
+-----------------------------------+---------------------------------------------+
```

### Request-Response RPC Method (`sendEnvelopeAndReceive`)
`P2PTransport.sendEnvelopeAndReceive` provides a robust, promise-based synchronous RPC over framed TCP:
- Opens a socket connection to target node endpoint `(host, port)`.
- Writes the 4-byte header and serialized envelope.
- Buffers incoming TCP chunks until the complete response frame header (4 bytes) and payload are fully assembled.
- Decodes the response `P2PMessageEnvelope`.
- Destroys socket and clears timers upon completion or error.
- Enforces configurable timeout (default 8000ms).

---

## 4. Node Vault Storage Policies

Each participant daemon manages its own isolated directory on disk (the Node Vault):

```
/vault/node-1/
  ├── identity.json                           (Node identity keys, mode 0o600)
  ├── share_frost_ed25519_<sessionId>.json    (Ed25519 Shamir scalar share, mode 0o600)
  ├── share_frost_taproot_<sessionId>.json    (Taproot Shamir scalar share, mode 0o600)
  └── share_cggmp21_<sessionId>.json          (CGGMP21 Shamir scalar share, mode 0o600)
```

### Storage Security Policies
1. **File Mode `0o600`:** Every identity and share file is written with strict OS-level permissions (`0o600` / `-rw-------`), ensuring only the specific node process user has read/write access.
2. **Isolation:** Node vaults are strictly separated by filesystem path. In production container deployments, each vault is mounted into an isolated Docker volume.
3. **No Network Share Transmission:** The daemon never exposes an endpoint that returns the plaintext secret scalar. The scalar is read exclusively by internal protocol handlers (`handleFrostEd25519`, `handleFrostTaproot`, `handleCggmp21`) to produce partial signature shares locally.

---

## 5. Verification Evidence

The P2P transport and daemon architecture were validated using real network integration tests in `backend/tests/integration/p2pNodeNetwork.test.ts`:

- [x] Ephemeral port allocation dynamically captures available operating system ports, preventing port collisions.
- [x] Mutual secp256k1 identity exchange and signature validation succeed between active daemons.
- [x] Encrypted payloads with ECDH + HKDF-SHA256 successfully decrypt only between intended endpoints.
- [x] Tampered payload envelopes fail signature verification and are discarded without processing.
- [x] Complete round-1 commitments and round-2 signature shares successfully exchange over live TCP sockets.
- [x] Clean daemon shutdown (`daemon.stop()`) properly closes listeners and releases socket resources.
