# SARAL POC — Protocol Compatibility & Standards Specification

**Document Version:** 1.0  
**Author:** Principal Blockchain Protocol Architect & Cryptography Engineer  
**Date:** November 18, 2026  

---

## 1. Official Standards & RFC Mapping

The SARAL threshold signing and distributed key generation implementation adheres strictly to published RFCs, Bitcoin Improvement Proposals (BIPs), Ethereum Improvement Proposals (EIPs), and peer-reviewed cryptographic literature:

```
+-------------------------------------------------------------------------------------------------------+
| Blockchain       | Cryptographic Standard        | Specification / Literature Reference              |
+-------------------------------------------------------------------------------------------------------+
| Solana           | FROST (RFC 9591)              | RFC 9591: Flexible Round-Optimized Schnorr        |
|                  | Ed25519 Ciphersuite           | Threshold Signatures (FROST-ED25519-SHA512)       |
+-------------------------------------------------------------------------------------------------------+
| Bitcoin Taproot  | BIP-340 Schnorr               | BIP-340: Schnorr Signatures for secp256k1         |
|                  | BIP-341 Taproot Spend         | BIP-341: Segregated Witness v1 (Key Path Spend)   |
|                  | BIP-350 Bech32m Address       | BIP-350: Bech32m format for v1+ witness addresses |
+-------------------------------------------------------------------------------------------------------+
| Ethereum / EVM   | CGGMP21 Threshold ECDSA       | Canetti, Gennaro, Goldfeder, Makriyannis,         |
|                  | EIP-155 Replay Protection     | Peled (ACM CCS 2021 / Cryptology ePrint 2021/060) |
|                  | EIP-1559 Fee Market           | EIP-155, EIP-1559, EIP-2 / BIP-62 low-s canonical |
+-------------------------------------------------------------------------------------------------------+
| DKG Engine       | HybridVSS & Feldman VSS       | "Distributed Key Generation in the Wild"          |
|                  |                               | Kokoris-Kogias et al. (IEEE S&P 2020)             |
+-------------------------------------------------------------------------------------------------------+
```

---

## 2. Protocol Details by Blockchain

### A. Solana — FROST Ed25519 (RFC 9591)

#### Ciphersuite Parameters
- **Base Curve:** Edwards25519: $-x^2 + y^2 = 1 - (121665/121666) x^2 y^2$ over $\mathbb{F}_{2^{255}-19}$.
- **Base Point Order:** $\ell = 2^{252} + 27742317777372353535851937790883648493$.
- **Hash Function:** `H(x) = SHA-512(x)` with RFC 9591 domain separation tag.
- **Signature Length:** 64 bytes: $R$ (32 bytes compressed Edwards point) $\parallel z$ (32 bytes scalar encoded little-endian).

#### Mathematical Protocol Flow
1. **Round 1 (Nonce Generation):**
   Each participant $i$ samples $d_i, e_i \stackrel{\$}{\leftarrow} \mathbb{F}_\ell$ and publishes commitments:
   $$D_i = d_i \cdot B, \quad E_i = e_i \cdot B$$
2. **Commitment Aggregation:**
   Aggregator computes binding factors:
   $$\rho_i = H_1(i, m, \vec{D}, \vec{E}) \pmod \ell$$
   $$R_i = D_i + \rho_i E_i, \quad R = \sum_{i \in S} R_i$$
3. **Challenge Computation:**
   $$c = H_2(R, Y, m) \pmod \ell$$
4. **Round 2 (Share Computation & Verification):**
   Participant computes:
   $$z_i = d_i + \rho_i e_i + c \cdot \lambda_i \cdot s_i \pmod \ell$$
   Individual share verification:
   $$z_i \cdot B \stackrel{?}{=} R_i + (c \cdot \lambda_i) \cdot Y_i$$
5. **Aggregation:**
   $$z = \sum_{i \in S} z_i \pmod \ell, \quad \sigma = (R, z)$$
   Standard verification: $z \cdot B = R + c \cdot Y$.

---

### B. Bitcoin Taproot — FROST Schnorr (BIP-340 / BIP-341 / BIP-350)

#### Ciphersuite Parameters
- **Base Curve:** secp256k1: $y^2 = x^3 + 7$ over $\mathbb{F}_p$, order $N$.
- **Challenge Hash:** TaggedHash(`BIP0340/challenge`, $R_x \parallel Q_x \parallel m$).
- **TapTweak Hash:** TaggedHash(`TapTweak`, $P_x \parallel \text{merkleRoot}$).
- **Address Format:** BIP-350 Bech32m witness version 1 (`tb1p...` / `bc1p...`).

#### Even-$Y$ Parity Normalization & Taproot Tweaking
1. **Internal Key Derivation:**
   Participants dealerlessly generate $P = \sum C_{i,0}$.
   If $P$ has odd $y$-coordinate, internal key is negated: $P \leftarrow -P$, and shares are negated: $s_i \leftarrow N - s_i$.
2. **Output Key Computation:**
   $$t = \text{TaggedHash}(\text{"TapTweak"}, P_x), \quad Q = P + t \cdot G$$
   If $Q$ has odd $y$-coordinate, output key is negated: $Q \leftarrow -Q$, requiring share and tweak negations ($s_i \leftarrow N - s_i$, $t \leftarrow N - t$).
3. **Group Nonce Commitment:**
   $$R = \sum (D_i + \rho_i E_i)$$
   If $R$ has odd $y$-coordinate, nonces are negated: $k_i \leftarrow N - k_i$.
4. **Signature Share & Aggregation:**
   $$z_i = k_i + e \cdot \lambda_i \cdot s_i^* \pmod N$$
   Coordinator adds tweak term:
   $$z = \sum z_i + e \cdot t^* \pmod N$$
   Final 64-byte Schnorr signature: $(R_x, z)$.
   Standard BIP-340 verification: $z \cdot G = R + e \cdot Q$.

---

### C. Ethereum / EVM — CGGMP21 Threshold ECDSA

#### Ciphersuite Parameters
- **Base Curve:** secp256k1.
- **Message Hash:** Keccak-256 of unsigned transaction payload.
- **Signature Format:** $(r, s, yParity, v)$ with low-$s$ canonicalization ($s \le N/2$).

#### Protocol Rounds & ZK Proofs
1. **Round 1:** Ephemeral blinding pairs $(k_i, \gamma_i)$ sampled. Hash commitment $C_i = H(sessionId \parallel i \parallel \Gamma_i \parallel K_i)$ broadcasted.
2. **Round 2:** Decommitments $(\Gamma_i, K_i)$ revealed along with Non-Interactive Zero-Knowledge Proofs:
   - $\Pi^{\text{log-star}}$: Proves knowledge of discrete logarithm $\gamma_i$ for $\Gamma_i = \gamma_i \cdot G$.
   - $\Pi^{\text{aff-g}}$: Proves correct affine relation between $k_i$, $w_i$, and $K_i$.
   - Authenticated by secp256k1 identity signature.
3. **Round 3 (Pairwise MtA):**
   Participants exchange cross-term blinds $(\alpha_{ij}, \beta_{ji})$ such that:
   $$\chi_i = k_i w_i + \sum_{j \ne i} (\alpha_{ij} + \beta_{ji}) \pmod N, \quad \sum \chi_i = (\sum k_i)(\sum w_i) = k \cdot x$$
   Delta shares $\delta_i = k_i \cdot \gamma$ broadcasted.
   Aggregated delta: $\delta = \sum \delta_i \pmod N$, $R = \delta^{-1} \cdot \sum \Gamma_i$, $r = R_x \pmod N$.
4. **Round 4 (Signature Shares & Aggregation):**
   $$\sigma_i = k_i \cdot m + r \cdot \chi_i \pmod N$$
   $$s = \sum \sigma_i \pmod N$$
   Enforce low-$s$: if $s > N/2$, $s \leftarrow N - s$, $yParity \leftarrow 1 - yParity$.
   Address recovery validates: $\text{recoverAddress}(m, (r, s, yParity)) = \text{expectedAddress}$.

---

## 3. Cross-Chain Protocol Matrix

| Property | Solana | Bitcoin Taproot | Ethereum / EVM |
|---|---|---|---|
| **Curve** | Edwards25519 | secp256k1 | secp256k1 |
| **Field Modulus** | $2^{255} - 19$ | $2^{256} - 2^{32} - 977$ | $2^{256} - 2^{32} - 977$ |
| **Order Size** | 253-bit prime $\ell$ | 256-bit prime $N$ | 256-bit prime $N$ |
| **Signer Rounds** | 2 rounds | 2 rounds | 4 rounds (MtA) |
| **Identifiable Abort** | Individual $z_i B$ check | Individual $z_i G$ check | Identity sig & $\sigma_i$ check |
| **Raw Sig Size** | 64 bytes | 64 bytes | 65 bytes ($r, s, v$) |
| **On-Chain Verification** | Native Ed25519 program | Native Taproot opcode | Native `ecrecover` precompile |
