# Privacy Boost Protocol Specification

## Abstract

Privacy Boost is a UTXO-based shielded transfer protocol for EVM chains, developed by **Sunnyside
Labs**. It lets users deposit, transfer, and withdraw ERC-20 tokens through Poseidon2 note
commitments in append-only Merkle trees. Spends are authorized by in-circuit EdDSA signatures,
double-spends are prevented by nullifiers, and each submitted batch is checked on-chain by a Groth16
verifier over BN254.

An **epoch** is one proof-backed submission batch that advances the shielded pool state.
The design separates three paths:

- **Deposit:** public ERC-20 funds enter the pool and become shielded notes after a relay-submitted deposit epoch.
- **Transfer / withdraw:** shielded spends are batched by the TEE server into an epoch proof.
- **Forced withdrawal:** a user can generate a client-side proof and exit without TEE proving or
 epoch sequencing, provided the user's auth key is already present in an accepted on-chain auth
 snapshot.

## Security Posture At A Glance

- **Fund safety** depends on cryptographic soundness, circuit correctness, smart-contract
 correctness, verifier-key integrity, and uncompromised governance/proxy administration. It does
 not depend on the TEE operator alone.
- **Privacy** depends on TEE isolation for the convenient path, user key secrecy, and the public
 leakage profile below. Deposits and withdrawals reveal public boundary data; transfers hide
 sender/recipient/value inside the shielded set.
- **Self-custody escape** is conditional: forced withdrawal is available for keys already captured
 in an accepted auth snapshot. Relays create those snapshots; a key registered after the last
 snapshot cannot force-exit until another snapshot is accepted.
- **Auth-key revocation and expiry** affect future registry roots. An older accepted auth snapshot
 can continue to authorize spends until a newer usable snapshot is referenced and accepted;
 `expiry` is included in auth leaves but is not independently enforced at spend time by
 `PrivacyBoost`.
- **Receiver recovery** depends on the receiver-targeted ciphertext being correct. The TEE validates
 the TEE-targeted ciphertext, but the receiver-targeted ciphertext is not server-, circuit-, or
 on-chain-enforced.
- **Public leakage:** deposit token/amount/depositor timing, withdrawal recipient/amount/timing,
 batch metadata, note-tree roots, nullifiers, forced-withdraw `spenderAccountId`, and TEE-observed
 plaintext/metadata for the convenient path. Audit access exists as a product feature, but its
 operational semantics are outside this protocol specification.
- **Throughput** is an implementation/deployment property, not a normative protocol guarantee in this specification.

## Conventions & Notation

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be
 interpreted as described in RFC 2119 when stating protocol invariants.
- **Working field.** Unless stated otherwise, all arithmetic is over the BN254 (alt_bn128) scalar
 field of prime order `r =
 21888242871839275222246405745257275088548364400416034343698204186575808495617`
 (`0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`), referred to on-chain as
 `SNARK_SCALAR_FIELD` and in Go as `SnarkScalarField`. A "field element" is an integer in `[0, r)`.
 The EdDSA auth signature scheme operates over the BabyJubJub twisted-Edwards curve embedded in
 this field; secp256k1 appears only in EOA/ECDSA authorization and in ECDH note-encryption key
 agreement and is always named explicitly.
- **Endianness.** Poseidon2 sponge IV and packed-field layouts use the documented bit shifts (e.g.
 `n·2^64` in the capacity lane, `treeNumber << (i·15)`, digest split `hi = digest >> 128`, `lo =
 digest & (2^128 − 1)`); these are big-integer operations on field elements, not byte streams.
 Where raw bytes are encoded — AES-GCM nonces, HKDF `info` suffixes, compressed-point prefixes —
 multi-byte integers are **big-endian** (e.g. the per-output index is a big-endian `uint32` in the
 last 4 bytes of the 12-byte GCM nonce). Solidity `abi.encode`/`abi.encodePacked` follow standard
 ABI rules.
- **Pseudocode.** `Poseidon(d, a, b, …)` denotes the domain-separated Poseidon2T4 sponge hash with
 leading domain tag `d`. The Go helper is variadic; Solidity exposes fixed-arity
 `Poseidon2T4.hashN` wrappers. `keccak256(abi.encode(…))` denotes
 Solidity ABI encoding followed by Keccak-256. `||` denotes byte concatenation. Field/struct names
 match the source identifiers.

## System Architecture

Privacy Boost is split across an **on-chain** layer and a single **off-chain TEE server** operated by Sunnyside Labs.

On-chain (the root of protocol enforcement, subject to governance/proxy/verifier integrity):
- **PrivacyBoost** — the core shielded pool: append-only note Merkle trees (root history of size
 64), the `nullifierSpent` registry, and the deposit / epoch / forced-withdrawal entrypoints. It
 independently re-derives operation digests and public-input vectors before delegating to the
 verifiers.
- **AuthRegistry** — registration, rotation, and revocation of per-account EdDSA auth keys,
 maintaining its own snapshotted auth Merkle trees consumed by the circuits.
- **TokenRegistry** — maps compact `uint16` token IDs to ERC-20 addresses.
- **Groth16 verifiers** — one per circuit family (epoch, deposit, forced), each consuming `proof[8]`
 plus a positional public-input vector built by `LibPublicInputs`.

Off-chain (trusted for privacy and liveness only):
- **Prover** — receives signed user requests, builds witnesses, generates Groth16 proofs, batches
 transfers into epochs, and submits them from a whitelisted relay address.
- **Indexer** — tracks user UTXOs, balances, and history inside the enclave; serves instant balance
 queries. Its state is reconstructable from chain on recovery.

The protocol exposes **three transaction types**: **Deposit** (public → shielded; 2-step: user
`requestDeposit`, then TEE `submitDepositEpoch`), **Transfer/Withdraw** (shielded → shielded/public;
batched via the TEE `submitEpoch`), and **Forced Withdrawal** (shielded → public; 2-step,
client-side proof, no TEE involvement).

Request / proof / verify data flow:

```text
┌──────────┐      signed request       ┌──────────────────────┐
│ User SDK │ ────────────────────────► │ TEE Server           │
│          │ ◄──────────────────────── │ Prover + Indexer     │
└────┬─────┘      balance / status     └──────────┬───────────┘
     │                                            │ proof + inputs
     │                                            ▼
     │                                  ┌──────────────────────┐
     │                                  │ Contracts            │
     │                                  │ - PrivacyBoost       │
     │                                  │ - AuthRegistry       │
     │                                  │ - TokenRegistry      │
     │                                  │ - Groth16 verifiers  │
     │                                  └──────────┬───────────┘
     │                                             │ verify result
     └─────────────────────────────────────────────┘

Deposit:            User -> Contract -> TEE -> Contract
Transfer/withdraw:  User -> TEE -> Contract
Forced withdrawal:  User -> Contract, with a client-side ZK proof and no TEE
```

The forced-withdrawal path is the **bypass** of TEE proving and epoch sequencing: a user generates
the proof client-side and calls `requestForcedWithdrawal` directly, then calls `executeForcedWithdrawal` after
`forcedWithdrawalDelay` blocks. It preserves self-custody regardless of TEE availability or
censorship **provided the user's auth key is already covered by an on-chain auth snapshot**
(snapshots are created only by a relay; see
[Forced Withdrawal](09-forced-withdrawal.md) and
[Key Management & Trusted-Setup Ceremony](11-key-management-ceremony.md)).

## Trust Model

Fund safety rests on the security of the cryptographic primitives, correctness of the circuits and
on-chain contracts, integrity of the registered verifying keys, and uncompromised governance/proxy
administration. Spending requires a user EdDSA signature the TEE operator cannot forge, the contract
independently verifies every proof, root, and nullifier, and conservation is enforced in-circuit.

The **TEE is trusted for privacy and convenient-path liveness only**. A compromised or offline
enclave can leak transaction metadata or stall normal transfers, but cannot by itself forge user
authorization or bypass on-chain proof checks. Users retain the forced-withdrawal exit only for auth
keys already covered by an accepted on-chain auth snapshot. See
[Security Model, Trust Assumptions & Invariants](12-security-model-invariants.md) for the full
per-component trust table, governance/mutability boundary, threat analysis, and invariant list.

## Governance and Deployment Evidence

Governance, verifier ownership, relay administration, and proxy-admin control are deployment
trust boundaries, not ZK validity checks. This protocol specification describes the mechanics those
roles can affect; time-sensitive deployment status such as Safe owners, thresholds, ProxyAdmin
owners, verifier controllers, relay allowlists, timelocks, monitoring, role-renunciation posture,
and emergency procedures is maintained in deployment evidence outside this specification.
