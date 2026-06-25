# Appendix B: Parameters, Constants & Domain Separators

## Overview

This appendix is the single normative reference for every protocol-wide constant, tree/circuit
sizing parameter, fee/timing parameter, field modulus, and domain separator / hash tag / KDF info
string in the Privacy Boost protocol. The same values must agree across the Solidity contracts, Go
circuits/prover, and SDK wire-format constants where those components share a protocol surface.

The scalar field for all Poseidon hashing, EdDSA, and proof public inputs is the BN254 scalar field `r`:

```text
r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
```

In Go this value is exposed as `SnarkScalarField`, parsed from the same decimal string. All
Poseidon outputs, commitments, nullifiers, roots, and digest hi/lo halves are elements of `GF(r)`.

---

## Table 1a — Normative Constants

These values are fixed by contract bytecode, circuit code, or curve choice. Changing a circuit-shape
constant requires recompiling circuits and registering matching verifying keys.

| Name | Value | Meaning |
|---|---|---|
| `MAX_NOTE_ROOTS_PER_PROOF` | 16 | Sparse note-root capacity carried in one proof |
| `MAX_AUTH_ROOTS_PER_PROOF` | 16 | Sparse auth-root capacity carried in one proof |
| `MAX_NOTE_TREE_NUMBER` | 32767 | Max global note tree id, 15-bit inclusive |
| `MAX_AUTH_TREE_NUMBER` | 32767 | Max global auth tree id, 15-bit inclusive |
| `TreeNumberBitsPerSlot` | 15 | Bits per packed tree number; 16 slots use 240 bits |
| `ROOT_HISTORY_SIZE` | 64 | Historical roots retained per note tree; reused by AuthRegistry as `AUTH_ROOT_HISTORY_SIZE` |
| `MAX_FEE_BPS` | 1000 (`1_000`) | Max withdraw fee = 10% |
| `FeeBpsDenominator` / `BASIS_POINTS` | 10000 (`10_000`) | Basis-point divisor; Go/circuit helper name and Solidity constant name |
| `DIGEST_HALF_BITS` | 128 | keccak digest split width into hi/lo halves for circuit field-fit |
| `COUNT_BITS_PER_SLOT` | 32 | Bits per slot in packed counts field |
| `COUNT_PACKED_SLOTS` | 5 | Slots in packed counts: CountOld, CountNew, Rollover, NTransfers, FeeTokenCount |
| `NullifierTreeNumberMultiplier` | 256 (2^8) | Tree-number multiplier folded into nullifier domain |
| `TOKEN_TYPE_ERC20` | 0 | Only supported token type |
| `MERKLE_ZERO_ROOT` | 12912536786691007423957206067517486813236154886763950786309034005218474477397 | Depth-20 note-hash zero root. It is not the configured depth-24 note empty root and not the auth empty root |
| `AUTH_ZERO_ROOT` | 5126366598568957508996612635770875836246285197448927819410732545299241365093 | Empty auth tree root at depth 20, computed with domain-separated auth nodes |
| `SnarkScalarField` (`r`) | 21888242871839275222246405745257275088548364400416034343698204186575808495617 | BN254 scalar field modulus |

**Range-check bit-lengths:** `BoolBits=1`,
`CountBits=32`, `TokenIDBits=16`, `FeeBpsBits=16`, `AmountBits=96` (matches
contract `uint96` amounts), `FeeRemainderBits=14` (since 10000 < 2^14). Also
`NoteTreeNumberBits = AuthTreeNumberBits = TreeNumberBitsPerSlot = 15` — the in-circuit
range bound enforcing `treeNumber <= 32767`.

## Table 1b — Circuit and Verifier Profile

These values are circuit/verifier-profile facts. Implementations should use the registered verifier
profile and constructor configuration.

| Name | Value | Meaning | Authority |
|---|---|---|---|
| `merkleDepth` | 24 in the registered note-tree profile | Note tree capacity is `2^24` leaves | PrivacyBoost constructor immutable |
| `authTreeDepth` | 20 in the registered auth-tree profile | Auth tree capacity is `2^20` leaves | AuthRegistry constructor immutable |
| `cancelDelay` | constructor arg | Block count before a pending deposit may be cancelled | PrivacyBoost constructor immutable |
| `forcedWithdrawalDelay` | constructor arg | Block count before a forced-withdrawal request matures for execute/cancel | PrivacyBoost constructor immutable |

The precomputed note zero-hash table covers levels 0..24. The configured note empty root is `zeros[24]`
(`6379...42833`). The configured auth empty root is `AUTH_ZERO_ROOT`, computed from the separate auth
zero-hash table at depth 20. `MERKLE_ZERO_ROOT` is only the depth-20 note-hash root, so it is
neither the configured note empty root nor the auth empty root.

---

## Table 2 — Poseidon Domain Separators (field-element tags)

Each tag is prepended as the first input to a Poseidon hash to give each context a disjoint hash
space. These are small field elements 1..8 and MUST
be identical on both sides.

| Tag | Value | Used for | Match |
|---|---|---|---|
| `DOMAIN_ACCOUNTID` | 1 | Account id derivation (`accountId = H(1, owner, salt)`) | ✓ |
| `DOMAIN_NOTE` | 2 | NPK + note commitment + withdrawal commitment | ✓ |
| `DOMAIN_NULLIFIER` | 3 | Nullifier derivation (base, before tree-number fold) | ✓ |
| `DOMAIN_REG_LEAF` | 4 | AuthRegistry leaf hash | ✓ |
| `DOMAIN_REG_NODE` | 5 | AuthRegistry internal Merkle node hash | ✓ |
| `DOMAIN_APPROVE` | 6 | EdDSA approval message hash (binds digest hi/lo) | ✓ |
| `DOMAIN_DEPOSIT_REQUEST` | 7 | Deposit request id derivation | ✓ |
| `DOMAIN_MPK` | 8 | Master public key derivation | ✓ |

The protocol assigns the following values across the implementation surfaces. Tag 1 is used by
`AuthRegistry.computeAccountId` and off-chain account-key derivation. It is defined in the circuit
constant set, but live circuit `Define` constraints consume an already-derived `accountId`; tags 3,
6, and 8 are circuit/prover-only.

---

## Table 3 — keccak256 String Domains, Type Tags & KDF Info Strings (wire-format literals)

These are exact ASCII byte strings. The keccak digest domains are ABI-encoded as the first element
of `abi.encode(...)`; the KDF strings are passed verbatim as HKDF-SHA256 `info` (or salt).

| Literal | Kind | Used for | Requirement |
|---|---|---|---|
| `"PB:TRANSFER:v1"` | keccak digest domain | Transfer approval digest | Exact ABI digest domain |
| `"PB:DEPOSIT:v1"` | declared keccak domain | Reserved; not used by live approval digests. Deposit ids use the Poseidon `DOMAIN_DEPOSIT_REQUEST` path, not this string | — |
| `"PB:WITHDRAW:v1"` | keccak digest domain | Withdrawal approval digest | Exact ABI digest domain |
| `"PB:FORCED_WITHDRAW:v1"` | keccak digest domain | Forced-withdrawal digest | Exact ABI digest domain |
| `"pb-transfer-output-v2"` | HKDF info prefix (+ `u32_be(outputIdx)`) | Per-output transfer content key | Exact byte string |
| `"tee-enc-key"` | HKDF info | Operator wrap key (`teeWrapKey`) | Exact byte string |
| `"receiver-enc-key"` | HKDF info | Per-recipient wrap key | Exact byte string |

---

## Hash & Digest Computations (exact field ordering)

All Poseidon calls use the `Poseidon2T4` permutation; the arity helpers
`hash1/hash2/hash3/hash4/hash5/...hash9` define fixed-arity sponge entry points. The first
argument is the domain tag where one is present. The Go prover uses `PoseidonMD(domain, args...)`
 with the same ordering.

```math
\begin{aligned}
\texttt{accountId} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_ACCOUNTID}=1, \texttt{uint160(owner)}, \texttt{salt}) \\
\texttt{MPK} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_MPK}=8, \texttt{accountId}, \texttt{nullifyingKey}) \\
\texttt{NPK} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_NOTE}=2, \texttt{MPK}, \texttt{noteRnd}) \\
\texttt{commitment} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_NOTE}=2, \texttt{NPK}, \texttt{tokenId}, \texttt{value}) \\
\texttt{nullifier} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_NULLIFIER} + 256 \cdot \texttt{treeNumber},
    \texttt{nullifyingKey}, \texttt{noteLeafIndex}) \\
\texttt{withdrawalCommitment} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_NOTE}=2, \texttt{uint160(to)}, \texttt{tokenId},
    \texttt{amount}) \\
\texttt{approveMsg} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_APPROVE}=6, \texttt{digestHi}, \texttt{digestLo})
\end{aligned}
```

The nullifier domain folds the tree number with base domain 3 and multiplier 256. Deposit request
IDs use:

```math
\begin{aligned}
\texttt{depositRequestId} =
\textsf{Poseidon}(&\texttt{DOMAIN\_DEPOSIT\_REQUEST}=7, \texttt{chainId}, \texttt{pool}, \\
&\texttt{depositor}, \texttt{tokenId}, \texttt{totalAmount}, \texttt{nonce},
\texttt{commitmentsHash}).
\end{aligned}
```

Auth-registry tree hashing:

```text
authLeaf = Poseidon(DOMAIN_REG_LEAF=4, accountId, authPkX, authPkY, expiry)

authNode = Poseidon(DOMAIN_REG_NODE=5, left, right)
```

Note-tree node hashing has **no domain tag** (distinct from auth):

```text
noteNode = Poseidon(left, right) // hash2, no domain
The note tree uses hash2 in-circuit and for zero-root derivation.
LibZeroHashes chains the same hash2 function for note-tree zero roots; PrivacyBoost stores the
proof-supplied note root via _updateTreeState rather than recomputing note nodes on-chain.
```

keccak256 authorization digests (ABI-encoded; split into 128-bit hi/lo):

```text
transferDigest = keccak256(abi.encode(
 "PB:TRANSFER:v1", chainId, pool, root, nullifiers, outputs, viewingKey, teeWrapKey))
 hi = digest >> 128; lo = digest & (2^128 - 1)

withdrawalDigest = keccak256(abi.encode(
 "PB:WITHDRAW:v1", chainId, pool, root, nullifiers, outputs,
 withdrawal, viewingKey, teeWrapKey))
 hi/lo split as above

forcedWithdrawalDigest = keccak256(abi.encode(
 "PB:FORCED_WITHDRAW:v1", chainId, pool, root, nullifiers, withdrawal))

forcedCommitmentsHash = keccak256(abi.encodePacked(inputCommitments))
requestKey = uint256(keccak256(abi.encodePacked(requester, forcedCommitmentsHash)))

depositCommitmentsHash = fold: h_0 = 0; h_{i+1} = Poseidon(h_i, c_i) // hash2, no domain
```

---

## Encryption / KDF Computations (HKDF-SHA256, AES-256-GCM)

All content-key derivation is HKDF-SHA256, 32-byte output, nil salt unless noted. Transfer outputs
derive their content keys per output:

```text
outKey_i = HKDF-SHA256(
 secret = rootKey,
 salt = nil,
 info = "pb-transfer-output-v2" || uint32_be(output_idx), // 25-byte info
 L = 32)

receiverEncKey = HKDF(ECDH(senderViewingKey, blindedReceiver).x, info="receiver-enc-key")

teeEncKey = HKDF(teeSharedX, info="tee-enc-key")

depositReceiverWrapKey = rootKey XOR receiverEncKey
transferReceiverWrapKey_i = outKey_i XOR receiverEncKey
teeWrapKey = rootKey XOR teeEncKey
```

AES-256-GCM nonce is derived from the output index only (12 bytes, big-endian u32 in the last 4 bytes, leading 8 zero):

```text
nonce(output_index) = 0x00 00 00 00 00 00 00 00 || uint32_be(output_index)

```

> Normative caller obligation: the (key, nonce) pair MUST be unique. Because the nonce is bound only
> to `output_index` and not to the key, the encryption key MUST be freshly derived per output. Live
> callers satisfy this by deriving a fresh per-output key. Reusing a fixed key across calls sharing
> an `output_index` breaks AES-GCM confidentiality and integrity.

---

## Normative Invariants

- Tree identifiers MUST satisfy `treeNumber <= MAX_NOTE_TREE_NUMBER (32767)` / `MAX_AUTH_TREE_NUMBER
 (32767)`; this is the 15-bit packing bound,
 range-checked in-circuit via `NoteTreeNumberBits/AuthTreeNumberBits = 15`.
- A proof MUST reference at most `MAX_NOTE_ROOTS_PER_PROOF (16)` note roots and
 `MAX_AUTH_ROOTS_PER_PROOF (16)` auth roots.
- The protocol retains `ROOT_HISTORY_SIZE (64)` historical roots per note tree, and
 `AUTH_ROOT_HISTORY_SIZE = ROOT_HISTORY_SIZE (64)` per auth tree; auth roots are
 written into a `% AUTH_ROOT_HISTORY_SIZE` ring buffer.
 Proofs against evicted roots are rejected.
- `withdrawFeeBps_` MUST NOT exceed `MAX_FEE_BPS (1000 = 10%)`; the `_setFees` setter reverts
 otherwise. Additionally, a non-zero
 fee with a zero treasury reverts.
- All Poseidon domain tags (Table 2) MUST equal across the contract, circuit, prover, and
 wire-format surfaces;
 the note-tree node hash MUST use un-domained `hash2(left,right)` while
 the auth-tree node hash MUST use `hash3(DOMAIN_REG_NODE, left, right)` — these are not
 interchangeable. At the configured depths, they produce the configured note empty root
 `LibZeroHashes.get[24] =
 6379059771196981783531842116523729103253487220527074934863013362203865842833` and the configured auth
 empty root `AUTH_ZERO_ROOT = LibAuthZeroHashes.get[20]`. `MERKLE_ZERO_ROOT` is only the depth-20
 note zero-root constant.
- The `"pb-transfer-output-v2"` HKDF info bytes MUST be exact or per-output decryption fails.
- `AmountBits = 96` MUST match the on-chain `uint96` amount type for all note values and fee amounts.

---

## Consistency requirements (summary)

| Value | Contract surface | Circuit/prover surface | Wire surface | Requirement |
|---|---|---|---|---|
| Configured **note** depth | immutable `merkleDepth` | circuit profile note depth | — | profile value |
| Configured **auth** depth | immutable `authTreeDepth` | circuit profile auth depth | — | profile value |
| `MERKLE_DEPTH` constant | 20 | n/a | — | — |
| Max roots per proof | 16 | 16 | — | must match |
| Max tree number | 32767 | 32767 | — | must match |
| `ROOT_HISTORY_SIZE` | 64 | — | — | (Sol-only; applies to both trees) |
| Counts pack: slots/bits | 5 / 32 | 5 / 32 | — | must match |
| Domain tags 1..8 | constants | circuit constants | wire-compatible where used | must match where used |
| `NullifierTreeNumberMultiplier` | — | 256 | — | must match |
| Configured note empty root (`zeros[24]`) | selected by `PrivacyBoost._zeroRoot` at configured `merkleDepth` | — | — | profile value |
| `MERKLE_ZERO_ROOT` == zeros[20] (hash2 chain) | == | — | — | must identify depth-20 note root |
| `AUTH_ZERO_ROOT` == zeros[20] (hash3 chain) | == | — | — | must identify depth-20 auth root |

Shared constants, domain separators, and KDF info strings are required to match wherever they cross
the contract, circuit, prover, or wire-format boundary. These values are normative; implementation
validation is internal to release engineering.
The binding Solidity constants `MAX_NOTE_ROOTS_PER_PROOF` and `MAX_AUTH_ROOTS_PER_PROOF` are
sparse-root caps per proof, not global tree-count caps; the global tree-id cap is 32767.

---
