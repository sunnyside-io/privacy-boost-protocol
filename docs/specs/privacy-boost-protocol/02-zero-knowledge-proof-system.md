# 2. Zero-Knowledge Proof System

## Proving stack

The protocol uses **Groth16 over the BN254 (alt-bn128) pairing-friendly curve**, with circuits
authored in Go against the **gnark** R1CS frontend and compiled over the BN254 scalar field `r`.
Proofs are produced with the proving key for the selected circuit shape and converted to the
on-chain Solidity format.

There is **no recursion or proof aggregation**. "Batching" is achieved inside a single circuit
instance by parameterizing it with multiple transfer slots (the *batch size*), and each on-chain
submission verifies exactly one Groth16 proof. A proof and its public-input vector are bound to one
logical operation (an epoch, a deposit epoch, or a forced withdrawal).

An in-circuit **Poseidon2 sponge with width t=4, rate 3, capacity 1** (`Poseidon2T4`) is the sole
algebraic hash for commitments, nullifiers, Merkle nodes, and the EdDSA approval message. The
capacity lane (`s3`) is
initialized to `n * 2^64` where `n` is the input count; 3 inputs
are absorbed per permutation and `s0` is squeezed as the output. EdDSA-Poseidon signatures authorize
each spend; the message is `Poseidon(domainApprove, ApproveDigestHi, ApproveDigestLo)`, verified by
`VerifyEdDSAIf` for gated epoch slots and `VerifyEdDSA` for forced withdrawal.

> The exact Poseidon2 round constants, S-box, and field arithmetic are out of scope here (covered by
> the primitives section). This section treats `Poseidon(...)` as a fixed function and focuses on
> the proof-system architecture and public-input plumbing.

## Groth16 Verification Model

Each supported circuit has a trusted-setup-derived proving key and verifying key. A proof attests
that there exists a private witness satisfying that circuit's constraints for the submitted
public-input vector. On-chain verification checks the Groth16 pairing equation against the
registered verifying key and the exact positional public inputs reconstructed by `LibPublicInputs`.

For public inputs `x_i`, the verifier computes:

```math
vk_x = IC_0 + \sum_i x_i \cdot IC_{i+1}
```

and accepts only if the pairing product over the proof points, `vk_x`, and the verifying-key
constants is the identity. This binds the proof to the registered circuit shape and to the submitted
public-input vector.

## The three circuits

| Circuit | Go type / constructor | Purpose |
|---|---|---|
| **DepositEpoch** | `DepositEpochCircuit` / `NewDepositEpochCircuit(maxSlots, merkleDepth, maxNoteRootsPerProof)` | Mint commitments for confirmed deposit requests; append to note tree |
| **Epoch** | `EpochCircuit` / `NewEpochCircuit(maxTransfers, maxInputsPerTransfer, maxOutputsPerTransfer, noteDepth, authDepth, maxFeeTokens, maxNoteRootsPerProof, maxAuthRootsPerProof)` | Batch of private N-in/M-out transfers + fee notes; spend (nullify) inputs and append outputs |
| **ForcedWithdraw** | `ForcedWithdrawCircuit` / `NewForcedWithdrawCircuit(maxInputs, merkleDepth, authDepth, maxNoteRootsPerProof, maxAuthRootsPerProof)` | Single-signer manual exit spending up to `MaxInputs` notes to an EOA |

They share primitives and conventions but are **independent circuits with independent trusted setups
and independent VKs**: each has its own R1CS, PK, VK, and Solidity verifier contract. They relate
operationally, not cryptographically:

- All three operate on the same Poseidon note-commitment Merkle tree. They carry up to
 `MaxNoteRootsPerProof = 16` historical note roots so a proof can spend
 from / append to past tree versions.
- Epoch and ForcedWithdraw additionally consume up to `MaxAuthRootsPerProof = 16` auth-registry
 roots and verify EdDSA authorization + auth-tree membership.
 DepositEpoch has no auth/spend; it only mints.
- Shared note commitment / NPK / nullifier / MPK derivations (identical domain tags across circuits)
 make notes minted by one circuit spendable by another.

### Shared cryptographic derivations

The exact domain tag values are defined in [Appendix B](13-parameters-constants.md). The circuits use
those tags in the following shared derivations:

```text
MPK = Poseidon(domainMPK, accountId, nullifyingKey)
NPK = Poseidon(domainNote, MPK, noteRnd)
commitment = Poseidon(domainNote, NPK, tokenId, value)
nullifier = Poseidon(domainNullifier + treeNumber * NullifierTreeNumberMultiplier, nullifyingKey, noteLeafIndex)
authLeaf = Poseidon(domainRegLeaf, accountId, authPkX, authPkY, authExpiry)
approveMsg = Poseidon(domainApprove, ApproveDigestHi, ApproveDigestLo) // EdDSA-signed message
```

The nullifier domain is offset by `treeNumber * NullifierTreeNumberMultiplier`. The deposit request
id binds chain context:

```text
RequestId = Poseidon(domainDepositRequest, chainId, pool, depositor, tokenId, totalAmount, nonce, commitmentsHash)
```

where `commitmentsHash` is a sequential Poseidon chain over that request's output commitments
(`Poseidon(prevHash, commitment)` per leaf), and the id
equality is enforced at request finalization.

> **MUST**: the registered VK data selected by the verifier registry and the proving key used by the
> prover MUST correspond to the same trusted setup output for the circuit shape. A mismatched VK/PK
> pair causes proof verification to fail.

## Public-input model: many field elements, not a single commitment

This protocol does **NOT** use the single-public-input hash-commitment pattern. Each circuit exposes
**all logical public inputs directly as a flat `uint256[]` vector** of BN254 scalars, in a fixed
order. The contract reconstructs this exact vector from on-chain state via `LibPublicInputs` and
passes it to the verifier; the Groth16 IC (linear-combination) basis has length `publicInputs.length
+ 1` (the `+1` is IC[0], the constant term).

Enforced length invariant (**MUST**): `publicInputs.length + 1 == vk.icLen`, else
`InvalidPublicInputLength`. Every scalar
**MUST** be `< R` (BN254 scalar modulus
`0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`), else
`PublicInputNotInField`.

Several logical fields are **bit-packed** into single field elements:

- **`CountsPacked`** (Epoch): `CountOld | (CountNew<<32) | (Rollover<<64) | (NTransfers<<96) |
 (FeeTokenCount<<128)` — 5×32-bit slots, 160 bits total.
- **Packed tree numbers**: 16 tree numbers at 15 bits each = 240 bits in one field element, for both
 note roots (`packedTreeNumbers`) and auth roots (`packedAuthTreeNumbers`)
 (`TreeNumberBitsPerSlot = 15`). Max tree number is `2^15 - 1 = 32767`; `_packTreeData`
 reverts `TreeNumberOverflow` above it and `TooManyDistinctTrees` past 16 slots.
- **`DigestRootMask`** (Epoch): a `MaxNoteRootsPerProof`-bit mask; bit *i* marks note-root slot *i*
 as referenced by a digest selection. Slots used by actual input spends are covered by membership
 paths.
- **Approval digests** are split into two 128-bit halves `ApproveDigestHi`/`ApproveDigestLo` because
 the digest is a 256-bit keccak hash that does not fit one BN254 scalar (`DIGEST_HALF_BITS = 128`);
 the forced-withdraw path performs the same split in-contract.

### Epoch public-input vector

Indices are sequential; `T = MaxTransfers`, `I = maxInputsPerTransfer`, `O = maxOutputsPerTransfer`,
`F = maxFeeTokens`. 2D arrays are flattened **row-major**: `nullifiers[t][i] -> t*I + i`.

| Order | Field | Count | Notes |
|---|---|---|---|
| 1 | `NoteKnownRoots` | 16 | on-chain note root history (sparse → padded) |
| 2 | `packedTreeNumbers` | 1 | 15-bit packed note tree numbers |
| 3 | `DigestRootMask` | 1 | digest-root bitmask |
| 4 | `ActiveNoteTreeNumber` | 1 | active output tree number |
| 5 | `ActiveNoteTreeRoot` | 1 | current root of active tree (frontier binding) |
| 6 | `CountsPacked` | 1 | packed counts (see above) |
| 7 | `RootNew` | 1 | note root after all appends |
| 8 | `AuthKnownRoots` | 16 | snapshotted auth roots |
| 9 | `packedAuthTreeNumbers` | 1 | 15-bit packed auth tree numbers |
| 10 | `Nullifiers` | T·I | per-input nullifiers (row-major, zero-padded) |
| 11 | `CommitmentsOut` | T·O | per-output commitments (row-major, zero-padded) |
| 12 | `ApproveDigestHi` | T | per-transfer digest high half |
| 13 | `ApproveDigestLo` | T | per-transfer digest low half |
| 14 | `FeeNPK` | 1 | fee recipient NPK |
| 15 | `FeeCommitmentsOut` | F | fee note commitments |

Total length = `16 + 2 + 16 + 1 + 4 + T·I + T·O + 2T + 1 + F`.

### Deposit public-input vector

`S = MaxSlots` (= batch size). Order: `chainId`, `pool` (as `uint160`), `NoteKnownRoots`(16),
`packedTreeNumbers`(1), `ActiveNoteTreeNumber`, `CountOld`, `RootNew`, `CountNew`, `Rollover`(0/1),
`NRequests`, `NTotalCommitments`, then four S-length blocks: `DepositRequestIds`, `TotalAmounts`,
`CommitmentCounts`, `CommitmentsOut`. Total length = `16 + 10 + 4·S`.

### ForcedWithdraw public-input vector

`N = maxInputs`. Order: `NoteKnownRoots`(16), `packedTreeNumbers`(1), `AuthKnownRoots`(16),
`packedAuthTreeNumbers`(1), `inputCount`, `spenderAccountId`, `Nullifiers`(N),
`InputCommitments`(N), `digestHi`, `digestLo`, `withdrawalTo`(as `uint160`), `tokenId`, `amount`.
Total length = `16 + 1 + 16 + 1 + 7 + 2N`.

> **MUST (digest binding)**: the approval-digest public inputs are the sole binding between the
> proof and the keccak-hashed transaction context (chain id, pool, root, nullifiers, outputs,
> withdrawal target). The circuit only proves *a valid EdDSA signature exists over
> `Poseidon(domainApprove, hi, lo)`* — it does **not** recompute the keccak digest. The contract
> MUST supply `(hi, lo)` derived from the actual keccak digest of the operation; the prover's digest
> helpers MUST mirror exactly. Live approval-digest domain strings are `PB:TRANSFER:v1`,
> `PB:WITHDRAW:v1`, and `PB:FORCED_WITHDRAW:v1`; they are ABI-encoded, hashed
> with keccak256, and split into `(hi = digest >> 128, lo = digest & (2^128 - 1))`. `PB:DEPOSIT:v1`
> is declared/reserved, but the live deposit epoch circuit does not use an EdDSA approval digest;
> deposits are bound by the Poseidon `depositRequestId` path instead. The
> forced-withdraw verifier path performs the equivalent split on-chain inside
> `buildForcedWithdrawalInputs`.

## Witness construction

Witnesses are built by the prover and assembled into a gnark circuit *assignment* (the same Go
struct used for compilation, with concrete values), then `frontend.NewWitness(assignment,
fr.Modulus)` separates public from private. Public inputs are
extracted from the witness via `wit.Public` → `fr.Vector` → `[]*big.Int`, and MUST match the contract-reconstructed vector
index-for-index.

Padding discipline (enforced by circuit constraints, not just convention):
- Inactive transfer slots are gated by `transferActive[t]:= (t < NTransfers)`; inactive nullifiers/commitments MUST be zero.
- ForcedWithdraw inactive input slots MUST be fully zero (tree number, token, value, rnd, leaf
 index, nullifier, commitment, all path elements).
- Counts are range-checked: `1 ≤ NTransfers ≤ MaxTransfers`, `1 ≤ FeeTokenCount ≤ MaxFeeTokens`, `1 ≤ NIn ≤ MaxInputs`.

Circuit-enforced constraints:
- **Tree-number binding**: a Merkle
 proof MUST match *both* a known root *and* its paired tree number at the same slot, preventing a
 prover from claiming a different tree number than the one proven against. Used for note inputs, auth membership, and forced
 inputs.
- **Canonical root coverage**:
 every non-zero `NoteKnownRoots` slot MUST be consumed by an active input OR flagged in
 `DigestRootMask`; a set mask bit MUST NOT point at a zero slot.
- **Conservation**: per transfer `sum(inputs) = sum(outputs) + fee`; forced `WithdrawalAmount =
 sum(inputValues)` and `WithdrawalTokenID = TransferTokenID`.
- **Frontier/rollover**: the tree update is a sequential frontier append; on `Rollover=1` the
 circuit requires `CountOld == 2^NoteDepth` and starts from empty, and binds the provided frontier to `ActiveNoteTreeRoot`
 when not rolling over.

The circuit does **NOT** enforce cross-transfer nullifier uniqueness or that the supplied root
arrays are consistent with the contract's history; those are enforced on-chain.

## Parameterization and verifier registration

Circuit *shape* (batch size, max inputs/outputs, fee tokens, depths, max roots per proof) is fixed
at compile time by the constructor arguments. These parameters determine R1CS size. **Every distinct
shape is a distinct circuit with a distinct trusted setup, PK, VK, and verifier registration.**
The verifier registry admits only the finite set of registered circuit shapes.

Implication (**MUST**): the verifier registry supports only the *finite set* of shapes whose VKs are
registered. The epoch verifier is keyed by the triple `(maxTransfers, maxInputsPerTransfer,
maxOutputsPerTransfer)` in a dedicated nested mapping `epochVkRegistry`;
deposit/forced are keyed by a single `uint32` param (batch size / max inputs) in the base
`vkRegistry` via `registerVK`. A submission
whose chosen shape has no registered VK reverts `VerifyingKeyNotFound`. Adding a new shape requires
a corresponding trusted setup output and owner-authorized VK registration.

## Verifying-key registration

A VK consists of: G1 `alpha`, G2 `beta`/`gamma`/`delta`, and the IC array `K` (one G1 point per
public input, plus IC[0]). The Solidity verifier expects **negated** `beta`/`gamma`/`delta` (so the
on-chain pairing is a product check against 1). Registered VK components are:

| VK component | On-chain form | Bytes |
|---|---|---|
| `alpha` (G1) | not negated, (x,y) | 64 |
| `betaNeg`, `gammaNeg`, `deltaNeg` (G2) | negated, (x1,x0,y1,y0) each | 128 each |
| **VK constants total** | one SSTORE2 blob | **448** |
| IC[0..icLen-1] X coords | SSTORE2 blob(s), 32 B each | 32·icLen |
| IC[0..icLen-1] Y coords | SSTORE2 blob(s), 32 B each | 32·icLen |

VKs are **not** hardcoded as immutable constants in a per-circuit verifier; they are stored as
**SSTORE2 data contracts** and registered by pointer. The base `Groth16Verifier` holds the
deposit/forced registry mapping
`circuitParam → VKPointers{ icxSources[], icySources[], vkConstants, icLen }` plus the owner-only
`registerVK`; the epoch verifier derives from it and adds its own triple-keyed `epochVkRegistry` and
`registerEpochVK`.

The VK registered on-chain must correspond to the trusted setup for the selected circuit shape. For
ceremony bundle derivation and deployed-verifier mapping, see
[Key Management & Ceremony](11-key-management-ceremony.md).

## On-chain verification

The single shared assembly routine `_verifyProof(proofOffset, publicInputs, vk)`
 performs a standard Groth16 check:

1. Load IC X, IC Y, and VK constants from their SSTORE2 contracts into memory.
2. MSM: `acc = IC[0] + Σ publicInputs[i] · IC[i+1]` using EC-mul precompile `0x07` and EC-add
 precompile `0x06`, with a `scalar < R` check per input.
3. One `ecPairing` (precompile `0x08`) over four pairs:
 `e(A,B)·e(alpha,-beta)·e(acc,-gamma)·e(C,-delta) == 1`.
4. Revert `ProofInvalid` if the pairing result is not 1.

The proof is read directly from calldata at a circuit-specific offset (epoch at `0x64`, after
selector + the three `uint32` params; deposit and forced at `0x24`, after selector + their single
`uint32` param). The proof is the 8-word array `[A.x, A.y,
B.x1, B.x0, B.y1, B.y0, C.x, C.y]`. Note the
**G2 limb order is (x1, x0, y1, y0)**, and the verifier consumes that wire ordering verbatim.

---
