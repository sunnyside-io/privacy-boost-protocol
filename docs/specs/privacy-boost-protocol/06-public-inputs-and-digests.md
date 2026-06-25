# 6. Public Inputs & Operation Digests

This section specifies, for each of the three Groth16 circuits, the exact ordered public-input
vector and the construction that folds the logical inputs into that vector, plus every operation
digest computed on-chain and bound into the proof. The Solidity public-input builders and the gnark
`Pub` structs are two encodings of the *same* ordered vector; protocol components must reproduce
both in lockstep. The
cross-component requirement is normative: the array order produced by each
`build*Inputs` function MUST equal the field-declaration order of the circuit's `Pub` struct
(INV-X01/X02/X03), because gnark serializes the public witness in struct declaration order and
Groth16 verification binds public inputs positionally.

All field elements are BN254 scalars (~254-bit). Two packing schemes and one digest-splitting scheme recur:

- **Counts packing**: five 32-bit
 slots into one field element, `CountOld | (CountNew<<32) | (Rollover<<64) | (NTransfers<<96) |
 (FeeTokenCount<<128)` (160 bits total). Slot width `COUNT_BITS_PER_SLOT=32`, count
 `COUNT_PACKED_SLOTS=5`; unpacked in-circuit by
 `unpackSlots(api, CountsPacked, CountsPackedSlots=5, CountsPackedBitsPerSlot=32)`.
- **Tree-number packing**: up to 16
 tree numbers at 15 bits each, `treeNum[0] | (treeNum[1]<<15) |...` (240 bits total). Width
 `TreeNumberBitsPerSlot=15`; each tree number MUST be `<=
 MAX_NOTE_TREE_NUMBER = 32767`  else revert `TreeNumberOverflow`; slot count MUST be
 `<= MAX_*_ROOTS_PER_PROOF = 16` via `_packTreeData(sparse, maxSlots)`, else revert
 `TooManyDistinctTrees`. Note: `_packTreeData`
 always bounds every tree number against `MAX_NOTE_TREE_NUMBER` (15-bit), even for auth roots —
 there is one shared 15-bit cap; the separate `MAX_AUTH_TREE_NUMBER=32767`
 is numerically identical.
- **Digest splitting**: a 256-bit keccak digest is split as `hi = digest >> 128` and
 `lo = digest & ((1<<128)-1)` so each half fits the scalar field.

The sparse-root representation is shared by all three circuits: `NoteKnownRoots[i]` (a fixed
length-16 array, zero-padded) paired with packed tree-number slot `i` forms a logical `(treeNumber,
root)` pair. **Tree selection is by tree-number match, not slot index** (INV-Z12). The
roots/tree-numbers are folded by `sparseToPackedRootsWithTreeNumbers` /
`sparseToPackedAuthRootsWithTreeNumbers`.

## Digest Encoding Reference

Approval digest preimages and hash/KDF literal constants are specified in
[Appendix B](13-parameters-constants.md). This section names the digest values only where they enter
the public-input vectors. All transfer, withdrawal, and forced-withdrawal authorization digests use
Solidity `abi.encode`; the forced-withdraw request key is the only listed packed keccak value.

| Value | Defined in | Public-input use |
|-------|------------|------------------|
| Transfer approval digest | Appendix B / transfer digest tuple | split into `ApproveDigestHi[t]`, `ApproveDigestLo[t]` |
| Withdrawal approval digest | Appendix B / withdrawal digest tuple | split into `ApproveDigestHi[t]`, `ApproveDigestLo[t]` |
| Forced-withdrawal digest | Appendix B / forced-withdrawal digest tuple | split into `DigestHi`, `DigestLo` |
| Deposit request ID | Appendix B / Poseidon request-id tuple | carried in `DepositRequestIds[i]` |
| Forced request key | Appendix B / packed request key | storage bookkeeping, not a public input |

`Output` and `Withdrawal` ABI tuple layouts are defined in
[Encryption & Message Formats](10-encryption-message-formats.md) and
[Transfer & Withdraw Flow](08-transfer-withdraw-flow.md). Implementations MUST preserve the
standard ABI offsets and element encodings exactly before splitting each keccak digest into
`ApproveDigestHi` and `ApproveDigestLo`.

## Builder Derivations Referenced by Public Inputs

Shared Poseidon derivations for MPK/NPK, commitments, nullifiers, auth leaves/nodes, approval
messages, withdrawal commitments, deposit request ids, and zero roots are centralized in
[Appendix B](13-parameters-constants.md). This section treats those computations as named
derivations and focuses on the field slots that carry their outputs.

The registered verifier profile uses note-tree depth 24 and auth-tree depth 20. The configured note
empty root, auth empty root, and `MERKLE_ZERO_ROOT` distinction are listed in Appendix B.

## EdDSA signature ⇄ digest relationship

For every active transfer (epoch) and for the single forced-withdraw spender, authorization is an
EdDSA (BabyJubjub) signature whose message is `approveMsg = Poseidon(DOMAIN_APPROVE,
ApproveDigestHi, ApproveDigestLo)`. The signature `(R8.x, R8.y, S)` and public key `(PkX,
PkY)` are **private** witness; only the digest halves are public. The circuit constraint
`VerifyEdDSAIf(transferActive, pk, sig, approveMsg)` /
`VerifyEdDSA(pk, sig, approveMsg)` enforces signature
validity, and the same `pk` is hashed into `authLeaf` and proven to be a registry member. Thus the
signature binds the signer's registered key to the exact on-chain transaction details captured by
the digest (INV-Z13/Z14/Z15). The digest halves are computed on-chain (the contract is the digest
authority); the prover does not get to choose them freely because their preimage is fully determined
by public/calldata values. (For the epoch circuit, EdDSA is gated by `transferActive`; the forced
circuit's single signature is verified unconditionally via `VerifyEdDSA`.)

---

## Circuit 1 — Epoch (transfers + withdrawals)

On-chain builder `LibPublicInputs.buildEpochInputs`; circuit `EpochCircuit.Pub` = `EpochPublicInputs`. Shape parameters in this instance: `MaxTransfers`,
`MaxInputsPerTransfer`, `MaxOutputsPerTransfer`, `MaxFeeTokens`, `MAX_NOTE_ROOTS_PER_PROOF=16`,
`MAX_AUTH_ROOTS_PER_PROOF=16`.

**Public-input vector** (index ranges with concrete bases for the 16/16 root arrays; later offsets depend on shape):

| Idx | Field (gnark `Pub`) | Encoding rule | Notes |
|-----|---------------------|-------------------|-------|
| 0..15 | `NoteKnownRoots[0..15]` | `packedRoots` from `treeState.usedRoots` | zero-padded sparse note roots |
| 16 | `NoteKnownTreeNumbersPacked` | `packedTreeNumbers` | 15-bit slots |
| 17 | `DigestRootMask` | `digestRootMask` | bit `i` set ⇒ slot `i` referenced by some per-transfer digest root |
| 18 | `ActiveNoteTreeNumber` | `treeState.activeTreeNumber` | selects active output tree |
| 19 | `ActiveNoteTreeRoot` | `activeTreeRoot` | on-chain `treeRoot[activeTreeNumber]`; frontier binding, distinct from `NoteKnownRoots` (INV-Z16) |
| 20 | `CountsPacked` | `packCounts(countOld,countNew,rollover,nTransfers,feeTokenCount)` | five 32-bit lanes |
| 21 | `RootNew` | `treeState.rootNew` | root after appending all outputs+fee notes |
| 22..37 | `AuthKnownRoots[0..15]` | `packedAuthRoots` from `authState.usedAuthRoots` | zero-padded sparse auth roots |
| 38 | `AuthKnownTreeNumbersPacked` | `packedAuthTreeNumbers` | 15-bit slots |
| 39.. 39+MT·MI−1 | `Nullifiers[t][i]` | `nullifiers[t][i]` | row-major `idx = t*MaxInputsPerTransfer + i` |
| then MT·MO | `CommitmentsOut[t][j]` | `commitmentsOut[t][j]` | row-major `idx = t*MaxOutputsPerTransfer + j` |
| then MT | `ApproveDigestHi[t]` | `approveDigestHi[t]` | one per transfer |
| then MT | `ApproveDigestLo[t]` | `approveDigestLo[t]` | one per transfer |
| then 1 | `FeeNPK` | `feeNPK` | fee receiver NPK |
| then MFT | `FeeCommitmentsOut[j]` | `feeCommitmentsOut[i]` | one per fee token |

(MT=`MaxTransfers`, MI=`MaxInputsPerTransfer`, MO=`MaxOutputsPerTransfer`, MFT=`MaxFeeTokens`.)
Total length `= 16 + 2 + 16 + 1 + 4 + MT·MI + MT·MO + 2·MT + 1 + MFT` (the literal `+2`
and `+4` in code count `[packedTreeNumbers, digestRootMask]` and `[activeTree, activeTreeRoot,
countsPacked, rootNew]` respectively). The canonical order inserts
`DigestRootMask` at index 17, shifting `ActiveNoteTreeNumber→18`, `ActiveNoteTreeRoot→19`,
`CountsPacked→20`, `RootNew→21`, auth roots `22..37`, packed-auth `38`.

**Folding / construction (epoch):**

```text
counts = CountOld | (CountNew<<32) | (Rollover?1:0)<<64 | (NTransfers<<96) | (FeeTokenCount<<128)
PI = [ NoteKnownRoots(16), packedNoteTreeNumbers, DigestRootMask,
 ActiveNoteTreeNumber, ActiveNoteTreeRoot, counts, RootNew,
 AuthKnownRoots(16), packedAuthTreeNumbers,
 Nullifiers[t][i] for t in 0..MT-1, i in 0..MI-1, # row-major
 CommitmentsOut[t][j] for t in 0..MT-1, j in 0..MO-1, # row-major
 ApproveDigestHi[t] for t in 0..MT-1,
 ApproveDigestLo[t] for t in 0..MT-1,
 FeeNPK, FeeCommitmentsOut[j] for j in 0..MFT-1 ]
```

The circuit re-derives every commitment/nullifier/fee value from private witness and asserts
equality with these public slots; fee commitment `= Poseidon(DOMAIN_NOTE, FeeNPK, FeeTokenID[j],
FeeValue[j])`. The active/inactive zero invariant on nullifiers and commitments
(INV-Z20) mirrors the contract `_validateSlotPadding` (INV-C27). `DigestRootMask` coverage is
enforced: a set bit MUST NOT point at a zero root slot, and every non-zero root slot MUST be covered
by an active-input membership or a digest-root selection.

**Epoch digests** (one per transfer, assembled in
`PrivacyBoost._computeTransferDigests`). Each transfer's
slot is classified as a plain transfer or a withdrawal by whether its index appears in
`withdrawalSlots` (the cursor advances in order, requiring
strictly ascending slot order and exact consumption). Non-ascending or duplicate slots revert
`WithdrawalSlotsNotStrictAscending`; a slot outside `nTransfers` or a withdrawal-output mismatch
reverts `InvalidWithdrawal`; `withdrawalSlots.length != withdrawals.length` or an unconsumed
withdrawal reverts `InvalidArrayLengths`. The
per-transfer `root` is **not** a single global root: it is `usedRoots[slotIdx].root` where `slotIdx`
is unpacked from 4-bit packed `digestRootIndices`
(`(word >> ((t%64)*4)) & 0xF`; `slotIdx >= usedRoots.length` reverts `InvalidBatchConfig`), and
`digestRootMask |= 1<<slotIdx`. The trimmed `nullifiers`/`outputs` arrays use the *actual*
per-transfer counts (`inputsPerTransfer[t]`/`outputsPerTransfer[t]`), not the circuit-padded width.

The transfer and withdrawal digest preimages are the exact ABI tuples listed in Appendix B and
include the trimmed `nullifiers`, trimmed `outputs`, `viewingKey`, and `teeWrapKey`. Withdrawal
digests additionally insert the public `Withdrawal{to, tokenId, amount}` tuple after `outputs`. The
resulting digest is split into the `ApproveDigestHi[t]` and `ApproveDigestLo[t]` public-input slots.

For a withdrawal slot the contract additionally requires `amount != 0`
 and `outputs[0].commitment
== computeWithdrawalCommitment(to,tokenId,amount)` (else revert `InvalidWithdrawal`),
where `computeWithdrawalCommitment = Poseidon(DOMAIN_NOTE, uint160(to), tokenId, amount)` =
`hash4(DOMAIN_NOTE, uint160(to), tokenId, amount)`. This
is a contract-internal pseudo-commitment (an address, not an NPK, occupies the second hash slot) and
is never a Merkle leaf.

Thus each epoch digest binds the operation domain, chain/pool replay scope, selected spend root,
ordered input nullifiers, full ordered outputs, shared encryption fields, and, for withdrawals, the
public `(to, tokenId, amount)`.

---

## Circuit 2 — Deposit-epoch

On-chain builder `LibPublicInputs.buildDepositInputs`; circuit `DepositEpochCircuit.Pub` =
`DepositEpochPublicInputs`. Shape: `MaxSlots` (shared
bound for requests and commitments), `MerkleDepth`, `MAX_NOTE_ROOTS_PER_PROOF=16`. Here `maxSlots =
commitmentsOutPadded.length`.

| Idx | Field (gnark `Pub`) | Encoding rule | Notes |
|-----|---------------------|-------------------|-------|
| 0 | `ChainId` | `chainId` | request-id domain separation |
| 1 | `PoolAddress` | `uint256(uint160(pool))` | binds pool address |
| 2..17 | `NoteKnownRoots[0..15]` | `packedRoots` | zero-padded sparse note roots |
| 18 | `NoteKnownTreeNumbersPacked` | `packedTreeNumbers` | 15-bit slots |
| 19 | `ActiveNoteTreeNumber` | `treeState.activeTreeNumber` | output tree id |
| 20 | `CountOld` | `treeState.countOld` | pre-append leaf count |
| 21 | `RootNew` | `treeState.rootNew` | post-append root |
| 22 | `CountNew` | `treeState.countNew` | post-append leaf count |
| 23 | `Rollover` | `treeState.rollover ? 1: 0` | boolean as field |
| 24 | `NRequests` | `nRequests` | 1..MaxSlots |
| 25 | `NTotalCommitments` | `nTotalCommitments` | 1..MaxSlots |
| 26.. 26+S−1 | `DepositRequestIds[i]` | `depositRequestIdsPadded` | zero-padded |
| then S | `TotalAmounts[i]` | `totalAmountsPadded` | zero-padded request slots |
| then S | `CommitmentCounts[i]` | `commitmentCountsPadded` | zero-padded request slots |
| then S | `CommitmentsOut[i]` | `commitmentsOutPadded` | zero-padded output slots |

(S=`MaxSlots`.) Total length `= 16 + 10 + 4·MaxSlots`. Note that here the tree counts are
passed as **separate unpacked fields** (`CountOld/RootNew/CountNew/Rollover` at indices 20–23, in
*that* source order, matching the `Pub` struct), unlike the epoch circuit's packed `CountsPacked`.

**Folding / construction (deposit):**

```text
PI = [ ChainId, PoolAddress,
 NoteKnownRoots(16), packedNoteTreeNumbers,
 ActiveNoteTreeNumber, CountOld, RootNew, CountNew, Rollover,
 NRequests, NTotalCommitments,
 DepositRequestIds(MaxSlots), TotalAmounts(MaxSlots),
 CommitmentCounts(MaxSlots), CommitmentsOut(MaxSlots) ]
```

Arrays are active-first then zero-padded; `CommitmentsOut` MUST be sorted by request (commitments of
request 0, then request 1, …) — enforced structurally because the circuit walks commitments in one
pass keyed by a running `requestIndex` and asserts all requests finalize (`AssertEqual(requestIndex,
NRequests)`). At each request boundary it asserts the per-request total and the request id.

**Deposit request id.** `DepositRequestIds[i]` carries the Poseidon request id defined in Appendix
B. It binds chain, pool, depositor identity, token, public total, depositor nonce, and the exact
ordered set of output commitments through the sequential `commitmentsHash`. Individual per-output
amounts remain hidden in ciphertext; only `totalAmount` is public (INV-C14/INV-Z02). The on-chain
`depositRequestId` value passed in `DepositRequestIds` is the one
stored at `requestDeposit` time; the circuit recomputes it from `(depositor, tokenId, totalAmount,
nonce)` plus the public commitments and asserts equality, binding the batch to genuine pending
requests. `totalAmount` is a public input; the individual output amounts remain private.

---

## Circuit 3 — Forced withdrawal

On-chain builder `LibPublicInputs.buildForcedWithdrawalInputs`; circuit `ForcedWithdrawCircuit.Pub` =
`ForcedWithdrawPublicInputs`. Shape: `MaxInputs`,
`MerkleDepth`, `AuthDepth`, `MAX_NOTE_ROOTS_PER_PROOF=16`, `MAX_AUTH_ROOTS_PER_PROOF=16`. Here
`maxInputs = nullifiersPadded.length`.

| Idx | Field (gnark `Pub`) | Encoding rule | Notes |
|-----|---------------------|-------------------|-------|
| 0..15 | `NoteKnownRoots[0..15]` | `packedRoots` from `sparseRoots` | zero-padded sparse note roots |
| 16 | `NoteKnownTreeNumbersPacked` | `packedTreeNumbers` | 15-bit slots |
| 17..32 | `AuthKnownRoots[0..15]` | `packedAuthRoots` | zero-padded sparse auth roots |
| 33 | `AuthKnownTreeNumbersPacked` | `packedAuthTreeNumbers` | 15-bit slots |
| 34 | `NIn` | `inputCount` | 1..MaxInputs |
| 35 | `SpenderAccountId` | `spenderAccountId` | owner-cancel lookup |
| 36.. 36+N−1 | `Nullifiers[i]` | `nullifiersPadded` | zero-padded |
| then N | `InputCommitments[i]` | `inputCommitmentsPadded` | zero-padded |
| then 1 | `ApproveDigestHi` | `uint256(digest) >> 128` | high 128 bits |
| then 1 | `ApproveDigestLo` | `uint256(digest) & ((1<<128)-1)` | low 128 bits |
| then 1 | `WithdrawalTo` | `uint256(uint160(withdrawalTo))` | recipient address as field |
| then 1 | `WithdrawalTokenID` | `uint256(tokenId)` | compact token id |
| then 1 | `WithdrawalAmount` | `uint256(amount)` | gross |

For `N = MaxInputs`, total length is `16 + 1 + 16 + 1 + 7 + 2·MaxInputs`; the `+7` counts
`NIn`, `SpenderAccountId`, `DigestHi`, `DigestLo`, `WithdrawalTo`, `WithdrawalTokenID`, and
`WithdrawalAmount`.
Here the digest is a **single** keccak digest split into hi/lo by the builder (not two per-transfer
arrays as in epoch), and `WithdrawalTo/TokenID/Amount` are separate public inputs (the circuit
asserts `TransferTokenID == WithdrawalTokenID` and `WithdrawalAmount == Σ active input values`, INV-Z03).

**Folding / construction (forced):**

```text
PI = [ NoteKnownRoots(16), packedNoteTreeNumbers,
 AuthKnownRoots(16), packedAuthTreeNumbers,
 NIn, SpenderAccountId,
 Nullifiers(MaxInputs), InputCommitments(MaxInputs),
 DigestHi, DigestLo,
 WithdrawalTo, WithdrawalTokenID, WithdrawalAmount ]
```

**Forced-withdraw digest.** `DigestHi` and `DigestLo` are the split forced-withdrawal digest defined
in Appendix B and computed at request time. Unlike transfer/withdrawal digests, the forced digest
omits `outputs`, `viewingKey`, and `teeWrapKey`; the emergency-exit path has no encrypted output
metadata. It binds the operation domain, chain, pool, the single active `root`, spent `nullifiers`,
and public withdrawal `(to, tokenId, amount)`.

**Forced-withdraw request key** (storage bookkeeping, not a public input; `computeRequestKey`): `requestKey =
uint256(keccak256(abi.encodePacked(requester, forcedCommitmentsHash)))` where
`forcedCommitmentsHash` denotes the forced-withdrawal
`keccak256(abi.encodePacked(inputCommitments))` value. This is distinct from the deposit circuit's
*Poseidon* `commitmentsHash`. The request also stores
`nullifiersHash = keccak256(abi.encodePacked(nullifiers))` for verification at submission time; the
forced-withdrawal commitments hash is the value folded into the request key.

---

## Cross-encoding invariants (normative)

- **MUST**: each `build*Inputs` output order equals the circuit `Pub` field-declaration order
 (INV-X01/X02/X03). A reordering silently breaks soundness, since Groth16 binds public inputs
 positionally. The positional ordering specified in this section is the normative reference.
- **MUST**: domain separator constants match across implementations (INV-X04);
 `Poseidon2T4` outputs match across Solidity, gnark, and native Go (INV-X05).
- **MUST**: configured tree depths, root-array capacities, and tree-number limits match
 contracts↔circuits (INV-X06); `MAX_NOTE_TREE_NUMBER = MAX_AUTH_TREE_NUMBER = 32767` (15-bit). In
 Solidity these are `MAX_NOTE_TREE_NUMBER`/`MAX_AUTH_TREE_NUMBER`; in gnark they are
 `MaxNoteTreeNumber`/`MaxAuthTreeNumber = (1<<15)-1`.
- **MUST**: tree selection is by `(treeNumber, root)` pair match, not slot index (INV-Z12); exact
 duplicate `(treeNumber,root)` pairs are rejected everywhere; deposit and forced reject duplicate
 `treeNumber`, epoch permits duplicate `treeNumber` (distinct roots) because of OR-based
 per-transfer digest-root selection (INV-C28).
- **MUST**: active nullifier/commitment slots are non-zero and inactive slots zero, enforced
 in-circuit (INV-Z20) and on-chain in `_validateSlotPadding` for epoch (INV-C27).
- The digest hi/lo halves are the only digest data exposed publicly; the EdDSA signature, public
 key, and (for deposit) per-output amounts remain private witness.

---
