# 8. Transfer & Withdraw Flow & EpochCircuit

## Overview

A Privacy Boost note is a UTXO-style shielded balance. Spending happens in **epochs**: a relay
batches up to `maxBatchSize` independent *transfer slots* into one `EpochCircuit` proof and submits
it via `PrivacyBoost.submitEpoch`. Each slot spends 1..`maxInputsPerTransfer` input notes and
creates 1..`maxOutputsPerTransfer` output notes, subject to per-slot value conservation. Two
user-visible operations share this machinery:

- **Transfer (shielded → shielded)**: all outputs are ordinary shielded note commitments.
- **Withdraw (shielded → public)**: the slot is identical in-circuit, but one output commitment is
 the canonical *withdrawal commitment* `Poseidon(DOMAIN_NOTE, uint160(to), tokenId, amount)`, and
 the contract pays `amount` of `tokenId` to `to` after verifying the proof.

A critical design fact: **the `EpochCircuit` itself has no withdrawal leg.** It only proves a batch
of N-in/M-out shielded transfers plus a fee bucket. The distinction between transfer and withdrawal
is made entirely **on-chain** by `submitEpoch`/`_computeTransferDigests`, which selects a different
approval-digest preimage (`PB:WITHDRAW:v1` vs `PB:TRANSFER:v1`) for slots named in
`withdrawalSlots`, and then transfers tokens out of the pool. The circuit only sees the resulting
`(ApproveDigestHi, ApproveDigestLo)` per slot and binds the EdDSA signature to it.

Poseidon domain tags, range-check widths, tree-number packing widths, and scalar-field constants are
defined in [Appendix B](13-parameters-constants.md). This flow uses them through the note, nullifier,
auth-root, and approval-digest formulas below. Empty-subtree node hashing uses
`Poseidon(left,right)` with **no** domain; the auth-registry tree instead uses domain-separated nodes
`Poseidon(domainRegNode, left, right)`.

## Note model and core cryptographic computations

A note is owned by a *master public key* derived from a (secret) nullifying key and an account id;
its commitment binds NPK, token id, and value.

```text
MPK = Poseidon(domainMPK, SpenderAccountId, NullifyingKey)
NPK = Poseidon(domainNote, MPK, noteRnd)
commitment = Poseidon(domainNote, NPK, tokenId, value)
nullifier = Poseidon(domainNullifier + treeNumber * NullifierTreeNumberMultiplier,
 NullifyingKey, noteLeafIndex)
authLeaf = Poseidon(domainRegLeaf, SpenderAccountId,
 AuthPkX, AuthPkY, AuthExpiry)
approveMsg = Poseidon(domainApprove, ApproveDigestHi, ApproveDigestLo)
feeCommitment = Poseidon(domainNote, FeeNPK, FeeTokenID, FeeValue)
```

The native prover uses the same formulas for master public keys, note public keys, commitments,
nullifiers, approve messages, auth leaves, and auth tree nodes.

The nullifier domain is offset by `treeNumber * NullifierTreeNumberMultiplier`, so the *same*
`(NullifyingKey, leafIndex)` spent against a different
historical tree yields a distinct nullifier. This prevents cross-tree nullifier confusion
(`AssertRootWithTreeNumberIf` additionally binds the proven root to its claimed tree number).

Withdrawal commitment (recipient address occupies the NPK field):

```text
withdrawalCommitment = Poseidon2T4.hash4(DOMAIN_NOTE, uint160(to), tokenId, amount)
```

Because the in-circuit output commitment is `Poseidon(domainNote, OutputNPK, TransferTokenID,
OutputValue)`, a withdrawal is realized off-circuit by setting, for the withdrawal output,
`OutputNPK = field(uint160(to))` and `OutputValue = amount` (with `TransferTokenID = tokenId`). The
SDK/caller assigns these output fields; the witness builder reads them — for the withdrawal slot it
recovers `to/amount` directly from `output[0]` (`FieldToAddress(outputs[0].npk)`,
`outputs[0].value`) to build the withdrawal record
and digest. The circuit treats `output[0]` as an ordinary output and appends it to the tree like any
other. The protocol treats this commitment as cryptographically unspendable in normal operation
because no normal recipient preimage is provided for `NPK = uint160(to)`; the contract does not keep
a separate "withdrawal commitment" spent/unspendable flag. Later spends are still governed by the
ordinary in-circuit note preimage, Merkle membership, authorization, and nullifier checks.

## Approval digests (the transfer/withdraw distinction)

Each active slot must be authorized by an EdDSA signature over a keccak256 *approval digest* split
into 128-bit `(hi, lo)`. The preimage differs by operation:

```text
TRANSFER_DOMAIN = "PB:TRANSFER:v1" WITHDRAW_DOMAIN = "PB:WITHDRAW:v1"

transferDigest = keccak256(abi.encode(
 TRANSFER_DOMAIN, chainId, pool, root,
 nullifiers[], outputs[], viewingKey, teeWrapKey))

withdrawalDigest = keccak256(abi.encode(
 WITHDRAW_DOMAIN, chainId, pool, root,
 nullifiers[], outputs[], withdrawal, viewingKey, teeWrapKey))

hi = digest >> 128; lo = digest & (2^128 - 1)
```

`chainId` is `block.chainid` and `pool` is `address(this)`. `root` is the per-slot *digest root* selected
via `digestRootIndices` (the historical note root the spender signed against);
`nullifiers[]`/`outputs[]` are the **trimmed** (actual-count, not circuit-padded) arrays built in
`_computeTransferDigests`; `withdrawal = (to, tokenId,
amount)`. `viewingKey`/`teeWrapKey` are per-`Transfer` shared keys, not per-output; the per-output `Output` carries
`commitment, receiverWrapKey, ct0, ct1, ct2, ct3`.
The Go prover mirrors this exactly with go-ethereum ABI packing; the `Output` ABI tuple is
`commitment(uint256), receiverWrapKey(bytes32), ct0(bytes32), ct1(bytes32), ct2(bytes32),
ct3(bytes16)`.

Normative: the contract recomputes both digests from calldata and feeds them as public inputs; the
proof's EdDSA check binds the signature to whichever digest the contract computed. A slot is a
withdrawal **iff** its index appears in `withdrawalSlots` and matches the sequential withdrawal
cursor. For a withdrawal slot the contract additionally
requires `transfers[t].outputs[0].commitment == computeWithdrawalCommitment(to, tokenId, amount)`
and `amount != 0`, else `InvalidWithdrawal`. MUST:
`withdrawalSlots` is strictly ascending, unique, and each entry `< nTransfers`
(`_validateWithdrawalSlots`, revert `InvalidWithdrawal`
for `slot >= nTransfers` and `WithdrawalSlotsNotStrictAscending` for non-ascending;
`withdrawalSlots.length == withdrawals.length` else `InvalidArrayLengths`). MUST: the withdrawal
cursor consumes every withdrawal exactly once, else `InvalidArrayLengths`.

## EpochCircuit structure

Compile-time shape: `MaxTransfers`,
`MaxInputsPerTransfer`, `MaxOutputsPerTransfer`, `MaxFeeTokens`, `NoteDepth`, `AuthDepth`,
`MaxNoteRootsPerProof`, `MaxAuthRootsPerProof`. The deployed verifier is selected by
`(circuitMaxTransfers, circuitMaxInputs, circuitMaxOutputs)` derived from calldata array lengths and
dispatched via
`epochVerifier.verifyEpoch(circuitMaxTransfers, circuitMaxInputs, circuitMaxOutputs, proof, publicInputs)`.
The protocol caps are the contract immutables `maxBatchSize`, `maxInputsPerTransfer`, and
`maxOutputsPerTransfer`.

Public inputs:

| Field | Shape | Meaning |
|-------|-------|---------|
| `NoteKnownRoots` | `[MaxNoteRootsPerProof]` | historical note tree roots available for input spending; zero = padding |
| `NoteKnownTreeNumbersPacked` | scalar | 15-bit packed tree numbers, slot-aligned with `NoteKnownRoots` |
| `DigestRootMask` | scalar | bit i set ⇔ slot i referenced as a per-slot digest root |
| `ActiveNoteTreeNumber` | scalar | which tree receives the appended outputs |
| `ActiveNoteTreeRoot` | scalar | current root of active tree, bound to `NoteFrontierOld` |
| `CountsPacked` | scalar | `countOld \| countNew<<32 \| rollover<<64 \| nTransfers<<96 \| feeTokenCount<<128` |
| `RootNew` | scalar | root after appending all outputs + fee notes |
| `AuthKnownRoots` | `[MaxAuthRootsPerProof]` | snapshotted auth registry roots |
| `AuthKnownTreeNumbersPacked` | scalar | packed auth tree numbers |
| `Nullifiers` | `[MaxTransfers][MaxInputsPerTransfer]` | per-input nullifiers; non-zero ⇔ active |
| `CommitmentsOut` | `[MaxTransfers][MaxOutputsPerTransfer]` | per-output commitments; non-zero ⇔ active |
| `ApproveDigestHi/Lo` | `[MaxTransfers]` each | per-slot approval digest halves |
| `FeeNPK` | scalar | fee receiver's NPK |
| `FeeCommitmentsOut` | `[MaxFeeTokens]` | fee note commitments per fee bucket |

Key private inputs: per-slot
`InputsPerTransfer`, `OutputsPerTransfer`, `AuthTreeNumber`, `SpenderAccountId`, `TransferTokenID`,
`NullifyingKey`, EdDSA `(AuthPkX,AuthPkY,AuthSigR8x,AuthSigR8y,AuthSigS)`, `AuthExpiry`,
`AuthLeafIndex`, `AuthPathElements[AuthDepth]`, `FeePerTransfer`; per-input `InputNoteTreeNumber`,
`InputValue`, `InputNoteRnd`, `InputNoteLeafIndex`, `InputNotePath[NoteDepth]`; per-output
`OutputNPK`, `OutputValue`; `NoteFrontierOld[NoteDepth]`; per-fee-bucket `FeeTokenID`, `FeeValue`.

The public-input vector flattening (contract↔verifier ABI contract) is, in order:
`NoteKnownRoots(16)`, `packedTreeNumbers`, `digestRootMask`, `activeTree`, `activeTreeRoot`,
`countsPacked`, `rootNew`, `authRoots(16)`, `packedAuthTreeNumbers`,
`nullifiers(maxTransfers*maxInputs, row-major)`, `commitments(maxTransfers*maxOutputs, row-major)`,
`digestHi(maxTransfers)`, `digestLo(maxTransfers)`, `feeNPK`, `feeCommitments(maxFeeTokens)`.
The contract reads `activeTreeRoot` from on-chain state (`treeRoot[activeTreeNumber]`), independent
of `NoteKnownRoots`.

## In-circuit constraints

Active gating: `transferActive[t]:= t < NTransfers` (`computeTransferActiveFlags`),
`feeActive[j]:= j < FeeTokenCount` (`validateFeeTokenInputs`); per-input/output activity
additionally `< InputsPerTransfer[t]` / `< OutputsPerTransfer[t]`. Inactive slots are
still well-formed but their constraints are disabled.

1. **Range/bounds** (`validatePublicInputsAndInitTreeState`+`validatePerTransferInputs`):
 `1 ≤ NTransfers ≤ MaxTransfers`, `1 ≤ FeeTokenCount ≤ MaxFeeTokens`, `ActiveNoteTreeNumber ≤ MaxNoteTreeNumber`, `countOld,countNew ∈ [0,
 2^NoteDepth]`, all values `AmountBits`-bounded, fee token ids `TokenIDBits`-bounded.

2. **Rollover/frontier binding** (`validatePublicInputsAndInitTreeState`): `rollover` is
 boolean. If `rollover=0`, `countOld < 2^NoteDepth` and
 `computeRootFromFrontier(NoteFrontierOld, countOld) == ActiveNoteTreeRoot`. If
 `rollover=1`, `countOld == 2^NoteDepth` (tree must be full) and appends start from
 `(count=0, frontier=0)`.

3. **Fee bucket structure** (`validateFeeTokenInputs`): first `FeeTokenCount` `FeeTokenID`
 are non-zero and pairwise distinct; the rest zero.

4. **Auth** (`verifyAuth`), per active slot: verify EdDSA over `approveMsg =
 Poseidon(domainApprove, ApproveDigestHi[t], ApproveDigestLo[t])` (`VerifyEdDSAIf`);
 compute `authLeaf`, derive `authRoot` via domain-separated Merkle path
 (`computeDomainRoot` with `domainRegNode`); assert `(authRoot, AuthTreeNumber[t])` is a
 known `(AuthKnownRoots, AuthKnownTreeNumbers)` pair (`AssertRootWithTreeNumberIf`).

5. **Inputs** (`assertInputNotes`+`assertNullifier`), per active input: require
 `TransferTokenID != 0`, recompute `inputCommitment` (MPK→NPK→commitment),
 prove Merkle membership and bind `(rootComputed, InputNoteTreeNumber[t][i])` to a known note-root
 pair; recompute `nullifier` and assert it equals public `Nullifiers[t][i]`.
 **Zero/non-zero invariant**: active nullifier non-zero, inactive nullifier zero —
 this binds per-slot input counts between circuit and contract.

6. **Outputs** (`assertOutputNotes`): active output commitment equals recomputed
 `Poseidon(domainNote, OutputNPK, TransferTokenID, OutputValue)` and is non-zero; inactive output
 commitment is zero. Each active output is appended to the evolving frontier
 (`appendCommitmentToFrontierMulti`).

7. **Value conservation** (`applyFeeAndAccumulate`): per active slot, `sum(InputValue
 active) == sum(OutputValue active) + FeePerTransfer[t]`, all sums
 `AmountBits`-bounded. The slot's fee routes into exactly one fee bucket
 whose `FeeTokenID[j] == TransferTokenID[t]` (`matchCount == 1`). Withdrawals are **not**
 a separate term here — the withdrawn `amount` is simply the value of the withdrawal *output*
 note, so conservation reads `inputs == outputs(incl. withdrawal output) + fee`.

8. **Fee outputs** (`processFeeCommitments`): active `FeeValue[j] == feeSums[j]`;
 fee commitment `= Poseidon(domainNote, FeeNPK, FeeTokenID[j], FeeValue[j])` equals public
 `FeeCommitmentsOut[j]` and is non-zero, appended; inactive buckets zero.

9. **Canonical root coverage** (`assertNoteKnownRootsCoverage`): every non-zero
 `NoteKnownRoots[s]` MUST be referenced by ≥1 active input membership or by `DigestRootMask` bit s; a set digest bit MUST NOT point at an empty slot. This forbids
 unused/padding roots from smuggling state.

10. **Final state** (`assertFinalState`): the recomputed root after all appends equals
 `RootNew`, and the evolving count equals `countNew`. When the tree fills exactly, the circuit
 selects `fullTreeRoot` (the final carry from `appendFrontier`); otherwise it uses
 `computeRootFromFrontier`.

Note: the circuit does **not** check nullifier uniqueness across slots, nor that the provided root
arrays match on-chain history — both are enforced on-chain.

## On-chain processing: `submitEpoch`

Signature and ordering:

1. **Config bounds**: `circuitMaxTransfers = nullifiers.length`, `1 ≤
 circuitMaxTransfers ≤ maxBatchSize`; `1 ≤ nTransfers ≤ circuitMaxTransfers`; array length
 consistency (`inputsPerTransfer`/`outputsPerTransfer`/`transfers` lengths ==
 `circuitMaxTransfers`, `feeTransfer.outputs.length == maxFeeTokens`); per-row `circuitMaxInputs =
 nullifiers[0].length`, `circuitMaxOutputs = transfers[0].outputs.length`, each `≤` the immutable
 cap; per-slot `inputsPerTransfer`/`outputsPerTransfer` non-zero and ≤ circuit max for active
 slots, exactly zero for inactive slots. Reverts `InvalidEpochConfig`/`InvalidArrayLengths`.
2. **State binding**: `treeState.activeTreeNumber == currentTreeNumber`,
 `treeState.countOld == treeCount[activeTreeNumber]`, else `InvalidEpochState`.
 `_validateKnownRoots(usedRoots, activeTreeNumber, allowDuplicateTreeNumbers=true)`
 checks `1 ≤ len ≤ MAX_NOTE_ROOTS_PER_PROOF`, each sparse root is known via `isKnownTreeRoot`, and
 that the active tree is present (else `InvalidEpochState`); exact-duplicate `(treeNumber,root)`
pairs revert `DuplicateTreeRootPair`. `activeRoot = treeRoot[activeTreeNumber]`
 (used as the frontier-binding root, independent of the historical roots used for
 spending). Auth roots validated/lazily snapshotted (`_validateAuthKnownRootsSparse`).
 `feeTokenCount` bounds checked.
3. **Digest index encoding**: `digestRootIndices` packs one 4-bit slot index per active
 transfer, 64 per word; exactly `ceil(nTransfers/64)` words else `InvalidArrayLengths`; padding
 bits in the last word must be zero else `NonCanonicalEncoding`.
4. **Capacity** (`_validateTreeCapacity`): `countNew == (rollover ? totalOutputs:
 countOld+totalOutputs)` where `totalOutputs = Σ outputsPerTransfer + feeTokenCount`;
 `rollover` requires `countOld == 2^merkleDepth`, non-rollover requires `countOld <
 2^merkleDepth`; `countNew ≤ 2^merkleDepth`. Reverts `InvalidEpochState`.
5. **Digest computation** (`_computeTransferDigests`): per active slot resolves its 4-bit
 digest-root index into `usedRoots[slotIdx].root` (`slotIdx >= usedRoots.length` reverts
 `InvalidBatchConfig`), ORs `digestRootMask |= 1<<slotIdx`, copies the M output
 commitments, builds trimmed nullifier/output arrays, and computes `transferDigest` or
 `withdrawalDigest` (the latter for slots matching the next `withdrawalSlots` cursor, with the
 `outputs[0].commitment == withdrawalCommitment` and `amount != 0` checks).
6. **Slot padding** (`_validateSlotPadding`): re-asserts the zero/non-zero invariant on
 nullifiers and commitments against per-slot counts; mismatch reverts `InvalidSlotPadding`.
7. **Verify**: build public inputs via `LibPublicInputs.buildEpochInputs`, call
 `epochVerifier.verifyEpoch(circuitMaxTransfers, circuitMaxInputs, circuitMaxOutputs, proof,
 publicInputs)`.
8. **Spend nullifiers** (`_spendNullifiers`): for every active input, require `nullifier != 0` and
 `!nullifierSpent[nullifier]`, then mark spent. Double-spend or zero reverts
 `InvalidNullifierSet`. This is where cross-slot/global uniqueness is enforced.
9. **Pay withdrawals** (`_processWithdrawals`): for each `Withdrawal w`,
 `_transferToken(w.tokenId, w.to, w.amount)`, which performs `safeTransfer` of the registered
 ERC20; unregistered token reverts `InvalidWithdrawal`, non-ERC20 reverts `TokenNotSupported`.
10. **Update tree** (`_updateTreeState`): if `rollover`, advance `currentTreeNumber`
 (overflow past `MAX_NOTE_TREE_NUMBER` reverts `InvalidEpochState`), set new tree's
 `treeRoot`/`treeCount`, push to its ring buffer, emit `TreeAdvanced`; else update active tree's
 `treeRoot`/`treeCount` and push `rootNew` into `treeRootHistory` (ring buffer size 64). Emits
 `EpochSubmitted`.

**Fee handling for epoch withdrawals**: `_processWithdrawals` pays `w.amount` verbatim — there is
**no** protocol `withdrawFeeBps` deduction on the epoch path (that fee only applies to the 2-step
*forced* withdrawal path, where `feeAmount = grossAmount*requestFeeBps/10000` and `netAmount =
grossAmount - feeAmount`; fee bps capped at `MAX_FEE_BPS = 1000` i.e. 10%). The only fee in an epoch is the per-slot `FeePerTransfer`, paid to the fee receiver
as a shielded fee note (`FeeNPK`) inside the tree, off-chain-computed and conservation-enforced; the
contract does not move tokens for it.

## Root history and replay protection

`isKnownTreeRoot`: `root==0` never known; current
root of any tree is known (O(1)); finalized trees (`treeNum < currentTreeNumber`) accept
only their final root; the current tree additionally accepts the last
`ROOT_HISTORY_SIZE=64` roots via the ring buffer. This lets users sign a digest against
a slightly stale root and still have the relay submit before more epochs land. Because
`treeState.countOld`/`activeRoot` are pinned to live on-chain state and nullifiers are globally
marked, proof replay and stale-state submission are rejected.

## End-to-end sequences

**Transfer (shielded → shielded):**
1. SDK selects input notes covering `target = Σoutputs + fee`; computes change/recipient output
 notes (`OutputNPK`, `OutputValue`, randomness, viewing/TEE/receiver keys).
2. For each input it gathers `(value, rnd, leafIndex, treeNumber, Merkle path)` and the spender's
 `(accountId, nullifyingKey)`; derives nullifiers.
3. It picks a *signed root* per slot (a known historical root) and computes
 `transferDigest=(hi,lo)`; the user's auth key signs `approveMsg = Poseidon(domainApprove, hi,
 lo)` via EdDSA.
4. Prover builds the witness, batching slots,
 accumulating fee buckets, and computing `RootNew/countNew` by appending all outputs + fee notes
 to the active frontier; generates the Groth16 proof.
5. Relay calls `submitEpoch` with `withdrawals=[]`, `withdrawalSlots=[]`. Contract verifies, marks
 nullifiers spent, appends commitments (root push), emits `EpochSubmitted`. No tokens move.

**Withdraw (shielded → public):**
1–2. As above, but for the withdrawing slot the SDK sets output[0] to the withdrawal output:
`OutputNPK = field(uint160(to))`, `OutputValue = amount`, `TransferTokenID = tokenId`; its
commitment equals `computeWithdrawalCommitment(to, tokenId, amount)`. Remaining outputs (e.g.
change) are ordinary notes; conservation still holds: `inputs == outputs(incl. withdrawal) + fee`.
3. The slot's digest is the `withdrawalDigest` (includes the `(to,tokenId,amount)` tuple); user signs it.
4. Prover builds an identical-shaped witness (the circuit is unaware this is a withdrawal); the
 builder recovers the withdrawal record from `output[0]` and emits `Withdrawals`/`WithdrawalSlots`
 for the relay; proof generated. A standalone entrypoint exercises this path with synthetic
 witnesses.
5. Relay calls `submitEpoch` with `withdrawals=[(to,tokenId,amount),...]` and ascending
 `withdrawalSlots`. Contract recomputes the withdrawal digest, checks `outputs[0].commitment ==
 withdrawalCommitment` and `amount != 0`, verifies the proof, marks nullifiers spent, **pays
 `amount` of `tokenId` to `to`** via `safeTransfer`, appends commitments, pushes root, emits
 `EpochSubmitted`.

---
