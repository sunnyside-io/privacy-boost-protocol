# 7. Deposit Flow & DepositEpochCircuit

## Overview

A deposit moves value from the public EVM layer into the shielded note-commitment tree. It is a
**two-step process** with an asynchronous, batched settlement:

1. **Step 1 — `requestDeposit` (depositor → contract).** The depositor escrows ERC-20 tokens into
 the `PrivacyBoost` pool and records a *pending deposit*. The total amount is public; the
 per-output split, recipients, and note randomness are hidden inside encrypted ciphertexts
 published on calldata. Output note commitments are revealed but not yet inserted into any tree.
2. **Step 2 — `submitDepositEpoch` (relay/TEE → contract).** An allowed relay batches one or more
 pending deposits, generates a single Groth16 proof of the `DepositEpochCircuit`, and submits it.
 The circuit proves that every revealed commitment correctly encodes the witness-supplied
 `NPK/token/value`, that per-request totals are conserved, that each request id binds to its
 public/private fields, and that all commitments are appended to the active tree producing
 `(RootNew, CountNew)`. It does not prove recipient ownership or ciphertext recoverability. The
 contract verifies the proof against the exact current tree state and advances tree state.

A depositor whose request is never processed can reclaim escrowed funds via `cancelDeposit` after a
delay. There is no on-chain refund inside epoch processing; refund is the depositor-initiated cancel
path only.

The deposit circuit uses the note-commitment and deposit-request domain tags, token type, root
count, and tree-number bounds listed in [Appendix B](13-parameters-constants.md). The contract,
circuit, and prover must use the same symbolic constants for these values.

## Hashing primitive

All deposit hashing uses the BN254 **Poseidon2 T4 sponge** (rate = 3, capacity = 1, output = first
state lane). The Go circuit calls `Poseidon2T4(api, inputs...)` as a single variadic sponge; the Solidity side exposes fixed-arity `hashN` wrappers that are
byte-for-byte the same sponge. A `hashK` call is identical to absorbing `K` inputs in the sponge. Both sides operate
mod the BN254 scalar field; `requestDeposit` additionally rejects any commitment `>=
SNARK_SCALAR_FIELD`.

```text
// Note commitment (4-input sponge == Poseidon2T4.hash4)
Commitment = Poseidon2T4( DOMAIN_NOTE, NPK, tokenId, value )
// NPK = recipient Note Public Key (witness; circuit does NOT re-derive it)
// tokenId= compact uint16 token id (per request)
// value = per-output amount (uint96 range)

// Sequential commitments hash over a request's K commitments (c_0..c_{K-1})
// each step is a 2-input sponge == Poseidon2T4.hash2
h_0 = 0
h_{i+1} = Poseidon2T4( h_i, c_i )
commitmentsHash = h_K

// Deposit request id (8-input sponge == Poseidon2T4.hash8)
depositRequestId = Poseidon2T4(
 DOMAIN_DEPOSIT_REQUEST,
 chainId, // block.chainid
 uint160(pool), // PrivacyBoost contract address as field element
 uint160(depositor),
 tokenId, // uint16
 totalAmount, // uint96, == sum of per-output values
 nonce, // per-depositor uint32, monotonic
 commitmentsHash )
```

The same field order is used by note commitments, withdrawal commitments, prover-side note
commitment construction, sequential deposit commitment hashing, and the deposit request-id circuit
path.
The depositor never re-derives the recipient `NPK` on-chain or in-circuit; ownership of the output
note belongs to whoever knows the preimage of `NPK`, and the circuit binds `NPK` as given.

## Step 1 — `requestDeposit`

Signature:

```text
function requestDeposit(
 uint16 _tokenId,
 uint96 _totalAmount,
 uint256[] calldata _commitments,
 DepositCiphertext[] calldata _ciphertexts
) external nonReentrant returns (uint256 depositRequestId)
```

Access: permissionless (any address). Reentrancy-guarded.

Validation and effects, in order:

| Step | Action | Revert on failure |
|------|--------|-------------------|
| 1 | `commitmentCount` in `[1, maxBatchSize]` | `InvalidDeposit` |
| 2 | `_totalAmount != 0` | `InvalidDeposit` |
| 3 | `_commitments.length == _ciphertexts.length` | `InvalidArrayLengths` |
| 4 | each commitment `!= 0` and `< SNARK_SCALAR_FIELD`; fold into `commitmentsHash` sequentially | `InvalidDeposit` |
| 5 | token resolves via `tokenRegistry.tokenOf(_tokenId)`, address `!= 0` | `InvalidDeposit` |
| 6 | token type `== TOKEN_TYPE_ERC20 (0)` | `TokenNotSupported` |
| 7 | `safeTransferFrom(depositor, pool, _totalAmount)`; measured received delta must equal `_totalAmount` (fee-on-transfer rejected) | `FeeOnTransferNotSupported` |
| 8 | `nonce = depositNonces[msg.sender]++` (post-increment) | — |
| 9 | compute `depositRequestId` (8-input digest above) | — |
| 10 | require `pendingDeposits[depositRequestId].depositor == 0` | `DepositAlreadyExists` |
| 11 | store `PendingDeposit`, emit `DepositRequested` | — |

Stored `PendingDeposit`:

| Field | Type | Meaning |
|-------|------|---------|
| `depositor` | `address` | `msg.sender`; non-zero sentinel for existence |
| `tokenId` | `uint16` | compact token id |
| `totalAmount` | `uint96` | public total (sum of hidden per-output amounts) |
| `requestBlock` | `uint64` | `block.number` at request; cancel-delay anchor |
| `nonce` | `uint32` | per-depositor monotonic nonce |
| `commitmentCount` | `uint16` | number of commitments in this request (≤ 65535) |
| `commitmentsHash` | `uint256` | sequential Poseidon over the request's commitments |

`DepositRequested` event carries
`depositRequestId` (indexed), `depositor` (indexed), `tokenId`, `totalAmount`, `commitmentCount`,
`commitmentsHash`, the full `commitments[]`, and the `DepositCiphertext[]`. The ciphertexts are the
only channel by which the TEE/recipient learn per-output `(recipientMPK, tokenId, amount,
noteRnd)` — payload is `recipientMPK(32)+tokenId(2)+amount(12)+noteRnd(16)=62B`, AES-256-GCM →
78B (`ct0`+`ct1`+16-byte `ct2` tag). Each `DepositCiphertext` also carries three 32-byte ECDH wrap
keys: `viewingKey` (blinded sender viewing key), `teeWrapKey` (wrapped ephemeral key for the TEE),
and `receiverWrapKey` (wrapped ephemeral key for the receiver).

Invariants established by Step 1:
- The contract **MUST** escrow exactly `_totalAmount` before the request is recorded; the per-output
 amounts are never revealed on-chain.
- The `commitmentsHash` and `depositRequestId` **MUST** bind commitment order — sequential hashing
 makes reordering produce a different id.
- `depositRequestId` **MUST** be unique; `(chainId, pool, depositor, tokenId, totalAmount, nonce,
 commitmentsHash)` are all bound, so the per-depositor `nonce` guarantees uniqueness even for
 otherwise-identical requests, and a hash collision into an existing entry reverts
 `DepositAlreadyExists`.

## Step 1b — `cancelDeposit` (refund path)

Signature `cancelDeposit(uint256 _depositRequestId)`. Access:
only the original `depositor`. Reentrancy-guarded (`nonReentrant`).

| Check | Revert |
|-------|--------|
| `pd.depositor == msg.sender` | `NotDepositor` |
| `!processedDeposits[_depositRequestId]` | `DepositAlreadyProcessed` |
| `block.number >= pd.requestBlock + cancelDelay` | `CancelTooEarly` |

On success it transfers `pd.totalAmount` of the request's token back to the depositor and `delete`s
the `pendingDeposits` entry, emitting `DepositCancelled`. `cancelDelay` is an immutable
set at construction. This is the **only** refund mechanism
— a deposit that cannot be processed in an epoch is not auto-refunded; the depositor must cancel
after the delay.

Note the asymmetry: epoch processing sets `processedDeposits[id] = true` but intentionally *retains*
the `pendingDeposits` entry for observability; only `cancelDeposit` clears storage.

## DepositEpochCircuit — shape and I/O

The deposit circuit is over BN254. Proving system at the contract
boundary: Groth16 (`Groth16DepositVerifier`; `verifyDeposit(uint32 batchSize, uint256[8] proof,
uint256[] publicInputs)`). Shape parameters (`DepositEpochShape`):

| Parameter | Meaning |
|-----------|---------|
| `MaxSlots` | shared compile-time bound for both request slots and commitment slots |
| `MerkleDepth` | depth of note trees; leaf capacity `= 2^MerkleDepth` |
| `MaxNoteRootsPerProof` | number of historical roots provided (contract pins 16) |

Arrays are fixed-size to `MaxSlots`; only the first `NRequests` request slots and first
`NTotalCommitments` commitment slots are active, all others **MUST** be zero. `CommitmentsOut` is
ordered request-by-request: all commitments of request 0, then request 1, etc..

**Public inputs** (`DepositEpochPublicInputs`); the on-chain flattening order is fixed by
`LibPublicInputs.buildDepositInputs`:

| Order | Field | Count | Meaning |
|-------|-------|-------|------------------|
| 0 | `ChainId` | 1 | `block.chainid`, bound into request id |
| 1 | `PoolAddress` | 1 | `uint160(address(this))`, bound into request id |
| 2..17 | `NoteKnownRoots` | 16 | historical note-tree roots, sparse-packed from `treeState.usedRoots` |
| 18 | `NoteKnownTreeNumbersPacked` | 1 | tree numbers packed 15 bits each |
| 19 | `ActiveNoteTreeNumber` | 1 | tree number (not slot index) selected as output tree |
| 20 | `CountOld` | 1 | leaf count before appends |
| 21 | `RootNew` | 1 | root after appending all active commitments |
| 22 | `CountNew` | 1 | leaf count after appends |
| 23 | `Rollover` | 1 | 0/1 flag |
| 24 | `NRequests` | 1 | active request count, `1..MaxSlots` |
| 25 | `NTotalCommitments` | 1 | active commitment count, `1..MaxSlots` |
| 26..26+M | `DepositRequestIds` | `MaxSlots` | per-request id (zero-padded) |
| … | `TotalAmounts` | `MaxSlots` | per-request total (zero-padded) |
| … | `CommitmentCounts` | `MaxSlots` | per-request commitment count (zero-padded) |
| … | `CommitmentsOut` | `MaxSlots` | output commitments (zero-padded) |

Total length `= MAX_NOTE_ROOTS_PER_PROOF + 10 + maxSlots*4`.

**Private inputs** (`DepositEpochPrivateInputs`):

| Field | Count | Meaning |
|-------|-------|---------|
| `Depositors` | `MaxSlots` | depositor address per request (request-id digest) |
| `TokenIDs` | `MaxSlots` | token id per request (commitment + request-id digest) |
| `Nonces` | `MaxSlots` | nonce per request (request-id digest) |
| `OutputNPKs` | `MaxSlots` | recipient NPK per commitment (witness only) |
| `OutputValues` | `MaxSlots` | per-commitment value (witness only) |
| `NoteFrontierOld` | `MerkleDepth` | frontier of the active output tree before appends |

## DepositEpochCircuit — constraints

`Define` builds the constraint system in five phases.

**1. Public bounds and tree-state init** (`validatePublicInputsAndInitTreeState`):
- `CountOld`, `CountNew` range-checked to `CountBits = 32`; `1 <=
 NRequests <= MaxSlots`, `1 <= NTotalCommitments <= MaxSlots`.
- `ActiveNoteTreeNumber <= MaxNoteTreeNumber (32767)`.
- `CountOld, CountNew <= 2^MerkleDepth`.
- **Rollover semantics**: `Rollover` is boolean. If `Rollover = 0`, `CountOld <
 2^MerkleDepth`; if `Rollover = 1`, `CountOld == 2^MerkleDepth` (the old tree is full).
- **Active-root selection**: unpacks tree numbers, asserts **exactly one** sparse slot
 matches `ActiveNoteTreeNumber` (`AssertSingleActiveRootForTreeNumber`), selects that root,
 recomputes the root from `NoteFrontierOld` + `CountOld`, and — when not rolling over — asserts the
 frontier-derived root equals the selected active root. On rollover the working count/frontier are
 reset to an empty tree.

**2. Request header integrity** (`assertTotalCommitmentCount`):
- Active requests **MUST** have `CommitmentCounts[r] >= 1`; inactive request slots **MUST** be zero
 in `CommitmentCounts`, `DepositRequestIds`, `TotalAmounts`, `Depositors`, `TokenIDs`, `Nonces`.
- `sum_{active r} CommitmentCounts[r] == NTotalCommitments`.

**3. Value range checks**: every `OutputValues[i]` range-checked to `AmountBits = 96`, preventing overflow in running sums.

**4. Per-commitment pass + tree append** (`processCommitments`), single loop over
`MaxSlots` with a moving `requestIndex`:
- Inactive commitment slots: `CommitmentsOut[i]`, `OutputNPKs[i]`, `OutputValues[i]` **MUST** be zero.
- Active commitments **MUST** have non-zero value — bars zero-value leaves from consuming tree capacity.
- **Commitment correctness:** `expected = Poseidon2T4(domainNote, OutputNPKs[i], tokenId,
 OutputValues[i])` with `tokenId = TokenIDs[requestIndex]`; assert `expected == CommitmentsOut[i]`
 and `CommitmentsOut[i] != 0` for active slots.
- Accumulate `requestValueSum` and fold `requestCommitmentsHash =
 Poseidon2T4(requestCommitmentsHash, CommitmentsOut[i])`.
- On reaching `CommitmentCounts[requestIndex]` commitments, **finalize the request**:
 assert `requestValueSum == TotalAmounts[requestIndex]` (**amount conservation**) and assert
 `Poseidon2T4(domainDepositRequest, ChainId, PoolAddress, depositor, tokenId, expectedTotal, nonce,
 requestCommitmentsHash) == DepositRequestIds[requestIndex]` (**request-id binding**), then reset
 accumulators and advance `requestIndex`.
- **Tree append:** each active commitment is appended via `appendFrontier` into the evolving
 frontier/count; updates gated by `commitmentActive`.
- After the loop, `requestIndex == NRequests` **MUST** hold — every request fully consumed.

**5. Final state binding** (`assertFinalState`): compute the new root from the evolving
frontier (or `fullTreeRoot`, the final carry from `appendFrontier`, when the tree filled exactly),
assert `RootNew` equals it and `CountNew` equals the evolving count.

What the circuit deliberately does **not** prove: that `NoteKnownRoots` matches the
contract's root history (the contract checks this), uniqueness/dedup of commitments across batches,
and any "who may deposit" policy. It only binds the witness to the public request ids and the tree
transition.

## Step 2 — `submitDepositEpoch` (on-chain verification & state transition)

Signature:

```text
function submitDepositEpoch(
 EpochTreeState calldata treeState,
 uint32 nTotalCommitments,
 Output[] calldata outputs, // length == maxSlots; only.commitment is consumed
 DepositEntry[] calldata deposits, // length == nRequests; only { depositRequestId }
 uint256[8] calldata proof
) external nonReentrant onlyRelay
```

Access: `onlyRelay` → `allowedRelays[msg.sender]` must be true, else `NotAllowedRelay`. `DepositEntry` on-chain is **just** `{ uint256
depositRequestId }`; the contract reads
`totalAmount`, `commitmentCount`, and `commitmentsHash` from stored `pendingDeposits`, so the relay
cannot lie about them. The `Output` calldata struct
carries `commitment` plus the transfer-style ciphertext fields (`receiverWrapKey, ct0..ct3`), but
`submitDepositEpoch` reads **only `.commitment`**; the
witness builder leaves the ciphertext fields zero.

Verification, in order:

| Step | Check | Revert |
|------|-------|--------|
| 1 | `maxSlots = outputs.length` in `[1, maxBatchSize]` | `InvalidEpochConfig` |
| 2 | `nRequests = deposits.length` in `[1, maxSlots]` | `InvalidEpochConfig` |
| 3 | `nTotalCommitments` in `[1, maxSlots]` | `InvalidEpochConfig` |
| 4 | `treeState.activeTreeNumber == currentTreeNumber` | `InvalidEpochState` |
| 5 | `treeState.countOld == treeCount[activeTreeNumber]` | `InvalidEpochState` |
| 6 | sparse `usedRoots` (`allowDuplicateTreeNumbers=false`): non-empty & `<= 16`, unique tree numbers, all known, includes active; returns `activeRoot` | `InvalidBatchConfig` / `DuplicateTreeNumber` / `RootNotKnown` / `InvalidEpochState` (`_validateKnownRoots`) |
| 7 | `activeRoot == treeRoot[activeTreeNumber]` (epochs require the *exact* current root) | `InvalidEpochState` |
| 8 | `_validateTreeCapacity`: rollover ⇒ `countOld == 2^merkleDepth`; non-rollover ⇒ `countOld < 2^merkleDepth`; `countNew == (rollover ? totalOutputs: countOld+totalOutputs)` and `<= 2^merkleDepth` | `InvalidEpochState` |
| 9 | per request `r`: `pd.depositor != 0`; `!processedDeposits[reqId]`; then set `processedDeposits[reqId]=true` | `InvalidDeposit` / `DepositAlreadyProcessed` |
| 10 | gather `outputs[cursor..cursor+pd.commitmentCount]` into `commitmentsOut`, recompute sequential hash; `endCursor > nTotalCommitments` rejected | `InvalidArrayLengths` |
| 11 | recomputed hash `== pd.commitmentsHash` | `InvalidDeposit` |
| 12 | after all requests, `cursor == nTotalCommitments` | `InvalidArrayLengths` |
| 13 | build public inputs and `depositVerifier.verifyDeposit(maxSlots, proof, publicInputs)` | verifier revert |
| 14 | `_updateTreeState(...)`; emit `DepositEpochSubmitted` | — |

The contract pulls `totalAmounts[r] = pd.totalAmount` and `commitmentCounts[r] = pd.commitmentCount`
from storage and reconstructs the same `commitmentsOut`/`commitmentsHash` the user
committed to in Step 1 — so the public inputs fed to the verifier are bound to escrowed state, not
relay-supplied claims. `depositRequestIds` (from storage-validated entries) is bound into the proof,
which in turn binds each request's `(depositor, tokenId, totalAmount, nonce, commitmentsHash)` via
the in-circuit request-id digest.

**State transition** (`_updateTreeState`):
- **Non-rollover:** `treeRoot[activeTreeNumber] = rootNew`; `treeCount[activeTreeNumber] =
 countNew`; push root into history ring (`_pushTreeRoot`).
- **Rollover:** `newTreeNumber = currentTreeNumber + 1` (require `<= MAX_NOTE_TREE_NUMBER`, else
 `InvalidEpochState`); set `treeRoot/treeCount[newTreeNumber]`, advance `currentTreeNumber`, push
 root, emit `TreeAdvanced(activeTreeNumber, newTreeNumber)`.

`DepositEpochSubmitted(currentTreeNumber, rootNew, rollover ? 0: countOld, countNew)` is emitted.

## Normative invariants (deposit subsystem)

- A deposit's escrowed tokens **MUST** be conserved: `sum(per-output values) == totalAmount`,
 enforced in-circuit per request against the
 on-chain-stored `pd.totalAmount` placed in the public inputs.
- Each output commitment **MUST** equal `Poseidon2T4(DOMAIN_NOTE, NPK, tokenId, value)`; the
 contract additionally rejects out-of-field/zero commitments at request time
 and the circuit rejects zero-value active commitments.
- The relay **MUST NOT** alter a request's amount, token, count, or commitment set: the contract
 reconstructs `commitmentsHash` from supplied `outputs` and checks it against stored
 `pd.commitmentsHash`, and only `{depositRequestId}` is
 relay-supplied.
- A deposit **MUST NOT** be processed twice and **MUST NOT** be processed after cancel:
 `processedDeposits` is set inside the epoch and checked in both epoch and cancel; a non-existent/cancelled `pendingDeposits` entry (`depositor == 0`) reverts the epoch.
- An epoch **MUST** match the exact current tree number, count, and root, and **MUST** present a
 non-duplicate sparse root set that includes the active tree (`_validateKnownRoots`).
- `submitDepositEpoch` and `submitEpoch` **MUST** be relay-gated (`onlyRelay`);
 `requestDeposit`/`cancelDeposit` are permissionless and depositor-scoped respectively.
- Only `cancelDeposit` may return escrowed funds; it **MUST** wait `cancelDelay` blocks past
 `requestBlock` and is callable only by the original depositor.

## End-to-end sequence

| # | Actor | Action | On-chain effect |
|---|-------|--------|-----------------|
| 1 | Depositor/SDK | Compute K output commitments `Poseidon2T4(DOMAIN_NOTE, NPK_j, tokenId, value_j)`; encrypt per-output metadata (three ECDH wrap keys, AES-256-GCM) | none (off-chain) |
| 2 | Depositor | `requestDeposit(tokenId, totalAmount, commitments, ciphertexts)` | tokens pulled (fee-on-transfer rejected); `nonce++`; compute `depositRequestId`; store `PendingDeposit`; emit `DepositRequested` |
| 3 | TEE/relay | Detect pending deposits via `DepositRequested` events / indexer | none |
| 4 | TEE/relay | Decrypt ciphertexts, build witness (`DepositWitnessBuilder`), generate Groth16 proof of `DepositEpochCircuit` over the batch; append commitments to the active tree to derive `RootNew/CountNew` | none |
| 5 | Relay | `submitDepositEpoch(treeState, nTotalCommitments, outputs, deposits, proof)` | per-request `processedDeposits[id]=true`; recompute & match `commitmentsHash`; verify proof; `_updateTreeState` (append or rollover); emit `DepositEpochSubmitted` (and `TreeAdvanced` on rollover) |
| 6a | — (success) | commitments are now spendable shielded notes | tree root/count advanced; `pendingDeposits` retained for observability |
| 6b | Depositor (if never processed) | After `cancelDelay`: `cancelDeposit(depositRequestId)` | refund `totalAmount`; `delete pendingDeposits[id]`; emit `DepositCancelled` |

---
