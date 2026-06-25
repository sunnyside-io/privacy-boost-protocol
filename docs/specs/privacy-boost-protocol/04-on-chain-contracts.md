# 4. On-Chain Contracts: PrivacyBoost & TokenRegistry

## Overview

The core on-chain protocol components are:

- **`PrivacyBoost`** — the epoch-based private transfer pool.
 Holds all deposited ERC-20 funds, maintains the note Merkle tree state and root history, the
 nullifier registry, and the deposit / forced-withdrawal request lifecycles. Verifies Groth16
 proofs through three external verifier contracts.
- **`TokenRegistry`** — append-only `uint16` token-id ↔ address
 registry. The pool always references tokens by compact id, never by raw address.
- **`AuthRegistry`** — account/auth-key Merkle tree consumed by PrivacyBoost for spend authorization
snapshots. Covered in its own section; PrivacyBoost holds it as immutable `authRegistry` and reads
 `ownerOf`, `currentAuthTreeNumber`, and `authTreeRoot`.

These core contracts use the OpenZeppelin `Ownable2StepUpgradeable` pattern with
`_disableInitializers` in the constructor and a single `initialize(...)`. These contracts inherit the initializer/`__gap` upgrade
conventions but do **not** themselves declare `_authorizeUpgrade`/`UUPSUpgradeable` in these source
files — the proxy/upgrade mechanism is provided by the deployment layer, so "UUPS-style" should be
read as "OZ upgradeable-initializer pattern" here. PrivacyBoost additionally inherits
`ReentrancyGuardTransient`; every external state-changing entrypoint in
`submitEpoch`/`requestDeposit`/`cancelDeposit`/`submitDepositEpoch`/`requestForcedWithdrawal`/`executeForcedWithdrawal`/`cancelForcedWithdrawal`
is `nonReentrant`. Note: the
admin setters and `snapshotAuthTrees`/`syncAuthSnapshotInterval` are **not** marked `nonReentrant`.

PrivacyBoost has **no pause/emergency-stop switch.** The only "emergency" exit is the permissionless
2-step forced-withdrawal path (described below). Solidity `0.8.34`; the BN254 scalar field is the deposit-commitment validity
bound (`SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`).

## Roles and Access Control

| Role | Storage / source | Who sets it | Powers |
|------|------------------|-------------|--------|
| `owner` | `Ownable2StepUpgradeable` (2-step transfer) | self (transfer/accept) | `setOperator`, `setFees`, `setEpochVerifier`, `setDepositVerifier`, `setTreasury` |
| `operator` | `address public operator` | `owner` via `setOperator` | `setAllowedRelays`, `setAuthSnapshotInterval` |
| relay | `mapping allowedRelays` | `operator` via `setAllowedRelays` | `submitEpoch`, `submitDepositEpoch`, `snapshotAuthTrees` |
| anyone | — | — | `requestDeposit`, `cancelDeposit`, `requestForcedWithdrawal`, `executeForcedWithdrawal`, `cancelForcedWithdrawal`, `syncAuthSnapshotInterval` |

Modifiers: `onlyOwner` (OZ), `onlyOperator` reverts `NotOperator` if `msg.sender != operator`, and
`onlyRelay` calls `_checkRelay`, which reverts `NotAllowedRelay` if `!allowedRelays[msg.sender]`.
`setOperator` rejects the zero address
with `InvalidOperatorAddress`. Note: `setForcedVerifier` does **not** exist — only the
epoch and deposit verifiers are owner-replaceable; `forcedVerifier` is set once at
`initialize` and has no setter, so it is immutable in practice.

## Governance and Mutability Boundary

Governance/admin control is part of the fund-safety trust boundary. The contracts and deployment
scripts expose mutable roles that can change verification, relay admission, fees, treasury routing,
and proxy implementations:

| Component | Mutable authority | Security consequence |
|-----------|-------------------|----------------------|
| `PrivacyBoost.owner` | `setEpochVerifier`, `setDepositVerifier`, `setOperator`, `setFees`, `setTreasury` | Compromise can replace epoch/deposit verifiers, route relay/operator policy, or change economic parameters |
| `PrivacyBoost.operator` | `setAllowedRelays`, `setAuthSnapshotInterval` | Compromise can admit or remove relay submitters and affect auth snapshot cadence |
| verifier owner | `registerVK` / `registerEpochVK` | Compromise can register or replace verifying-key pointers for supported circuit shapes |
| proxy admin | `TransparentUpgradeableProxy` / `ProxyAdmin` deployment and upgrade scripts | Compromise can upgrade implementation code or proxy state where the deployed instance remains upgradeable |
| forced verifier | Set once during `PrivacyBoost.initialize`; no `setForcedVerifier` exists | No setter exists in the current implementation; a proxy upgrade can still change forced-withdraw behavior if the deployed proxy remains upgradeable |

Therefore, statements about fund safety in this spec assume not only cryptographic soundness and
contract correctness, but also verifier-key integrity and uncompromised governance/proxy
administration. Production readiness requires documenting whether these roles are
multisig-controlled, timelocked, monitored, renounced, or otherwise constrained.

## Entrypoint Table (PrivacyBoost)

| Function | Caller | Verifier invoked | Core state transitions | Key reverts |
|----------|--------|------------------|------------------------|-------------|
| `submitEpoch` | relay | `epochVerifier.verifyEpoch` | spend nullifiers, process withdrawals (token out), append outputs → tree root push / rollover | `InvalidEpochConfig`, `InvalidEpochState`, `InvalidArrayLengths`, `NonCanonicalEncoding`, `InvalidBatchConfig`, `RootNotKnown`, `DuplicateTreeRootPair`, `InvalidNullifierSet`, `InvalidWithdrawal`, `InvalidSlotPadding`, `WithdrawalSlotsNotStrictAscending`, `InvalidAuthSnapshotRound`/`AuthTreeNotSnapshotted`/`DuplicateTreeNumber` |
| `requestDeposit` | anyone | none | pull ERC-20 in, store `PendingDeposit`, bump `depositNonces` | `InvalidDeposit`, `InvalidArrayLengths`, `TokenNotSupported`, `FeeOnTransferNotSupported`, `DepositAlreadyExists` |
| `cancelDeposit` | depositor | none | refund ERC-20, delete `PendingDeposit` | `NotDepositor`, `DepositAlreadyProcessed`, `CancelTooEarly` |
| `submitDepositEpoch` | relay | `depositVerifier.verifyDeposit` | mark `processedDeposits`, append commitments → tree root push / rollover (no token movement) | `InvalidEpochConfig`, `InvalidEpochState`, `InvalidDeposit`, `DepositAlreadyProcessed`, `InvalidArrayLengths`, `InvalidBatchConfig`, `RootNotKnown`, `DuplicateTreeNumber` |
| `requestForcedWithdrawal` | anyone | `forcedVerifier.verifyForcedWithdraw` | store `ForcedWithdrawalRequest`, bind commitments → request key (no spend yet) | `InvalidArrayLengths`, `InvalidEpochConfig`, `InvalidWithdrawal`, `TokenNotSupported`, `InvalidNullifierSet`, `ForcedWithdrawalAlreadyRequested`, `DuplicateNullifier`, `DuplicateInputCommitment`, `RootNotKnown`, `InvalidBatchConfig`, `InvalidAuthSnapshotRound`/`AuthTreeNotSnapshotted` |
| `executeForcedWithdrawal` | anyone | none (proof already done at request) | mark nullifiers spent, token out (net), fee → treasury, clear request | `ForcedWithdrawalNotRequested`, `ForcedWithdrawalTooEarly`, `ForcedWithdrawalMismatch`, `InvalidNullifierSet`, `InvalidArrayLengths`, `InvalidEpochConfig` |
| `cancelForcedWithdrawal` | requester or account owner | none | clear request, unbind commitments | `NotRequesterOrOwner`, `ForcedWithdrawalNotRequested`, `ForcedWithdrawalTooEarly`, `ForcedWithdrawalMismatch`, `InvalidArrayLengths` |
| `snapshotAuthTrees` | relay | none | write `authSnapshots[round][tree]` from AuthRegistry | `InvalidBatchConfig`, `InvalidAuthSnapshotRound`, `InvalidAuthTreeNumber` |
| `syncAuthSnapshotInterval` | anyone | none | apply pending interval if due | — |
| admin setters  | owner/operator | none | config writes | role + validation reverts |

## Token in/out semantics

- The pool is the sole custodian. Tokens enter **only** through `requestDeposit` via
 `safeTransferFrom` and leave **only** through `_transferToken`/`safeTransfer` driven by
 `submitEpoch` withdrawals (`_processWithdrawals`, which calls `_transferToken`),
 `executeForcedWithdrawal`, and `cancelDeposit` refunds.
- `submitDepositEpoch` moves **no tokens**; funds were already escrowed at `requestDeposit`. It only
 converts escrowed deposits into tree leaves.
- Only `TOKEN_TYPE_ERC20` is accepted
 everywhere a token is resolved; any other `tokenType` reverts
 `TokenNotSupported(tokenType)`.

## Deposit lifecycle (2-step)

**Step 1 — `requestDeposit(_tokenId, _totalAmount, _commitments[], _ciphertexts[])`**,
where `_totalAmount` is `uint96` and `_tokenId` is `uint16`.

1. `1 ≤ _commitments.length ≤ maxBatchSize`, `_totalAmount != 0`, `_commitments.length ==
 _ciphertexts.length` (the first two revert `InvalidDeposit`, the third `InvalidArrayLengths`).
2. Each commitment MUST satisfy `0 < c < SNARK_SCALAR_FIELD` (strict field element, prevents
 calldata aliasing where `x` and `x+q` Poseidon-hash identically) — else `InvalidDeposit`.
3. Sequential commitment hash binds order (see pseudocode below).
4. Token resolved; non-ERC20 reverts `TokenNotSupported`, unknown id reverts `InvalidDeposit`.
5. **Fee-on-transfer guard**: measured balance delta MUST equal `_totalAmount`, else
 `FeeOnTransferNotSupported(requested, received)`. Rebasing tokens are explicitly
 unsupported.
6. `nonce = depositNonces[msg.sender]++`; `depositRequestId` derived deterministically (pseudocode below).
7. MUST NOT collide with an existing pending deposit — `DepositAlreadyExists`.
8. Store `PendingDeposit`, emit `DepositRequested` (which carries the full `_commitments` and
 `_ciphertexts` for the indexer/TEE).

```text
commitmentsHash = 0
for c in commitments: // order-binding
 commitmentsHash = Poseidon2T4.hash2(commitmentsHash, c) // LibDigest.computeCommitmentsHashStep

depositRequestId = Poseidon2T4.hash8(
 DOMAIN_DEPOSIT_REQUEST,
 chainId,
 uint256(uint160(poolAddress)),
 uint256(uint160(depositor)),
 uint256(tokenId),
 uint256(totalAmount),
 uint256(nonce),
 commitmentsHash
) // LibDigest.computeDepositRequestId
```

**`cancelDeposit(_depositRequestId)`**: only the depositor (`NotDepositor`), only if not
yet processed (`DepositAlreadyProcessed`), only after `block.number ≥ pd.requestBlock + cancelDelay`
(`CancelTooEarly`). Refunds `pd.totalAmount`, deletes the record, emits
`DepositCancelled`.

**Step 2 — `submitDepositEpoch(treeState, nTotalCommitments, outputs[], deposits[], proof)`** (relay-only)

- Bounds: `1 ≤ outputs.length ≤ maxBatchSize`; `1 ≤ deposits.length ≤ outputs.length`; `1 ≤
 nTotalCommitments ≤ outputs.length` — all revert `InvalidEpochConfig`.
- Tree-state binding: `treeState.activeTreeNumber == currentTreeNumber` and `treeState.countOld ==
 treeCount[active]`, else `InvalidEpochState`.
- Sparse roots validated **with unique tree numbers** (`allowDuplicateTreeNumbers=false`);
 the active-tree root returned MUST equal the exact current `treeRoot[active]` else
 `InvalidEpochState` — deposit epochs require append-only freshness, no stale-root
 spending.
- For each deposit: record MUST exist (`InvalidDeposit`) and be unprocessed
 (`DepositAlreadyProcessed`); mark `processedDeposits[reqId]=true`; walk `outputs` and recompute
 the sequential commitment hash; it MUST equal the stored `pd.commitmentsHash`, else
 `InvalidDeposit`. The cursor MUST consume exactly `nTotalCommitments`, else
 `InvalidArrayLengths`.
- Verify proof, then `_updateTreeState` (append/rollover), emit `DepositEpochSubmitted`.

## Transfer / Withdraw epoch — `submitEpoch(...)` (relay-only)

This single entrypoint processes a batch of up to `maxBatchSize` "transfers", each of which is
either a private→private transfer or a private→public withdrawal (selected per-slot by membership in
`withdrawalSlots`), plus one shared fee transfer (`feeTransfer`).

Circuit-dimension binding (all derived from calldata array shapes and bounded by immutables):

| Quantity | Notes | Bound |
|----------|--------|-------|
| `circuitMaxTransfers` | `nullifiers.length` | `1..maxBatchSize`  |
| `nTransfers` (active) | param | `1..circuitMaxTransfers` |
| `circuitMaxInputs` | `nullifiers[0].length` | `1..maxInputsPerTransfer`  |
| `circuitMaxOutputs` | `transfers[0].outputs.length` | `1..maxOutputsPerTransfer`  |
| `feeTokenCount` | param | `1..maxFeeTokens` |
| `feeTransfer.outputs.length` | calldata | `== maxFeeTokens` |

Validation pipeline (in order):

1. **Array-shape consistency** across all top-level and inner arrays (`InvalidArrayLengths`);
 inactive transfer slots (`t ≥ nTransfers`) MUST have `inputsPerTransfer[t]==0 &&
 outputsPerTransfer[t]==0`, active slots MUST be in-range (`InvalidEpochConfig`).
2. **Tree binding** identical to deposit epoch. Note roots validated with
 `allowDuplicateTreeNumbers=true`: epoch permits the same tree number with different
 roots because each transfer selects its own digest root via `digestRootIndices` and the circuit
 uses OR-based `findPairMatch`; exact duplicate `(tree,root)` pairs are still rejected
 (`DuplicateTreeRootPair`). The active root for frontier binding comes directly from
 on-chain state (`activeRoot = treeRoot[active]`), so `usedRoots` may carry past roots for
 input spending.
3. **Auth-snapshot roots** validated/lazily snapshotted (`allowLazySnapshot=true`; see Auth Snapshots).
4. **`feeTokenCount`** bounds checked (`1..maxFeeTokens`, `InvalidEpochConfig`).
5. **`digestRootIndices` canonical encoding**: exactly `ceil(nTransfers/64)` words of packed 4-bit
 indices (`InvalidArrayLengths` if length wrong); padding bits in the final word MUST be zero else
 `NonCanonicalEncoding`.
6. **Tree capacity** for `totalOutputs + feeTokenCount` (`_validateTreeCapacity`).
7. **Withdrawal slots** MUST be strictly ascending, unique, and `< nTransfers`
 (`_validateWithdrawalSlots`; reverts `InvalidArrayLengths`, `InvalidWithdrawal`,
 `WithdrawalSlotsNotStrictAscending`).
8. **Per-transfer digests** computed (`_computeTransferDigests`): per slot, resolve
 `digestRoot` from the packed index into `usedRoots` (`InvalidBatchConfig` if index out of range);
 for a withdrawal slot, `amount != 0` and the slot's `outputs[0].commitment`
 MUST equal `computeWithdrawalCommitment(to,tokenId,amount)`, and a
 withdraw-domain digest is produced; otherwise a transfer-domain digest is produced.
9. **Slot padding invariant** (`_validateSlotPadding`): for every slot,
 nullifier/commitment at index `i` is non-zero **iff** `i < perTransferCount`. This binds
 per-transfer counts between contract and circuit (`InvalidSlotPadding`).
10. Build fee commitments (`_buildFeeCommitments`), build public inputs
 (`LibPublicInputs.buildEpochInputs`) and `epochVerifier.verifyEpoch(circuitMaxTransfers,
 circuitMaxInputs, circuitMaxOutputs, proof, publicInputs)`. Selecting the verifier by
 dimension triples means each circuit shape has its own verifying key.

State mutations after a valid proof:

- `_spendNullifiers` — for every active input, nullifier MUST be non-zero and unspent
 (`InvalidNullifierSet`), then mark spent.
- `_processWithdrawals` — `safeTransfer` each withdrawal's gross `amount` to `to`.
 **Withdrawals in `submitEpoch` are paid gross; no fee is taken here.** The withdraw fee applies
 only to the forced-withdrawal path (see Fees).
- `_updateTreeState` — append outputs by writing the new root/count and pushing into history, or
 rollover to a new tree.
- Emit `EpochSubmitted(currentTreeNumber, rootNew, rollover?0:countOld, countNew)`.

Approval digests (the message the spend-authorization signature in the circuit commits to). All
digests use `abi.encode` (not packed) of the `string` domain tag followed by the listed fields:

```text
// Transfer slot — LibDigest.computeTransferDigest
d = keccak256(abi.encode(
 "PB:TRANSFER:v1", chainId, pool, root,
 nullifiers[], outputs[], viewingKey, teeWrapKey))
hi = d >> 128; lo = d & (2^128 - 1) // DIGEST_HALF_BITS = 128

// Withdrawal slot — LibDigest.computeWithdrawalDigest
d = keccak256(abi.encode(
 "PB:WITHDRAW:v1", chainId, pool, root,
 nullifiers[], outputs[], withdrawal, viewingKey, teeWrapKey))
hi = d >> 128; lo = d & (2^128 - 1)

// Withdrawal output[0] commitment — LibDigest.computeWithdrawalCommitment
commitment = Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(to)), uint256(tokenId), uint256(amount))
```

Here the digest `nullifiers[]`/`outputs[]` are the **trimmed** per-slot arrays (length = actual
`inputsPerTransfer[t]`/`outputsPerTransfer[t]`, not circuit-padded). `outputs[]`
element is the `Output` struct (commitment + 256-bit `receiverWrapKey` + 4 ciphertext words
`ct0..ct3` = 32+32+32+16 = 112 storage bytes carrying the 110-byte AES-256-GCM payload
`ciphertext(94B)||tag(16B)`; struct total 176B).
`root` is the slot's selected `digestRoot`, not necessarily the active root.

## Forced Withdrawal lifecycle (2-step, permissionless)

This is the censorship-resistance escape hatch for already-snapshotted auth keys: any holder of a
note whose auth key is covered by an existing on-chain auth snapshot can exit without TEE proving or
epoch sequencing. A relay is still required at least once to create the auth snapshot.

**Step 1 — `requestForcedWithdrawal(knownRoots, authState, spenderAccountId, nullifiers[],
inputCommitments[], withdrawal, proof)`**

- `1 ≤ inputLen ≤ maxForcedInputs` (`InvalidArrayLengths` if 0/mismatch, `InvalidEpochConfig` if `>
 maxForcedInputs`), `inputLen == inputCommitments.length`, `inputLen ≤ 255`
 (`InvalidArrayLengths`), `withdrawal.to != 0` (`InvalidWithdrawal`).
- Token validated at request time (so a request can't lock notes for an unexecutable token): unknown
 id → `InvalidWithdrawal`, non-ERC20 → `TokenNotSupported`.
- Active note root from `_validateKnownRoots(..., allowDuplicateTreeNumbers=false)`; auth
 roots validated with `allowLazySnapshot=false` — **permissionless callers MUST NOT create
 new auth snapshots** (anti-griefing); they reference an existing round such as
 `latestSnapshotRound`, else `AuthTreeNotSnapshotted`.
- Per input: nullifier non-zero and **unspent** (both `InvalidNullifierSet`),
 commitment not already bound (`ForcedWithdrawalAlreadyRequested`), and no in-batch
 duplicate nullifiers/commitments (`DuplicateNullifier`/`DuplicateInputCommitment`).
- Compute the forced-withdrawal digest (uses `activeRoot`), build public inputs, verify proof:

```text
// LibDigest.computeForcedWithdrawalDigest
digest = keccak256(abi.encode(
 "PB:FORCED_WITHDRAW:v1", chainId, pool, activeRoot, nullifiers[], withdrawal))
// Note: no viewingKey/teeWrapKey/outputs in this digest (returned as a single bytes32, not hi/lo split).
```

- Store the request under `requestKey = uint256(keccak256(abi.encodePacked(msg.sender,
 forcedCommitmentsHash)))`, where `forcedCommitmentsHash` denotes the forced-withdrawal
 `keccak256(abi.encodePacked(inputCommitments))` value, capturing
 `withdrawFeeBps` **at request time** so later fee changes can't alter a pending exit. Bind each commitment → requestKey. Emit
 `ForcedWithdrawalRequested`.

```text
nullifiersHash = keccak256(abi.encodePacked(nullifiers))
forcedCommitmentsHash = keccak256(abi.encodePacked(inputCommitments))
requestKey = uint256(keccak256(abi.encodePacked(requester, forcedCommitmentsHash)))
```

**Step 2 — `executeForcedWithdrawal(nullifiers[], inputCommitments[])`** (anyone)

- Resolve request by `commitmentToRequestKey[inputCommitments[0]]`
 (`_validateForcedWithdrawalExecution`); MUST exist (`ForcedWithdrawalNotRequested`), MUST
 be past `requestBlock + forcedWithdrawalDelay` (`ForcedWithdrawalTooEarly`), and
 `inputCount`/`nullifiersHash`/`commitmentsHash` (the stored forced-withdrawal commitments hash)
 MUST match the stored request
 (`ForcedWithdrawalMismatch`).
- Re-check each nullifier is still unspent (`InvalidNullifierSet`) — if a normal
 `submitEpoch` spent it first, the forced path correctly fails.
- Mark nullifiers spent, clear request + commitment bindings, pay net to `withdrawalTo`, fee to
 treasury.

```text
feeAmount = (grossAmount * request.withdrawFeeBps) / 10_000 // BASIS_POINTS
netAmount = grossAmount - feeAmount
_transferToken(tokenId, withdrawalTo, netAmount)
if feeAmount > 0 && treasury != 0: _transferToken(tokenId, treasury, feeAmount)
```

**`cancelForcedWithdrawal(nullifiers[], inputCommitments[])`**: callable after the same
delay by the **requester**, or by the **account owner** resolved via
`authRegistry.ownerOf(request.spenderAccountId)`. The requester path keys the request by
`keccak256(msg.sender, forcedCommitmentsHash)`; the
owner path resolves it via `commitmentToRequestKey[inputCommitments[0]]` then checks `msg.sender ==
accountOwner` (`NotRequesterOrOwner`). This lets a victim of a malicious request (e.g. a
leaked spend key) cancel before execution. Clears the request without spending nullifiers.

## Nullifier registry (double-spend prevention)

- Storage: `mapping(uint256 nullifier => bool spent) public nullifierSpent`.
- **Invariant**: a nullifier MUST be spendable at most once. Enforced at: `_spendNullifiers` for
 epoch spends, `executeForcedWithdrawal`, and the request-time non-spent check in
 `requestForcedWithdrawal`. Zero nullifiers are rejected.
- The forced path is request/execute-separated specifically so a nullifier spent by a normal epoch
 between request and execute makes forced-withdraw execution revert, preventing a second payout.

## Note Merkle tree, roots, and capacity

| Storage | Meaning |
|---------|---------|
| `currentTreeNumber` | active tree id (`uint256`) |
| `treeRoot[treeNum]` | current root per tree |
| `treeCount[treeNum]` | leaf count per tree (`uint32`) |
| `treeRootHistory[treeNum][ROOT_HISTORY_SIZE]` | ring buffer of recent roots |
| `treeRootHistoryCursor[treeNum]` | ring-buffer write cursor |

- `ROOT_HISTORY_SIZE = 64`; `merkleDepth` is
 immutable, `1..24` enforced (`MerkleDepthOutOfRange`), and MUST match the compiled note-tree
 depth used by the registered verifier profile. Max leaves per tree `= 1 << merkleDepth`.
- Empty-tree root is `LibZeroHashes.get[merkleDepth]`; for configured depth 24 this is `zeros[24] =
 6379059771196981783531842116523729103253487220527074934863013362203865842833`, **not** `MERKLE_ZERO_ROOT`
 (the depth-20 note-hash value).
- `isKnownTreeRoot`: root 0 is never known; the current root of any tree is O(1)-known;
 finalized trees (`treeNum < currentTreeNumber`) accept **only** their current/final root; the
 current tree additionally scans its 64-entry history backwards. This is what permits proofs
 against slightly stale roots.
- Capacity (`_validateTreeCapacity`): non-rollover requires `countOld < maxLeaves` and
 `countNew == countOld + totalOutputs`; rollover requires `countOld == maxLeaves` and `countNew ==
 totalOutputs` (`countNew > maxLeaves` always rejected); violations revert `InvalidEpochState`.
 `_updateTreeState` on rollover increments `currentTreeNumber` (bounded by `MAX_NOTE_TREE_NUMBER =
 32767`, reverts `InvalidEpochState` on overflow), seeds the new tree's root/count, and pushes history; emits `TreeAdvanced(oldTreeNumber,
 newTreeNumber)`.
- `MAX_NOTE_ROOTS_PER_PROOF = MAX_AUTH_ROOTS_PER_PROOF = 16` cap the sparse-root arrays
 (over-cap reverts
 `InvalidBatchConfig`).

## Auth snapshots (key-rotation protection)

PrivacyBoost freezes AuthRegistry roots into per-round snapshots so a spend proof is validated
against a stable auth state, preventing key-rotation races.

- `authSnapshots[round][treeNum]`; round numbering is a piecewise schedule: `round =
 startRound + (block - startBlock) / interval`.
- `authSnapshotInterval` bounded `10..100000` blocks. `setAuthSnapshotInterval` (operator) schedules a change at the next round
 boundary;
 `_applyPendingAuthSnapshotIntervalIfDue`/`syncAuthSnapshotInterval` activate it; only one pending
 update at a time (`AuthSnapshotIntervalUpdatePending`), and a no-op change reverts
 `AuthSnapshotIntervalNoChange`.
- `snapshotAuthTrees` (relay) eagerly snapshots the current round to avoid a first-caller
 race for permissionless forced withdrawals.
- Round-window validity (`_validateAuthKnownRootsSparse`): a referenced `authSnapshotRound`
 is accepted only if it is the current round, current−1, `latestSnapshotRound` (when `>0`), or
 `latestSnapshotRound−1`, else `InvalidAuthSnapshotRound`. Lazy snapshotting of
 the current round is allowed only when `allowLazySnapshot=true` (epoch path); forced withdrawals
 (`false`) require the snapshot to already exist (`AuthTreeNotSnapshotted`). Each provided
 root MUST be non-zero and equal the stored snapshot (`RootNotKnown`). Sparse
 auth tree numbers MUST be unique (`DuplicateTreeNumber`).

## Fees

| Fact | Value / source |
|------|----------------|
| `BASIS_POINTS` denominator | `10_000` |
| `MAX_FEE_BPS` cap | `1_000` (= 10%) |
| `withdrawFeeBps` storage | `uint16` |
| where applied | **forced withdrawal execution only**; regular `submitEpoch` withdrawals are gross |
| recipient | `treasury`; skipped if `feeAmount == 0` or `treasury == 0` |
| who configures | `owner` via `setFees` / `initialize`  |

`_setFees` reverts `FeeExceedsMaximum` if `> MAX_FEE_BPS`, and `TreasuryNotSet` if a
non-zero fee is set with no treasury. `setTreasury` symmetrically refuses to clear the treasury
while a fee is active. Forced-withdrawal fee is snapshotted at request time into
`ForcedWithdrawalRequest.withdrawFeeBps`, so config changes never retroactively alter a
pending exit. The enforced cap is 10%.

## TokenRegistry

Append-only `uint16` id assignment. Ids start at 1 (`tokenId = ++nextId`), so id `0` is the
sentinel for "not registered".

| Storage | Meaning |
|---------|---------|
| `tokenOf[uint16] → TokenInfo{tokenType,tokenAddress,tokenSubId}` | id → token |
| `idOf[bytes32 key] → uint16` | key → id (0 if none) |
| `nextId` | last assigned id (`uint16`) |

- `register(tokenType, tokenAddress, tokenSubId)` is **owner-only**. MUST be
 `TOKEN_TYPE_ERC20` (`TokenTypeNotSupported`), non-zero address (`ZeroAddress`), and
 a contract (`code.length != 0`, `NotAContract`). `key = keccak256(abi.encode(tokenType,
 tokenAddress, tokenSubId))`; duplicate keys revert `TokenAlreadyRegistered`;
 `nextId == type(uint16).max` reverts `TokenIdOverflow`. Emits `TokenRegistered(tokenId,
 tokenType, tokenAddress, tokenSubId)`.
- **Immutability invariant**: there is no update or delete function. Once `tokenOf[id]` is written
 it is never changed — ids are stable forever, which is what lets the pool and circuits treat
 `tokenId` as a permanent compact identifier.

## Storage-layout summary

PrivacyBoost slot order (after `Ownable2Step`/`ReentrancyGuardTransient` bases; immutables are not
in storage): scalars `epochVerifier`, `depositVerifier`, `forcedVerifier`,
`currentTreeNumber`, `treasury`, `operator`, `withdrawFeeBps`,
`authSnapshotInterval`; mappings
`treeRoot`/`treeCount`/`treeRootHistory`/`treeRootHistoryCursor`,
`nullifierSpent`, `allowedRelays`, `pendingDeposits`,
`processedDeposits`, `depositNonces`, `forcedWithdrawalRequests`,
`commitmentToRequestKey`, `authSnapshots`; auth-schedule scalars
`latestSnapshotRound` … `pendingAuthSnapshotStartRound`; reserved `uint256[44]
__gap`. TokenRegistry: `tokenOf`,`idOf`,`nextId`, `uint256[50]
__gap`. All immutable PrivacyBoost params (`tokenRegistry`, `authRegistry`,
`maxBatchSize`, `maxInputsPerTransfer`, `maxOutputsPerTransfer`, `maxFeeTokens`, `cancelDelay`,
`forcedWithdrawalDelay`, `maxForcedInputs`, `merkleDepth`) are set in the constructor and are
bytecode-embedded, not storage. Constructor validation rejects zero values for the address and
capacity parameters; delay parameters are configuration values.

## Important events (indexer-relevant)

`EpochSubmitted`, `DepositEpochSubmitted`, `TreeAdvanced`, `DepositRequested` (carries commitments +
ciphertexts), `DepositCancelled`, `ForcedWithdrawalRequested/Executed/Cancelled`,
`AuthTreeSnapshotted`, `FeesUpdated`, `RelayUpdated`, `OperatorUpdated`, `TreasuryUpdated`,
`EpochVerifierUpdated`, `DepositVerifierUpdated`, and the three auth-schedule events
`AuthSnapshotIntervalUpdated`/`AuthSnapshotIntervalUpdateScheduled`/`AuthSnapshotIntervalActivated`; `TokenRegistered`.

---
