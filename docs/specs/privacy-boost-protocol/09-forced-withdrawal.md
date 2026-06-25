# 9. Forced Withdrawal (Escape Hatch) & ForcedWithdrawCircuit

## Purpose and Trust Model

Forced withdrawal is the protocol's emergency exit. It lets a note owner spend up to
`maxForcedInputs` of their own input notes and withdraw the underlying ERC-20 tokens to a public
address with **no TEE proving and no epoch-sequencing dependence** — the proof is generated
client-side and the entrypoints are permissionless. The user needs (a) their own secret key
material, (b) on-chain event data (to reconstruct their UTXO set), (c) the public on-chain note-root
histories, and (d) an **existing auth snapshot** (`authSnapshots`) covering their auth key. Auth
snapshots are created only by an allowed relay via `snapshotAuthTrees` (`onlyRelay`); the
permissionless caller **cannot** create one
(`requestForcedWithdrawal` passes `allowLazySnapshot=false`). The contract entrypoints
themselves are permissionless: `requestForcedWithdrawal`, `executeForcedWithdrawal`, and
`cancelForcedWithdrawal` carry no `onlyOwner`/operator modifier — anyone holding a valid proof may
call them (`cancelForcedWithdrawal` additionally checks requester/owner identity, see below). Given
a snapshot that already covers the user's key, this preserves self-custody even if all off-chain
infrastructure later goes permanently offline — snapshot entries are never deleted and the last good
snapshot stays referenceable via `latestSnapshotRound`. A key registered *after* the final snapshot
cannot be force-exited until a relay snapshots again.

The exit differs from a normal epoch withdrawal in two ways: it produces **no shielded outputs** (it
can only pay out to a public address), and it is verified by a dedicated circuit
(`ForcedWithdrawCircuit`) and verifier. All active inputs MUST share one token id, enforced in-circuit by
`AssertEqualIf(active, InputTokenID[i], TransferTokenID)`.

## Why Two Steps (Request → Delay → Execute/Cancel)

The flow is split into request and execute with a mandatory timelock of `forcedWithdrawalDelay`
blocks. The two-step design exists to interleave forced exits with normal epoch processing, keep
nullifier accounting single-spend, and allow either execution or cancellation once the request
matures:

- **Nullifier-set arbitration vs. epochs.** A note must never be spendable both via forced exit and
 via a normal epoch. The proof is verified at request time, but nullifiers are NOT marked spent
 until execution. During the delay window, if the operator processes those same notes in a normal
 epoch, `_spendNullifiers` sets `nullifierSpent`. At
 execution, `executeForcedWithdrawal` re-checks every nullifier and reverts with
 `InvalidNullifierSet` if any was already spent. Conversely, if the forced exit executes
 first it spends the nullifiers, and a later epoch attempting the same note reverts in
 `_spendNullifiers`. Either ordering yields a single spend; the delay makes the competing paths
 explicit and resolved by the first valid spend after maturation.
- **Post-delay owner cancellation.** `spenderAccountId` is a public input. After the same delay
 that gates execution, the account owner (resolved via `authRegistry.ownerOf(spenderAccountId)`)
 may cancel a request even if they were not the requester. Cancellation is not a pre-maturity
 veto; once the delay has elapsed, execution and cancellation are both available and transaction
 ordering determines which one lands first.
- **Anti-griefing on roots.** Forced withdrawal is permissionless, so it MUST NOT be able to lazily
 create new auth snapshots (which would let an attacker spam snapshot state).
 `requestForcedWithdrawal` passes `allowLazySnapshot=false` to `_validateAuthKnownRootsSparse`, forcing the caller to reference an already-snapshotted
 round; the round-window check accepts the current round (must already be snapshotted), the
 previous round, `latestSnapshotRound`, or `latestSnapshotRound - 1`. Callers should prefer
 `latestSnapshotRound` to avoid round-boundary races.

## Forced-Withdrawal Parameters

| Parameter | Meaning | Requirement | Notes |
|---|---|---|---|
| `forcedWithdrawalDelay` | Timelock in **blocks** between request and execute/cancel | Constructor immutable; deployment-profile value | block-number based |
| `maxForcedInputs` | Max input notes per forced withdrawal (also circuit `MaxInputs`) | Constructor immutable; must match the registered forced-withdraw verifier profile | constructor reverts `MaxForcedInputsCannotBeZero` if 0 |
| `withdrawFeeBps` | Fee captured at request time, applied at execution | ≤ `MAX_FEE_BPS` (`1_000` = 10%) | set through fee policy |

The circuit `MaxInputs` used to generate the proof must match the on-chain verifier VK registered
for that input count and the deployment's `maxForcedInputs` value.

The delay is measured against `block.number`: execution and cancellation both revert with
`ForcedWithdrawalTooEarly` while `block.number < request.requestBlock + forcedWithdrawalDelay`.

## ForcedWithdrawCircuit — What the User Proves Client-Side

The circuit proves, entirely client-side, that the prover
owns the input notes and that the withdrawal is correctly bound. Its `Define` does four things:
`validateInputs`, `verifyAuth`, `processInputs`, `assertFinalState`.

**Circuit shape** (`ForcedWithdrawShape`): `MaxInputs`, `MerkleDepth` (note tree depth),
`AuthDepth` (auth tree depth), `MaxNoteRootsPerProof`, `MaxAuthRootsPerProof`.

**Public inputs** (`ForcedWithdrawPublicInputs`). The on-chain flattened ordering is built by
`LibPublicInputs.buildForcedWithdrawalInputs`;
array length is `MAX_NOTE_ROOTS_PER_PROOF + 1 + MAX_AUTH_ROOTS_PER_PROOF + 1 + 7 + (maxInputs*2)`:

| Order | Public input | Count | Meaning |
|---|---|---|---|
| 1 | `NoteKnownRoots[i]` | `MAX_NOTE_ROOTS_PER_PROOF` = 16 | packed historical note-tree roots |
| 2 | `NoteKnownTreeNumbersPacked` | 1 | 15-bit tree numbers packed |
| 3 | `AuthKnownRoots[i]` | `MAX_AUTH_ROOTS_PER_PROOF` = 16 | packed auth registry roots |
| 4 | `AuthKnownTreeNumbersPacked` | 1 | 15-bit auth tree numbers packed |
| 5 | `NIn` (= `inputCount`) | 1 | number of active inputs (1..MaxInputs) |
| 6 | `SpenderAccountId` | 1 | account id for owner lookup / cancel |
| 7 | `Nullifiers[i]` | `maxInputs` | active nullifiers, zero-padded |
| 8 | `InputCommitments[i]` | `maxInputs` | active input commitments, zero-padded |
| 9 | `ApproveDigestHi` | 1 | high 128 bits of digest |
| 10 | `ApproveDigestLo` | 1 | low 128 bits of digest |
| 11 | `WithdrawalTo` | 1 | recipient as `uint160(address)` |
| 12 | `WithdrawalTokenID` | 1 | token id |
| 13 | `WithdrawalAmount` | 1 | gross amount (= sum of input values) |

The "7" scalar tail in the length formula corresponds to the seven non-array scalars:
`NIn`/`inputCount` and `SpenderAccountId` (written *before* the arrays), plus
`ApproveDigestHi`, `ApproveDigestLo`, `WithdrawalTo`, `WithdrawalTokenID`, `WithdrawalAmount`
(written *after* the arrays). They are not contiguous in the flattened vector.

**Range / structural constraints** (`validateInputs`): `NIn` is `CountBits`=32-bit,
`WithdrawalAmount` is `AmountBits`=96-bit, `WithdrawalTokenID` is `TokenIDBits`=16-bit; `1 <= NIn <=
MaxInputs` (zero inputs is invalid); `AuthTreeNumber <= MaxAuthTreeNumber` (32767).
Each active input also range-checks `InputValue` to `AmountBits` and `InputTokenID` to
`TokenIDBits`, and bounds-checks `InputNoteTreeNumber <= MaxNoteTreeNumber`. Inactive
input slots (`i >= NIn`) MUST be zero-padded across every per-input private and public field
(`processInputs`).

### Auth: single EdDSA signature + registry membership

The circuit verifies **one** EdDSA signature over an approval message and proves the signer is
registered (`verifyAuth`):

```text
approveMsg = Poseidon2T4(domainApprove, ApproveDigestHi, ApproveDigestLo)
VerifyEdDSA(pk={AuthPkX,AuthPkY}, sig={R8x,R8y,S}, approveMsg)

authLeaf = Poseidon2T4(domainRegLeaf, SpenderAccountId, AuthPkX, AuthPkY, AuthExpiry)
authRoot = computeDomainRoot(authLeaf, AuthLeafIndex, AuthPathElements, AuthDepth, domainRegNode)
assert authRoot ∈ AuthKnownRoots AND AuthTreeNumber matches the packed tree number
```

The circuit hashes `AuthExpiry` into the leaf but does NOT enforce expiry/flags semantics at spend
time. `PrivacyBoost` likewise does not enforce auth-key
expiry at forced-withdraw time.

### Spend: per-input commitment, membership, nullifier

The master key is derived once (`processInputs`), then for each active input the commitment,
membership and nullifier are bound:

```text
MPK = Poseidon2T4(domainMPK, SpenderAccountId, NullifyingKey)
NPK = Poseidon2T4(domainNote, MPK, InputNoteRnd[i])
commitment = Poseidon2T4(domainNote, NPK, InputTokenID[i], InputValue[i])
assert commitment == InputCommitments[i] (and commitment != 0 for active)

rootComputed = computeRoot(commitment, InputNoteLeafIndex[i], InputNotePath[i], MerkleDepth)
assert rootComputed ∈ NoteKnownRoots AND InputNoteTreeNumber[i] matches packed tree number

combinedDomain = domainNullifier + InputNoteTreeNumber[i] * NullifierTreeNumberMultiplier
nullifier = Poseidon2T4(combinedDomain, NullifyingKey, InputNoteLeafIndex[i])
assert nullifier == Nullifiers[i]
```

The domain tags and tree-number packing constants used above are defined in
[Appendix B](13-parameters-constants.md). Binding `InputNoteTreeNumber` into both the membership
check and the nullifier domain is what prevents cross-tree double-spend.

### Final binding

```text
assert TransferTokenID == WithdrawalTokenID
assert WithdrawalAmount == sum(active InputValue[i])
```

The circuit explicitly does NOT prove nullifier uniqueness or that the supplied roots correspond to
real contract histories — both are the contract's responsibility.

## On-Chain Entrypoints and Enforced Invariants

### `requestForcedWithdrawal`

Arguments: `(TreeRootPair[] knownRoots, AuthSnapshotState authState, uint256 spenderAccountId,
uint256[] nullifiers, uint256[] inputCommitments, Withdrawal withdrawal, uint256[8] proof)`. `Withdrawal = {address to; uint16 tokenId; uint96 amount}`.

Checks, in order:
- `nullifiers.length` MUST be non-zero and equal `inputCommitments.length`, MUST be `<=
maxForcedInputs`, and `<= uint8.max`; violations revert `InvalidArrayLengths` or
`InvalidEpochConfig`.
- `withdrawal.to != address(0)` else `InvalidWithdrawal`.
- Token validated at request time (so a request can't lock commitments for an unexecutable
 withdrawal): token must exist (`tokenAddress != address(0)`) and be `TOKEN_TYPE_ERC20`
 (else `InvalidWithdrawal` / `TokenNotSupported`).
- Note roots validated against the active tree via `_validateKnownRoots(knownRoots,
 currentTreeNumber, false)`; auth roots validated with `allowLazySnapshot=false`.
- Per input: nullifier MUST be non-zero, MUST NOT already be in `nullifierSpent`, and the commitment
 MUST NOT already map to an existing request via `commitmentToRequestKey` (reverts
`InvalidNullifierSet` / `ForcedWithdrawalAlreadyRequested`). Intra-batch duplicates of
 nullifiers or commitments revert `DuplicateNullifier` / `DuplicateInputCommitment`.
- Digest recomputed, nullifiers/commitments padded to `maxForcedInputs`, public inputs built, proof
 verified by `forcedVerifier.verifyForcedWithdraw(maxForcedInputs, proof, publicInputs)`
 (interface `IForcedWithdrawVerifier.verifyForcedWithdraw`). A failing proof reverts.
- Request stored under `requestKey = uint256(keccak256(abi.encodePacked(msg.sender,
 forcedCommitmentsHash)))`, where `forcedCommitmentsHash =
 keccak256(abi.encodePacked(inputCommitments))`;
 each commitment is indexed to that key in `commitmentToRequestKey`. `requestBlock`,
 `requester`, `withdrawalTo`, `tokenId`, `amount`, `withdrawFeeBps`, `inputCount`,
 `spenderAccountId`, and keccak hashes of nullifiers/commitments are persisted.

**Digest**:
```text
FORCED_WITHDRAW_DOMAIN = "PB:FORCED_WITHDRAW:v1"
digest = keccak256(abi.encode(FORCED_WITHDRAW_DOMAIN, chainId, pool, root, nullifiers, withdrawal))
ApproveDigestHi = uint256(digest) >> 128 // DIGEST_HALF_BITS = 128
ApproveDigestLo = uint256(digest) & ((1 << 128) - 1)
```
`root` is the active note tree root returned by `_validateKnownRoots`. Note `nullifiers` here is the *unpadded*
calldata array, while the proof's public-input `Nullifiers[]` are zero-padded to `maxForcedInputs`.
The digest binds the exit to chain id, pool address, the authorized note root, the exact (unpadded)
nullifier set, and the recipient/token/amount — so the EdDSA-signed approval cannot be replayed
across chains, pools, or altered recipients.

### `executeForcedWithdrawal(uint256[] nullifiers, uint256[] inputCommitments)` (`nonReentrant`, permissionless)

- `_validateForcedWithdrawalExecution`: resolves `requestKey` from
 `commitmentToRequestKey[inputCommitments[0]]` (reverts `ForcedWithdrawalNotRequested` if absent or
 `request.requestBlock == 0`), enforces the delay (`ForcedWithdrawalTooEarly`), and enforces that
 `inputCount`, `keccak256(abi.encodePacked(nullifiers))` and
 `keccak256(abi.encodePacked(inputCommitments))` exactly match the stored request
 (`ForcedWithdrawalMismatch`).
- Re-checks each nullifier against `nullifierSpent` and reverts `InvalidNullifierSet` if any was
 spent by an epoch during the delay. This is the load-bearing anti-double-spend
 invariant.
- Computes `feeAmount = grossAmount * requestFeeBps / BASIS_POINTS`, `netAmount = grossAmount -
 feeAmount` using the fee rate captured at request time (`request.withdrawFeeBps`) and
 `BASIS_POINTS = 10_000`.
- Marks all nullifiers spent, clears the request and commitment index with
 `_clearForcedWithdrawalRequest`, transfers `netAmount` to `withdrawalTo` and,
 only if `feeAmount > 0 && treasury != address(0)`, `feeAmount` to `treasury`.

### `cancelForcedWithdrawal(uint256[] nullifiers, uint256[] inputCommitments)` (`nonReentrant`)

- `_validateForcedWithdrawalCancellation`: caller may be the original `requester` (found
 via `requestKey = computeRequestKey(msg.sender, forcedCommitmentsHash)`), OR — if not — the account
 owner resolved via `authRegistry.ownerOf(request.spenderAccountId)` looked up through
 `commitmentToRequestKey[inputCommitments[0]]` (`ForcedWithdrawalNotRequested` if no such request,
 `NotRequesterOrOwner` if caller is neither).
 Same delay and hash-match invariants apply.
- Clears the request without spending nullifiers or moving funds; emits `ForcedWithdrawalCancelled`. The notes remain unspent and re-usable.

## End-to-End Sequence

1. **Reconstruct UTXOs** from on-chain events + viewing-key decryption; pick the note root and auth
 snapshot round (use `latestSnapshotRound` since lazy snapshotting is disallowed here).
2. **Generate proof locally** with `ForcedWithdrawCircuit`. No TEE involved.
3. **Call `requestForcedWithdrawal`** with proof, roots, nullifiers, commitments, withdrawal;
 contract verifies and stores the request, starting the `forcedWithdrawalDelay` block timer.
4. **Wait `forcedWithdrawalDelay` blocks.** During this window an epoch may legitimately spend the
 same notes (operator-driven) — whichever path spends first wins; the other reverts on
 `nullifierSpent`.
5. **Call `executeForcedWithdrawal`** to spend nullifiers and receive `netAmount`; OR the
 requester/owner **cancels**. Both require the delay to have elapsed.

## Self-Custody Scope

Because (a) the proof is generated entirely client-side from the user's own keys and public chain
data, (b) all three entrypoints are permissionless and contract-verified, and (c) nullifier
uniqueness is enforced by the on-chain registry, a user can exit with only their private
keys and chain data even if the TEE, indexer, and every relayer go permanently offline — **provided
their auth key was already captured in an on-chain auth snapshot before the relays stopped**. Auth
snapshots are relay-created (`snapshotAuthTrees`, `onlyRelay`); the permissionless path cannot
create one, so a key registered after the final snapshot cannot be force-exited until a relay
snapshots again. The residual dependencies are therefore: a pre-existing auth snapshot covering the
key, the note-opening and auth material required to build the proof, the ability to land
transactions on L2, and the `forcedWithdrawalDelay` maturation rule.

---
