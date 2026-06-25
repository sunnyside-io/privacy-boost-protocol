# 12. Security Model, Trust Assumptions & Invariants

## Overview

Privacy Boost is a TEE-coordinated, epoch-batched shielded transfer pool. Its security rests on a
strict separation of concerns:

- **Fund safety** depends on (a) sound cryptographic primitives, (b) correct circuits and on-chain
 contracts, (c) integrity of registered verifying keys, and (d) uncompromised governance/proxy
 administration. It does **not** depend on the TEE operator alone.
- **Privacy** depends additionally on TEE hardware isolation and on the user keeping their
 viewing/nullifying keys secret.
- **Liveness** of the convenient path depends on TEE availability, but every user retains a
 forced-withdrawal escape hatch that needs only their keys, a live chain, and an already-existing
 on-chain auth snapshot covering their key (snapshots are relay-created via `snapshotAuthTrees`,
 but remain usable indefinitely once taken).

This section consolidates the threat model, gives a per-actor trust table, maps the normative
protocol invariants to their enforcing mechanisms, and enumerates the privacy guarantees and known
leakage. The invariant mapping covers the three proof-bearing paths: the epoch circuit, the deposit
epoch circuit, and the forced-withdrawal circuit.

## Per-Actor Trust Table

The defining off-chain separation property: a compromise of the TEE operator or a relay alone cannot
move funds without valid user authorization and accepted proofs. Fund safety also assumes the
on-chain governance/proxy/verifier-key layer is not maliciously reconfigured.

| Actor | Trusted for | NOT trusted for | Protocol controls and residual exposure |
|-------|-------------|-----------------|----------------------------------------|
| **User (key holder)** | Keeping EOA key, auth (EdDSA) key, viewing key, nullifying key secret | — | AuthRegistry ownership and revocation limit account-key rotation flows, but user-key loss remains outside protocol recovery. Auth-key exposure can authorize spends; viewing-key exposure reveals metadata without spend authority; nullifying-key exposure reveals nullifiers without spend authority. |
| **TEE operator (Sunnyside Labs)** | Privacy (enclave isolation), liveness of the convenient path (batching, indexing, proving) | Fund safety; transaction forgery; censorship-resistance for already-snapshotted keys | The TEE does not hold the user's EdDSA auth signing secret, and all spends still require accepted ZK proofs. TEE exposure can reveal convenient-path plaintext for the exposed period; forced exits remain available for keys already covered by an on-chain auth snapshot. |
| **Relay (`allowedRelays`)** | Submitting epoch/deposit-epoch proofs and creating auth snapshots | Producing invalid proofs; stealing funds | Every relay submission is independently proof-verified on-chain. A rogue or unavailable relay can stall the convenient path, but cannot bypass verifier checks. |
| **Governance / ProxyAdmin / verifier owners** | Maintaining verifier addresses, VK registry pointers, proxy implementations, relay/operator policy, fees, treasury | Being untrusted for fund safety | These roles can affect verifier selection, implementation code, relay admission, and economic policy. Production role controls are deployment evidence, separate from this protocol specification. |
| **Smart contracts (PrivacyBoost, AuthRegistry, TokenRegistry, verifiers, libs)** | Enforcing all invariants below; value conservation; nullifier uniqueness; access control | — | Contract correctness is the core protocol review surface; these components enforce the invariant mapping below. |
| **Target chain / sequencer** | Consensus correctness, liveness, ordering | Extracting plaintext from proofs (ZK); reordering independent epochs | Chain reorgs can affect finalized state. MEV/front-running does not reveal private witness data and cannot bypass relay allowlists or proof checks. |
| **Ceremony participants (Groth16 trusted setup)** | At least one honest participant destroying toxic waste | — | The ceremony relies on 1-of-N honesty: if at least one participant destroys toxic waste, the setup remains sound under the standard Groth16 assumption. |

In one line: **fund safety ⇐ crypto primitives + circuit/contract correctness + verifier-key
integrity + governance/proxy integrity; privacy ⇐ TEE isolation + key secrecy; convenient-path
liveness ⇐ TEE availability; exit liveness for already-snapshotted keys ⇐ forced withdrawal + live
chain**.

## Threat Model (Consolidated)

| # | Threat | Protocol control | Residual exposure |
|---|--------|------------------|-------------------|
| T1 | TEE memory exposure | User spends still require an EdDSA auth signature and an accepted ZK proof; the TEE does not hold the auth signing secret | Convenient-path plaintext for the exposed period may be visible to the operator-side decryptor |
| T2 | TEE operator censorship | Forced withdrawal (`requestForcedWithdrawal`/`executeForcedWithdrawal`) bypasses TEE proving and epoch sequencing for keys already covered by an auth snapshot | The convenient path can be unavailable while the TEE/operator path is censored |
| T3 | TEE downtime | Deposit cancel after `cancelDelay`; forced exit; state reconstructable from chain | Transfers and deposit processing can stall until the convenient path recovers or an exit/cancel path is used |
| T4 | Front-running / MEV / sequencer | Relay allowlist on `submitEpoch`/`submitDepositEpoch`; forced-withdrawal delay; private mempools where available | Ordering can affect independent transactions, but cannot reveal private witness data or bypass proof checks |
| T5 | Malicious sender (bad recipient ciphertext) | The TEE validates the TEE-targeted ciphertext; funds remain governed by proofs and user authorization | Receiver-targeted ciphertext is not verified by the contract/circuit, so unaided recipient self-recovery for that note can fail if the TEE is permanently unavailable |
| T6 | Nullifier grinding / double-spend | On-chain `nullifierSpent` mapping + in-circuit nullifier binding (`INV-Z07` through `INV-Z09`, `INV-C18`) | None under the stated circuit/contract assumptions |
| T7 | Auth/spend-material exposure | `AuthRegistry.revoke` zeroes the leaf; owner can attempt post-delay `cancelForcedWithdrawal`; multi-device registration limits blast radius | Material sufficient to satisfy auth and note-opening/nullifier checks can authorize spends until excluded by a later accepted auth snapshot. Auth-leaf `expiry` is recorded but not independently enforced at spend time by `PrivacyBoost` |
| T8 | Viewing key exposure | Viewing keys do not authorize spends or nullifier derivation; users can rotate and migrate | Metadata becomes decryptable and UTXO ownership can become linkable |
| T9 | Operator note-encryption key exposure | User spends still require EdDSA authorization and accepted ZK proofs | Output metadata encrypted to the operator-side decryptor becomes decryptable |
| T10 | Trusted-setup toxic waste | Per-circuit multi-party ceremony with 1-of-N honesty assumption | If every relevant participant retained toxic waste, proof integrity/privacy assumptions fail |
| T11 | Governance/proxy/verifier-owner misuse | Production controls must constrain owner/operator/ProxyAdmin/verifier-owner roles; forced-withdraw verifier has no ordinary setter in the current implementation | Proxy or verifier-governance misuse can affect verifier selection, implementation behavior, relay policy, or economic parameters |

## Core Security Invariants (Normative)

Each invariant is stated as a protocol requirement and tied to the enforcing function or
constraint. Contract invariants are enforced in Solidity; circuit invariants (prefixed Z) are
enforced by the gnark R1CS and accepted on-chain only through the relevant Groth16 verifier call.
The mapping is organized by enforcement surface.

### Invariant Reference

| ID | Statement | Enforced by |
|---|---|---|
| `INV-X01` | Public-input vector order is canonical for each circuit | `LibPublicInputs` builders + gnark public witness order |
| `INV-X02` | Public-input vector length matches the verifier IC length | on-chain verifier length check |
| `INV-X03` | Public inputs are BN254 scalar-field elements | on-chain verifier field check |
| `INV-X04` | Poseidon domain separator constants match across implementations | Appendix B constants + contract/circuit/prover constants |
| `INV-X05` | Poseidon2T4 constants, schedule, and sponge encoding are canonical | [Cryptographic Primitives](01-cryptographic-primitives.md) + Appendix B |
| `INV-X06` | Packed tree numbers use 15-bit slots and reject out-of-range tree ids | Appendix B constants + pack/unpack helpers + circuit range checks |
| `INV-Z01` | Epoch transfer value conservation holds per active slot | `EpochCircuit` constraints |
| `INV-Z02` | Deposit request total equals hidden per-commitment values | `DepositEpochCircuit` constraints |
| `INV-Z03` | Forced-withdrawal amount equals active input values | `ForcedWithdrawCircuit` constraints |
| `INV-Z07` | Nullifier domain includes the note tree number | nullifier derivation constraints |
| `INV-Z08` | Nullifier binds to the user's nullifying key | nullifier derivation constraints |
| `INV-Z09` | Nullifier binds to the note leaf index | nullifier derivation constraints |
| `INV-Z11` | Spend auth key is in an accepted auth snapshot root | auth Merkle proof constraints + on-chain snapshot validation |
| `INV-Z12` | Sparse root selection is by `(treeNumber, root)` | root-with-tree-number assertions |
| `INV-Z13` | Spend authorization carries a valid EdDSA signature | `VerifyEdDSAIf` / `VerifyEdDSA` |
| `INV-Z14` | Signing key is bound into the auth leaf | auth leaf hash constraints |
| `INV-Z15` | Signed digest is bound to transaction details | digest recomputation + approval-message constraints |
| `INV-Z16` | Active output-tree root is distinct from historical spend roots | public input layout + frontier binding |
| `INV-Z19` | Active slot counts match circuit selectors | count fields + circuit selectors |
| `INV-Z20` | Inactive padded slots are zero | circuit padding constraints |
| `INV-Z21` | Note values and fees are 96-bit bounded | amount range checks |
| `INV-C14` | Deposit commitments are bound to stored pending deposits | `requestDeposit` storage + `submitDepositEpoch` validation |
| `INV-C15` | Forced withdrawal execution waits `forcedWithdrawalDelay` blocks | `_validateForcedWithdrawalExecution` |
| `INV-C16` | Forced withdrawal re-checks nullifiers at execution | inline `nullifierSpent` check + mark during execute |
| `INV-C17` | Forced withdrawal cancellation is requester-or-owner gated | `_validateForcedWithdrawalCancellation` |
| `INV-C18` | Nullifiers are globally single-spend | `nullifierSpent` + `_spendNullifiers` |
| `INV-C22` | Non-zero withdraw fees require a non-zero treasury | fee setter validation |
| `INV-C27` | Epoch calldata padding matches active per-slot counts | `_validateSlotPadding` |
| `INV-C28` | Digest root indices cover every digest-selected root | `_computeTransferDigests` / digest root mask |
| `INV-C29` | Deposit escrow is released only by processing or delayed cancellation | `processedDeposits` / `pendingDeposits` |
| `INV-C30` | Forced withdrawal cannot lazily create auth snapshots | `_validateAuthKnownRootsSparse(..., false)` |

1. **Value conservation.** The protocol MUST NOT create or destroy value within an epoch, deposit
 batch, or forced withdrawal.
 - Per active transfer: `sum(inputValues) = sum(outputValues) + feeAmount` (`INV-Z01`).
 - Per deposit request: `totalAmount = sum(perCommitmentValues)` (`INV-Z02`), and the on-chain
 `totalAmount` MUST equal the sum of per-commitment hidden amounts bound by `commitmentsHash`.
 - Forced withdrawal: `withdrawalAmount = sum(activeInputValues)` (`INV-Z03`).
 - Enforced in-circuit and gated on-chain by the Groth16 verifier calls in `submitEpoch`, `submitDepositEpoch`, and `requestForcedWithdrawal`.

2. **No double-spend / nullifier uniqueness.** A nullifier MUST be recordable at most once and MUST
 NOT ever transition back to unspent.
 - `nullifierSpent[x]` is set true only after successful proof verification: in `_spendNullifiers`
 for epochs and in `executeForcedWithdrawal`.
 - Each path rejects an already-spent or zero nullifier before marking: epoch spend, forced-withdraw
 request, and forced-withdraw execution.
 - In-circuit, each nullifier MUST equal
 `Poseidon(DOMAIN_NULLIFIER + treeNumber * NullifierTreeNumberMultiplier,
 nullifyingKey, leafIndex)` and bind to the proven tree/leaf (`INV-Z07`–`INV-Z09`); domain
 encoding `domainNullifier + treeNumber * NullifierTreeNumberMultiplier`.

3. **Only the owner can spend / authorization required.** Every active spend MUST carry a valid
 EdDSA signature over the approval digest, by a key bound to the spender's account in the auth
 tree.
 - In-circuit: valid EdDSA over the digest (`INV-Z13`), signing key bound via the auth leaf hash
 (`INV-Z14`), digest bound to tx details (`INV-Z15`).
 - The auth key MUST have a valid Merkle path into a provided, snapshot-validated auth root
 (`INV-Z11`); on-chain, auth roots are validated against an allowed snapshot round by
 `_validateAuthKnownRootsSparse`, invoked from
 `submitEpoch` with lazy-snapshot enabled.
 - AuthRegistry mutations (`register`/`rotate`/`revoke`) MUST carry an owner signature (verified
 via OZ `SignatureChecker`, supporting EOA, ERC-1271, and an ERC-7739 fallback) over an EIP-712
 struct hash including a per-account `nonce`.
 Account ID MUST be derived as `Poseidon(DOMAIN_ACCOUNTID, owner, salt)` (via `hash3`) at
 registration to prevent ID squatting. Spend circuits consume the already-derived `accountId`.
 - Auth public keys MUST lie on BabyJubjub; off-curve points revert `InvalidAuthPublicKey` via
 `LibBabyJubJub.isValidPublicKey`.

4. **Deposits credit exactly the escrowed amount.** `requestDeposit` MUST transfer exactly
 `totalAmount` from the depositor and MUST reject fee-on-transfer tokens.
 - Balance-delta check reverts `FeeOnTransferNotSupported` if received ≠ `totalAmount`.
 - The deposit ID is deterministic: `Poseidon(DOMAIN_DEPOSIT_REQUEST, chainId, pool, depositor,
 tokenId, totalAmount, nonce, commitmentsHash)` via `computeDepositRequestId` (`hash8`), bound
 in-circuit at processing (`INV-C14`).
 - `processedDeposits[id]` transitions false→true exactly once; processing does not delete
 `pendingDeposits[id]` (`INV-C29`), which is cleared only by `cancelDeposit`.
 - `cancelDeposit` returns exactly `totalAmount` and only after `cancelDelay` blocks.

5. **Withdrawal amount and fee semantics are path-specific.**
 - **Epoch withdrawal path:** each withdrawal output's commitment MUST equal
 `Poseidon(DOMAIN_NOTE, to, tokenId, amount)` via `computeWithdrawalCommitment` (`hash4`);
 mismatch reverts `InvalidWithdrawal`. Zero-amount withdrawals revert. The
 public ERC-20 payout is the proven `amount`; `withdrawFeeBps` is not applied on this path.
 Epoch-level fees are represented as shielded fee-note outputs and are conservation-enforced
 in-circuit.
 - **Forced withdrawal path:** the public ERC-20 payout is `netAmount = grossAmount − feeAmount`,
 with `feeAmount = uint96(grossAmount * requestFeeBps / BASIS_POINTS)`; `BASIS_POINTS = 10_000`. The fee rate used
 is the one captured **at request time** (`request.withdrawFeeBps`), not the current rate.
 - Caveat: in the forced path the fee transfer to treasury is gated on `treasury != address(0)`;
 if the treasury were somehow zeroed after a fee-bearing request, the fee portion remains in the
 contract. Setting a non-zero rate without a treasury is
 blocked at config time (next bullet), so this is an edge case, not a steady-state path.
 - Fee rate MUST NOT exceed `MAX_FEE_BPS = 1_000` (10%) and a non-zero fee MUST NOT be set without
 a treasury; `setTreasury` also blocks zeroing the treasury while a fee is set (`INV-C22`).

6. **Roots used in proofs MUST be canonical/historical.** A proof MUST only spend against a root
 that was genuinely produced by the contract.
 - `isKnownTreeRoot(treeNum, root)` returns true only for the current root of any tree, or a root
 in that tree's `ROOT_HISTORY_SIZE`-deep ring buffer for the active tree; finalized trees
 (`treeNum < currentTreeNumber`) accept only their current/final root. `ROOT_HISTORY_SIZE = 64`.
 - `_validateKnownRoots` MUST reject any unknown root (`RootNotKnown`) and enforce sparse-set
 tree-number uniqueness, with the documented epoch exception allowing duplicate tree numbers but
 rejecting exact duplicate `(treeNumber, root)` pairs.
 - The active tree's frontier-binding root is sourced directly from on-chain
 `treeRoot[activeTreeNumber]`, independent of the
 historical `usedRoots`/`NoteKnownRoots` used for input spending (`INV-Z16`).
 - Tree state submitted MUST exactly match on-chain state at submission: `activeTreeNumber ==
 currentTreeNumber` and `countOld == treeCount[...]`, preventing proof replay against stale
 state. `submitDepositEpoch` additionally requires the active root to equal the exact current
 root.

7. **Forced exit MUST be available without the TEE (self-custody).** A user holding their keys MUST
 be able to exit without TEE proving or epoch sequencing, given a live chain **and an existing
 auth snapshot covering their auth key**.
 - `requestForcedWithdrawal` is permissionless (no `onlyRelay`/`onlyOwner` modifier —
 `nonReentrant` only) and MUST NOT create auth
 snapshots (`_validateAuthKnownRootsSparse(..., false)`, `INV-C30`); it references an
 existing snapshot round. The snapshot is created only by a relay (`snapshotAuthTrees`,
 `onlyRelay`); if no snapshot covering the caller's auth key exists, the request
 reverts `AuthTreeNotSnapshotted`. Because snapshot entries are never deleted,
 the last snapshot covering a key remains usable even after the relay goes offline (self-custody
 holds for already-snapshotted keys).
 - `executeForcedWithdrawal` is callable only after `forcedWithdrawalDelay` blocks (delay check in
 `_validateForcedWithdrawalExecution`, `INV-C15`) and MUST
 revert if any nullifier was spent meanwhile by a concurrent epoch (`INV-C16`).
 - `cancelForcedWithdrawal` is callable after the same delay by the original requester or the
 account owner (resolved via `AuthRegistry.ownerOf(spenderAccountId)`, `INV-C17`). It is a
 post-maturity cancellation path: execution and cancellation become available at the same time, so
 transaction ordering determines which action lands first.

8. **Replay resistance via digests and nonces.** A signed authorization MUST NOT be replayable
 across transactions, accounts, chains, or pools.
 - Transfer and withdrawal digests bind `chainId`, `pool` (contract address), the selected `root`,
 the trimmed nullifier set, `outputs`, and the sender's `viewingKey`/`teeWrapKey`; the withdrawal
 digest additionally binds the public `withdrawal` tuple. These digests are split into 128-bit
 hi/lo halves for field compatibility (`DIGEST_HALF_BITS = 128`) and bound in-circuit (`INV-Z15`).
 The forced-withdrawal digest binds only `chainId`, `pool`, `root`, `nullifiers`, and `withdrawal`,
 and is passed whole.
 - AuthRegistry struct hashes bind `chainId` and `address(this)` via the EIP-712 domain separator
 and a strictly incrementing per-account `nonce`
 consumed on every `register`/`rotate`/`revoke`. The ERC-7739 fallback path
 additionally re-checks the app domain separator to prevent cross-app replay.
 - Deposit uniqueness is enforced by the per-depositor `nonce` folded into the deposit ID
 and an existence check that reverts
 `DepositAlreadyExists`.

9. **Slot-padding consistency (count binding).** Active input/output slots MUST be non-zero and
 inactive (padding) slots MUST be zero, on both nullifiers and output commitments.
 - On-chain `_validateSlotPadding` reverts `InvalidSlotPadding` on violation; the circuit-side counterpart is
 `INV-Z19`/`INV-Z20`. This binds per-transfer input/output counts between contract and circuit,
 preventing count-mismatch attacks.

10. **Access control.** Privileged actions MUST be restricted.
 - `submitEpoch`, `submitDepositEpoch`, `snapshotAuthTrees` MUST be relay-only.
 - `setAllowedRelays` and `setAuthSnapshotInterval` MUST be operator-only.
 - `setOperator`, `setFees`, `setEpochVerifier`, `setDepositVerifier`, and `setTreasury` MUST be
 owner-only. The current implementation has no `setForcedVerifier`: `forcedVerifier` is set once
 during initialization and has no ordinary setter. This is not absolute immutability if the deployed
 proxy remains upgradeable; a ProxyAdmin-controlled implementation upgrade can still change
 forced-withdraw behavior. By contrast, `epochVerifier` and `depositVerifier` are owner-reassignable
 inside the current implementation.

## Privacy Guarantees and Leakage

The privacy boundary is sharp: **transfers are fully shielded on-chain but visible to the TEE on the
convenient path; deposits and withdrawals are public at their boundary** (the points where value
enters/leaves the pool).

**Hidden (shielded) on transfer:**

| Property | Mechanism |
|----------|-----------|
| Sender identity | Nullifier unlinkable to any commitment; proven privately in-circuit |
| Recipient identity | Commitment hides NPK; `NPK = Poseidon(DOMAIN_NOTE, MPK, noteRnd)`, `MPK = Poseidon(DOMAIN_MPK, accountId, nullifyingKey)`; identifying it requires the viewing key |
| Token type | Folded into the commitment hash; not exposed on-chain |
| Transfer amount | Folded into the commitment hash (range-checked to 96 bits, `INV-Z21`); not exposed on-chain |
| Which UTXO was spent | Nullifier derived from secret nullifying key + leaf index; unlinkable to its commitment |

**Public (NOT hidden):**

| Property | Where exposed |
|----------|---------------|
| Deposit address | ERC-20 transfer from depositor; `PendingDeposit.depositor` |
| Deposit total amount | `PendingDeposit.totalAmount` (public; individual per-commitment amounts remain hidden in ciphertext) |
| Withdrawal address | `Withdrawal.to` |
| Withdrawal amount | `Withdrawal.amount` (gross) |
| Epoch timing | On-chain tx timestamps |
| Transfers per epoch | `nTransfers` |
| Fee token-type count | `feeTokenCount` |
| Spender account ID (forced exit only) | `spenderAccountId` public input — revealed so the owner can identify and attempt post-delay cancellation of a forced-exit request |

**Anonymity set.** A transfer's anonymity set is bounded by: all UTXOs across all historical trees
(input selection), all outputs in the same epoch (output linkage), and the publicly visible number
of active transfers in the epoch.

## Known Trade-offs and Out-of-Scope Assumptions

- **TEE for convenient-path liveness.** Centralized TEE proving is chosen for sub-500ms proofs,
 batch coordination, and plaintext indexing; the accepted cost is that ordinary transfers depend on
 the operator. Forced withdrawal bypasses TEE proving and epoch sequencing for keys already covered
 by an on-chain auth snapshot.
- **Groth16 trusted setup.** Each circuit needs a per-circuit ceremony; circuit changes require new
 ceremonies. Security reduces to 1-of-N honest participants.
- **ERC-20 assumptions.** Tokens MUST be standard ERC-20. Fee-on-transfer tokens are rejected at
 deposit. **Rebasing tokens (e.g., stETH, AMPL) are
 unsupported and may cause fund loss** — this is an explicit out-of-scope assumption, not an
 enforced invariant.
- **Auth-leaf expiry not spend-enforced.** `expiry` is stored in the auth leaf and checked against
 `block.timestamp` only at AuthRegistry mutation time; `PrivacyBoost` does not independently re-validate
 expiry at spend time. Revocation works by zeroing the leaf (`AuthRegistry._revoke` →
 `_updateLeaf(..., 0)`), which advances the auth root so
 subsequent snapshots exclude the key.
- **Tree depth and tree count.** Note/auth tree depths are deployment profile values and must match
 the registered verifier profiles. The maximum tree number is
 `MAX_NOTE_TREE_NUMBER = MAX_AUTH_TREE_NUMBER = 32767` (15-bit), distinct from
 `MAX_NOTE_ROOTS_PER_PROOF = MAX_AUTH_ROOTS_PER_PROOF = 16` (sparse roots per proof).
- **Reorg sensitivity.** Finalized state assumes target-chain consensus; deep reorgs are out of the contract's control.
- **Protocol enforcement scope.** Interface contracts, deployment scripts, prover infrastructure,
 CLI utilities, E2E tests, and product-level controls are outside the protocol
 enforcement surface described here.

---
