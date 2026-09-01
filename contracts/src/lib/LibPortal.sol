// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2026 Sunnyside Labs Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
pragma solidity 0.8.34;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {TOKEN_TYPE_ERC20, ROOT_HISTORY_SIZE, BASIS_POINTS} from "src/interfaces/Constants.sol";
import {PortalPendingDeposit, EpochTreeState, PortalDepositEntry} from "src/interfaces/IStructs.sol";
import {
    IPrivacyBoost,
    IPortalSweepSource,
    IPortalDepositVerifier,
    IPortalDelegate
} from "src/interfaces/IPrivacyBoost.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPoolShared} from "src/lib/LibPoolShared.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title LibPortal
/// @notice Portal-deposit helpers extracted from PrivacyBoost to keep the implementation bytecode under
///         the EIP-170 limit. Deployed as an external (delegatecall) library, exactly like LibEpoch, so
///         every function runs in the calling pool's context: `address(this)`, `msg.sender`, `block.*`,
///         and pool storage all resolve to the pool, not the library.
/// @dev Every function here is STORAGE-COUPLED: {requestPortalDeposit}, {cancelPortalDeposit}, and
///      {submitPortalDepositEpoch} receive the pool's portal-storage mappings BY REFERENCE and read/write
///      them directly under delegatecall. Solidity passes a storage reference as the slot number, and
///      because the library executes against the pool's storage (delegatecall), those writes land in the
///      pool. Two values that a delegatecall library CANNOT see from the caller — the `tokenRegistry`
///      immutable and the `cancelDelay` immutable (immutables are baked into the pool's own bytecode, not
///      its storage) — are therefore passed by value. The pool keeps the `nonReentrant` guard on its thin
///      wrapper: the transient-storage guard is set before the delegatecall, so a re-entrant call routes
///      back through the guarded wrapper and reverts. {requestPortalDeposit} additionally STATICCALLS the
///      portal account for its owner binding (IPortalDelegate.portalBinding) — the binding lives in the
///      portal's own account storage under EIP-7702 delegation, not in pool storage.
/// @custom:security-contact contact@sunnyside.io
library LibPortal {
    using SafeERC20 for IERC20;

    /// @notice Sweep a registered portal's ERC-20 balance into pool escrow and record the pending deposit.
    /// @dev Body moved verbatim from PrivacyBoost.requestPortalDeposit; the pool wrapper keeps `nonReentrant`
    ///      and forwards its portal-storage mappings by reference plus the `tokenRegistry` immutable and the
    ///      currently-snapshotted `portalSweepFeeBps` by value. `msg.sender` (the sweeper/keeper) and
    ///      `address(this)`/`block.*` are the pool's under delegatecall.
    /// @param portalCounter Per-portal counter used to derive a unique sweep id
    /// @param portalMinSweep Per-token minimum sweep amount
    /// @param portalPendingDeposits Pending portal-sweep map this call writes into
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param portalSweepFeeBps Sweep fee rate in basis points, snapshotted for this sweep
    /// @param portal The registered portal EOA being swept
    /// @param _tokenId The registered token being swept
    /// @return portalDepositId The identifier recorded for the pending sweep
    function requestPortalDeposit(
        mapping(address => uint256) storage portalCounter,
        mapping(uint16 => uint96) storage portalMinSweep,
        mapping(uint256 => PortalPendingDeposit) storage portalPendingDeposits,
        ITokenRegistry tokenRegistry,
        uint16 portalSweepFeeBps,
        address portal,
        uint16 _tokenId
    ) external returns (uint256 portalDepositId) {
        // The portal must be registered: the portal's own account storage holds the owner binding the
        // deposit proof will open, and it keys the request id. Read it back with a STATICCALL to the
        // delegated account (IPortalDelegate.portalBinding) — the binding lives at the portal account under
        // EIP-7702, not in pool storage, so the owner controls it directly. A LOW-LEVEL staticcall is used
        // deliberately, not a typed IPortalDelegate(portal).portalBinding(): for a plain EOA with no code the
        // typed call reverts with EMPTY data from Solidity's return-data extcodesize guard, which a try/catch
        // cannot remap to a precise error. The low-level form funnels BOTH unregistered shapes to
        // PortalNotRegistered — the account is not delegated to the portal code (a no-code account returns
        // success with < 32 bytes, and a non-portal delegate reverts), or it is delegated but never
        // initialized (returns a 32-byte zero) —
        // because a sweep of either could never be credited and would carry a zero recipientBindH that
        // computePortalDepositId rejects.
        (bool ok, bytes memory ret) = portal.staticcall(abi.encodeCall(IPortalDelegate.portalBinding, ()));
        if (!ok || ret.length < 32) revert IPrivacyBoost.PortalNotRegistered();
        uint256 recipientBindH = abi.decode(ret, (uint256));
        if (recipientBindH == 0) revert IPrivacyBoost.PortalNotRegistered();
        // The binding lives in the portal's own (owner-controlled, re-delegatable) account storage, so the
        // pool must NOT trust the staticcall return to be a canonical field element. PortalDelegate enforces
        // recipientBinding < SNARK_SCALAR_FIELD at initialization, but a re-delegated portal could return an
        // out-of-field word. recipientBindH is a portal-deposit-circuit PUBLIC input, and gnark reduces public
        // inputs mod PRIME, so a non-canonical binding would snapshot an on-chain word that diverges from the
        // in-circuit value. Reject it
        // here too, restoring the canonical-field guarantee the former pool-side registration enforced.
        if (recipientBindH >= LibDigest.SNARK_SCALAR_FIELD) revert IPrivacyBoost.InvalidPortalBinding();

        // Only standard ERC-20s registered with the protocol may be swept. The measured-delta
        // accounting below has no caller-declared amount to validate against, so fee-on-transfer and
        // rebasing tokens are excluded here by registration gating — the exact gate requestDeposit
        // applies, the difference being the portal cannot run the
        // FeeOnTransfer balance-equality check because the amount is discovered, not declared.
        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(_tokenId);
        if (tokenAddress == address(0)) revert IPrivacyBoost.InvalidDeposit();
        if (tokenType != TOKEN_TYPE_ERC20) revert IPrivacyBoost.TokenNotSupported(tokenType);

        // The portal PUSHES on a pool-invoked sweep; the pool measures the received
        // balance delta. Alternatives: the pool PULLS via an allowance the portal granted, or a portal-
        // initiated push. The pool — not the portal — is the accounting source of truth: it caps the
        // pull at the uint96 record ceiling and measures the actual received delta, so a misbehaving
        // portal cannot inflate the recorded amount, and any balance above the ceiling stays at the portal for
        // the next sweep. To change the seam, swap this push for an allowance-pull here and
        // the IPortalSweepSource interface together. nonReentrant guards the before/after measurement.
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IPortalSweepSource(portal).sweep(tokenAddress, type(uint96).max);
        uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;

        // Revert on nothing-swept or a balance below the per-token dust threshold (0 by default), so a
        // trivial sweep is not escrowed at a loss once a fee is enabled. The zero case is folded in:
        // received == 0 is always < any threshold >= 0, and the explicit < catches it when minSweep==0.
        uint96 minSweep = portalMinSweep[_tokenId];
        if (received == 0 || received < minSweep) revert IPrivacyBoost.SweepBelowDust(received, minSweep);

        // A compliant portal pushes at most the cap, so received <= type(uint96).max; reject an over-
        // push rather than truncate (truncation would strand the lost remainder permanently in escrow).
        if (received > type(uint96).max) revert IPrivacyBoost.SweepAmountOverflow(received);
        // forge-lint: disable-next-line(unsafe-typecast) received <= type(uint96).max enforced above
        uint96 amount = uint96(received);

        // Snapshot the fee rate NOW so a later setPortalSweepFeeBps cannot change an already-escrowed
        // sweep's credited amount; the net credit (amount - fee) is computed at epoch time from this.
        uint16 sweepFeeBps = portalSweepFeeBps;

        // Read the counter, then increment it: each sweep of the same portal gets a distinct counter,
        // which feeds noteRnd so two sweeps of the same (token, amount) still produce distinct notes
        // rather than a colliding commitment. The post-increment binds THIS record to the pre-value.
        uint256 counter = portalCounter[portal];
        portalCounter[portal] = counter + 1;

        // Build the request id from the swept amount and the storage-read binding/counter. The digest
        // helper enforces the field-element bounds (and the non-zero binding, already guaranteed above), so
        // the on-chain key matches the value the portal circuit and indexer recompute.
        portalDepositId = LibDigest.computePortalDepositId(
            block.chainid, address(this), portal, _tokenId, amount, counter, recipientBindH
        );

        // Uniqueness guard mirroring requestDeposit's DepositAlreadyExists: the (portal, counter) pair is
        // unique by the monotonic counter, so this only fires on a Poseidon collision or a storage bug.
        if (portalPendingDeposits[portalDepositId].portal != address(0)) {
            revert IPrivacyBoost.PortalDepositAlreadyExists();
        }

        portalPendingDeposits[portalDepositId] = PortalPendingDeposit({
            portal: portal,
            tokenId: _tokenId,
            amount: amount,
            sweepFeeBps: sweepFeeBps,
            requestBlock: uint64(block.number),
            // Record the sweeper (this caller) as the fee payee. The fee is charged at epoch time but
            // earned by whoever did the keeper work here, so it must be captured now: the relay that
            // later submits the epoch is a different actor in a permissionless keeper market and has no
            // way to know who swept each record. msg.sender is the keeper for a third-party
            // sweep, or the owner for a zero-fee self-sweep.
            sweeper: msg.sender,
            counter: counter,
            recipientBindH: recipientBindH
        });

        // The event carries no commitment or ciphertext (the sweeper has no recipientMPK): note discovery
        // recomputes the note from (portal, counter) + the off-chain registry. recipientBindH and the snapshotted
        // sweepFeeBps ARE emitted so the indexer's pending-sweep ingest is fully log-derived — it rebuilds the
        // escrow record from this event alone and never reads the portalPendingDeposits slot, which a later
        // cancelPortalDeposit/reclaim deletes (a catch-up or reorg could otherwise read it as zero and record
        // an uncreditable sweep).
        emit IPrivacyBoost.PortalDepositRequested(
            portalDepositId, portal, counter, _tokenId, amount, recipientBindH, sweepFeeBps
        );
    }

    /// @notice Reclaim an escrowed-but-uncredited portal sweep back to the portal after the cancel delay.
    /// @dev Body moved verbatim from PrivacyBoost.cancelPortalDeposit; the pool wrapper keeps `nonReentrant`
    ///      and forwards its portal-storage mappings by reference plus the `tokenRegistry` and `cancelDelay`
    ///      immutables by value. The refund target is the portal account (never msg.sender); reclaim is
    ///      permissionless.
    /// @param portalPendingDeposits Pending portal-sweep map the reclaimed entry is cleared from
    /// @param processedPortalDeposits Map marking sweeps already credited by an epoch
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param cancelDelay The delay that must elapse before a sweep may be reclaimed
    /// @param portalDepositId The pending sweep to reclaim to the portal
    function cancelPortalDeposit(
        mapping(uint256 => PortalPendingDeposit) storage portalPendingDeposits,
        mapping(uint256 => bool) storage processedPortalDeposits,
        ITokenRegistry tokenRegistry,
        uint256 cancelDelay,
        uint256 portalDepositId
    ) external {
        PortalPendingDeposit storage portalPendingDeposit = portalPendingDeposits[portalDepositId];

        // Processed first: this is the authoritative "already terminal" signal and is the only guard that
        // survives BOTH terminal paths. A reclaim deletes the record (portal -> 0) but sets processed; a
        // credit (submitPortalDepositEpoch) leaves the record intact but also sets processed. Checking
        // processed before existence makes a second cancel (deleted record) AND a cancel-after-credit
        // (intact record) both revert with the same precise already-processed error — and blocks the
        // credit-then-reclaim double-spend — rather than a deleted record falling through to the existence
        // error below. A never-swept id has processed == false and portal == 0, so it reaches the existence
        // guard and reverts as a non-existent deposit.
        if (processedPortalDeposits[portalDepositId]) revert IPrivacyBoost.PortalDepositAlreadyProcessed();
        if (portalPendingDeposit.portal == address(0)) revert IPrivacyBoost.InvalidDeposit();
        if (block.number < portalPendingDeposit.requestBlock + cancelDelay) revert IPrivacyBoost.CancelTooEarly();

        // Refund the FULL gross amount — no fee is charged on a reclaim. The sweep fee accrues only when an
        // epoch credits the note (submitPortalDepositEpoch), so an escrowed-but-uncredited record owes
        // nothing; refunding gross keeps value conservation exact and the pool collateralized.
        // Reclaim is permissionless and the refund target is portalPendingDeposit.portal, never msg.sender:
        // after the delay anyone may trigger the reclaim and the funds return to the portal, which the portal
        // contract then forwards to the owner's rescue destination (liveness backstop). This is
        // the one deliberate divergence from cancelDeposit, which restricts the caller to the depositor and
        // refunds msg.sender — a portal record has no depositor, only the bound owner behind the portal.
        address portal = portalPendingDeposit.portal;
        uint16 tokenId = portalPendingDeposit.tokenId;
        uint96 amount = portalPendingDeposit.amount;

        // Effects before interaction (checks-effects-interactions): set processed (the terminal flag the
        // guards above key on) and delete the record before the external token transfer. nonReentrant
        // already guards the transfer, so this ordering is defense in depth, not the sole protection; it
        // also leaves the deleted record un-creditable should any path ever bypass the modifier.
        processedPortalDeposits[portalDepositId] = true;
        delete portalPendingDeposits[portalDepositId];

        LibPoolShared.transferToken(tokenRegistry, tokenId, portal, amount);

        emit IPrivacyBoost.PortalDepositCancelled(portalDepositId);
    }

    /// @notice Credit a batch of escrowed portal sweeps into the note tree against a single ZK proof.
    /// @dev Storage-heavy remainder of PrivacyBoost.submitPortalDepositEpoch, moved here to keep the pool
    ///      under the EIP-170 limit. The pool wrapper performs the tree-state CAS validation AND the one
    ///      value-type tree-state write (`currentTreeNumber` + `TreeAdvanced`) before calling this, because
    ///      a delegatecall library cannot receive a storage reference to a value-type state variable — only
    ///      to mappings/structs/arrays. This function therefore receives the tree MAPPINGS by reference and
    ///      derives the target tree number from the (already-validated) `treeState`. Checks-effects-
    ///      interactions is preserved end-to-end: the wrapper's `currentTreeNumber` write and the mapping
    ///      writes below both land before the fee transfers (the only external interaction).
    /// @param portalDepositVerifier the portal-deposit Groth16 verifier (read from pool storage, passed by value)
    /// @param portalPendingDeposits Pending portal-sweep map each credited entry is read from
    /// @param processedPortalDeposits Map marking sweeps already credited, written as the double-credit guard
    /// @param claimablePortalSweepFees Per-sweeper, per-token deferred fee balances
    /// @param treeRoot Per-tree current root map
    /// @param treeCount Per-tree leaf-count map
    /// @param treeRootHistory Per-tree ring buffer of recent roots
    /// @param treeRootHistoryCursor Per-tree write cursor into that ring buffer
    /// @param treeState The epoch's note-tree state, already CAS-validated by the wrapper
    /// @param entries The pending portal sweeps this epoch credits
    /// @param commitments The note commitments the epoch appends
    /// @param proof The Groth16 proof over the built public inputs
    function submitPortalDepositEpoch(
        mapping(uint256 => PortalPendingDeposit) storage portalPendingDeposits,
        mapping(uint256 => bool) storage processedPortalDeposits,
        mapping(address => mapping(uint16 => uint256)) storage claimablePortalSweepFees,
        mapping(uint256 => uint256) storage treeRoot,
        mapping(uint256 => uint32) storage treeCount,
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        IPortalDepositVerifier portalDepositVerifier,
        EpochTreeState calldata treeState,
        PortalDepositEntry[] calldata entries,
        uint256[] calldata commitments,
        uint256[8] calldata proof
    ) external {
        // maxSlots (the VK shape) and the tree-state CAS were validated by the pool wrapper. The shape is the
        // padded commitments.length; nRequests (entries.length) is the active count, and the trailing
        // maxSlots - nRequests public-input slots are zero (the memory arrays below default to zero) to match
        // the circuit's zero-padded inactive slots.
        uint32 maxSlots = uint32(commitments.length);
        uint32 nRequests = uint32(entries.length);

        // Build the public-input arrays from STORAGE, never from caller arguments. The credited amount is
        // the net (gross − snapshotted fee). The binding and counter come from the stored record. This is what
        // prevents a malicious relay from substituting a different amount, owner binding, or counter — the
        // contract, not the proof submitter, dictates every bound public input.
        uint256[] memory portals = new uint256[](maxSlots);
        uint256[] memory counters = new uint256[](maxSlots);
        uint256[] memory recipientBindHs = new uint256[](maxSlots);
        uint256[] memory tokenIds = new uint256[](maxSlots);
        uint256[] memory netAmounts = new uint256[](maxSlots);
        uint256[] memory commitmentsOut = new uint256[](maxSlots);

        // Accumulate fees per (sweeper, token) pair so a batch mixing tokens AND sweepers settles each
        // pair's fee in a single transfer to the address that actually performed that sweep. A batch can
        // contain records swept by different keepers, so the payee is keyed alongside the token — keying
        // by token alone would mis-route one keeper's fee to another. The three arrays stay parallel and
        // feePairCount is the number of distinct (sweeper, token) pairs that accrued a fee.
        address[] memory feeSweepers = new address[](maxSlots);
        uint16[] memory feeTokenIds = new uint16[](maxSlots);
        // Each record's fee fits uint96, but the sum for one (sweeper, token) pair can exceed uint96 in
        // multi-record batches. Memory elements already occupy a full 32-byte word, so widening only this
        // aggregate does not affect PortalPendingDeposit's packed storage layout.
        uint256[] memory feeAmounts = new uint256[](maxSlots);
        uint256 feePairCount = 0;

        for (uint256 i = 0; i < nRequests; ++i) {
            uint256 id = entries[i].portalDepositId;
            PortalPendingDeposit storage portalPendingDeposit = portalPendingDeposits[id];

            // Existence (portal != 0) and not-yet-processed guards mirror submitDepositEpoch's
            // depositor!=0 / processedDeposits checks; set processed before the verify so a re-entrant or
            // duplicate-in-batch id cannot be credited twice (the second pass reverts here).
            if (portalPendingDeposit.portal == address(0)) revert IPrivacyBoost.InvalidDeposit();
            if (processedPortalDeposits[id]) revert IPrivacyBoost.PortalDepositAlreadyProcessed();
            processedPortalDeposits[id] = true;

            // Net credited amount = gross − gross·sweepFeeBps/BASIS_POINTS, mirroring the withdrawal
            // path's request-time-snapshotted fee math. The fee was snapshotted at sweep time, so a later
            // rate change cannot alter an escrowed sweep's credit.
            uint96 gross = portalPendingDeposit.amount;
            // forge-lint: disable-next-line(unsafe-typecast) sweepFeeBps <= MAX_FEE_BPS (10%) of uint96 gross
            uint96 feeAmount = uint96((uint256(gross) * portalPendingDeposit.sweepFeeBps) / BASIS_POINTS);
            uint96 netAmount = gross - feeAmount;

            portals[i] = uint256(uint160(portalPendingDeposit.portal));
            counters[i] = portalPendingDeposit.counter;
            recipientBindHs[i] = portalPendingDeposit.recipientBindH;
            tokenIds[i] = uint256(portalPendingDeposit.tokenId);
            netAmounts[i] = uint256(netAmount);
            commitmentsOut[i] = commitments[i];

            // Keeper economics: sweepFeeBps = 0 at launch, so this branch is dead in the operator-run MVP
            // (no fee accrues); the plumbing is built for the later permissionless keeper market. The fee
            // accrues to portalPendingDeposit.sweeper, the keeper who performed this record's sweep and paid its gas,
            // to the epoch submitter, because the sweeper and the relay are distinct actors.
            if (feeAmount > 0) {
                feePairCount = _accrueFee(
                    feeSweepers,
                    feeTokenIds,
                    feeAmounts,
                    feePairCount,
                    portalPendingDeposit.sweeper,
                    portalPendingDeposit.tokenId,
                    feeAmount
                );
            }
        }

        uint256[] memory publicInputs = LibPublicInputs.buildPortalDepositInputs(
            block.chainid,
            address(this),
            treeState,
            nRequests, // active portal deposits; the trailing maxSlots - nRequests slots are zero-padded
            portals,
            counters,
            recipientBindHs,
            tokenIds,
            netAmounts,
            commitmentsOut
        );

        portalDepositVerifier.verifyPortalDeposit(maxSlots, proof, publicInputs);

        // Tree-state mapping writes (the value-type `currentTreeNumber` advance + `TreeAdvanced` already
        // happened in the wrapper). The target tree is the active tree, or the next one on rollover — the
        // wrapper enforced activeTreeNumber == currentTreeNumber and the rollover bound, so this matches
        // the value the wrapper advanced `currentTreeNumber` to.
        uint256 targetTree = treeState.rollover ? treeState.activeTreeNumber + 1 : treeState.activeTreeNumber;
        treeRoot[targetTree] = treeState.rootNew;
        treeCount[targetTree] = treeState.countNew;
        LibPoolShared.pushTreeRoot(treeRootHistory, treeRootHistoryCursor, targetTree, treeState.rootNew);

        // Isolate each recipient-specific transfer so a token blacklist or allowlist cannot make one sweeper
        // control epoch liveness. A failed push becomes a liability payable only to the same recorded sweeper.
        for (uint256 i = 0; i < feePairCount; ++i) {
            try IPrivacyBoost(address(this)).payPortalSweepFee(feeTokenIds[i], feeSweepers[i], feeAmounts[i]) {}
            catch {
                claimablePortalSweepFees[feeSweepers[i]][feeTokenIds[i]] += feeAmounts[i];
                emit IPrivacyBoost.PortalSweepFeeDeferred(feeSweepers[i], feeTokenIds[i], feeAmounts[i]);
            }
        }
    }

    /// @notice Pay the caller's deferred portal sweep fee for one token.
    /// @dev The library runs by delegatecall, so msg.sender remains the original sweeper. Effects precede the
    ///      ERC-20 interaction. A failed transfer restores the liability, while a successful transfer cannot
    ///      be replayed.
    /// @param claimablePortalSweepFees Per-sweeper, per-token deferred fee balances
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param tokenId The token whose deferred fee is being paid out
    function claimPortalSweepFee(
        mapping(address => mapping(uint16 => uint256)) storage claimablePortalSweepFees,
        ITokenRegistry tokenRegistry,
        uint16 tokenId
    ) external {
        uint256 amount = claimablePortalSweepFees[msg.sender][tokenId];
        if (amount == 0) revert IPrivacyBoost.NoDeferredPortalSweepFee(msg.sender, tokenId);

        claimablePortalSweepFees[msg.sender][tokenId] = 0;
        LibPoolShared.transferToken(tokenRegistry, tokenId, msg.sender, amount);

        emit IPrivacyBoost.PortalSweepFeeClaimed(msg.sender, tokenId, amount);
    }

    /// @dev Accumulate `feeAmount` for the `(sweeper, tokenId)` pair into the parallel (sweepers, ids,
    ///      amounts) arrays, deduping on BOTH keys so the same token swept by two keepers stays two payouts
    ///      and the same keeper sweeping two tokens stays two payouts. Returns the (possibly incremented)
    ///      count of distinct pairs. Linear scan is fine: feePairCount <= maxSlots <= maxBatchSize, and the
    ///      operator-run MVP never reaches here because sweepFeeBps is 0. Moved verbatim from PrivacyBoost.
    function _accrueFee(
        address[] memory feeSweepers,
        uint16[] memory feeTokenIds,
        uint256[] memory feeAmounts,
        uint256 feePairCount,
        address sweeper,
        uint16 tokenId,
        uint96 feeAmount
    ) private pure returns (uint256) {
        for (uint256 j = 0; j < feePairCount; ++j) {
            if (feeSweepers[j] == sweeper && feeTokenIds[j] == tokenId) {
                feeAmounts[j] += feeAmount;
                return feePairCount;
            }
        }
        feeSweepers[feePairCount] = sweeper;
        feeTokenIds[feePairCount] = tokenId;
        feeAmounts[feePairCount] = feeAmount;
        return feePairCount + 1;
    }
}
