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

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20, MockVerifier, BindablePortal} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";
import {PortalDepositEntry, EpochTreeState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20, MAX_NOTE_ROOTS_PER_PROOF} from "src/interfaces/Constants.sol";

/// @dev A minimal cap-honoring portal: pushes min(balance, cap) of the token to the pool on sweep. Holding
///      the funds here and pushing on demand exercises the real measured-delta accounting in
///      requestPortalDeposit, so the escrow records the pool actually credits are the ones we assert on.
contract PortalSweepSourceMock is BindablePortal, IPortalSweepSource {
    function sweep(address token, uint256 cap) external override {
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 amount = bal < cap ? bal : cap;
        IERC20(token).transfer(msg.sender, amount);
    }
}

/// @dev ERC-20 mock whose issuer can reject selected recipients, matching tokens with an address blacklist
///      or recipient allowlist. Blocking happens after the portal sweep so only fee settlement is affected.
contract RecipientBlockingToken is MockERC20 {
    error RecipientBlocked(address recipient);

    mapping(address recipient => bool blocked) public blockedRecipients;

    function setRecipientBlocked(address recipient, bool blocked) external {
        blockedRecipients[recipient] = blocked;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (blockedRecipients[to]) revert RecipientBlocked(to);
        super._update(from, to, value);
    }
}

/// @dev A stateless portal-deposit verifier that ACCEPTS every proof. It is `view` (no state writes) so the
///      pool's staticcall to verifyPortalDeposit succeeds — the real verifier is `view` too. Capturing what
///      public inputs the pool passed is done with vm.expectCall against the EXACT expected vector (the pool
///      builds it from storage, so a wrong net amount / binding / counter would mismatch and fail). The
///      cryptographic "reject a tampered proof" half is covered by the real-proof FFI test
///      (test/ffi/PortalDepositFFI.t.sol) — a mock verifier cannot exercise the pairing check.
contract AcceptingPortalVerifier {
    function verifyPortalDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev A portal-deposit verifier that REJECTS every proof (reverts), to prove the verify call is actually
///      on the credit path: if submitPortalDepositEpoch skipped the verifier, the happy path would still
///      pass with this installed — so the revert here is what makes "the proof is verified" observable.
contract RejectingPortalVerifier {
    error PortalProofRejected();

    function verifyPortalDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        revert PortalProofRejected();
    }
}

/// @dev Behavior coverage for submitPortalDepositEpoch (step 2 of the hidden-recipient portal deposit: the
///      relay credits swept escrow into the shielded pool). Every test asserts an observable outcome that
///      changes if the entrypoint or one of its guards is deleted — never a bare "didn't revert". The
///      load-bearing properties: the credited amount is the NET
///      (gross − snapshotted fee) the contract derives from storage; the H/counter/commitment public
///      inputs are storage-derived and not caller-influenceable; the proof is actually verified; the tree
///      root advances; double-submit and stale-tree-state revert; any sweep fee is paid immediately or
///      deferred for the SWEEPER that earned it (per (sweeper, token) pair), not the relay submitting the epoch.
contract SubmitPortalDepositEpochTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;
    MockERC20 token2; // second token for multi-token fee-aggregation coverage
    AcceptingPortalVerifier portalVerifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address relay = makeAddr("relay");
    address keeper = makeAddr("keeper");
    address keeper2 = makeAddr("keeper2"); // second sweeper for per-sweeper fee-routing coverage
    address operator = makeAddr("operator");

    PortalSweepSourceMock portal;
    address E; // portal address == address(portal)

    uint16 tokenId;
    uint16 tokenId2;
    uint256 constant H = 0xB14D; // the registered owner binding
    uint256[8] dummyProof;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        // Raise the batch cap above the largest registered portal shape (32) so the full-batch gas tests can
        // submit a maxSlots=32 epoch. The cap is an immutable read in the entrypoint, so its value does not
        // affect the measured submit gas (only that maxSlots <= cap); production deploys with a larger cap (100).
        cfg.batchSize = 64;
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        token2 = new MockERC20();
        tokenId2 = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token2), 0);

        // Install an accepting portal verifier (the portal verifier defaults to address(0) and is set
        // post-deployment via setPortalDepositVerifier — mirrors the verifier wiring). It is `view`/stateless so the
        // pool's staticcall succeeds; the public-input binding is asserted with vm.expectCall.
        portalVerifier = new AcceptingPortalVerifier();
        pool.setPortalDepositVerifier(address(portalVerifier));

        // Allow `relay` to submit portal epochs.
        pool.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        // Deploy the portal and initialize its account-side binding (read back via portalBinding() at sweep).
        portal = new PortalSweepSourceMock();
        E = address(portal);
        portal.initializePortal(H);
    }

    // ============================================
    // Helpers
    // ============================================

    /// @dev Fund + sweep the portal so a pending escrow record exists to credit. Returns the id.
    ///      Swept by `keeper` (the default sweeper); use `_sweepAs` to record a different sweeper.
    function _sweep(uint96 amount) internal returns (uint256 id) {
        token.mint(E, amount);
        vm.prank(keeper);
        id = pool.requestPortalDeposit(E, tokenId);
    }

    /// @dev Fund + sweep the shared portal E as an explicit sweeper and token, so multi-sweeper /
    ///      multi-token batches can assert the fee routes per (sweeper, token) pair. Mints `amount` of `tok`
    ///      to E then sweeps it whole (the mock pushes its full token balance), so each call escrows exactly
    ///      one record swept by `sweeper`; repeated calls get distinct ids via the per-portal counter.
    function _sweepAs(address sweeper, uint96 amount, MockERC20 tok, uint16 tid) internal returns (uint256 id) {
        tok.mint(E, amount);
        vm.prank(sweeper);
        id = pool.requestPortalDeposit(E, tid);
    }

    function _getUsedRoots(uint256 treeNum) internal view returns (TreeRootPair[] memory roots) {
        roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: treeNum, root: pool.treeRoot(treeNum)});
    }

    function _singleEntry(uint256 id) internal pure returns (PortalDepositEntry[] memory entries) {
        entries = new PortalDepositEntry[](1);
        entries[0] = PortalDepositEntry({portalDepositId: id});
    }

    function _singleCommitment(uint256 c) internal pure returns (uint256[] memory cs) {
        cs = new uint256[](1);
        cs[0] = c;
    }

    function _samePairBatch(uint32 n, uint96 gross)
        internal
        returns (PortalDepositEntry[] memory entries, uint256[] memory commitments)
    {
        entries = new PortalDepositEntry[](n);
        commitments = new uint256[](n);
        for (uint32 i = 0; i < n; ++i) {
            entries[i] = PortalDepositEntry({portalDepositId: _sweepAs(keeper, gross, token, tokenId)});
            commitments[i] = uint256(i) + 1;
        }
    }

    /// @dev Credit one sweep whose token rejects the recorded sweeper, leaving its fee deferred.
    function _deferBlockedSweeperFee()
        internal
        returns (RecipientBlockingToken restrictedToken, uint16 restrictedTokenId, uint96 fee)
    {
        restrictedToken = new RecipientBlockingToken();
        restrictedTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(restrictedToken), 0);
        pool.setPortalSweepFeeBps(300);

        uint96 gross = 250 ether;
        uint256 id = _sweepAs(keeper2, gross, restrictedToken, restrictedTokenId);
        fee = uint96((uint256(gross) * 300) / 10_000);
        restrictedToken.setRecipientBlocked(keeper2, true);

        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(_getUsedRoots(0), 0, countOld, 0xABCD, countOld + 1, false);
        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, _singleEntry(id), _singleCommitment(111), dummyProof);
    }

    function _u(uint256 v) internal pure returns (uint256[] memory a) {
        a = new uint256[](1);
        a[0] = v;
    }

    /// @dev Build the EXACT public-input vector the contract is expected to pass to the verifier for a
    ///      single-slot portal epoch, from the values the contract must read from storage (E, counter, H,
    ///      net amount, tokenId) plus the caller-supplied commitment and the tree-state. Calling the same
    ///      LibPublicInputs.buildPortalDepositInputs the contract calls makes vm.expectCall a tight,
    ///      load-bearing assertion: if submitPortalDepositEpoch substituted any value (wrong net, wrong
    ///      binding, caller-influenced counter) the calldata would differ and the match would fail.
    function _expectedInputs(EpochTreeState memory treeState, uint256 counter, uint256 netAmount, uint256 commitment)
        internal
        view
        returns (uint256[] memory)
    {
        return LibPublicInputs.buildPortalDepositInputs(
            block.chainid,
            address(pool),
            treeState,
            1, // nRequests
            _u(uint256(uint160(E))),
            _u(counter),
            _u(H),
            _u(uint256(tokenId)),
            _u(netAmount),
            _u(commitment)
        );
    }

    /// @dev Assert the pool calls the portal verifier exactly once with `expected` public inputs.
    function _expectVerifyCall(uint32 maxSlots, uint256[] memory expected) internal {
        vm.expectCall(
            address(portalVerifier),
            abi.encodeWithSelector(
                AcceptingPortalVerifier.verifyPortalDeposit.selector, maxSlots, dummyProof, expected
            ),
            1
        );
    }

    /// @dev Submit a FULL maxSlots=n portal epoch (n real entries, no padding) under the no-op verifier and
    ///      return the measured gas of just the submitPortalDepositEpoch call. Isolates the entrypoint
    ///      overhead (storage reads, net-fee accounting, per-slot credit + tree append) from proof
    ///      verification, which the AcceptingPortalVerifier makes ~free. A full batch is the worst case
    ///      (every slot is a real credit + append), so it bounds the gas for any padded batch at that shape.
    function _submitFullBatchGas(uint32 n) internal returns (uint256 gasUsed) {
        uint96 amount = 1000 ether;
        PortalDepositEntry[] memory entries = new PortalDepositEntry[](n);
        uint256[] memory commitments = new uint256[](n);
        for (uint32 i = 0; i < n; i++) {
            entries[i] = PortalDepositEntry({portalDepositId: _sweep(amount)});
            commitments[i] = 0xC0FFEE + i;
        }
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xDEAD0000 + uint256(n), countOld + n, false);

        vm.prank(relay);
        uint256 g = gasleft();
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);
        gasUsed = g - gasleft();
    }

    /// @dev Measure the maximum fee-settlement work for one registered shape: every record has a distinct
    ///      sweeper, so no pair deduplicates, and one recipient rejects its transfer and writes a liability.
    function _submitFullBatchDistinctSweeperFeeGas(uint32 n) internal returns (uint256 gasUsed) {
        RecipientBlockingToken restrictedToken = new RecipientBlockingToken();
        uint16 restrictedTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(restrictedToken), 0);
        uint16 feeBps = 300;
        uint96 amount = 1000 ether;
        pool.setPortalSweepFeeBps(feeBps);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](n);
        uint256[] memory commitments = new uint256[](n);
        address blockedSweeper;
        for (uint32 i = 0; i < n; i++) {
            address sweeper = address(uint160(uint256(keccak256(abi.encode("portal gas sweeper", i)))));
            entries[i] =
                PortalDepositEntry({portalDepositId: _sweepAs(sweeper, amount, restrictedToken, restrictedTokenId)});
            commitments[i] = 0xFEE000 + i;
            if (i == n - 1) blockedSweeper = sweeper;
        }
        restrictedToken.setRecipientBlocked(blockedSweeper, true);

        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(_getUsedRoots(0), 0, countOld, 0xFEE00000 + uint256(n), countOld + n, false);

        vm.prank(relay);
        uint256 g = gasleft();
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);
        gasUsed = g - gasleft();

        uint256 expectedDeferred = (uint256(amount) * feeBps) / 10_000;
        assertEq(
            pool.claimablePortalSweepFees(blockedSweeper, restrictedTokenId), expectedDeferred, "blocked pair deferred"
        );
    }

    /// @notice Measure the submitPortalDepositEpoch entrypoint overhead at the registered production shape 8.
    /// @dev Feeds the sequencer's portal_s8 gas-limit constant: the on-chain submit cost is this entrypoint
    ///      overhead plus the real Groth16 verify gas (measured separately by PortalDepositFFI.t.sol).
    function test_submitPortalDepositEpoch_gas_fullBatch8() public {
        emit log_named_uint(
            "portal_s8 submitPortalDepositEpoch overhead (no-op verifier, 8 full)", _submitFullBatchGas(8)
        );
    }

    /// @notice Measure the submitPortalDepositEpoch entrypoint overhead at the registered production shape 32.
    function test_submitPortalDepositEpoch_gas_fullBatch32() public {
        emit log_named_uint(
            "portal_s32 submitPortalDepositEpoch overhead (no-op verifier, 32 full)", _submitFullBatchGas(32)
        );
    }

    /// @notice Measure the portal_s1 fee-settlement worst case used by the relay gas-limit table.
    function test_submitPortalDepositEpoch_gas_fullBatch1DistinctSweeperOneBlocked() public {
        emit log_named_uint(
            "portal_s1 submitPortalDepositEpoch overhead (1 fee pair, blocked)",
            _submitFullBatchDistinctSweeperFeeGas(1)
        );
    }

    /// @notice Measure the portal_s8 fee-settlement worst case used by the relay gas-limit table.
    function test_submitPortalDepositEpoch_gas_fullBatch8DistinctSweepersOneBlocked() public {
        emit log_named_uint(
            "portal_s8 submitPortalDepositEpoch overhead (8 fee pairs, one blocked)",
            _submitFullBatchDistinctSweeperFeeGas(8)
        );
    }

    /// @notice Measure the portal_s32 fee-settlement worst case used by the relay gas-limit table.
    function test_submitPortalDepositEpoch_gas_fullBatch32DistinctSweepersOneBlocked() public {
        emit log_named_uint(
            "portal_s32 submitPortalDepositEpoch overhead (32 fee pairs, one blocked)",
            _submitFullBatchDistinctSweeperFeeGas(32)
        );
    }

    // ========== Happy path: net credit, storage-bound public inputs, root advance ==========

    /// @dev A valid portal epoch credits the NET amount, advances the tree root/count, marks the record
    ///      processed, and feeds the verifier a public-input vector whose amount/H/counter/commitment slots
    ///      are storage-derived. With sweepFeeBps = 0 (MVP default) net == gross. The vm.expectCall asserts
    ///      the EXACT vector (built from storage E/counter/H/net/tokenId); deleting the entrypoint, skipping
    ///      the storage-build, or computing the wrong net fails these assertions.
    function test_submitPortalDepositEpoch_creditsNetAndAdvancesRoot() public {
        uint96 amount = 1000 ether;
        uint256 id = _sweep(amount);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        uint256 newRoot = 0xDEADBEEF;
        uint256 commitment = 0xC0FFEE;

        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, newRoot, countOld + 1, false);

        // At fee 0 the net credited amount equals the gross; counter is 0 (first sweep of this portal).
        _expectVerifyCall(1, _expectedInputs(treeState, 0, uint256(amount), commitment));

        vm.expectEmit(true, true, true, true, address(pool));
        emit IPrivacyBoost.PortalDepositEpochSubmitted(0, newRoot, countOld, countOld + 1);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, _singleEntry(id), _singleCommitment(commitment), dummyProof);

        // The record is processed (no double-credit possible) and the tree advanced to the submitted root.
        assertTrue(pool.processedPortalDeposits(id), "record marked processed");
        assertEq(pool.treeRoot(0), newRoot, "tree root advanced to the submitted root");
        assertEq(pool.treeCount(0), countOld + 1, "leaf count advanced by one note");
    }

    /// @dev Rollover variant of the happy path: when the active tree is full the epoch advances to the NEXT
    ///      tree. This exercises the wrapper/library split of the tree-state write — the pool wrapper does
    ///      the value-type `currentTreeNumber` increment + `TreeAdvanced` emit, while LibPortal writes the
    ///      new tree's root/count/history mappings — and asserts both agree on the target tree (1). A
    ///      delegatecall library cannot receive a storage reference to the value-type `currentTreeNumber`,
    ///      so the split puts that one write in the wrapper; this is the path most likely to diverge if the
    ///      wrapper and library disagreed on the rollover target, so it is asserted directly.
    function test_submitPortalDepositEpoch_rollover_advancesToNextTree() public {
        uint96 amount = 1000 ether;
        uint256 id = _sweep(amount);

        // Fill the active tree (0) to capacity so the epoch must roll over. merkleDepth is 20 (PoolDeployer
        // default) → maxLeaves = 2^20; fill via vm.store rather than a million appends. Slots from
        // `forge inspect`: treeRoot=7, treeCount=8, treeRootHistory=9, treeRootHistoryCursor=10.
        uint32 maxLeaves = uint32(1 << 20);
        uint256 fullRoot = 0xF011EEEE;
        vm.store(address(pool), keccak256(abi.encode(uint256(0), uint256(8))), bytes32(uint256(maxLeaves)));
        vm.store(address(pool), keccak256(abi.encode(uint256(0), uint256(7))), bytes32(fullRoot));
        vm.store(address(pool), keccak256(abi.encode(uint256(0), uint256(10))), bytes32(uint256(1)));
        vm.store(address(pool), bytes32(uint256(keccak256(abi.encode(uint256(0), uint256(9)))) + 1), bytes32(fullRoot));
        assertEq(pool.treeCount(0), maxLeaves, "active tree filled to capacity");
        assertEq(pool.currentTreeNumber(), 0, "still on tree 0 before submit");

        TreeRootPair[] memory usedRoots = new TreeRootPair[](1);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: fullRoot});
        uint256 newRoot = 0xABCD1234;
        uint256 commitment = 0xC0FFEE;

        // rollover=true → countNew is the NEW tree's leaf count (one note), not countOld + 1.
        EpochTreeState memory treeState = EpochHelpers.buildTreeState(usedRoots, 0, maxLeaves, newRoot, 1, true);

        _expectVerifyCall(1, _expectedInputs(treeState, 0, uint256(amount), commitment));

        // Wrapper advances currentTreeNumber and emits TreeAdvanced(0, 1) before delegating; the final
        // PortalDepositEpochSubmitted reports the new tree number (1) and countOld 0 on rollover.
        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.TreeAdvanced(0, 1);
        vm.expectEmit(true, true, true, true, address(pool));
        emit IPrivacyBoost.PortalDepositEpochSubmitted(1, newRoot, 0, 1);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, _singleEntry(id), _singleCommitment(commitment), dummyProof);

        // The tree advanced to 1, the NEW tree carries the submitted root/count, and the record is processed.
        assertEq(pool.currentTreeNumber(), 1, "advanced to next tree");
        assertEq(pool.treeRoot(1), newRoot, "new tree root == submitted root");
        assertEq(pool.treeCount(1), 1, "new tree leaf count == one note");
        assertTrue(pool.processedPortalDeposits(id), "record marked processed");
    }

    /// @dev Value conservation with a non-zero fee: credited net == gross − gross·feeBps/BASIS_POINTS, and
    ///      the fee is transferred to the SWEEPER that earned it (here `keeper`, the requestPortalDeposit
    ///      caller), NOT to the relay submitting the epoch. The two are distinct actors; the
    ///      `_sweep` helper sweeps as `keeper` while the epoch is submitted by `relay`, so a payout to
    ///      msg.sender (the relay) would fail the keeper assertion and credit the wrong party. The fee is
    ///      snapshotted at SWEEP time, so it is charged here even though the live rate is later changed.
    ///      Deleting the net computation (crediting gross) or paying the relay fails the respective assertion.
    function test_submitPortalDepositEpoch_chargesSnapshottedFeeToSweeper() public {
        // Snapshot a 300 bps fee into the record at sweep time.
        pool.setPortalSweepFeeBps(300);
        uint96 gross = 1000 ether;
        uint256 id = _sweep(gross); // swept by `keeper`

        // Change the live rate afterward — must NOT affect the already-escrowed record.
        pool.setPortalSweepFeeBps(900);

        uint96 expectedFee = uint96((uint256(gross) * 300) / 10_000);
        uint96 expectedNet = gross - expectedFee;

        uint256 keeperBefore = token.balanceOf(keeper);
        uint256 relayBefore = token.balanceOf(relay);
        uint256 poolBefore = token.balanceOf(address(pool));

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false);

        // The verifier must see the NET amount (snapshotted 300 bps, not the live 900), not the gross.
        _expectVerifyCall(1, _expectedInputs(treeState, 0, uint256(expectedNet), 0xC0FFEE));

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, _singleEntry(id), _singleCommitment(0xC0FFEE), dummyProof);

        // The fee landed at the sweeper (keeper) — the keeper-incentive invariant; the relay earns nothing
        // for merely submitting; the credited net stays escrowed in the pool.
        assertEq(token.balanceOf(keeper) - keeperBefore, expectedFee, "fee paid to the sweeper (keeper), not the relay");
        assertEq(token.balanceOf(relay), relayBefore, "relay (epoch submitter) earns no fee");
        assertEq(
            poolBefore - token.balanceOf(address(pool)), expectedFee, "pool retains exactly the net (only the fee left)"
        );
    }

    /// @dev The proof is actually verified: installing a verifier that rejects every proof makes the
    ///      otherwise-valid epoch revert. Without the verify call this epoch would succeed, so the revert is
    ///      what makes "the proof is checked" observable (root-cause behavior, not a vacuous pass).
    function test_submitPortalDepositEpoch_revertWhen_proofRejected() public {
        uint256 id = _sweep(500 ether);

        RejectingPortalVerifier rejecting = new RejectingPortalVerifier();
        pool.setPortalDepositVerifier(address(rejecting));

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        vm.prank(relay);
        vm.expectRevert(RejectingPortalVerifier.PortalProofRejected.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );

        // Full rollback: the record is not processed and the tree did not advance.
        assertFalse(pool.processedPortalDeposits(id), "record not processed when proof rejected");
        assertEq(pool.treeCount(0), countOld, "tree count unchanged on revert");
    }

    /// @dev The resulting root is exactly the submitted rootNew (the append result the relay computed
    ///      off-chain). The contract is the append authority for state, so crediting a note then reading
    ///      back treeRoot pins the recomputed-append property. A wrong _updateTreeState would diverge here.
    function test_submitPortalDepositEpoch_resultingRootMatchesSubmitted() public {
        uint256 id = _sweep(42 ether);
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        uint256 newRoot = 0x1234567890ABCDEF;

        vm.prank(relay);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, newRoot, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(777),
            dummyProof
        );

        assertEq(pool.treeRoot(0), newRoot, "stored root == submitted append result");
        assertTrue(pool.isKnownTreeRoot(0, newRoot), "new root recorded in history");
    }

    // ========== Multi-entry batch ==========

    /// @dev A batch of two portal deposits credits both, advancing the count by two and feeding a maxSlots=2
    ///      public vector whose per-slot arrays carry both records' storage-derived values (distinct
    ///      counters 0 and 1, each record's net amount). The vm.expectCall pins the exact 2-slot vector;
    ///      deleting the per-entry loop or mis-indexing the arrays fails the match.
    function test_submitPortalDepositEpoch_multiEntryBatch() public {
        uint256 id0 = _sweep(100 ether);
        uint256 id1 = _sweep(250 ether);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: id0});
        entries[1] = PortalDepositEntry({portalDepositId: id1});
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        // Build the expected 2-slot vector from storage-derived values: both records bind the same E and H,
        // distinct counters (0, 1), their own net amounts (== gross at fee 0), and the supplied commitments.
        uint256[] memory portals = new uint256[](2);
        portals[0] = uint256(uint160(E));
        portals[1] = uint256(uint160(E));
        uint256[] memory counters = new uint256[](2);
        counters[0] = 0;
        counters[1] = 1;
        uint256[] memory hs = new uint256[](2);
        hs[0] = H;
        hs[1] = H;
        uint256[] memory tids = new uint256[](2);
        tids[0] = uint256(tokenId);
        tids[1] = uint256(tokenId);
        uint256[] memory nets = new uint256[](2);
        nets[0] = 100 ether;
        nets[1] = 250 ether;
        uint256[] memory expected = LibPublicInputs.buildPortalDepositInputs(
            block.chainid, address(pool), treeState, 2, portals, counters, hs, tids, nets, commitments
        );
        _expectVerifyCall(2, expected);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        assertTrue(pool.processedPortalDeposits(id0), "first record processed");
        assertTrue(pool.processedPortalDeposits(id1), "second record processed");
        assertEq(pool.treeCount(0), countOld + 2, "count advanced by two notes");
    }

    /// @dev Padded batch: ONE real escrowed record submitted in a 2-slot VK shape (commitments.length = 2 >
    ///      entries.length = 1). The contract sets maxSlots = commitments.length = 2 (the registered shape)
    ///      and nRequests = entries.length = 1, builds the per-slot public-input arrays at the shape with the
    ///      single active slot storage-derived and the trailing slot zero-padded, credits exactly ONE note,
    ///      and verifies against the maxSlots-keyed VK. This is the load-bearing multi-slot property — a
    ///      sub-full batch pads up to a registered shape instead of needing a portal VK for every survivor
    ///      count. Looping 0..maxSlots instead of 0..nRequests would read past the entries array or credit a
    ///      phantom zero note and fail here.
    function test_submitPortalDepositEpoch_paddedBatch_creditsActiveSlotsOnly() public {
        uint96 amount = 1000 ether;
        uint256 id = _sweep(amount);

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        uint256 commitment = 0xC0FFEE;
        // Only nRequests = 1 note is appended, so countNew advances by one even though the VK shape is 2.
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false);

        // entries.length = 1 (active) with commitments.length = 2 (the padded shape): the trailing slot is
        // zero across every per-slot array (Solidity zero-inits the unset index 1).
        PortalDepositEntry[] memory entries = _singleEntry(id);
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = commitment;

        uint256[] memory portals = new uint256[](2);
        portals[0] = uint256(uint160(E));
        uint256[] memory counters = new uint256[](2);
        uint256[] memory hs = new uint256[](2);
        hs[0] = H;
        uint256[] memory tids = new uint256[](2);
        tids[0] = uint256(tokenId);
        uint256[] memory nets = new uint256[](2);
        nets[0] = uint256(amount);
        uint256[] memory commitmentsOut = new uint256[](2);
        commitmentsOut[0] = commitment;
        uint256[] memory expected = LibPublicInputs.buildPortalDepositInputs(
            block.chainid, address(pool), treeState, 1, portals, counters, hs, tids, nets, commitmentsOut
        );
        // The VK is keyed by the padded shape maxSlots = commitments.length = 2.
        _expectVerifyCall(2, expected);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        assertTrue(pool.processedPortalDeposits(id), "the single active record is credited");
        assertEq(pool.treeCount(0), countOld + 1, "exactly one note appended despite the 2-slot shape");
    }

    // ========== Multi-entry fee aggregation (dedup + multi-token payout) ==========

    /// @dev Two records of the SAME token swept by the SAME keeper, each with a non-zero fee, settle in ONE
    ///      transfer of fee0+fee1 to that keeper, and the pool retains exactly net0+net1. This is the
    ///      load-bearing coverage for the _accrueFee dedup branch (`feeAmounts[j] += feeAmount`): breaking
    ///      the dedup so it appends a duplicate row (or mis-aggregates) would change the per-keeper total or
    ///      the number of transfers and fail these assertions. Value conservation across the batch: the pool
    ///      balance delta equals the total fee, never the gross.
    function test_submitPortalDepositEpoch_multiEntrySameToken_aggregatesFeeToOneSweeper() public {
        pool.setPortalSweepFeeBps(300);
        uint96 gross0 = 100 ether;
        uint96 gross1 = 250 ether;
        uint256 id0 = _sweepAs(keeper, gross0, token, tokenId);
        uint256 id1 = _sweepAs(keeper, gross1, token, tokenId);

        uint96 fee0 = uint96((uint256(gross0) * 300) / 10_000);
        uint96 fee1 = uint96((uint256(gross1) * 300) / 10_000);
        uint96 totalFee = fee0 + fee1;

        uint256 keeperBefore = token.balanceOf(keeper);
        uint256 poolBefore = token.balanceOf(address(pool));

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: id0});
        entries[1] = PortalDepositEntry({portalDepositId: id1});
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        // The two records aggregate into a SINGLE (keeper, token) fee transfer; assert exactly one transfer
        // of the summed fee — the dedup property. A duplicated/append-mutated dedup would either transfer
        // twice or transfer the wrong total.
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper, totalFee), 1);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        assertEq(token.balanceOf(keeper) - keeperBefore, totalFee, "keeper receives fee0+fee1 in aggregate");
        assertEq(poolBefore - token.balanceOf(address(pool)), totalFee, "pool delta == total fee, never gross");
    }

    /// @dev Eleven maximum-size records at the maximum fee produce a valid aggregate fee above uint96.max.
    ///      Individual records remain uint96-packed; only the in-memory payout accumulator must be wider.
    function test_submitPortalDepositEpoch_elevenMaxAmountFees_aggregatesAboveUint96() public {
        // Arrange
        uint32 n = 11;
        uint16 feeBps = 1_000;
        uint96 gross = type(uint96).max;
        pool.setPortalSweepFeeBps(feeBps);
        (PortalDepositEntry[] memory entries, uint256[] memory commitments) = _samePairBatch(n, gross);

        uint256 feePerRecord = (uint256(gross) * feeBps) / 10_000;
        uint256 totalFee = feePerRecord * n;
        uint256 totalGross = uint256(gross) * n;
        assertGt(totalFee, type(uint96).max, "regression setup must exceed uint96");

        uint256 keeperBefore = token.balanceOf(keeper);
        uint256 poolBefore = token.balanceOf(address(pool));
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(_getUsedRoots(0), 0, countOld, 0xABCD, countOld + n, false);
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper, totalFee), 1);

        // Act
        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        // Assert
        assertEq(poolBefore, totalGross, "pool receives every gross record");
        assertEq(token.balanceOf(keeper) - keeperBefore, totalFee, "keeper receives the uint256 aggregate");
        assertEq(token.balanceOf(address(pool)), totalGross - totalFee, "pool retains the aggregate net");
    }

    /// @dev At 32 maximum-size records, 312 bps still fits uint96 while 313 bps is the first whole-bps fee
    ///      whose aggregate exceeds it. The supported portal_s32 shape must settle the 313 bps batch.
    function test_submitPortalDepositEpoch_fullBatch32_aggregatesFeeAtUint96Boundary() public {
        // Arrange
        uint32 n = 32;
        uint16 feeBps = 313;
        uint96 gross = type(uint96).max;
        uint256 feePerRecordAt312 = (uint256(gross) * 312) / 10_000;
        uint256 feePerRecord = (uint256(gross) * feeBps) / 10_000;
        uint256 totalFeeAt312 = feePerRecordAt312 * n;
        uint256 totalFee = feePerRecord * n;
        assertLe(totalFeeAt312, type(uint96).max, "312 bps must fit uint96");
        assertGt(totalFee, type(uint96).max, "313 bps must exceed uint96");

        pool.setPortalSweepFeeBps(feeBps);
        (PortalDepositEntry[] memory entries, uint256[] memory commitments) = _samePairBatch(n, gross);
        uint256 totalGross = uint256(gross) * n;
        uint256 keeperBefore = token.balanceOf(keeper);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(_getUsedRoots(0), 0, countOld, 0xDCBA, countOld + n, false);
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper, totalFee), 1);

        // Act
        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        // Assert
        assertEq(token.balanceOf(keeper) - keeperBefore, totalFee, "keeper receives the boundary aggregate");
        assertEq(token.balanceOf(address(pool)), totalGross - totalFee, "pool retains every record's net");
    }

    /// @dev Two records of TWO DIFFERENT tokens (same keeper) settle as two independent payouts — one per
    ///      token — exercising the multi-token payout loop (feePairCount == 2). Each token's fee leaves the
    ///      pool to the keeper independently; collapsing the per-token loop or keying only on the sweeper
    ///      (ignoring tokenId) would mis-pay one of the two tokens.
    function test_submitPortalDepositEpoch_multiEntryTwoTokens_paysEachIndependently() public {
        pool.setPortalSweepFeeBps(300);
        uint96 grossA = 100 ether;
        uint96 grossB = 80 ether;
        uint256 idA = _sweepAs(keeper, grossA, token, tokenId); // token
        uint256 idB = _sweepAs(keeper, grossB, token2, tokenId2); // token2

        uint96 feeA = uint96((uint256(grossA) * 300) / 10_000);
        uint96 feeB = uint96((uint256(grossB) * 300) / 10_000);

        uint256 keeperABefore = token.balanceOf(keeper);
        uint256 keeperBBefore = token2.balanceOf(keeper);
        uint256 poolABefore = token.balanceOf(address(pool));
        uint256 poolBBefore = token2.balanceOf(address(pool));

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: idA});
        entries[1] = PortalDepositEntry({portalDepositId: idB});
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        // Each token pays its own fee exactly once — independent payout-loop iterations.
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper, feeA), 1);
        vm.expectCall(address(token2), abi.encodeWithSelector(IERC20.transfer.selector, keeper, feeB), 1);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        assertEq(token.balanceOf(keeper) - keeperABefore, feeA, "token A fee paid to keeper");
        assertEq(token2.balanceOf(keeper) - keeperBBefore, feeB, "token B fee paid to keeper");
        assertEq(poolABefore - token.balanceOf(address(pool)), feeA, "pool token A delta == feeA");
        assertEq(poolBBefore - token2.balanceOf(address(pool)), feeB, "pool token B delta == feeB");
    }

    /// @dev Two records of the SAME token swept by TWO DIFFERENT keepers settle as two payouts — one per
    ///      sweeper — proving the fee routes per (sweeper, token) pair, not per token. Keying the dedup on
    ///      tokenId alone would aggregate both into one payout to whichever keeper appeared first and starve
    ///      the other; this is the per-sweeper-incentive property the sweeper field exists for.
    function test_submitPortalDepositEpoch_multiEntrySameTokenTwoSweepers_paysEachSweeper() public {
        pool.setPortalSweepFeeBps(300);
        uint96 gross0 = 100 ether;
        uint96 gross1 = 250 ether;
        uint256 id0 = _sweepAs(keeper, gross0, token, tokenId); // swept by keeper
        uint256 id1 = _sweepAs(keeper2, gross1, token, tokenId); // swept by keeper2

        uint96 fee0 = uint96((uint256(gross0) * 300) / 10_000);
        uint96 fee1 = uint96((uint256(gross1) * 300) / 10_000);

        uint256 keeperBefore = token.balanceOf(keeper);
        uint256 keeper2Before = token.balanceOf(keeper2);
        uint256 poolBefore = token.balanceOf(address(pool));

        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: id0});
        entries[1] = PortalDepositEntry({portalDepositId: id1});
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        // Each keeper is paid its OWN record's fee — never the other's, never aggregated.
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper, fee0), 1);
        vm.expectCall(address(token), abi.encodeWithSelector(IERC20.transfer.selector, keeper2, fee1), 1);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        assertEq(token.balanceOf(keeper) - keeperBefore, fee0, "keeper paid only its own sweep's fee");
        assertEq(token.balanceOf(keeper2) - keeper2Before, fee1, "keeper2 paid only its own sweep's fee");
        assertEq(poolBefore - token.balanceOf(address(pool)), fee0 + fee1, "pool delta == fee0+fee1 total");
    }

    /// @dev A token-level recipient restriction on one sweeper must not block the portal epoch or the other
    ///      sweeper's fee. Both records are credited and the failed fee remains backed by the pool balance.
    function test_submitPortalDepositEpoch_blockedSweeperDefersFeeAndContinues() public {
        // Arrange
        RecipientBlockingToken restrictedToken = new RecipientBlockingToken();
        uint16 restrictedTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(restrictedToken), 0);
        pool.setPortalSweepFeeBps(300);

        uint96 gross0 = 100 ether;
        uint96 gross1 = 250 ether;
        uint256 id0 = _sweepAs(keeper, gross0, restrictedToken, restrictedTokenId);
        uint256 id1 = _sweepAs(keeper2, gross1, restrictedToken, restrictedTokenId);
        restrictedToken.setRecipientBlocked(keeper2, true);

        uint96 fee0 = uint96((uint256(gross0) * 300) / 10_000);
        uint96 fee1 = uint96((uint256(gross1) * 300) / 10_000);
        uint256 keeperBefore = restrictedToken.balanceOf(keeper);
        uint256 keeper2Before = restrictedToken.balanceOf(keeper2);
        uint256 poolBefore = restrictedToken.balanceOf(address(pool));
        uint32 countOld = pool.treeCount(0);
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(_getUsedRoots(0), 0, countOld, 0xABCD, countOld + 2, false);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: id0});
        entries[1] = PortalDepositEntry({portalDepositId: id1});
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        // Act
        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.PortalSweepFeeDeferred(keeper2, restrictedTokenId, fee1);
        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        // Assert
        assertTrue(pool.processedPortalDeposits(id0), "allowed sweeper record credited");
        assertTrue(pool.processedPortalDeposits(id1), "blocked sweeper record credited");
        assertEq(pool.treeRoot(0), 0xABCD, "tree root advances");
        assertEq(pool.treeCount(0), countOld + 2, "both notes appended");
        assertEq(restrictedToken.balanceOf(keeper) - keeperBefore, fee0, "allowed sweeper paid immediately");
        assertEq(restrictedToken.balanceOf(keeper2), keeper2Before, "blocked sweeper not paid");
        assertEq(pool.claimablePortalSweepFees(keeper2, restrictedTokenId), fee1, "failed fee is deferred");
        assertEq(poolBefore - restrictedToken.balanceOf(address(pool)), fee0, "only successful fee leaves pool");
    }

    function test_claimPortalSweepFee_revertWhen_stillBlockedPreservesLiability() public {
        // Arrange - create a deferred fee that the token still refuses to pay
        (RecipientBlockingToken restrictedToken, uint16 restrictedTokenId, uint96 fee) = _deferBlockedSweeperFee();
        uint256 poolBefore = restrictedToken.balanceOf(address(pool));
        uint256 keeperBefore = restrictedToken.balanceOf(keeper2);

        // Act - retry the same recipient while its restriction remains active
        vm.expectRevert(abi.encodeWithSelector(RecipientBlockingToken.RecipientBlocked.selector, keeper2));
        vm.prank(keeper2);
        pool.claimPortalSweepFee(restrictedTokenId);

        // Assert - the failed claim rolls back its effects and preserves the full liability
        assertEq(pool.claimablePortalSweepFees(keeper2, restrictedTokenId), fee, "failed claim keeps liability");
        assertEq(restrictedToken.balanceOf(address(pool)), poolBefore, "pool still backs deferred fee");
        assertEq(restrictedToken.balanceOf(keeper2), keeperBefore, "blocked sweeper remains unpaid");
    }

    function test_claimPortalSweepFee_unblockedSweeperReceivesAndClearsLiability() public {
        // Arrange - create a deferred fee and remove the recipient restriction
        (RecipientBlockingToken restrictedToken, uint16 restrictedTokenId, uint96 fee) = _deferBlockedSweeperFee();
        restrictedToken.setRecipientBlocked(keeper2, false);
        uint256 poolBefore = restrictedToken.balanceOf(address(pool));
        uint256 keeperBefore = restrictedToken.balanceOf(keeper2);

        // Act - claim to the fixed original sweeper address
        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.PortalSweepFeeClaimed(keeper2, restrictedTokenId, fee);
        vm.prank(keeper2);
        pool.claimPortalSweepFee(restrictedTokenId);

        // Assert - the liability is paid exactly once and cleared
        assertEq(restrictedToken.balanceOf(keeper2) - keeperBefore, fee, "unblocked sweeper claims full fee");
        assertEq(pool.claimablePortalSweepFees(keeper2, restrictedTokenId), 0, "successful claim clears liability");
        assertEq(poolBefore - restrictedToken.balanceOf(address(pool)), fee, "claim transfers only deferred fee");
    }

    function test_claimPortalSweepFee_revertWhen_alreadyClaimed() public {
        // Arrange - claim a deferred fee successfully once
        (RecipientBlockingToken restrictedToken, uint16 restrictedTokenId,) = _deferBlockedSweeperFee();
        restrictedToken.setRecipientBlocked(keeper2, false);
        vm.prank(keeper2);
        pool.claimPortalSweepFee(restrictedTokenId);
        uint256 keeperBefore = restrictedToken.balanceOf(keeper2);

        // Act - attempt to replay the cleared claim
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyBoost.NoDeferredPortalSweepFee.selector, keeper2, restrictedTokenId)
        );
        vm.prank(keeper2);
        pool.claimPortalSweepFee(restrictedTokenId);

        // Assert - no second payment occurs
        assertEq(pool.claimablePortalSweepFees(keeper2, restrictedTokenId), 0, "liability remains cleared");
        assertEq(restrictedToken.balanceOf(keeper2), keeperBefore, "replay pays nothing");
    }

    /// @dev The isolated payment target cannot be used by an external caller to move pool funds.
    function test_payPortalSweepFee_revertWhen_calledExternally() public {
        // Arrange - record balances before an unauthorized helper call
        uint256 poolBefore = token.balanceOf(address(pool));
        uint256 keeperBefore = token.balanceOf(keeper);

        // Act - call the self-only payment target directly
        vm.expectRevert(IPrivacyBoost.PortalSweepFeePaymentOnlySelf.selector);
        pool.payPortalSweepFee(tokenId, keeper, 1 ether);

        // Assert - the guard prevents token movement
        assertEq(token.balanceOf(address(pool)), poolBefore, "pool balance unchanged");
        assertEq(token.balanceOf(keeper), keeperBefore, "caller cannot pay a recipient");
    }

    // ========== Double-credit / processed guard ==========

    /// @dev Re-submitting an already-credited id reverts (PortalDepositAlreadyProcessed) — no double-credit.
    ///      Removing the processed guard would credit the same escrow twice. The counter/recipient "tamper"
    ///      defense reduces to this on-chain: a relay cannot replay a record once it is processed, and
    ///      cannot construct a NEW record (that requires an on-chain sweep). The cryptographic amount/
    ///      recipient binding is enforced by the real-proof FFI test.
    function test_submitPortalDepositEpoch_revertWhen_doubleSubmit() public {
        uint256 id = _sweep(500 ether);
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        vm.prank(relay);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );

        // Second submit of the same id reverts on the processed guard.
        usedRoots = _getUsedRoots(0);
        countOld = pool.treeCount(0);
        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.PortalDepositAlreadyProcessed.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xBEEF, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );
    }

    /// @dev The same id appearing TWICE in one batch reverts on the second pass (processed within the same
    ///      call). This blocks a relay padding a batch with a duplicate to mint two notes from one escrow.
    function test_submitPortalDepositEpoch_revertWhen_duplicateIdInBatch() public {
        uint256 id = _sweep(500 ether);
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2);
        entries[0] = PortalDepositEntry({portalDepositId: id});
        entries[1] = PortalDepositEntry({portalDepositId: id}); // duplicate
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.PortalDepositAlreadyProcessed.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 2, false),
            entries,
            commitments,
            dummyProof
        );
    }

    // ========== Existence guard ==========

    /// @dev An entry referencing a non-existent portalDepositId reverts (InvalidDeposit). A relay cannot
    ///      credit a note for a record that was never escrowed on-chain. Removing the existence guard would
    ///      let a fabricated id reach the verifier with a zero record (and zero binding).
    function test_submitPortalDepositEpoch_revertWhen_unknownId() public {
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            _singleEntry(999999),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );
    }

    // ========== Stale tree-state CAS ==========

    /// @dev A stale treeState (countOld moved by an interleaved epoch) reverts (InvalidEpochState). The
    ///      portal epoch shares the note tree and inherits the exact-match CAS; a racing epoch makes this
    ///      submission's countOld stale, so it reverts and the relay rebuilds. Removing the CAS check would
    ///      let a stale append corrupt the tree.
    function test_submitPortalDepositEpoch_revertWhen_staleTreeState() public {
        uint256 id = _sweep(500 ether);
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);

        // countOld is deliberately wrong (999 vs the real 0): simulates a concurrent epoch having advanced
        // the tree between this relay's read and submit.
        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, 999, 0xABCD, 1000, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );
    }

    /// @dev A wrong active root (not the current tree root) reverts (RootNotKnown), proving the active-root
    ///      half of the CAS. _validateKnownRoots rejects an unknown root before the activeRoot equality
    ///      check is reached.
    function test_submitPortalDepositEpoch_revertWhen_unknownRoot() public {
        uint256 id = _sweep(500 ether);
        uint32 countOld = pool.treeCount(0);

        TreeRootPair[] memory usedRoots = new TreeRootPair[](1);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: 0xBADBAD}); // not the current root

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.RootNotKnown.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );
    }

    // ========== Access control ==========

    /// @dev Only an allowed relay may submit a portal epoch; a non-relay reverts (NotAllowedRelay). The
    ///      credit path is relay-gated exactly like submitDepositEpoch. Removing onlyRelay opens crediting
    ///      to anyone.
    function test_submitPortalDepositEpoch_revertWhen_notRelay() public {
        uint256 id = _sweep(500 ether);
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        vm.prank(keeper); // not a relay
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            _singleEntry(id),
            _singleCommitment(0xC0FFEE),
            dummyProof
        );
    }

    // ========== Config guards ==========

    /// @dev An empty batch reverts (InvalidEpochConfig). An epoch with no entries has nothing to credit and
    ///      a zero maxSlots would have no registered VK.
    function test_submitPortalDepositEpoch_revertWhen_emptyBatch() public {
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](0);
        uint256[] memory commitments = new uint256[](0);

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            entries,
            commitments,
            dummyProof
        );
    }

    /// @dev More active entries than commitment slots (entries.length > commitments.length) reverts
    ///      (InvalidEpochConfig): the active count nRequests must be <= the padded VK shape
    ///      maxSlots = commitments.length. The reverse (fewer entries than slots) is the valid padded batch,
    ///      covered by test_submitPortalDepositEpoch_paddedBatch_creditsActiveSlotsOnly. The guard fires
    ///      before any storage read, so dummy ids suffice.
    function test_submitPortalDepositEpoch_revertWhen_moreEntriesThanShape() public {
        TreeRootPair[] memory usedRoots = _getUsedRoots(0);
        uint32 countOld = pool.treeCount(0);

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](2); // nRequests = 2
        entries[0] = PortalDepositEntry({portalDepositId: 1});
        entries[1] = PortalDepositEntry({portalDepositId: 2});
        uint256[] memory commitments = new uint256[](1); // maxSlots = 1 < nRequests
        commitments[0] = 1;

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitPortalDepositEpoch(
            EpochHelpers.buildTreeState(usedRoots, 0, countOld, 0xABCD, countOld + 1, false),
            entries,
            commitments,
            dummyProof
        );
    }

    // ========== Public-input layout parity ==========

    /// @dev buildPortalDepositInputs must mirror the circuit's public-witness order index-for-index. Pin
    ///      the scalar-prefix and per-slot-tail positions directly on the built vector (chainId at 0, pool
    ///      at 1, the tree-state block at its fixed offsets, then E/counter/H/tokenId/amount/commitment) so
    ///      a reorder of the Solidity builder is caught here, complementing the Go parity test. The full
    ///      cryptographic round-trip against a real proof is the FFI test's job; this locks the layout.
    function test_buildPortalDepositInputs_layoutPrefixPositions() public view {
        EpochTreeState memory treeState =
            EpochHelpers.buildTreeState(EpochHelpers.buildUsedRoots(0, 0x1111), 0, 7, 0xFEEDFACE, 8, false);
        uint256 net = 7 ether;
        uint256 commitment = 0xABCDEF;
        uint256 counter = 3;
        uint256[] memory v = _expectedInputs(treeState, counter, net, commitment);

        // Scalar prefix: chainId, pool, then knownRoots(16), packedTreeNumbers, activeTree, countOld,
        // rootNew, countNew, rollover, nRequests.
        assertEq(v[0], block.chainid, "slot 0 == chainId");
        assertEq(v[1], uint256(uint160(address(pool))), "slot 1 == pool address");
        uint256 base = MAX_NOTE_ROOTS_PER_PROOF + 2; // skip chainId, pool, 16 roots → packedTreeNumbers
        assertEq(v[base + 1], uint256(0), "activeTree slot");
        assertEq(v[base + 2], uint256(7), "countOld slot");
        assertEq(v[base + 3], 0xFEEDFACE, "rootNew slot");
        assertEq(v[base + 4], uint256(8), "countNew slot");
        assertEq(v[base + 5], uint256(0), "rollover slot == 0");
        assertEq(v[base + 6], uint256(1), "nRequests slot == 1");

        // Per-slot tail for maxSlots=1: E, counter, H, tokenId, amount, commitment at the last 6 indices.
        uint256 tail = MAX_NOTE_ROOTS_PER_PROOF + 9; // first per-slot index (E)
        assertEq(v[tail], uint256(uint160(E)), "E slot");
        assertEq(v[tail + 1], counter, "counter slot");
        assertEq(v[tail + 2], H, "H slot");
        assertEq(v[tail + 3], uint256(tokenId), "tokenId slot");
        assertEq(v[tail + 4], net, "amount slot == net credited");
        assertEq(v[tail + 5], commitment, "commitment slot");
    }
}
