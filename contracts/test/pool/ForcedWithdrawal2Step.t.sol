// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {Withdrawal, TreeRootPair} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";

import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

contract ForcedWithdrawal2StepTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockERC20 token;

    address constant PROXY_ADMIN = address(0xAD);
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address keeper = makeAddr("keeper");
    address treasury = makeAddr("treasury");

    uint16 tokenId;
    uint256 accountId;
    bytes32 authId;
    uint256 approvalBatchRoot;
    uint64 authExpiry;
    uint256 noteRoot;

    uint96 constant AMOUNT = 1000 ether;
    uint16 constant FEE_BPS = 200;
    uint256 constant APPROVAL_COMMITMENT = 123456789;
    bytes32 private constant REQUEST_KEY_DOMAIN = keccak256("PB:FORCED_REQUEST_KEY:SNAPSHOT:v1");

    function setUp() public {
        MockVerifier verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(address(this), PROXY_ADMIN, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        token.mint(address(pool), 100_000 ether);
        noteRoot = pool.treeRoot(0);

        vm.prank(alice);
        accountId = authRegistry.createAccount(123);
        authExpiry = uint64(block.timestamp + 1 days);
        vm.prank(alice);
        authRegistry.approveSpend(accountId, APPROVAL_COMMITMENT, authExpiry);

        uint256[] memory batch = new uint256[](1);
        batch[0] = APPROVAL_COMMITMENT;
        approvalBatchRoot = authRegistry.computeSpendApprovalBatchRoot(batch);
        authId = authRegistry.computeSpendApprovalBatchId(accountId, approvalBatchRoot);
    }

    function _authContext() internal view returns (uint128) {
        return uint128(authExpiry) | (uint128(1) << 64) | (uint128(1) << 100);
    }

    function _authContext(uint64 expiry, uint8 mode, uint32 leafIndex, uint16 treeNumber)
        internal
        pure
        returns (uint128)
    {
        return uint128(expiry) | (uint128(mode) << 64) | (uint128(leafIndex) << 65) | (uint128(treeNumber) << 85)
            | (uint128(1) << 100);
    }

    function _roots() internal view returns (TreeRootPair[] memory roots) {
        roots = EpochHelpers.buildUsedRoots(0, noteRoot);
    }

    function _arrays(uint256 nullifier, uint256 commitment)
        internal
        pure
        returns (uint256[] memory nullifiers, uint256[] memory commitments)
    {
        nullifiers = new uint256[](1);
        commitments = new uint256[](1);
        nullifiers[0] = nullifier;
        commitments[0] = commitment;
    }

    function _request(address submitter, uint256[] memory nullifiers, uint256[] memory commitments) internal {
        _requestWithAuthorization(submitter, accountId, _authContext(), authId, nullifiers, commitments);
    }

    function _requestWithAuthorization(
        address submitter,
        uint256 requestAccountId,
        uint128 requestAuthContext,
        bytes32 requestAuthId,
        uint256[] memory nullifiers,
        uint256[] memory commitments
    ) internal {
        TreeRootPair[] memory forcedAuthData = new TreeRootPair[](1);
        forcedAuthData[0] = TreeRootPair({treeNumber: requestAuthContext, root: uint256(requestAuthId)});
        vm.prank(submitter);
        pool.requestForcedWithdrawal(
            _roots(),
            forcedAuthData,
            requestAccountId,
            nullifiers,
            commitments,
            Withdrawal({to: alice, tokenId: tokenId, amount: AMOUNT}),
            EpochHelpers.dummyProof()
        );
    }

    function _requestKey(uint256[] memory nullifiers, uint256[] memory commitments) internal pure returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    REQUEST_KEY_DOMAIN,
                    keccak256(abi.encodePacked(nullifiers)),
                    keccak256(abi.encodePacked(commitments))
                )
            )
        );
    }

    function _legacyRequestKey(address requester, uint256[] memory commitments) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(requester, keccak256(abi.encodePacked(commitments)))));
    }

    function _storeLegacyRequest(
        address requester,
        uint256[] memory nullifiers,
        uint256[] memory commitments,
        uint16 feeBps
    ) internal returns (uint256 requestKey) {
        requestKey = _legacyRequestKey(requester, commitments);
        bytes32 requestBase = keccak256(abi.encode(requestKey, uint256(16)));

        vm.store(address(pool), requestBase, bytes32(uint256(block.number) | (uint256(uint160(requester)) << 64)));
        vm.store(
            address(pool),
            bytes32(uint256(requestBase) + 1),
            bytes32(uint256(uint160(alice)) | (uint256(tokenId) << 160))
        );
        vm.store(
            address(pool),
            bytes32(uint256(requestBase) + 2),
            bytes32(uint256(AMOUNT) | (uint256(feeBps) << 96) | (uint256(1) << 112))
        );
        vm.store(address(pool), bytes32(uint256(requestBase) + 3), bytes32(accountId));
        vm.store(address(pool), bytes32(uint256(requestBase) + 4), keccak256(abi.encodePacked(nullifiers)));
        vm.store(address(pool), bytes32(uint256(requestBase) + 5), keccak256(abi.encodePacked(commitments)));
        bytes32 commitmentSlot = keccak256(abi.encode(commitments[0], uint256(17)));
        vm.store(address(pool), commitmentSlot, bytes32(requestKey));
    }

    function test_authContextMatchesCrossLanguageGoldenVector() public pure {
        assertEq(_authContext(0x0102030405060708, 1, 0xabcde, 0x1234), uint128(0x12469579bd0102030405060708));
    }

    function test_requestUsesLayoutFrozenRecordWithoutGivingRelayerAuthority() public {
        pool.setTreasury(treasury);
        pool.setFees(FEE_BPS);
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(11, 101);

        _request(bob, nullifiers, commitments);

        uint256 key = _requestKey(nullifiers, commitments);
        (
            uint64 requestBlock,
            address requester,
            address withdrawalTo,
            uint16 storedTokenId,
            uint96 amount,
            uint16 storedFeeBps,
            uint8 inputCount,
            uint256 storedAccountId,
            bytes32 nullifiersHash,
            bytes32 commitmentsHash
        ) = pool.forcedWithdrawalRequests(key);
        assertEq(requestBlock, block.number);
        assertEq(requester, address(0));
        assertEq(withdrawalTo, alice);
        assertEq(storedTokenId, tokenId);
        assertEq(amount, AMOUNT);
        assertEq(storedFeeBps, FEE_BPS);
        assertEq(inputCount, 1);
        assertEq(storedAccountId, accountId);
        assertEq(nullifiersHash, keccak256(abi.encodePacked(nullifiers)));
        assertEq(commitmentsHash, keccak256(abi.encodePacked(commitments)));
        assertEq(pool.commitmentToRequestKey(commitments[0]), key);

        vm.prank(bob);
        vm.expectRevert(IPrivacyBoost.NotAccountOwner.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
    }

    function test_requestRejectsRevokedAuthorization() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(12, 102);
        vm.prank(alice);
        authRegistry.revokeSpendApprovalBatch(accountId, approvalBatchRoot);

        vm.expectRevert(IPrivacyBoost.ForcedAuthorizationInvalid.selector);
        _request(bob, nullifiers, commitments);
    }

    function test_requestRejectsAuthorizationAtDifferentLeafIndex() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(13, 103);
        uint128 wrongIndexContext = _authContext() | (uint128(1) << 65);

        vm.expectRevert(IPrivacyBoost.ForcedAuthorizationInvalid.selector);
        _requestWithAuthorization(bob, accountId, wrongIndexContext, authId, nullifiers, commitments);
    }

    function test_requestRejectsAuthorizationAtDifferentTreeNumber() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(13, 103);
        uint128 wrongTreeContext = _authContext() | (uint128(1) << 85);

        vm.expectRevert(IPrivacyBoost.ForcedAuthorizationInvalid.selector);
        _requestWithAuthorization(bob, accountId, wrongTreeContext, authId, nullifiers, commitments);
    }

    function test_requestRejectsExpiredAuthorization() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(14, 104);
        vm.warp(uint256(authExpiry) + 1);

        vm.expectRevert(IPrivacyBoost.ForcedAuthorizationExpired.selector);
        _request(bob, nullifiers, commitments);
    }

    function test_requestRejectsNonCanonicalContext() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(15, 105);
        uint128 badContext = _authContext() | (uint128(1) << 108);

        vm.expectRevert(IPrivacyBoost.InvalidForcedAuthContext.selector);
        _requestWithAuthorization(bob, accountId, badContext, authId, nullifiers, commitments);
    }

    function test_requestRejectsDuplicateAndZeroInputs() public {
        uint256[] memory nullifiers = new uint256[](2);
        uint256[] memory commitments = new uint256[](2);
        nullifiers[0] = 16;
        nullifiers[1] = 16;
        commitments[0] = 106;
        commitments[1] = 107;

        vm.expectRevert(IPrivacyBoost.DuplicateNullifier.selector);
        _request(bob, nullifiers, commitments);

        nullifiers[1] = 17;
        commitments[1] = commitments[0];
        vm.expectRevert(IPrivacyBoost.DuplicateInputCommitment.selector);
        _request(bob, nullifiers, commitments);

        (nullifiers, commitments) = _arrays(18, 0);
        vm.expectRevert(IPrivacyBoost.InvalidSlotPadding.selector);
        _request(bob, nullifiers, commitments);
    }

    function test_executeUsesSnapshotAfterDelayDespiteFeeAndAuthChanges() public {
        pool.setTreasury(treasury);
        pool.setFees(FEE_BPS);
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(19, 109);
        _request(bob, nullifiers, commitments);

        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalTooEarly.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        vm.prank(alice);
        authRegistry.revokeSpendApprovalBatch(accountId, approvalBatchRoot);
        pool.setFees(500);
        vm.warp(uint256(authExpiry) + 1);
        vm.roll(block.number + pool.forcedWithdrawalDelay());
        pool.executeForcedWithdrawal(nullifiers, commitments);

        assertTrue(pool.nullifierSpent(nullifiers[0]));
        assertEq(token.balanceOf(alice), 980 ether);
        assertEq(token.balanceOf(treasury), 20 ether);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    function test_executePaysGrossWhenTreasuryUnset() public {
        // Arrange
        pool.setTreasury(treasury);
        pool.setFees(FEE_BPS);
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(26, 116);
        _request(bob, nullifiers, commitments);
        uint256 requestKey = _requestKey(nullifiers, commitments);
        uint256 poolBalanceBefore = token.balanceOf(address(pool));

        pool.setFees(0);
        pool.setTreasury(address(0));
        vm.roll(block.number + pool.forcedWithdrawalDelay());

        // Act
        vm.expectEmit(true, false, false, true, address(pool));
        emit IPrivacyBoost.ForcedWithdrawalExecuted(alice, tokenId, AMOUNT, nullifiers, commitments);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Assert
        assertTrue(pool.nullifierSpent(nullifiers[0]));
        assertEq(token.balanceOf(alice), AMOUNT);
        assertEq(token.balanceOf(treasury), 0);
        assertEq(poolBalanceBefore - token.balanceOf(address(pool)), AMOUNT);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);
    }

    function test_executeRejectsMismatchedNullifiers() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(20, 110);
        _request(bob, nullifiers, commitments);
        vm.roll(block.number + pool.forcedWithdrawalDelay());

        nullifiers[0] += 1;
        vm.expectRevert(IPrivacyBoost.ForcedWithdrawalMismatch.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);
    }

    function test_accountOwnerCanCancelImmediately() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(21, 111);
        _request(bob, nullifiers, commitments);

        vm.prank(alice);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    function test_revokeThenCancelPreventsProofResubmission() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(25, 115);
        _request(bob, nullifiers, commitments);

        vm.startPrank(alice);
        authRegistry.revokeSpendApprovalBatch(accountId, approvalBatchRoot);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
        vm.stopPrank();

        vm.expectRevert(IPrivacyBoost.ForcedAuthorizationInvalid.selector);
        _request(bob, nullifiers, commitments);
    }

    function test_unrelatedCallerCanOnlyPruneAfterCompetingSpend() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(22, 112);
        _request(bob, nullifiers, commitments);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.NotAccountOwner.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);

        bytes32 nullifierSlot = keccak256(abi.encode(nullifiers[0], uint256(11)));
        vm.store(address(pool), nullifierSlot, bytes32(uint256(1)));
        vm.prank(keeper);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    function test_legacyPendingRequestRemainsExecutable() public {
        pool.setTreasury(treasury);
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(23, 113);
        uint256 requestKey = _storeLegacyRequest(bob, nullifiers, commitments, FEE_BPS);

        vm.roll(block.number + pool.forcedWithdrawalDelay());
        vm.prank(keeper);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        assertTrue(pool.nullifierSpent(nullifiers[0]));
        assertEq(token.balanceOf(alice), 980 ether);
        assertEq(token.balanceOf(treasury), 20 ether);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);
    }

    function test_legacyPendingRequestPaysGrossWhenTreasuryUnset() public {
        // Arrange
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(27, 117);
        uint256 requestKey = _storeLegacyRequest(bob, nullifiers, commitments, FEE_BPS);
        uint256 poolBalanceBefore = token.balanceOf(address(pool));
        vm.roll(block.number + pool.forcedWithdrawalDelay());

        // Act
        vm.expectEmit(true, false, false, true, address(pool));
        emit IPrivacyBoost.ForcedWithdrawalExecuted(alice, tokenId, AMOUNT, nullifiers, commitments);
        pool.executeForcedWithdrawal(nullifiers, commitments);

        // Assert
        assertTrue(pool.nullifierSpent(nullifiers[0]));
        assertEq(token.balanceOf(alice), AMOUNT);
        assertEq(poolBalanceBefore - token.balanceOf(address(pool)), AMOUNT);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);
    }

    function test_legacyRequesterCannotCancelButOwnerCan() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _arrays(24, 114);
        _storeLegacyRequest(bob, nullifiers, commitments, 0);

        vm.prank(bob);
        vm.expectRevert(IPrivacyBoost.NotAccountOwner.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);

        vm.prank(alice);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
        assertEq(pool.commitmentToRequestKey(commitments[0]), 0);
    }

    /// @dev Builds `pool.maxForcedInputs() + 1` distinct, non-zero nullifiers and commitments from a seed,
    ///      so the resulting request's input count always exceeds the current bound.
    function _oversizedArrays(uint256 seed)
        internal
        view
        returns (uint256[] memory nullifiers, uint256[] memory commitments)
    {
        uint256 count = uint256(pool.maxForcedInputs()) + 1;
        nullifiers = new uint256[](count);
        commitments = new uint256[](count);
        for (uint256 i = 0; i < count; ++i) {
            nullifiers[i] = seed + i;
            commitments[i] = seed + 1000 + i;
        }
    }

    /// @dev Stores a snapshot-format forced-withdrawal request with `commitments.length` inputs directly in
    ///      the pool, mirroring the record {LibForced} writes. Stages the state a maxForcedInputs downgrade
    ///      (an upgrade to an implementation with a smaller bound) leaves behind for a request that was
    ///      accepted while the bound was higher.
    function _storeOversizedRequest(uint256[] memory nullifiers, uint256[] memory commitments, uint16 feeBps)
        internal
        returns (uint256 requestKey)
    {
        requestKey = _requestKey(nullifiers, commitments);
        bytes32 requestBase = keccak256(abi.encode(requestKey, uint256(16)));

        // requester is address(0) for snapshot-format records: the relayer is never a cancellation principal.
        vm.store(address(pool), requestBase, bytes32(uint256(block.number)));
        vm.store(
            address(pool),
            bytes32(uint256(requestBase) + 1),
            bytes32(uint256(uint160(alice)) | (uint256(tokenId) << 160))
        );
        vm.store(
            address(pool),
            bytes32(uint256(requestBase) + 2),
            bytes32(uint256(AMOUNT) | (uint256(feeBps) << 96) | (uint256(commitments.length) << 112))
        );
        vm.store(address(pool), bytes32(uint256(requestBase) + 3), bytes32(accountId));
        vm.store(address(pool), bytes32(uint256(requestBase) + 4), keccak256(abi.encodePacked(nullifiers)));
        vm.store(address(pool), bytes32(uint256(requestBase) + 5), keccak256(abi.encodePacked(commitments)));
        for (uint256 i = 0; i < commitments.length; ++i) {
            vm.store(address(pool), keccak256(abi.encode(commitments[i], uint256(17))), bytes32(requestKey));
        }
    }

    /// @dev Regression: a request whose input count exceeds the CURRENT maxForcedInputs, left behind when a
    ///      later implementation lowers the bound, must stay cancellable by the account owner. Before the
    ///      cancel/prune carve-out this reverted InvalidEpochConfig and locked the commitments permanently.
    function test_ownerCancelsOversizedRequestAfterMaxInputsDowngrade() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _oversizedArrays(30);
        assertGt(nullifiers.length, pool.maxForcedInputs());
        uint256 requestKey = _storeOversizedRequest(nullifiers, commitments, FEE_BPS);

        vm.prank(alice);
        pool.cancelForcedWithdrawal(nullifiers, commitments);

        for (uint256 i = 0; i < commitments.length; ++i) {
            assertEq(pool.commitmentToRequestKey(commitments[i]), 0);
        }
        (uint64 requestBlock,,,,,,,,,) = pool.forcedWithdrawalRequests(requestKey);
        assertEq(requestBlock, 0);
    }

    /// @dev Regression: pruning an oversized request after a competing spend must also stay reachable, and
    ///      the carve-out must not weaken the authorization gate: a non-owner still cannot cancel until a
    ///      competing nullifier spend makes execution impossible.
    function test_prunesOversizedRequestAfterMaxInputsDowngrade() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _oversizedArrays(40);
        _storeOversizedRequest(nullifiers, commitments, FEE_BPS);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.NotAccountOwner.selector);
        pool.cancelForcedWithdrawal(nullifiers, commitments);

        vm.store(address(pool), keccak256(abi.encode(nullifiers[0], uint256(11))), bytes32(uint256(1)));
        vm.prank(keeper);
        pool.cancelForcedWithdrawal(nullifiers, commitments);
        for (uint256 i = 0; i < commitments.length; ++i) {
            assertEq(pool.commitmentToRequestKey(commitments[i]), 0);
        }
    }

    /// @dev The carve-out is cancel/prune only: execute still enforces maxForcedInputs, so an oversized
    ///      request cannot be executed after a downgrade. The owner cancels and re-requests within the bound.
    function test_executeStillRejectsOversizedRequestAfterMaxInputsDowngrade() public {
        (uint256[] memory nullifiers, uint256[] memory commitments) = _oversizedArrays(50);
        _storeOversizedRequest(nullifiers, commitments, FEE_BPS);

        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.executeForcedWithdrawal(nullifiers, commitments);
    }
}
