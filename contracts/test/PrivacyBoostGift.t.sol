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

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {Output, TreeRootPair, EpochTreeState} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

/// @notice Mock gift claim verifier that always returns true.
/// @dev Mirrors the real Groth16GiftClaimVerifier.verifyGiftClaim shape (single batchSize param). The real
///      verifying key is produced by a ceremony and is out of scope for these tests — the mock isolates the
///      contract's request/spend/append/exit logic from proof verification, the same way MockVerifier does
///      for the epoch/deposit/forced paths.
contract MockGiftClaimVerifier {
    function verifyGiftClaim(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function hasVerifyingKey(uint32) external pure returns (bool) {
        return true;
    }
}

/// @notice Sentinel verifier used to prove fee slippage is rejected before the pairing call.
contract RevertingGiftClaimVerifier {
    error VerifierReached();

    function verifyGiftClaim(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        revert VerifierReached();
    }

    function hasVerifyingKey(uint32) external pure returns (bool) {
        return true;
    }
}

contract PrivacyBoostGiftTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address alice = makeAddr("alice");
    address relay = makeAddr("relay");
    address operator = makeAddr("operator");

    uint16 tokenId;
    uint96 constant AMOUNT = 1000 ether;

    uint256 private constant AUTH_PK_X = 15836372343211832006828833031571087401945044377577570170285606102491215895900;
    uint256 private constant AUTH_PK_Y = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    uint256 private constant AUTH_PK_2_X = 6051870528627443215417572713686187686603320022838464173412598084084592599717;
    uint256 private constant AUTH_PK_2_Y = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("PB:AuthRegistry:vNext");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(uint256 accountId,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)");
    bytes32 private constant REVOKE_TYPEHASH =
        keccak256("Revoke(uint256 accountId,uint256 authPkX,uint64 expiry,uint256 nonce)");

    function setUp() public {
        verifier = new MockVerifier();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        // Fund the pool (simulating private gift funding).
        token.mint(address(pool), 100_000 ether);

        pool.setOperator(operator);

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    // ========== Helpers ==========

    function _makeOutput(uint256 commitment) internal pure returns (Output memory) {
        return EpochHelpers.makeOutput(commitment);
    }

    function _getAuthRoots() internal view returns (TreeRootPair[] memory) {
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: authRegistry.authTreeRoot(0)});
        return roots;
    }

    function _signAuthAction(uint256 privateKey, bytes32 structHash) private view returns (bytes memory) {
        bytes32 domainSeparator =
            keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(authRegistry)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerAuthKey()
        private
        returns (
            uint256 ownerPrivateKey,
            address accountOwner,
            uint256 accountId,
            uint64 expiry,
            uint256 leaf,
            uint256 root
        )
    {
        ownerPrivateKey = 0xA11CE;
        accountOwner = vm.addr(ownerPrivateKey);
        uint256 salt = 123;
        expiry = uint64(block.timestamp + 1 days);
        accountId = authRegistry.computeAccountId(accountOwner, salt);

        bytes memory registerSig = _signAuthAction(
            ownerPrivateKey,
            keccak256(abi.encode(REGISTER_TYPEHASH, accountId, AUTH_PK_X, AUTH_PK_Y, expiry, uint256(0)))
        );
        vm.prank(accountOwner);
        authRegistry.register(salt, AUTH_PK_X, AUTH_PK_Y, expiry, accountOwner, registerSig);
        leaf = authRegistry.computeLeaf(accountId, AUTH_PK_X, AUTH_PK_Y, expiry);
        root = authRegistry.authTreeRoot(0);
    }

    function _revokeAuthKey(uint256 ownerPrivateKey, address accountOwner, uint256 accountId, uint64 expiry) private {
        vm.roll(100);
        bytes memory revokeSig = _signAuthAction(
            ownerPrivateKey, keccak256(abi.encode(REVOKE_TYPEHASH, accountId, AUTH_PK_X, expiry, uint256(1)))
        );
        vm.prank(accountOwner);
        authRegistry.revoke(accountId, AUTH_PK_X, expiry, revokeSig);
    }

    function _addSecondAuthKey(uint256 ownerPrivateKey, address accountOwner, uint256 accountId, uint64 expiry)
        private
    {
        bytes memory registerSig = _signAuthAction(
            ownerPrivateKey,
            keccak256(abi.encode(REGISTER_TYPEHASH, accountId, AUTH_PK_2_X, AUTH_PK_2_Y, expiry, uint256(1)))
        );
        vm.prank(accountOwner);
        authRegistry.register(123, AUTH_PK_2_X, AUTH_PK_2_Y, expiry, accountOwner, registerSig);
    }

    function _publicGiftExitWithAuthRoot(
        uint256 authRoot,
        uint256 exitAuthLeaf,
        uint64 authLeafLocation,
        address destination,
        uint256 giftNullifier,
        bool expectInactiveLeaf
    ) private {
        TreeRootPair[] memory authRoots = new TreeRootPair[](1);
        authRoots[0] = TreeRootPair({treeNumber: 0, root: authRoot});
        uint256 treeNumber = pool.currentTreeNumber();
        uint256 noteRoot = pool.treeRoot(treeNumber);
        uint32 treeCount = pool.treeCount(treeNumber);

        if (expectInactiveLeaf) vm.expectRevert(IPrivacyBoost.AuthLeafNotActive.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(treeNumber, noteRoot),
            authRoots,
            giftNullifier,
            exitAuthLeaf,
            authLeafLocation,
            destination,
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            treeCount,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    /// @dev Build the single-slot claim arguments around one gift nullifier + one minted commitment.
    function _giftClaimArrays(uint256 nullifier, uint256 commitment)
        internal
        view
        returns (
            uint256[] memory nullifiers,
            Output[] memory outputs,
            uint16[] memory tokenIds,
            uint96[] memory amounts
        )
    {
        nullifiers = new uint256[](1);
        nullifiers[0] = nullifier;
        outputs = new Output[](1);
        outputs[0] = _makeOutput(commitment);
        tokenIds = new uint16[](1);
        tokenIds[0] = tokenId;
        amounts = new uint96[](1);
        amounts[0] = AMOUNT;
    }

    /// @dev Tree state for appending `nNew` minted notes to the fresh active tree (no rollover).
    function _treeState(uint32 nNew)
        internal
        view
        returns (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        )
    {
        activeTreeNumber = pool.currentTreeNumber();
        uint256 rootVal = pool.treeRoot(activeTreeNumber);
        usedRoots = EpochHelpers.buildUsedRoots(activeTreeNumber, rootVal);
        countOld = pool.treeCount(activeTreeNumber);
        countNew = countOld + nNew;
        rootNew = uint256(keccak256(abi.encodePacked("giftRoot", countNew)));
        rollover = false;
    }

    function _submitClaim(
        uint256 nullifier,
        uint256 commitment,
        uint256 /* claimRefundLabels: no longer on-chain */
    )
        internal
    {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(nullifier, commitment);

        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);

        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    /// @dev Exercise common public-exit settlement with an authless secret-bearer
    /// proof shape. Sender refunds use a non-zero key or Safe-approval leaf in
    /// the real circuit and are covered by the exact-leaf tests below.
    function _publicGiftExitWithoutAuth(address caller, address destination, uint256 giftNullifier) internal {
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = new TreeRootPair[](0);

        vm.prank(caller);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            giftNullifier,
            0,
            0,
            destination,
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    // ========== publicGiftExit ==========

    function test_publicGiftExit_paysDestinationAndSpendsNullifier() public {
        uint256 giftNullifier = 7001;
        address dest = makeAddr("secretExitDest");
        uint256 destBalBefore = token.balanceOf(dest);

        // Permissionless: a caller settles a digest-bound secret-bearer exit in one step.
        _publicGiftExitWithoutAuth(makeAddr("bob"), dest, giftNullifier);

        // Fee is 0 in the default config, so the destination receives the full amount (same convention as
        // the 2-step exit test). The shared gift nullifier is spent, closing the gift.
        assertEq(token.balanceOf(dest), destBalBefore + AMOUNT);
        assertTrue(pool.nullifierSpent(giftNullifier));
    }

    function test_publicGiftExit_emitsGiftExitExecuted() public {
        uint256 giftNullifier = 7002;
        address dest = makeAddr("secretExitDest2");

        vm.expectEmit(true, false, false, true);
        emit IPrivacyBoost.GiftExitExecuted(dest, tokenId, AMOUNT, giftNullifier);
        _publicGiftExitWithoutAuth(makeAddr("bob"), dest, giftNullifier);
    }

    function test_publicGiftExit_fullTreeUsesVirtualRolloverWithoutChangingTreeState() public {
        uint256 treeNumber = pool.currentTreeNumber();
        uint256 rootBefore = pool.treeRoot(treeNumber);
        uint32 capacity = uint32(1) << pool.merkleDepth();
        bytes32 countSlot = keccak256(abi.encode(treeNumber, uint256(8)));
        vm.store(address(pool), countSlot, bytes32(uint256(capacity)));

        uint256 giftNullifier = 7012;
        address destination = makeAddr("fullTreeExitDestination");
        uint256 balanceBefore = token.balanceOf(destination);

        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(treeNumber, rootBefore),
            new TreeRootPair[](0),
            giftNullifier,
            0,
            0,
            destination,
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            capacity,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );

        assertEq(pool.currentTreeNumber(), treeNumber);
        assertEq(pool.treeRoot(treeNumber), rootBefore);
        assertEq(pool.treeCount(treeNumber), capacity);
        assertEq(token.balanceOf(destination), balanceBefore + AMOUNT);
        assertTrue(pool.nullifierSpent(giftNullifier));
    }

    function test_revertWhen_publicGiftExitClaimsFullTreeAgainstNonFullLiveTip() public {
        uint32 capacity = uint32(1) << pool.merkleDepth();
        uint256 treeNumber = pool.currentTreeNumber();
        uint256 activeRoot = pool.treeRoot(treeNumber);

        vm.expectRevert(IPrivacyBoost.InvalidEpochState.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(treeNumber, activeRoot),
            new TreeRootPair[](0),
            7013,
            0,
            0,
            makeAddr("invalidFullTreeExitDestination"),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            capacity,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_publicGiftExitFeeExceedsProofBoundMinimum_beforeVerifierOrSpend() public {
        address treasury = makeAddr("giftTreasury");
        pool.setTreasury(treasury);

        // The proof author accepted the 1% quote. A later increase to 2% must not silently reduce payout.
        pool.setFees(100);
        uint96 quotedFee = uint96((uint256(AMOUNT) * 100) / 10_000);
        uint96 minNetAmount = AMOUNT - quotedFee;
        pool.setFees(200);
        uint96 actualNetAmount = AMOUNT - uint96((uint256(AMOUNT) * 200) / 10_000);

        // If the slippage guard were after Groth16 verification, this sentinel error would win instead.
        pool.setGiftClaimVerifier(address(new RevertingGiftClaimVerifier()));

        uint256 giftNullifier = 7014;
        address destination = makeAddr("slippageProtectedDestination");
        uint256 destinationBefore = token.balanceOf(destination);
        uint256 treasuryBefore = token.balanceOf(treasury);
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());

        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.GiftExitSlippage.selector, minNetAmount, actualNetAmount));
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            new TreeRootPair[](0),
            giftNullifier,
            0,
            0,
            destination,
            tokenId,
            AMOUNT,
            minNetAmount,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );

        assertFalse(pool.nullifierSpent(giftNullifier));
        assertEq(token.balanceOf(destination), destinationBefore);
        assertEq(token.balanceOf(treasury), treasuryBefore);
    }

    function test_publicGiftExitFeeDecreasePaysImprovedQuoteWithoutReproof() public {
        address treasury = makeAddr("giftTreasuryImprovedQuote");
        pool.setTreasury(treasury);

        // Bind the proof to a 2% minimum quote, then improve the live fee to 1% before execution.
        pool.setFees(200);
        uint96 minNetAmount = AMOUNT - uint96((uint256(AMOUNT) * 200) / 10_000);
        pool.setFees(100);
        uint96 actualFee = uint96((uint256(AMOUNT) * 100) / 10_000);
        uint96 actualNetAmount = AMOUNT - actualFee;

        uint256 giftNullifier = 7015;
        address destination = makeAddr("improvedQuoteDestination");
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            new TreeRootPair[](0),
            giftNullifier,
            0,
            0,
            destination,
            tokenId,
            AMOUNT,
            minNetAmount,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );

        assertEq(token.balanceOf(destination), actualNetAmount);
        assertEq(token.balanceOf(treasury), actualFee);
        assertTrue(pool.nullifierSpent(giftNullifier));
    }

    function test_revertWhen_publicGiftExitZeroDestination() public {
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.expectRevert(IPrivacyBoost.InvalidWithdrawal.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            7003,
            0,
            0,
            address(0),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_publicGiftExitProvingTimestampInFuture() public {
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.expectRevert(IPrivacyBoost.InvalidProvingTimestamp.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            7013,
            0,
            0,
            makeAddr("futureTimestampDestination"),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp + 1),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_publicGiftExitZeroNullifier() public {
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            0,
            0,
            0,
            makeAddr("refundDest4"),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_publicGiftExitAlreadyClaimed() public {
        uint256 giftNullifier = 7005;
        // A private claim spends the gift first.
        _submitClaim(giftNullifier, 8005, 0);
        assertTrue(pool.nullifierSpent(giftNullifier));

        // A later public exit of the same gift must now revert via the shared nullifier.
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            giftNullifier,
            0,
            0,
            makeAddr("refundDest5"),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_publicGiftExitBlockInFuture() public {
        uint256 rootVal = pool.treeRoot(pool.currentTreeNumber());
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // A currentBlock past block.number is rejected before verification, mirroring submitGiftClaimEpoch:
        // an off-chain proof may anchor a recent PAST block, never a future one.
        vm.expectRevert(IPrivacyBoost.GiftClaimBlockInFuture.selector);
        pool.publicGiftExit(
            EpochHelpers.buildUsedRoots(0, rootVal),
            authRoots,
            7006,
            0,
            0,
            makeAddr("refundDest6"),
            tokenId,
            AMOUNT,
            AMOUNT,
            bytes32(0),
            bytes32(0),
            0,
            block.number + 1,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_publicGiftExit_secretExitIgnoresAuthRootChurn() public {
        (uint256 ownerKey, address accountOwner, uint256 accountId, uint64 expiry,, uint256 oldRoot) =
            _registerAuthKey();
        _addSecondAuthKey(ownerKey, accountOwner, accountId, expiry);
        assertNotEq(authRegistry.authTreeRoot(0), oldRoot);

        address destination = makeAddr("authlessDestination");
        _publicGiftExitWithAuthRoot(oldRoot, 0, 0, destination, 7007, false);

        assertEq(token.balanceOf(destination), AMOUNT);
        assertTrue(pool.nullifierSpent(7007));
    }

    function test_publicGiftExit_activeLeafIgnoresUnrelatedAuthRootChurn() public {
        (
            uint256 ownerKey,
            address accountOwner,
            uint256 accountId,
            uint64 expiry,
            uint256 activeLeaf,
            uint256 oldRoot
        ) = _registerAuthKey();
        _addSecondAuthKey(ownerKey, accountOwner, accountId, expiry);

        assertTrue(authRegistry.isCurrentAuthLeafAt(0, activeLeaf));
        address destination = makeAddr("walletDestination");
        _publicGiftExitWithAuthRoot(oldRoot, activeLeaf, 0, destination, 7008, false);

        assertEq(token.balanceOf(destination), AMOUNT);
        assertTrue(pool.nullifierSpent(7008));
    }

    function test_revertWhen_publicGiftExitAuthLeafRevoked() public {
        (
            uint256 ownerKey,
            address accountOwner,
            uint256 accountId,
            uint64 expiry,
            uint256 revokedLeaf,
            uint256 oldRoot
        ) = _registerAuthKey();
        _revokeAuthKey(ownerKey, accountOwner, accountId, expiry);

        assertFalse(authRegistry.isCurrentAuthLeafAt(0, revokedLeaf));
        _publicGiftExitWithAuthRoot(oldRoot, revokedLeaf, 0, makeAddr("attackerDestination"), 7009, true);
        assertFalse(pool.nullifierSpent(7009));
    }

    function test_revertWhen_publicGiftExitAuthLeafLocationDoesNotContainLeaf() public {
        (uint256 ownerKey, address accountOwner, uint256 accountId, uint64 expiry, uint256 activeLeaf, uint256 root) =
            _registerAuthKey();
        _addSecondAuthKey(ownerKey, accountOwner, accountId, expiry);

        // Slot 1 contains the second key, not activeLeaf from slot 0.
        _publicGiftExitWithAuthRoot(root, activeLeaf, 1, makeAddr("wrongSlotDestination"), 7010, true);
        assertFalse(pool.nullifierSpent(7010));
    }

    function test_revertWhen_publicGiftExitAuthlessLocationIsNonZero() public {
        uint256 root = authRegistry.authTreeRoot(0);
        _publicGiftExitWithAuthRoot(root, 0, 1, makeAddr("authlessNonCanonicalDestination"), 7011, true);
        assertFalse(pool.nullifierSpent(7011));
    }

    // ========== setGiftClaimVerifier ==========

    function test_setGiftClaimVerifier_swapsVerifierAndClaimsStillWork() public {
        MockGiftClaimVerifier giftVerifier = new MockGiftClaimVerifier();

        vm.expectEmit(true, true, false, false);
        emit IPrivacyBoost.GiftClaimVerifierUpdated(address(verifier), address(giftVerifier));
        pool.setGiftClaimVerifier(address(giftVerifier));
        assertEq(address(pool.giftClaimVerifier()), address(giftVerifier));

        // A claim verified by the dedicated mock gift verifier still spends + mints.
        _submitClaim(1212, 3434, 0);
        assertTrue(pool.nullifierSpent(1212));
    }

    function test_revertWhen_setGiftClaimVerifierNotOwner() public {
        MockGiftClaimVerifier giftVerifier = new MockGiftClaimVerifier();
        vm.prank(alice);
        vm.expectRevert();
        pool.setGiftClaimVerifier(address(giftVerifier));
    }

    // ========== submitGiftClaimEpoch: happy paths ==========

    function test_submitGiftClaimEpoch_claimSpendsNullifierAndAppendsMint() public {
        uint256 nullifier = 111;
        uint256 commitment = 222;

        (,, uint32 countOld,, uint32 countNew,) = _treeState(1);

        _submitClaim(nullifier, commitment, 0); // branch 0 = claim

        // Nullifier spent → a second claim of the same gift must fail.
        assertTrue(pool.nullifierSpent(nullifier));
        // Tree advanced by exactly one minted note.
        assertEq(pool.treeCount(0), countNew);
        assertEq(countNew, countOld + 1);
    }

    function test_submitGiftClaimEpoch_emitsGiftSettled() public {
        uint256 nullifier = 333;
        uint256 commitment = 444;

        vm.expectEmit(true, false, false, true);
        emit IPrivacyBoost.GiftSettled(nullifier, commitment);
        _submitClaim(nullifier, commitment, 0);
    }

    // A refund settles through the SAME undifferentiated GiftSettled event as a claim, so a public observer
    // cannot tell claim from refund on chain (the branch is the circuit's private witness).
    function test_submitGiftClaimEpoch_refundAlsoEmitsGiftSettled() public {
        uint256 nullifier = 555;
        uint256 commitment = 666;

        vm.expectEmit(true, false, false, true);
        emit IPrivacyBoost.GiftSettled(nullifier, commitment);
        _submitClaim(nullifier, commitment, 1);
        assertTrue(pool.nullifierSpent(nullifier));
    }

    // ========== submitGiftClaimEpoch: revert paths ==========

    function test_revertWhen_giftClaimBlockInFuture() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(1313, 1414);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // A currentBlock in the future (block.number + 1) is rejected before verification: the attested block
        // has not occurred, so the relay cannot anchor the proof to a block that does not yet exist.
        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.GiftClaimBlockInFuture.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number + 1,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimProvingTimestampInFuture() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(1515, 1616);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidProvingTimestamp.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp + 1),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimDoubleSpendsNullifier() public {
        uint256 nullifier = 777;
        _submitClaim(nullifier, 888, 0);

        // Re-claiming the same gift nullifier (with a fresh commitment) must revert.
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(nullifier, 999);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimZeroNullifier() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(0, 1234);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidNullifierSet.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimNotRelay() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(10, 20);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Alice is not an allowed relay.
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_submitGiftClaimEpoch_padsInactiveOutputSlot() public {
        // One active claim in a two-slot verifier shape.
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 42;
        Output[] memory outputs = new Output[](2);
        outputs[0] = _makeOutput(1);
        outputs[1] = _makeOutput(2);

        (TreeRootPair[] memory usedRoots, uint256 activeTreeNumber, uint32 countOld, uint256 rootNew,, bool rollover) =
            _treeState(2);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countOld + 1, rollover),
            authRoots,
            nullifiers,
            outputs,
            EpochHelpers.defaultDigestRootIndices(),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );

        assertTrue(pool.nullifierSpent(42));
        assertEq(pool.treeCount(activeTreeNumber), countOld + 1);
    }

    function test_revertWhen_giftClaimEmptyBatch() public {
        uint256[] memory nullifiers = new uint256[](0);
        Output[] memory outputs = new Output[](0);

        uint256 activeTreeNumber = pool.currentTreeNumber();
        uint256 rootVal = pool.treeRoot(activeTreeNumber);
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(activeTreeNumber, rootVal);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidEpochConfig.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, 0, rootVal, 0, false),
            authRoots,
            nullifiers,
            outputs,
            new uint256[](0),
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    // ========== submitGiftClaimEpoch: digestRootIndices compatibility ==========

    // Authorization v2 excludes mutable roots. The compatibility selector may
    // still name a non-tip known-root slot without changing the approved digest.
    function test_submitGiftClaimEpoch_digestRootIndexAcceptsNonTipKnownRoot() public {
        // Advance the active tree once so the genesis root becomes a known, non-tip historical root.
        uint256 historicalRoot = pool.treeRoot(0);
        _submitClaim(8101, 8102, 0);

        uint32 countAfter = pool.treeCount(0);
        uint256 activeRoot = pool.treeRoot(0); // the new tip after the first claim

        // usedRoots[0] = active tip (must be present); usedRoots[1] = the non-tip historical root.
        TreeRootPair[] memory usedRoots = new TreeRootPair[](2);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: activeRoot});
        usedRoots[1] = TreeRootPair({treeNumber: 0, root: historicalRoot});

        // digestRootIndices[0] = 1 declares the non-tip historical slot.
        uint256[] memory indices = new uint256[](1);
        indices[0] = 1;

        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(8201, 8202);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        vm.prank(relay);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(
                usedRoots,
                0,
                countAfter,
                uint256(keccak256(abi.encodePacked("giftRoot", countAfter + 1))),
                countAfter + 1,
                false
            ),
            authRoots,
            nullifiers,
            outputs,
            indices,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );

        assertTrue(pool.nullifierSpent(8201), "claim declaring a non-tip known root should settle");
        assertEq(pool.treeCount(0), countAfter + 1, "active tree advanced by the minted note");
    }

    function test_revertWhen_giftClaimDigestRootIndicesTooLong() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(8301, 8302);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // batchSize=1 ⇒ expectedDigestRootWords=1, so a length-2 selector is rejected.
        uint256[] memory indices = new uint256[](2);

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            indices,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimDigestRootIndicesNonCanonical() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(8401, 8402);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // batchSize=1 ⇒ only the lowest 4 bits are meaningful; a non-zero padding nibble is non-canonical.
        uint256[] memory indices = new uint256[](1);
        indices[0] = uint256(1) << 4;

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.NonCanonicalEncoding.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            indices,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }

    function test_revertWhen_giftClaimDigestRootIndexOutOfBounds() public {
        (uint256[] memory nullifiers, Output[] memory outputs,,) = _giftClaimArrays(8501, 8502);
        (
            TreeRootPair[] memory usedRoots,
            uint256 activeTreeNumber,
            uint32 countOld,
            uint256 rootNew,
            uint32 countNew,
            bool rollover
        ) = _treeState(1);
        TreeRootPair[] memory authRoots = _getAuthRoots();

        // Slot 1 is out of range when usedRoots has a single entry (slot 0 only).
        uint256[] memory indices = new uint256[](1);
        indices[0] = 1;

        vm.prank(relay);
        vm.expectRevert(IPrivacyBoost.InvalidBatchConfig.selector);
        pool.submitGiftClaimEpoch(
            EpochHelpers.buildTreeState(usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover),
            authRoots,
            nullifiers,
            outputs,
            indices,
            block.number,
            uint64(block.timestamp),
            EpochHelpers.dummyProof()
        );
    }
}

/// @dev Wrapper exposing the calldata-typed gift public-input builders for direct unit testing.
contract LibGiftInputsWrapper {
    function buildGiftClaimInputs(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeTreeRoot,
        uint256 nClaims,
        uint256[] memory giftNullifiers,
        uint256[] memory commitmentsOut,
        uint256[] memory claimDigestHi,
        uint256[] memory claimDigestLo,
        uint256 currentBlock,
        uint64 provingTimestamp
    ) external pure returns (uint256[] memory) {
        return LibPublicInputs.buildGiftClaimInputs(
            treeState,
            usedAuthRoots,
            activeTreeRoot,
            nClaims,
            giftNullifiers,
            commitmentsOut,
            claimDigestHi,
            claimDigestLo,
            currentBlock,
            provingTimestamp
        );
    }

    function buildGiftExitInputs(
        TreeRootPair[] calldata sparseRoots,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 activeTreeNumber,
        uint256 activeTreeRoot,
        uint256 treeCount,
        uint256 emptyTreeRoot,
        bool fullTreeExit,
        uint256 giftNullifier,
        uint256 exitAuthLeaf,
        uint256 tokenId,
        uint256 amount,
        uint256 digestHi,
        uint256 digestLo,
        uint256 currentBlock,
        uint64 provingTimestamp
    ) external pure returns (uint256[] memory) {
        return LibPublicInputs.buildGiftExitInputs(
            sparseRoots,
            usedAuthRoots,
            activeTreeNumber,
            activeTreeRoot,
            treeCount,
            emptyTreeRoot,
            fullTreeExit,
            giftNullifier,
            exitAuthLeaf,
            tokenId,
            amount,
            digestHi,
            digestLo,
            currentBlock,
            provingTimestamp
        );
    }
}

/// @notice Unit coverage for the gift digest + the two gift public-input builders (audited lib surface).
contract LibGiftTest is Test {
    uint8 constant MAX_TREES = 16;
    uint8 constant MAX_AUTH_TREES = 16;

    uint256 constant CHAIN_ID = 1;
    address constant POOL = address(0x1234);
    uint256 constant ROOT = 0xABCD;

    LibGiftInputsWrapper wrapper;

    function setUp() public {
        wrapper = new LibGiftInputsWrapper();
    }

    function _zeroOutput() internal pure returns (Output memory) {
        return Output({
            commitment: 0,
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes32(0),
            ct3: bytes16(0)
        });
    }

    function _authRoots() internal pure returns (TreeRootPair[] memory roots) {
        roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: 777});
    }

    // ========== computeGiftClaimDigest ==========

    function test_computeGiftClaimDigest_returnsSplitHash() public pure {
        Output memory output = _zeroOutput();

        uint256 giftNullifier = 0xDEAD;
        // The private-mint digest binds the output commitment (which commits to token+amount) and omits
        // cleartext token/amount, so a private claim never reveals the gifted value on chain.
        (uint256 hi, uint256 lo) =
            LibDigest.computeGiftClaimDigest(CHAIN_ID, POOL, giftNullifier, output, bytes32(0), bytes32(0));

        bytes32 expected =
            keccak256(abi.encode("PB:GIFT_CLAIM:v2", CHAIN_ID, POOL, giftNullifier, output, bytes32(0), bytes32(0)));

        assertEq(hi, uint256(expected) >> 128);
        assertEq(lo, uint256(expected) & ((uint256(1) << 128) - 1));
    }

    function test_computeGiftExitDigest_destinationChangesDigest() public pure {
        // The public-exit digest binds the payout destination, which is what authorizes one specific target.
        // Two exits that differ only in destination must produce different digests.
        (uint256 hiA, uint256 loA) = LibDigest.computeGiftExitDigest(
            CHAIN_ID, POOL, 1, address(0xBEEF), 1, 1 ether, 0.99 ether, bytes32(0), bytes32(0)
        );
        (uint256 hiB, uint256 loB) = LibDigest.computeGiftExitDigest(
            CHAIN_ID, POOL, 1, address(0xCAFE), 1, 1 ether, 0.99 ether, bytes32(0), bytes32(0)
        );

        assertTrue(hiA != hiB || loA != loB);
    }

    function test_computeGiftExitDigest_minNetAmountChangesDigestAndUsesV2Domain() public pure {
        uint96 amount = 1 ether;
        uint96 minNetA = 0.99 ether;
        uint96 minNetB = 0.98 ether;
        (uint256 hiA, uint256 loA) = LibDigest.computeGiftExitDigest(
            CHAIN_ID, POOL, 1, address(0xBEEF), 1, amount, minNetA, bytes32(0), bytes32(0)
        );
        (uint256 hiB, uint256 loB) = LibDigest.computeGiftExitDigest(
            CHAIN_ID, POOL, 1, address(0xBEEF), 1, amount, minNetB, bytes32(0), bytes32(0)
        );

        bytes32 expected = keccak256(
            abi.encode(
                "PB:GIFT_EXIT:v2",
                CHAIN_ID,
                POOL,
                uint256(1),
                address(0xBEEF),
                uint16(1),
                amount,
                minNetA,
                bytes32(0),
                bytes32(0)
            )
        );
        assertEq(hiA, uint256(expected) >> 128);
        assertEq(loA, uint256(expected) & ((uint256(1) << 128) - 1));
        assertTrue(hiA != hiB || loA != loB);
    }

    function test_computeGiftClaimDigest_differentFromTransferDigest() public pure {
        Output[] memory outputs = new Output[](1);
        outputs[0] = _zeroOutput();
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = 1;

        (uint256 transferHi,) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers, outputs, bytes32(0), bytes32(0));
        (uint256 giftHi,) = LibDigest.computeGiftClaimDigest(CHAIN_ID, POOL, 1, outputs[0], bytes32(0), bytes32(0));

        assertTrue(transferHi != giftHi);
    }

    // ========== buildGiftClaimInputs (private, epoch-shaped) ==========

    function test_buildGiftClaimInputs_layout() public view {
        EpochTreeState memory treeState = EpochTreeState({
            usedRoots: new TreeRootPair[](1),
            activeTreeNumber: 0,
            countOld: 5,
            rootNew: 0xBEEF,
            countNew: 7,
            rollover: false
        });
        treeState.usedRoots[0] = TreeRootPair({treeNumber: 0, root: 0xACE});

        uint256[] memory giftNullifiers = new uint256[](2);
        giftNullifiers[0] = 11;
        uint256[] memory commitmentsOut = new uint256[](2);
        commitmentsOut[0] = 33;
        uint256[] memory claimDigestHi = new uint256[](2);
        claimDigestHi[0] = 55;
        uint256[] memory claimDigestLo = new uint256[](2);
        claimDigestLo[0] = 77;

        uint256[] memory inputs = wrapper.buildGiftClaimInputs(
            treeState,
            _authRoots(),
            0xACE,
            1,
            giftNullifiers,
            commitmentsOut,
            claimDigestHi,
            claimDigestLo,
            12345,
            54321
        );

        // Mirrors the circuit's GiftClaimPublicInputs (gnark order == struct field order):
        //   knownRoots(16) + packedTreeNumbers(1) + authRoots(16) + packedAuthTreeNumbers(1) = 34
        //   + 9 tree/batch scalars + 7 per-slot columns * 2 slots = 34 + 9 + 14 = 57
        assertEq(inputs.length, 57);

        // funding root lands in slot 0; NO public destination anywhere in the private layout.
        assertEq(inputs[0], 0xACE);

        // Tree/batch scalars after roots+auth (34).
        uint256 sb = MAX_TREES + 1 + MAX_AUTH_TREES + 1;
        assertEq(inputs[sb + 0], 0); // activeTreeNumber
        assertEq(inputs[sb + 1], 0xACE); // activeTreeRoot
        assertEq(inputs[sb + 2], 5); // countOld
        assertEq(inputs[sb + 3], 0xBEEF); // rootNew
        assertEq(inputs[sb + 4], 7); // countNew
        assertEq(inputs[sb + 5], 0); // rollover
        assertEq(inputs[sb + 6], 1); // nClaims
        assertEq(inputs[sb + 7], 12345); // currentBlock
        assertEq(inputs[sb + 8], 54321); // provingTimestamp

        // Per-slot columns at stride 1, in circuit-declared order.
        uint256 pb = sb + 9;
        assertEq(inputs[pb + 0], 11); // nullifier[0]
        assertEq(inputs[pb + 1], 0); // nullifier[1] (inactive padding)
        assertEq(inputs[pb + 2], 33); // commitment[0]
        assertEq(inputs[pb + 4], 0); // outputTokenId[0] — zero in private-mint mode (hidden)
        assertEq(inputs[pb + 6], 0); // outputAmount[0] — zero in private-mint mode (hidden)
        assertEq(inputs[pb + 8], 55); // claimDigestHi[0]
        assertEq(inputs[pb + 10], 77); // claimDigestLo[0]
        assertEq(inputs[pb + 12], 1); // branchSelector[0] (private mint)
        assertEq(inputs[pb + 13], 0); // branchSelector[1] (inactive padding)
    }

    // ========== buildGiftExitInputs (public, destination bound) ==========

    function test_buildGiftExitInputs_layout() public view {
        TreeRootPair[] memory sparseRoots = new TreeRootPair[](1);
        sparseRoots[0] = TreeRootPair({treeNumber: 0, root: 0xACE});

        uint256 digestHi = 0xD1;
        uint256 digestLo = 0xD0;
        uint16 tokenId = 9;
        uint96 amount = 500 ether;

        uint256[] memory inputs = wrapper.buildGiftExitInputs(
            sparseRoots,
            _authRoots(),
            3,
            0xACE,
            12,
            0xE11E,
            false,
            101,
            202,
            tokenId,
            amount,
            digestHi,
            digestLo,
            67890,
            98765
        );

        // Same canonical GiftClaimPublicInputs layout as the private path, batchSize 1:
        //   knownRoots(16) + packedTreeNumbers(1) + authRoots(16) + packedAuthTreeNumbers(1) = 34
        //   + 9 tree/batch scalars + 7 per-slot columns = 50
        assertEq(inputs.length, 50);
        assertEq(inputs[0], 0xACE);

        // Tree/batch scalars: the exit is a no-op tree transition (rootNew == activeTreeRoot, countNew == countOld).
        uint256 sb = MAX_TREES + 1 + MAX_AUTH_TREES + 1;
        assertEq(inputs[sb + 0], 3); // activeTreeNumber
        assertEq(inputs[sb + 1], 0xACE); // activeTreeRoot
        assertEq(inputs[sb + 2], 12); // countOld
        assertEq(inputs[sb + 3], 0xACE); // rootNew == activeTreeRoot
        assertEq(inputs[sb + 4], 12); // countNew == countOld
        assertEq(inputs[sb + 5], 0); // rollover
        assertEq(inputs[sb + 6], 1); // nClaims
        assertEq(inputs[sb + 7], 67890); // currentBlock
        assertEq(inputs[sb + 8], 98765); // provingTimestamp

        // Per-slot column set; destination is bound via the digest (not a public input); branchSelector 0 = payout.
        uint256 pb = sb + 9;
        assertEq(inputs[pb + 0], 101); // giftNullifier
        assertEq(inputs[pb + 1], 202); // exitAuthLeaf
        assertEq(inputs[pb + 2], uint256(tokenId)); // outputTokenId
        assertEq(inputs[pb + 3], uint256(amount)); // outputAmount
        assertEq(inputs[pb + 4], digestHi);
        assertEq(inputs[pb + 5], digestLo);
        assertEq(inputs[pb + 6], 0); // branchSelector (public payout)
    }

    function test_buildGiftExitInputs_fullTreeUsesVirtualRollover() public view {
        TreeRootPair[] memory sparseRoots = new TreeRootPair[](1);
        sparseRoots[0] = TreeRootPair({treeNumber: 3, root: 0xACE});

        uint256[] memory inputs = wrapper.buildGiftExitInputs(
            sparseRoots, _authRoots(), 3, 0xACE, 16, 0xE11E, true, 101, 0, 9, 500 ether, 0xD1, 0xD0, 67890, 98765
        );

        uint256 sb = MAX_TREES + 1 + MAX_AUTH_TREES + 1;
        assertEq(inputs[sb + 2], 16); // countOld: full tree
        assertEq(inputs[sb + 3], 0xE11E); // rootNew: empty tree root
        assertEq(inputs[sb + 4], 0); // countNew: no append after virtual rollover
        assertEq(inputs[sb + 5], 1); // rollover
    }
}
