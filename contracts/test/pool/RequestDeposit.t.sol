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
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {DepositOrigin, DepositCiphertext} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20, DOMAIN_DEPOSIT_REQUEST} from "src/interfaces/Constants.sol";
import {MockERC20, MockFeeOnTransferToken, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

contract PendingDepositObserver {
    PrivacyBoost public immutable pool;
    address public immutable token;
    uint256 public requestId;
    bool public callbackObserved;
    address public observedDepositor;

    constructor(PrivacyBoost _pool, address _token) {
        pool = _pool;
        token = _token;
    }

    function setRequestId(uint256 _requestId) external {
        requestId = _requestId;
    }

    function observePendingDeposit() external {
        require(msg.sender == token);
        (address depositor,,,,,,,) = pool.pendingDeposits(requestId);
        observedDepositor = depositor;
        callbackObserved = true;
    }
}

contract PendingDepositObservingToken is MockERC20 {
    address public observer;

    function setObserver(address _observer) external {
        observer = _observer;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        bool transferred = super.transfer(to, value);
        if (to == observer) PendingDepositObserver(observer).observePendingDeposit();
        return transferred;
    }
}

contract RequestDepositTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    uint16 tokenId;
    uint96 constant AMOUNT = 1000 ether;
    uint256 constant COMMITMENT = 12345;
    uint256 constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        token.mint(alice, 100_000 ether);
        token.mint(bob, 100_000 ether);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
        vm.prank(bob);
        token.approve(address(pool), type(uint256).max);
    }

    function _dummyCiphertext() internal pure returns (DepositCiphertext memory) {
        return DepositCiphertext({
            viewingKey: bytes32(uint256(1)),
            teeWrapKey: bytes32(uint256(2)),
            receiverWrapKey: bytes32(uint256(3)),
            ct0: bytes32(uint256(4)),
            ct1: bytes32(uint256(5)),
            ct2: bytes16(uint128(6))
        });
    }

    // ========== Happy Path ==========

    function test_requestDeposit_singleCommitment() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        uint256 balBefore = token.balanceOf(alice);

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        assertTrue(reqId != 0);
        assertEq(token.balanceOf(alice), balBefore - AMOUNT);
        assertEq(token.balanceOf(address(pool)), AMOUNT);

        (address depositor, uint16 tid, uint96 totalAmt,,, uint16 commitmentCount, uint256 commitmentsHash,) =
            pool.pendingDeposits(reqId);
        assertEq(depositor, alice);
        assertEq(tid, tokenId);
        assertEq(totalAmt, AMOUNT);
        assertEq(commitmentCount, 1);
        assertEq(commitmentsHash, LibDigest.computeCommitmentsHash(commitments));
    }

    function test_requestDeposit_multipleCommitments() public {
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = 100;
        commitments[1] = 200;
        commitments[2] = 300;
        DepositCiphertext[] memory cts = new DepositCiphertext[](3);
        for (uint256 i = 0; i < 3; i++) {
            cts[i] = _dummyCiphertext();
        }

        uint96 totalAmount = 1500 ether;

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, totalAmount, commitments, cts);

        (address depositor, uint16 tid, uint96 totalAmt,,, uint16 commitmentCount, uint256 commitmentsHash,) =
            pool.pendingDeposits(reqId);
        assertEq(depositor, alice);
        assertEq(tid, tokenId);
        assertEq(totalAmt, totalAmount);
        assertEq(commitmentCount, 3);
        assertEq(commitmentsHash, LibDigest.computeCommitmentsHash(commitments));
    }

    // ========== Input Validation ==========

    function test_revertWhen_zeroAmount() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, 0, commitments, cts);
    }

    function test_revertWhen_zeroCommitment() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 0; // zero commitment
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_commitmentEqualsScalarField() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = SNARK_SCALAR_FIELD;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_commitmentGreaterThanScalarField() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = SNARK_SCALAR_FIELD + 1;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_emptyCommitments() public {
        uint256[] memory commitments = new uint256[](0);
        DepositCiphertext[] memory cts = new DepositCiphertext[](0);

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_arrayLengthMismatch() public {
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 100;
        commitments[1] = 200;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1); // mismatch
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidArrayLengths.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_invalidTokenId() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(999, AMOUNT, commitments, cts); // unregistered tokenId
    }

    function test_revertWhen_commitmentCountExceedsMaxBatchSize() public {
        // maxBatchSize is 8 in setUp, so 9 commitments should fail
        uint256 count = pool.maxBatchSize() + 1;
        uint256[] memory commitments = new uint256[](count);
        DepositCiphertext[] memory cts = new DepositCiphertext[](count);
        for (uint256 i = 0; i < count; i++) {
            commitments[i] = 100 + i;
            cts[i] = _dummyCiphertext();
        }

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    // ========== Cancel ==========

    function test_cancelDeposit_afterDelay() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        uint256 balBefore = token.balanceOf(alice);
        vm.roll(block.number + pool.cancelDelay() + 1);

        vm.prank(alice);
        pool.cancelDeposit(reqId);

        assertEq(token.balanceOf(alice), balBefore + AMOUNT);
        (address depositor,,,,,,,) = pool.pendingDeposits(reqId);
        assertEq(depositor, address(0)); // cleared
    }

    function test_cancelDeposit_clearsStateBeforeRefundInteraction() public {
        // Arrange
        PendingDepositObservingToken observingToken = new PendingDepositObservingToken();
        uint16 observingTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(observingToken), 0);
        PendingDepositObserver observer = new PendingDepositObserver(pool, address(observingToken));
        observingToken.setObserver(address(observer));
        observingToken.mint(address(observer), AMOUNT);

        vm.prank(address(observer));
        observingToken.approve(address(pool), type(uint256).max);

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(address(observer));
        uint256 reqId = pool.requestDeposit(observingTokenId, AMOUNT, commitments, cts);
        observer.setRequestId(reqId);
        vm.roll(block.number + pool.cancelDelay() + 1);

        // Act
        vm.prank(address(observer));
        pool.cancelDeposit(reqId);

        // Assert
        assertTrue(observer.callbackObserved());
        assertEq(observer.observedDepositor(), address(0));
        assertEq(observingToken.balanceOf(address(observer)), AMOUNT);
        assertEq(observingToken.balanceOf(address(pool)), 0);
        (address depositor,,,,,,,) = pool.pendingDeposits(reqId);
        assertEq(depositor, address(0));
        assertFalse(pool.processedDeposits(reqId));
    }

    function test_revertWhen_cancelTooEarly() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.CancelTooEarly.selector);
        pool.cancelDeposit(reqId);
    }

    function test_revertWhen_notDepositor() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        vm.roll(block.number + pool.cancelDelay() + 1);

        vm.prank(bob); // bob tries to cancel alice's deposit
        vm.expectRevert(IPrivacyBoost.NotDepositor.selector);
        pool.cancelDeposit(reqId);
    }

    // ========== State Verification ==========

    function test_nonceIncrement() public {
        assertEq(pool.depositNonces(alice), 0);

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
        assertEq(pool.depositNonces(alice), 1);

        commitments[0] = COMMITMENT + 1;
        vm.prank(alice);
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
        assertEq(pool.depositNonces(alice), 2);
    }

    function test_depositRequestIdComputation() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        uint32 nonceBefore = pool.depositNonces(alice);
        uint256 commitmentsHash = LibDigest.computeCommitmentsHash(commitments);

        uint256 expectedReqId = Poseidon2T4.hash8(
            DOMAIN_DEPOSIT_REQUEST,
            block.chainid,
            uint256(uint160(address(pool))),
            uint256(uint160(alice)),
            uint256(tokenId),
            uint256(AMOUNT),
            uint256(nonceBefore),
            commitmentsHash
        );

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        assertEq(reqId, expectedReqId);
    }

    // ========== Events ==========

    function test_depositRequestedEvent() public {
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 100;
        commitments[1] = 200;
        DepositCiphertext[] memory cts = new DepositCiphertext[](2);
        cts[0] = _dummyCiphertext();
        cts[1] = _dummyCiphertext();

        uint256 commitmentsHash = LibDigest.computeCommitmentsHash(commitments);
        uint256 expectedReqId = Poseidon2T4.hash8(
            DOMAIN_DEPOSIT_REQUEST,
            block.chainid,
            uint256(uint160(address(pool))),
            uint256(uint160(alice)),
            uint256(tokenId),
            uint256(AMOUNT),
            0, // nonce
            commitmentsHash
        );

        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit IPrivacyBoost.DepositRequested(
            expectedReqId,
            alice,
            DepositOrigin.UserShield,
            tokenId,
            AMOUNT,
            2, // commitmentCount
            commitmentsHash,
            commitments,
            cts
        );
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_depositCancelledEvent() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        vm.roll(block.number + pool.cancelDelay() + 1);

        vm.prank(alice);
        vm.expectEmit(true, false, false, false);
        emit IPrivacyBoost.DepositCancelled(reqId);
        pool.cancelDeposit(reqId);
    }

    // ========== Token Transfer ==========

    function test_revertWhen_insufficientBalance() public {
        address poorUser = makeAddr("poor");
        token.mint(poorUser, 100); // only 100 wei
        vm.prank(poorUser);
        token.approve(address(pool), type(uint256).max);

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(poorUser);
        vm.expectRevert(); // ERC20 insufficient balance
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_noApproval() public {
        address noApprovalUser = makeAddr("noApproval");
        token.mint(noApprovalUser, AMOUNT);
        // No approval

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(noApprovalUser);
        vm.expectRevert(); // ERC20 insufficient allowance
        pool.requestDeposit(tokenId, AMOUNT, commitments, cts);
    }

    function test_revertWhen_feeOnTransferToken() public {
        // Deploy fee-on-transfer token and register it
        MockFeeOnTransferToken feeToken = new MockFeeOnTransferToken();
        uint16 feeTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(feeToken), 0);

        // Setup alice with fee token
        feeToken.mint(alice, 100_000 ether);
        vm.prank(alice);
        feeToken.approve(address(pool), type(uint256).max);

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        // Should revert because received amount differs from requested
        uint256 expectedReceived = AMOUNT - (AMOUNT / 100); // 1% fee deducted
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyBoost.FeeOnTransferNotSupported.selector, AMOUNT, expectedReceived)
        );
        pool.requestDeposit(feeTokenId, AMOUNT, commitments, cts);
    }
}
