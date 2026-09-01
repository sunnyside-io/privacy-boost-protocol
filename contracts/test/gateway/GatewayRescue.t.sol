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

import {GatewayBaseTest} from "./GatewayBase.t.sol";
import {GatewayAction, GatewayReceipt, GatewaySlot, RescueKind, Withdrawal} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {DOMAIN_NOTE} from "src/interfaces/Constants.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract GatewayRescueTest is GatewayBaseTest {
    bytes32 internal constant RESCUE_DOMAIN = keccak256("PB:RESCUE:v1");
    bytes32 internal constant AUTHORITY_RESCUE_DOMAIN = keccak256("PB:GATEWAY:AUTHORITY_RESCUE:v1");

    address rescueSigner;
    uint256 rescuePk;
    bytes32 rescueSalt = keccak256("salt-rescue");
    bytes32 rescueCommit;

    function setUp() public override {
        super.setUp();
        (rescueSigner, rescuePk) = makeAddrAndKey("rescueSigner-rescue");
        rescueCommit = keccak256(abi.encode(rescueSigner, rescueSalt));
    }

    function test_gatewayDepositRescue_signaturePath() public {
        // Trigger an external ERC-4626 deposit that creates a gateway-origin pending deposit.
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, rescueCommit, 999);
        _submitOneWithdrawal(w, _slotArr1(slot));
        GatewayReceipt memory r = slot.receipt;

        // Compute deterministic depositRequestId (matches the pool's _recordGatewayOriginDeposit).
        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );

        // Wait past cancelDelay (10) and rescue.
        vm.roll(block.number + 11);

        address destination = makeAddr("rescueDeposit-dest");
        bytes32 digest = _digest(RescueKind.GatewayDeposit, depositRequestId, rescueCommit, destination);
        bytes memory sig = _sign(rescuePk, MessageHashUtils.toEthSignedMessageHash(digest));

        pool.rescueGatewayDeposit(depositRequestId, destination, rescueSalt, rescueSigner, sig);
        assertEq(vault4626.balanceOf(destination), 100 ether);
    }

    function test_gatewayDepositRescue_wrongSignatureReverts() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, rescueCommit, 998);
        _submitOneWithdrawal(w, _slotArr1(slot));
        GatewayReceipt memory r = slot.receipt;

        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        uint256 depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );
        vm.roll(block.number + 11);

        address destination = makeAddr("rescueDeposit-dest2");
        // Sign with a different key → recover fails.
        (, uint256 wrongPk) = makeAddrAndKey("wrongKey");
        bytes32 digest = _digest(RescueKind.GatewayDeposit, depositRequestId, rescueCommit, destination);
        bytes memory sig = _sign(wrongPk, MessageHashUtils.toEthSignedMessageHash(digest));

        vm.expectRevert(IPrivacyBoost.InvalidRescueSignature.selector);
        pool.rescueGatewayDeposit(depositRequestId, destination, rescueSalt, rescueSigner, sig);
    }

    function test_authorityRescue_succeedsFromCommittedEoa() public {
        // Arrange
        address authority = makeAddr("authority-rescue");
        address destination = makeAddr("authority-rescue-destination");
        bytes32 authoritySalt = keccak256("authority-rescue-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_101);
        vm.roll(block.number + 11);

        // Act
        vm.prank(authority);
        pool.rescueGatewayDeposit(depositRequestId, destination, authoritySalt, authority, "");

        // Assert
        assertEq(vault4626.balanceOf(destination), 100 ether);
    }

    function test_authorityRescue_succeedsFromCommittedContractAccount() public {
        // Arrange
        address authority = address(externalGateway);
        address destination = makeAddr("authority-contract-destination");
        bytes32 authoritySalt = keccak256("authority-contract-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_102);
        vm.roll(block.number + 11);

        // Act
        vm.prank(authority);
        pool.rescueGatewayDeposit(depositRequestId, destination, authoritySalt, authority, "");

        // Assert
        assertEq(vault4626.balanceOf(destination), 100 ether);
    }

    function test_authorityRescue_revertsBeforeCancelDelay() public {
        // Arrange
        address authority = makeAddr("authority-too-early");
        bytes32 authoritySalt = keccak256("authority-too-early-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_103);

        // Act / Assert
        vm.prank(authority);
        vm.expectRevert(IPrivacyBoost.RescueTooEarly.selector);
        pool.rescueGatewayDeposit(depositRequestId, authority, authoritySalt, authority, "");
    }

    function test_authorityRescue_revertsForDifferentAuthority() public {
        // Arrange
        address authority = makeAddr("authority-authority");
        address otherAuthority = makeAddr("other-authority");
        bytes32 authoritySalt = keccak256("authority-wrong-caller-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_104);
        vm.roll(block.number + 11);

        // Act / Assert
        vm.prank(otherAuthority);
        vm.expectRevert(IPrivacyBoost.InvalidRescueAuthority.selector);
        pool.rescueGatewayDeposit(depositRequestId, otherAuthority, authoritySalt, authority, "");
    }

    function test_authorityRescue_rejectsNonemptySignature() public {
        // Arrange
        address authority = makeAddr("authority-nonempty-signature");
        bytes32 authoritySalt = keccak256("authority-nonempty-signature-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_105);
        vm.roll(block.number + 11);

        // Act / Assert
        vm.prank(authority);
        vm.expectRevert(IPrivacyBoost.InvalidRescueSignature.selector);
        pool.rescueGatewayDeposit(depositRequestId, authority, authoritySalt, authority, hex"01");
    }

    function test_legacyRescue_rejectsAuthorityCommitment() public {
        // Arrange
        address authority = makeAddr("authority-key-reject");
        address destination = makeAddr("authority-key-destination");
        bytes32 authoritySalt = keccak256("authority-key-reject-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_106);
        vm.roll(block.number + 11);

        // Act / Assert
        vm.expectRevert(IPrivacyBoost.InvalidRescueCommitment.selector);
        pool.rescueGatewayDeposit(depositRequestId, destination, rescueSalt, rescueSigner, "");
    }

    function test_authorityRescue_revertsWhenReplayed() public {
        // Arrange
        address authority = makeAddr("authority-replay");
        bytes32 authoritySalt = keccak256("authority-replay-salt");
        uint256 depositRequestId = _createPendingDeposit(_authorityCommitment(authority, authoritySalt), 1_107);
        vm.roll(block.number + 11);
        vm.prank(authority);
        pool.rescueGatewayDeposit(depositRequestId, authority, authoritySalt, authority, "");

        // Act / Assert
        vm.prank(authority);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.rescueGatewayDeposit(depositRequestId, authority, authoritySalt, authority, "");
    }

    function test_authorityCommitment_usesPerReceiptSalt() public pure {
        address authority = address(0x1111111111111111111111111111111111111111);
        assertNotEq(
            _authorityCommitment(authority, bytes32(uint256(1))), _authorityCommitment(authority, bytes32(uint256(2)))
        );
    }

    function _createPendingDeposit(bytes32 commitment_, uint256 seed) internal returns (uint256 depositRequestId) {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, commitment_, seed);
        _submitOneWithdrawal(w, _slotArr1(slot));
        GatewayReceipt memory r = slot.receipt;
        uint256 commitment = Poseidon2T4.hash4(DOMAIN_NOTE, r.npk, uint256(r.outputTokenId), uint256(uint96(100 ether)));
        uint256 commitmentsHash = LibDigest.computeCommitmentsHashStep(0, commitment);
        depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(pool), address(externalGateway), idVault4626, uint96(100 ether), 0, commitmentsHash
        );
    }

    function _authorityCommitment(address authority, bytes32 authoritySalt) internal pure returns (bytes32) {
        return keccak256(abi.encode(AUTHORITY_RESCUE_DOMAIN, authority, authoritySalt));
    }

    function _digest(RescueKind kind, uint256 reqId, bytes32 rc, address dest) internal view returns (bytes32) {
        return keccak256(abi.encode(RESCUE_DOMAIN, block.chainid, address(pool), kind, reqId, rc, dest));
    }

    function _sign(uint256 pk, bytes32 ethSignedMsgHash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedMsgHash);
        return abi.encodePacked(r, s, v);
    }
}
