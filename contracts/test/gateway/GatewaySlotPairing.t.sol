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
import {GatewaySlot, Withdrawal} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";

contract GatewaySlotPairingTest is GatewayBaseTest {
    bytes32 constant RC = keccak256("rc-gateway-slot-pairing");

    function test_gatewaySlots_multipleExternalSlots_happyPath() public {
        // Arrange
        Withdrawal memory w0 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 200 ether});
        GatewaySlot memory slot0 = _erc4626DepositSlot(0, 100 ether, 0, RC, 100);
        GatewaySlot memory slot1 = _erc4626DepositSlot(1, 200 ether, 0, RC, 101);
        SubmitArgs memory args = _prepareTwoWithdrawals(w0, w1);

        uint256 poolSharesBefore = vault4626.balanceOf(address(pool));

        // Act
        _callSubmit(args, _slotArr2(slot0, slot1));

        // Assert
        assertEq(vault4626.balanceOf(address(pool)) - poolSharesBefore, 300 ether);
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
        assertEq(vault4626.balanceOf(address(externalGateway)), 0);
    }

    function test_gatewaySlots_plainThenGateway_nonZeroIndex_happyPath() public {
        // Arrange
        Withdrawal memory plain = Withdrawal({to: user, tokenId: idUsdc, amount: 11 ether});
        Withdrawal memory gateway = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(1, 100 ether, 0, RC, 102);
        SubmitArgs memory args = _prepareTwoWithdrawals(plain, gateway);

        uint256 userUsdcBefore = usdc.balanceOf(user);
        uint256 poolSharesBefore = vault4626.balanceOf(address(pool));

        // Act
        _callSubmit(args, _slotArr1(slot));

        // Assert
        assertEq(usdc.balanceOf(user) - userUsdcBefore, 11 ether);
        assertEq(vault4626.balanceOf(address(pool)) - poolSharesBefore, 100 ether);
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
    }

    function test_gatewaySlots_depositAndRedeemSlots_happyPath() public {
        // Arrange
        uint96 redeemShares = 100 ether;
        _fundPoolWithVaultShares(redeemShares, user);
        Withdrawal memory depositWithdrawal =
            Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 50 ether});
        Withdrawal memory redeemWithdrawal =
            Withdrawal({to: address(externalGateway), tokenId: idVault4626, amount: redeemShares});
        GatewaySlot memory depositSlot = _erc4626DepositSlot(0, 50 ether, 0, RC, 103);
        GatewaySlot memory redeemSlot = _erc4626RedeemSlot(1, redeemShares, 0, RC, 104);
        SubmitArgs memory args = _prepareTwoWithdrawals(depositWithdrawal, redeemWithdrawal);

        uint256 poolSharesBefore = vault4626.balanceOf(address(pool));
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));

        // Act
        _callSubmit(args, _slotArr2(depositSlot, redeemSlot));

        // Assert
        assertEq(vault4626.balanceOf(address(pool)), poolSharesBefore + 50 ether - redeemShares);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore - 50 ether + 100 ether);
    }

    function test_gatewaySlots_notStrictlyAscending_reverts() public {
        // Arrange
        Withdrawal memory w0 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 200 ether});
        GatewaySlot memory slot0 = _erc4626DepositSlot(1, 100 ether, 0, RC, 105);
        GatewaySlot memory slot1 = _erc4626DepositSlot(0, 200 ether, 0, RC, 106);

        // Act / Assert
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyBoost.GatewayExecutionFailed.selector,
                abi.encodeWithSelector(IPrivacyBoost.GatewaySlotsNotStrictlyAscending.selector)
            )
        );
        pool.simulateGatewayWithdrawals(_withdrawalArr2(w0, w1), _slotArr2(slot0, slot1));
    }
}
