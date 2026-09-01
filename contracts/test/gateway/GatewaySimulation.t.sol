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

import {GatewayBaseTest} from "./GatewayBase.t.sol";
import {
    GatewayAction,
    GatewayRoute,
    GatewaySettlementOutcome,
    GatewaySlot,
    Withdrawal
} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {MockERC20} from "test/helpers/Mocks.sol";

contract GatewaySimulationTest is GatewayBaseTest {
    bytes32 constant RC = keccak256("rc-simulation");

    function test_simulateGatewayWithdrawals_erc4626Deposit_revertsWithResultAndRollsBack() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 1);
        Withdrawal[] memory withdrawals = _withdrawalArr1(w);
        GatewaySlot[] memory slots = _slotArr1(slot);

        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));
        uint256 poolShareBefore = vault4626.balanceOf(address(pool));

        // Act
        vm.prank(relayer);
        vm.expectRevert();
        pool.simulateGatewayWithdrawals(withdrawals, slots);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore);
        assertEq(vault4626.balanceOf(address(pool)), poolShareBefore);
        assertEq(pool.depositNonces(address(externalGateway)), 0);
    }

    function test_simulateGatewayWithdrawals_erc4626Redeem_revertsWithResultAndRollsBack() public {
        // Arrange
        _fundPoolWithVaultShares(100 ether, user);
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idVault4626, amount: 100 ether});
        GatewaySlot memory slot = _erc4626RedeemSlot(0, 100 ether, 1, RC, 2);
        Withdrawal[] memory withdrawals = _withdrawalArr1(w);
        GatewaySlot[] memory slots = _slotArr1(slot);

        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));
        uint256 poolShareBefore = vault4626.balanceOf(address(pool));

        // Act
        vm.prank(relayer);
        vm.expectRevert();
        pool.simulateGatewayWithdrawals(withdrawals, slots);

        // Assert
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore);
        assertEq(vault4626.balanceOf(address(pool)), poolShareBefore);
        assertEq(pool.depositNonces(address(externalGateway)), 0);
    }

    function test_simulateGatewayWithdrawals_revertsWhen_notRelay() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 4);

        // Act / Assert
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.simulateGatewayWithdrawals(_withdrawalArr1(w), _slotArr1(slot));
    }

    function test_simulateGatewayWithdrawals_minOutShortfallIsFatal() public {
        // Arrange
        (UnderpayingGateway hardGateway, uint16 idOutput) = _deployUnderpayingGateway(1 ether);
        Withdrawal memory w = Withdrawal({to: address(hardGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _underpayingSlot(0, idOutput, 2 ether, RC, 5);

        // Act / Assert
        _expectGatewaySimulationFatal(_withdrawalArr1(w), _slotArr1(slot), IPrivacyBoost.OutputBelowMin.selector);
    }

    function test_simulateGatewayWithdrawals_invalidGatewaySlotIsFatal() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(0, 100 ether, 1, RC, 6);
        slot.callData = hex"1234";

        // Act / Assert
        _expectGatewaySimulationFatal(_withdrawalArr1(w), _slotArr1(slot), IPrivacyBoost.InvalidGatewaySlot.selector);
    }

    function test_simulateGatewayWithdrawals_laterMinOutShortfallIsFatal() public {
        // Arrange
        (UnderpayingGateway hardGateway, uint16 idOutput) = _deployUnderpayingGateway(1 ether);
        Withdrawal memory w0 = Withdrawal({to: address(hardGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory w1 = Withdrawal({to: address(hardGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot0 = _underpayingSlot(0, idOutput, 1 ether, RC, 7);
        GatewaySlot memory slot1 = _underpayingSlot(1, idOutput, 2 ether, RC, 8);

        // Act / Assert
        _expectGatewaySimulationFatal(
            _withdrawalArr2(w0, w1), _slotArr2(slot0, slot1), IPrivacyBoost.OutputBelowMin.selector
        );
    }

    function test_simulateGatewayWithdrawals_minOutFatalRollsBackBeforeLaterPlainRevert() public {
        // Arrange
        (UnderpayingGateway hardGateway, uint16 idOutput) = _deployUnderpayingGateway(1 ether);
        Withdrawal memory gateway = Withdrawal({to: address(hardGateway), tokenId: idUsdc, amount: 100 ether});
        Withdrawal memory plain = Withdrawal({to: user, tokenId: idUsdc, amount: type(uint96).max});
        GatewaySlot memory slot = _underpayingSlot(0, idOutput, 2 ether, RC, 9);
        uint256 userUsdcBefore = usdc.balanceOf(user);
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));

        // Act / Assert
        _expectGatewaySimulationFatal(
            _withdrawalArr2(gateway, plain), _slotArr1(slot), IPrivacyBoost.OutputBelowMin.selector
        );

        // Assert
        assertEq(usdc.balanceOf(user), userUsdcBefore);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore);
    }

    function test_submitEpoch_minOutShortfallRevertsBatch() public {
        // Arrange
        (UnderpayingGateway hardGateway, uint16 idOutput) = _deployUnderpayingGateway(1 ether);
        Withdrawal memory w = Withdrawal({to: address(hardGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _underpayingSlot(0, idOutput, 2 ether, RC, 11);
        uint256 poolInputBefore = usdc.balanceOf(address(pool));

        SubmitArgs memory args = _prepareSingleWithdrawal(w);

        // Act / Assert
        vm.expectRevert(IPrivacyBoost.OutputBelowMin.selector);
        _callSubmit(args, _slotArr1(slot));
        assertEq(usdc.balanceOf(address(pool)), poolInputBefore);
        assertEq(pool.depositNonces(address(hardGateway)), 0);
    }

    function test_simulateGatewayWithdrawals_plainWithdrawalAffectsLaterGatewaySlot() public {
        // Arrange
        Withdrawal memory plain = Withdrawal({to: user, tokenId: idUsdc, amount: 9950 ether});
        Withdrawal memory gateway = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _erc4626DepositSlot(1, 100 ether, 1, RC, 10);
        uint256 userUsdcBefore = usdc.balanceOf(user);
        uint256 poolUsdcBefore = usdc.balanceOf(address(pool));

        // Act
        (GatewaySettlementOutcome[] memory outcomes,,,) =
            _simulateGatewayWithdrawals(_withdrawalArr2(plain, gateway), _slotArr1(slot));

        // Assert
        assertEq(uint8(outcomes[0]), uint8(GatewaySettlementOutcome.Fallback));
        assertEq(usdc.balanceOf(user), userUsdcBefore);
        assertEq(usdc.balanceOf(address(pool)), poolUsdcBefore);
    }

    function test_simulateGatewayWithdrawals_maxConfiguredGatewaySlots_useScaledReserve() public {
        // Arrange. The largest registered epoch circuit has 100 transfer slots.
        uint16 slotCount = 100;
        Withdrawal[] memory withdrawals = new Withdrawal[](slotCount);
        GatewaySlot[] memory slots = new GatewaySlot[](slotCount);
        vm.roll(1_000);
        for (uint16 i = 0; i < slotCount; ++i) {
            uint96 amount = uint96(i) + 1;
            withdrawals[i] = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: amount});
            slots[i] = _erc4626DepositSlot(i, amount, 1, RC, uint256(i) + 100);
            slots[i].expiryBlock = 999;
        }

        // Act
        (GatewaySettlementOutcome[] memory outcomes,,,) = _simulateGatewayWithdrawals(withdrawals, slots);

        // Assert
        assertEq(outcomes.length, slotCount);
        for (uint16 i = 0; i < slotCount; ++i) {
            assertEq(uint8(outcomes[i]), uint8(GatewaySettlementOutcome.Fallback));
        }
        assertEq(pool.depositNonces(address(externalGateway)), 0, "simulation state rolled back");
    }

    function _withdrawalArr1(Withdrawal memory w) internal pure returns (Withdrawal[] memory arr) {
        arr = new Withdrawal[](1);
        arr[0] = w;
    }

    function _deployUnderpayingGateway(uint256 outputAmount)
        internal
        returns (UnderpayingGateway hardGateway, uint16 idOutput)
    {
        MockERC20 output = new MockERC20();
        idOutput = tokenRegistry.register(TOKEN_TYPE_ERC20, address(output), 0);
        hardGateway =
            new UnderpayingGateway(address(pool), IERC20(address(usdc)), IERC20(address(output)), outputAmount);
        output.mint(address(hardGateway), 10_000 ether);
        pool.setGatewayRoute(address(hardGateway), GatewayRoute.Sync);
    }

    function _underpayingSlot(
        uint16 withdrawalIndex,
        uint16 outputTokenId,
        uint96 minOut,
        bytes32 rescueCommitment,
        uint256 seed
    ) internal view returns (GatewaySlot memory) {
        bytes memory callData = hex"12345678";
        return GatewaySlot({
            withdrawalIndex: withdrawalIndex,
            action: GatewayAction.ExternalCall,
            expiryBlock: uint64(block.number + 100),
            target: address(pool),
            callData: callData,
            receipt: _makeReceipt(outputTokenId, minOut, rescueCommitment, seed),
            fallbackReceipt: _makeFallbackReceipt(idUsdc, rescueCommitment, seed + 10_000)
        });
    }

    function _simulateGatewayWithdrawals(Withdrawal[] memory withdrawals, GatewaySlot[] memory slots)
        internal
        returns (
            GatewaySettlementOutcome[] memory outcomes,
            bytes32[] memory receiptHashes,
            bytes4[] memory failureSelectors,
            bytes[] memory failureReasons
        )
    {
        vm.prank(relayer);
        try pool.simulateGatewayWithdrawals(withdrawals, slots) {
            fail("simulateGatewayWithdrawals must revert with outcomes");
        } catch (bytes memory reason) {
            assertEq(_selector(reason), IPrivacyBoost.GatewaySimulationOutcomes.selector);
            (outcomes, receiptHashes, failureSelectors, failureReasons) =
                abi.decode(_stripSelector(reason), (GatewaySettlementOutcome[], bytes32[], bytes4[], bytes[]));
        }
    }

    function _expectGatewaySimulationFatal(
        Withdrawal[] memory withdrawals,
        GatewaySlot[] memory slots,
        bytes4 expectedInnerSelector
    ) internal {
        vm.prank(relayer);
        try pool.simulateGatewayWithdrawals(withdrawals, slots) {
            fail("simulateGatewayWithdrawals must revert");
        } catch (bytes memory reason) {
            assertEq(_selector(reason), IPrivacyBoost.GatewayExecutionFailed.selector);
            bytes memory inner = abi.decode(_stripSelector(reason), (bytes));
            assertEq(_selector(inner), expectedInnerSelector);
        }
    }

    function _selector(bytes memory reason) internal pure returns (bytes4 selector) {
        require(reason.length >= 4, "short revert data");
        assembly ("memory-safe") {
            selector := mload(add(reason, 32))
        }
    }

    function _stripSelector(bytes memory reason) internal pure returns (bytes memory payload) {
        require(reason.length >= 4, "short revert data");
        payload = new bytes(reason.length - 4);
        for (uint256 i = 4; i < reason.length; ++i) {
            payload[i - 4] = reason[i];
        }
    }
}

contract UnderpayingGateway {
    address immutable POOL;
    IERC20 immutable INPUT_TOKEN;
    IERC20 immutable OUTPUT_TOKEN;
    uint256 immutable OUTPUT_AMOUNT;

    error NotPool();

    constructor(address pool_, IERC20 inputToken_, IERC20 outputToken_, uint256 outputAmount_) {
        POOL = pool_;
        INPUT_TOKEN = inputToken_;
        OUTPUT_TOKEN = outputToken_;
        OUTPUT_AMOUNT = outputAmount_;
    }

    function executeGatewayCall(
        uint16,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        GatewaySlot calldata
    ) external {
        if (msg.sender != POOL) revert NotPool();
        require(inputToken == address(INPUT_TOKEN), "wrong input token");
        require(outputToken == address(OUTPUT_TOKEN), "wrong output token");
        require(INPUT_TOKEN.transferFrom(POOL, address(this), inputAmount), "pull failed");
        require(OUTPUT_TOKEN.transfer(POOL, OUTPUT_AMOUNT), "output failed");
    }
}
