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
import {ExternalCallGateway} from "src/gateway/ExternalCallGateway.sol";
import {GatewayAction, GatewayRoute, GatewaySlot, Withdrawal} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {SPENDABLE_NPK_FLOOR, TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {MockERC20} from "test/helpers/Mocks.sol";

contract MockExternalSwapTarget {
    error TargetReverted();

    function swapExactInput(
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        address recipient,
        bool shouldRevert
    ) external {
        if (shouldRevert) revert TargetReverted();
        IERC20(inputToken).transferFrom(msg.sender, address(this), inputAmount);
        IERC20(outputToken).transfer(recipient, outputAmount);
    }

    function swapExactInputAndDonateInput(
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        address recipient,
        address pool,
        uint256 donationAmount
    ) external {
        IERC20(inputToken).transferFrom(msg.sender, address(this), inputAmount);
        IERC20(inputToken).transfer(pool, donationAmount);
        IERC20(outputToken).transfer(recipient, outputAmount);
    }
}

contract MockNonPullingGateway {
    function executeGatewayCall(uint16, address, address outputToken, uint256, GatewaySlot calldata slot) external {
        IERC20(outputToken).transfer(msg.sender, slot.receipt.minOutputAmount);
    }
}

contract GatewayExternalCallGatewayTest is GatewayBaseTest {
    bytes32 constant RC = keccak256("rc-external");

    MockExternalSwapTarget target;
    MockERC20 outputToken;
    uint16 idOutput;

    function setUp() public override {
        super.setUp();

        externalGateway = new ExternalCallGateway(address(pool), owner);
        target = new MockExternalSwapTarget();
        outputToken = new MockERC20();
        idOutput = tokenRegistry.register(TOKEN_TYPE_ERC20, address(outputToken), 0);

        outputToken.mint(address(target), 10_000 ether);
        _allowExternalGatewayPolicy(address(target), MockExternalSwapTarget.swapExactInput.selector, idUsdc, idOutput);
        _allowExternalGatewayPolicy(
            address(target), MockExternalSwapTarget.swapExactInputAndDonateInput.selector, idUsdc, idOutput
        );
        pool.setGatewayRoute(address(externalGateway), GatewayRoute.Sync);
    }

    function test_gatewayRouteManager_isIndependentFromOwner() public {
        address manager = makeAddr("route-manager");
        address anotherGateway = makeAddr("another-gateway");

        assertEq(pool.gatewayRouteManager(), owner);
        pool.setGatewayRouteManager(manager);

        vm.expectRevert(IPrivacyBoost.NotGatewayRouteManager.selector);
        pool.setGatewayRoute(anotherGateway, GatewayRoute.Sync);

        vm.prank(manager);
        pool.setGatewayRoute(anotherGateway, GatewayRoute.Sync);
        assertTrue(pool.gatewayRoute(anotherGateway) == GatewayRoute.Sync);
    }

    function test_setGatewayRouteManager_revertsForZeroAddress() public {
        vm.expectRevert(IPrivacyBoost.InvalidGatewayRouteManager.selector);
        pool.setGatewayRouteManager(address(0));
    }

    function test_setGatewayRouteManager_revertsForNonOwner() public {
        vm.prank(makeAddr("not-owner"));
        vm.expectRevert();
        pool.setGatewayRouteManager(makeAddr("route-manager"));
    }

    function test_policy_crud_and_enumeration() public {
        MockExternalSwapTarget otherTarget = new MockExternalSwapTarget();
        bytes4 selector = MockExternalSwapTarget.swapExactInput.selector;

        uint256 countBefore = externalGateway.policyKeyCount();

        externalGateway.setCallPolicy(
            address(otherTarget),
            selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput})
        );

        assertEq(externalGateway.policyKeyCount(), countBefore + 1);
        ExternalCallGateway.CallPolicy memory p = externalGateway.getCallPolicy(address(otherTarget), selector);
        assertTrue(p.allowed);
        assertEq(p.inputTokenId, idUsdc);
        assertEq(p.outputTokenId, idOutput);

        ExternalCallGateway.CallPolicyEntry memory last = externalGateway.policyEntryAt(countBefore);
        assertEq(last.target, address(otherTarget));
        assertEq(last.selector, selector);
        assertEq(last.policy.inputTokenId, idUsdc);

        ExternalCallGateway.CallPolicyEntry[] memory page = externalGateway.policyEntries(countBefore, 10);
        assertEq(page.length, 1);
        assertEq(page[0].target, address(otherTarget));

        externalGateway.removeCallPolicy(address(otherTarget), selector);
        assertEq(externalGateway.policyKeyCount(), countBefore);
        p = externalGateway.getCallPolicy(address(otherTarget), selector);
        assertFalse(p.allowed);
    }

    function test_policy_batch_set() public {
        MockExternalSwapTarget targetA = new MockExternalSwapTarget();
        MockExternalSwapTarget targetB = new MockExternalSwapTarget();
        address[] memory targets = new address[](2);
        targets[0] = address(targetA);
        targets[1] = address(targetB);
        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = MockExternalSwapTarget.swapExactInput.selector;
        selectors[1] = MockExternalSwapTarget.swapExactInputAndDonateInput.selector;
        ExternalCallGateway.CallPolicy[] memory policies = new ExternalCallGateway.CallPolicy[](2);
        policies[0] = ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput});
        policies[1] = ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput});

        externalGateway.setCallPolicies(targets, selectors, policies);

        assertTrue(externalGateway.getCallPolicy(address(targetA), selectors[0]).allowed);
        assertEq(externalGateway.getCallPolicy(address(targetB), selectors[1]).outputTokenId, idOutput);
    }

    function test_pause_guardianPausesAndOwnerUnpauses() public {
        // Arrange - guardian who may pause but not unpause
        address g = makeAddr("gateway-guardian");
        externalGateway.setGuardian(g);

        // Act - guardian pauses
        vm.prank(g);
        externalGateway.pause();

        // Assert - paused
        assertTrue(externalGateway.paused());

        // Act - owner unpauses
        externalGateway.unpause();

        // Assert - unpaused
        assertFalse(externalGateway.paused());
    }

    function test_sweepToPool_onlyWhilePausedAndOnlyToPool() public {
        // Arrange - dust stranded on the gateway by a direct transfer
        outputToken.mint(address(externalGateway), 5 ether);

        // Act/Assert - sweeping while live is rejected
        vm.expectRevert(ExternalCallGateway.NotPaused.selector);
        externalGateway.sweepToPool(address(outputToken));

        // Act - pause, then sweep
        externalGateway.pause();
        uint256 poolBefore = outputToken.balanceOf(address(pool));
        externalGateway.sweepToPool(address(outputToken));

        // Assert - dust moved to the pool, gateway drained
        assertEq(outputToken.balanceOf(address(pool)), poolBefore + 5 ether);
        assertEq(outputToken.balanceOf(address(externalGateway)), 0);
    }

    function test_revertWhen_sweepToPool_notOwner() public {
        externalGateway.pause();
        vm.prank(user);
        vm.expectRevert();
        externalGateway.sweepToPool(address(outputToken));
    }

    function test_revertWhen_policy_target_has_no_code() public {
        vm.expectRevert(ExternalCallGateway.InvalidCallPolicy.selector);
        externalGateway.setCallPolicy(
            makeAddr("codeless-target"),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput})
        );
    }

    function test_revertWhen_policy_upsert_notOwner() public {
        vm.prank(user);
        vm.expectRevert();
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput})
        );
    }

    function test_revertWhen_policy_upsert_denied_policy() public {
        vm.expectRevert(ExternalCallGateway.InvalidCallPolicy.selector);
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: false, inputTokenId: idUsdc, outputTokenId: idOutput})
        );
    }

    function test_policy_guardian_can_remove_but_not_add() public {
        address g = makeAddr("gateway-guardian");
        externalGateway.setGuardian(g);

        vm.prank(g);
        externalGateway.removeCallPolicy(address(target), MockExternalSwapTarget.swapExactInput.selector);
        assertFalse(
            externalGateway.getCallPolicy(address(target), MockExternalSwapTarget.swapExactInput.selector).allowed
        );

        vm.prank(g);
        vm.expectRevert();
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idOutput})
        );
    }

    function test_revertWhen_policy_denies_call() public {
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 100);
        externalGateway.removeCallPolicy(address(target), MockExternalSwapTarget.swapExactInput.selector);

        vm.prank(address(pool));
        vm.expectRevert(ExternalCallGateway.CallNotAllowed.selector);
        externalGateway.executeGatewayCall(idUsdc, address(usdc), address(outputToken), 100 ether, slot);
    }

    function test_revertWhen_policy_input_token_mismatch() public {
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 102);
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idOutput, outputTokenId: idOutput})
        );

        vm.prank(address(pool));
        vm.expectRevert(ExternalCallGateway.PolicyTokenMismatch.selector);
        externalGateway.executeGatewayCall(idUsdc, address(usdc), address(outputToken), 100 ether, slot);
    }

    function test_revertWhen_policy_output_token_mismatch() public {
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 103);
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: idUsdc, outputTokenId: idUsdc})
        );

        vm.prank(address(pool));
        vm.expectRevert(ExternalCallGateway.PolicyTokenMismatch.selector);
        externalGateway.executeGatewayCall(idUsdc, address(usdc), address(outputToken), 100 ether, slot);
    }

    function test_external_call_wildcardTokenIdsAllowRegisteredPair() public {
        // Arrange - install the contract-level wildcard policy defined by the gateway specification.
        externalGateway.setCallPolicy(
            address(target),
            MockExternalSwapTarget.swapExactInput.selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: 0, outputTokenId: 0})
        );
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 104);
        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        // Act - execute a registered token pair through the wildcard policy.
        _submitOneWithdrawal(w, _slotArr1(slot));

        // Assert - both wildcard fields remain installed and settlement succeeds.
        ExternalCallGateway.CallPolicy memory p =
            externalGateway.getCallPolicy(address(target), MockExternalSwapTarget.swapExactInput.selector);
        assertEq(p.inputTokenId, 0);
        assertEq(p.outputTokenId, 0);
        assertEq(usdc.balanceOf(address(pool)), poolInputBefore - 100 ether);
        assertEq(outputToken.balanceOf(address(pool)) - poolOutputBefore, 100 ether);
    }

    function test_external_call_happyPath() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 1);

        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore - 100 ether);
        assertEq(outputToken.balanceOf(address(pool)) - poolOutputBefore, 100 ether);
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
        assertEq(outputToken.balanceOf(address(externalGateway)), 0);
        assertEq(usdc.balanceOf(address(target)), 100 ether);
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "pool allowance consumed");
        assertEq(usdc.allowance(address(externalGateway), address(target)), 0, "target allowance consumed");
    }

    function test_revertWhen_gatewayDoesNotPullInput() public {
        // Arrange
        MockNonPullingGateway nonPullingGateway = new MockNonPullingGateway();
        outputToken.mint(address(nonPullingGateway), 95 ether);
        pool.setGatewayRoute(address(nonPullingGateway), GatewayRoute.Sync);

        Withdrawal memory w = Withdrawal({to: address(nonPullingGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 10);
        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));
        SubmitArgs memory args = _prepareSingleWithdrawal(w);

        // Act
        vm.expectRevert(IPrivacyBoost.InputDeltaMismatch.selector);
        _callSubmit(args, _slotArr1(slot));

        // Assert
        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "gateway did not pull input");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "gateway output rolled back");
        assertEq(usdc.allowance(address(pool), address(nonPullingGateway)), 0, "gateway allowance rolled back");
    }

    function test_external_call_targetRevertFallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, true, 2);

        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input preserved for fallback");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "no primary output credited");
        assertEq(usdc.balanceOf(address(target)), 0);
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "pool allowance cleared");
        assertEq(usdc.allowance(address(externalGateway), address(target)), 0, "target approval rolled back");
    }

    function test_external_call_minOutShortfallFallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 90 ether, 95 ether, false, 3);

        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input preserved for fallback");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "short output rolled back");
        assertEq(usdc.balanceOf(address(target)), 0);
        assertEq(usdc.allowance(address(pool), address(externalGateway)), 0, "pool allowance cleared");
        assertEq(usdc.allowance(address(externalGateway), address(target)), 0, "target approval rolled back");
    }

    function test_revertWhen_externalCallDonatesInputToPool() public {
        // Arrange
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalDonationSlot(0, 100 ether, 95 ether, 1, 4);
        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));
        SubmitArgs memory args = _prepareSingleWithdrawal(w);

        // Act
        vm.expectRevert(IPrivacyBoost.InputDeltaMismatch.selector);
        _callSubmit(args, _slotArr1(slot));

        // Assert
        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input movement rolled back");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "output movement rolled back");
        assertEq(usdc.balanceOf(address(externalGateway)), 0);
        assertEq(outputToken.balanceOf(address(externalGateway)), 0);
    }

    function test_external_call_expiredSameTokenPrimaryFallsBack() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 5);
        slot.receipt.outputTokenId = idUsdc;
        vm.roll(block.number + 200);
        slot.expiryBlock = uint64(block.number - 1);

        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input preserved for expired fallback");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "expired slot skipped primary call");
    }

    function test_external_call_shortCalldataRevertsBeforeFallback() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 4);
        slot.callData = hex"1234";

        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vm.expectRevert(IPrivacyBoost.InvalidGatewaySlot.selector);
        _callSubmit(args, _slotArr1(slot));
    }

    // A gateway-origin credit is the one deposit path where the pool itself builds the note
    // commitment from a caller-supplied key, so the reserved range has to be refused here. Without
    // this the credit appends normally and then fails every spend relation's range check.
    function test_external_call_revertWhen_primaryNpkInReservedRange() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 900);
        slot.receipt.npk = SPENDABLE_NPK_FLOOR - 1;

        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vm.expectRevert(IPrivacyBoost.InvalidGatewaySlot.selector);
        _callSubmit(args, _slotArr1(slot));
    }

    // The fallback receipt credits the same way when the external call does not settle, so it
    // carries the same guard rather than only the zero and field-bound checks.
    function test_external_call_revertWhen_fallbackNpkInReservedRange() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 901);
        slot.fallbackReceipt.npk = SPENDABLE_NPK_FLOOR - 1;

        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        vm.expectRevert(IPrivacyBoost.InvalidGatewaySlot.selector);
        _callSubmit(args, _slotArr1(slot));
    }

    // The boundary control: the floor itself is the smallest spendable key, so the guard must be a
    // range check rather than a blanket rejection of anything numerically small.
    function test_external_call_npkAtSpendableFloorIsAccepted() public {
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlot(0, 100 ether, 95 ether, false, 902);
        slot.receipt.npk = SPENDABLE_NPK_FLOOR;

        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertGt(outputToken.balanceOf(address(pool)), poolOutputBefore, "floor key settled the gateway credit");
    }

    function test_external_call_unconfigured_target_fallsBack() public {
        MockExternalSwapTarget unconfiguredTarget = new MockExternalSwapTarget();
        outputToken.mint(address(unconfiguredTarget), 10_000 ether);
        Withdrawal memory w = Withdrawal({to: address(externalGateway), tokenId: idUsdc, amount: 100 ether});
        GatewaySlot memory slot = _externalSlotForTarget(address(unconfiguredTarget), 0, 100 ether, 95 ether, false, 6);

        uint256 poolInputBefore = usdc.balanceOf(address(pool));
        uint256 poolOutputBefore = outputToken.balanceOf(address(pool));

        _submitOneWithdrawal(w, _slotArr1(slot));

        assertEq(usdc.balanceOf(address(pool)), poolInputBefore, "input preserved for fallback");
        assertEq(outputToken.balanceOf(address(pool)), poolOutputBefore, "no primary output credited");
        assertEq(usdc.balanceOf(address(unconfiguredTarget)), 0);
        assertEq(outputToken.balanceOf(address(externalGateway)), 0);
    }

    function _externalSlot(
        uint16 withdrawalIndex,
        uint96 targetOutputAmount,
        uint96 minOutputAmount,
        bool shouldRevert,
        uint256 seed
    ) internal view returns (GatewaySlot memory slot) {
        return _externalSlotForTarget(
            address(target), withdrawalIndex, targetOutputAmount, minOutputAmount, shouldRevert, seed
        );
    }

    function _externalSlotForTarget(
        address target_,
        uint16 withdrawalIndex,
        uint96 targetOutputAmount,
        uint96 minOutputAmount,
        bool shouldRevert,
        uint256 seed
    ) internal view returns (GatewaySlot memory slot) {
        bytes memory callData = abi.encodeCall(
            MockExternalSwapTarget.swapExactInput,
            (address(usdc), address(outputToken), 100 ether, targetOutputAmount, address(externalGateway), shouldRevert)
        );
        slot = GatewaySlot({
            withdrawalIndex: withdrawalIndex,
            action: GatewayAction.ExternalCall,
            expiryBlock: uint64(block.number + 100),
            target: target_,
            callData: callData,
            receipt: _makeReceipt(idOutput, minOutputAmount, RC, seed),
            fallbackReceipt: _makeFallbackReceipt(idUsdc, RC, seed + 10_000)
        });
    }

    function _externalDonationSlot(
        uint16 withdrawalIndex,
        uint96 targetOutputAmount,
        uint96 minOutputAmount,
        uint256 donationAmount,
        uint256 seed
    ) internal view returns (GatewaySlot memory slot) {
        bytes memory callData = abi.encodeCall(
            MockExternalSwapTarget.swapExactInputAndDonateInput,
            (
                address(usdc),
                address(outputToken),
                100 ether,
                targetOutputAmount,
                address(externalGateway),
                address(pool),
                donationAmount
            )
        );
        slot = GatewaySlot({
            withdrawalIndex: withdrawalIndex,
            action: GatewayAction.ExternalCall,
            expiryBlock: uint64(block.number + 100),
            target: address(target),
            callData: callData,
            receipt: _makeReceipt(idOutput, minOutputAmount, RC, seed),
            fallbackReceipt: _makeFallbackReceipt(idUsdc, RC, seed + 10_000)
        });
    }
}
