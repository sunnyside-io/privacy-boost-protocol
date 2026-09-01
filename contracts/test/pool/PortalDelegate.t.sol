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
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";

import {PortalDelegate} from "src/PortalDelegate.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {IWETH} from "src/interfaces/IWETH.sol";
import {MockWETH} from "src/testnet/MockWETH.sol";
import {MockERC20} from "test/helpers/Mocks.sol";

/// @dev Minimal stand-in for the pool's portal-facing surface, isolating the delegate's sweep access control
///      from the full pool. `sweepPortal` reproduces the pool's caller context for the sweep push (the call
///      into `E` originates from the pool), so the delegate's OnlyPool gate is exercised with the right
///      `msg.sender`. The owner binding now lives in the delegate's OWN account storage (initializePortal /
///      portalBinding), so this stand-in records no bindings — it only stands in as the sweep caller.
contract MockPortalPool {
    function sweepPortal(address E, address token, uint256 cap) external {
        IPortalSweepSource(E).sweep(token, cap);
    }
}

/// @dev Unit tests for the shared EIP-7702 PortalDelegate in isolation: a fresh EOA is delegated to the impl
///      (`vm.signAndAttachDelegation`) and exercised as the portal `E`. The pool-integration paths
///      (requestPortalDeposit / sweep epoch / cancel) are covered separately against the real pool.
contract PortalDelegateTest is Test {
    MockPortalPool pool;
    PortalDelegate delegateImpl;
    MockERC20 token;
    MockWETH weth;

    uint256 constant EOA_PK = 0xA11CE;
    address eoa;

    address attacker = makeAddr("attacker");
    address rescueDest = makeAddr("rescueDest");

    uint256 constant H = 0xB14D;
    uint256 constant AMOUNT = 1000 ether;
    uint256 constant CAP = type(uint96).max; // the pool's uint96 record ceiling

    // Mirrors PortalDelegate.NATIVE_GAS_RESERVE, which is private so the dedicated deposit account exposes no
    // getter for it. Kept as a named constant here so a change to the floor fails these tests loudly.
    uint256 constant RESERVE = 0.001 ether;

    function setUp() public {
        pool = new MockPortalPool();
        token = new MockERC20();
        weth = new MockWETH();
        delegateImpl = new PortalDelegate(IPrivacyBoost(address(pool)), IWETH(address(weth)));

        // Make the EOA a portal: delegate its code to the shared PortalDelegate impl (EIP-7702).
        eoa = vm.addr(EOA_PK);
        vm.signAndAttachDelegation(address(delegateImpl), EOA_PK);
    }

    function test_initializePortal_recordsBindingViaSelfCall() public {
        vm.prank(eoa);
        PortalDelegate(payable(eoa)).initializePortal(H);

        assertEq(PortalDelegate(payable(eoa)).portalBinding(), H, "binding recorded in the EOA's own account storage");
        assertGt(eoa.code.length, 0, "delegation designator installed on the EOA");
        assertEq(EIP7702Utils.fetchDelegate(eoa), address(delegateImpl), "EOA delegates to the impl");
    }

    function test_revertWhen_initializePortalFromNonSelf() public {
        // A third party calling the EOA's delegated initializePortal: msg.sender is the attacker, not E.
        vm.prank(attacker);
        vm.expectRevert(PortalDelegate.OnlySelf.selector);
        PortalDelegate(payable(eoa)).initializePortal(H);
    }

    function test_sweep_pushesMinBalanceCapToPool() public {
        token.mint(eoa, AMOUNT);

        pool.sweepPortal(eoa, address(token), CAP);

        assertEq(token.balanceOf(address(pool)), AMOUNT, "balance swept to the pool");
        assertEq(token.balanceOf(eoa), 0, "portal EOA drained");
    }

    function test_sweep_wrapsNativeEthAndPushesWethToPool() public {
        // Arrange
        uint256 amount = 10 ether;
        vm.deal(eoa, amount);

        // Act
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(
            weth.balanceOf(address(pool)), amount - RESERVE, "pool received wrapped native value above the reserve"
        );
        assertEq(weth.balanceOf(eoa), 0, "portal WETH fully swept");
        assertEq(eoa.balance, RESERVE, "portal kept the native gas reserve");
    }

    function test_sweep_combinesExistingWethAndEthWithoutExceedingCap() public {
        // Arrange
        uint256 existingWeth = 3 ether;
        uint256 nativeAmount = 5 ether;
        uint256 cap = 6 ether;
        weth.mint(eoa, existingWeth);
        vm.deal(eoa, nativeAmount);

        // Act
        pool.sweepPortal(eoa, address(weth), cap);

        // Assert
        assertEq(weth.balanceOf(address(pool)), cap, "pool received exactly the cap");
        assertEq(weth.balanceOf(eoa), 0, "all portal WETH moved under the cap");
        assertEq(eoa.balance, 2 ether, "native value above the remaining cap stayed at the portal");
    }

    function test_sweep_leavesNativeEthAboveCapForLaterSweep() public {
        // Arrange
        uint256 cap = 4 ether;
        uint256 remainder = 2 ether;
        vm.deal(eoa, cap + remainder);

        // Act
        pool.sweepPortal(eoa, address(weth), cap);

        // Assert
        assertEq(weth.balanceOf(address(pool)), cap, "pool received exactly the capped amount");
        assertEq(eoa.balance, remainder, "native remainder stayed at the portal");
    }

    function test_sweep_nonWethDoesNotWrapNativeEth() public {
        // Arrange
        uint256 tokenAmount = 7 ether;
        uint256 nativeAmount = 3 ether;
        token.mint(eoa, tokenAmount);
        vm.deal(eoa, nativeAmount);

        // Act
        pool.sweepPortal(eoa, address(token), CAP);

        // Assert
        assertEq(token.balanceOf(address(pool)), tokenAmount, "non-WETH token swept normally");
        assertEq(eoa.balance, nativeAmount, "non-WETH sweep left native ETH untouched");
        assertEq(weth.balanceOf(address(pool)), 0, "non-WETH sweep minted no WETH");
    }

    /// @dev The sweep credits the deposited amount directly instead of re-reading the WETH balance, so this is
    ///      the test that keeps an under-minting wrapped-native token from over-pushing: the transfer of the
    ///      credited amount exceeds what was actually minted and reverts the whole sweep atomically.
    function test_revertWhen_sweepWethMintsLessThanDeposited() public {
        // Arrange
        uint256 amount = 2 ether;
        vm.deal(eoa, amount);
        weth.setDepositBehavior(MockWETH.DepositBehavior.UnderMint);

        // Act
        vm.expectRevert();
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(eoa.balance, amount, "revert restored the portal ETH balance");
        assertEq(weth.balanceOf(eoa), 0, "revert removed the short WETH mint");
        assertEq(weth.balanceOf(address(pool)), 0, "pool received no WETH");
    }

    /// @dev An over-minting wrapped-native token is not a loss case: the sweep pushes only the amount it
    ///      deposited, so any surplus stays at the portal where the owner's key can still reach it.
    function test_sweep_leavesSurplusAtPortalWhenWethOverMints() public {
        // Arrange
        uint256 amount = 2 ether;
        vm.deal(eoa, amount);
        weth.setDepositBehavior(MockWETH.DepositBehavior.OverMint);
        uint256 wrapped = amount - RESERVE;

        // Act
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(weth.balanceOf(address(pool)), wrapped, "pool received exactly the deposited amount");
        assertEq(weth.balanceOf(eoa), 1, "the over-minted surplus stayed at the portal");
        assertEq(eoa.balance, RESERVE, "the native reserve was still withheld");
    }

    function test_revertWhen_sweepWethDepositFails() public {
        // Arrange
        uint256 amount = 2 ether;
        vm.deal(eoa, amount);
        weth.setDepositBehavior(MockWETH.DepositBehavior.Revert);

        // Act
        vm.expectRevert(MockWETH.DepositFailed.selector);
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(eoa.balance, amount, "failed deposit left portal ETH untouched");
        assertEq(weth.balanceOf(address(pool)), 0, "failed deposit transferred no WETH");
    }

    function test_revertWhen_sweepFromNonPool() public {
        token.mint(eoa, AMOUNT);

        vm.prank(attacker);
        vm.expectRevert(PortalDelegate.OnlyPool.selector);
        PortalDelegate(payable(eoa)).sweep(address(token), CAP);
    }

    /// @dev The griefing case the reserve exists for: `requestPortalDeposit` is permissionless, so a third
    ///      party can sweep the moment a gas top-up lands. The reserve must survive an unbounded-cap sweep,
    ///      and must keep surviving repeated sweeps, or the owner can never fund a self-call again.
    function test_sweep_withholdsNativeGasReserveFromUncappedSweep() public {
        // Arrange
        vm.deal(eoa, 10 ether);

        // Act
        vm.prank(attacker);
        pool.sweepPortal(eoa, address(weth), CAP);
        vm.prank(attacker);
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(eoa.balance, RESERVE, "repeated uncapped sweeps cannot take the portal below the reserve");
        assertEq(weth.balanceOf(address(pool)), 10 ether - RESERVE, "everything above the reserve was swept");
    }

    function test_sweep_wrapsNothingWhenNativeAtOrBelowReserve() public {
        // Arrange
        vm.deal(eoa, RESERVE);

        // Act
        pool.sweepPortal(eoa, address(weth), CAP);

        // Assert
        assertEq(eoa.balance, RESERVE, "a balance at the reserve is left untouched");
        assertEq(weth.balanceOf(address(pool)), 0, "nothing was wrapped or pushed");
    }

    /// @dev The withheld reserve needs no dedicated exit: `E` is the owner's own EOA, and a 7702 designator
    ///      only changes what runs when `E` is called, so the key still originates an ordinary native transfer.
    function test_sweep_leavesReserveSpendableByTheOwnersOwnKey() public {
        // Arrange
        vm.deal(eoa, 10 ether);
        pool.sweepPortal(eoa, address(weth), CAP);
        assertEq(eoa.balance, RESERVE, "sweep left exactly the reserve");

        // Act
        vm.prank(eoa);
        (bool ok,) = rescueDest.call{value: RESERVE}("");

        // Assert
        assertTrue(ok, "the portal EOA can still originate a native transfer while delegated");
        assertEq(rescueDest.balance, RESERVE, "reserve reclaimed to the owner's destination");
        assertEq(eoa.balance, 0, "portal native balance drained");
    }

    function test_withdraw_rescuesRestingFundsViaSelfCall() public {
        token.mint(eoa, AMOUNT);

        vm.prank(eoa);
        PortalDelegate(payable(eoa)).withdraw(address(token), rescueDest, AMOUNT);

        assertEq(token.balanceOf(rescueDest), AMOUNT, "resting funds withdrawn to destination");
        assertEq(token.balanceOf(eoa), 0, "portal EOA drained");
    }

    function test_revertWhen_withdrawFromNonSelf() public {
        token.mint(eoa, AMOUNT);

        vm.prank(attacker);
        vm.expectRevert(PortalDelegate.OnlySelf.selector);
        PortalDelegate(payable(eoa)).withdraw(address(token), rescueDest, AMOUNT);
    }

    function test_revertWhen_withdrawToZero() public {
        token.mint(eoa, AMOUNT);

        vm.prank(eoa);
        vm.expectRevert(PortalDelegate.ZeroAddress.selector);
        PortalDelegate(payable(eoa)).withdraw(address(token), address(0), AMOUNT);
    }

    function test_receive_acceptsValueCall() public {
        // Arrange
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        // Act
        vm.expectEmit(false, false, false, true, eoa);
        emit PortalDelegate.PortalETHReceived(amount);
        (bool success,) = payable(eoa).call{value: amount}("");

        // Assert
        assertTrue(success, "value-bearing empty call accepted");
        assertEq(eoa.balance, amount, "portal received the exact ETH value");
    }

    function test_receive_acceptsSendWithEvent() public {
        // Arrange
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        // Act
        vm.expectEmit(false, false, false, true, eoa);
        emit PortalDelegate.PortalETHReceived(amount);
        bool success = payable(eoa).send(amount);

        // Assert
        assertTrue(success, "send succeeded within the stipend");
        assertEq(eoa.balance, amount, "send delivered the exact ETH value");
    }

    function test_receive_acceptsZeroValueEmptyCall() public {
        // Arrange
        uint256 balanceBefore = eoa.balance;

        // Act
        (bool success,) = eoa.call("");

        // Assert
        assertTrue(success, "zero-value empty call accepted");
        assertEq(eoa.balance, balanceBefore, "zero-value call did not change the portal balance");
    }

    function test_receive_acceptsTransfer() public {
        // Arrange
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        // Act
        vm.expectEmit(false, false, false, true, eoa);
        emit PortalDelegate.PortalETHReceived(amount);
        payable(eoa).transfer(amount);

        // Assert
        assertEq(eoa.balance, amount, "transfer delivered the exact ETH value");
    }

    function test_revertWhen_receiveCalledOnImplementation() public {
        // Arrange
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        // Act
        (bool success,) = payable(address(delegateImpl)).call{value: amount}("");

        // Assert
        assertFalse(success, "direct implementation transfer rejected");
        assertEq(address(delegateImpl).balance, 0, "implementation did not trap ETH");
    }

    function test_unknownCalldataRemainsRejected() public {
        // Arrange
        uint256 amount = 1 ether;
        vm.deal(address(this), amount);

        // Act
        (bool success,) = payable(eoa).call{value: amount}(hex"deadbeef");

        // Assert
        assertFalse(success, "unknown non-empty calldata rejected");
        assertEq(eoa.balance, 0, "rejected call did not transfer ETH");
    }

    function test_revertWhen_constructorZeroPool() public {
        vm.expectRevert(PortalDelegate.ZeroAddress.selector);
        new PortalDelegate(IPrivacyBoost(address(0)), IWETH(address(weth)));
    }

    function test_revertWhen_constructorZeroWrappedNativeToken() public {
        vm.expectRevert(PortalDelegate.ZeroAddress.selector);
        new PortalDelegate(IPrivacyBoost(address(pool)), IWETH(address(0)));
    }

    function test_revertWhen_constructorWrappedNativeTokenHasNoCode() public {
        vm.expectRevert(PortalDelegate.WrappedNativeTokenHasNoCode.selector);
        new PortalDelegate(IPrivacyBoost(address(pool)), IWETH(makeAddr("codeLessWeth")));
    }
}
