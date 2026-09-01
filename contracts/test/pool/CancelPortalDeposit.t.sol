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
import {StdStorage, stdStorage} from "forge-std/StdStorage.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {MockERC20, MockVerifier, BindablePortal} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

/// @dev The minimal portal stand-in used to escrow a record via the real sweep path, so cancel tests
///      operate on a genuinely-written portalPendingDeposits record rather than a vm.store fabrication.
///      On sweep it pushes min(balance, cap) of the token to the caller (the pool) — the sweep push
///      shape requestPortalDeposit measures the received delta against.
contract PortalSweepSourceMock is BindablePortal, IPortalSweepSource {
    function sweep(address token, uint256 cap) external override {
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 amount = bal < cap ? bal : cap;
        IERC20(token).transfer(msg.sender, amount);
    }
}

/// @dev Behavior coverage for cancelPortalDeposit (the reclaim / liveness backstop). Every
///      test asserts an observable outcome that flips if the entrypoint or one of its guards is deleted,
///      never a bare "didn't revert". Load-bearing properties proven here:
///        - after cancelDelay the FULL GROSS amount is refunded to the portal E (never net, never the
///          caller) and the record is deleted + marked processed;
///        - before the delay the reclaim reverts (CancelTooEarly);
///        - a non-existent / already-reclaimed / already-credited record reverts, so no double-spend and
///          no double-refund are possible;
///        - reclaim is permissionless — any caller triggers it but the refund still routes to E.
///
///      Reentrancy note: the cancel refund is a plain IERC20.safeTransfer to E. A standard ERC-20 invokes
///      no recipient callback, so reentrancy is not reachable through the real-token refund path; the
///      nonReentrant guard is the same modifier proven load-bearing against the sweep-push callback in
///      RequestPortalDeposit.t.sol (test_requestPortalDeposit_revertWhen_reentrantPortal), applied
///      uniformly to all three portal entrypoints. A separate "didn't re-enter" test against a
///      non-callback token would be vacuous, so it is intentionally omitted.
contract CancelPortalDepositTest is Test {
    using stdStorage for StdStorage;

    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address keeper = makeAddr("keeper");
    address anyone = makeAddr("anyone");

    PortalSweepSourceMock portal;
    address E; // the portal address == address(portal)

    uint16 tokenId;
    uint256 constant H = 0xB14D; // the registered owner binding for the portal
    uint256 cancelDelay;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
        cancelDelay = pool.cancelDelay();

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        portal = new PortalSweepSourceMock();
        E = address(portal);
        portal.initializePortal(H);
    }

    /// @dev Escrow a record by funding E and sweeping; returns the recorded portalDepositId and amount.
    function _escrow(uint96 amount) internal returns (uint256 id) {
        token.mint(E, amount);
        vm.prank(keeper);
        id = pool.requestPortalDeposit(E, tokenId);
    }

    /// @dev Roll past the cancel delay so a reclaim is permitted (requestBlock was the current block).
    function _passDelay() internal {
        vm.roll(block.number + cancelDelay);
    }

    // ========== Happy path: gross refunded to E after the delay ==========

    /// @dev After the delay, cancel refunds the FULL GROSS amount to the portal E, deletes the record, and
    ///      marks it processed, emitting PortalDepositCancelled. This is the core reclaim behavior; deleting
    ///      the entrypoint, refunding the wrong target, or skipping the delete each fail an assertion below.
    function test_cancelPortalDeposit_refundsGrossToEAfterDelay() public {
        uint96 amount = 1000 ether;
        uint256 id = _escrow(amount);

        // Pool holds the escrow; E is empty after the sweep.
        assertEq(token.balanceOf(address(pool)), amount, "pool holds the escrow before cancel");
        assertEq(token.balanceOf(E), 0, "E emptied by the sweep");

        _passDelay();

        vm.expectEmit(true, false, false, false, address(pool));
        emit IPrivacyBoost.PortalDepositCancelled(id);

        vm.prank(keeper);
        pool.cancelPortalDeposit(id);

        // The gross amount returned to E (the portal), not stayed in the pool and not to the caller.
        assertEq(token.balanceOf(E), amount, "full gross refunded to E");
        assertEq(token.balanceOf(address(pool)), 0, "pool no longer holds the escrow");
        assertEq(token.balanceOf(keeper), 0, "refund did not go to the caller");

        // The record is deleted (portal zeroed) and marked processed.
        (address recPortal,,,,, uint96 recAmount,,) = pool.portalPendingDeposits(id);
        assertEq(recPortal, address(0), "record deleted");
        assertEq(recAmount, 0, "record amount cleared");
        assertTrue(pool.processedPortalDeposits(id), "record marked processed");
    }

    /// @dev The refund is the GROSS amount, not the net (gross minus fee). A fee snapshotted at sweep time
    ///      must NOT be deducted on a reclaim — the fee only ever accrues when an epoch credits the note, so
    ///      an uncredited record owes nothing. Sweep with a 5% fee snapshotted, cancel, and assert the full
    ///      gross is refunded. A net-refund regression (subtracting the fee) would leave the fee stranded.
    function test_cancelPortalDeposit_refundsGrossNotNetWhenFeeSet() public {
        pool.setPortalSweepFeeBps(500); // 5%

        uint96 amount = 1000 ether;
        uint256 id = _escrow(amount);

        // Confirm the record really did snapshot a non-zero fee, so this test would catch a net refund.
        (,,, uint16 recFee,,,,) = pool.portalPendingDeposits(id);
        assertEq(recFee, 500, "fee snapshotted into the record");

        _passDelay();
        vm.prank(anyone);
        pool.cancelPortalDeposit(id);

        assertEq(token.balanceOf(E), amount, "gross (not gross-minus-fee) refunded to E");
        assertEq(token.balanceOf(address(pool)), 0, "no fee retained by the pool on a reclaim");
    }

    // ========== Boundary: the cancel delay ==========

    /// @dev Before the delay elapses the reclaim reverts with CancelTooEarly and the record is untouched —
    ///      the escrow is not refundable while the relay could still finalize the epoch. Removing the delay
    ///      guard would let a reclaim race a pending epoch credit.
    function test_cancelPortalDeposit_revertWhen_beforeDelay() public {
        uint96 amount = 100 ether;
        uint256 id = _escrow(amount);

        // One block short of the delay window.
        vm.roll(block.number + cancelDelay - 1);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.CancelTooEarly.selector);
        pool.cancelPortalDeposit(id);

        // Untouched: still escrowed, not processed, funds still in the pool.
        (address recPortal,,,,,,,) = pool.portalPendingDeposits(id);
        assertEq(recPortal, E, "record intact after the too-early revert");
        assertFalse(pool.processedPortalDeposits(id), "not marked processed");
        assertEq(token.balanceOf(address(pool)), amount, "escrow still held by the pool");
    }

    /// @dev Exactly at the delay boundary (requestBlock + cancelDelay) the reclaim succeeds — the guard is
    ///      block.number < requestBlock + cancelDelay (strict), so the boundary block is allowed. Pins the
    ///      off-by-one against the too-early test one block earlier.
    function test_cancelPortalDeposit_atDelayBoundary() public {
        uint96 amount = 100 ether;
        uint256 id = _escrow(amount);

        vm.roll(block.number + cancelDelay); // exactly requestBlock + cancelDelay

        vm.prank(keeper);
        pool.cancelPortalDeposit(id);

        assertEq(token.balanceOf(E), amount, "reclaim succeeds at the exact boundary block");
    }

    // ========== Reverts: non-existent record ==========

    /// @dev Cancelling an id that was never swept reverts with InvalidDeposit (the existence guard), so a
    ///      fabricated id cannot drain a zero record or emit a phantom cancellation. Removing the
    ///      portal==0 guard would let a non-existent record be "refunded" (a zero transfer + event).
    function test_cancelPortalDeposit_revertWhen_nonExistent() public {
        uint256 bogusId = uint256(keccak256("never-swept"));
        _passDelay(); // delay alone must not make a non-existent record cancellable

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.cancelPortalDeposit(bogusId);
    }

    // ========== Reverts: double cancel ==========

    /// @dev A second cancel of the same record reverts with PortalDepositAlreadyProcessed — the first
    ///      cancel set the processed flag (which survives the record delete), so the funds cannot be
    ///      refunded twice. Without the processed flag the deleted record would revert with the existence
    ///      error instead; this test pins the exact already-processed selector AND that no extra refund
    ///      occurred. Either deleting the processed-set or the processed-check would change the outcome.
    function test_cancelPortalDeposit_revertWhen_doubleCancel() public {
        uint96 amount = 250 ether;
        uint256 id = _escrow(amount);
        _passDelay();

        vm.prank(keeper);
        pool.cancelPortalDeposit(id);
        assertEq(token.balanceOf(E), amount, "first cancel refunded the gross");

        // Second cancel must revert on the processed flag, not silently double-refund.
        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.PortalDepositAlreadyProcessed.selector);
        pool.cancelPortalDeposit(id);

        assertEq(token.balanceOf(E), amount, "no second refund: E balance unchanged after the revert");
    }

    // ========== Reverts: cancel after the epoch already credited ==========

    /// @dev A record already credited by submitPortalDepositEpoch cannot be reclaimed. The epoch sets
    ///      processedPortalDeposits[id] = true but does NOT delete the record, so the existence guard would
    ///      still pass — it is the processed guard that blocks the credit-then-reclaim double-spend. Mirror
    ///      that exact post-epoch state (processed = true, record intact) via stdstore and assert the cancel
    ///      reverts with PortalDepositAlreadyProcessed, EVEN after the delay has elapsed. Deleting the
    ///      processed check (relying only on existence) would let a credited deposit be refunded a second
    ///      time — the very double-spend this guard prevents.
    function test_cancelPortalDeposit_revertWhen_alreadyCredited() public {
        uint96 amount = 300 ether;
        uint256 id = _escrow(amount);

        // Reproduce the state submitPortalDepositEpoch leaves: processed set, record NOT deleted.
        stdstore.target(address(pool)).sig("processedPortalDeposits(uint256)").with_key(id).checked_write(true);
        assertTrue(pool.processedPortalDeposits(id), "simulated credited state: processed = true");
        (address recPortal,,,,,,,) = pool.portalPendingDeposits(id);
        assertEq(recPortal, E, "simulated credited state: record still present (epoch does not delete)");

        _passDelay(); // even past the delay, a credited record stays un-reclaimable

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.PortalDepositAlreadyProcessed.selector);
        pool.cancelPortalDeposit(id);

        // No refund of an already-credited deposit: the pool keeps the escrow it credited.
        assertEq(token.balanceOf(address(pool)), amount, "credited escrow not refunded");
        assertEq(token.balanceOf(E), 0, "no refund to E for a credited record");
    }

    // ========== Permissionless: any caller reclaims, but funds route to E ==========

    /// @dev Reclaim is permissionless — a caller who is neither the keeper nor the owner triggers it — and
    ///      the refund always routes to E, never to the caller. This is the liveness backstop: anyone may
    ///      free stranded funds on the owner's behalf. A caller restriction (mirroring cancelDeposit's
    ///      NotDepositor gate) would revert this, and a refund-to-msg.sender bug would send the funds to the
    ///      wrong address.
    function test_cancelPortalDeposit_permissionlessButRefundsE() public {
        uint96 amount = 500 ether;
        uint256 id = _escrow(amount);
        _passDelay();

        // A random third party triggers the reclaim.
        vm.prank(anyone);
        pool.cancelPortalDeposit(id);

        assertEq(token.balanceOf(E), amount, "funds returned to E regardless of who called");
        assertEq(token.balanceOf(anyone), 0, "the triggering caller receives nothing");
    }
}
