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
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {MockERC20, MockVerifier, BindablePortal} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

/// @dev A minimal stand-in for a portal sweep source. It implements the sweep push interface
///      the pool invokes: on sweep, it transfers min(its balance, cap) of the token to the caller
///      (the pool). Holding the funds here and pushing them on demand is exactly the shape
///      requestPortalDeposit measures the received delta against, so the test exercises the real
///      measured-delta accounting rather than faking the balance move.
contract PortalSweepSourceMock is BindablePortal, IPortalSweepSource {
    function sweep(address token, uint256 cap) external override {
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 amount = bal < cap ? bal : cap;
        IERC20(token).transfer(msg.sender, amount);
    }
}

/// @dev A non-compliant portal that IGNORES the cap and pushes its ENTIRE balance. The cap exists so a
///      sweep never records more than the uint96 record ceiling; a misbehaving portal that over-pushes
///      must be rejected (SweepAmountOverflow) rather than have its received delta silently truncated to
///      uint96 — truncation would strand the lost remainder permanently in pool escrow. Funded past the
///      ceiling, this drives requestPortalDeposit's over-push guard, which no cap-honoring mock can reach.
contract OverPushingPortalMock is BindablePortal, IPortalSweepSource {
    function sweep(address token, uint256) external override {
        // Deliberately ignore `cap`: push the whole balance so `received` exceeds type(uint96).max.
        IERC20(token).transfer(msg.sender, IERC20(token).balanceOf(address(this)));
    }
}

/// @dev A portal that re-enters the pool exactly ONCE during its push, on a path that WOULD otherwise
///      succeed: it calls requestPortalDeposit for a DIFFERENT, already-registered+funded portal (the
///      "victim"). Without the nonReentrant guard the inner sweep completes normally and the outer sweep
///      then completes too — so the only thing that makes the outer call revert is the guard itself,
///      reverting with the precise ReentrancyGuardReentrantCall selector. (A self-re-entrant mock instead
///      recurses infinitely and reverts with OutOfGas even when the guard is absent, which a bare
///      expectRevert would wrongly accept — so the re-entered target must be a separately-succeeding one.)
contract ReentrantPortalMock is BindablePortal, IPortalSweepSource {
    PrivacyBoost immutable pool;
    address immutable victimPortal;
    uint16 immutable victimTokenId;

    constructor(PrivacyBoost pool_, address victimPortal_, uint16 victimTokenId_) {
        pool = pool_;
        victimPortal = victimPortal_;
        victimTokenId = victimTokenId_;
    }

    function sweep(address token, uint256 cap) external override {
        // Re-enter ONCE for a different, fully-funded+registered portal. With the guard this inner call
        // reverts (ReentrancyGuardReentrantCall) and bubbles up; without it, the inner call succeeds —
        // which is exactly what makes the test distinguish a load-bearing guard from a vacuous OOG.
        pool.requestPortalDeposit(victimPortal, victimTokenId);

        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 amount = bal < cap ? bal : cap;
        IERC20(token).transfer(msg.sender, amount);
    }
}

/// @dev Behavior coverage for requestPortalDeposit (the portal sweep, step 1 of the hidden-recipient
///      deposit). Every test asserts an observable outcome that changes if the entrypoint or one of its
///      guards is deleted — never a bare "didn't revert". The load-bearing properties: the stored gross
///      amount equals the pool's MEASURED received delta (not a caller-declared value), the binding H
///      and counter come from storage (never the caller), the fee is snapshotted, the counter advances,
///      the event/record carry the recomputable portalDepositId, and the over-uint96 remainder stays at
///      E so no value is lost.
contract RequestPortalDepositTest is Test {
    using stdStorage for StdStorage;

    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address keeper = makeAddr("keeper");

    PortalSweepSourceMock portal;
    address E; // the portal address == address(portal)

    uint16 tokenId;
    uint256 constant H = 0xB14D; // the registered owner binding for the portal

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        // Deploy the portal and initialize its account-side binding (the pool reads it back via
        // portalBinding() at sweep time, replacing the former pool-side registry).
        portal = new PortalSweepSourceMock();
        E = address(portal);
        portal.initializePortal(H);
    }

    /// @dev Fund the portal so the next sweep has a balance to push.
    function _fundPortal(uint256 amount) internal {
        token.mint(E, amount);
    }

    /// @dev Recompute the expected id the contract derives, to pin the event/record key.
    function _expectedId(uint96 amount, uint256 counter) internal view returns (uint256) {
        return LibDigest.computePortalDepositId(block.chainid, address(pool), E, tokenId, amount, counter, H);
    }

    // ========== Happy path: measured-delta accounting ==========

    /// @dev A sweep escrows the MEASURED received delta, snapshots the (zero) fee and the pre-counter,
    ///      stores the record under the recomputable id, advances the counter, moves the tokens into the
    ///      pool, and emits the discovery event. Deleting the entrypoint, or storing a caller value
    ///      instead of the measured delta, fails these assertions.
    function test_requestPortalDeposit_storesMeasuredDelta() public {
        uint96 amount = 1000 ether;
        _fundPortal(amount);

        uint256 poolBefore = token.balanceOf(address(pool));
        uint256 expectedId = _expectedId(amount, 0);

        vm.expectEmit(true, true, false, true, address(pool));
        emit IPrivacyBoost.PortalDepositRequested(expectedId, E, 0, tokenId, amount, H, 0);

        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);

        // The returned id matches the recomputed key.
        assertEq(id, expectedId, "id matches recomputed digest");

        // The tokens actually moved into the pool (the push happened, not a phantom credit).
        assertEq(token.balanceOf(address(pool)) - poolBefore, amount, "pool received the swept tokens");
        assertEq(token.balanceOf(E), 0, "portal balance fully swept");

        // The record stores the measured delta and the storage-read binding/counter, plus the sweeper
        // (this caller) recorded as the fee payee.
        (
            address recPortal,
            uint64 recBlock,
            uint16 recTokenId,
            uint16 recFee,
            address recSweeper,
            uint96 recAmount,
            uint256 recCounter,
            uint256 recH
        ) = pool.portalPendingDeposits(id);
        assertEq(recPortal, E, "record portal");
        assertEq(recTokenId, tokenId, "record tokenId");
        assertEq(recAmount, amount, "record amount == measured delta");
        assertEq(recFee, 0, "record fee snapshotted (0 by default)");
        assertEq(recBlock, uint64(block.number), "record requestBlock");
        assertEq(recSweeper, keeper, "record sweeper == the requestPortalDeposit caller");
        assertEq(recCounter, 0, "record counter == pre-increment value");
        assertEq(recH, H, "record recipientBindH read from E's portalBinding()");

        // The counter advanced for the next sweep.
        assertEq(pool.portalCounter(E), 1, "counter incremented");
    }

    /// @dev The stored gross amount tracks the ACTUAL delta, not any caller input: there is no amount
    ///      parameter, and funding a different balance changes the recorded amount accordingly. This is
    ///      the property that blocks a sweeper from inflating the credit. Two sweeps with different
    ///      balances record their respective deltas.
    function test_requestPortalDeposit_amountIsMeasuredNotDeclared() public {
        _fundPortal(250 ether);
        vm.prank(keeper);
        uint256 id0 = pool.requestPortalDeposit(E, tokenId);
        (,,,,, uint96 amt0,,) = pool.portalPendingDeposits(id0);
        assertEq(amt0, 250 ether, "first sweep records its delta");

        _fundPortal(777 ether);
        vm.prank(keeper);
        uint256 id1 = pool.requestPortalDeposit(E, tokenId);
        (,,,,, uint96 amt1,, uint256 h1) = pool.portalPendingDeposits(id1);
        assertEq(amt1, 777 ether, "second sweep records its own delta");
        assertEq(h1, H, "second record binds the same owner H");
    }

    // ========== Counter uniqueness across repeated sweeps ==========

    /// @dev Repeated sweeps of the SAME portal/token/amount produce DISTINCT ids and records via the
    ///      monotonic counter — the property that makes repeated deposits distinct notes rather than a
    ///      colliding commitment. Removing the counter increment makes the second id collide with the
    ///      first and the existence guard reverts; this test asserts both records exist independently.
    function test_requestPortalDeposit_counterMakesRepeatsUnique() public {
        uint96 amount = 100 ether;

        _fundPortal(amount);
        vm.prank(keeper);
        uint256 id0 = pool.requestPortalDeposit(E, tokenId);

        _fundPortal(amount);
        vm.prank(keeper);
        uint256 id1 = pool.requestPortalDeposit(E, tokenId);

        assertTrue(id0 != id1, "same amount, different counter -> distinct ids");
        assertEq(id0, _expectedId(amount, 0), "first id uses counter 0");
        assertEq(id1, _expectedId(amount, 1), "second id uses counter 1");

        (address p0,,,,,, uint256 c0,) = pool.portalPendingDeposits(id0);
        (address p1,,,,,, uint256 c1,) = pool.portalPendingDeposits(id1);
        assertEq(p0, E, "first record exists");
        assertEq(p1, E, "second record exists");
        assertEq(c0, 0, "first record counter");
        assertEq(c1, 1, "second record counter");
        assertEq(pool.portalCounter(E), 2, "counter advanced twice");
    }

    // ========== Fee snapshotting ==========

    /// @dev The fee rate is snapshotted into the record at sweep time, so a later setPortalSweepFeeBps
    ///      cannot change an already-escrowed sweep's credited amount. Sweep at fee=300, then raise the
    ///      fee, and the record still reads 300. Removing the snapshot (reading the live fee at epoch
    ///      time instead) would let the assertion below drift.
    function test_requestPortalDeposit_snapshotsFee() public {
        pool.setPortalSweepFeeBps(300);

        _fundPortal(500 ether);
        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);

        (,,, uint16 recFee,,,,) = pool.portalPendingDeposits(id);
        assertEq(recFee, 300, "fee snapshotted at sweep time");

        // Raising the live fee afterward must not retroactively change the stored record.
        pool.setPortalSweepFeeBps(900);
        (,,, uint16 recFeeAfter,,,,) = pool.portalPendingDeposits(id);
        assertEq(recFeeAfter, 300, "stored fee unchanged by later rate change");
    }

    // ========== Over-uint96: remainder stays at E ==========

    /// @dev When the portal holds more than the uint96 record ceiling, the pool caps the pull at that
    ///      ceiling and the remainder stays at E for the next sweep — no value is lost. The recorded
    ///      amount is exactly uint96 max and E retains the excess. Removing the cap would either
    ///      overflow the uint96 amount or strand the truncated remainder.
    function test_requestPortalDeposit_overUint96LeavesRemainderAtE() public {
        uint256 ceiling = uint256(type(uint96).max);
        uint256 excess = 12345;
        _fundPortal(ceiling + excess);

        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);

        (,,,,, uint96 recAmount,,) = pool.portalPendingDeposits(id);
        assertEq(recAmount, type(uint96).max, "recorded amount capped at uint96 max");
        assertEq(token.balanceOf(E), excess, "remainder stays at E for the next sweep");
        assertEq(token.balanceOf(address(pool)), ceiling, "pool received exactly the cap");
    }

    /// @dev A second sweep then escrows the leftover remainder, proving the cap defers value rather than
    ///      losing it. Funds are conserved across the two sweeps.
    function test_requestPortalDeposit_remainderSweptOnNextCall() public {
        uint256 ceiling = uint256(type(uint96).max);
        uint256 excess = 9999;
        _fundPortal(ceiling + excess);

        vm.prank(keeper);
        pool.requestPortalDeposit(E, tokenId);

        vm.prank(keeper);
        uint256 id2 = pool.requestPortalDeposit(E, tokenId);

        (,,,,, uint96 recAmount2,, uint256 h2) = pool.portalPendingDeposits(id2);
        assertEq(recAmount2, uint96(excess), "second sweep escrows the leftover remainder");
        assertEq(h2, H, "remainder sweep binds the same owner");
        assertEq(token.balanceOf(E), 0, "all funds eventually swept");
    }

    // ========== Reverts: unregistered portal ==========

    /// @dev Sweeping an unregistered portal reverts: with no binding the deposit could never be credited
    ///      (the proof has no H to open) and the record would carry a zero recipientBindH the digest rejects.
    ///      Removing the zero-binding guard would let an un-creditable record be written.
    function test_requestPortalDeposit_revertWhen_unregisteredPortal() public {
        PortalSweepSourceMock unregistered = new PortalSweepSourceMock();
        token.mint(address(unregistered), 100 ether);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.PortalNotRegistered.selector);
        pool.requestPortalDeposit(address(unregistered), tokenId);
    }

    /// @dev A re-delegated / malicious portal whose portalBinding() returns an out-of-field word (>= the
    ///      BN254 scalar field) is rejected: the binding lives in E's own account storage, so the pool
    ///      re-validates the staticcall return rather than trusting it. The honest PortalDelegate enforces
    ///      H < PRIME at init, so this shape only arises from an E that bypasses that guard; without the
    ///      pool-side range check it would snapshot a non-canonical H the circuit (which reduces public
    ///      inputs mod PRIME) could never open. The mock returns H == PRIME directly to drive the guard;
    ///      deleting the LibPortal range check flips this from revert to a successful, un-creditable escrow.
    function test_requestPortalDeposit_revertWhen_bindingOutOfField() public {
        uint256 prime = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
        PortalSweepSourceMock outOfField = new PortalSweepSourceMock();
        outOfField.initializePortal(prime); // a binding AT the scalar field — not a canonical element
        token.mint(address(outOfField), 100 ether);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.InvalidPortalBinding.selector);
        pool.requestPortalDeposit(address(outOfField), tokenId);
    }

    // ========== Reverts: token gating ==========

    /// @dev An unregistered tokenId reverts (tokenOf returns the zero address). Only registered ERC-20s
    ///      may be swept, mirroring requestDeposit's gate. Removing the token-registry check would let an
    ///      unregistered token reach the measured-delta path with no valid token address.
    function test_requestPortalDeposit_revertWhen_unregisteredToken() public {
        _fundPortal(100 ether);
        uint16 bogusTokenId = 4242;

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.InvalidDeposit.selector);
        pool.requestPortalDeposit(E, bogusTokenId);
    }

    /// @dev A non-ERC-20 token type reverts with TokenNotSupported. The portal path only sweeps standard
    ///      ERC-20s; a token registered under a different type is rejected by the TOKEN_TYPE_ERC20 gate.
    ///      The production TokenRegistry only ever stores ERC-20s, so the pool's defensive type gate is
    ///      unreachable through the real registry; mock tokenOf to return a non-ERC20 type (with a valid
    ///      non-zero address, so the zero-address branch is bypassed) to exercise the gate directly.
    function test_requestPortalDeposit_revertWhen_nonErc20Token() public {
        uint8 nonErc20Type = TOKEN_TYPE_ERC20 + 1;
        token.mint(E, 100 ether);

        vm.mockCall(
            address(tokenRegistry),
            abi.encodeWithSelector(ITokenRegistry.tokenOf.selector, tokenId),
            abi.encode(nonErc20Type, address(token), uint256(0))
        );

        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.TokenNotSupported.selector, nonErc20Type));
        pool.requestPortalDeposit(E, tokenId);

        vm.clearMockedCalls();
    }

    // ========== Reverts: zero / dust ==========

    /// @dev A sweep that yields nothing (portal is empty) reverts with SweepBelowDust(0, 0). Removing the
    ///      zero check would write a zero-amount escrow record that could never credit a meaningful note.
    function test_requestPortalDeposit_revertWhen_zeroDelta() public {
        // Portal has no balance.
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.SweepBelowDust.selector, uint256(0), uint96(0)));
        pool.requestPortalDeposit(E, tokenId);
    }

    /// @dev A received delta below the per-token dust threshold reverts. Set the threshold to 1000, fund
    ///      999, and the sweep reverts; the record is never written. Removing the dust comparison would
    ///      escrow a sub-threshold balance. Pairs with the at-threshold success below.
    function test_requestPortalDeposit_revertWhen_belowDust() public {
        pool.setPortalMinSweep(tokenId, 1000);

        _fundPortal(999);
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.SweepBelowDust.selector, uint256(999), uint96(1000)));
        pool.requestPortalDeposit(E, tokenId);
    }

    /// @dev Exactly the dust threshold is accepted (the comparison is strict-less-than). Funds at the
    ///      threshold escrow a record with that amount, pinning the boundary rather than an off-by-one.
    function test_requestPortalDeposit_atDustThreshold() public {
        pool.setPortalMinSweep(tokenId, 1000);

        _fundPortal(1000);
        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);

        (,,,,, uint96 recAmount,,) = pool.portalPendingDeposits(id);
        assertEq(recAmount, 1000, "at-threshold sweep is accepted and recorded");
    }

    // ========== Reverts: reentrancy ==========

    /// @dev The nonReentrant guard is load-bearing, proven against a re-entry that WOULD otherwise
    ///      succeed. The reentrant portal re-enters requestPortalDeposit for a SEPARATE, fully
    ///      registered+funded "victim" portal during its push. With the guard, the inner call reverts
    ///      with the precise ReentrancyGuardReentrantCall selector (asserted exactly, so a generic
    ///      OutOfGas cannot satisfy it) and the whole sweep rolls back. Without nonReentrant the inner
    ///      victim sweep completes and the outer sweep returns normally — so the inner call's success is
    ///      what would corrupt the before/after delta measurement of the outer sweep. The mutation
    ///      delete-nonReentrant therefore FLIPS this test from pass to fail (no revert occurs), unlike a
    ///      self-re-entrant mock whose infinite recursion reverts with OutOfGas even when the guard is
    ///      gone and a bare expectRevert wrongly passes.
    function test_requestPortalDeposit_revertWhen_reentrantPortal() public {
        // The victim: a normal, cap-honoring portal, registered and funded so its sweep would succeed.
        PortalSweepSourceMock victim = new PortalSweepSourceMock();
        address victimAddr = address(victim);
        victim.initializePortal(0xC0DE);
        token.mint(victimAddr, 100 ether);

        // The attacker: re-enters the pool once for the victim during its own push.
        ReentrantPortalMock reentrant = new ReentrantPortalMock(pool, victimAddr, tokenId);
        address reAddr = address(reentrant);
        reentrant.initializePortal(0xBEEF);
        token.mint(reAddr, 100 ether);

        // The inner re-entry hits the guard and reverts with the EXACT selector; OutOfGas would not match.
        vm.prank(keeper);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        pool.requestPortalDeposit(reAddr, tokenId);

        // Full rollback: neither the attacker nor the victim advanced, and no tokens moved into the pool.
        assertEq(pool.portalCounter(reAddr), 0, "attacker counter never advanced");
        assertEq(pool.portalCounter(victimAddr), 0, "victim counter never advanced (inner call rolled back)");
        assertEq(token.balanceOf(address(pool)), 0, "no tokens swept into the pool");
        assertEq(token.balanceOf(reAddr), 100 ether, "attacker funds returned by the revert");
        assertEq(token.balanceOf(victimAddr), 100 ether, "victim funds untouched");
    }

    // ========== Reverts: over-push past the uint96 ceiling ==========

    /// @dev A non-compliant portal that IGNORES the cap and over-pushes past the uint96 record ceiling is
    ///      rejected with SweepAmountOverflow(received) — never silently truncated. Truncation would
    ///      strand the lost remainder (received − uint96.max) permanently in pool escrow, since the record
    ///      can only ever credit/refund the truncated uint96 amount. Fund the portal to uint96.max + N,
    ///      let it push everything, and assert the exact received value in the revert AND a full
    ///      rollback: no record, counter unmoved, and every token returned to the portal (no value
    ///      stranded on the adversarial push). This is the only sweep guard a cap-honoring mock cannot
    ///      reach, so deleting `if (received > type(uint96).max) revert ...` is caught ONLY by this test.
    function test_requestPortalDeposit_revertWhen_portalOverPushes() public {
        OverPushingPortalMock overPusher = new OverPushingPortalMock();
        address opAddr = address(overPusher);
        overPusher.initializePortal(0xF00D);

        // Fund past the ceiling so the full push exceeds type(uint96).max by exactly N.
        uint256 excess = 7;
        uint256 funded = uint256(type(uint96).max) + excess;
        token.mint(opAddr, funded);

        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.SweepAmountOverflow.selector, funded));
        pool.requestPortalDeposit(opAddr, tokenId);

        // Full rollback — the over-pushed tokens are returned to the portal by the revert, none stranded.
        (address recPortal,,,,,,,) = pool.portalPendingDeposits(_expectedId(type(uint96).max, 0));
        assertEq(recPortal, address(0), "no record written for the rejected over-push");
        assertEq(pool.portalCounter(opAddr), 0, "counter not advanced");
        assertEq(token.balanceOf(opAddr), funded, "all over-pushed tokens returned to E (none stranded)");
        assertEq(token.balanceOf(address(pool)), 0, "pool balance unchanged");
    }

    // ========== Reverts: duplicate portalDepositId ==========

    /// @dev The PortalDepositAlreadyExists uniqueness guard rejects a record collision. The (E, counter)
    ///      pair is unique by the monotonic counter, so a colliding id cannot arise on the happy path —
    ///      it only fires on a Poseidon collision or a counter-rollback storage bug. Force the collision
    ///      deterministically: sweep once (writing a record at counter 0), then roll portalCounter[E]
    ///      back to 0 via stdstore so the next sweep recomputes the SAME id, and assert the existence
    ///      guard reverts. Deleting the counter increment (PrivacyBoost.sol:787) or the existence check
    ///      (:797) would both let a second record silently overwrite the first; this test catches either —
    ///      the counterMakesRepeatsUnique happy-path test only checks distinct ids, never the collision.
    function test_requestPortalDeposit_revertWhen_duplicateId() public {
        // First sweep writes a record keyed at counter 0.
        _fundPortal(100 ether);
        vm.prank(keeper);
        pool.requestPortalDeposit(E, tokenId);
        assertEq(pool.portalCounter(E), 1, "counter advanced to 1 after the first sweep");

        // Roll the counter back to its already-consumed value, simulating a rollback bug / forced reuse.
        stdstore.target(address(pool)).sig("portalCounter(address)").with_key(E).checked_write(uint256(0));
        assertEq(pool.portalCounter(E), 0, "counter forced back to the consumed value 0");

        // A second sweep of the same amount now recomputes the SAME id and hits the existence guard.
        _fundPortal(100 ether);
        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.PortalDepositAlreadyExists.selector);
        pool.requestPortalDeposit(E, tokenId);

        // The original record is intact (not overwritten) and the over-funded balance was returned.
        (,,,,, uint96 recAmount,,) = pool.portalPendingDeposits(_expectedId(100 ether, 0));
        assertEq(recAmount, 100 ether, "original record unchanged by the rejected duplicate");
        assertEq(token.balanceOf(E), 100 ether, "second sweep's funds returned to E by the revert");
    }

    // ========== Permissionless: any caller may sweep ==========

    /// @dev Any caller may sweep (a keeper or the owner) — there is no relay/operator gate. Two different
    ///      callers each sweep successfully, recording the credit to the SAME owner binding regardless of
    ///      who called. This is the permissionless-keeper property; a caller restriction would revert one.
    function test_requestPortalDeposit_permissionlessCaller() public {
        address randomCaller = makeAddr("randomCaller");

        _fundPortal(10 ether);
        vm.prank(keeper);
        uint256 id0 = pool.requestPortalDeposit(E, tokenId);
        (,,,,,,, uint256 h0) = pool.portalPendingDeposits(id0);
        assertEq(h0, H, "keeper sweep credits the registered owner");

        _fundPortal(10 ether);
        vm.prank(randomCaller);
        uint256 id1 = pool.requestPortalDeposit(E, tokenId);
        (,,,,,,, uint256 h1) = pool.portalPendingDeposits(id1);
        assertEq(h1, H, "a different caller credits the SAME owner, not themselves");
    }

    // ========== setPortalMinSweep admin ==========

    /// @dev Owner sets a per-token dust threshold; the getter reflects it and the event carries old->new.
    ///      Deleting the setter or its state write fails the getter assertion.
    function test_setPortalMinSweep_setsValue() public {
        assertEq(pool.portalMinSweep(tokenId), 0, "default dust threshold is zero");

        vm.expectEmit(true, false, false, true, address(pool));
        emit IPrivacyBoost.PortalMinSweepUpdated(tokenId, 0, 5000);
        pool.setPortalMinSweep(tokenId, 5000);

        assertEq(pool.portalMinSweep(tokenId), 5000, "threshold updated");
    }

    /// @dev onlyOwner: a non-owner cannot change the dust threshold. The call reverts with
    ///      OwnableUnauthorizedAccount and the threshold is unchanged. Removing onlyOwner makes the
    ///      reverted call succeed and the unchanged-threshold assertion fail.
    function test_setPortalMinSweep_revertWhen_notOwner() public {
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, keeper));
        pool.setPortalMinSweep(tokenId, 100);

        assertEq(pool.portalMinSweep(tokenId), 0, "threshold unchanged by unauthorized caller");
    }
}
