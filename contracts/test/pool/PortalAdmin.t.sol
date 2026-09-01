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
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";

import {MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

/// @dev Behavior coverage for the pool's portal ADMIN entrypoints — the sweep-fee setter and the
///      portal-deposit verifier setter. The owner binding no longer lives in pool storage: it moved
///      into each portal account's own EIP-7702 storage (PortalDelegate.initializePortal /
///      initializePortalWithSig, read by the pool via staticcall at sweep), so registration is covered
///      by Portal.t.sol and PortalDelegate.t.sol, not here. The two setters that remain are owner-only
///      config writes, and each test asserts an observable outcome that flips if the entrypoint or its
///      guard were removed: the MAX_FEE_BPS bound stops an owner snapshotting an out-of-range fee into a
///      sweep record, and the verifier setter's onlyOwner gate stops a permissive verifier being wired
///      in to credit any account.
contract PortalAdminTest is Test {
    PrivacyBoost pool;
    MockVerifier verifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address stranger = makeAddr("stranger");

    // MAX_FEE_BPS is a private constant in the pool (1_000 = 10%); mirror it here for the boundary
    // tests. Fee.t.sol pins the same literal, so a divergence in the real cap surfaces there too.
    uint16 constant MAX_FEE_BPS = 1_000;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool,,) = PoolDeployer.deployFullStack(cfg);
    }

    // ========== setPortalSweepFeeBps — owner-only, MAX_FEE_BPS-bounded ==========

    /// @dev Owner sets a fee within bound; the getter reflects it and the event carries old->new.
    ///      Deleting the setter or its state write fails the getter assertion.
    function test_setPortalSweepFeeBps_setsValue() public {
        assertEq(pool.portalSweepFeeBps(), 0, "default fee is zero");

        vm.expectEmit(false, false, false, true, address(pool));
        emit IPrivacyBoost.PortalSweepFeeUpdated(0, 250);
        pool.setPortalSweepFeeBps(250);

        assertEq(pool.portalSweepFeeBps(), 250, "fee updated");
    }

    /// @dev The boundary is inclusive: exactly MAX_FEE_BPS is accepted. Pairs with the +1 revert below
    ///      to pin the cap rather than an off-by-one.
    function test_setPortalSweepFeeBps_atMaxBoundary() public {
        pool.setPortalSweepFeeBps(MAX_FEE_BPS);
        assertEq(pool.portalSweepFeeBps(), MAX_FEE_BPS, "max fee accepted");
    }

    /// @dev Above the cap reverts with FeeExceedsMaximum — the same cap the withdraw fee uses. Removing
    ///      the MAX_FEE_BPS check makes this succeed and the assert (unchanged fee) fail.
    function test_setPortalSweepFeeBps_revertWhen_exceedsMax() public {
        vm.expectRevert(IPrivacyBoost.FeeExceedsMaximum.selector);
        pool.setPortalSweepFeeBps(MAX_FEE_BPS + 1);

        assertEq(pool.portalSweepFeeBps(), 0, "fee unchanged after reverted set");
    }

    /// @dev onlyOwner: a non-owner caller reverts with OwnableUnauthorizedAccount and the fee stays
    ///      put. Guards against a non-admin snapshotting a fee into future sweep records.
    function test_setPortalSweepFeeBps_revertWhen_notOwner() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        pool.setPortalSweepFeeBps(100);

        assertEq(pool.portalSweepFeeBps(), 0, "fee unchanged by unauthorized caller");
    }

    // ========== setPortalDepositVerifier — owner-only verifier wiring ==========

    /// @dev Owner sets the portal-deposit verifier; the getter reflects it and the event carries
    ///      old->new. This is the verifier the portal epoch checks every credit against, so a missing
    ///      state write or event would silently break crediting integrity. Deleting the setter or its
    ///      state write fails the getter assertion; dropping the event fails the expectEmit.
    function test_setPortalDepositVerifier_setsValue() public {
        // The verifier is now bound at initialize, so it is already set here (not the zero default it
        // used to be); capture whatever the deployment wired so the setter's old->new event matches.
        address initial = address(pool.portalDepositVerifier());

        address sentinel = makeAddr("portalVerifier");
        vm.expectEmit(true, true, false, false, address(pool));
        emit IPrivacyBoost.PortalDepositVerifierUpdated(initial, sentinel);
        pool.setPortalDepositVerifier(sentinel);

        assertEq(address(pool.portalDepositVerifier()), sentinel, "verifier updated");

        // A second set emits the correct old->new transition (old == the prior sentinel, not zero).
        address sentinel2 = makeAddr("portalVerifier2");
        vm.expectEmit(true, true, false, false, address(pool));
        emit IPrivacyBoost.PortalDepositVerifierUpdated(sentinel, sentinel2);
        pool.setPortalDepositVerifier(sentinel2);

        assertEq(address(pool.portalDepositVerifier()), sentinel2, "verifier re-updated");
    }

    /// @dev onlyOwner: a non-owner cannot replace the portal-deposit verifier — a critical control,
    ///      since substituting a permissive verifier would let any proof credit any account. The call
    ///      reverts with OwnableUnauthorizedAccount and the verifier is left unchanged. Removing
    ///      `onlyOwner` from the setter makes this call succeed and the unchanged-verifier assert fail.
    function test_setPortalDepositVerifier_revertWhen_notOwner() public {
        // Seed a known verifier as owner so the unchanged-after-revert assertion is meaningful.
        address seeded = makeAddr("seededVerifier");
        pool.setPortalDepositVerifier(seeded);

        address attackerVerifier = makeAddr("attackerVerifier");
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        pool.setPortalDepositVerifier(attackerVerifier);

        assertEq(address(pool.portalDepositVerifier()), seeded, "verifier unchanged by unauthorized caller");
    }
}
