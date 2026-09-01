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
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";

import {MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

contract FeeTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address notOwner = makeAddr("notOwner");
    address treasury = makeAddr("treasury");

    uint16 constant MAX_FEE_BPS = 1_000; // 10% max fee cap

    function setUp() public {
        verifier = new MockVerifier();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.withdrawFeeBps = 200;
        cfg.treasury = treasury;

        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
    }

    // ========== Initial State ==========

    function test_initialFees_setCorrectly() public view {
        assertEq(pool.withdrawFeeBps(), 200);
    }

    // ========== setFees ==========

    function test_setFees_updatesWithdrawFee() public {
        pool.setFees(150);
        assertEq(pool.withdrawFeeBps(), 150);
    }

    function test_setFees_canSetToZero() public {
        pool.setFees(0);
        assertEq(pool.withdrawFeeBps(), 0);
    }

    function test_setFees_canSetToMaxBps() public {
        pool.setTreasury(treasury);
        pool.setFees(MAX_FEE_BPS);
        assertEq(pool.withdrawFeeBps(), MAX_FEE_BPS);
    }

    function test_setFees_emitsFeesUpdatedEvent() public {
        pool.setTreasury(treasury);
        vm.expectEmit(false, false, false, true);
        emit IPrivacyBoost.FeesUpdated(400);

        pool.setFees(400);
    }

    // ========== Access Control ==========

    function test_revertWhen_setFeesByNonOwner() public {
        pool.setTreasury(treasury);
        vm.prank(notOwner);
        vm.expectRevert();
        pool.setFees(100);
    }

    function test_revertWhen_withdrawFeeWithoutTreasury() public {
        // First set fees to zero (no treasury required)
        pool.setFees(0);
        // Clear treasury
        pool.setTreasury(address(0));
        // Now try to set withdrawFee > 0 without treasury
        vm.expectRevert(IPrivacyBoost.TreasuryNotSet.selector);
        pool.setFees(200);
    }

    function test_setFees_allowsWithdrawFeeWithTreasury() public {
        // Ensure treasury is set
        pool.setTreasury(treasury);
        // Should succeed with withdrawFee > 0
        pool.setFees(200);
        assertEq(pool.withdrawFeeBps(), 200);
    }

    function test_setFees_allowsZeroWithdrawFeeWithoutTreasury() public {
        // Set fees to zero first
        pool.setFees(0);
        // Clear treasury
        pool.setTreasury(address(0));
        // Should succeed with withdrawFee = 0 (no treasury required)
        pool.setFees(0);
        assertEq(pool.withdrawFeeBps(), 0);
    }

    // ========== Input Validation ==========

    function test_revertWhen_withdrawFeeExceedsMaximum() public {
        vm.expectRevert(IPrivacyBoost.FeeExceedsMaximum.selector);
        pool.setFees(MAX_FEE_BPS + 1);
    }

    // ========== Edge Cases ==========

    function test_setFees_canUpdateMultipleTimes() public {
        pool.setTreasury(treasury);
        pool.setFees(200);
        assertEq(pool.withdrawFeeBps(), 200);

        pool.setFees(400);
        assertEq(pool.withdrawFeeBps(), 400);

        pool.setFees(0);
        assertEq(pool.withdrawFeeBps(), 0);
    }

    // ========== Initialize Fee Validation ==========

    function test_initialize_revertWhen_withdrawFeeExceedsMaximum() public {
        PrivacyBoost poolImpl =
            new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);

        vm.expectRevert(IPrivacyBoost.FeeExceedsMaximum.selector);
        new TransparentUpgradeableProxy(
            address(poolImpl),
            proxyAdmin,
            abi.encodeCall(
                PrivacyBoost.initialize,
                (
                    owner,
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    MAX_FEE_BPS + 1, // exceeds maximum
                    treasury // treasury required for withdrawFee > 0
                )
            )
        );
    }

    function test_initialize_revertWhen_withdrawFeeWithoutTreasury() public {
        PrivacyBoost poolImpl =
            new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);

        vm.expectRevert(IPrivacyBoost.TreasuryNotSet.selector);
        new TransparentUpgradeableProxy(
            address(poolImpl),
            proxyAdmin,
            abi.encodeCall(
                PrivacyBoost.initialize,
                (
                    owner,
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    address(verifier),
                    200, // withdrawFee > 0
                    address(0) // but treasury not set
                )
            )
        );
    }

    // ========== Fuzz Tests ==========

    function testFuzz_setFees_validRange(uint16 withdrawFee) public {
        withdrawFee = uint16(bound(withdrawFee, 0, MAX_FEE_BPS));

        // Treasury required if withdrawFee > 0
        if (withdrawFee > 0) {
            pool.setTreasury(treasury);
        }

        pool.setFees(withdrawFee);
        assertEq(pool.withdrawFeeBps(), withdrawFee);
    }

    function testFuzz_setFees_revertAboveMax(uint16 withdrawFee) public {
        vm.assume(withdrawFee > MAX_FEE_BPS);

        vm.expectRevert(IPrivacyBoost.FeeExceedsMaximum.selector);
        pool.setFees(withdrawFee);
    }
}
