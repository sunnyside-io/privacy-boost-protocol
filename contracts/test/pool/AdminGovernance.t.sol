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
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {MAX_NOTE_TREE_DEPTH} from "src/interfaces/Constants.sol";

import {MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

contract AdminGovernanceTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockVerifier newVerifier;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address newOwner = makeAddr("newOwner");
    address treasury = makeAddr("treasury");
    address operator = makeAddr("operator");

    function setUp() public {
        verifier = new MockVerifier();
        newVerifier = new MockVerifier();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.withdrawFeeBps = 200;
        cfg.treasury = treasury;

        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        // Set operator
        pool.setOperator(operator);
    }

    // ========== Two-Step Ownership Transfer ==========

    function test_ownershipTransfer_requiresTwoSteps() public {
        Ownable2StepUpgradeable(address(pool)).transferOwnership(newOwner);

        assertEq(Ownable2StepUpgradeable(address(pool)).owner(), owner);
        assertEq(Ownable2StepUpgradeable(address(pool)).pendingOwner(), newOwner);

        vm.prank(newOwner);
        Ownable2StepUpgradeable(address(pool)).acceptOwnership();

        assertEq(Ownable2StepUpgradeable(address(pool)).owner(), newOwner);
        assertEq(Ownable2StepUpgradeable(address(pool)).pendingOwner(), address(0));
    }

    function test_revertWhen_nonPendingOwnerAccepts() public {
        Ownable2StepUpgradeable(address(pool)).transferOwnership(newOwner);

        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        vm.expectRevert();
        Ownable2StepUpgradeable(address(pool)).acceptOwnership();
    }

    function test_ownershipTransfer_canBeCancelled() public {
        Ownable2StepUpgradeable(address(pool)).transferOwnership(newOwner);

        Ownable2StepUpgradeable(address(pool)).transferOwnership(address(0));

        assertEq(Ownable2StepUpgradeable(address(pool)).pendingOwner(), address(0));
        assertEq(Ownable2StepUpgradeable(address(pool)).owner(), owner);
    }

    // ========== Verifier Update Events ==========

    function test_setEpochVerifier_emitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.EpochVerifierUpdated(address(verifier), address(newVerifier));

        pool.setEpochVerifier(address(newVerifier));
    }

    function test_setDepositVerifier_emitsEvent() public {
        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.DepositVerifierUpdated(address(verifier), address(newVerifier));

        pool.setDepositVerifier(address(newVerifier));
    }

    function test_setEpochVerifier_updatesState() public {
        pool.setEpochVerifier(address(newVerifier));
        assertEq(address(pool.epochVerifier()), address(newVerifier));
    }

    function test_setDepositVerifier_updatesState() public {
        pool.setDepositVerifier(address(newVerifier));
        assertEq(address(pool.depositVerifier()), address(newVerifier));
    }

    function test_revertWhen_nonOwnerSetsEpochVerifier() public {
        vm.prank(newOwner);
        vm.expectRevert();
        pool.setEpochVerifier(address(newVerifier));
    }

    function test_revertWhen_nonOwnerSetsDepositVerifier() public {
        vm.prank(newOwner);
        vm.expectRevert();
        pool.setDepositVerifier(address(newVerifier));
    }

    // ========== MaxForcedInputs Validation ==========

    function test_constructor_revertWhen_maxForcedInputsZero() public {
        vm.expectRevert(IPrivacyBoost.MaxForcedInputsCannotBeZero.selector);
        new PrivacyBoost(
            address(tokenRegistry),
            address(authRegistry),
            8,
            1,
            1,
            4,
            256,
            256,
            0, // maxForcedInputs = 0
            300,
            300,
            20
        );
    }

    function test_constructor_allowsForcedDelayIndependentOfRootStaleness() public {
        PrivacyBoost configured = new PrivacyBoost(
            address(tokenRegistry),
            address(authRegistry),
            8,
            1,
            1,
            4,
            256,
            64, // forcedWithdrawalDelay
            4,
            300,
            64, // retained for gift-exit root validation, not forced-withdraw execution
            20
        );
        assertEq(configured.forcedWithdrawalDelay(), 64);
        assertEq(configured.maxForcedWithdrawalAuthStalenessBlocks(), 64);
    }

    // ========== Constructor Config Validation ==========

    function test_constructor_revertWhen_tokenRegistryZeroAddress() public {
        vm.expectRevert(IPrivacyBoost.InvalidTokenRegistryAddress.selector);
        new PrivacyBoost(address(0), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_tokenRegistryNotContract() public {
        address eoa = makeAddr("eoa");
        vm.expectRevert(IPrivacyBoost.InvalidTokenRegistryAddress.selector);
        new PrivacyBoost(eoa, address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_authRegistryZeroAddress() public {
        vm.expectRevert(IPrivacyBoost.InvalidAuthRegistryAddress.selector);
        new PrivacyBoost(address(tokenRegistry), address(0), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_authRegistryNotContract() public {
        address eoa = makeAddr("eoaAuth");
        vm.expectRevert(IPrivacyBoost.InvalidAuthRegistryAddress.selector);
        new PrivacyBoost(address(tokenRegistry), eoa, 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_maxBatchSizeZero() public {
        vm.expectRevert(IPrivacyBoost.MaxBatchSizeCannotBeZero.selector);
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 0, 1, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_maxBatchSizeExceedsDepositCountWidth() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IPrivacyBoost.MaxBatchSizeOutOfRange.selector, uint32(type(uint16).max) + 1, uint32(type(uint16).max)
            )
        );
        new PrivacyBoost(
            address(tokenRegistry),
            address(authRegistry),
            uint32(type(uint16).max) + 1,
            1,
            1,
            4,
            256,
            256,
            4,
            300,
            64,
            20
        );
    }

    function test_constructor_revertWhen_maxInputsPerTransferZero() public {
        vm.expectRevert(IPrivacyBoost.MaxInputsPerTransferCannotBeZero.selector);
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 0, 1, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_maxOutputsPerTransferZero() public {
        vm.expectRevert(IPrivacyBoost.MaxOutputsPerTransferCannotBeZero.selector);
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 0, 4, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_maxFeeTokensZero() public {
        vm.expectRevert(IPrivacyBoost.MaxFeeTokensCannotBeZero.selector);
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 0, 256, 256, 4, 300, 64, 20);
    }

    function test_constructor_revertWhen_merkleDepthOutOfRange() public {
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.MerkleDepthOutOfRange.selector, 0, 1, MAX_NOTE_TREE_DEPTH));
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 0);

        uint8 aboveMaximum = MAX_NOTE_TREE_DEPTH + 1;
        vm.expectRevert(
            abi.encodeWithSelector(IPrivacyBoost.MerkleDepthOutOfRange.selector, aboveMaximum, 1, MAX_NOTE_TREE_DEPTH)
        );
        new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, aboveMaximum);
    }

    function test_constructor_acceptsMaximumMerkleDepth() public {
        // Arrange
        uint8 maximumMerkleDepth = MAX_NOTE_TREE_DEPTH;

        // Act
        PrivacyBoost configured = new PrivacyBoost(
            address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, maximumMerkleDepth
        );

        // Assert
        assertEq(configured.merkleDepth(), maximumMerkleDepth);
    }

    // ========== Treasury Validation ==========

    function test_setTreasury_revertWhen_zeroAddressWithActiveFees() public {
        assertEq(pool.treasury(), treasury);
        assertTrue(pool.withdrawFeeBps() > 0);

        vm.expectRevert(IPrivacyBoost.TreasuryNotSet.selector);
        pool.setTreasury(address(0));
    }

    function test_setTreasury_allowsZeroWhenNoFees() public {
        pool.setFees(0);

        pool.setTreasury(address(0));
        assertEq(pool.treasury(), address(0));
    }

    function test_setTreasury_emitsEvent() public {
        address newTreasury = makeAddr("newTreasury");

        vm.expectEmit(false, false, false, true);
        emit IPrivacyBoost.TreasuryUpdated(treasury, newTreasury);

        pool.setTreasury(newTreasury);
    }

    function test_revertWhen_nonOwnerSetsTreasury() public {
        vm.prank(newOwner);
        vm.expectRevert();
        pool.setTreasury(makeAddr("newTreasury"));
    }

    // ========== Operator Management ==========

    function test_setOperator_updatesState() public {
        address newOperator = makeAddr("newOperator");
        pool.setOperator(newOperator);
        assertEq(pool.operator(), newOperator);
    }

    function test_setOperator_emitsEvent() public {
        address newOperator = makeAddr("newOperator");

        vm.expectEmit(true, true, false, true);
        emit IPrivacyBoost.OperatorUpdated(operator, newOperator);

        pool.setOperator(newOperator);
    }

    function test_revertWhen_nonOwnerSetsOperator() public {
        vm.prank(newOwner);
        vm.expectRevert();
        pool.setOperator(makeAddr("newOperator"));
    }

    function test_revertWhen_setOperatorZeroAddress() public {
        vm.expectRevert(IPrivacyBoost.InvalidOperatorAddress.selector);
        pool.setOperator(address(0));
    }

    // ========== Fee Cap (10% Max) ==========

    function test_feeCap_maxIs10Percent() public {
        uint16 maxFeeBps = 1_000; // 10%

        pool.setTreasury(treasury);
        pool.setFees(maxFeeBps);
        assertEq(pool.withdrawFeeBps(), maxFeeBps);

        vm.expectRevert(IPrivacyBoost.FeeExceedsMaximum.selector);
        pool.setFees(maxFeeBps + 1);
    }
}
