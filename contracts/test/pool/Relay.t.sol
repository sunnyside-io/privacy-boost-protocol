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

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {
    Output,
    Transfer,
    Withdrawal,
    DepositCiphertext,
    DepositEntry,
    EpochTreeState,
    TreeRootPair,
    GatewaySlot
} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";

import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

contract RelayTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address notOwner = makeAddr("notOwner");
    address operator = makeAddr("operator");
    address relay1 = makeAddr("relay1");
    address relay2 = makeAddr("relay2");
    address relay3 = makeAddr("relay3");
    address alice = makeAddr("alice");

    uint16 tokenId;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        token.mint(alice, 100_000 ether);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);

        pool.setOperator(operator);
    }

    // ========== Initial State ==========

    function test_initialState_noRelaysAllowed() public view {
        assertFalse(pool.allowedRelays(relay1));
        assertFalse(pool.allowedRelays(relay2));
    }

    // ========== setAllowedRelays ==========

    function test_setAllowedRelays_singleRelay() public {
        address[] memory relays = new address[](1);
        relays[0] = relay1;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        assertTrue(pool.allowedRelays(relay1));
        assertFalse(pool.allowedRelays(relay2));
    }

    function test_setAllowedRelays_multipleRelays() public {
        address[] memory relays = new address[](3);
        relays[0] = relay1;
        relays[1] = relay2;
        relays[2] = relay3;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        assertTrue(pool.allowedRelays(relay1));
        assertTrue(pool.allowedRelays(relay2));
        assertTrue(pool.allowedRelays(relay3));
    }

    function test_setAllowedRelays_removeRelay() public {
        address[] memory relays = new address[](1);
        relays[0] = relay1;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(relay1));

        vm.prank(operator);
        pool.setAllowedRelays(relays, false);
        assertFalse(pool.allowedRelays(relay1));
    }

    function test_setAllowedRelays_emitsRelayUpdatedEvent() public {
        address[] memory relays = new address[](1);
        relays[0] = relay1;

        vm.expectEmit(false, false, false, true);
        emit IPrivacyBoost.RelayUpdated(relay1, true);

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    function test_setAllowedRelays_emitsMultipleEvents() public {
        address[] memory relays = new address[](2);
        relays[0] = relay1;
        relays[1] = relay2;

        vm.expectEmit(false, false, false, true);
        emit IPrivacyBoost.RelayUpdated(relay1, true);
        vm.expectEmit(false, false, false, true);
        emit IPrivacyBoost.RelayUpdated(relay2, true);

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    function test_setAllowedRelays_emptyArray() public {
        address[] memory relays = new address[](0);

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
    }

    // ========== Access Control ==========

    function test_revertWhen_setAllowedRelaysByNonOperator() public {
        address[] memory relays = new address[](1);
        relays[0] = relay1;

        vm.prank(notOwner);
        vm.expectRevert(IPrivacyBoost.NotOperator.selector);
        pool.setAllowedRelays(relays, true);
    }

    // ========== onlyRelay modifier ==========

    function test_revertWhen_submitEpochByNonRelay() public {
        TreeRootPair[] memory usedRoots = new TreeRootPair[](1);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: 0});
        TreeRootPair[] memory authRoots = new TreeRootPair[](1);
        authRoots[0] = TreeRootPair({treeNumber: 0, root: 0});
        uint256[] memory nullifiers = new uint256[](1);
        Output[] memory outputs = new Output[](1);
        Output[] memory feeOutputs = new Output[](4);
        Withdrawal[] memory withdrawals = new Withdrawal[](0);
        uint32[] memory withdrawalSlots = new uint32[](0);
        uint256[8] memory proof;

        EpochTreeState memory treeState = EpochTreeState({
            usedRoots: usedRoots, activeTreeNumber: 0, countOld: 0, rootNew: 0, countNew: 0, rollover: false
        });

        vm.prank(notOwner);
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.submitEpoch(
            treeState,
            authRoots,
            1, // nTransfers
            1, // feeTokenCount
            0, // feeNPK
            EpochHelpers.singletonUint32Array(1), // inputsPerTransfer
            EpochHelpers.singletonUint32Array(1), // outputsPerTransfer
            EpochHelpers.wrap2D(nullifiers),
            EpochHelpers.buildTransfers(outputs),
            EpochHelpers.buildFeeTransfer(feeOutputs),
            withdrawals,
            withdrawalSlots,
            uint64(block.timestamp),
            proof,
            new GatewaySlot[](0)
        );
    }

    function test_revertWhen_submitDepositEpochByNonRelay() public {
        TreeRootPair[] memory usedRoots = new TreeRootPair[](1);
        usedRoots[0] = TreeRootPair({treeNumber: 0, root: 0});
        Output[] memory outputs = new Output[](1);
        DepositEntry[] memory deposits = new DepositEntry[](1);
        uint256[8] memory proof;

        EpochTreeState memory treeState = EpochTreeState({
            usedRoots: usedRoots, activeTreeNumber: 0, countOld: 0, rootNew: 0, countNew: 0, rollover: false
        });

        vm.prank(notOwner);
        vm.expectRevert(IPrivacyBoost.NotAllowedRelay.selector);
        pool.submitDepositEpoch(treeState, 1, outputs, deposits, proof);
    }

    // ========== Edge Cases ==========

    function test_setAllowedRelays_toggleMultipleTimes() public {
        address[] memory relays = new address[](1);
        relays[0] = relay1;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(relay1));

        vm.prank(operator);
        pool.setAllowedRelays(relays, false);
        assertFalse(pool.allowedRelays(relay1));

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(relay1));
    }

    function test_setAllowedRelays_canAddAndRemoveInSeparateCalls() public {
        address[] memory addRelays = new address[](2);
        addRelays[0] = relay1;
        addRelays[1] = relay2;
        vm.prank(operator);
        pool.setAllowedRelays(addRelays, true);

        address[] memory removeRelays = new address[](1);
        removeRelays[0] = relay1;
        vm.prank(operator);
        pool.setAllowedRelays(removeRelays, false);

        assertFalse(pool.allowedRelays(relay1));
        assertTrue(pool.allowedRelays(relay2));
    }

    function test_setAllowedRelays_sameRelayMultipleTimes() public {
        address[] memory relays = new address[](3);
        relays[0] = relay1;
        relays[1] = relay1;
        relays[2] = relay1;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(relay1));

        vm.prank(operator);
        pool.setAllowedRelays(relays, false);
        assertFalse(pool.allowedRelays(relay1));
    }

    function test_setAllowedRelays_zeroAddress() public {
        address[] memory relays = new address[](1);
        relays[0] = address(0);

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(address(0)));
    }

    // ========== Fuzz Tests ==========

    function testFuzz_setAllowedRelays_anyAddress(address relay) public {
        address[] memory relays = new address[](1);
        relays[0] = relay;

        vm.prank(operator);
        pool.setAllowedRelays(relays, true);
        assertTrue(pool.allowedRelays(relay));

        vm.prank(operator);
        pool.setAllowedRelays(relays, false);
        assertFalse(pool.allowedRelays(relay));
    }
}
