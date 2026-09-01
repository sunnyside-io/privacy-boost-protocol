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

import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";
import {Groth16EpochVerifier} from "../src/verifier/Groth16EpochVerifier.sol";

contract Groth16EpochVerifierTest is Test {
    Groth16EpochVerifier internal verifier;

    function setUp() public {
        verifier = new Groth16EpochVerifier(address(this));
    }

    function test_getEpochVKInfo_returnsRegisteredConfiguration() public {
        // Arrange
        address[] memory icxSources = new address[](2);
        address[] memory icySources = new address[](2);
        icxSources[0] = address(0x1111);
        icySources[0] = address(0x1212);
        icxSources[1] = address(0x1414);
        icySources[1] = address(0);
        address vkConstants = address(0x1313);
        vm.etch(icxSources[0], new bytes(65));
        vm.etch(icySources[0], new bytes(65));
        vm.etch(icxSources[1], new bytes(1));
        vm.etch(vkConstants, new bytes(449));

        // Act
        verifier.registerEpochVK(4, 2, 2, icxSources, icySources, vkConstants, 2);
        (uint256 icLen, address registeredConstants) = verifier.getEpochVKInfo(4, 2, 2);
        (uint256 otherIcLen, address otherConstants) = verifier.getEpochVKInfo(4, 4, 2);

        // Assert
        assertEq(icLen, 2);
        assertEq(registeredConstants, vkConstants);
        assertEq(otherIcLen, 0);
        assertEq(otherConstants, address(0));
    }

    function test_registerEpochVK_revertsForMissingICSourceCode() public {
        // Arrange
        address[] memory icxSources = new address[](1);
        address[] memory icySources = new address[](1);
        icxSources[0] = address(0x1111);
        icySources[0] = address(0x1212);
        address vkConstants = address(0x1313);
        vm.etch(icySources[0], new bytes(65));
        vm.etch(vkConstants, new bytes(449));

        // Act
        vm.expectRevert(Groth16Verifier.InvalidICSource.selector);
        verifier.registerEpochVK(4, 2, 2, icxSources, icySources, vkConstants, 2);

        // Assert
        (uint256 icLen,) = verifier.getEpochVKInfo(4, 2, 2);
        assertEq(icLen, 0);
    }

    function test_registerEpochVK_revertsForMismatchedICLength() public {
        // Arrange
        address[] memory icxSources = new address[](1);
        address[] memory icySources = new address[](1);
        icxSources[0] = address(0x1111);
        icySources[0] = address(0x1212);
        address vkConstants = address(0x1313);
        vm.etch(icxSources[0], new bytes(65));
        vm.etch(icySources[0], new bytes(65));
        vm.etch(vkConstants, new bytes(449));

        // Act
        vm.expectRevert(Groth16Verifier.InvalidICLength.selector);
        verifier.registerEpochVK(4, 2, 2, icxSources, icySources, vkConstants, 3);

        // Assert
        (uint256 icLen,) = verifier.getEpochVKInfo(4, 2, 2);
        assertEq(icLen, 0);
    }

    function test_registerEpochVK_revertsForInvalidVKConstantsCode() public {
        // Arrange
        address[] memory icxSources = new address[](1);
        address[] memory icySources = new address[](1);
        icxSources[0] = address(0x1111);
        icySources[0] = address(0x1212);
        address vkConstants = address(0x1313);
        vm.etch(icxSources[0], new bytes(65));
        vm.etch(icySources[0], new bytes(65));
        vm.etch(vkConstants, new bytes(448));

        // Act
        vm.expectRevert(Groth16Verifier.InvalidVKConstants.selector);
        verifier.registerEpochVK(4, 2, 2, icxSources, icySources, vkConstants, 2);

        // Assert
        (uint256 icLen,) = verifier.getEpochVKInfo(4, 2, 2);
        assertEq(icLen, 0);
    }

    function test_getEpochVKInfo_returnsZeroForUnregisteredConfiguration() public view {
        // Act
        (uint256 icLen, address registeredConstants) = verifier.getEpochVKInfo(8, 4, 2);

        // Assert
        assertEq(icLen, 0);
        assertEq(registeredConstants, address(0));
    }
}
