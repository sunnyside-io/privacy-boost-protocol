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
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";

import {Groth16Verifier} from "../src/verifier/Groth16Verifier.sol";
import {Groth16DepositVerifier} from "../src/verifier/Groth16DepositVerifier.sol";

contract Groth16VerifierMSMErrorsTest is Test {
    uint256 private constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint32 private constant BATCH_SIZE = 1;

    Groth16DepositVerifier private verifier;

    function setUp() public {
        verifier = new Groth16DepositVerifier(address(this));
    }

    function test_verifyDeposit_revertsWhen_publicInputNotInField() public {
        _registerVKWithIC(bytes32(0), bytes32(0), bytes32(0), bytes32(0));

        uint256[8] memory proof;
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = R;

        vm.expectRevert(Groth16Verifier.PublicInputNotInField.selector);
        verifier.verifyDeposit(BATCH_SIZE, proof, publicInputs);
    }

    function test_verifyDeposit_revertsWhen_precompileCallFails() public {
        _registerVKWithIC(bytes32(0), bytes32(0), bytes32(uint256(1)), bytes32(uint256(1)));

        uint256[8] memory proof;
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = 1;

        vm.expectRevert(Groth16Verifier.PrecompileCallFailed.selector);
        verifier.verifyDeposit(BATCH_SIZE, proof, publicInputs);
    }

    function _registerVKWithIC(bytes32 ic0x, bytes32 ic0y, bytes32 ic1x, bytes32 ic1y) internal {
        bytes memory icxData = abi.encodePacked(ic0x, ic1x);
        bytes memory icyData = abi.encodePacked(ic0y, ic1y);

        address[] memory icxSources = new address[](1);
        address[] memory icySources = new address[](1);
        icxSources[0] = _deploySSTORE2(icxData);
        icySources[0] = _deploySSTORE2(icyData);

        address vkConstants = _deploySSTORE2(new bytes(0));
        verifier.registerVK(BATCH_SIZE, icxSources, icySources, vkConstants, 2);
    }

    /// @dev Deploy a SSTORE2-style contract where runtime code is `0x00 || data`.
    function _deploySSTORE2(bytes memory data) internal returns (address addr) {
        uint256 dataLen = data.length + 1; // +1 for STOP prefix
        require(dataLen <= 0xFFFF, "Data too large for SSTORE2");

        bytes memory creationCode = abi.encodePacked(
            hex"61", // PUSH2
            uint16(dataLen), // length of runtime code
            hex"80", // DUP1
            hex"600a", // PUSH1 0x0a (offset where runtime code starts)
            hex"3d", // RETURNDATASIZE (0)
            hex"39", // CODECOPY
            hex"3d", // RETURNDATASIZE (0)
            hex"f3", // RETURN
            hex"00", // STOP (start of runtime code)
            data
        );

        assembly {
            addr := create(0, add(creationCode, 0x20), mload(creationCode))
        }
        require(addr != address(0), "SSTORE2 deploy failed");
    }
}

