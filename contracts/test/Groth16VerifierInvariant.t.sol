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

contract Groth16VerifierHarness is Groth16Verifier {
    constructor() Groth16Verifier(address(this)) {}

    function setICLen(uint32 param, uint256 icLen) external {
        vkRegistry[param].icLen = icLen;
    }

    function verifyUnchecked(uint32 param, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool)
    {
        // Suppress unused variable warning - proof is read via calldataload at proofOffset
        proof;

        VKPointers storage vk = vkRegistry[param];
        _verifyProof(0x24, publicInputs, vk);
        return true;
    }
}

contract Groth16VerifierInvariantTest is Test {
    Groth16VerifierHarness harness;

    function setUp() public {
        harness = new Groth16VerifierHarness();
    }

    function test_verifyUnchecked_revertsWhen_publicInputLengthMismatch() public {
        uint32 param = 1;
        harness.setICLen(param, 2);

        uint256[8] memory proof;

        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = 1;
        publicInputs[1] = 2;

        vm.expectRevert(Groth16Verifier.InvalidPublicInputLength.selector);
        harness.verifyUnchecked(param, proof, publicInputs);
    }
}

