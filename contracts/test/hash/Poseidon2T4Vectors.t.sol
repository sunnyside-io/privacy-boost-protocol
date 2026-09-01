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
import {stdJson} from "forge-std/StdJson.sol";

import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";

contract Poseidon2T4Harness {
    function hashUpTo5WithConstants(uint256 len, uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        external
        pure
        returns (uint256)
    {
        bytes memory rc = Poseidon2T4.loadRoundConstants();
        return Poseidon2T4.hashUpTo5WithConstants(rc, len, a0, a1, a2, a3, a4);
    }
}

contract Poseidon2T4VectorsTest is Test {
    using stdJson for string;

    string internal constant FIXTURE_PATH = "testdata/poseidon2t4/vectors.json";
    Poseidon2T4Harness internal harness;

    function setUp() public {
        harness = new Poseidon2T4Harness();
    }

    function test_poseidon2t4_vectors_smoke() public view {
        string memory fixture = vm.readFile(FIXTURE_PATH);
        uint256 total = fixture.readUint(".count");
        // The generator writes one deterministic edge-case vector per length first.
        uint256 limit = total < 9 ? total : 9;
        for (uint256 i = 0; i < limit; i++) {
            _assertVector(fixture, i);
        }
    }

    function test_poseidon2t4_vectors_fuzzSample(uint256 seed) public view {
        string memory fixture = vm.readFile(FIXTURE_PATH);
        uint256 total = fixture.readUint(".count");
        require(total > 0, "empty fixture");

        // Sample a single index per fuzz case (keeps runtime reasonable).
        uint256 idx = uint256(keccak256(abi.encode(seed))) % total;
        _assertVector(fixture, idx);
    }

    function testFuzz_hashUpTo5_matchesFixedArity(uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        public
        pure
    {
        assertEq(Poseidon2T4.hashUpTo5(2, a0, a1, 0, 0, 0), Poseidon2T4.hash2(a0, a1));
        assertEq(Poseidon2T4.hashUpTo5(3, a0, a1, a2, 0, 0), Poseidon2T4.hash3(a0, a1, a2));
        assertEq(Poseidon2T4.hashUpTo5(4, a0, a1, a2, a3, 0), Poseidon2T4.hash4(a0, a1, a2, a3));
        assertEq(Poseidon2T4.hashUpTo5(5, a0, a1, a2, a3, a4), Poseidon2T4.hash5(a0, a1, a2, a3, a4));
    }

    /// @dev Positive control for the harness itself. Without it the rejection tests below could pass
    ///      against a harness whose round-constant plumbing is broken, since a bad `rc` would not
    ///      change which lengths revert.
    function testFuzz_harnessHashUpTo5WithConstants_matchesFixedArity(
        uint256 a0,
        uint256 a1,
        uint256 a2,
        uint256 a3,
        uint256 a4
    ) public view {
        assertEq(harness.hashUpTo5WithConstants(2, a0, a1, 0, 0, 0), Poseidon2T4.hash2(a0, a1));
        assertEq(harness.hashUpTo5WithConstants(5, a0, a1, a2, a3, a4), Poseidon2T4.hash5(a0, a1, a2, a3, a4));
    }

    function test_revertWhen_hashUpTo5WithConstantsLengthBelowTwo() public {
        // Arrange
        uint256[2] memory invalidLengths = [uint256(0), uint256(1)];

        // Act / Assert
        for (uint256 i = 0; i < invalidLengths.length; ++i) {
            vm.expectRevert(Poseidon2T4.InvalidHashLength.selector);
            harness.hashUpTo5WithConstants(invalidLengths[i], 1, 2, 3, 4, 5);
        }
    }

    function test_revertWhen_hashUpTo5WithConstantsLengthAboveFive() public {
        // Arrange - the third entry is a field-modular alias of the valid length five.
        uint256[3] memory invalidLengths = [uint256(6), type(uint256).max, Poseidon2T4.PRIME + 5];

        // Act / Assert
        for (uint256 i = 0; i < invalidLengths.length; ++i) {
            vm.expectRevert(Poseidon2T4.InvalidHashLength.selector);
            harness.hashUpTo5WithConstants(invalidLengths[i], 1, 2, 3, 4, 5);
        }
    }

    function _assertVector(string memory fixture, uint256 idx) internal view {
        string memory base = string.concat(".vectors[", vm.toString(idx), "]");
        string[] memory inputsHex = fixture.readStringArray(string.concat(base, ".inputs"));
        string memory expectedHex = fixture.readString(string.concat(base, ".expected"));

        uint256[] memory inputs = new uint256[](inputsHex.length);
        for (uint256 i = 0; i < inputsHex.length; i++) {
            inputs[i] = vm.parseUint(inputsHex[i]);
        }
        uint256 expected = vm.parseUint(expectedHex);
        uint256 actual = _hash(inputs);
        assertEq(actual, expected, string.concat("vector mismatch idx=", vm.toString(idx)));
    }

    function _hash(uint256[] memory inps) internal pure returns (uint256) {
        if (inps.length == 1) return Poseidon2T4.hash1(inps[0]);
        if (inps.length == 2) return Poseidon2T4.hash2(inps[0], inps[1]);
        if (inps.length == 3) return Poseidon2T4.hash3(inps[0], inps[1], inps[2]);
        if (inps.length == 4) return Poseidon2T4.hash4(inps[0], inps[1], inps[2], inps[3]);
        if (inps.length == 5) return Poseidon2T4.hash5(inps[0], inps[1], inps[2], inps[3], inps[4]);
        if (inps.length == 6) return Poseidon2T4.hash6(inps[0], inps[1], inps[2], inps[3], inps[4], inps[5]);
        if (inps.length == 7) {
            return Poseidon2T4.hash7(inps[0], inps[1], inps[2], inps[3], inps[4], inps[5], inps[6]);
        }
        if (inps.length == 8) {
            return Poseidon2T4.hash8(inps[0], inps[1], inps[2], inps[3], inps[4], inps[5], inps[6], inps[7]);
        }
        if (inps.length == 9) {
            return Poseidon2T4.hash9(inps[0], inps[1], inps[2], inps[3], inps[4], inps[5], inps[6], inps[7], inps[8]);
        }
        revert("unsupported length");
    }
}
