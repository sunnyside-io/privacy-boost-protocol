// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";

import {AuthPoseidon} from "src/hash/AuthPoseidon.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {DOMAIN_REG_NODE, MAX_SPEND_APPROVAL_BATCH, SPEND_APPROVAL_BATCH_DEPTH} from "src/interfaces/Constants.sol";
import {LibZeroHashes} from "src/lib/LibZeroHashes.sol";

contract AuthPoseidonTest is Test {
    AuthPoseidon internal authPoseidon;

    function setUp() public {
        authPoseidon = new AuthPoseidon();
    }

    function _manualSpendApprovalRoot(uint256[] memory commitments) internal pure returns (uint256) {
        uint256[25] memory zeros = LibZeroHashes.get();
        uint256[] memory spine = new uint256[](commitments.length);
        for (uint256 i = 0; i < commitments.length; ++i) {
            spine[i] = commitments[i];
        }
        uint256 width = commitments.length;
        for (uint256 level = 0; level < SPEND_APPROVAL_BATCH_DEPTH; ++level) {
            uint256 parentCount = (width + 1) / 2;
            for (uint256 i = 0; i < parentCount; ++i) {
                uint256 left = spine[2 * i];
                uint256 right = (2 * i + 1 < width) ? spine[2 * i + 1] : zeros[level];
                spine[i] = Poseidon2T4.hash2(left, right);
            }
            width = parentCount;
        }
        return spine[0];
    }

    function test_hashSpendApprovalBatch_matchesManualFold() public view {
        // Arrange
        uint256[] memory commitments = new uint256[](7);
        for (uint256 i = 0; i < commitments.length; ++i) {
            commitments[i] = 100 + i;
        }
        uint256[25] memory zeros = LibZeroHashes.get();
        uint256[] memory spine = new uint256[](commitments.length);
        for (uint256 i = 0; i < commitments.length; ++i) {
            spine[i] = commitments[i];
        }
        uint256 width = commitments.length;
        for (uint256 level = 0; level < SPEND_APPROVAL_BATCH_DEPTH; ++level) {
            uint256 parentCount = (width + 1) / 2;
            for (uint256 i = 0; i < parentCount; ++i) {
                uint256 left = spine[2 * i];
                uint256 right = (2 * i + 1 < width) ? spine[2 * i + 1] : zeros[level];
                spine[i] = Poseidon2T4.hash2(left, right);
            }
            width = parentCount;
        }
        uint256 expected = spine[0];

        // Act
        uint256 actual = authPoseidon.hashSpendApprovalBatch(commitments);

        // Assert
        assertEq(actual, expected);
    }

    function test_hashAuthPath_matchesManualFold() public view {
        // Arrange
        uint256 leaf = 123;
        uint256 index = 0xA53D1;
        uint256 depth = 20;
        uint256[20] memory siblings;
        uint256[20] memory expected;
        for (uint256 level = 0; level < depth; ++level) {
            siblings[level] = 1000 + level;
        }
        uint256 current = leaf;
        uint256 idx = index;
        for (uint256 level = 0; level < depth; ++level) {
            uint256 left = (idx & 1 == 0) ? current : siblings[level];
            uint256 right = (idx & 1 == 0) ? siblings[level] : current;
            current = Poseidon2T4.hash3(DOMAIN_REG_NODE, left, right);
            expected[level] = current;
            idx >>= 1;
        }

        // Act
        uint256[20] memory actual = authPoseidon.hashAuthPath(leaf, index, depth, siblings);

        // Assert
        for (uint256 level = 0; level < depth; ++level) {
            assertEq(actual[level], expected[level]);
        }
    }

    function test_hashSpendApprovalBatch_representativeWidthsMatchManualFold() public view {
        // Arrange / Act / Assert
        uint256[10] memory widths = [uint256(1), 2, 3, 7, 31, 32, 33, 128, 255, 256];
        for (uint256 w = 0; w < widths.length; ++w) {
            uint256 width = widths[w];
            uint256[] memory commitments = new uint256[](width);
            for (uint256 i = 0; i < width; ++i) {
                commitments[i] = 1000 + i;
            }
            assertEq(authPoseidon.hashSpendApprovalBatch(commitments), _manualSpendApprovalRoot(commitments));
        }
    }

    function test_hashAuthPath_depthsOneThroughTwentyMatchManualFold() public view {
        // Arrange
        uint256 leaf = 123;
        uint256 index = 0xA53D1;
        uint256[20] memory siblings;
        for (uint256 level = 0; level < siblings.length; ++level) {
            siblings[level] = 1000 + level;
        }

        // Act / Assert
        for (uint256 depth = 1; depth <= 20; ++depth) {
            uint256[20] memory actual = authPoseidon.hashAuthPath(leaf, index, depth, siblings);
            uint256 current = leaf;
            uint256 idx = index;
            for (uint256 level = 0; level < depth; ++level) {
                uint256 left = (idx & 1 == 0) ? current : siblings[level];
                uint256 right = (idx & 1 == 0) ? siblings[level] : current;
                current = Poseidon2T4.hash3(DOMAIN_REG_NODE, left, right);
                assertEq(actual[level], current);
                idx >>= 1;
            }
        }
    }

    function test_revertWhen_hashSpendApprovalBatchWidthInvalid() public {
        // Arrange
        uint256[] memory commitments = new uint256[](0);

        // Act
        vm.expectRevert(AuthPoseidon.InvalidBatchWidth.selector);

        // Assert
        authPoseidon.hashSpendApprovalBatch(commitments);
    }

    function test_revertWhen_hashSpendApprovalBatchWidthExceedsMaximum() public {
        // Arrange
        uint256[] memory commitments = new uint256[](MAX_SPEND_APPROVAL_BATCH + 1);

        // Act
        vm.expectRevert(AuthPoseidon.InvalidBatchWidth.selector);

        // Assert
        authPoseidon.hashSpendApprovalBatch(commitments);
    }

    function test_revertWhen_hashAuthPathLengthZero() public {
        // Arrange
        uint256[20] memory siblings;

        // Act
        vm.expectRevert(AuthPoseidon.InvalidAuthPathLength.selector);

        // Assert
        authPoseidon.hashAuthPath(1, 0, 0, siblings);
    }

    function test_revertWhen_hashAuthPathLengthInvalid() public {
        // Arrange
        uint256[20] memory siblings;

        // Act
        vm.expectRevert(AuthPoseidon.InvalidAuthPathLength.selector);

        // Assert
        authPoseidon.hashAuthPath(1, 0, 21, siblings);
    }

    function test_revertWhen_hashLengthAliasesFieldPrime() public {
        // Arrange
        uint256 aliasedLength = Poseidon2T4.PRIME + 5;

        // Act
        vm.expectRevert(Poseidon2T4.InvalidHashLength.selector);

        // Assert
        authPoseidon.hash(aliasedLength, 1, 2, 3, 4, 5);
    }
}
