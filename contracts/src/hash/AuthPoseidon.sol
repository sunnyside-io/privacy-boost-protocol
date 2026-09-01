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

import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {LibZeroHashes} from "src/lib/LibZeroHashes.sol";
import {
    DOMAIN_REG_NODE,
    MAX_AUTH_TREE_DEPTH,
    MAX_NOTE_TREE_DEPTH,
    MAX_SPEND_APPROVAL_BATCH,
    SPEND_APPROVAL_BATCH_DEPTH
} from "src/interfaces/Constants.sol";

/// @notice Shared optimized Poseidon entry point for one AuthRegistry implementation.
/// @dev AuthRegistry deploys this stateless helper from its constructor. Keeping the permutation
///      here avoids duplicating its bytecode in AuthRegistry without requiring linked-library
///      addresses in deployment or verification tooling.
/// @custom:security-contact contact@sunnyside.io
contract AuthPoseidon {
    error InvalidBatchWidth();
    error InvalidAuthPathLength();

    /// @notice Hash two to five field elements with the shared Poseidon2 permutation.
    /// @dev `len` must be from two through five. Inputs after the active length do not affect the digest.
    /// @param len Number of active inputs.
    /// @param a0 First input field element.
    /// @param a1 Second input field element.
    /// @param a2 Third input field element when `len` is at least three.
    /// @param a3 Fourth input field element when `len` is at least four.
    /// @param a4 Fifth input field element when `len` is five.
    /// @return The Poseidon2 digest of the active inputs.
    function hash(uint256 len, uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        external
        pure
        returns (uint256)
    {
        return Poseidon2T4.hashUpTo5(len, a0, a1, a2, a3, a4);
    }

    /// @notice Compute the fixed-depth Merkle root of a spend-approval commitment batch.
    /// @dev Accepts one through `MAX_SPEND_APPROVAL_BATCH` commitments. Odd levels are padded with the canonical
    ///      zero hash for that level until `SPEND_APPROVAL_BATCH_DEPTH` levels have been computed.
    /// @param commitments Ordered spend-approval leaf commitments.
    /// @return The fixed-depth Poseidon2 Merkle root of the batch.
    function hashSpendApprovalBatch(uint256[] calldata commitments) external pure returns (uint256) {
        uint256 width = commitments.length;
        if (width == 0 || width > MAX_SPEND_APPROVAL_BATCH) revert InvalidBatchWidth();

        uint256[MAX_NOTE_TREE_DEPTH + 1] memory zeros = LibZeroHashes.get();
        uint256[] memory spine = commitments;
        bytes memory rc = Poseidon2T4.loadRoundConstants();
        for (uint256 level = 0; level < SPEND_APPROVAL_BATCH_DEPTH; ++level) {
            uint256 parentCount = (width + 1) / 2;
            for (uint256 i = 0; i < parentCount; ++i) {
                uint256 left = spine[2 * i];
                uint256 right = (2 * i + 1 < width) ? spine[2 * i + 1] : zeros[level];
                spine[i] = Poseidon2T4.hashUpTo5WithConstants(rc, 2, left, right, 0, 0, 0);
            }
            width = parentCount;
        }
        return spine[0];
    }

    /// @notice Compute every parent along an AuthRegistry Merkle path.
    /// @dev Accepts a depth from one through `MAX_AUTH_TREE_DEPTH`. At each level the low bit of `index` selects
    ///      whether the current node is the left or right child. Entries at and above `depth` remain zero.
    /// @param leaf Starting leaf value.
    /// @param index Zero-based leaf index whose low bit is consumed at each level.
    /// @param depth Number of siblings to consume and parents to compute.
    /// @param siblings Merkle siblings ordered from the leaf level toward the root.
    /// @return parents Parent hash after each consumed sibling, with unused entries left as zero.
    function hashAuthPath(uint256 leaf, uint256 index, uint256 depth, uint256[MAX_AUTH_TREE_DEPTH] calldata siblings)
        external
        pure
        returns (uint256[MAX_AUTH_TREE_DEPTH] memory parents)
    {
        if (depth == 0 || depth > MAX_AUTH_TREE_DEPTH) revert InvalidAuthPathLength();

        uint256 current = leaf;
        bytes memory rc = Poseidon2T4.loadRoundConstants();
        for (uint256 level = 0; level < depth; ++level) {
            uint256 sibling = siblings[level];
            uint256 left = (index & 1 == 0) ? current : sibling;
            uint256 right = (index & 1 == 0) ? sibling : current;
            current = Poseidon2T4.hashUpTo5WithConstants(rc, 3, DOMAIN_REG_NODE, left, right, 0, 0);
            parents[level] = current;
            index >>= 1;
        }
    }
}
