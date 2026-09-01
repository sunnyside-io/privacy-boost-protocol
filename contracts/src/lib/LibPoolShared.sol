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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {TOKEN_TYPE_ERC20, ROOT_HISTORY_SIZE} from "src/interfaces/Constants.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";

/// @title LibPoolShared
/// @notice Small pool helpers shared by PrivacyBoost and every settlement library (deposit, epoch, portal,
///         gift, forced, gateway), so this cross-cutting logic lives in exactly one place and cannot drift
///         between call sites.
/// @dev Functions are `internal`, so they inline into each caller instead of deploying and linking a separate
///      library. Storage is reached the same way every settlement library reaches it: the pool's mappings are
///      passed in by reference and, because callers run against the pool's storage under delegatecall, the
///      writes land in the pool.
/// @custom:security-contact contact@sunnyside.io
library LibPoolShared {
    using SafeERC20 for IERC20;

    /// @notice Append `rootNew` to tree `treeNum`'s recent-root ring buffer and advance the cursor.
    /// @dev The ring buffer keeps the last ROOT_HISTORY_SIZE roots so a proof can verify against a slightly
    ///      stale root (a tree append between proof build and mining does not invalidate it). Callers pass
    ///      their own `treeRootHistory` / `treeRootHistoryCursor` mappings by reference.
    function pushTreeRoot(
        mapping(uint256 => uint256[ROOT_HISTORY_SIZE]) storage treeRootHistory,
        mapping(uint256 => uint256) storage treeRootHistoryCursor,
        uint256 treeNum,
        uint256 rootNew
    ) internal {
        uint256 next = (treeRootHistoryCursor[treeNum] + 1) % ROOT_HISTORY_SIZE;
        treeRootHistory[treeNum][next] = rootNew;
        treeRootHistoryCursor[treeNum] = next;
    }

    /// @notice Resolve `tokenId` to its registered ERC-20 and `safeTransfer` `amount` to `to`.
    /// @dev Reverts on an unregistered token (`InvalidWithdrawal`) or a non-ERC20 token type
    ///      (`TokenNotSupported`) — the same gate every settlement payout and refund applied inline before.
    function transferToken(ITokenRegistry tokenRegistry, uint16 tokenId, address to, uint256 amount) internal {
        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(tokenId);
        if (tokenAddress == address(0)) revert IPrivacyBoost.InvalidWithdrawal();
        if (tokenType != TOKEN_TYPE_ERC20) revert IPrivacyBoost.TokenNotSupported(tokenType);
        IERC20(tokenAddress).safeTransfer(to, amount);
    }
}
