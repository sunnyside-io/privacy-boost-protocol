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

import {GatewaySlot} from "src/interfaces/IStructs.sol";

/// @notice Pool callback to an approved gateway executor. The pool grants allowance first;
///         the executor pulls exactly inputAmount and reverts on any target failure or
///         min-output shortfall so the pool can settle a fallback re-shield.
interface IGatewayExecutor {
    /// @notice Execute one policy-approved external call and return its output tokens to the pool.
    /// @dev The executor must pull exactly `inputAmount` from the pool, reject target failure, enforce the signed
    ///      receipt minimum, and leave no residual input allowance. Implementations may intentionally ignore returndata.
    /// @param inputTokenId Registered token ID of the input asset.
    /// @param inputTokenAddress ERC-20 input token address resolved by the pool.
    /// @param outputTokenAddress ERC-20 output token address resolved from the signed receipt.
    /// @param inputAmount Exact input amount made available by the pool.
    /// @param slot Signed gateway target, calldata, expiry, and output constraints for this withdrawal.
    function executeGatewayCall(
        uint16 inputTokenId,
        address inputTokenAddress,
        address outputTokenAddress,
        uint256 inputAmount,
        GatewaySlot calldata slot
    ) external;
}
