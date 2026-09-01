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

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Inventory-backed AggregationRouterV6 stand-in for public testnets.
/// @dev Rates operate on raw token units. This contract deliberately supports
///      exact-input ERC-20 swaps only because ExternalCallGateway requires the
///      complete input amount to be consumed.
contract MockOneInchRouterV6 is Ownable {
    using SafeERC20 for IERC20;

    uint256 public constant MOCK_VERSION = 1;

    struct SwapDescription {
        IERC20 srcToken;
        IERC20 dstToken;
        address payable srcReceiver;
        address payable dstReceiver;
        uint256 amount;
        uint256 minReturnAmount;
        uint256 flags;
    }

    struct PairRate {
        uint256 numerator;
        uint256 denominator;
    }

    mapping(address srcToken => mapping(address dstToken => PairRate)) public pairRates;

    error InvalidPair();
    error InvalidRate();
    error InvalidSwap();
    error PairNotConfigured(address srcToken, address dstToken);
    error InsufficientInventory(address token, uint256 available, uint256 required);
    error InsufficientReturnAmount(uint256 returnAmount, uint256 minReturnAmount);

    event PairRateUpdated(address indexed srcToken, address indexed dstToken, uint256 numerator, uint256 denominator);
    event MockSwap(
        address indexed caller,
        address indexed srcToken,
        address indexed dstToken,
        address dstReceiver,
        uint256 spentAmount,
        uint256 returnAmount
    );

    constructor(address initialOwner) Ownable(initialOwner) {}

    function mockVersion() external pure returns (uint256) {
        return MOCK_VERSION;
    }

    function setPairRate(address srcToken, address dstToken, uint256 numerator, uint256 denominator)
        external
        onlyOwner
    {
        if (srcToken == address(0) || dstToken == address(0) || srcToken == dstToken) revert InvalidPair();
        if (numerator == 0 || denominator == 0) revert InvalidRate();
        pairRates[srcToken][dstToken] = PairRate({numerator: numerator, denominator: denominator});
        emit PairRateUpdated(srcToken, dstToken, numerator, denominator);
    }

    function removePair(address srcToken, address dstToken) external onlyOwner {
        delete pairRates[srcToken][dstToken];
        emit PairRateUpdated(srcToken, dstToken, 0, 0);
    }

    function withdrawToken(IERC20 token, address to, uint256 amount) external onlyOwner {
        if (address(token) == address(0) || to == address(0)) revert InvalidSwap();
        token.safeTransfer(to, amount);
    }

    function quote(address srcToken, address dstToken, uint256 amount) public view returns (uint256 returnAmount) {
        if (amount == 0) revert InvalidSwap();
        PairRate memory rate = pairRates[srcToken][dstToken];
        if (rate.denominator == 0) revert PairNotConfigured(srcToken, dstToken);
        returnAmount = Math.mulDiv(amount, rate.numerator, rate.denominator);
        if (returnAmount == 0) revert InvalidSwap();
        uint256 inventory = IERC20(dstToken).balanceOf(address(this));
        if (inventory < returnAmount) revert InsufficientInventory(dstToken, inventory, returnAmount);
    }

    /// @notice Matches AggregationRouterV6.swap(address,(...),bytes).
    function swap(address executor, SwapDescription calldata desc, bytes calldata data)
        external
        payable
        returns (uint256 returnAmount, uint256 spentAmount)
    {
        if (
            msg.value != 0 || executor == address(0) || address(desc.srcToken) == address(0)
                || address(desc.dstToken) == address(0) || desc.srcReceiver == address(0)
                || desc.dstReceiver == address(0) || desc.flags != 0 || data.length == 0
        ) revert InvalidSwap();

        spentAmount = desc.amount;
        returnAmount = quote(address(desc.srcToken), address(desc.dstToken), spentAmount);
        if (returnAmount < desc.minReturnAmount) {
            revert InsufficientReturnAmount(returnAmount, desc.minReturnAmount);
        }

        desc.srcToken.safeTransferFrom(msg.sender, address(this), spentAmount);
        desc.dstToken.safeTransfer(desc.dstReceiver, returnAmount);

        emit MockSwap(
            msg.sender, address(desc.srcToken), address(desc.dstToken), desc.dstReceiver, spentAmount, returnAmount
        );
    }
}
