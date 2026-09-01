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

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IWETH} from "src/interfaces/IWETH.sol";

/// @notice Local-chain wrapped native token with configurable failure behavior for regressions.
contract MockWETH is ERC20, IWETH {
    enum DepositBehavior {
        Exact,
        Revert,
        UnderMint,
        OverMint
    }

    /// @dev The local development chain ids. `setDepositBehavior` and `mint` are deliberately unauthenticated so
    ///      regressions can drive failure modes freely, which makes this contract unsafe to deploy anywhere a
    ///      real balance could depend on it. Both production deploy scripts already refuse to fall back to this
    ///      mock off the two Anvil chains; the constructor repeats that gate so the restriction travels with the code.
    uint256 private constant LOCAL_CHAIN_A_ID = 31337;
    uint256 private constant LOCAL_CHAIN_B_ID = 31338;

    DepositBehavior public depositBehavior;

    error DepositFailed();
    error NotLocalChain();
    error WithdrawFailed();

    constructor() ERC20("Mock Wrapped Ether", "WETH") {
        if (block.chainid != LOCAL_CHAIN_A_ID && block.chainid != LOCAL_CHAIN_B_ID) revert NotLocalChain();
    }

    function setDepositBehavior(DepositBehavior behavior) external {
        depositBehavior = behavior;
    }

    /// @dev WETH9 wraps on a bare value transfer as well as on an explicit `deposit()`, and callers rely on
    ///      that. Route both through the same configurable behavior so the mock cannot silently diverge.
    receive() external payable {
        _deposit();
    }

    function deposit() external payable override {
        _deposit();
    }

    /// @notice Unwrap `amount` back to native ETH, mirroring WETH9.
    /// @dev Present so that a caller holding this mock is exercised against the same exit surface real WETH
    ///      offers. Its absence would let a test pass while the production path has no way back to native.
    function withdraw(uint256 amount) external {
        _burn(msg.sender, amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _deposit() private {
        if (depositBehavior == DepositBehavior.Revert) revert DepositFailed();

        uint256 mintAmount = msg.value;
        if (depositBehavior == DepositBehavior.UnderMint && mintAmount > 0) {
            --mintAmount;
        } else if (depositBehavior == DepositBehavior.OverMint) {
            ++mintAmount;
        }
        _mint(msg.sender, mintAmount);
    }
}
