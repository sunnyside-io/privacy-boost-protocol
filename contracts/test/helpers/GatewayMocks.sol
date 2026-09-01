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

import {ERC20, IERC20, IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

/// @notice Minimal ERC-4626 vault for sync gateway tests. Default OZ math; supports yield simulation.
contract MockERC4626 is ERC4626 {
    enum DepositMode {
        Normal,
        Revert,
        NoPull,
        PartialPull,
        ShortOutput,
        BurnGas,
        WrongReceiver,
        ReenterPool
    }

    DepositMode public depositMode;
    bool public revertRedeems;

    error MockTargetReverted();
    error UnexpectedReentryResult(bytes4 selector);

    constructor(IERC20 underlying)
        ERC4626(underlying)
        ERC20(
            string.concat("Vault ", IERC20Metadata(address(underlying)).name()),
            string.concat("v", IERC20Metadata(address(underlying)).symbol())
        )
    {}

    function simulateYield(uint256 amount) external {
        IERC20(asset()).transferFrom(msg.sender, address(this), amount);
    }

    function setFailureMode(bool deposits, bool redeems) external {
        depositMode = deposits ? DepositMode.Revert : DepositMode.Normal;
        revertRedeems = redeems;
    }

    function setDepositMode(DepositMode mode) external {
        depositMode = mode;
    }

    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        if (depositMode == DepositMode.Revert) revert MockTargetReverted();
        if (depositMode == DepositMode.NoPull) return assets;
        if (depositMode == DepositMode.PartialPull) {
            require(IERC20(asset()).transferFrom(msg.sender, address(this), assets / 2));
            _mint(receiver, assets);
            return assets;
        }
        if (depositMode == DepositMode.ShortOutput) {
            require(IERC20(asset()).transferFrom(msg.sender, address(this), assets));
            uint256 shares = assets / 2;
            _mint(receiver, shares);
            return shares;
        }
        if (depositMode == DepositMode.BurnGas) {
            while (gasleft() > 1000) {}
            revert MockTargetReverted();
        }
        if (depositMode == DepositMode.WrongReceiver) {
            require(IERC20(asset()).transferFrom(msg.sender, address(this), assets));
            _mint(address(0xdead), assets);
            return assets;
        }
        if (depositMode == DepositMode.ReenterPool) {
            (bool readOk, bytes memory poolData) = msg.sender.staticcall(abi.encodeWithSignature("pool()"));
            require(readOk);
            address pool = abi.decode(poolData, (address));
            (bool reentered, bytes memory reason) = pool.call(
                abi.encodeWithSignature(
                    "rescueGatewayDeposit(uint256,address,bytes32,address,bytes)",
                    uint256(0),
                    receiver,
                    bytes32(0),
                    address(0),
                    bytes("")
                )
            );
            bytes4 selector;
            if (reason.length >= 4) {
                assembly {
                    selector := mload(add(reason, 32))
                }
            }
            bytes4 expected = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
            if (reentered || selector != expected) revert UnexpectedReentryResult(selector);
        }
        return super.deposit(assets, receiver);
    }

    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        if (revertRedeems) revert MockTargetReverted();
        return super.redeem(shares, receiver, owner);
    }
}

/// @notice Token that is standard while notes are created, then can enable a
/// transfer fee to exercise Gateway fail-closed accounting at execution time.
contract MockToggleFeeToken is ERC20 {
    bool public feeEnabled;

    constructor() ERC20("Toggle Fee Token", "TFT") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setFeeEnabled(bool enabled) external {
        feeEnabled = enabled;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (feeEnabled && from != address(0) && to != address(0)) {
            uint256 fee = value / 100;
            super._update(from, address(0xfee), fee);
            super._update(from, to, value - fee);
            return;
        }
        super._update(from, to, value);
    }
}

contract MockFeeERC4626 is MockERC4626 {
    constructor(IERC20 underlying) MockERC4626(underlying) {}
}

/// @notice Stateless AggregationRouterV6 stand-in for the server Gateway E2E.
///         Anvil installs this runtime bytecode at the pinned Router address.
contract MockOneInchRouter {
    struct SwapDescription {
        IERC20 srcToken;
        IERC20 dstToken;
        address payable srcReceiver;
        address payable dstReceiver;
        uint256 amount;
        uint256 minReturnAmount;
        uint256 flags;
    }

    function swap(address, SwapDescription calldata desc, bytes calldata data)
        external
        payable
        returns (uint256 returnAmount, uint256 spentAmount)
    {
        require(msg.value == 0 && desc.flags == 0 && data.length != 0, "invalid mock swap");
        require(desc.amount >= desc.minReturnAmount, "insufficient mock output");
        require(desc.srcToken.transferFrom(msg.sender, address(this), desc.amount), "input transfer failed");
        require(desc.dstToken.transfer(desc.dstReceiver, desc.amount), "output transfer failed");
        return (desc.amount, desc.amount);
    }
}
