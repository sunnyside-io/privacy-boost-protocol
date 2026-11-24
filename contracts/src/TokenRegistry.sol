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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {TokenInfo} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";

/// @title TokenRegistry
/// @notice Append-only registry for compact token IDs (uint16)
contract TokenRegistry is ITokenRegistry, Ownable2StepUpgradeable {
    /// @notice Get token info by compact ID
    mapping(uint16 tokenId => TokenInfo info) public tokenOf;

    /// @notice Get compact ID by token key hash
    mapping(bytes32 key => uint16 tokenId) public idOf;

    /// @notice Latest token ID assigned (0 if none)
    uint16 public nextId;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc ITokenRegistry
    function initialize(address initialOwner) external initializer {
        __Ownable2Step_init();
        _transferOwnership(initialOwner);
    }

    /// @inheritdoc ITokenRegistry
    function register(uint8 tokenType, address tokenAddress, uint256 tokenSubId)
        external
        onlyOwner
        returns (uint16 tokenId)
    {
        if (tokenType != TOKEN_TYPE_ERC20) revert TokenTypeNotSupported(tokenType);
        if (tokenAddress == address(0)) revert ZeroAddress();
        if (tokenAddress.code.length == 0) revert NotAContract();
        bytes32 key = keccak256(abi.encode(tokenType, tokenAddress, tokenSubId));
        if (idOf[key] != 0) revert TokenAlreadyRegistered();
        if (nextId == type(uint16).max) revert TokenIdOverflow();
        tokenId = ++nextId;
        tokenOf[tokenId] = TokenInfo({tokenType: tokenType, tokenAddress: tokenAddress, tokenSubId: tokenSubId});
        idOf[key] = tokenId;
        emit TokenRegistered(tokenId, tokenType, tokenAddress, tokenSubId);
    }

    uint256[50] private __gap;
}
