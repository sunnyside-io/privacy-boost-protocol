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

/// @title ITokenRegistry
/// @notice Interface for append-only registry for compact token IDs (uint16)
interface ITokenRegistry {
    // ============ Errors ============

    /// @notice Thrown when attempting to register a token that already exists
    error TokenAlreadyRegistered();

    /// @notice Thrown when attempting to register a token type that is not supported
    /// @param tokenType The unsupported token type
    error TokenTypeNotSupported(uint8 tokenType);

    /// @notice Thrown when attempting to register a token with zero address
    error ZeroAddress();

    /// @notice Thrown when the token ID counter overflows (exceeds uint16 max)
    error TokenIdOverflow();

    /// @notice Thrown when attempting to register an address that is not a contract
    error NotAContract();

    // ============ Events ============

    /// @notice Emitted when a new token is registered
    /// @param tokenId The assigned compact token ID
    /// @param tokenType The type of token (e.g., ERC20, ERC721)
    /// @param tokenAddress The address of the token contract
    /// @param tokenSubId The sub-ID for distinguishing tokens (e.g., ERC1155 token ID)
    event TokenRegistered(uint16 indexed tokenId, uint8 tokenType, address tokenAddress, uint256 tokenSubId);

    // ============ Functions ============

    /// @notice Initialize the registry
    /// @param initialOwner The address of the initial owner
    function initialize(address initialOwner) external;

    /// @notice Register a new token and assign a compact ID
    /// @dev Only standard ERC20 tokens are supported. The token ID starts from 1.
    ///      Fee-on-transfer tokens will be rejected at deposit time.
    ///      Rebasing tokens (stETH, AMPL) are NOT supported and may cause fund loss.
    /// @param tokenType The type of token (must be TOKEN_TYPE_ERC20)
    /// @param tokenAddress The address of the token contract
    /// @param tokenSubId The sub-ID for the token (0 for ERC20)
    /// @return tokenId The assigned compact token ID
    function register(uint8 tokenType, address tokenAddress, uint256 tokenSubId) external returns (uint16 tokenId);

    /// @notice Get token info by compact ID
    /// @param tokenId The compact token ID
    /// @return tokenType The type of token
    /// @return tokenAddress The address of the token contract
    /// @return tokenSubId The sub-ID for the token
    function tokenOf(uint16 tokenId) external view returns (uint8 tokenType, address tokenAddress, uint256 tokenSubId);

    /// @notice Get compact ID by token key hash
    /// @param key The keccak256 hash of (tokenType, tokenAddress, tokenSubId)
    /// @return tokenId The compact token ID (0 if not registered)
    function idOf(bytes32 key) external view returns (uint16 tokenId);

    /// @notice Get the next token ID to be assigned
    /// @return id The next token ID
    function nextId() external view returns (uint16 id);
}
