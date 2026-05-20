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

import {EcdsaSig} from "src/interfaces/IStructs.sol";

/// @title IAuthRegistry
/// @notice Interface for Poseidon2T4 Merkle registry for approval keys with multi-tree support
interface IAuthRegistry {
    // ============ Errors ============

    /// @notice Thrown when attempting to register an account key that is already registered
    error AlreadyRegistered();

    /// @notice Thrown when attempting to rotate a key for an account that is not registered
    error NotRegistered();

    /// @notice Thrown when the provided signature is invalid
    error InvalidSignature();

    /// @notice Thrown when an ERC-7739 fallback signature has a malformed appendix length
    error InvalidSignatureLength();

    /// @notice Thrown when an ERC-7739 fallback signature is scoped to a different app domain
    error InvalidERC7739AppDomain();

    /// @notice Thrown when an ERC-7739 fallback signature uses an unsupported contents description
    error InvalidERC7739ContentsDescription();

    /// @notice Thrown when an ERC-7739 fallback signature contents hash is not bound to the current action
    error InvalidERC7739ContentsHash();

    /// @notice Thrown when an ERC-7739 fallback signature is rejected after wrapping
    error InvalidERC7739WrappedSignature();

    /// @notice Thrown when the current tree is full and cannot accept new registrations
    error RegistryFull();

    /// @notice Thrown when the computed leaf hash is zero (invalid)
    error InvalidLeaf();

    /// @notice Thrown when the signature has expired
    error SignatureExpired();

    /// @notice Thrown when the account ID is zero
    error InvalidAccountId();

    /// @notice Thrown when caller is neither the owner nor an allowed relay
    error NotAuthorized();

    /// @notice Thrown when attempting to set zero address as relay
    error InvalidRelayAddress();

    /// @notice Thrown when caller is not the operator
    error NotOperator();

    /// @notice Thrown when operator address is zero
    error InvalidOperatorAddress();

    /// @notice Thrown when attempting to access an auth key that doesn't exist
    error AuthKeyNotFound();

    /// @notice Thrown when attempting to use a revoked auth key
    error AuthKeyAlreadyRevoked();

    /// @notice Thrown when adding auth key with different owner than existing account
    error OwnerMismatch();

    /// @notice Thrown when the provided auth public key is not on the BabyJubJub curve or is a low-order torsion point
    error InvalidAuthPublicKey();

    // ============ Events ============

    /// @notice Emitted when a new account ID is registered
    /// @param accountId The unique account ID identifier
    /// @param owner The owner address
    /// @param treeNumber The tree number where the key was registered
    /// @param authPkX The X coordinate of the approval public key
    /// @param authPkY The Y coordinate of the approval public key
    /// @param expiry The expiry timestamp of the approval key
    event Registered(
        uint256 indexed accountId,
        address indexed owner,
        uint256 treeNumber,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry
    );

    /// @notice Emitted when a tree root is updated
    /// @param treeNumber The tree that was updated
    /// @param root The new root value
    event RootUpdated(uint256 indexed treeNumber, uint256 root);

    /// @notice Emitted when a relay address is allowed or disallowed
    /// @param relay The relay address
    /// @param allowed Whether the relay is allowed
    event RelayUpdated(address indexed relay, bool allowed);

    /// @notice Emitted when the operator address is updated
    /// @param oldOperator The previous operator address
    /// @param newOperator The new operator address
    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);

    /// @notice Emitted when a new auth key is added to an account
    /// @param accountId The account ID
    /// @param authKeyId The unique auth key identifier
    /// @param treeNumber The tree number where the auth key was registered
    /// @param authPkX The X coordinate of the approval public key
    /// @param authPkY The Y coordinate of the approval public key
    event AuthKeyAdded(
        uint256 indexed accountId, bytes32 indexed authKeyId, uint256 treeNumber, uint256 authPkX, uint256 authPkY
    );

    /// @notice Emitted when an auth key is rotated
    /// @param accountId The account ID
    /// @param authKeyId The unique auth key identifier
    /// @param newAuthPkX The new X coordinate of the approval public key
    /// @param newAuthPkY The new Y coordinate of the approval public key
    /// @param treeIndex The leaf index within the tree
    /// @param newExpiry The new expiry timestamp
    event AuthKeyRotated(
        uint256 indexed accountId,
        bytes32 indexed authKeyId,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint32 treeIndex,
        uint64 newExpiry
    );

    /// @notice Emitted when an auth key is revoked
    /// @param accountId The account ID
    /// @param authKeyId The unique auth key identifier
    /// @param treeIndex The leaf index within the tree
    event AuthKeyRevoked(uint256 indexed accountId, bytes32 indexed authKeyId, uint32 treeIndex);

    // ============ Functions ============

    /// @notice Initialize the registry
    /// @param initialOwner The address of the initial owner
    function initialize(address initialOwner) external;

    /// @notice Set the operator address
    /// @dev Only callable by owner. Operator can manage relays.
    /// @param operator_ The new operator address
    function setOperator(address operator_) external;

    /// @notice Set allowed relay addresses
    /// @dev Only callable by operator. Relays can submit register/rotate transactions on behalf of users.
    /// @param relays Array of relay addresses to update
    /// @param allowed Whether to allow or disallow the relays
    function setAllowedRelays(address[] calldata relays, bool allowed) external;

    /// @notice Register a new account ID with an approval key
    /// @dev Uses EIP-712 typed signature for authorization. The account ID is derived internally as
    ///      computeAccountId(expectedOwner, salt). If the current tree is full, a new tree is created automatically.
    ///      Supports EOAs and EIP-1271 contract wallets. EOAs should submit 65-byte signatures with v in {27,28}.
    /// @param salt User-provided salt used to derive and bind accountId to expectedOwner
    /// @param authPkX The X coordinate of the approval public key
    /// @param authPkY The Y coordinate of the approval public key
    /// @param expiry The signature expiry timestamp (0 for no expiry)
    /// @param expectedOwner The expected owner address (must validate the signature)
    /// @param sig The EIP-712 typed signature
    function register(
        uint256 salt,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        bytes calldata sig
    ) external;

    /// @notice Register a new account ID with a legacy 65-byte ECDSA tuple signature.
    /// @dev Backwards-compatible selector for servers deployed before the bytes signature ABI.
    function register(
        uint256 salt,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        EcdsaSig calldata sig
    ) external;

    /// @notice Compute the deterministic account ID for an owner and salt
    /// @dev accountId = Poseidon2T4(DOMAIN_ACCOUNTID, uint256(uint160(owner)), salt)
    function computeAccountId(address owner, uint256 salt) external pure returns (uint256);

    /// @notice Rotate the approval key for a specific auth key
    /// @dev Uses EIP-712 typed signature for authorization. The auth key must exist and not be revoked.
    ///      Only the owner or an allowed relay can call this function.
    ///      Supports EOAs and EIP-1271 contract wallets. EOAs should submit 65-byte signatures with v in {27,28}.
    ///      Use cases: (1) extend expiry without changing authPkX, (2) periodic key refresh on same device.
    ///      Unlike revoke+register, rotate reuses the Merkle slot and allows keeping the same authPkX.
    /// @param accountId The account ID
    /// @param oldAuthPkX The X coordinate of the auth key to rotate (identifies the auth key)
    /// @param newAuthPkX The new X coordinate of the approval public key
    /// @param newAuthPkY The new Y coordinate of the approval public key
    /// @param newExpiry The new signature expiry timestamp (0 for no expiry)
    /// @param sig The EIP-712 typed signature from the owner
    function rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        bytes calldata sig
    ) external;

    /// @notice Rotate an approval key with a legacy 65-byte ECDSA tuple signature.
    /// @dev Backwards-compatible selector for servers deployed before the bytes signature ABI.
    function rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        EcdsaSig calldata sig
    ) external;

    /// @notice Revoke a specific auth key
    /// @dev Sets the leaf to zero in the Merkle tree. Revocation is permanent.
    ///      Only the owner or an allowed relay can call this function.
    ///      Supports EOAs and EIP-1271 contract wallets. EOAs should submit 65-byte signatures with v in {27,28}.
    ///      Note: The Merkle tree slot is permanently consumed and cannot be reused.
    ///      The same authPkX cannot be re-registered for security reasons.
    /// @param accountId The account ID
    /// @param authPkX The X coordinate of the auth key to revoke
    /// @param expiry The signature expiry timestamp (0 for no expiry)
    /// @param sig The EIP-712 typed signature from the owner
    function revoke(uint256 accountId, uint256 authPkX, uint64 expiry, bytes calldata sig) external;

    /// @notice Revoke a specific auth key with a legacy 65-byte ECDSA tuple signature.
    /// @dev Backwards-compatible selector for servers deployed before the bytes signature ABI.
    function revoke(uint256 accountId, uint256 authPkX, uint64 expiry, EcdsaSig calldata sig) external;

    /// @notice Compute the leaf hash for a registration
    /// @dev Uses Poseidon2MD hash with DOMAIN_REG_LEAF domain separator.
    ///      Owner address is no longer included in the leaf hash as it can be
    ///      retrieved via ownerOf(accountId) when needed.
    /// @param accountId The account ID
    /// @param authPkX The X coordinate of the approval public key
    /// @param authPkY The Y coordinate of the approval public key
    /// @param expiry The expiry timestamp
    /// @return The computed leaf hash
    function computeLeaf(uint256 accountId, uint256 authPkX, uint256 authPkY, uint64 expiry)
        external
        pure
        returns (uint256);

    /// @notice Get roots of all existing auth trees
    /// @return roots Dynamic array of roots for each tree (length = currentAuthTreeNumber + 1)
    function getAllAuthTreeRoots() external view returns (uint256[] memory roots);

    /// @notice Get the current active tree's root
    /// @dev Backwards compatibility function
    /// @return The current active tree's root
    function registryRoot() external view returns (uint256);

    // ============ View Functions (State Variables) ============

    /// @notice The depth of the auth Merkle tree
    function authTreeDepth() external view returns (uint8);

    /// @notice Maximum tree number allowed (2^15 - 1, constrained by circuit packing)
    function MAX_AUTH_TREE_NUMBER() external view returns (uint16);

    /// @notice Size of the root history ring buffer per tree
    function AUTH_ROOT_HISTORY_SIZE() external view returns (uint256);

    /// @notice Current active tree number (0-indexed)
    function currentAuthTreeNumber() external view returns (uint256);

    /// @notice Get the root of a specific tree
    /// @param treeNum The tree number
    /// @return The tree root
    function authTreeRoot(uint256 treeNum) external view returns (uint256);

    /// @notice Get the leaf count of a specific tree
    /// @param treeNum The tree number
    /// @return The number of leaves in the tree
    function authTreeCount(uint256 treeNum) external view returns (uint32);

    /// @notice Get a historical root from a tree's history
    /// @param treeNum The tree number
    /// @param idx The history index
    /// @return The historical root
    function authTreeRootHistory(uint256 treeNum, uint256 idx) external view returns (uint256);

    /// @notice Get the cursor position in the root history ring buffer
    /// @param treeNum The tree number
    /// @return The cursor position
    function authTreeRootHistoryCursor(uint256 treeNum) external view returns (uint256);

    /// @notice Get the owner of an account ID
    /// @param accountId The account ID
    /// @return The owner address
    function ownerOf(uint256 accountId) external view returns (address);

    /// @notice Get the tree number where an auth key is registered
    /// @param authKeyId The auth key identifier
    /// @return The tree number
    function authKeyTreeOf(bytes32 authKeyId) external view returns (uint16);

    /// @notice Get the index of an auth key within its tree
    /// @param authKeyId The auth key identifier
    /// @return The index
    function authKeyIndexOf(bytes32 authKeyId) external view returns (uint32);

    /// @notice Check if an auth key is revoked
    /// @param authKeyId The auth key identifier
    /// @return True if revoked
    function authKeyRevoked(bytes32 authKeyId) external view returns (bool);

    /// @notice Get the nonce for an account ID (replay protection)
    /// @param accountId The account ID
    /// @return The current nonce
    function nonces(uint256 accountId) external view returns (uint256);

    /// @notice Check if an address is an allowed relay
    /// @param relay The address to check
    /// @return True if the address is an allowed relay
    function allowedRelays(address relay) external view returns (bool);

    /// @notice Operator address for operational functions
    function operator() external view returns (address);

    // ============ Multi-Device View Functions ============

    /// @notice Get all auth keys for an account
    /// @param accountId The account ID
    /// @return Array of auth key IDs
    function getAuthKeys(uint256 accountId) external view returns (bytes32[] memory);

    /// @notice Compute the auth key ID for an account and auth public key
    /// @param accountId The account ID
    /// @param authPkX The X coordinate of the auth public key
    /// @return The auth key ID
    function computeAuthKeyId(uint256 accountId, uint256 authPkX) external pure returns (bytes32);

    /// @notice Get all info about an auth key in a single call
    /// @dev Useful for clients to atomically retrieve all auth key state.
    ///      For unregistered authKeyIds, returns (0, 0, false).
    /// @param authKeyId The auth key identifier
    /// @return treeNum The tree number where the auth key is registered
    /// @return index The index within the tree
    /// @return revoked Whether the auth key has been revoked
    function getAuthKeyInfo(bytes32 authKeyId) external view returns (uint16 treeNum, uint32 index, bool revoked);
}
