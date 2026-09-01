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

import {AuthRootStatus, EcdsaSig, TreeRootPair} from "src/interfaces/IStructs.sol";

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

    /// @notice Thrown when caller is not authorized for the requested auth mutation
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

    /// @notice Thrown when a migration root references an auth tree that does not exist
    error InvalidAuthTreeNumber();

    /// @notice Thrown when a migration root is zero
    error InvalidSnapshotRoot();

    /// @notice Thrown when root anchors are already initialized and the legacy hydration migration is unavailable
    error AuthRootAnchorsAlreadyInitialized();

    /// @notice Thrown when the configured auth tree depth is outside the supported range
    /// @param value The configured depth that was rejected
    /// @param min The smallest supported depth
    /// @param max The largest supported depth
    error AuthTreeDepthOutOfRange(uint8 value, uint8 min, uint8 max);
    /// @notice Thrown when trying to create an account that already exists
    error AccountAlreadyExists();

    /// @notice Thrown when an auth-key operation is attempted on an approval-only account
    error ApprovalOnlyAccount();

    /// @notice Thrown when a spend approval commitment is zero or outside the SNARK scalar field
    error InvalidApprovalCommitment();

    /// @notice Thrown when a spend approval batch is empty or larger than MAX_SPEND_APPROVAL_BATCH
    error InvalidApprovalBatchSize();

    /// @notice Thrown when batch commitments are not strictly increasing
    error UnsortedApprovalCommitments();

    /// @notice Thrown when a spend approval expiry is expired or too far in the future
    error InvalidApprovalExpiry();

    /// @notice Thrown when the spend approval has already been inserted
    error SpendApprovalAlreadyExists();

    /// @notice Thrown when the spend approval is not known
    error SpendApprovalNotFound();

    /// @notice Thrown when the spend approval has already been revoked
    error SpendApprovalAlreadyRevoked();

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
    /// @param expiry The expiry timestamp of the approval key
    event AuthKeyAdded(
        uint256 indexed accountId,
        bytes32 indexed authKeyId,
        uint256 treeNumber,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry
    );

    /// @notice Emitted when an auth key is rotated
    /// @param accountId The account ID
    /// @param authKeyId The unique auth key identifier
    /// @param treeNumber The auth tree number containing the rotated leaf
    /// @param newAuthPkX The new X coordinate of the approval public key
    /// @param newAuthPkY The new Y coordinate of the approval public key
    /// @param treeIndex The leaf index within the tree
    /// @param newExpiry The new expiry timestamp
    event AuthKeyRotated(
        uint256 indexed accountId,
        bytes32 indexed authKeyId,
        uint256 treeNumber,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint32 treeIndex,
        uint64 newExpiry
    );

    /// @notice Emitted when an auth key is revoked
    /// @param accountId The account ID
    /// @param authKeyId The unique auth key identifier
    /// @param treeNumber The auth tree number containing the revoked leaf
    /// @param treeIndex The leaf index within the tree
    event AuthKeyRevoked(uint256 indexed accountId, bytes32 indexed authKeyId, uint256 treeNumber, uint32 treeIndex);

    /// @notice Emitted when an approval-only account is created
    /// @param accountId The account ID
    /// @param owner The account owner
    event AccountCreated(uint256 indexed accountId, address indexed owner);

    /// @notice Emitted when an account-owner spend approval batch leaf is inserted
    /// @dev One event per batch; a single approval is a batch of size 1. The
    ///      leaf preimage is reconstructible from (accountId, batchRoot, expiry)
    ///      alone; commitments were hashed on-chain into batchRoot, so indexers
    ///      may trust them for per-spend status without recomputing the root.
    /// @param accountId The account ID
    /// @param batchId keccak256(abi.encode(accountId, batchRoot))
    /// @param batchRoot Depth-SPEND_APPROVAL_BATCH_DEPTH Merkle root over the commitments
    /// @param expiry Approval expiry timestamp shared by the whole batch
    /// @param treeNumber The auth tree number where the leaf was inserted
    /// @param leafIndex The leaf index within the tree
    /// @param commitments The approved commitments in batch order
    event SpendApproved(
        uint256 indexed accountId,
        bytes32 indexed batchId,
        uint256 batchRoot,
        uint64 expiry,
        uint256 treeNumber,
        uint32 leafIndex,
        uint256[] commitments
    );

    /// @notice Emitted when an account-owner spend approval batch leaf is revoked
    /// @param accountId The account ID
    /// @param batchId keccak256(abi.encode(accountId, batchRoot))
    /// @param treeNumber The auth tree number where the leaf was revoked
    /// @param leafIndex The leaf index within the tree
    event SpendApprovalRevoked(
        uint256 indexed accountId, bytes32 indexed batchId, uint256 treeNumber, uint32 leafIndex
    );

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

    /// @notice One-time upgrade migration that seeds root anchors from legacy PrivacyBoost auth snapshots
    /// @dev Intended for proxies upgraded from the auth-snapshot implementation. Operators should collect
    ///      non-zero `PrivacyBoost.authSnapshots(round, treeNum)` roots before upgrading PrivacyBoost and pass
    ///      them here via `upgradeAndCall`. Current roots are accepted directly by `isRecentAuthTreeRoot`;
    ///      non-current legacy snapshot roots are stamped as superseded at the migration block. Existing
    ///      anchors are preserved. This is callable only by the registry owner or the EIP-1967 proxy admin,
    ///      and is also gated by `reinitializer(2)` in the implementation so it can run atomically via
    ///      upgradeAndCall.
    /// @param snapshotRoots The legacy (treeNumber, root) pairs to stamp as anchors
    function hydrateAuthRootAnchorsFromRoots(TreeRootPair[] calldata snapshotRoots) external;

    /// @notice Create an approval-only account owned by msg.sender
    /// @param salt User-provided salt used to derive accountId from msg.sender
    /// @return accountId The computed account ID
    function createAccount(uint256 salt) external returns (uint256 accountId);

    /// @notice Approve exactly one spend by inserting a size-1 batch approval leaf
    /// @dev Wrapper around the batch path: folds the commitment with the
    ///      zero-subtree constants into a size-1 batchRoot and delegates.
    /// @param accountId The account ID owned by msg.sender
    /// @param commitment The opaque Poseidon commitment to the approval digest and blinding
    /// @param expiry The approval expiry timestamp
    function approveSpend(uint256 accountId, uint256 commitment, uint64 expiry) external;

    /// @notice Approve up to MAX_SPEND_APPROVAL_BATCH spends with one tree insertion
    /// @dev Computes the batch Merkle root on-chain over the zero-padded
    ///      commitments and inserts a single approval leaf committing to it.
    ///      Commitments must be strictly increasing (the canonical batch
    ///      encoding); sortedness makes duplicates structurally impossible.
    /// @param accountId The account ID owned by msg.sender
    /// @param expiry The approval expiry timestamp shared by the whole batch
    /// @param commitments The approved commitments, strictly ascending (1..MAX_SPEND_APPROVAL_BATCH)
    function approveSpendBatch(uint256 accountId, uint64 expiry, uint256[] calldata commitments) external;

    /// @notice Revoke an entire approval batch by zeroing its leaf
    /// @dev Sole revocation entrypoint; revocation is all-or-nothing per
    ///      batch. Callers know the root from the SpendApproved event, and a
    ///      size-1 root is a zero-constant fold of its commitment.
    /// @param accountId The account ID owned by msg.sender
    /// @param batchRoot The batch Merkle root that identifies the batch
    function revokeSpendApprovalBatch(uint256 accountId, uint256 batchRoot) external;

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
    /// @param salt User-provided salt used to derive and bind accountId to expectedOwner
    /// @param authPkX The X coordinate of the approval public key
    /// @param authPkY The Y coordinate of the approval public key
    /// @param expiry The signature expiry timestamp (0 for no expiry)
    /// @param expectedOwner The expected owner address (must validate the signature)
    /// @param sig The EIP-712 typed signature as a 65-byte ECDSA tuple
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
    /// @param owner The owner address the account is bound to
    /// @param salt User-provided salt
    /// @return The deterministic account ID
    function computeAccountId(address owner, uint256 salt) external view returns (uint256);

    /// @notice Rotate the approval key for a specific auth key
    /// @dev Uses EIP-712 typed signature for authorization. The auth key must exist and not be revoked.
    ///      Only an allowed relay or the account owner can call this function.
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
    /// @param accountId The account ID
    /// @param oldAuthPkX The X coordinate of the auth key to rotate (identifies the auth key)
    /// @param newAuthPkX The new X coordinate of the approval public key
    /// @param newAuthPkY The new Y coordinate of the approval public key
    /// @param newExpiry The new signature expiry timestamp (0 for no expiry)
    /// @param sig The EIP-712 typed signature from the owner as a 65-byte ECDSA tuple
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
    ///      Only an allowed relay or the account owner can call this function.
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
    /// @param accountId The account ID
    /// @param authPkX The X coordinate of the auth key to revoke
    /// @param expiry The signature expiry timestamp (0 for no expiry)
    /// @param sig The EIP-712 typed signature from the owner as a 65-byte ECDSA tuple
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
        view
        returns (uint256);

    /// @notice Compute an account-owner spend approval commitment
    /// @dev commitment = Poseidon2T4(DOMAIN_APPROVE_COMMIT, digestHi, digestLo, blinding)
    /// @param digestHi High half of the approved spend digest
    /// @param digestLo Low half of the approved spend digest
    /// @param blinding Blinding factor that hides the digest in the commitment
    /// @return The spend approval commitment
    function computeSpendApprovalCommitment(uint256 digestHi, uint256 digestLo, uint256 blinding)
        external
        view
        returns (uint256);

    /// @notice Compute an account-owner spend approval auth leaf
    /// @dev leaf = Poseidon2T4(DOMAIN_APPROVAL_LEAF, accountId, batchRoot, expiry)
    /// @param accountId The account ID the approval belongs to
    /// @param batchRoot The batch Merkle root the leaf commits to
    /// @param expiry The approval expiry timestamp
    /// @return The approval auth leaf
    function computeApprovalLeaf(uint256 accountId, uint256 batchRoot, uint64 expiry) external view returns (uint256);

    /// @notice Compute the batch Merkle root over zero-padded commitments
    /// @dev Depth-SPEND_APPROVAL_BATCH_DEPTH binary tree, internal nodes
    ///      Poseidon2T4.hash2(left, right), padding slots hold zero.
    /// @param commitments The approval commitments to fold, zero-padded to the batch depth
    /// @return The batch Merkle root
    function computeSpendApprovalBatchRoot(uint256[] memory commitments) external view returns (uint256);

    /// @notice Compute the per-spend approval identifier
    /// @dev Off-chain identifier only (indexer, app); the registry keeps no
    ///      per-commitment storage.
    /// @param accountId The account ID the approval belongs to
    /// @param commitment The approval commitment
    /// @return The per-spend approval identifier
    function computeApprovalId(uint256 accountId, uint256 commitment) external pure returns (bytes32);

    /// @notice Compute the batch identifier
    /// @param accountId The account ID the batch belongs to
    /// @param batchRoot The batch Merkle root
    /// @return The batch identifier
    function computeSpendApprovalBatchId(uint256 accountId, uint256 batchRoot) external pure returns (bytes32);

    /// @notice Get roots of all existing auth trees
    /// @return roots Dynamic array of roots for each tree (length = currentAuthTreeNumber + 1)
    function getAllAuthTreeRoots() external view returns (uint256[] memory roots);

    /// @notice Get the current active tree's root
    /// @dev Backwards compatibility function
    /// @return The current active tree's root
    function registryRoot() external view returns (uint256);

    // ============ View Functions (State Variables) ============

    /// @notice The depth of the auth Merkle tree
    /// @return The depth of the auth Merkle tree
    function authTreeDepth() external view returns (uint8);

    /// @notice Stateless Poseidon helper used by the current implementation
    /// @dev The address is immutable per implementation and is exposed so deployment tooling can
    ///      verify and record the constructor-created dependency.
    /// @return The address of the stateless Poseidon helper
    function authPoseidon() external view returns (address);

    /// @notice Maximum tree number allowed (2^15 - 1, constrained by circuit packing)
    /// @return The maximum permitted tree number
    function MAX_AUTH_TREE_NUMBER() external view returns (uint16);

    /// @notice Maximum lifetime for account-owner spend approvals
    /// @return The maximum permitted approval lifetime in seconds
    function MAX_APPROVAL_LIFETIME() external view returns (uint64);

    /// @notice Current active tree number (0-indexed)
    /// @return The current active tree number
    function currentAuthTreeNumber() external view returns (uint256);

    /// @notice Get the root of a specific tree
    /// @param treeNum The tree number
    /// @return The tree root
    function authTreeRoot(uint256 treeNum) external view returns (uint256);

    /// @notice Get the leaf count of a specific tree
    /// @param treeNum The tree number
    /// @return The number of leaves in the tree
    function authTreeCount(uint256 treeNum) external view returns (uint32);

    /// @notice True iff the exact auth-key leaf currently occupies the supplied registry slot.
    /// @dev The location is a lookup hint, not authority: callers must separately bind `authLeaf` to their proof.
    ///      Rotation replaces the slot and revocation zeros it, so both invalidate the prior leaf immediately.
    /// @param location Packed auth-tree location (`treeNumber << 32 | leafIndex`)
    /// @param authLeaf Poseidon auth-key leaf committed by the gift circuit
    /// @return True when that exact auth leaf currently occupies the slot
    function isCurrentAuthLeafAt(uint64 location, uint256 authLeaf) external view returns (bool);

    /// @notice Get the freshness anchor for an auth tree root
    /// @param treeNum The tree number
    /// @param root The auth tree root
    /// @return supersededBlock Block when this root was superseded, or 0 if untracked/current
    function authTreeRootAnchors(uint256 treeNum, uint256 root) external view returns (uint64 supersededBlock);

    /// @notice Batch auth-root freshness data for submit preflight callers.
    /// @param roots Sparse auth roots to inspect, returned in the same order
    /// @param maxStalenessBlocks Maximum blocks since root was superseded
    /// @return blockNumber Current block number used for freshness calculations
    /// @return currentAuthTreeNumber_ Current active auth tree number
    /// @return statuses Per-root current/recent status and superseded-root freshness metadata
    function getAuthRootStatuses(TreeRootPair[] calldata roots, uint64 maxStalenessBlocks)
        external
        view
        returns (uint64 blockNumber, uint256 currentAuthTreeNumber_, AuthRootStatus[] memory statuses);

    /// @notice True iff `root` is the current root of an existing auth tree
    /// @param treeNum The auth tree number
    /// @param root The root to verify
    /// @return True if root is current
    function isCurrentAuthTreeRoot(uint256 treeNum, uint256 root) external view returns (bool);

    /// @notice True iff `root` is current, or was current recently.
    /// @dev `maxStalenessBlocks == 0` is equivalent to current-root-only. Non-current roots must both
    ///      have a root-keyed freshness anchor and be superseded within `maxStalenessBlocks`.
    /// @param treeNum The auth tree number
    /// @param root The root to verify
    /// @param maxStalenessBlocks Maximum blocks since root was superseded
    /// @return True if root is current, or recent enough
    function isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64 maxStalenessBlocks) external view returns (bool);

    /// @notice Lean batch check for hot-path auth-root validation.
    /// @dev Returns false on the first root that is not current or recent enough. Detailed status metadata is exposed
    ///      by `getAuthRootStatuses` for off-chain preflight callers.
    /// @param roots Sparse auth roots to verify
    /// @param maxStalenessBlocks Maximum blocks since a non-current root was superseded
    /// @return True if every root is current, or recent enough
    function areRecentAuthTreeRoots(TreeRootPair[] calldata roots, uint64 maxStalenessBlocks)
        external
        view
        returns (bool);

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
    /// @return The operator address
    function operator() external view returns (address);

    /// @notice True if the account was created for approval leaves only
    /// @param accountId The account ID to check
    /// @return True when the account was created for approval leaves only
    function approvalOnly(uint256 accountId) external view returns (bool);

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
    ///      For unregistered authKeyIds, returns (0, 0, false, false, 0).
    /// @param authKeyId The auth key identifier
    /// @return treeNum The tree number where the auth key is registered
    /// @return index The index within the tree
    /// @return revoked Whether the auth key has been revoked
    /// @return exists Whether the auth key is registered
    /// @return leaf The current leaf value (zero after revocation)
    function getAuthKeyInfo(bytes32 authKeyId)
        external
        view
        returns (uint16 treeNum, uint32 index, bool revoked, bool exists, uint256 leaf);

    /// @notice Get all info about an account-owner spend approval batch in a single call
    /// @param batchId The batch identifier
    /// @return treeNum The tree number where the batch leaf is registered
    /// @return index The index within the tree
    /// @return revoked Whether the batch has been revoked
    /// @return exists Whether the batch id exists
    /// @return leaf The current leaf value (zero after revocation)
    function getSpendApprovalBatchInfo(bytes32 batchId)
        external
        view
        returns (uint16 treeNum, uint32 index, bool revoked, bool exists, uint256 leaf);
}
