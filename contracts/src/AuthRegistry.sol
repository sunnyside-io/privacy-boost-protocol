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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {AuthPoseidon} from "src/hash/AuthPoseidon.sol";
import {
    DOMAIN_ACCOUNTID,
    DOMAIN_APPROVAL_LEAF,
    DOMAIN_APPROVE_COMMIT,
    DOMAIN_REG_LEAF,
    MAX_AUTH_TREE_DEPTH,
    MAX_SPEND_APPROVAL_BATCH,
    SNARK_SCALAR_FIELD
} from "src/interfaces/Constants.sol";
import "src/interfaces/Constants.sol" as ContractConstants;
import {LibAuthZeroHashes} from "src/lib/LibAuthZeroHashes.sol";
import {
    EcdsaSig,
    AuthKeyInfo,
    AccountInfo,
    AuthTreeState,
    RootAnchor,
    TreeRootPair,
    AuthRootStatus,
    SpendApprovalInfo
} from "src/interfaces/IStructs.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {LibBabyJubJub} from "src/lib/LibBabyJubJub.sol";

/// @title AuthRegistry
/// @notice Poseidon Merkle registry for approval keys with multi-tree support
/// @custom:security-contact contact@sunnyside.io
contract AuthRegistry is IAuthRegistry, Ownable2StepUpgradeable {
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("PB:AuthRegistry:vNext");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(uint256 accountId,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)");
    bytes32 private constant ROTATE_TYPEHASH = keccak256(
        "Rotate(uint256 accountId,uint256 oldAuthPkX,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)"
    );
    bytes32 private constant REVOKE_TYPEHASH =
        keccak256("Revoke(uint256 accountId,uint256 authPkX,uint64 expiry,uint256 nonce)");
    bytes32 private constant ERC1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /// @dev Solady implicit-mode ERC-7739 contents description
    ///      supported by _verifyOwnerSig's fallback appendix parser.
    ///      ERC-7739 encodes the contentsDescription bytes followed by their
    ///      uint16 length; this contract intentionally only supports the
    ///      implicit `Contents(bytes32 stuff)` description shape.
    bytes32 private constant CONTENTS_DESCRIPTION_HASH = keccak256("Contents(bytes32 stuff)");
    uint256 private constant CONTENTS_DESCRIPTION_LENGTH = 23;
    /// @dev 32-byte app domain separator, 32-byte contents hash, and 2-byte description-length field.
    uint256 private constant ERC7739_SUFFIX_LENGTH = 66;

    /// @dev Byte length of an EIP-7702 delegation indicator: the 3-byte
    ///      `0xef0100` prefix plus a 20-byte implementation address. Checking
    ///      this first short-circuits the delegated-owner branch on an
    ///      EXTCODESIZE against an already-warm address, so an ordinary
    ///      contract wallet reaching the ERC-7739 fallback never pays the
    ///      EXTCODECOPY of its whole runtime code that `fetchDelegate`
    ///      performs. No deployed contract can carry code of this exact shape
    ///      because EIP-3541 rejects runtime code beginning with `0xef`.
    uint256 private constant DELEGATION_INDICATOR_LENGTH = 23;

    /// @notice Maximum number of auth trees supported (tree numbers are 0..MAX_AUTH_TREE_NUMBER-1)
    uint16 public constant MAX_AUTH_TREE_NUMBER = ContractConstants.MAX_AUTH_TREE_NUMBER;

    /// @notice Maximum lifetime for account-owner spend approvals
    uint64 public constant MAX_APPROVAL_LIFETIME = 30 days;

    /// @notice The depth of the auth Merkle tree
    uint8 public immutable authTreeDepth;

    /// @dev Stateless hash helper deployed with this implementation. The address lives in
    ///      implementation bytecode, so proxy storage and upgrades remain unaffected.
    AuthPoseidon private immutable _AUTH_POSEIDON;

    /// @dev Per-tree Merkle state.
    uint256 public currentAuthTreeNumber;
    mapping(uint256 treeNum => AuthTreeState) internal _authTreeState;

    /// @dev Deprecated root history, kept only for proxy storage compatibility.
    mapping(uint256 treeNum => mapping(uint256 idx => uint256 root)) private authTreeRootHistory;

    /// @dev Account ownership and replay protection (packed: owner + nonce)
    mapping(uint256 accountId => AccountInfo) internal _accountInfo;
    mapping(uint256 treeNum => mapping(uint256 level => mapping(uint256 idx => uint256 value))) internal nodes;

    /// @notice True for allowed relay addresses
    mapping(address relay => bool allowed) public allowedRelays;

    /// @notice Operator address for operational functions
    address public operator;

    /// @dev Multi-device support: authKeyId = keccak256(accountId, authPkX)
    mapping(bytes32 authKeyId => AuthKeyInfo) internal _authKeyInfo;
    mapping(uint256 accountId => bytes32[] authKeyIds) internal _authKeyList;

    /// @notice Per-tree root freshness anchors keyed by root value.
    mapping(uint256 treeNum => mapping(uint256 root => RootAnchor anchor)) public authTreeRootAnchors;

    /// @dev Fresh deployments close the legacy snapshot hydration reinitializer immediately.
    ///      Existing v1 proxies default this to false and may run hydrateAuthRootAnchorsFromRoots once.
    bool private authRootAnchorMigrationClosed;

    /// @dev Approval-only account flag and account-owner spend approval metadata.
    ///      Leaf info is keyed by batchId only (a single approval is a batch
    ///      of size 1). There is no per-commitment storage: spend single-use
    ///      is enforced by nullifiers, intra-batch uniqueness by the canonical
    ///      sorted encoding, and cross-batch commitment reuse is an off-chain
    ///      hygiene concern tracked by the indexer.
    mapping(uint256 accountId => bool enabled) public approvalOnly;
    mapping(bytes32 batchId => SpendApprovalInfo) internal _spendApprovalBatchInfo;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(uint8 authTreeDepth_) {
        if (authTreeDepth_ == 0 || authTreeDepth_ > MAX_AUTH_TREE_DEPTH) {
            revert AuthTreeDepthOutOfRange(authTreeDepth_, 1, MAX_AUTH_TREE_DEPTH);
        }
        authTreeDepth = authTreeDepth_;
        _AUTH_POSEIDON = new AuthPoseidon();
        _disableInitializers();
    }

    /// @inheritdoc IAuthRegistry
    function authPoseidon() external view returns (address) {
        return address(_AUTH_POSEIDON);
    }

    /// @inheritdoc IAuthRegistry
    function initialize(address initialOwner) external initializer {
        __Ownable2Step_init();
        _transferOwnership(initialOwner);
        uint256 zeroRoot = _zeroRoot();
        currentAuthTreeNumber = 0;
        _authTreeState[0].root = zeroRoot;
        authTreeRootHistory[0][0] = zeroRoot;
        authRootAnchorMigrationClosed = true;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    /// @dev Verify caller is either an allowed relay or the account owner.
    function _checkRelayOrOwner(address accountOwner) internal view {
        if (!allowedRelays[msg.sender] && msg.sender != accountOwner) revert NotAuthorized();
    }

    function _authorizeExistingAuthMutation(AccountInfo storage account) internal view returns (address accountOwner) {
        accountOwner = account.owner;
        if (allowedRelays[msg.sender]) {
            if (accountOwner == address(0)) revert NotRegistered();
            return accountOwner;
        }
        if (accountOwner == address(0) || msg.sender != accountOwner) revert NotAuthorized();
    }

    function _checkOwnerOrProxyAdmin() internal view {
        if (msg.sender == owner()) return;
        address proxyAdmin_;
        bytes32 adminSlot = ERC1967_ADMIN_SLOT;
        assembly ("memory-safe") {
            proxyAdmin_ := sload(adminSlot)
        }
        if (msg.sender != proxyAdmin_) revert NotAuthorized();
    }

    function _seedAuthRootAnchor(uint256 treeNum, uint256 root, uint64 migrationBlock) internal {
        if (root == _authTreeState[treeNum].root) return;

        RootAnchor storage anchor = authTreeRootAnchors[treeNum][root];
        if (anchor.supersededBlock != 0) return;
        anchor.supersededBlock = migrationBlock;
    }

    function _checkLegacyAnchorMigrationAvailable() internal view {
        if (authRootAnchorMigrationClosed) revert AuthRootAnchorsAlreadyInitialized();
    }

    /// @inheritdoc IAuthRegistry
    function setOperator(address operator_) external onlyOwner {
        if (operator_ == address(0)) revert InvalidOperatorAddress();
        address oldOperator = operator;
        operator = operator_;
        emit OperatorUpdated(oldOperator, operator_);
    }

    /// @inheritdoc IAuthRegistry
    function setAllowedRelays(address[] calldata relays, bool allowed) external onlyOperator {
        for (uint256 i = 0; i < relays.length; ++i) {
            if (relays[i] == address(0)) revert InvalidRelayAddress();
            allowedRelays[relays[i]] = allowed;
            emit RelayUpdated(relays[i], allowed);
        }
    }

    /// @inheritdoc IAuthRegistry
    function hydrateAuthRootAnchorsFromRoots(TreeRootPair[] calldata snapshotRoots) external reinitializer(2) {
        _checkOwnerOrProxyAdmin();
        _checkLegacyAnchorMigrationAvailable();
        uint64 migrationBlock = uint64(block.number);
        for (uint256 i = 0; i < snapshotRoots.length; ++i) {
            uint256 treeNum = snapshotRoots[i].treeNumber;
            uint256 root = snapshotRoots[i].root;
            if (treeNum > currentAuthTreeNumber) revert InvalidAuthTreeNumber();
            if (root == 0) revert InvalidSnapshotRoot();
            _seedAuthRootAnchor(treeNum, root, migrationBlock);
        }
    }

    /// @inheritdoc IAuthRegistry
    function createAccount(uint256 salt) external returns (uint256 accountId) {
        accountId = computeAccountId(msg.sender, salt);
        if (accountId == 0) revert InvalidAccountId();

        AccountInfo storage account = _accountInfo[accountId];
        if (account.owner != address(0)) revert AccountAlreadyExists();

        account.owner = msg.sender;
        approvalOnly[accountId] = true;

        emit AccountCreated(accountId, msg.sender);
    }

    /// @inheritdoc IAuthRegistry
    function approveSpend(uint256 accountId, uint256 commitment, uint64 expiry) external {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        _approveSpendBatch(accountId, expiry, commitments);
    }

    /// @inheritdoc IAuthRegistry
    function approveSpendBatch(uint256 accountId, uint64 expiry, uint256[] calldata commitments) external {
        _approveSpendBatch(accountId, expiry, commitments);
    }

    function _approveSpendBatch(uint256 accountId, uint64 expiry, uint256[] memory commitments) internal {
        if (msg.sender != _accountInfo[accountId].owner) revert NotAuthorized();
        uint256 batchSize = commitments.length;
        if (batchSize == 0 || batchSize > MAX_SPEND_APPROVAL_BATCH) revert InvalidApprovalBatchSize();

        // Canonical-order validation: strict ascending order plus the two
        // endpoint checks imply every element is nonzero, in range, and
        // unique in one O(N) pass.
        if (commitments[0] == 0) revert InvalidApprovalCommitment();
        for (uint256 i = 1; i < batchSize; ++i) {
            if (commitments[i] <= commitments[i - 1]) revert UnsortedApprovalCommitments();
        }
        if (commitments[batchSize - 1] >= SNARK_SCALAR_FIELD) revert InvalidApprovalCommitment();

        if (block.timestamp >= expiry || expiry > block.timestamp + MAX_APPROVAL_LIFETIME) {
            revert InvalidApprovalExpiry();
        }

        uint256 batchRoot = computeSpendApprovalBatchRoot(commitments);
        bytes32 batchId = computeSpendApprovalBatchId(accountId, batchRoot);
        // Load-bearing for revocation integrity: a byte-identical second
        // insertion would overwrite batchId -> (treeNumber, treeIndex) with
        // the new position, and a later revoke would zero only the recorded
        // leaf while the first stayed live until expiry. Since batchId omits
        // expiry, this also forces fresh blindings on any re-approval.
        if (_spendApprovalBatchInfo[batchId].exists) revert SpendApprovalAlreadyExists();

        (uint256 treeNum, uint32 idx) = _allocateLeafSlot();
        _spendApprovalBatchInfo[batchId] = SpendApprovalInfo({
            // _allocateLeafSlot caps treeNum at MAX_AUTH_TREE_NUMBER (32767).
            // forge-lint: disable-next-line(unsafe-typecast)
            treeNumber: uint16(treeNum),
            treeIndex: idx,
            revoked: false,
            exists: true
        });

        uint256 leaf = computeApprovalLeaf(accountId, batchRoot, expiry);
        if (leaf == 0) revert InvalidLeaf();
        _updateLeaf(treeNum, idx, leaf, true);

        emit SpendApproved(accountId, batchId, batchRoot, expiry, treeNum, idx, commitments);
    }

    /// @inheritdoc IAuthRegistry
    function revokeSpendApprovalBatch(uint256 accountId, uint256 batchRoot) external {
        if (msg.sender != _accountInfo[accountId].owner) revert NotAuthorized();
        bytes32 batchId = computeSpendApprovalBatchId(accountId, batchRoot);

        SpendApprovalInfo storage info = _spendApprovalBatchInfo[batchId];
        if (!info.exists) revert SpendApprovalNotFound();
        if (info.revoked) revert SpendApprovalAlreadyRevoked();

        info.revoked = true;
        _updateLeaf(info.treeNumber, info.treeIndex, 0, false);

        emit SpendApprovalRevoked(accountId, batchId, info.treeNumber, info.treeIndex);
    }

    /// @inheritdoc IAuthRegistry
    function register(
        uint256 salt,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        bytes calldata sig
    ) external {
        _checkRelayOrOwner(expectedOwner);
        uint256 accountId = computeAccountId(expectedOwner, salt);
        _registerAccount(accountId, authPkX, authPkY, expiry, expectedOwner, sig);
    }

    /// @inheritdoc IAuthRegistry
    function register(
        uint256 salt,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        EcdsaSig calldata sig
    ) external {
        _checkRelayOrOwner(expectedOwner);
        uint256 accountId = computeAccountId(expectedOwner, salt);
        _registerAccount(accountId, authPkX, authPkY, expiry, expectedOwner, _packLegacySig(sig));
    }

    /// @inheritdoc IAuthRegistry
    function computeAccountId(address owner, uint256 salt) public view returns (uint256) {
        return _AUTH_POSEIDON.hash(3, DOMAIN_ACCOUNTID, uint256(uint160(owner)), salt, 0, 0);
    }

    function _registerAccount(
        uint256 accountId,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        address expectedOwner,
        bytes memory sig
    ) internal {
        if (accountId == 0) revert InvalidAccountId();
        if (expiry != 0 && block.timestamp > expiry) revert SignatureExpired();

        bytes32 authKeyId = keccak256(abi.encode(accountId, authPkX));
        if (_authKeyInfo[authKeyId].listIndex != 0) revert AlreadyRegistered();

        AccountInfo storage account = _accountInfo[accountId];
        if (account.owner != address(0) && approvalOnly[accountId]) revert ApprovalOnlyAccount();
        if (!LibBabyJubJub.isValidPublicKey(authPkX, authPkY)) revert InvalidAuthPublicKey();

        uint96 nonce = account.nonce;
        bytes32 structHash = _registerStructHash(accountId, authPkX, authPkY, expiry, nonce);
        _verifyOwnerSig(expectedOwner, structHash, sig);

        address existingOwner = account.owner;
        if (existingOwner != address(0)) {
            if (existingOwner != expectedOwner) revert OwnerMismatch();
        } else {
            account.owner = expectedOwner;
        }

        account.nonce = nonce + 1;
        (uint256 treeNum, uint32 idx) = _allocateLeafSlot();
        _authKeyInfo[authKeyId] = AuthKeyInfo({
            // _allocateLeafSlot caps treeNum at MAX_AUTH_TREE_NUMBER (32767).
            // forge-lint: disable-next-line(unsafe-typecast)
            treeNumber: uint16(treeNum),
            treeIndex: idx,
            listIndex: uint32(_authKeyList[accountId].length) + 1, // 1-indexed
            revoked: false
        });
        _authKeyList[accountId].push(authKeyId);

        uint256 leaf = computeLeaf(accountId, authPkX, authPkY, expiry);
        if (leaf == 0) revert InvalidLeaf();
        _updateLeaf(treeNum, idx, leaf, true);

        if (existingOwner == address(0)) {
            emit Registered(accountId, expectedOwner, treeNum, authPkX, authPkY, expiry);
        }
        emit AuthKeyAdded(accountId, authKeyId, treeNum, authPkX, authPkY, expiry);
    }

    /// @inheritdoc IAuthRegistry
    function rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        bytes calldata sig
    ) external {
        _rotate(accountId, oldAuthPkX, newAuthPkX, newAuthPkY, newExpiry, sig);
    }

    /// @inheritdoc IAuthRegistry
    function rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        EcdsaSig calldata sig
    ) external {
        _rotate(accountId, oldAuthPkX, newAuthPkX, newAuthPkY, newExpiry, _packLegacySig(sig));
    }

    function _rotate(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 newAuthPkX,
        uint256 newAuthPkY,
        uint64 newExpiry,
        bytes memory sig
    ) internal {
        AccountInfo storage account = _accountInfo[accountId];
        address accountOwner = _authorizeExistingAuthMutation(account);
        if (approvalOnly[accountId]) revert ApprovalOnlyAccount();
        if (newExpiry != 0 && block.timestamp > newExpiry) revert SignatureExpired();

        bytes32 oldAuthKeyId = keccak256(abi.encode(accountId, oldAuthPkX));
        bytes32 newAuthKeyId = keccak256(abi.encode(accountId, newAuthPkX));

        AuthKeyInfo memory oldInfo = _authKeyInfo[oldAuthKeyId];
        if (oldInfo.listIndex == 0) revert AuthKeyNotFound();
        if (oldInfo.revoked) revert AuthKeyAlreadyRevoked();

        uint96 nonce = account.nonce;
        bytes32 structHash = _rotateStructHash(accountId, oldAuthPkX, newAuthPkX, newAuthPkY, newExpiry, nonce);
        _verifyOwnerSig(accountOwner, structHash, sig);
        if (!LibBabyJubJub.isValidPublicKey(newAuthPkX, newAuthPkY)) revert InvalidAuthPublicKey();

        account.nonce = nonce + 1;

        uint16 treeNum = oldInfo.treeNumber;
        uint32 idx = oldInfo.treeIndex;

        if (oldAuthPkX != newAuthPkX) {
            if (_authKeyInfo[newAuthKeyId].listIndex != 0) revert AlreadyRegistered();

            delete _authKeyInfo[oldAuthKeyId];
            _authKeyInfo[newAuthKeyId] =
                AuthKeyInfo({treeNumber: treeNum, treeIndex: idx, listIndex: oldInfo.listIndex, revoked: false});
            _authKeyList[accountId][oldInfo.listIndex - 1] = newAuthKeyId;
        }

        uint256 leaf = computeLeaf(accountId, newAuthPkX, newAuthPkY, newExpiry);
        if (leaf == 0) revert InvalidLeaf();
        _updateLeaf(treeNum, idx, leaf, false);

        emit AuthKeyRotated(accountId, newAuthKeyId, treeNum, newAuthPkX, newAuthPkY, idx, newExpiry);
    }

    /// @inheritdoc IAuthRegistry
    function revoke(uint256 accountId, uint256 authPkX, uint64 expiry, bytes calldata sig) external {
        _revoke(accountId, authPkX, expiry, sig);
    }

    /// @inheritdoc IAuthRegistry
    function revoke(uint256 accountId, uint256 authPkX, uint64 expiry, EcdsaSig calldata sig) external {
        _revoke(accountId, authPkX, expiry, _packLegacySig(sig));
    }

    function _revoke(uint256 accountId, uint256 authPkX, uint64 expiry, bytes memory sig) internal {
        AccountInfo storage account = _accountInfo[accountId];
        address accountOwner = _authorizeExistingAuthMutation(account);
        if (expiry != 0 && block.timestamp > expiry) revert SignatureExpired();

        bytes32 authKeyId = keccak256(abi.encode(accountId, authPkX));
        AuthKeyInfo storage info = _authKeyInfo[authKeyId];
        if (info.listIndex == 0) revert AuthKeyNotFound();
        if (info.revoked) revert AuthKeyAlreadyRevoked();

        uint96 nonce = account.nonce;
        bytes32 structHash = _revokeStructHash(accountId, authPkX, expiry, nonce);
        _verifyOwnerSig(accountOwner, structHash, sig);

        account.nonce = nonce + 1;
        info.revoked = true;

        _updateLeaf(info.treeNumber, info.treeIndex, 0, false);

        emit AuthKeyRevoked(accountId, authKeyId, info.treeNumber, info.treeIndex);
    }

    function _packLegacySig(EcdsaSig calldata sig) internal pure returns (bytes memory) {
        return abi.encodePacked(sig.r, sig.s, sig.v);
    }

    /// @dev Verifies `sig` against `expectedOwner` for the action whose
    ///      EIP-712 struct hash is `structHash`. Routes EOAs and EIP-1271
    ///      smart-contract wallets through OZ's SignatureChecker on the raw
    ///      dapp digest first. If an EIP-7702 delegated EOA's implementation
    ///      rejects ERC-1271, the EOA key remains root authority through a
    ///      direct ECDSA check. Only then does verification attempt an
    ///      ERC-7739 ("defensive rehashing") rewrap for wallets that decline
    ///      raw and require a Solady-style ERC-7739 generic-wrap digest.
    ///
    ///      Raw-first matters for compatibility:
    ///        - EOAs (recover on raw EIP-712 digest).
    ///        - Standard ERC-1271 wallets that accept the raw dapp digest.
    ///        - 7739-aware wallets that also accept the raw digest fall here.
    ///      A wallet that strictly requires the wrapped digest fails the raw
    ///      check and is served by the fallback.
    ///
    ///      The delegated-owner check requires a real EIP-7702 delegation
    ///      indicator, screened by its exact byte length before the delegate
    ///      is read, so a deployed contract wallet never enters it. It uses
    ///      non-reverting `tryRecover`, so longer ERC-7739 signatures continue
    ///      to the appendix parser instead of reverting.
    ///
    ///      The fallback path is gated on independent checks. Failing any one
    ///      reverts with a granular ERC-7739 diagnostic — mismatch is
    ///      rejection, not soft-pass:
    ///
    ///        1. `expectedOwner.code.length > 0` — codeless EOAs cannot verify
    ///           an appendix sig through ecrecover, so there is no fallback
    ///           path for them and we revert immediately.
    ///        2. `appSep == _domainSeparator()` — cross-app sig replay
    ///           defense.
    ///        3. The appendix contentsDescription is exactly the 23-byte
    ///           Solady implicit-mode
    ///           `Contents(bytes32 stuff)` description; explicit-mode and
    ///           other description shapes are outside the path this validator
    ///           supports.
    ///        4. `contentsHash` binds to THIS action as one of the two
    ///           deployed wallet shapes we intentionally support:
    ///             - `rawDigest`: the appendix contentsHash is the dapp's
    ///               full EIP-712 digest.
    ///             - `keccak256(CONTENTS_DESCRIPTION_HASH, structHash)`: the
    ///               appendix contentsHash is the Solady-style
    ///               `Contents(bytes32 stuff)` hashStruct.
    ///           In the rawDigest shape, the AuthRegistry domain is part of
    ///           contentsHash. In the hashStruct shape, the domain is bound by
    ///           the separate appSep check and the final wrapped digest. Both
    ///           accepted paths bind the signature to this AuthRegistry domain
    ///           and the action struct fields, including nonce. Without this
    ///           binding, any 7739 sig the user ever produced against our
    ///           domain would replay across register / rotate / revoke and
    ///           across any (accountId, authPk*, expiry, nonce) tuple.
    function _verifyOwnerSig(address expectedOwner, bytes32 structHash, bytes memory sig) internal view {
        bytes32 domainSep = _domainSeparator();
        bytes32 rawDigest = MessageHashUtils.toTypedDataHash(domainSep, structHash);

        if (SignatureChecker.isValidSignatureNow(expectedOwner, rawDigest, sig)) {
            return;
        }
        if (
            expectedOwner.code.length == DELEGATION_INDICATOR_LENGTH
                && EIP7702Utils.fetchDelegate(expectedOwner) != address(0)
        ) {
            (address recovered, ECDSA.RecoverError recoverError,) = ECDSA.tryRecover(rawDigest, sig);
            if (recoverError == ECDSA.RecoverError.NoError && recovered == expectedOwner) {
                return;
            }
        }
        if (expectedOwner.code.length == 0) revert InvalidSignature();

        uint256 sigLen = sig.length;
        if (sigLen < 2) revert InvalidSignatureLength();
        uint256 n;
        unchecked {
            n = (uint256(uint8(sig[sigLen - 2])) << 8) | uint256(uint8(sig[sigLen - 1]));
        }
        if (n != CONTENTS_DESCRIPTION_LENGTH || sigLen <= ERC7739_SUFFIX_LENGTH + n) {
            revert InvalidSignatureLength();
        }

        uint256 appStart = sigLen - ERC7739_SUFFIX_LENGTH - n;
        bytes32 appSep;
        bytes32 contentsHash;
        bytes32 contentsDescriptionHash;
        assembly ("memory-safe") {
            appSep := mload(add(add(sig, 0x20), appStart))
            contentsHash := mload(add(add(sig, 0x20), add(appStart, 0x20)))
            contentsDescriptionHash := keccak256(add(add(sig, 0x20), add(appStart, 0x40)), n)
        }
        if (appSep != domainSep) revert InvalidERC7739AppDomain();
        if (contentsDescriptionHash != CONTENTS_DESCRIPTION_HASH) revert InvalidERC7739ContentsDescription();
        bytes32 placeholderContentsHash = keccak256(abi.encode(CONTENTS_DESCRIPTION_HASH, structHash));
        if (contentsHash != rawDigest && contentsHash != placeholderContentsHash) revert InvalidERC7739ContentsHash();

        bytes32 wrappedDigest = keccak256(abi.encodePacked(hex"1901", appSep, contentsHash));
        if (!SignatureChecker.isValidSignatureNow(expectedOwner, wrappedDigest, sig)) {
            revert InvalidERC7739WrappedSignature();
        }
    }

    /// @inheritdoc IAuthRegistry
    function computeLeaf(uint256 accountId, uint256 authPkX, uint256 authPkY, uint64 expiry)
        public
        view
        returns (uint256)
    {
        return _AUTH_POSEIDON.hash(5, DOMAIN_REG_LEAF, accountId, authPkX, authPkY, uint256(expiry));
    }

    /// @inheritdoc IAuthRegistry
    function computeSpendApprovalCommitment(uint256 digestHi, uint256 digestLo, uint256 blinding)
        public
        view
        returns (uint256)
    {
        return _AUTH_POSEIDON.hash(4, DOMAIN_APPROVE_COMMIT, digestHi, digestLo, blinding, 0);
    }

    /// @inheritdoc IAuthRegistry
    function computeApprovalLeaf(uint256 accountId, uint256 batchRoot, uint64 expiry) public view returns (uint256) {
        return _AUTH_POSEIDON.hash(4, DOMAIN_APPROVAL_LEAF, accountId, batchRoot, uint256(expiry), 0);
    }

    /// @inheritdoc IAuthRegistry
    function computeSpendApprovalBatchRoot(uint256[] memory commitments) public view returns (uint256) {
        uint256 width = commitments.length;
        if (width == 0 || width > MAX_SPEND_APPROVAL_BATCH) revert InvalidApprovalBatchSize();
        return _AUTH_POSEIDON.hashSpendApprovalBatch(commitments);
    }

    /// @inheritdoc IAuthRegistry
    function computeApprovalId(uint256 accountId, uint256 commitment) public pure returns (bytes32) {
        return keccak256(abi.encode(accountId, commitment));
    }

    /// @inheritdoc IAuthRegistry
    function computeSpendApprovalBatchId(uint256 accountId, uint256 batchRoot) public pure returns (bytes32) {
        return keccak256(abi.encode(accountId, batchRoot));
    }

    function _allocateLeafSlot() internal returns (uint256 treeNum, uint32 idx) {
        treeNum = currentAuthTreeNumber;
        AuthTreeState storage treeState = _authTreeState[treeNum];
        idx = treeState.leafCount;

        if (idx >= (uint32(1) << authTreeDepth)) {
            treeNum = currentAuthTreeNumber + 1;
            if (treeNum > MAX_AUTH_TREE_NUMBER) revert RegistryFull();
            currentAuthTreeNumber = treeNum;
            treeState = _authTreeState[treeNum];
            treeState.root = _zeroRoot();
            idx = 0;
        }

        treeState.leafCount = idx + 1;
    }

    function _updateLeaf(uint256 treeNum, uint256 index, uint256 leaf, bool appendOnly) internal {
        uint256[MAX_AUTH_TREE_DEPTH + 1] memory zeros = LibAuthZeroHashes.get();
        nodes[treeNum][0][index] = leaf;
        uint256[MAX_AUTH_TREE_DEPTH] memory siblings;
        uint256 idx = index;
        for (uint256 level = 0; level < authTreeDepth; ++level) {
            uint256 sibling;
            if (appendOnly && (idx & 1) == 0) {
                sibling = zeros[level];
            } else {
                sibling = nodes[treeNum][level][idx ^ 1];
                if (sibling == 0) {
                    sibling = zeros[level];
                }
            }
            siblings[level] = sibling;
            idx >>= 1;
        }
        uint256[MAX_AUTH_TREE_DEPTH] memory parents = _AUTH_POSEIDON.hashAuthPath(leaf, index, authTreeDepth, siblings);
        idx = index;
        for (uint256 level = 0; level < authTreeDepth; ++level) {
            idx >>= 1;
            nodes[treeNum][level + 1][idx] = parents[level];
        }
        uint256 current = parents[authTreeDepth - 1];
        AuthTreeState storage treeState = _authTreeState[treeNum];
        // Rotating to the same auth key and expiry rewrites the same leaf. In
        // that no-op case the tree root, anchors, and RootUpdated event all
        // remain unchanged.
        if (current == treeState.root) {
            return;
        }
        uint256 previousRoot = treeState.root;
        authTreeRootAnchors[treeNum][previousRoot].supersededBlock = uint64(block.number);
        treeState.root = current;
        emit RootUpdated(treeNum, current);
    }

    function _zeroRoot() internal view returns (uint256) {
        return LibAuthZeroHashes.get()[authTreeDepth];
    }

    /// @inheritdoc IAuthRegistry
    function getAllAuthTreeRoots() external view returns (uint256[] memory roots) {
        uint256 treeCount = currentAuthTreeNumber + 1;
        roots = new uint256[](treeCount);
        for (uint256 i = 0; i < treeCount; ++i) {
            roots[i] = _authTreeState[i].root;
        }
    }

    /// @inheritdoc IAuthRegistry
    function registryRoot() external view returns (uint256) {
        return _authTreeState[currentAuthTreeNumber].root;
    }

    /// @dev Compute EIP-712 domain separator for signature verification
    /// @return Domain separator hash
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function _registerStructHash(uint256 accountId, uint256 authPkX, uint256 authPkY, uint64 expiry, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(REGISTER_TYPEHASH, accountId, authPkX, authPkY, expiry, nonce));
    }

    function _rotateStructHash(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(ROTATE_TYPEHASH, accountId, oldAuthPkX, authPkX, authPkY, expiry, nonce));
    }

    function _revokeStructHash(uint256 accountId, uint256 authPkX, uint64 expiry, uint256 nonce)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(REVOKE_TYPEHASH, accountId, authPkX, expiry, nonce));
    }

    /// @inheritdoc IAuthRegistry
    function getAuthKeys(uint256 accountId) external view returns (bytes32[] memory) {
        return _authKeyList[accountId];
    }

    /// @inheritdoc IAuthRegistry
    function computeAuthKeyId(uint256 accountId, uint256 authPkX) external pure returns (bytes32) {
        return keccak256(abi.encode(accountId, authPkX));
    }

    /// @inheritdoc IAuthRegistry
    function getAuthKeyInfo(bytes32 authKeyId)
        external
        view
        returns (uint16 treeNum, uint32 index, bool revoked, bool exists, uint256 leaf)
    {
        AuthKeyInfo memory info = _authKeyInfo[authKeyId];
        treeNum = info.treeNumber;
        index = info.treeIndex;
        revoked = info.revoked;
        exists = info.listIndex != 0;
        if (exists) leaf = nodes[treeNum][0][index];
    }

    /// @inheritdoc IAuthRegistry
    function getSpendApprovalBatchInfo(bytes32 batchId)
        external
        view
        returns (uint16 treeNum, uint32 index, bool revoked, bool exists, uint256 leaf)
    {
        SpendApprovalInfo memory info = _spendApprovalBatchInfo[batchId];
        treeNum = info.treeNumber;
        index = info.treeIndex;
        revoked = info.revoked;
        exists = info.exists;
        if (exists) leaf = nodes[treeNum][0][index];
    }

    /// @inheritdoc IAuthRegistry
    function authKeyTreeOf(bytes32 authKeyId) external view returns (uint16) {
        return _authKeyInfo[authKeyId].treeNumber;
    }

    /// @inheritdoc IAuthRegistry
    function authKeyIndexOf(bytes32 authKeyId) external view returns (uint32) {
        return _authKeyInfo[authKeyId].treeIndex;
    }

    /// @inheritdoc IAuthRegistry
    function authKeyRevoked(bytes32 authKeyId) external view returns (bool) {
        return _authKeyInfo[authKeyId].revoked;
    }

    /// @inheritdoc IAuthRegistry
    function authTreeRoot(uint256 treeNum) external view returns (uint256) {
        return _authTreeState[treeNum].root;
    }

    /// @inheritdoc IAuthRegistry
    function authTreeCount(uint256 treeNum) external view returns (uint32) {
        return _authTreeState[treeNum].leafCount;
    }

    /// @inheritdoc IAuthRegistry
    function isCurrentAuthLeafAt(uint64 location, uint256 authLeaf) external view returns (bool) {
        uint256 treeNum = uint256(location >> 32);
        uint256 index = uint256(location & type(uint32).max);
        return authLeaf != 0 && nodes[treeNum][0][index] == authLeaf;
    }

    /// @inheritdoc IAuthRegistry
    function isCurrentAuthTreeRoot(uint256 treeNum, uint256 root) public view returns (bool) {
        if (root == 0) return false;
        if (treeNum > currentAuthTreeNumber) return false;
        return _authTreeState[treeNum].root == root;
    }

    /// @inheritdoc IAuthRegistry
    function isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64 maxStalenessBlocks) public view returns (bool) {
        return _isRecentAuthTreeRoot(treeNum, root, maxStalenessBlocks);
    }

    function _isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64 maxStalenessBlocks)
        internal
        view
        returns (bool)
    {
        if (root == 0) return false;
        if (treeNum > currentAuthTreeNumber) return false;
        if (_authTreeState[treeNum].root == root) return true;
        if (maxStalenessBlocks == 0) return false;

        RootAnchor storage anchor = authTreeRootAnchors[treeNum][root];
        if (anchor.supersededBlock == 0) return false;
        return block.number - anchor.supersededBlock <= maxStalenessBlocks;
    }

    /// @inheritdoc IAuthRegistry
    function areRecentAuthTreeRoots(TreeRootPair[] calldata roots, uint64 maxStalenessBlocks)
        external
        view
        returns (bool)
    {
        for (uint256 i = 0; i < roots.length; ++i) {
            if (!_isRecentAuthTreeRoot(roots[i].treeNumber, roots[i].root, maxStalenessBlocks)) {
                return false;
            }
        }
        return true;
    }

    /// @inheritdoc IAuthRegistry
    function getAuthRootStatuses(TreeRootPair[] calldata roots, uint64 maxStalenessBlocks)
        external
        view
        returns (uint64 blockNumber, uint256 currentAuthTreeNumber_, AuthRootStatus[] memory statuses)
    {
        blockNumber = uint64(block.number);
        currentAuthTreeNumber_ = currentAuthTreeNumber;
        statuses = new AuthRootStatus[](roots.length);

        for (uint256 i = 0; i < roots.length; ++i) {
            uint256 treeNum = roots[i].treeNumber;
            uint256 root = roots[i].root;
            AuthRootStatus memory status;
            status.treeNumber = treeNum;
            status.root = root;

            if (root != 0 && treeNum <= currentAuthTreeNumber_) {
                uint256 currentRoot = _authTreeState[treeNum].root;
                if (currentRoot == root) {
                    status.isCurrent = true;
                    status.isRecent = true;
                    status.remainingBlocks = type(uint64).max;
                } else if (maxStalenessBlocks != 0) {
                    RootAnchor storage anchor = authTreeRootAnchors[treeNum][root];
                    status.supersededBlock = anchor.supersededBlock;
                    if (anchor.supersededBlock != 0) {
                        uint256 age = block.number - anchor.supersededBlock;
                        if (age <= maxStalenessBlocks) {
                            status.isRecent = true;
                            // age <= maxStalenessBlocks (uint64) in this branch.
                            // forge-lint: disable-next-line(unsafe-typecast)
                            status.remainingBlocks = maxStalenessBlocks - uint64(age);
                        }
                    }
                }
            }

            statuses[i] = status;
        }
    }

    /// @inheritdoc IAuthRegistry
    function ownerOf(uint256 accountId) external view returns (address) {
        return _accountInfo[accountId].owner;
    }

    /// @inheritdoc IAuthRegistry
    function nonces(uint256 accountId) external view returns (uint256) {
        return _accountInfo[accountId].nonce;
    }

    uint256[46] private __gap;
}
