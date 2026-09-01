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

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {EIP7702Utils} from "@openzeppelin/contracts/account/utils/EIP7702Utils.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {PortalDelegate} from "src/PortalDelegate.sol";
import {DOMAIN_REG_NODE} from "src/interfaces/Constants.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {IWETH} from "src/interfaces/IWETH.sol";
import {AuthRootStatus, EcdsaSig, TreeRootPair} from "src/interfaces/IStructs.sol";
import {LibAuthZeroHashes} from "src/lib/LibAuthZeroHashes.sol";
import {MockWETH} from "src/testnet/MockWETH.sol";
import {MockERC7739Account} from "test/mocks/MockERC7739Account.sol";

interface IAuthPoseidonHash {
    function hash(uint256 len, uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        external
        pure
        returns (uint256);
}

contract ERC1271WalletMock {
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    mapping(bytes32 hash => mapping(bytes32 signatureHash => bool approved)) internal approvedSignatures;

    function approveSignature(bytes32 hash, bytes calldata signature) external {
        approvedSignatures[hash][keccak256(signature)] = true;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        return approvedSignatures[hash][keccak256(signature)] ? MAGIC_VALUE : bytes4(0xffffffff);
    }
}

/// @notice ERC-1271 implementation that rejects every signature. Installed as
///         an EIP-7702 delegate it models an account whose delegate declines
///         the raw digest, leaving the delegated EOA's own key as the only
///         remaining authority over its auth keys.
contract ERC1271RejectingWalletMock {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return bytes4(0xffffffff);
    }
}

/// @notice Unit tests for AuthRegistry multi-tree support with nonce-based signatures
contract AuthRegistryTest is Test {
    AuthRegistry registry;
    address owner = address(this);
    address proxyAdmin = address(0xAD); // Separate proxy admin to avoid TransparentProxy routing issue
    address operator = makeAddr("operator");
    address server = makeAddr("server");

    // Valid BabyJubJub curve points (gnark BN254: a=-1, d=12181644...846)
    // B8 = 8 * Generator (cofactor-cleared base point)
    uint256 constant PK1X = 15836372343211832006828833031571087401945044377577570170285606102491215895900;
    uint256 constant PK1Y = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    // -B8 (negated x)
    uint256 constant PK2X = 6051870528627443215417572713686187686603320022838464173412598084084592599717;
    uint256 constant PK2Y = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    // Conjugate of B8 (negated y) — same x as PK1, different y
    uint256 constant PK1Y_ALT = 14086713941007883609332862791408011996427599113237354702707988497628294654357;
    // 2*B8
    uint256 constant PK3X = 5261822793729097469124322713944452436263585332274847136083146132068833612219;
    uint256 constant PK3Y = 21459189231378695508316163458360356529222201254620325044724979975334648070151;
    // 3*B8
    uint256 constant PK4X = 2434057818750457421387010563733183007830828680493589737249041737000851160914;
    uint256 constant PK4Y = 6508671331239705069506722850208743045976028031090591091395110337207569614260;
    // 4*B8
    uint256 constant PK5X = 5305964347488303400773845277503515540218478095610222488366115857400103923823;
    uint256 constant PK5Y = 19641326725043875799903403987343978153690949184340502090612493837393445612301;

    uint256 constant DEFAULT_SALT = 123;
    uint256 constant DELEGATED_OWNER_PK = 0xA11CE;

    // EIP-712 domain constants (must match AuthRegistry)
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
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    function setUp() public {
        AuthRegistry impl = new AuthRegistry(20);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(AuthRegistry.initialize, (owner))
        );
        registry = AuthRegistry(address(proxy));

        // Set operator
        registry.setOperator(operator);

        // The test contract acts as the default relay for happy-path writes.
        address[] memory relays = new address[](1);
        relays[0] = address(this);
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(registry)));
    }

    function _markAsLegacyInitialized() internal {
        vm.store(address(registry), INITIALIZABLE_STORAGE, bytes32(uint256(1)));
        _openLegacyAnchorMigration();
    }

    function _openLegacyAnchorMigration() internal {
        vm.store(address(registry), bytes32(uint256(10)), bytes32(0));
    }

    function _packAuthTreeStateTail(uint64 cursor, uint32 leafCount) internal pure returns (bytes32) {
        return bytes32(uint256(cursor) | (uint256(leafCount) << 64));
    }

    function _manualSingleLeafRoot(uint256 leaf) internal view returns (uint256 current) {
        uint256[21] memory zeros = LibAuthZeroHashes.get();
        IAuthPoseidonHash poseidon = IAuthPoseidonHash(registry.authPoseidon());
        current = leaf;
        for (uint256 level = 0; level < 20; ++level) {
            current = poseidon.hash(3, DOMAIN_REG_NODE, current, zeros[level], 0, 0);
        }
    }

    function _manualTwoLeafRoot(uint256 leftLeaf, uint256 rightLeaf) internal view returns (uint256 current) {
        uint256[21] memory zeros = LibAuthZeroHashes.get();
        IAuthPoseidonHash poseidon = IAuthPoseidonHash(registry.authPoseidon());
        current = poseidon.hash(3, DOMAIN_REG_NODE, leftLeaf, rightLeaf, 0, 0);
        for (uint256 level = 1; level < 20; ++level) {
            current = poseidon.hash(3, DOMAIN_REG_NODE, current, zeros[level], 0, 0);
        }
    }

    function _manualRootForPrefix(uint256[] memory leaves, uint256 count) internal view returns (uint256 current) {
        uint256[21] memory zeros = LibAuthZeroHashes.get();
        IAuthPoseidonHash poseidon = IAuthPoseidonHash(registry.authPoseidon());
        uint256[] memory level = new uint256[](16);
        for (uint256 i = 0; i < level.length; ++i) {
            level[i] = i < count ? leaves[i] : zeros[0];
        }
        uint256 width = level.length;
        for (uint256 treeLevel = 0; treeLevel < 4; ++treeLevel) {
            width /= 2;
            for (uint256 i = 0; i < width; ++i) {
                level[i] = poseidon.hash(3, DOMAIN_REG_NODE, level[2 * i], level[2 * i + 1], 0, 0);
            }
        }
        current = level[0];
        for (uint256 treeLevel = 4; treeLevel < 20; ++treeLevel) {
            current = poseidon.hash(3, DOMAIN_REG_NODE, current, zeros[treeLevel], 0, 0);
        }
    }

    function _signRegister(
        uint256 privateKey,
        uint256 accountId,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, authPkX, authPkY, expiry, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerDigest(uint256 accountId, uint256 authPkX, uint256 authPkY, uint64 expiry, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, authPkX, authPkY, expiry, nonce));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _signRotate(
        uint256 privateKey,
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(ROTATE_TYPEHASH, accountId, oldAuthPkX, authPkX, authPkY, expiry, nonce)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _rotateDigest(
        uint256 accountId,
        uint256 oldAuthPkX,
        uint256 authPkX,
        uint256 authPkY,
        uint64 expiry,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(ROTATE_TYPEHASH, accountId, oldAuthPkX, authPkX, authPkY, expiry, nonce)
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _signRevoke(uint256 privateKey, uint256 accountId, uint256 authPkX, uint64 expiry, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, accountId, authPkX, expiry, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _revokeDigest(uint256 accountId, uint256 authPkX, uint64 expiry, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(REVOKE_TYPEHASH, accountId, authPkX, expiry, nonce));
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    function _legacySig(bytes memory sig) internal pure returns (EcdsaSig memory) {
        require(sig.length == 65, "bad sig len");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return EcdsaSig({v: v, r: r, s: s});
    }

    // ============ Initial State Tests ============

    function test_initialState() public view {
        assertEq(registry.currentAuthTreeNumber(), 0, "Should start at tree 0");
        assertEq(registry.authTreeCount(0), 0, "Tree 0 count should be 0");

        uint256 tree0Root = registry.authTreeRoot(0);
        assertGt(tree0Root, 0, "Tree 0 should have non-zero initial root (empty tree)");

        // registryRoot() should return tree 0's root
        assertEq(registry.registryRoot(), tree0Root, "registryRoot should equal tree 0 root");
    }

    function test_constants() public view {
        assertEq(registry.authTreeDepth(), 20, "authTreeDepth should be 20");
        assertEq(registry.MAX_AUTH_TREE_NUMBER(), 32767, "MAX_AUTH_TREE_NUMBER should be 2^15 - 1");
    }

    function test_constructor_revertWhen_authTreeDepthOutOfRange() public {
        vm.expectRevert(abi.encodeWithSelector(IAuthRegistry.AuthTreeDepthOutOfRange.selector, 0, 1, 20));
        new AuthRegistry(0);

        vm.expectRevert(abi.encodeWithSelector(IAuthRegistry.AuthTreeDepthOutOfRange.selector, 21, 1, 20));
        new AuthRegistry(21);

        // Boundary: depth 20 is accepted.
        AuthRegistry maxDepth = new AuthRegistry(20);
        assertEq(maxDepth.authTreeDepth(), 20, "depth 20 should be allowed");
    }

    function test_constructor_deploysPoseidonHelper() public view {
        address helper = registry.authPoseidon();
        uint256 accountId = registry.computeAccountId(owner, 123);
        uint256 leaf = registry.computeLeaf(accountId, PK1X, PK1Y, uint64(block.timestamp + 1 days));

        assertNotEq(helper, address(0));
        assertGt(helper.code.length, 0);
        assertNotEq(accountId, 0);
        assertNotEq(leaf, 0);
    }

    // ============ Register Tests ============

    function test_register_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint256 authPkX = PK1X;
        uint256 authPkY = PK1Y;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 nonce = registry.nonces(accountId);

        bytes memory sig = _signRegister(privateKey, accountId, authPkX, authPkY, expiry, nonce);
        bytes32 authKeyId = registry.computeAuthKeyId(accountId, authPkX);

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.Registered(accountId, signer, 0, authPkX, authPkY, expiry);
        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.AuthKeyAdded(accountId, authKeyId, 0, authPkX, authPkY, expiry);
        registry.register(salt, authPkX, authPkY, expiry, signer, sig);

        assertEq(registry.ownerOf(accountId), signer, "Owner should be signer");
        assertEq(registry.authKeyTreeOf(authKeyId), 0, "Should be in tree 0");
        assertEq(registry.authKeyIndexOf(authKeyId), 0, "Should be at index 0");
        assertEq(registry.authTreeCount(0), 1, "Tree count should be 1");
        assertEq(registry.nonces(accountId), 1, "Nonce should be incremented");
        assertEq(registry.getAuthKeys(accountId).length, 1, "Should have 1 auth key");
    }

    function test_register_legacyEcdsaSigTuple_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, _legacySig(sig));

        assertEq(registry.ownerOf(accountId), signer, "Owner should be signer");
        assertEq(registry.nonces(accountId), 1, "Nonce should be incremented");
    }

    function test_register_owner_direct_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);

        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        assertEq(registry.ownerOf(accountId), signer, "owner direct register should set owner");
        assertEq(registry.nonces(accountId), 1, "owner direct register should increment nonce");
    }

    function test_register_multipleAccounts() public {
        for (uint256 i = 1; i <= 5; i++) {
            uint256 privateKey = i;
            address signer = vm.addr(privateKey);

            uint256 salt = DEFAULT_SALT;
            uint256 accountId = registry.computeAccountId(signer, salt);
            uint64 expiry = uint64(block.timestamp + 1 hours);
            uint256 nonce = registry.nonces(accountId);

            bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, nonce);
            registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

            bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
            assertEq(registry.ownerOf(accountId), signer);
            assertEq(registry.authKeyTreeOf(authKeyId), 0);
            assertEq(registry.authKeyIndexOf(authKeyId), uint32(i - 1));
        }
        assertEq(registry.authTreeCount(0), 5);
    }

    function test_register_sameAuthKey_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        // Try to register same authPkX again (different authPkY doesn't matter - authKeyId is based on authPkX)
        bytes memory sig2 = _signRegister(privateKey, accountId, PK1X, PK1Y_ALT, expiry, 1);
        vm.expectRevert(IAuthRegistry.AlreadyRegistered.selector);
        registry.register(salt, PK1X, PK1Y_ALT, expiry, signer, sig2);
    }

    function test_register_multipleAuthKeys_sameAccount() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint64 secondExpiry = uint64(block.timestamp + 2 hours);

        // Register first auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.getAuthKeys(accountId).length, 1);

        // Register second auth key (different authPkX) - should succeed
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, secondExpiry, 1);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.AuthKeyAdded(accountId, authKeyId2, 0, PK2X, PK2Y, secondExpiry);
        registry.register(salt, PK2X, PK2Y, secondExpiry, signer, sig2);

        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.getAuthKeys(accountId).length, 2);
        assertEq(registry.nonces(accountId), 2);

        // Verify both auth keys exist
        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        assertEq(registry.authKeyTreeOf(authKeyId1), 0);
        assertEq(registry.authKeyIndexOf(authKeyId1), 0);
        assertEq(registry.authKeyTreeOf(authKeyId2), 0);
        assertEq(registry.authKeyIndexOf(authKeyId2), 1);
    }

    function test_register_differentOwner_invalidSignature_reverts() public {
        uint256 privateKey1 = 0x1234;
        uint256 privateKey2 = 0x5678;
        address signer1 = vm.addr(privateKey1);
        address signer2 = vm.addr(privateKey2);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer1, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register with first owner
        bytes memory sig1 = _signRegister(privateKey1, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer1, sig1);

        // A different owner derives a different accountId for the same salt, so the signature
        // over signer1's accountId becomes invalid for signer2's registration attempt.
        bytes memory sig2 = _signRegister(privateKey2, accountId, PK2X, PK2Y, expiry, 1);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.register(salt, PK2X, PK2Y, expiry, signer2, sig2);
    }

    function test_register_invalidSignature_reverts() public {
        uint256 privateKey = 0x1234;
        address wrongSigner = vm.addr(0x5678);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(wrongSigner, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Sign with privateKey but call as wrongSigner (msg.sender == expectedOwner, but signature doesn't match)
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.register(salt, PK1X, PK1Y, expiry, wrongSigner, sig);
    }

    function test_register_expiredSignature_reverts() public {
        // Warp to a larger timestamp so block.timestamp - 1 is non-zero
        vm.warp(1000);

        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp - 1); // Expired (999 < 1000)

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.expectRevert(IAuthRegistry.SignatureExpired.selector);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    function test_register_wrongNonce_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 wrongNonce = 999; // Wrong nonce

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, wrongNonce);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    function test_appendLeaf_rootMatchesManualFold() public {
        // Arrange
        uint256 privateKey = 0xA551;
        address signer = vm.addr(privateKey);
        uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 leaf = registry.computeLeaf(accountId, PK1X, PK1Y, expiry);
        uint256 expectedRoot = _manualSingleLeafRoot(leaf);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);

        // Act
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, sig);

        // Assert
        assertEq(registry.authTreeRoot(0), expectedRoot);
    }

    function test_appendLeaf_oddIndexUsesLeftSibling() public {
        // Arrange
        uint256 firstPrivateKey = 0xA552;
        uint256 secondPrivateKey = 0xA553;
        address firstSigner = vm.addr(firstPrivateKey);
        address secondSigner = vm.addr(secondPrivateKey);
        uint256 firstAccountId = registry.computeAccountId(firstSigner, DEFAULT_SALT);
        uint256 secondAccountId = registry.computeAccountId(secondSigner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 firstLeaf = registry.computeLeaf(firstAccountId, PK1X, PK1Y, expiry);
        uint256 secondLeaf = registry.computeLeaf(secondAccountId, PK2X, PK2Y, expiry);
        uint256 expectedRoot = _manualTwoLeafRoot(firstLeaf, secondLeaf);
        bytes memory firstSig = _signRegister(firstPrivateKey, firstAccountId, PK1X, PK1Y, expiry, 0);
        bytes memory secondSig = _signRegister(secondPrivateKey, secondAccountId, PK2X, PK2Y, expiry, 0);

        // Act
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, firstSigner, firstSig);
        registry.register(DEFAULT_SALT, PK2X, PK2Y, expiry, secondSigner, secondSig);

        // Assert
        assertEq(registry.authTreeRoot(0), expectedRoot);
    }

    function test_appendLeaf_sequenceMatchesIndependentFullTreeModel() public {
        // Arrange
        uint256[] memory leaves = new uint256[](9);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        for (uint256 i = 0; i < leaves.length; ++i) {
            uint256 privateKey = 0xA600 + i;
            address signer = vm.addr(privateKey);
            uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
            leaves[i] = registry.computeLeaf(accountId, PK1X, PK1Y, expiry);
        }

        // Act / Assert
        for (uint256 i = 0; i < leaves.length; ++i) {
            uint256 privateKey = 0xA600 + i;
            address signer = vm.addr(privateKey);
            uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
            bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
            registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, sig);

            assertEq(registry.authTreeRoot(0), _manualRootForPrefix(leaves, i + 1), "append root mismatch");
        }
    }

    function test_updateLeaf_indexFourMatchesIndependentFullTreeModel() public {
        // Arrange
        uint256[] memory leaves = new uint256[](9);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 targetPrivateKey;
        uint256 targetAccountId;
        for (uint256 i = 0; i < leaves.length; ++i) {
            uint256 privateKey = 0xA700 + i;
            address signer = vm.addr(privateKey);
            uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
            leaves[i] = registry.computeLeaf(accountId, PK1X, PK1Y, expiry);
            bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
            registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, sig);
            if (i == 4) {
                targetPrivateKey = privateKey;
                targetAccountId = accountId;
            }
        }
        uint64 newExpiry = expiry + 1 hours;
        bytes memory rotateSig = _signRotate(targetPrivateKey, targetAccountId, PK1X, PK2X, PK2Y, newExpiry, 1);

        // Act
        registry.rotate(targetAccountId, PK1X, PK2X, PK2Y, newExpiry, rotateSig);
        leaves[4] = registry.computeLeaf(targetAccountId, PK2X, PK2Y, newExpiry);

        // Assert
        assertEq(registry.authTreeRoot(0), _manualRootForPrefix(leaves, leaves.length));

        // Act
        bytes memory revokeSig = _signRevoke(targetPrivateKey, targetAccountId, PK2X, newExpiry, 2);
        registry.revoke(targetAccountId, PK2X, newExpiry, revokeSig);
        leaves[4] = 0;

        // Assert
        assertEq(registry.authTreeRoot(0), _manualRootForPrefix(leaves, leaves.length));
    }

    // ============ Rotate Tests ============

    function test_rotate_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint256 authPkX = PK1X;
        uint256 authPkY = PK1Y;
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // First register
        bytes memory regSig = _signRegister(privateKey, accountId, authPkX, authPkY, expiry, 0);
        registry.register(salt, authPkX, authPkY, expiry, signer, regSig);

        uint256 rootAfterRegister = registry.authTreeRoot(0);

        // Now rotate
        uint256 newAuthPkX = PK2X;
        uint256 newAuthPkY = PK2Y;
        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        uint256 rotateNonce = registry.nonces(accountId); // Should be 1
        bytes memory rotSig =
            _signRotate(privateKey, accountId, authPkX, newAuthPkX, newAuthPkY, newExpiry, rotateNonce);
        registry.rotate(accountId, authPkX, newAuthPkX, newAuthPkY, newExpiry, rotSig);

        uint256 expectedRoot = _manualSingleLeafRoot(registry.computeLeaf(accountId, newAuthPkX, newAuthPkY, newExpiry));

        // Owner should remain the same
        assertEq(registry.ownerOf(accountId), signer);
        // New auth key should be at the same tree/index position
        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, newAuthPkX);
        assertEq(registry.authKeyTreeOf(newAuthKeyId), 0);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0);
        // Old auth key ID should be cleared
        bytes32 oldAuthKeyId = registry.computeAuthKeyId(accountId, authPkX);
        assertEq(registry.authKeyTreeOf(oldAuthKeyId), 0);
        assertEq(registry.authKeyIndexOf(oldAuthKeyId), 0);
        // Root should match the exact replacement leaf fold.
        assertNotEq(expectedRoot, rootAfterRegister);
        assertEq(registry.authTreeRoot(0), expectedRoot);
        // Nonce should increment
        assertEq(registry.nonces(accountId), 2);
    }

    function test_currentAuthLeafAt_tracksRegisterRotateAndRevoke() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        uint256 firstLeaf = registry.computeLeaf(accountId, PK1X, PK1Y, expiry);
        bytes memory registerSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, registerSig);

        assertTrue(registry.isCurrentAuthLeafAt(0, firstLeaf));
        assertFalse(registry.isCurrentAuthLeafAt(1, firstLeaf));

        uint256 secondLeaf = registry.computeLeaf(accountId, PK2X, PK2Y, expiry);
        bytes memory rotateSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotateSig);

        assertFalse(registry.isCurrentAuthLeafAt(0, firstLeaf));
        assertTrue(registry.isCurrentAuthLeafAt(0, secondLeaf));

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK2X, expiry, 2);
        registry.revoke(accountId, PK2X, expiry, revokeSig);

        assertFalse(registry.isCurrentAuthLeafAt(0, secondLeaf));
    }

    function test_rotate_owner_direct_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);

        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, PK2X);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0, "owner direct rotate should reuse slot");
        assertEq(registry.nonces(accountId), 2, "owner direct rotate should increment nonce");
    }

    function test_rotateAndRevoke_legacyEcdsaSigTuple_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, _legacySig(regSig));

        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, _legacySig(rotSig));
        assertEq(registry.nonces(accountId), 2, "Nonce should increment after rotate");

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK2X, expiry, 2);
        registry.revoke(accountId, PK2X, expiry, _legacySig(revokeSig));

        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, PK2X);
        assertEq(registry.authKeyRevoked(newAuthKeyId), true, "Rotated key should be revoked");
        assertEq(registry.nonces(accountId), 3, "Nonce should increment after revoke");
    }

    function test_rotate_notRegistered_reverts() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        uint256 accountId = 111;
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Enable relay to test NotRegistered (rotate() would give NotOwner first)
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        bytes memory sig = _signRotate(privateKey, accountId, 111, PK1X, PK1Y, expiry, 0);
        vm.expectRevert(IAuthRegistry.NotRegistered.selector);
        registry.rotate(accountId, 111, PK1X, PK1Y, expiry, sig);
    }

    function test_rotate_authKeyNotFound_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register one auth key
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate non-existent auth key
        bytes memory rotSig = _signRotate(privateKey, accountId, 999, 666, 777, expiry, 1);
        vm.expectRevert(IAuthRegistry.AuthKeyNotFound.selector);
        registry.rotate(accountId, 999, 666, 777, expiry, rotSig); // oldAuthPkX = 999 doesn't exist
    }

    function test_rotate_toExistingAuthKey_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register two auth keys: 222 and 444
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        // Try to rotate auth key 222 → 444 (444 already exists)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 2);
        vm.expectRevert(IAuthRegistry.AlreadyRegistered.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);
    }

    function test_rotate_wrongSigner_reverts() public {
        uint256 privateKey = 0x1234;
        uint256 wrongPrivateKey = 0x5678;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register with privateKey
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate with wrongPrivateKey (but calling as correct owner)
        bytes memory rotSig = _signRotate(wrongPrivateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);
    }

    function test_rotate_expiredSignature_reverts() public {
        // Warp to a larger timestamp so block.timestamp - 1 is non-zero
        vm.warp(1000);

        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate with expired signature
        uint64 expiredExpiry = uint64(block.timestamp - 1); // 999 < 1000
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiredExpiry, 1);
        vm.expectRevert(IAuthRegistry.SignatureExpired.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiredExpiry, rotSig);
    }

    function test_rotate_replayAttack_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Rotate once
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);

        // Try to replay the same signature (nonce is now 2, but sig was for nonce 1)
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.rotate(accountId, PK2X, PK2X, PK2Y, expiry, rotSig);
    }

    function test_rotate_wrongOldAuthPkX_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register two auth keys: 222 and 444
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        // Sign rotate for key 222 → 666 (oldAuthPkX = 222)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 666, 777, expiry, 2);

        // Try to use same signature to rotate key 444 → 666 (oldAuthPkX = 444)
        // This should fail because the signature binds oldAuthPkX = 222
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.rotate(accountId, PK2X, 666, 777, expiry, rotSig);
    }

    // ============ getAllAuthTreeRoots Tests ============

    function test_getAllAuthTreeRoots_initial() public view {
        uint256[] memory roots = registry.getAllAuthTreeRoots();
        assertEq(roots.length, 1, "Should return 1 tree");
        assertGt(roots[0], 0, "Tree 0 root should be non-zero");
    }

    function test_getAllAuthTreeRoots_afterRegister() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        uint256 rootBefore = registry.authTreeRoot(0);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        uint256[] memory roots = registry.getAllAuthTreeRoots();
        assertEq(roots.length, 1, "Should still return 1 tree");
        assertNotEq(roots[0], rootBefore, "Root should change after register");
        assertEq(roots[0], registry.authTreeRoot(0));
    }

    // ============ getAuthRootStatuses Tests ============

    function test_getAuthRootStatuses_currentRoot() public view {
        uint256 currentRoot = registry.authTreeRoot(0);
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: currentRoot});

        (uint64 blockNumber, uint256 currentTreeNumber, AuthRootStatus[] memory statuses) =
            registry.getAuthRootStatuses(roots, 64);

        assertEq(blockNumber, uint64(block.number), "block number should match");
        assertEq(currentTreeNumber, 0, "current tree should be 0");
        assertEq(statuses.length, 1, "one status");
        assertEq(statuses[0].treeNumber, 0, "tree number");
        assertEq(statuses[0].root, currentRoot, "root");
        assertTrue(statuses[0].isCurrent, "current root should be current");
        assertTrue(statuses[0].isRecent, "current root should be recent");
        assertEq(statuses[0].supersededBlock, 0, "current root should not be superseded");
        assertEq(statuses[0].remainingBlocks, type(uint64).max, "current root should not expire");
    }

    function test_getAuthRootStatuses_supersededFreshAndExpiredRoot() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 previousRoot = registry.authTreeRoot(0);

        vm.roll(100);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
        uint256 currentRoot = registry.authTreeRoot(0);

        TreeRootPair[] memory roots = new TreeRootPair[](2);
        roots[0] = TreeRootPair({treeNumber: 0, root: previousRoot});
        roots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        vm.roll(120);
        (, uint256 currentTreeNumber, AuthRootStatus[] memory freshStatuses) = registry.getAuthRootStatuses(roots, 64);
        assertEq(currentTreeNumber, 0, "current tree should be 0");
        assertFalse(freshStatuses[0].isCurrent, "old root is not current");
        assertTrue(freshStatuses[0].isRecent, "old root should still be recent");
        assertEq(freshStatuses[0].supersededBlock, 100, "old root superseded block");
        assertEq(freshStatuses[0].remainingBlocks, 44, "old root remaining window");
        assertTrue(freshStatuses[1].isCurrent, "new root is current");
        assertTrue(freshStatuses[1].isRecent, "new root is recent");

        vm.roll(165);
        (,, AuthRootStatus[] memory expiredStatuses) = registry.getAuthRootStatuses(roots, 64);
        assertFalse(expiredStatuses[0].isCurrent, "expired root is not current");
        assertFalse(expiredStatuses[0].isRecent, "expired root is not recent");
        assertEq(expiredStatuses[0].supersededBlock, 100, "expired root superseded block");
        assertEq(expiredStatuses[0].remainingBlocks, 0, "expired root remaining window");
    }

    function test_getAuthRootStatuses_zeroAndFutureTreeRoots() public view {
        TreeRootPair[] memory roots = new TreeRootPair[](2);
        roots[0] = TreeRootPair({treeNumber: 0, root: 0});
        roots[1] = TreeRootPair({treeNumber: 99, root: registry.authTreeRoot(0)});

        (, uint256 currentTreeNumber, AuthRootStatus[] memory statuses) = registry.getAuthRootStatuses(roots, 64);

        assertEq(currentTreeNumber, 0, "current tree should be 0");
        assertEq(statuses.length, 2, "two statuses");
        assertEq(statuses[0].treeNumber, 0, "zero status preserves tree");
        assertEq(statuses[0].root, 0, "zero status preserves root");
        assertFalse(statuses[0].isCurrent, "zero root is not current");
        assertFalse(statuses[0].isRecent, "zero root is not recent");
        assertEq(statuses[1].treeNumber, 99, "future status preserves tree");
        assertFalse(statuses[1].isCurrent, "future tree is not current");
        assertFalse(statuses[1].isRecent, "future tree is not recent");
    }

    // ============ registryRoot (backwards compatibility) Tests ============

    function test_registryRoot_backwardsCompatibility() public view {
        // registryRoot() should always return current active tree's root
        assertEq(registry.registryRoot(), registry.authTreeRoot(registry.currentAuthTreeNumber()));
    }

    // ============ computeLeaf Tests ============

    function test_computeLeaf_deterministic() public view {
        uint256 leaf1 = registry.computeLeaf(111, 222, 333, 0);
        uint256 leaf2 = registry.computeLeaf(111, 222, 333, 0);
        assertEq(leaf1, leaf2, "Same inputs should produce same leaf");
    }

    function test_computeLeaf_differentInputs() public view {
        uint256 leaf1 = registry.computeLeaf(111, 222, 333, 0);
        uint256 leaf2 = registry.computeLeaf(112, 222, 333, 0);
        assertNotEq(leaf1, leaf2, "Different accountId should produce different leaf");
    }

    // ============ RootUpdated Event Tests ============

    function test_rootUpdatedEvent_includesTreeNumber() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);

        // Expect RootUpdated event with treeNumber = 0
        vm.expectEmit(true, false, false, false);
        emit IAuthRegistry.RootUpdated(0, 0); // Only check indexed treeNumber
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    // ============ Multi-tree Rollover Tests (Conceptual) ============
    // Note: Testing actual rollover would require filling 2^20 = 1M+ entries,
    // which is impractical in a unit test. We test the logic conceptually.

    function test_multiTree_authKeyTreeOfMapping() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        // authKeyTreeOf should return the tree number where the auth key was registered
        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertEq(registry.authKeyTreeOf(authKeyId), 0);
    }

    function test_multiTree_authKeyIndexOfMapping() public {
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register multiple accounts and verify indices
        for (uint256 i = 1; i <= 3; i++) {
            uint256 privateKey = i;
            address signer = vm.addr(privateKey);
            uint256 salt = DEFAULT_SALT;
            uint256 accountId = registry.computeAccountId(signer, salt);
            uint256 nonce = registry.nonces(accountId);

            bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, nonce);
            registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

            bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
            assertEq(registry.authKeyIndexOf(authKeyId), uint32(i - 1), "Index should be sequential");
        }
    }

    // ============ Nonce Tests ============

    function test_nonce_incrementsCorrectly() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        assertEq(registry.nonces(accountId), 0);

        // Register increments nonce
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);
        assertEq(registry.nonces(accountId), 1);

        // Rotate increments nonce
        bytes memory rotSig1 = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig1);
        assertEq(registry.nonces(accountId), 2);

        // Another rotate increments nonce again
        bytes memory rotSig2 = _signRotate(privateKey, accountId, PK2X, PK3X, PK3Y, expiry, 2);
        registry.rotate(accountId, PK2X, PK3X, PK3Y, expiry, rotSig2);
        assertEq(registry.nonces(accountId), 3);
    }

    function test_nonce_sharedAcrossAuthKeys() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        assertEq(registry.nonces(accountId), 0);

        // Register first auth key (nonce 0)
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);
        assertEq(registry.nonces(accountId), 1);

        // Register second auth key (nonce 1)
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);
        assertEq(registry.nonces(accountId), 2);

        // Rotate first auth key (nonce 2)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK3X, PK3Y, expiry, 2);
        registry.rotate(accountId, PK1X, PK3X, PK3Y, expiry, rotSig);
        assertEq(registry.nonces(accountId), 3);
    }

    // ============ Edge Cases ============

    function test_register_withExpiryAndFlags() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint256 authPkX = PK1X;
        uint256 authPkY = PK1Y;
        uint64 expiry = uint64(block.timestamp + 1 days);

        bytes memory sig = _signRegister(privateKey, accountId, authPkX, authPkY, expiry, 0);
        registry.register(salt, authPkX, authPkY, expiry, signer, sig);

        assertEq(registry.ownerOf(accountId), signer);
    }

    // ============ NotAuthorized Tests ============

    function test_register_notAuthorized_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        address notAuthorized = address(0xDEAD);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);

        // Try to call register as notAuthorized (not owner and not relay)
        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    function test_rotate_notAuthorized_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        address notAuthorized = address(0xDEAD);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // First register
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate as notAuthorized (not owner and not relay)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);
    }

    function test_rotate_notAuthorized_beforeNotRegistered_reverts() public {
        uint256 privateKey = 0x1234;
        address notAuthorized = address(0xDEAD);
        uint256 accountId = 111;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 0);

        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);
    }

    // ============ Operator Tests ============

    function test_setOperator_success() public {
        address newOperator = makeAddr("newOperator");
        registry.setOperator(newOperator);
        assertEq(registry.operator(), newOperator);
    }

    function test_setOperator_emitsEvent() public {
        address newOperator = makeAddr("newOperator");

        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.OperatorUpdated(operator, newOperator);

        registry.setOperator(newOperator);
    }

    function test_setOperator_notOwner_reverts() public {
        address notOwner = makeAddr("notOwner");
        vm.prank(notOwner);
        vm.expectRevert();
        registry.setOperator(makeAddr("newOperator"));
    }

    function test_setOperator_zeroAddress_reverts() public {
        vm.expectRevert(IAuthRegistry.InvalidOperatorAddress.selector);
        registry.setOperator(address(0));
    }

    // ============ Relayer Tests ============

    function test_setAllowedRelays_success() public {
        address relay1 = address(0xBEEF);
        address relay2 = address(0xCAFE);

        assertFalse(registry.allowedRelays(relay1));
        assertFalse(registry.allowedRelays(relay2));

        address[] memory relays = new address[](2);
        relays[0] = relay1;
        relays[1] = relay2;

        vm.expectEmit(true, false, false, true);
        emit IAuthRegistry.RelayUpdated(relay1, true);
        vm.expectEmit(true, false, false, true);
        emit IAuthRegistry.RelayUpdated(relay2, true);

        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        assertTrue(registry.allowedRelays(relay1));
        assertTrue(registry.allowedRelays(relay2));

        // Disable one relay
        address[] memory toDisable = new address[](1);
        toDisable[0] = relay1;

        vm.expectEmit(true, false, false, true);
        emit IAuthRegistry.RelayUpdated(relay1, false);

        vm.prank(operator);
        registry.setAllowedRelays(toDisable, false);

        assertFalse(registry.allowedRelays(relay1));
        assertTrue(registry.allowedRelays(relay2));
    }

    function test_setAllowedRelays_notOwner_reverts() public {
        address notOwner = address(0xDEAD);
        address relay = address(0xBEEF);

        address[] memory relays = new address[](1);
        relays[0] = relay;

        vm.prank(notOwner);
        vm.expectRevert(IAuthRegistry.NotOperator.selector);
        registry.setAllowedRelays(relays, true);
    }

    function test_register_allowedRelay_success() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint256 authPkX = PK1X;
        uint256 authPkY = PK1Y;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 nonce = registry.nonces(accountId);

        bytes memory sig = _signRegister(privateKey, accountId, authPkX, authPkY, expiry, nonce);

        vm.prank(relay);
        registry.register(salt, authPkX, authPkY, expiry, signer, sig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, authPkX);
        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.authKeyTreeOf(authKeyId), 0);
        assertEq(registry.authKeyIndexOf(authKeyId), 0);
        assertEq(registry.authTreeCount(0), 1);
    }

    function test_rotate_allowedRelay_success() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // First register (using relay)
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Now rotate (using relay)
        uint256 newAuthPkX = PK2X;
        uint256 newAuthPkY = PK2Y;
        uint256 rotateNonce = registry.nonces(accountId);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, newAuthPkX, newAuthPkY, expiry, rotateNonce);

        vm.prank(relay);
        registry.rotate(accountId, PK1X, newAuthPkX, newAuthPkY, expiry, rotSig);

        bytes32 oldAuthKeyId = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, newAuthPkX);
        assertEq(registry.authKeyIndexOf(oldAuthKeyId), 0);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0);
        assertEq(registry.nonces(accountId), 2);
    }

    function test_register_allowedRelay_invalidSignature_reverts() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address wrongSigner = vm.addr(0x5678);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(wrongSigner, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Sign with privateKey but claim wrongSigner as expectedOwner
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(relay);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.register(salt, PK1X, PK1Y, expiry, wrongSigner, sig);
    }

    function test_register_eip1271ContractWallet_success() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = hex"1271c0ffee";
        bytes32 digest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        wallet.approveSignature(digest, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.authKeyTreeOf(authKeyId), 0);
        assertEq(registry.authKeyIndexOf(authKeyId), 0);
        assertEq(registry.nonces(accountId), 1);
    }

    function test_register_eip1271ContractWallet_rejectedSignature_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = hex"bad01271";
        vm.expectRevert(IAuthRegistry.InvalidSignatureLength.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    function test_register_erc7739Appendix_malformedLength_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = new bytes(131);
        vm.expectRevert(IAuthRegistry.InvalidSignatureLength.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    /// @dev keccak256("Contents(bytes32 stuff)") duplicated from
    ///      AuthRegistry.CONTENTS_DESCRIPTION_HASH (private constant). If the
    ///      supported appendix description ever changes, this must move in
    ///      lockstep.
    bytes32 private constant CONTENTS_DESCRIPTION_HASH = keccak256("Contents(bytes32 stuff)");
    bytes32 private constant MOCK_ERC7739_TYPED_DATA_SIGN_TYPEHASH = keccak256(
        "TypedDataSign(Contents contents,string name,string version,uint256 chainId,address verifyingContract)Contents(bytes32 stuff)"
    );

    /// @dev Builds an ERC-7739 TypedDataSign appendix shaped like the ones
    ///      Solady-derived validators (Startale's StartaleSmartAccount, etc.)
    ///      emit when the wallet wraps dapp typed data into a generic
    ///      `Contents(bytes32 stuff)` placeholder rather than introspecting
    ///      it. Inner sig content is opaque — our mock approves by hash, not
    ///      by sig validity.
    function _buildErc7739Sig(bytes32 appSep, bytes32 contentsHash) internal pure returns (bytes memory) {
        return _buildErc7739SigWithDescription(appSep, contentsHash, "Contents(bytes32 stuff)");
    }

    function _buildErc7739SigWithInner(bytes memory inner, bytes32 appSep, bytes32 contentsHash)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(inner, appSep, contentsHash, bytes("Contents(bytes32 stuff)"), uint16(23));
    }

    function _buildErc7739SigWithoutInner(bytes32 appSep, bytes32 contentsHash) internal pure returns (bytes memory) {
        return abi.encodePacked(appSep, contentsHash, bytes("Contents(bytes32 stuff)"), uint16(23));
    }

    /// @dev Variant that allows overriding the contentsDescription byte
    ///      string. Layout is identical; only the description bytes and the
    ///      trailing uint16 length
    ///      differ.
    function _buildErc7739SigWithDescription(bytes32 appSep, bytes32 contentsHash, bytes memory contentsDescription)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory inner = new bytes(65); // any opaque 65-byte inner sig
        return abi.encodePacked(inner, appSep, contentsHash, contentsDescription, uint16(contentsDescription.length));
    }

    /// @dev Computes the Solady accepted contentsHash shape for the rewrap path:
    ///      Solady's generic wrap places the dapp's struct hash into
    ///      `Contents{stuff: dappStructHash}` and hashStructs that.
    function _erc7739BoundContentsHash(bytes32 dappStructHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(CONTENTS_DESCRIPTION_HASH, dappStructHash));
    }

    function _mockERC7739WalletDigest(address wallet, bytes32 contentsHash) internal view returns (bytes32) {
        bytes32 walletDomainSep = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256(bytes("MockERC7739Account")), keccak256(bytes("1")), block.chainid, wallet
            )
        );
        bytes32 walletStructHash = keccak256(
            abi.encode(
                MOCK_ERC7739_TYPED_DATA_SIGN_TYPEHASH,
                contentsHash,
                keccak256(bytes("MockERC7739Account")),
                keccak256(bytes("1")),
                block.chainid,
                wallet
            )
        );
        return keccak256(abi.encodePacked(hex"1901", walletDomainSep, walletStructHash));
    }

    function test_register_erc7739Appendix_success() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // contentsHash must bind to THIS register call, otherwise the
        // wrapped fallback rejects after the raw path fails.
        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 contentsHash = _erc7739BoundContentsHash(registerStructHash);
        bytes memory sig = _buildErc7739Sig(_domainSeparator(), contentsHash);
        bytes32 expectedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), contentsHash));
        wallet.approveSignature(expectedWrapped, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    function test_register_erc7739Appendix_rawDigestContentsHash_success() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes memory sig = _buildErc7739Sig(_domainSeparator(), rawDigest);
        bytes32 expectedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), rawDigest));
        wallet.approveSignature(expectedWrapped, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    function test_register_erc7739Appendix_shortOpaquePrefix_success() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes memory sig = _buildErc7739SigWithInner(hex"01", _domainSeparator(), rawDigest);
        assertEq(sig.length - 66 - 23, 1, "sanity: one-byte opaque prefix");
        bytes32 expectedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), rawDigest));
        wallet.approveSignature(expectedWrapped, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    function test_register_erc7739Appendix_zeroOpaquePrefix_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes memory sig = _buildErc7739SigWithoutInner(_domainSeparator(), rawDigest);
        assertEq(sig.length, 66 + 23, "sanity: appendix-only sig");
        vm.expectRevert(IAuthRegistry.InvalidSignatureLength.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    function test_register_erc7739Appendix_rawDigestContentsHash_real7739Wallet_success() public {
        uint256 ownerKey = 0x7739;
        address walletOwner = vm.addr(ownerKey);
        address relay = address(0xBEEF);
        MockERC7739Account wallet = new MockERC7739Account(walletOwner);

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes32 walletDigest = _mockERC7739WalletDigest(address(wallet), rawDigest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, walletDigest);
        bytes memory innerSig = abi.encodePacked(r, s, v);
        bytes memory sig =
            abi.encodePacked(innerSig, _domainSeparator(), rawDigest, bytes("Contents(bytes32 stuff)"), uint16(23));
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    /// @dev Appendix carries a different APP_DOMAIN_SEPARATOR than ours —
    ///      contract must NOT trust it, so verification fails after the raw
    ///      path fails.
    ///      This is the cross-app sig replay defense.
    function test_register_erc7739Appendix_wrongAppDomainSep_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 contentsHash = _erc7739BoundContentsHash(registerStructHash);
        bytes32 wrongSep = bytes32(uint256(0xdeadbeef));
        bytes memory sig = _buildErc7739Sig(wrongSep, contentsHash);
        // Wallet would have approved the wrapped hash IF we'd rewrapped under
        // wrongSep — but we don't, because wrongSep != ours. So the wallet
        // never sees a hash it recognises.
        bytes32 wouldBeWrapped = keccak256(abi.encodePacked(hex"1901", wrongSep, contentsHash));
        wallet.approveSignature(wouldBeWrapped, sig);
        vm.expectRevert(IAuthRegistry.InvalidERC7739AppDomain.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    /// @dev Appendix carries a contentsHash that is NOT bound to the current
    ///      Register struct hash (e.g. it was bound to a different action,
    ///      or to an arbitrary value). The contract MUST reject it; otherwise
    ///      any 7739 sig the user ever produced for our domain could be
    ///      replayed across (accountId, authPk*, expiry, nonce) tuples.
    function test_register_erc7739Appendix_unboundContentsHash_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        // Arbitrary contentsHash NOT derived from the current Register struct hash.
        bytes32 contentsHash = keccak256("not-bound-to-this-action");
        bytes memory sig = _buildErc7739Sig(_domainSeparator(), contentsHash);
        // Pre-approve the wrapped hash on the wallet so the ONLY thing
        // standing between the attack and success is the contract's binding
        // check. If the contract incorrectly rewraps, the wallet would
        // accept and the test would fail.
        bytes32 wouldBeWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), contentsHash));
        wallet.approveSignature(wouldBeWrapped, sig);

        uint256 salt = DEFAULT_SALT;
        uint64 expiry = uint64(block.timestamp + 1 hours);
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsHash.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    /// @dev Appendix carries a contentsDescription length other than 23.
    ///      AuthRegistry intentionally supports only the exact implicit-mode
    ///      Solady/Startale `Contents(bytes32 stuff)` appendix shape.
    function test_register_erc7739Appendix_wrongContentsDescriptionLength_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 contentsHash = _erc7739BoundContentsHash(registerStructHash);
        bytes memory sig =
            _buildErc7739SigWithDescription(_domainSeparator(), contentsHash, "MailDigest(bytes32 stuff)");
        bytes32 wouldBeWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), contentsHash));
        wallet.approveSignature(wouldBeWrapped, sig);
        vm.expectRevert(IAuthRegistry.InvalidSignatureLength.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    /// @dev Appendix is well-formed and contentsHash binds to the current
    ///      struct hash, BUT contentsDescription is not the Solady placeholder.
    ///      The contract MUST reject it. Pinning to the placeholder typestring
    ///      is the safety margin that prevents future nested-typed-data shapes
    ///      (with different hashStruct semantics) from silently routing through
    ///      this rewrap path.
    function test_register_erc7739Appendix_wrongContentsDescription_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 contentsHash = _erc7739BoundContentsHash(registerStructHash);
        // Same 23-byte appendix shape but with a different description.
        bytes memory sig = _buildErc7739SigWithDescription(_domainSeparator(), contentsHash, "Contentz(bytes32 stuff)");
        bytes32 wouldBeWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), contentsHash));
        wallet.approveSignature(wouldBeWrapped, sig);
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsDescription.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    function test_register_erc7739Appendix_wrappedSignatureRejected_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 contentsHash = _erc7739BoundContentsHash(registerStructHash);
        bytes memory sig = _buildErc7739Sig(_domainSeparator(), contentsHash);
        vm.expectRevert(IAuthRegistry.InvalidERC7739WrappedSignature.selector);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);
    }

    /// @dev Capture a valid 7739 sig for register(PK1) and attempt to replay
    ///      it as register(PK2). The captured appendix binds contentsHash to
    ///      the PK1 struct hash; the on-chain rewrap computes the accepted
    ///      contents hashes from the PK2 call, sees the mismatch, and rejects.
    function test_register_erc7739Appendix_replayAcrossAuthKey_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Wallet "signs" for register(PK1) — pre-approve the wrapped hash it
        // would produce if the rewrap fired with the PK1-bound contentsHash.
        bytes32 pk1StructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 capturedContentsHash = _erc7739BoundContentsHash(pk1StructHash);
        bytes memory capturedSig = _buildErc7739Sig(_domainSeparator(), capturedContentsHash);
        bytes32 capturedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), capturedContentsHash));
        wallet.approveSignature(capturedWrapped, capturedSig);

        // Attacker submits register(PK2) using the captured sig. On-chain,
        // expectedContentsHash is derived from the PK2 struct hash so does
        // not match capturedContentsHash, so the fallback rejects.
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsHash.selector);
        registry.register(salt, PK2X, PK2Y, expiry, address(wallet), capturedSig);
    }

    /// @dev Same replay shape as above, but for the Startale-compatible branch
    ///      where contentsHash is the raw dapp EIP-712 digest. A digest captured
    ///      for register(PK1) must not authorize register(PK2).
    function test_register_erc7739Appendix_rawDigestReplayAcrossAuthKey_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes32 capturedRawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes memory capturedSig = _buildErc7739Sig(_domainSeparator(), capturedRawDigest);
        bytes32 capturedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), capturedRawDigest));
        wallet.approveSignature(capturedWrapped, capturedSig);
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsHash.selector);
        registry.register(salt, PK2X, PK2Y, expiry, address(wallet), capturedSig);
    }

    /// @dev Replay across expiry: sig bound to expiry=t1 must not authorize
    ///      a register call with expiry=t2.
    function test_register_erc7739Appendix_replayAcrossExpiry_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry1 = uint64(block.timestamp + 1 hours);
        uint64 expiry2 = uint64(block.timestamp + 2 hours);

        bytes32 capturedStructHash =
            keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry1, uint256(0)));
        bytes32 capturedContentsHash = _erc7739BoundContentsHash(capturedStructHash);
        bytes memory capturedSig = _buildErc7739Sig(_domainSeparator(), capturedContentsHash);
        bytes32 capturedWrapped = keccak256(abi.encodePacked(hex"1901", _domainSeparator(), capturedContentsHash));
        wallet.approveSignature(capturedWrapped, capturedSig);
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsHash.selector);
        registry.register(salt, PK1X, PK1Y, expiry2, address(wallet), capturedSig);
    }

    /// @dev Replay across action: sig bound to Register cannot authorize a
    ///      Rotate. First register a wallet's key via the 7739 path, then
    ///      attempt to rotate that key using the SAME 7739 appendix. The
    ///      Register-bound contentsHash doesn't match the Rotate call's
    ///      accepted contentsHash, so the fallback rejects.
    function test_rotate_erc7739Appendix_replayFromRegister_reverts() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Phase 1 — legitimate register(PK1) via 7739.
        bytes32 registerStructHash = keccak256(abi.encode(REGISTER_TYPEHASH, accountId, PK1X, PK1Y, expiry, uint256(0)));
        bytes32 registerContentsHash = _erc7739BoundContentsHash(registerStructHash);
        bytes memory registerSig = _buildErc7739Sig(_domainSeparator(), registerContentsHash);
        wallet.approveSignature(
            keccak256(abi.encodePacked(hex"1901", _domainSeparator(), registerContentsHash)), registerSig
        );
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), registerSig);
        assertEq(registry.ownerOf(accountId), address(wallet));

        // Phase 2 — attacker replays the SAME 7739 register sig as a rotate.
        // The contract derives expectedContentsHash from the Rotate struct
        // hash (different typehash + different fields + nonce=1 now); it
        // won't match the captured Register-bound contentsHash, so the
        // fallback rejects.
        vm.expectRevert(IAuthRegistry.InvalidERC7739ContentsHash.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, registerSig);
    }

    /// @dev Trailing uint16 length > 256 — outside the heuristic cap.
    ///      _verifyOwnerSig MUST accept through the raw-first path before
    ///      trying the appendix parser. Wallet only approves the raw digest
    ///      here, so register must succeed.
    function test_register_erc7739Appendix_oversizedContentsLength_fallback() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        // Build a sig whose tail decodes to uint16=257 — past the cap. The
        // body is opaque; what matters is the heuristic gate rejects it.
        bytes memory body = new bytes(200); // any payload >= 132 bytes
        bytes memory sig = abi.encodePacked(body, uint16(257));

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        wallet.approveSignature(rawDigest, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    /// @dev Trailing uint16 declares an appendix larger than the sig can
    ///      hold (66 + n + 65 > sigLen). _verifyOwnerSig MUST accept through
    ///      the raw-first path before trying the appendix parser.
    function test_register_erc7739Appendix_lengthBypass_fallback() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        // 132-byte sig (smallest length the heuristic gate inspects) whose
        // trailing uint16 = 200. Then 66 + 200 + 65 = 331 > 132, so the
        // appendix would not fit, but raw-first must accept it.
        bytes memory body = new bytes(130);
        bytes memory sig = abi.encodePacked(body, uint16(200));
        assertEq(sig.length, 132, "sanity: sig at minimum gate length");

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        wallet.approveSignature(rawDigest, sig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), sig);

        assertEq(registry.ownerOf(accountId), address(wallet));
        assertEq(registry.nonces(accountId), 1);
    }

    function test_rotateAndRevoke_eip1271ContractWallet_success() public {
        address relay = address(0xBEEF);
        ERC1271WalletMock wallet = new ERC1271WalletMock();

        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(address(wallet), salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory registerSig = hex"127101";
        wallet.approveSignature(_registerDigest(accountId, PK1X, PK1Y, expiry, 0), registerSig);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), registerSig);

        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        bytes memory rotateSig = hex"12710202";
        wallet.approveSignature(_rotateDigest(accountId, PK1X, PK2X, PK2Y, newExpiry, 1), rotateSig);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, newExpiry, rotateSig);

        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, PK2X);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0);
        assertEq(registry.nonces(accountId), 2);

        bytes memory revokeSig = hex"1271030303";
        wallet.approveSignature(_revokeDigest(accountId, PK2X, newExpiry, 2), revokeSig);
        registry.revoke(accountId, PK2X, newExpiry, revokeSig);

        assertTrue(registry.authKeyRevoked(newAuthKeyId));
        assertEq(registry.nonces(accountId), 3);
    }

    function test_relay_disabled_after_use_reverts() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register using relay (should succeed)
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        assertEq(registry.ownerOf(accountId), signer);

        // Disable relay
        vm.prank(operator);
        registry.setAllowedRelays(relays, false);
        assertFalse(registry.allowedRelays(relay));

        // Try to rotate using disabled relay (should revert with NotAuthorized)
        uint256 rotateNonce = registry.nonces(accountId);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, rotateNonce);
        vm.prank(relay);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);
    }

    function test_setAllowedRelays_zeroAddress_reverts() public {
        address[] memory relays = new address[](1);
        relays[0] = address(0);

        vm.prank(operator);
        vm.expectRevert(IAuthRegistry.InvalidRelayAddress.selector);
        registry.setAllowedRelays(relays, true);
    }

    function test_setAllowedRelays_zeroAddressInArray_reverts() public {
        address[] memory relays = new address[](3);
        relays[0] = address(0xBEEF);
        relays[1] = address(0); // zero address in middle
        relays[2] = address(0xCAFE);

        vm.prank(operator);
        vm.expectRevert(IAuthRegistry.InvalidRelayAddress.selector);
        registry.setAllowedRelays(relays, true);

        // Verify first relay was not set (transaction reverted)
        assertFalse(registry.allowedRelays(address(0xBEEF)));
    }

    function _attachPortalDelegation(uint256 privateKey) internal returns (address delegatedOwner) {
        MockWETH weth = new MockWETH();
        PortalDelegate delegateImpl = new PortalDelegate(IPrivacyBoost(makeAddr("portalPool")), IWETH(address(weth)));
        delegatedOwner = vm.addr(privateKey);
        vm.signAndAttachDelegation(address(delegateImpl), privateKey);
        assertEq(EIP7702Utils.fetchDelegate(delegatedOwner), address(delegateImpl));
    }

    // ============ EIP-7702 Delegated Owner Tests ============

    function test_register_eip7702DelegatedOwner_directOwner_success() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);

        // Act
        vm.prank(delegatedOwner);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, sig);

        // Assert
        assertEq(registry.ownerOf(accountId), delegatedOwner);
        assertEq(registry.nonces(accountId), 1);
    }

    function test_rotate_eip7702DelegatedOwner_directOwner_success() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory registerSig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, registerSig);
        bytes memory rotateSig = _signRotate(DELEGATED_OWNER_PK, accountId, PK1X, PK2X, PK2Y, expiry, 1);

        // Act
        vm.prank(delegatedOwner);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotateSig);

        // Assert
        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, PK2X);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0);
        assertEq(registry.nonces(accountId), 2);
    }

    function test_revoke_eip7702DelegatedOwner_directOwner_success() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory registerSig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, registerSig);
        bytes memory revokeSig = _signRevoke(DELEGATED_OWNER_PK, accountId, PK1X, expiry, 1);
        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);

        // Act
        vm.prank(delegatedOwner);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        // Assert
        assertTrue(registry.authKeyRevoked(authKeyId));
        assertEq(registry.nonces(accountId), 2);
    }

    function test_register_eip7702DelegatedOwner_wrongSigner_reverts() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory wrongSig = _signRegister(0xB0B, accountId, PK1X, PK1Y, expiry, 0);

        // Act
        vm.startPrank(delegatedOwner);
        vm.expectRevert(IAuthRegistry.InvalidSignatureLength.selector);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, wrongSig);
        vm.stopPrank();

        // Assert
        assertEq(registry.ownerOf(accountId), address(0));
        assertEq(registry.nonces(accountId), 0);
    }

    function test_register_eip7702DelegatedOwner_legacyEcdsaSigTuple_success() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);

        // Act
        vm.prank(delegatedOwner);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, _legacySig(sig));

        // Assert
        assertEq(registry.ownerOf(accountId), delegatedOwner);
        assertEq(registry.nonces(accountId), 1);
    }

    function test_register_eip7702DelegatedOwner_allowedRelay_success() public {
        // Arrange
        address delegatedOwner = _attachPortalDelegation(DELEGATED_OWNER_PK);
        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);
        assertTrue(registry.allowedRelays(address(this)));

        // Act
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, sig);

        // Assert
        assertEq(registry.ownerOf(accountId), delegatedOwner);
        assertEq(registry.nonces(accountId), 1);
    }

    /// @dev A delegated EOA whose delegate is a real ERC-7739 wallet must
    ///      still reach the appendix parser. This is what forces the
    ///      delegated-owner branch to use non-reverting `tryRecover`: a
    ///      reverting `recover` would reject the longer appendix signature
    ///      on length before the parser ever saw it, locking out every
    ///      7739-capable delegate.
    function test_register_eip7702DelegatedOwner_erc7739AppendixSignature_success() public {
        // Arrange
        uint256 walletOwnerKey = 0x7739;
        address walletOwner = vm.addr(walletOwnerKey);
        MockERC7739Account walletImpl = new MockERC7739Account(walletOwner);
        address delegatedOwner = vm.addr(DELEGATED_OWNER_PK);
        vm.signAndAttachDelegation(address(walletImpl), DELEGATED_OWNER_PK);
        assertEq(EIP7702Utils.fetchDelegate(delegatedOwner), address(walletImpl));

        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes32 rawDigest = _registerDigest(accountId, PK1X, PK1Y, expiry, 0);
        bytes32 walletDigest = _mockERC7739WalletDigest(delegatedOwner, rawDigest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(walletOwnerKey, walletDigest);
        bytes memory sig = abi.encodePacked(
            abi.encodePacked(r, s, v), _domainSeparator(), rawDigest, bytes("Contents(bytes32 stuff)"), uint16(23)
        );

        // Act
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, sig);

        // Assert
        assertEq(registry.ownerOf(accountId), delegatedOwner);
        assertEq(registry.nonces(accountId), 1);
    }

    /// @dev The delegated EOA's own key stays root authority for auth key
    ///      mutations even when the installed delegate's ERC-1271 policy
    ///      rejects the same raw digest. That key can revoke the delegation
    ///      at any time, so the delegate never holds authority the key lacks.
    function test_register_eip7702DelegatedOwner_delegateRejectsErc1271_success() public {
        // Arrange
        ERC1271RejectingWalletMock rejectingImpl = new ERC1271RejectingWalletMock();
        address delegatedOwner = vm.addr(DELEGATED_OWNER_PK);
        vm.signAndAttachDelegation(address(rejectingImpl), DELEGATED_OWNER_PK);
        assertEq(EIP7702Utils.fetchDelegate(delegatedOwner), address(rejectingImpl));

        uint256 accountId = registry.computeAccountId(delegatedOwner, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(DELEGATED_OWNER_PK, accountId, PK1X, PK1Y, expiry, 0);

        // Act
        vm.prank(delegatedOwner);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, delegatedOwner, sig);

        // Assert
        assertEq(registry.ownerOf(accountId), delegatedOwner);
        assertEq(registry.nonces(accountId), 1);
    }

    // ============ Revoke Tests ============

    function test_revoke_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register two auth keys
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        assertFalse(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke first auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 2);

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.AuthKeyRevoked(accountId, authKeyId1, 0, 0);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        assertTrue(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2)); // Second key still active
        assertEq(registry.getAuthKeys(accountId).length, 2); // Total still 2
        assertEq(registry.nonces(accountId), 3);
    }

    function test_revoke_owner_direct_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertTrue(registry.authKeyRevoked(authKeyId), "owner direct revoke should revoke key");
        assertEq(registry.nonces(accountId), 2, "owner direct revoke should increment nonce");
    }

    function test_revoke_alreadyRevoked_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Revoke it
        bytes memory revokeSig1 = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        registry.revoke(accountId, PK1X, expiry, revokeSig1);

        // Try to revoke again
        bytes memory revokeSig2 = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        vm.expectRevert(IAuthRegistry.AuthKeyAlreadyRevoked.selector);
        registry.revoke(accountId, PK1X, expiry, revokeSig2);
    }

    function test_revoke_authKeyNotFound_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register one auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke non-existent auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, 999, expiry, 1);
        vm.expectRevert(IAuthRegistry.AuthKeyNotFound.selector);
        registry.revoke(accountId, 999, expiry, revokeSig);
    }

    function test_rotate_revokedAuthKey_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register and revoke auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        // Try to rotate revoked auth key
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 666, 777, expiry, 2);
        vm.expectRevert(IAuthRegistry.AuthKeyAlreadyRevoked.selector);
        registry.rotate(accountId, PK1X, 666, 777, expiry, rotSig);
    }

    function test_revoke_notAuthorized_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        address notAuthorized = address(0xDEAD);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke as notAuthorized
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.revoke(accountId, PK1X, expiry, revokeSig);
    }

    function test_revoke_notAuthorized_beforeNotRegistered_reverts() public {
        uint256 privateKey = 0x1234;
        address notAuthorized = address(0xDEAD);
        uint256 accountId = 111;

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, 0, 0);
        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.revoke(accountId, PK1X, 0, revokeSig);
    }

    function test_revoke_invalidSignature_reverts() public {
        uint256 privateKey = 0x1234;
        uint256 wrongPrivateKey = 0x5678;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke with wrong signature
        bytes memory revokeSig = _signRevoke(wrongPrivateKey, accountId, PK1X, expiry, 1);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.revoke(accountId, PK1X, expiry, revokeSig);
    }

    function test_revoke_expiredSignature_reverts() public {
        // Warp to a larger timestamp so block.timestamp - 1 is non-zero
        vm.warp(1000);

        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);

        // Register auth key
        uint64 regExpiry = uint64(block.timestamp + 1 hours);
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, regExpiry, 0);
        registry.register(salt, PK1X, PK1Y, regExpiry, signer, regSig);

        // Try to revoke with expired signature
        uint64 revokeExpiry = uint64(block.timestamp - 1); // 999 < 1000
        uint256 nonce = registry.nonces(accountId); // Should be 1
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, revokeExpiry, nonce);
        vm.expectRevert(IAuthRegistry.SignatureExpired.selector);
        registry.revoke(accountId, PK1X, revokeExpiry, revokeSig);
    }

    function test_revoke_updatesAuthTreeRoot() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        uint256 rootBeforeRevoke = registry.authTreeRoot(0);

        // Revoke
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        // Verify the only leaf was replaced by the canonical zero leaf.
        assertNotEq(registry.authTreeRoot(0), rootBeforeRevoke, "Root should change after revoke");
        assertEq(registry.authTreeRoot(0), LibAuthZeroHashes.get()[20]);
    }

    function test_revoke_allowedRelay_success() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        // Register auth key (using relay)
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertFalse(registry.authKeyRevoked(authKeyId));

        // Revoke using relay
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);

        vm.prank(relay);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        assertTrue(registry.authKeyRevoked(authKeyId));
    }

    function test_revoke_disabledRelay_reverts() public {
        address relay = address(0xBEEF);
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Enable relay
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Disable relay
        vm.prank(operator);
        registry.setAllowedRelays(relays, false);

        // Try to revoke with disabled relay
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(relay);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.revoke(accountId, PK1X, expiry, revokeSig);
    }

    function test_revoke_notRegistered_reverts() public {
        uint256 privateKey = 0x1234;
        uint256 accountId = 111;

        // Try to revoke without any registration (ownerOf[accountId] == address(0))
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, 0, 0);
        vm.expectRevert(IAuthRegistry.NotRegistered.selector);
        registry.revoke(accountId, PK1X, 0, revokeSig);
    }

    function test_revoke_allAuthKeys_allRevoked() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register two auth keys
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        assertFalse(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke first auth key
        bytes memory revokeSig1 = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        registry.revoke(accountId, PK1X, expiry, revokeSig1);
        assertTrue(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke second auth key
        bytes memory revokeSig2 = _signRevoke(privateKey, accountId, PK2X, expiry, 3);
        registry.revoke(accountId, PK2X, expiry, revokeSig2);

        // Verify all auth keys are revoked
        assertTrue(registry.authKeyRevoked(authKeyId1));
        assertTrue(registry.authKeyRevoked(authKeyId2));
        // Total count should still be 2
        assertEq(registry.getAuthKeys(accountId).length, 2);
    }

    // ============ Rotate Same AuthPkX Tests ============

    function test_rotate_sameAuthPkX_extendsExpiry() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint256 authPkX = PK1X;
        uint256 authPkY = PK1Y;
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register
        bytes memory regSig = _signRegister(privateKey, accountId, authPkX, authPkY, expiry, 0);
        registry.register(salt, authPkX, authPkY, expiry, signer, regSig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, authPkX);
        uint16 originalTree = registry.authKeyTreeOf(authKeyId);
        uint32 originalIndex = registry.authKeyIndexOf(authKeyId);
        uint256 rootAfterRegister = registry.authTreeRoot(0);

        // Rotate with same authPkX but new expiry
        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        uint256 newAuthPkY = PK1Y_ALT; // Can change Y without changing authKeyId
        bytes memory rotSig = _signRotate(privateKey, accountId, authPkX, authPkX, newAuthPkY, newExpiry, 1);

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.AuthKeyRotated(
            accountId, authKeyId, originalTree, authPkX, newAuthPkY, originalIndex, newExpiry
        );
        registry.rotate(accountId, authPkX, authPkX, newAuthPkY, newExpiry, rotSig);

        // Verify authKeyId unchanged (same tree/index)
        assertEq(registry.authKeyTreeOf(authKeyId), originalTree);
        assertEq(registry.authKeyIndexOf(authKeyId), originalIndex);
        // Root should change (new leaf with updated expiry/authPkY)
        assertNotEq(registry.authTreeRoot(0), rootAfterRegister);
        // Auth key count should remain 1
        assertEq(registry.getAuthKeys(accountId).length, 1);
        // Nonce should increment
        assertEq(registry.nonces(accountId), 2);
    }

    // ============ Multi-Device View Functions Tests ============

    function test_getAuthKeys_returnsAllAuthKeys() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register multiple auth keys using distinct valid curve points
        uint256[5] memory pkXs = [PK1X, PK2X, PK3X, PK4X, PK5X];
        uint256[5] memory pkYs = [PK1Y, PK2Y, PK3Y, PK4Y, PK5Y];

        for (uint256 i = 0; i < 5; i++) {
            uint256 nonce = registry.nonces(accountId);
            bytes memory sig = _signRegister(privateKey, accountId, pkXs[i], pkYs[i], expiry, nonce);
            registry.register(salt, pkXs[i], pkYs[i], expiry, signer, sig);
        }

        bytes32[] memory authKeys = registry.getAuthKeys(accountId);
        assertEq(authKeys.length, 5);

        // Verify each auth key ID
        for (uint256 i = 0; i < 5; i++) {
            bytes32 expectedAuthKeyId = registry.computeAuthKeyId(accountId, pkXs[i]);
            assertEq(authKeys[i], expectedAuthKeyId);
        }
    }

    function test_computeAuthKeyId_deterministic() public view {
        bytes32 id1 = registry.computeAuthKeyId(111, 222);
        bytes32 id2 = registry.computeAuthKeyId(111, 222);
        assertEq(id1, id2, "Same inputs should produce same authKeyId");

        bytes32 id3 = registry.computeAuthKeyId(111, 333);
        assertNotEq(id1, id3, "Different authPkX should produce different authKeyId");
    }

    // ============ On-Curve Validation Tests ============

    function test_register_offCurvePoint_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // (1, 2) is not on the BabyJubJub curve
        bytes memory sig = _signRegister(privateKey, accountId, 1, 2, expiry, 0);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.register(salt, 1, 2, expiry, signer, sig);
    }

    function test_register_identityPoint_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // (0, 1) is the Edwards identity and a low-order point (8*P == identity).
        bytes memory sig = _signRegister(privateKey, accountId, 0, 1, expiry, 0);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.register(salt, 0, 1, expiry, signer, sig);
    }

    function test_register_torsionPoint_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // (0, -1) is on-curve but has order 2, so 8*P == identity.
        uint256 prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 yMinus1 = prime - 1;

        bytes memory sig = _signRegister(privateKey, accountId, 0, yMinus1, expiry, 0);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.register(salt, 0, yMinus1, expiry, signer, sig);
    }

    function test_register_coordinateExceedsPrime_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // x >= BabyJubJub PRIME
        uint256 bigX = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // PRIME
        bytes memory sig = _signRegister(privateKey, accountId, bigX, PK1Y, expiry, 0);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.register(salt, bigX, PK1Y, expiry, signer, sig);
    }

    function test_rotate_offCurveNewKey_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register a valid key first
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate to an off-curve point
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 1, 2, expiry, 1);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.rotate(accountId, PK1X, 1, 2, expiry, rotSig);
    }

    function test_rotate_toIdentityPoint_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register a valid key first
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        uint256 rotateNonce = registry.nonces(accountId);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 0, 1, newExpiry, rotateNonce);
        vm.expectRevert(IAuthRegistry.InvalidAuthPublicKey.selector);
        registry.rotate(accountId, PK1X, 0, 1, newExpiry, rotSig);
    }

    function test_getAuthKeyInfo_returnsAllInfo() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Unregistered authKeyId should return zeros
        bytes32 unregisteredId = registry.computeAuthKeyId(accountId, 999);
        (uint16 tree1, uint32 index1, bool revoked1, bool exists1, uint256 leaf1) =
            registry.getAuthKeyInfo(unregisteredId);
        assertEq(tree1, 0);
        assertEq(index1, 0);
        assertFalse(revoked1);
        assertFalse(exists1);
        assertEq(leaf1, 0);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        (uint16 tree2, uint32 index2, bool revoked2, bool exists2, uint256 leaf2) = registry.getAuthKeyInfo(authKeyId);
        assertEq(tree2, 0);
        assertEq(index2, 0);
        assertFalse(revoked2);
        assertTrue(exists2);
        assertTrue(leaf2 != 0);

        // Register second auth key
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        (uint16 tree3, uint32 index3, bool revoked3,,) = registry.getAuthKeyInfo(authKeyId2);
        assertEq(tree3, 0);
        assertEq(index3, 1); // Second registration
        assertFalse(revoked3);

        // Revoke first auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        (uint16 tree4, uint32 index4, bool revoked4, bool exists4, uint256 leaf4) = registry.getAuthKeyInfo(authKeyId);
        assertEq(tree4, 0);
        assertEq(index4, 0);
        assertTrue(revoked4); // Now revoked
        assertTrue(exists4);
        assertEq(leaf4, 0);
    }

    // ============ Unlimited Tree Rollover Tests ============

    function test_register_revertWhen_registryFull() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Set currentAuthTreeNumber to MAX_AUTH_TREE_NUMBER (32767)
        bytes32 currentTreeSlot = bytes32(uint256(0));
        vm.store(address(registry), currentTreeSlot, bytes32(uint256(32767)));
        assertEq(registry.currentAuthTreeNumber(), 32767);

        // Set _authTreeState[32767].leafCount = 2^20 (full)
        bytes32 treeStateBase = keccak256(abi.encode(uint256(32767), uint256(1)));
        vm.store(address(registry), treeStateBase, bytes32(uint256(12345)));
        vm.store(address(registry), bytes32(uint256(treeStateBase) + 1), _packAuthTreeStateTail(0, uint32(1 << 20)));

        // Register should revert with RegistryFull since no more trees can be created
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.expectRevert(IAuthRegistry.RegistryFull.selector);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    function test_register_rolloverBeyondTree15() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Use vm.store to simulate tree 15 being full (2^20 leaves).
        // currentAuthTreeNumber is the first state variable (slot 0 after OZ ERC-7201 namespaced storage).
        bytes32 currentTreeSlot = bytes32(uint256(0));
        vm.store(address(registry), currentTreeSlot, bytes32(uint256(15)));
        assertEq(registry.currentAuthTreeNumber(), 15, "currentAuthTreeNumber should be 15");

        // Set _authTreeState[15].leafCount = 2^20 (full).
        // _authTreeState mapping is at slot 1. AuthTreeState: root (slot+0), cursor/leafCount (slot+1).
        bytes32 treeStateBase = keccak256(abi.encode(uint256(15), uint256(1)));
        // Set root to non-zero (simulating an initialized tree)
        vm.store(address(registry), treeStateBase, bytes32(uint256(12345)));
        vm.store(address(registry), bytes32(uint256(treeStateBase) + 1), _packAuthTreeStateTail(0, uint32(1 << 20)));

        // Register: should trigger rollover to tree 16 (previously reverted with MaxAuthTreesReached)
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        assertEq(registry.currentAuthTreeNumber(), 16, "Should have rolled over to tree 16");

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertEq(registry.authKeyTreeOf(authKeyId), 16, "Auth key should be in tree 16");

        uint256[] memory roots = registry.getAllAuthTreeRoots();
        assertEq(roots.length, 17, "Should return 17 trees (0-16)");
        assertGt(roots[16], 0, "Tree 16 root should be non-zero");
    }

    /// @dev Registers PK1X under a fresh account derived from `privateKey` so each call adds a
    ///      distinct leaf and advances the active tree root by one update.
    function _registerFreshAccount(uint256 privateKey) internal {
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        uint256 nonce = registry.nonces(accountId);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, nonce);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
    }

    function _forceRolloverAfterNextRegister() internal {
        bytes32 treeStateBase = keccak256(abi.encode(uint256(0), uint256(1)));
        vm.store(address(registry), bytes32(uint256(treeStateBase) + 1), _packAuthTreeStateTail(0, uint32(1 << 20)));

        _registerFreshAccount(0xC3);
        assertEq(registry.currentAuthTreeNumber(), 1, "should have rolled over to tree 1");
    }

    function test_auth_root_anchors_initialized() public view {
        // Arrange
        uint256 zeroRoot = registry.authTreeRoot(0);

        // Act
        uint64 supersededBlock = registry.authTreeRootAnchors(0, zeroRoot);

        // Assert
        assertEq(supersededBlock, 0, "current root should not write an anchor");
    }

    function test_auth_root_anchors_update_on_register() public {
        // Arrange
        uint256 previousRoot = registry.authTreeRoot(0);
        uint64 updateBlock = uint64(block.number + 7);

        // Act
        vm.roll(updateBlock);
        _registerFreshAccount(0xA0);
        uint256 currentRoot = registry.authTreeRoot(0);
        uint64 oldSupersededBlock = registry.authTreeRootAnchors(0, previousRoot);
        uint64 newSupersededBlock = registry.authTreeRootAnchors(0, currentRoot);

        // Assert
        assertEq(oldSupersededBlock, updateBlock, "previous anchor should be superseded at update block");
        assertEq(newSupersededBlock, 0, "current root should not write an anchor");
    }

    function test_auth_root_anchors_seed_new_tree_on_rollover() public {
        // Arrange
        uint64 rolloverBlock = uint64(block.number + 3);
        uint256 zeroRoot = registry.authTreeRoot(0);
        address signer = vm.addr(0xC3);
        uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
        uint256 leaf = registry.computeLeaf(accountId, PK1X, PK1Y, uint64(block.timestamp + 1 hours));
        uint256 expectedRoot = _manualSingleLeafRoot(leaf);

        // Act
        vm.roll(rolloverBlock);
        _forceRolloverAfterNextRegister();
        uint256 newTreeRoot = registry.authTreeRoot(1);
        uint64 zeroSupersededBlock = registry.authTreeRootAnchors(1, zeroRoot);
        uint64 currentSupersededBlock = registry.authTreeRootAnchors(1, newTreeRoot);

        // Assert
        assertEq(newTreeRoot, expectedRoot, "first leaf after rollover should match manual root");
        assertEq(zeroSupersededBlock, rolloverBlock, "zero-root anchor should be superseded by first leaf");
        assertEq(currentSupersededBlock, 0, "new tree first leaf root should not write an anchor");
    }

    function test_auth_root_anchors_same_leaf_does_not_update_root() public {
        // Arrange
        uint256 privateKey = 0xA3;
        address signer = vm.addr(privateKey);
        uint256 accountId = registry.computeAccountId(signer, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, regSig);
        uint256 rootBefore = registry.authTreeRoot(0);
        uint64 rootSupersededBefore = registry.authTreeRootAnchors(0, rootBefore);

        // Act
        vm.recordLogs();
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK1X, PK1Y, expiry, registry.nonces(accountId));
        registry.rotate(accountId, PK1X, PK1X, PK1Y, expiry, rotSig);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Assert
        assertEq(registry.authTreeRoot(0), rootBefore, "same leaf should keep root");
        assertEq(
            registry.authTreeRootAnchors(0, rootBefore), rootSupersededBefore, "same leaf should not update anchor"
        );
        bytes32 rootUpdatedTopic = keccak256("RootUpdated(uint256,uint256)");
        for (uint256 i = 0; i < logs.length; ++i) {
            assertFalse(logs[i].topics[0] == rootUpdatedTopic, "same leaf should not emit RootUpdated");
        }
    }

    function test_isCurrentAuthTreeRoot_zero_root_returns_false() public view {
        // Arrange / Act / Assert
        assertFalse(registry.isCurrentAuthTreeRoot(0, 0));
    }

    function test_isCurrentAuthTreeRoot_current_root() public {
        // Arrange / Act / Assert
        assertTrue(registry.isCurrentAuthTreeRoot(0, registry.authTreeRoot(0)));

        // Act
        _registerFreshAccount(0x1234);

        // Assert
        assertTrue(registry.isCurrentAuthTreeRoot(0, registry.authTreeRoot(0)));
    }

    function test_isRecentAuthTreeRoot_zero_staleness_matches_current_only() public {
        // Arrange
        _registerFreshAccount(0xA1);
        uint256 oldRoot = registry.authTreeRoot(0);
        _registerFreshAccount(0xA2);
        uint256 currentRoot = registry.authTreeRoot(0);

        // Act / Assert
        assertFalse(registry.isRecentAuthTreeRoot(0, oldRoot, 0), "old root should fail current-only validation");
        assertTrue(registry.isRecentAuthTreeRoot(0, currentRoot, 0), "current root should pass current-only validation");
    }

    function test_isRecentAuthTreeRoot_staleness_boundaries() public {
        // Arrange
        _registerFreshAccount(0xA4);
        uint256 oldRoot = registry.authTreeRoot(0);
        vm.roll(block.number + 10);
        _registerFreshAccount(0xA5);

        // Act / Assert
        assertTrue(registry.isRecentAuthTreeRoot(0, oldRoot, 4), "same block superseded root is valid in window");
        vm.roll(block.number + 4);
        assertTrue(registry.isRecentAuthTreeRoot(0, oldRoot, 4), "root should be valid at exact staleness bound");
        vm.roll(block.number + 1);
        assertFalse(registry.isRecentAuthTreeRoot(0, oldRoot, 4), "root should expire after staleness bound");
    }

    function test_areRecentAuthTreeRoots_empty_returns_true() public view {
        // Arrange
        TreeRootPair[] memory roots = new TreeRootPair[](0);

        // Act / Assert
        assertTrue(registry.areRecentAuthTreeRoots(roots, 0), "empty batch should pass aggregate check");
    }

    function test_areRecentAuthTreeRoots_all_recent_returns_true() public {
        // Arrange
        _registerFreshAccount(0xA40);
        uint256 oldRoot = registry.authTreeRoot(0);
        _registerFreshAccount(0xA41);
        uint256 currentRoot = registry.authTreeRoot(0);
        TreeRootPair[] memory roots = new TreeRootPair[](2);
        roots[0] = TreeRootPair({treeNumber: 0, root: oldRoot});
        roots[1] = TreeRootPair({treeNumber: 0, root: currentRoot});

        // Act / Assert
        assertTrue(registry.areRecentAuthTreeRoots(roots, type(uint64).max), "all recent roots should pass");
    }

    function test_areRecentAuthTreeRoots_unknown_or_zero_returns_false() public view {
        // Arrange
        TreeRootPair[] memory unknownRoots = new TreeRootPair[](1);
        unknownRoots[0] = TreeRootPair({treeNumber: 0, root: uint256(keccak256("unknown-auth-root"))});
        TreeRootPair[] memory zeroRoots = new TreeRootPair[](1);
        zeroRoots[0] = TreeRootPair({treeNumber: 0, root: 0});

        // Act / Assert
        assertFalse(registry.areRecentAuthTreeRoots(unknownRoots, type(uint64).max), "unknown root should fail");
        assertFalse(registry.areRecentAuthTreeRoots(zeroRoots, type(uint64).max), "zero root should fail");
    }

    function test_areRecentAuthTreeRoots_expired_root_returns_false() public {
        // Arrange
        _registerFreshAccount(0xA42);
        uint256 oldRoot = registry.authTreeRoot(0);
        vm.roll(block.number + 10);
        _registerFreshAccount(0xA43);
        TreeRootPair[] memory roots = new TreeRootPair[](1);
        roots[0] = TreeRootPair({treeNumber: 0, root: oldRoot});

        // Act / Assert
        assertTrue(registry.areRecentAuthTreeRoots(roots, 4), "root should be valid in window");
        vm.roll(block.number + 5);
        assertFalse(registry.areRecentAuthTreeRoots(roots, 4), "expired root should fail aggregate check");
    }

    function test_isRecentAuthTreeRoot_tracks_superseded_root_by_anchor() public {
        // Arrange
        _registerFreshAccount(0xB0);
        uint256 supersededRoot = registry.authTreeRoot(0);
        assertTrue(registry.isRecentAuthTreeRoot(0, supersededRoot, type(uint64).max), "root should start as recent");

        // Act
        for (uint256 i = 0; i < 64; ++i) {
            _registerFreshAccount(0x1000 + i);
        }

        // Assert
        assertTrue(
            registry.isRecentAuthTreeRoot(0, supersededRoot, type(uint64).max),
            "root-keyed anchor should remain recent independent of update count"
        );
        assertTrue(registry.isRecentAuthTreeRoot(0, registry.authTreeRoot(0), 0), "current root should remain accepted");
    }

    function test_hydrateAuthRootAnchorsFromRoots_seeds_snapshot_root_not_in_history() public {
        // Arrange
        _markAsLegacyInitialized();
        uint256 snapshotRoot = uint256(keccak256("snapshot-root-not-in-history"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});
        uint64 migrationBlock = uint64(block.number + 9);

        assertFalse(
            registry.isRecentAuthTreeRoot(0, snapshotRoot, type(uint64).max),
            "snapshot root should not be recent before migration"
        );

        // Act
        vm.roll(migrationBlock);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
        uint64 snapshotSuperseded = registry.authTreeRootAnchors(0, snapshotRoot);

        // Assert
        assertEq(snapshotSuperseded, migrationBlock, "snapshot superseded should be migration block");
        assertTrue(registry.isRecentAuthTreeRoot(0, snapshotRoot, 300), "hydrated snapshot root should be recent");
    }

    function test_hydrateAuthRootAnchorsFromRoots_seeds_current_roots_without_snapshot_input() public {
        // Arrange
        _markAsLegacyInitialized();
        _registerFreshAccount(0xA8);
        uint256 currentRoot = registry.authTreeRoot(0);
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](0);
        uint64 migrationBlock = uint64(block.number + 4);

        // Act
        vm.roll(migrationBlock);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
        uint64 currentSuperseded = registry.authTreeRootAnchors(0, currentRoot);

        // Assert
        assertEq(currentSuperseded, 0, "current root should not write an anchor");
        assertTrue(registry.isRecentAuthTreeRoot(0, currentRoot, 0), "current root should be recent with zero window");
    }

    function test_hydrateAuthRootAnchorsFromRoots_current_snapshot_root_has_zero_superseded() public {
        // Arrange
        _markAsLegacyInitialized();
        _registerFreshAccount(0xA9);
        uint256 currentRoot = registry.authTreeRoot(0);
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: currentRoot});
        uint64 migrationBlock = uint64(block.number + 5);

        // Act
        vm.roll(migrationBlock);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
        uint64 currentSuperseded = registry.authTreeRootAnchors(0, currentRoot);

        // Assert
        assertEq(currentSuperseded, 0, "current snapshot root should not write an anchor");
    }

    function test_hydrateAuthRootAnchorsFromRoots_stale_root_expires_after_window() public {
        // Arrange
        _markAsLegacyInitialized();
        uint256 snapshotRoot = uint256(keccak256("snapshot-root-expires"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});
        uint64 migrationBlock = uint64(block.number + 6);

        // Act
        vm.roll(migrationBlock);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);

        // Assert
        assertTrue(registry.isRecentAuthTreeRoot(0, snapshotRoot, 3), "snapshot root should be valid in window");
        vm.roll(migrationBlock + 4);
        assertFalse(registry.isRecentAuthTreeRoot(0, snapshotRoot, 3), "snapshot root should expire after window");
    }

    function test_hydrateAuthRootAnchorsFromRoots_reverts_invalid_tree() public {
        // Arrange
        _markAsLegacyInitialized();
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: registry.currentAuthTreeNumber() + 1, root: 123});

        // Act / Assert
        vm.expectRevert(IAuthRegistry.InvalidAuthTreeNumber.selector);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
    }

    function test_hydrateAuthRootAnchorsFromRoots_reverts_zero_root() public {
        // Arrange
        _markAsLegacyInitialized();
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: 0});

        // Act / Assert
        vm.expectRevert(IAuthRegistry.InvalidSnapshotRoot.selector);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
    }

    function test_hydrateAuthRootAnchorsFromRoots_reverts_non_owner() public {
        // Arrange
        _markAsLegacyInitialized();
        uint256 snapshotRoot = uint256(keccak256("non-owner-snapshot-root"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});

        // Act / Assert
        vm.prank(makeAddr("not-owner"));
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);

        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
        uint64 hydratedSuperseded = registry.authTreeRootAnchors(0, snapshotRoot);
        assertEq(hydratedSuperseded, uint64(block.number), "reverted non-owner call should not consume initializer");
    }

    function test_hydrateAuthRootAnchorsFromRoots_allows_owner_once() public {
        // Arrange
        _markAsLegacyInitialized();
        uint256 snapshotRoot = uint256(keccak256("owner-snapshot-root"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});

        // Act
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);

        // Assert
        uint64 hydratedSuperseded = registry.authTreeRootAnchors(0, snapshotRoot);
        assertEq(hydratedSuperseded, uint64(block.number), "owner should hydrate anchors");

        vm.expectRevert();
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
    }

    function test_hydrateAuthRootAnchorsFromRoots_setAllowedRelaysDoesNotCloseLegacyWindow() public {
        // Arrange
        _markAsLegacyInitialized();
        uint256 snapshotRoot = uint256(keccak256("relay-update-before-hydrate"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});
        address[] memory relays = new address[](1);
        relays[0] = makeAddr("new-relay");

        // Act
        vm.prank(operator);
        registry.setAllowedRelays(relays, true);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);

        // Assert
        assertEq(registry.authTreeRootAnchors(0, snapshotRoot), uint64(block.number));
    }

    function test_hydrateAuthRootAnchorsFromRoots_reverts_after_fresh_initialize() public {
        // Arrange
        uint256 snapshotRoot = uint256(keccak256("fresh-deploy-snapshot-root"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});

        // Act / Assert
        vm.expectRevert(IAuthRegistry.AuthRootAnchorsAlreadyInitialized.selector);
        registry.hydrateAuthRootAnchorsFromRoots(snapshotRoots);
    }

    function test_initialize_reverts_after_legacy_v1_initialization() public {
        // Arrange
        _markAsLegacyInitialized();
        address attacker = makeAddr("attacker");

        // Act / Assert
        vm.prank(attacker);
        vm.expectRevert();
        registry.initialize(attacker);
        assertEq(registry.owner(), owner, "owner should not change");
    }

    function test_isRecentAuthTreeRoot_finalizedTreeRecentRoot() public {
        uint256 privateKey = 0xC1;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        uint256 rootBeforeOldTreeUpdate = registry.authTreeRoot(0);
        _forceRolloverAfterNextRegister();

        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        bytes memory rotSig =
            _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, newExpiry, registry.nonces(accountId));
        registry.rotate(accountId, PK1X, PK2X, PK2Y, newExpiry, rotSig);

        assertTrue(
            registry.isRecentAuthTreeRoot(0, rootBeforeOldTreeUpdate, type(uint64).max),
            "recent pre-rotate root of finalized tree should remain recent"
        );
        assertTrue(
            registry.isRecentAuthTreeRoot(0, registry.authTreeRoot(0), 0), "current finalized tree root is recent"
        );
    }

    function test_isRecentAuthTreeRoot_finalizedTreeRootExpiresByBlockWindow() public {
        uint256 privateKey = 0xC2;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        uint256 staleRoot = registry.authTreeRoot(0);
        _forceRolloverAfterNextRegister();
        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        bytes memory rotSig =
            _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, newExpiry, registry.nonces(accountId));
        registry.rotate(accountId, PK1X, PK2X, PK2Y, newExpiry, rotSig);

        vm.roll(block.number + 10);

        assertFalse(
            registry.isRecentAuthTreeRoot(0, staleRoot, 9), "old finalized tree root should expire by block window"
        );
        assertTrue(
            registry.isRecentAuthTreeRoot(0, registry.authTreeRoot(0), 0), "current finalized tree root is recent"
        );
    }
}
