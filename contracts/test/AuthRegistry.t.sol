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
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {EcdsaSig} from "src/interfaces/IStructs.sol";
import {MockERC7739Account} from "test/mocks/MockERC7739Account.sol";

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

/// @notice Unit tests for AuthRegistry multi-tree support with nonce-based signatures
contract AuthRegistryTest is Test {
    AuthRegistry registry;
    address owner = address(this);
    address proxyAdmin = address(0xAD); // Separate proxy admin to avoid TransparentProxy routing issue
    address operator = makeAddr("operator");

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

    function setUp() public {
        AuthRegistry impl = new AuthRegistry(20);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(AuthRegistry.initialize, (owner))
        );
        registry = AuthRegistry(address(proxy));

        // Set operator
        registry.setOperator(operator);
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(registry)));
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
        assertEq(registry.AUTH_ROOT_HISTORY_SIZE(), 64, "AUTH_ROOT_HISTORY_SIZE should be 64");
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

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.Registered(accountId, signer, 0, authPkX, authPkY, expiry);

        vm.prank(signer);
        registry.register(salt, authPkX, authPkY, expiry, signer, sig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, authPkX);
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

        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, _legacySig(sig));

        assertEq(registry.ownerOf(accountId), signer, "Owner should be signer");
        assertEq(registry.nonces(accountId), 1, "Nonce should be incremented");
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
            vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        // Try to register same authPkX again (different authPkY doesn't matter - authKeyId is based on authPkX)
        bytes memory sig2 = _signRegister(privateKey, accountId, PK1X, PK1Y_ALT, expiry, 1);
        vm.prank(signer);
        vm.expectRevert(IAuthRegistry.AlreadyRegistered.selector);
        registry.register(salt, PK1X, PK1Y_ALT, expiry, signer, sig2);
    }

    function test_register_multipleAuthKeys_sameAccount() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register first auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.getAuthKeys(accountId).length, 1);

        // Register second auth key (different authPkX) - should succeed
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.getAuthKeys(accountId).length, 2);
        assertEq(registry.nonces(accountId), 2);

        // Verify both auth keys exist
        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
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
        vm.prank(signer1);
        registry.register(salt, PK1X, PK1Y, expiry, signer1, sig1);

        // A different owner derives a different accountId for the same salt, so the signature
        // over signer1's accountId becomes invalid for signer2's registration attempt.
        bytes memory sig2 = _signRegister(privateKey2, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer2);
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

        vm.prank(wrongSigner);
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

        vm.prank(signer);
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

        vm.prank(signer);
        vm.expectRevert(IAuthRegistry.InvalidSignature.selector);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);
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
        vm.prank(signer);
        registry.register(salt, authPkX, authPkY, expiry, signer, regSig);

        uint256 rootAfterRegister = registry.authTreeRoot(0);

        // Now rotate
        uint256 newAuthPkX = PK2X;
        uint256 newAuthPkY = PK2Y;
        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        uint256 rotateNonce = registry.nonces(accountId); // Should be 1
        bytes memory rotSig =
            _signRotate(privateKey, accountId, authPkX, newAuthPkX, newAuthPkY, newExpiry, rotateNonce);

        vm.prank(signer);
        registry.rotate(accountId, authPkX, newAuthPkX, newAuthPkY, newExpiry, rotSig);

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
        // Root should change
        assertNotEq(registry.authTreeRoot(0), rootAfterRegister);
        // Nonce should increment
        assertEq(registry.nonces(accountId), 2);
    }

    function test_rotateAndRevoke_legacyEcdsaSigTuple_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);

        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        bytes memory regSig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, _legacySig(regSig));

        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, _legacySig(rotSig));
        assertEq(registry.nonces(accountId), 2, "Nonce should increment after rotate");

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK2X, expiry, 2);
        vm.prank(signer);
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

        vm.prank(relay);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate non-existent auth key
        bytes memory rotSig = _signRotate(privateKey, accountId, 999, 666, 777, expiry, 1);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        // Try to rotate auth key 222 → 444 (444 already exists)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 2);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate with wrongPrivateKey (but calling as correct owner)
        bytes memory rotSig = _signRotate(wrongPrivateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);

        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate with expired signature
        uint64 expiredExpiry = uint64(block.timestamp - 1); // 999 < 1000
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiredExpiry, 1);

        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Rotate once
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig);

        // Try to replay the same signature (nonce is now 2, but sig was for nonce 1)
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        // Sign rotate for key 222 → 666 (oldAuthPkX = 222)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 666, 777, expiry, 2);

        // Try to use same signature to rotate key 444 → 666 (oldAuthPkX = 444)
        // This should fail because the signature binds oldAuthPkX = 222
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        uint256[] memory roots = registry.getAllAuthTreeRoots();
        assertEq(roots.length, 1, "Should still return 1 tree");
        assertNotEq(roots[0], rootBefore, "Root should change after register");
        assertEq(roots[0], registry.authTreeRoot(0));
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

        vm.prank(signer);
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
        vm.prank(signer);
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
            vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);
        assertEq(registry.nonces(accountId), 1);

        // Rotate increments nonce
        bytes memory rotSig1 = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, expiry, rotSig1);
        assertEq(registry.nonces(accountId), 2);

        // Another rotate increments nonce again
        bytes memory rotSig2 = _signRotate(privateKey, accountId, PK2X, PK3X, PK3Y, expiry, 2);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);
        assertEq(registry.nonces(accountId), 1);

        // Register second auth key (nonce 1)
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);
        assertEq(registry.nonces(accountId), 2);

        // Rotate first auth key (nonce 2)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK3X, PK3Y, expiry, 2);
        vm.prank(signer);
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
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate as notAuthorized (not owner and not relay)
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, PK2X, PK2Y, expiry, 1);
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

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.Registered(accountId, signer, 0, authPkX, authPkY, expiry);

        vm.prank(relay);
        registry.register(salt, authPkX, authPkY, expiry, signer, sig);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, authPkX);
        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.authKeyTreeOf(authKeyId), 0);
        assertEq(registry.authKeyIndexOf(authKeyId), 0);
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
        vm.prank(relay);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Now rotate (using relay)
        uint256 newAuthPkX = PK2X;
        uint256 newAuthPkY = PK2Y;
        uint256 rotateNonce = registry.nonces(accountId);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, newAuthPkX, newAuthPkY, expiry, rotateNonce);

        vm.prank(relay);
        registry.rotate(accountId, PK1X, newAuthPkX, newAuthPkY, expiry, rotSig);

        assertEq(registry.ownerOf(accountId), signer);
        assertEq(registry.nonces(accountId), 2);
    }

    function test_register_relay_invalidSignature_reverts() public {
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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
        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), registerSig);
        assertEq(registry.ownerOf(accountId), address(wallet));

        // Phase 2 — attacker replays the SAME 7739 register sig as a rotate.
        // The contract derives expectedContentsHash from the Rotate struct
        // hash (different typehash + different fields + nonce=1 now); it
        // won't match the captured Register-bound contentsHash, so the
        // fallback rejects.
        vm.prank(relay);
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

        vm.prank(relay);
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

        vm.prank(relay);
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
        vm.prank(relay);
        registry.register(salt, PK1X, PK1Y, expiry, address(wallet), registerSig);

        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        bytes memory rotateSig = hex"12710202";
        wallet.approveSignature(_rotateDigest(accountId, PK1X, PK2X, PK2Y, newExpiry, 1), rotateSig);
        vm.prank(relay);
        registry.rotate(accountId, PK1X, PK2X, PK2Y, newExpiry, rotateSig);

        bytes32 newAuthKeyId = registry.computeAuthKeyId(accountId, PK2X);
        assertEq(registry.authKeyIndexOf(newAuthKeyId), 0);
        assertEq(registry.nonces(accountId), 2);

        bytes memory revokeSig = hex"1271030303";
        wallet.approveSignature(_revokeDigest(accountId, PK2X, newExpiry, 2), revokeSig);
        vm.prank(relay);
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
        vm.prank(relay);
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

    // ============ Revoke Tests ============

    function test_revoke_success() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register two auth keys
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        assertFalse(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke first auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 2);

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.AuthKeyRevoked(accountId, authKeyId1, 0);

        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        assertTrue(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2)); // Second key still active
        assertEq(registry.getAuthKeys(accountId).length, 2); // Total still 2
        assertEq(registry.nonces(accountId), 3);
    }

    function test_revoke_alreadyRevoked_reverts() public {
        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 salt = DEFAULT_SALT;
        uint256 accountId = registry.computeAccountId(signer, salt);
        uint64 expiry = uint64(block.timestamp + 1 hours);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Revoke it
        bytes memory revokeSig1 = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig1);

        // Try to revoke again
        bytes memory revokeSig2 = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke non-existent auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, 999, expiry, 1);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        // Try to rotate revoked auth key
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 666, 777, expiry, 2);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke as notAuthorized
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(notAuthorized);
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.revoke(accountId, PK1X, expiry, revokeSig);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        // Try to revoke with wrong signature
        bytes memory revokeSig = _signRevoke(wrongPrivateKey, accountId, PK1X, expiry, 1);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, regExpiry, signer, regSig);

        // Try to revoke with expired signature
        uint64 revokeExpiry = uint64(block.timestamp - 1); // 999 < 1000
        uint256 nonce = registry.nonces(accountId); // Should be 1
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, revokeExpiry, nonce);

        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        uint256 rootBeforeRevoke = registry.authTreeRoot(0);

        // Revoke
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        // Verify root changed (leaf set to 0)
        assertNotEq(registry.authTreeRoot(0), rootBeforeRevoke, "Root should change after revoke");
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
        vm.prank(relay);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertFalse(registry.authKeyRevoked(authKeyId));

        // Revoke using relay
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 1);

        vm.expectEmit(true, true, true, true);
        emit IAuthRegistry.AuthKeyRevoked(accountId, authKeyId, 0);

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
        vm.prank(relay);
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
        address signer = vm.addr(privateKey);
        uint256 accountId = 111;

        // Try to revoke without any registration (ownerOf[accountId] == address(0))
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, 0, 0);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId1 = registry.computeAuthKeyId(accountId, PK1X);
        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        assertFalse(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke first auth key
        bytes memory revokeSig1 = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig1);
        assertTrue(registry.authKeyRevoked(authKeyId1));
        assertFalse(registry.authKeyRevoked(authKeyId2));

        // Revoke second auth key
        bytes memory revokeSig2 = _signRevoke(privateKey, accountId, PK2X, expiry, 3);
        vm.prank(signer);
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
        vm.prank(signer);
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
        emit IAuthRegistry.AuthKeyRotated(accountId, authKeyId, authPkX, newAuthPkY, originalIndex, newExpiry);

        vm.prank(signer);
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
            vm.prank(signer);
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
        vm.prank(signer);
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
        vm.prank(signer);
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
        vm.prank(signer);
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
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        // Try to rotate to an off-curve point
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 1, 2, expiry, 1);
        vm.prank(signer);
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
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, regSig);

        uint64 newExpiry = uint64(block.timestamp + 2 hours);
        uint256 rotateNonce = registry.nonces(accountId);
        bytes memory rotSig = _signRotate(privateKey, accountId, PK1X, 0, 1, newExpiry, rotateNonce);

        vm.prank(signer);
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
        (uint16 tree1, uint32 index1, bool revoked1) = registry.getAuthKeyInfo(unregisteredId);
        assertEq(tree1, 0);
        assertEq(index1, 0);
        assertFalse(revoked1);

        // Register auth key
        bytes memory sig1 = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig1);

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        (uint16 tree2, uint32 index2, bool revoked2) = registry.getAuthKeyInfo(authKeyId);
        assertEq(tree2, 0);
        assertEq(index2, 0);
        assertFalse(revoked2);

        // Register second auth key
        bytes memory sig2 = _signRegister(privateKey, accountId, PK2X, PK2Y, expiry, 1);
        vm.prank(signer);
        registry.register(salt, PK2X, PK2Y, expiry, signer, sig2);

        bytes32 authKeyId2 = registry.computeAuthKeyId(accountId, PK2X);
        (uint16 tree3, uint32 index3, bool revoked3) = registry.getAuthKeyInfo(authKeyId2);
        assertEq(tree3, 0);
        assertEq(index3, 1); // Second registration
        assertFalse(revoked3);

        // Revoke first auth key
        bytes memory revokeSig = _signRevoke(privateKey, accountId, PK1X, expiry, 2);
        vm.prank(signer);
        registry.revoke(accountId, PK1X, expiry, revokeSig);

        (uint16 tree4, uint32 index4, bool revoked4) = registry.getAuthKeyInfo(authKeyId);
        assertEq(tree4, 0);
        assertEq(index4, 0);
        assertTrue(revoked4); // Now revoked
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
        uint256 packedCursorLeafCount = uint256(1 << 20) << 64;
        vm.store(address(registry), bytes32(uint256(treeStateBase) + 1), bytes32(packedCursorLeafCount));

        // Register should revert with RegistryFull since no more trees can be created
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
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
        // _authTreeState mapping is at slot 1. AuthTreeState: root (slot+0), cursor|leafCount (slot+1).
        bytes32 treeStateBase = keccak256(abi.encode(uint256(15), uint256(1)));
        // Set root to non-zero (simulating an initialized tree)
        vm.store(address(registry), treeStateBase, bytes32(uint256(12345)));
        // Pack leafCount (uint32 at bits 64-95) with cursor=0 (uint64 at bits 0-63)
        uint256 packedCursorLeafCount = uint256(1 << 20) << 64;
        vm.store(address(registry), bytes32(uint256(treeStateBase) + 1), bytes32(packedCursorLeafCount));

        // Register: should trigger rollover to tree 16 (previously reverted with MaxAuthTreesReached)
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        registry.register(salt, PK1X, PK1Y, expiry, signer, sig);

        assertEq(registry.currentAuthTreeNumber(), 16, "Should have rolled over to tree 16");

        bytes32 authKeyId = registry.computeAuthKeyId(accountId, PK1X);
        assertEq(registry.authKeyTreeOf(authKeyId), 16, "Auth key should be in tree 16");

        uint256[] memory roots = registry.getAllAuthTreeRoots();
        assertEq(roots.length, 17, "Should return 17 trees (0-16)");
        assertGt(roots[16], 0, "Tree 16 root should be non-zero");
    }
}
