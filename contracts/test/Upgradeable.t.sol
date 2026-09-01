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
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";

import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {TreeRootPair} from "src/interfaces/IStructs.sol";
import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

// V2 contracts for upgrade testing
contract TokenRegistryV2 is TokenRegistry {
    uint256 public newVariable;

    function setNewVariable(uint256 val) external onlyOwner {
        newVariable = val;
    }

    function version() external pure returns (string memory) {
        return "v2";
    }
}

contract AuthRegistryV2 is AuthRegistry {
    uint256 public newVariable;

    constructor(uint8 authTreeDepth_) AuthRegistry(authTreeDepth_) {}

    function setNewVariable(uint256 val) external onlyOwner {
        newVariable = val;
    }

    function version() external pure returns (string memory) {
        return "v2";
    }
}

contract PrivacyBoostV2 is PrivacyBoost {
    uint256 public newVariable;

    constructor(
        address tokenRegistry_,
        address authRegistry_,
        uint32 maxBatchSize_,
        uint32 maxInputsPerTransfer_,
        uint32 maxOutputsPerTransfer_,
        uint32 maxFeeTokens_,
        uint256 cancelDelay_,
        uint256 forcedWithdrawalDelay_,
        uint32 maxForcedInputs_,
        uint64 maxEpochAuthStalenessBlocks_,
        uint64 maxForcedWithdrawalAuthStalenessBlocks_,
        uint8 merkleDepth_
    )
        PrivacyBoost(
            tokenRegistry_,
            authRegistry_,
            maxBatchSize_,
            maxInputsPerTransfer_,
            maxOutputsPerTransfer_,
            maxFeeTokens_,
            cancelDelay_,
            forcedWithdrawalDelay_,
            maxForcedInputs_,
            maxEpochAuthStalenessBlocks_,
            maxForcedWithdrawalAuthStalenessBlocks_,
            merkleDepth_
        )
    {}

    function setNewVariable(uint256 val) external onlyOwner {
        newVariable = val;
    }

    function version() external pure returns (string memory) {
        return "v2";
    }
}

/// @notice Tests for upgradeable contracts with TransparentProxy
contract UpgradeableTest is Test {
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    PrivacyBoost pool;
    MockVerifier verifier;
    MockERC20 token;

    TransparentUpgradeableProxy tokenRegistryProxy;
    TransparentUpgradeableProxy authRegistryProxy;
    TransparentUpgradeableProxy poolProxy;

    address owner = address(this);
    // IMPORTANT: proxyAdmin must be different from owner to avoid TransparentProxy routing issue
    // When admin calls proxy, call goes to ProxyAdmin, not implementation
    address proxyAdminOwner = makeAddr("proxyAdminOwner");
    address alice = makeAddr("alice");
    address operator = makeAddr("operator");
    address relay = makeAddr("relay");

    uint256 constant DEFAULT_SALT = 123;
    uint256 constant PK1X = 15836372343211832006828833031571087401945044377577570170285606102491215895900;
    uint256 constant PK1Y = 7801528930831391612913542953849263092120765287178679640990215688947513841260;
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("PB:AuthRegistry:vNext");
    bytes32 private constant VERSION_HASH = keccak256("1");
    bytes32 private constant REGISTER_TYPEHASH =
        keccak256("Register(uint256 accountId,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)");

    function _markAuthRegistryAsLegacyInitialized() internal {
        vm.store(address(authRegistryProxy), INITIALIZABLE_STORAGE, bytes32(uint256(1)));
        _openLegacyAnchorMigration();
    }

    function _openLegacyAnchorMigration() internal {
        vm.store(address(authRegistryProxy), bytes32(uint256(10)), bytes32(0));
    }

    function _authRegistryDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(authRegistry)));
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
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _authRegistryDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdminOwner, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
        tokenRegistryProxy = TransparentUpgradeableProxy(payable(address(tokenRegistry)));
        authRegistryProxy = TransparentUpgradeableProxy(payable(address(authRegistry)));
        poolProxy = TransparentUpgradeableProxy(payable(address(pool)));
        pool.setOperator(operator);
        token = new MockERC20();
    }

    // ============ TokenRegistry Tests ============

    function test_tokenRegistry_initializationSucceeds() public view {
        assertEq(tokenRegistry.owner(), owner);
        assertEq(tokenRegistry.nextId(), 0);
    }

    function test_tokenRegistry_reinitializationBlocked() public {
        vm.expectRevert();
        tokenRegistry.initialize(alice);
    }

    function test_tokenRegistry_statePreservedAfterUpgrade() public {
        // Register a token before upgrade
        uint16 tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        assertEq(tokenId, 1);

        (uint8 tokenType, address tokenAddress, uint256 tokenSubId) = tokenRegistry.tokenOf(tokenId);
        assertEq(tokenType, TOKEN_TYPE_ERC20);
        assertEq(tokenAddress, address(token));
        assertEq(tokenSubId, 0);

        // Deploy V2 implementation
        TokenRegistryV2 tokenRegistryV2Impl = new TokenRegistryV2();

        // Get ProxyAdmin address (it's deployed by the proxy, owner is the initial admin)
        // In OZ v5, ProxyAdmin is created automatically and owner becomes ProxyAdmin's owner
        // We need to call upgradeAndCall via the proxy admin
        address proxyAdmin = _getProxyAdmin(address(tokenRegistryProxy));

        // Upgrade via ProxyAdmin
        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(tokenRegistryProxy)), address(tokenRegistryV2Impl), "");

        // Verify state is preserved
        TokenRegistryV2 tokenRegistryV2 = TokenRegistryV2(address(tokenRegistryProxy));
        (uint8 tokenType2, address tokenAddress2, uint256 tokenSubId2) = tokenRegistryV2.tokenOf(tokenId);
        assertEq(tokenType2, TOKEN_TYPE_ERC20);
        assertEq(tokenAddress2, address(token));
        assertEq(tokenSubId2, 0);
        assertEq(tokenRegistryV2.nextId(), 1);

        // Verify new functionality works
        assertEq(tokenRegistryV2.version(), "v2");
        tokenRegistryV2.setNewVariable(42);
        assertEq(tokenRegistryV2.newVariable(), 42);
    }

    function test_tokenRegistry_upgradeOnlyByAdmin() public {
        TokenRegistryV2 tokenRegistryV2Impl = new TokenRegistryV2();
        address proxyAdmin = _getProxyAdmin(address(tokenRegistryProxy));

        // Non-admin cannot upgrade
        vm.prank(alice);
        vm.expectRevert();
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(tokenRegistryProxy)), address(tokenRegistryV2Impl), "");
    }

    // ============ AuthRegistry Tests ============

    function test_authRegistry_initializationSucceeds() public view {
        assertEq(authRegistry.owner(), owner);
        assertEq(authRegistry.currentAuthTreeNumber(), 0);
        assertGt(authRegistry.authTreeRoot(0), 0);
    }

    function test_authRegistry_reinitializationBlocked() public {
        vm.expectRevert();
        authRegistry.initialize(alice);
    }

    function test_authRegistry_statePreservedAfterUpgrade() public {
        // Arrange - populate storage slots whose ordering must remain stable across upgrades.
        authRegistry.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        authRegistry.setAllowedRelays(relays, true);

        uint256 privateKey = 0x1234;
        address signer = vm.addr(privateKey);
        uint256 accountId = authRegistry.computeAccountId(signer, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(relay);
        authRegistry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, sig);

        uint256 initialRoot = authRegistry.authTreeRoot(0);
        uint256 initialTreeNumber = authRegistry.currentAuthTreeNumber();
        uint256 authLeaf = authRegistry.computeLeaf(accountId, PK1X, PK1Y, expiry);
        bytes32 authKeyId = authRegistry.computeAuthKeyId(accountId, PK1X);

        // Act - upgrade via ProxyAdmin.
        // Deploy V2 implementation
        AuthRegistryV2 authRegistryV2Impl = new AuthRegistryV2(20);
        address proxyAdmin = _getProxyAdmin(address(authRegistryProxy));

        // Upgrade via ProxyAdmin
        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(authRegistryProxy)), address(authRegistryV2Impl), "");

        // Assert - verify state is preserved
        AuthRegistryV2 authRegistryV2 = AuthRegistryV2(address(authRegistryProxy));
        assertEq(authRegistryV2.authTreeRoot(0), initialRoot);
        assertEq(authRegistryV2.currentAuthTreeNumber(), initialTreeNumber);
        assertEq(authRegistryV2.owner(), owner);
        assertEq(authRegistryV2.ownerOf(accountId), signer);
        assertEq(authRegistryV2.nonces(accountId), 1);
        assertEq(authRegistryV2.operator(), operator);
        assertTrue(authRegistryV2.allowedRelays(relay));
        assertEq(authRegistryV2.authKeyTreeOf(authKeyId), 0);
        assertEq(authRegistryV2.authKeyIndexOf(authKeyId), 0);
        assertFalse(authRegistryV2.authKeyRevoked(authKeyId));
        assertEq(authRegistryV2.authTreeCount(0), 1);
        // No leaf-index migration or reinitializer is required: the existing
        // level-zero Merkle slot remains the current-key source of truth.
        assertTrue(authRegistryV2.isCurrentAuthLeafAt(0, authLeaf));

        // Verify new functionality works
        assertEq(authRegistryV2.version(), "v2");
        authRegistryV2.setNewVariable(123);
        assertEq(authRegistryV2.newVariable(), 123);
    }

    function test_authRegistry_preUpgradeKeyCanPublicGiftExitWithoutLeafMigration() public {
        uint256 privateKey = 0xA11CE;
        address signer = vm.addr(privateKey);
        uint256 accountId = authRegistry.computeAccountId(signer, DEFAULT_SALT);
        uint64 expiry = uint64(block.timestamp + 1 hours);
        bytes memory sig = _signRegister(privateKey, accountId, PK1X, PK1Y, expiry, 0);
        vm.prank(signer);
        authRegistry.register(DEFAULT_SALT, PK1X, PK1Y, expiry, signer, sig);

        uint256 authLeaf = authRegistry.computeLeaf(accountId, PK1X, PK1Y, expiry);
        uint256 preUpgradeAuthRoot = authRegistry.authTreeRoot(0);

        // Upgrade without a reinitializer or any leaf backfill call.
        AuthRegistryV2 authRegistryV2Impl = new AuthRegistryV2(20);
        address proxyAdmin = _getProxyAdmin(address(authRegistryProxy));
        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(authRegistryProxy)), address(authRegistryV2Impl), "");

        uint16 tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        uint96 amount = 1 ether;
        token.mint(address(pool), amount);

        TreeRootPair[] memory noteRoots = new TreeRootPair[](1);
        noteRoots[0] = TreeRootPair({treeNumber: 0, root: pool.treeRoot(0)});
        TreeRootPair[] memory authRoots = new TreeRootPair[](1);
        authRoots[0] = TreeRootPair({treeNumber: 0, root: preUpgradeAuthRoot});

        // Packed location 0 is tree 0 / index 0. The exact leaf is proof-bound
        // in production; MockVerifier isolates the post-upgrade settlement check.
        pool.publicGiftExit(
            noteRoots,
            authRoots,
            0xBEEF,
            authLeaf,
            0,
            alice,
            tokenId,
            amount,
            amount,
            bytes32(0),
            bytes32(0),
            pool.treeCount(0),
            block.number,
            uint64(block.timestamp),
            [uint256(0), 0, 0, 0, 0, 0, 0, 0]
        );

        assertEq(token.balanceOf(alice), amount);
        assertTrue(pool.nullifierSpent(0xBEEF));
    }

    function test_authRegistry_hydrationRunsViaProxyAdminUpgradeAndCall() public {
        _markAuthRegistryAsLegacyInitialized();

        uint256 snapshotRoot = uint256(keccak256("upgrade-snapshot-root"));
        TreeRootPair[] memory snapshotRoots = new TreeRootPair[](1);
        snapshotRoots[0] = TreeRootPair({treeNumber: 0, root: snapshotRoot});

        AuthRegistryV2 authRegistryV2Impl = new AuthRegistryV2(20);
        address proxyAdmin = _getProxyAdmin(address(authRegistryProxy));
        bytes memory initCalldata = abi.encodeCall(AuthRegistry.hydrateAuthRootAnchorsFromRoots, (snapshotRoots));

        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(
                ITransparentUpgradeableProxy(address(authRegistryProxy)), address(authRegistryV2Impl), initCalldata
            );

        AuthRegistryV2 authRegistryV2 = AuthRegistryV2(address(authRegistryProxy));
        uint64 supersededBlock = authRegistryV2.authTreeRootAnchors(0, snapshotRoot);
        assertEq(supersededBlock, uint64(block.number), "snapshot root should be stamped as superseded");
    }

    // ============ PrivacyBoost Tests ============

    function test_privacyBoost_initializationSucceeds() public view {
        assertEq(pool.owner(), owner);
        assertEq(pool.gatewayRouteManager(), owner);
        assertEq(address(pool.tokenRegistry()), address(tokenRegistry));
        assertEq(address(pool.authRegistry()), address(authRegistry));
        assertEq(pool.maxBatchSize(), 8);
        assertEq(pool.maxFeeTokens(), 4);
        assertEq(pool.currentTreeNumber(), 0);
        assertGt(pool.treeRoot(0), 0);
    }

    function test_privacyBoost_gatewayRouteManagerMigratesAtomicallyViaProxyAdmin() public {
        address routeManager = makeAddr("route-manager");
        bytes32 managerSlot = bytes32(uint256(33));
        vm.store(address(pool), managerSlot, bytes32(0));
        assertEq(pool.gatewayRouteManager(), address(0));

        PrivacyBoost newImpl =
            new PrivacyBoost(address(tokenRegistry), address(authRegistry), 8, 1, 1, 4, 256, 256, 4, 300, 64, 20);
        address proxyAdmin = _getProxyAdmin(address(poolProxy));
        bytes memory initCalldata = abi.encodeCall(PrivacyBoost.initializeGatewayRouteManager, (routeManager));

        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(poolProxy)), address(newImpl), initCalldata);

        assertEq(pool.gatewayRouteManager(), routeManager);
    }

    function test_privacyBoost_gatewayRouteManagerMigrationRejectsUnauthorizedCaller() public {
        vm.prank(alice);
        vm.expectRevert(IPrivacyBoost.NotGatewayRouteMigrationAdmin.selector);
        pool.initializeGatewayRouteManager(makeAddr("route-manager"));
    }

    function test_privacyBoost_reinitializationBlocked() public {
        vm.expectRevert();
        pool.initialize(
            alice,
            address(verifier),
            address(verifier),
            address(verifier),
            address(verifier),
            address(verifier),
            0,
            address(0)
        );
    }

    function test_privacyBoost_statePreservedAfterUpgrade() public {
        // Set up some state
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        uint256 initialTreeRoot = pool.treeRoot(0);
        uint256 initialTreeNumber = pool.currentTreeNumber();

        // Deploy V2 implementation (must use same immutable values)
        PrivacyBoostV2 poolV2Impl = new PrivacyBoostV2(
            address(tokenRegistry),
            address(authRegistry),
            8, // batchSize
            1, // maxInputsPerTransfer
            1, // maxOutputsPerTransfer
            4, // maxFeeTokens
            256, // cancelDelay
            256, // forcedWithdrawalDelay
            4, // maxForcedInputs
            300, // maxEpochAuthStalenessBlocks
            64, // maxForcedWithdrawalAuthStalenessBlocks
            20 // merkleDepth
        );
        address proxyAdmin = _getProxyAdmin(address(poolProxy));

        // Upgrade via ProxyAdmin
        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin).upgradeAndCall(ITransparentUpgradeableProxy(address(poolProxy)), address(poolV2Impl), "");

        // Verify state is preserved
        PrivacyBoostV2 poolV2 = PrivacyBoostV2(address(poolProxy));
        assertEq(poolV2.treeRoot(0), initialTreeRoot);
        assertEq(poolV2.currentTreeNumber(), initialTreeNumber);
        assertEq(poolV2.owner(), owner);
        assertEq(poolV2.maxBatchSize(), 8);
        assertTrue(poolV2.allowedRelays(relay));

        // Verify new functionality works
        assertEq(poolV2.version(), "v2");
        poolV2.setNewVariable(999);
        assertEq(poolV2.newVariable(), 999);
    }

    function test_privacyBoost_upgradeOnlyByAdmin() public {
        PrivacyBoostV2 poolV2Impl = new PrivacyBoostV2(
            address(tokenRegistry),
            address(authRegistry),
            8, // batchSize
            1, // maxInputsPerTransfer
            1, // maxOutputsPerTransfer
            4, // maxFeeTokens
            256, // cancelDelay
            256, // forcedWithdrawalDelay
            4, // maxForcedInputs
            300, // maxEpochAuthStalenessBlocks
            64, // maxForcedWithdrawalAuthStalenessBlocks
            20 // merkleDepth
        );
        address proxyAdmin = _getProxyAdmin(address(poolProxy));

        // Non-admin cannot upgrade
        vm.prank(alice);
        vm.expectRevert();
        ProxyAdmin(proxyAdmin).upgradeAndCall(ITransparentUpgradeableProxy(address(poolProxy)), address(poolV2Impl), "");
    }

    // ============ Implementation Direct Call Tests ============

    function test_implementation_cannotBeInitializedDirectly() public {
        // Deploy fresh implementations
        TokenRegistry tokenRegistryImpl = new TokenRegistry();
        AuthRegistry authRegistryImpl = new AuthRegistry(20);
        PrivacyBoost poolImpl = new PrivacyBoost(
            address(tokenRegistry),
            address(authRegistry),
            8, // batchSize
            1, // maxInputsPerTransfer
            1, // maxOutputsPerTransfer
            4, // maxFeeTokens
            256, // cancelDelay
            256, // forcedWithdrawalDelay
            4, // maxForcedInputs
            300, // maxEpochAuthStalenessBlocks
            64, // maxForcedWithdrawalAuthStalenessBlocks
            20 // merkleDepth
        );

        // All should revert when trying to initialize directly
        // because constructor calls _disableInitializers()
        vm.expectRevert();
        tokenRegistryImpl.initialize(owner);

        vm.expectRevert();
        authRegistryImpl.initialize(owner);

        vm.expectRevert();
        poolImpl.initialize(
            owner,
            address(verifier),
            address(verifier),
            address(verifier),
            address(verifier),
            address(verifier),
            0,
            address(0)
        );
    }

    // ============ Storage Gap Tests ============

    function test_tokenRegistry_storageGapExists() public {
        // Storage gap should allow adding ~50 new state variables without collision
        // This is verified by successful V2 upgrade above
        TokenRegistryV2 tokenRegistryV2Impl = new TokenRegistryV2();
        address proxyAdmin = _getProxyAdmin(address(tokenRegistryProxy));

        vm.prank(ProxyAdmin(proxyAdmin).owner());
        ProxyAdmin(proxyAdmin)
            .upgradeAndCall(ITransparentUpgradeableProxy(address(tokenRegistryProxy)), address(tokenRegistryV2Impl), "");

        TokenRegistryV2 tokenRegistryV2 = TokenRegistryV2(address(tokenRegistryProxy));

        // New variable should work without affecting existing storage
        tokenRegistryV2.setNewVariable(12345);
        assertEq(tokenRegistryV2.newVariable(), 12345);
        assertEq(tokenRegistryV2.owner(), owner); // Owner unchanged
    }

    // ============ Helper Functions ============

    function _getProxyAdmin(address proxy) internal view returns (address) {
        // ERC1967 admin slot: bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
        bytes32 adminSlot = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
        bytes32 adminBytes = vm.load(proxy, adminSlot);
        return address(uint160(uint256(adminBytes)));
    }
}
