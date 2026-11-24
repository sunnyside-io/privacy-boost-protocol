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

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {TokenRegistry} from "src/TokenRegistry.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {TokenInfo} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";

contract MockToken {
    string public name = "Mock Token";
}

contract TokenRegistryTest is Test {
    TokenRegistry registry;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address notOwner = makeAddr("notOwner");

    MockToken tokenA;
    MockToken tokenB;
    MockToken tokenC;

    function setUp() public {
        TokenRegistry impl = new TokenRegistry();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(TokenRegistry.initialize, (owner))
        );
        registry = TokenRegistry(address(proxy));

        tokenA = new MockToken();
        tokenB = new MockToken();
        tokenC = new MockToken();
    }

    // ========== Happy Path ==========

    function test_register_single() public {
        uint16 tokenId = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);

        assertEq(tokenId, 1);
        assertEq(registry.nextId(), 1);

        (uint8 tokenType, address tokenAddress, uint256 tokenSubId) = registry.tokenOf(tokenId);
        assertEq(tokenType, TOKEN_TYPE_ERC20);
        assertEq(tokenAddress, address(tokenA));
        assertEq(tokenSubId, 0);
    }

    function test_register_multiple() public {
        uint16 idA = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);
        uint16 idB = registry.register(TOKEN_TYPE_ERC20, address(tokenB), 0);
        uint16 idC = registry.register(TOKEN_TYPE_ERC20, address(tokenC), 0);

        assertEq(idA, 1);
        assertEq(idB, 2);
        assertEq(idC, 3);
        assertEq(registry.nextId(), 3);
    }

    function test_idOf_returnsCorrectId() public {
        uint16 tokenId = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);

        bytes32 key = keccak256(abi.encode(TOKEN_TYPE_ERC20, address(tokenA), uint256(0)));
        assertEq(registry.idOf(key), tokenId);
    }

    // ========== Access Control ==========

    function test_revertWhen_registerByNonOwner() public {
        vm.prank(notOwner);
        vm.expectRevert();
        registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);
    }

    // ========== Input Validation ==========

    function test_revertWhen_zeroAddress() public {
        vm.expectRevert(ITokenRegistry.ZeroAddress.selector);
        registry.register(TOKEN_TYPE_ERC20, address(0), 0);
    }

    function test_revertWhen_tokenAlreadyRegistered() public {
        registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);

        vm.expectRevert(ITokenRegistry.TokenAlreadyRegistered.selector);
        registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);
    }

    function test_revertWhen_unsupportedTokenType() public {
        uint8 unsupportedType = 99;
        vm.expectRevert(abi.encodeWithSelector(ITokenRegistry.TokenTypeNotSupported.selector, unsupportedType));
        registry.register(unsupportedType, address(tokenA), 0);
    }

    function test_revertWhen_notAContract() public {
        address eoa = makeAddr("regularEOA");
        vm.expectRevert(ITokenRegistry.NotAContract.selector);
        registry.register(TOKEN_TYPE_ERC20, eoa, 0);
    }

    // ========== Events ==========

    function test_emitsTokenRegisteredEvent() public {
        vm.expectEmit(true, false, false, true);
        emit ITokenRegistry.TokenRegistered(1, TOKEN_TYPE_ERC20, address(tokenA), 0);

        registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);
    }

    // ========== Edge Cases ==========

    function test_register_withSubId() public {
        uint16 id1 = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 0);
        uint16 id2 = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 1);
        uint16 id3 = registry.register(TOKEN_TYPE_ERC20, address(tokenA), 2);

        assertEq(id1, 1);
        assertEq(id2, 2);
        assertEq(id3, 3);

        (,, uint256 subId1) = registry.tokenOf(id1);
        (,, uint256 subId2) = registry.tokenOf(id2);
        (,, uint256 subId3) = registry.tokenOf(id3);

        assertEq(subId1, 0);
        assertEq(subId2, 1);
        assertEq(subId3, 2);
    }

    function test_tokenOf_unregisteredId_returnsZeroValues() public view {
        (uint8 tokenType, address tokenAddress, uint256 tokenSubId) = registry.tokenOf(999);

        assertEq(tokenType, 0);
        assertEq(tokenAddress, address(0));
        assertEq(tokenSubId, 0);
    }

    function test_idOf_unregisteredToken_returnsZero() public view {
        bytes32 key = keccak256(abi.encode(TOKEN_TYPE_ERC20, address(tokenA), uint256(0)));
        assertEq(registry.idOf(key), 0);
    }

    // ========== Initialization ==========

    function test_initialize_setsOwner() public view {
        assertEq(registry.owner(), owner);
    }

    function test_initialize_startsWithNextIdZero() public view {
        assertEq(registry.nextId(), 0);
    }

    function test_revertWhen_doubleInitialize() public {
        vm.expectRevert();
        registry.initialize(notOwner);
    }
}
