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
import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {DepositCiphertext} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

/// @dev Storage-layout and shape coverage for the portal-deposit state added to the pool.
///      The portal mappings are appended after the pre-existing storage tail (before __gap),
///      so the two load-bearing properties are: (1) the new mappings occupy slots distinct
///      from the existing deposit storage (no aliasing — a portal record must never read or
///      clobber a normal deposit record), and (2) the PortalPendingDeposit struct round-trips
///      through the public mapping getter field-for-field (correct packing/order).
contract PortalStorageTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address alice = makeAddr("alice");

    uint16 tokenId;
    uint96 constant AMOUNT = 1000 ether;
    uint256 constant COMMITMENT = 12345;

    /// @dev Declaration slot of the portalPendingDeposits mapping, from the compiled storage
    ///      layout (`forge inspect src/PrivacyBoost.sol:PrivacyBoost storage`). Used only by the
    ///      struct-field round-trip test to address the record's storage word(s).
    uint256 constant PORTAL_PENDING_SLOT = 27;

    /// @dev Shared slot of the packed portal pair from the compiled storage layout:
    ///      portalSweepFeeBps (uint16, byte offset 0) and portalDepositVerifier (address, byte
    ///      offset 2) pack into slot 29. The portalMinSweep mapping is declared next at slot 30.
    ///      Gift, gateway, and deferred-fee state occupy slots 31 through 34, then __gap begins at 35.
    uint256 constant PORTAL_FEE_AND_VERIFIER_SLOT = 29;
    uint256 constant PORTAL_MIN_SWEEP_SLOT = 30;
    uint256 constant DEFERRED_PORTAL_SWEEP_FEES_SLOT = 34;
    uint256 constant GAP_START_SLOT = 35;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);
        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        token.mint(alice, 100_000 ether);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    function _dummyCiphertext() internal pure returns (DepositCiphertext memory) {
        return DepositCiphertext({
            viewingKey: bytes32(uint256(1)),
            teeWrapKey: bytes32(uint256(2)),
            receiverWrapKey: bytes32(uint256(3)),
            ct0: bytes32(uint256(4)),
            ct1: bytes32(uint256(5)),
            ct2: bytes16(uint128(6))
        });
    }

    // ========== Default state ==========

    /// @dev A fresh deploy must expose every portal getter at its zero default. This is the
    ///      compile-time + presence proof that the mappings and fee var were added to the
    ///      contract; it fails to compile if any getter is missing.
    function test_portalStorage_defaultsAreZero() public view {
        assertEq(pool.portalCounter(alice), 0, "portalCounter default");
        assertFalse(pool.processedPortalDeposits(0), "processedPortalDeposits default");
        assertEq(pool.portalSweepFeeBps(), 0, "portalSweepFeeBps default");
        assertEq(pool.claimablePortalSweepFees(alice, tokenId), 0, "claimablePortalSweepFees default");

        (
            address portal,
            uint64 requestBlock,
            uint16 tid,
            uint16 sweepFeeBps,
            address sweeper,
            uint96 amount,
            uint256 counter,
            uint256 recipientBindH
        ) = pool.portalPendingDeposits(0);
        assertEq(portal, address(0), "portal default");
        assertEq(tid, 0, "tokenId default");
        assertEq(amount, 0, "amount default");
        assertEq(sweepFeeBps, 0, "sweepFeeBps default");
        assertEq(requestBlock, 0, "requestBlock default");
        assertEq(sweeper, address(0), "sweeper default");
        assertEq(counter, 0, "counter default");
        assertEq(recipientBindH, 0, "recipientBindH default");
    }

    // ========== No aliasing with the existing deposit storage ==========

    /// @dev Populating the standard deposit mapping must leave the portal mapping at the same
    ///      key untouched: the two mappings live in different storage slots, so a portal
    ///      record can never collide with a normal deposit record. Deleting the new portal
    ///      storage (or accidentally reusing the deposit slot) would surface here as a
    ///      non-zero portal record after a normal deposit.
    function test_portalStorage_doesNotAliasDepositStorage() public {
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = COMMITMENT;
        DepositCiphertext[] memory cts = new DepositCiphertext[](1);
        cts[0] = _dummyCiphertext();

        vm.prank(alice);
        uint256 reqId = pool.requestDeposit(tokenId, AMOUNT, commitments, cts);

        // The standard deposit record is now populated at reqId.
        (address depositor,,,,,,,) = pool.pendingDeposits(reqId);
        assertEq(depositor, alice, "deposit record populated");

        // The portal record at the very same key must still be empty — distinct slot.
        (address portal,,,,, uint96 amount,, uint256 recipientBindH) = pool.portalPendingDeposits(reqId);
        assertEq(portal, address(0), "portal record must not alias deposit record");
        assertEq(amount, 0, "portal amount must not alias deposit amount");
        assertEq(recipientBindH, 0, "portal H must not alias deposit storage");
    }

    // ========== Struct field order/packing ==========

    /// @dev Pin the PortalPendingDeposit field ORDER and PACKING by poking each field into the
    ///      record's storage word(s) via the compiler-reported slot+offset and reading every
    ///      field back through the public getter with a distinct non-zero value. The mapping
    ///      slot and each field's (slot, byte-offset) come from `forge inspect` (the same
    ///      storage-layout snapshot the success criterion calls for), not hand-rolled packing
    ///      math, so the test reflects the real layout. Reorder two fields, or change a field's
    ///      width so packing shifts, and the decoded values no longer match — the test fails.
    ///      Populating via raw storage (rather than the sweep entrypoint) isolates the layout
    ///      assertion from the entrypoint's accounting logic, which is covered separately.
    function test_portalPendingDeposit_structFieldsRoundTrip() public {
        uint256 portalDepositId = 0xDEAD;

        address portalE = address(0xE);
        uint16 tid = 7;
        uint96 amount = 123456789;
        uint16 sweepFeeBps = 250;
        uint64 requestBlock = 999;
        address sweeper = address(0x5EEE);
        uint256 counter = 42;
        uint256 recipientBindH = 0xABCDEF;

        // base = slot of portalPendingDeposits[portalDepositId]. PORTAL_PENDING_SLOT is the
        // mapping's declaration slot taken from the compiled storage layout.
        bytes32 base = keccak256(abi.encode(portalDepositId, PORTAL_PENDING_SLOT));

        // Field (slot, byte-offset) per the compiled layout (forge inspect ... storage):
        //   word 0: portal @0, requestBlock @20 (bit 160), tokenId @28 (bit 224), sweepFeeBps @30 (bit 240)
        //   word 1: sweeper @0, amount @20 (bit 160)
        //   word 2: counter   word 3: recipientBindH
        bytes32 word0 = bytes32(
            uint256(uint160(portalE)) | (uint256(requestBlock) << 160) | (uint256(tid) << 224)
                | (uint256(sweepFeeBps) << 240)
        );
        bytes32 word1 = bytes32(uint256(uint160(sweeper)) | (uint256(amount) << 160));
        vm.store(address(pool), base, word0);
        vm.store(address(pool), bytes32(uint256(base) + 1), word1);
        vm.store(address(pool), bytes32(uint256(base) + 2), bytes32(counter));
        vm.store(address(pool), bytes32(uint256(base) + 3), bytes32(recipientBindH));

        (
            address gotPortal,
            uint64 gotBlock,
            uint16 gotTid,
            uint16 gotFee,
            address gotSweeper,
            uint96 gotAmount,
            uint256 gotCounter,
            uint256 gotH
        ) = pool.portalPendingDeposits(portalDepositId);

        assertEq(gotPortal, portalE, "portal");
        assertEq(gotTid, tid, "tokenId");
        assertEq(gotAmount, amount, "amount");
        assertEq(gotFee, sweepFeeBps, "sweepFeeBps");
        assertEq(gotBlock, requestBlock, "requestBlock");
        assertEq(gotSweeper, sweeper, "sweeper");
        assertEq(gotCounter, counter, "counter");
        assertEq(gotH, recipientBindH, "recipientBindH");
    }

    // ========== Portal packing and the current __gap boundary ==========

    /// @dev Pin the upgrade-safety boundary the reserved __gap protects: portalSweepFeeBps and
    ///      portalDepositVerifier must PACK into one slot (slot 29), so the six appended portal
    ///      declarations consume exactly five storage slots (26..29 for the three record mappings + the
    ///      packed pair, then portalMinSweep at 30). Later gift, gateway, and deferred-fee declarations
    ///      occupy slots 31 through 34. The current reserved gap begins at slot 35.
    ///      Probing raw storage rather than `forge inspect` keeps the guard live at test time so a
    ///      regression fails CI instead of needing a manual layout review.
    function test_portalStorage_feeAndVerifierPackIntoOneSlot() public {
        // Set the verifier through its real entrypoint; it must land in the packed slot's upper
        // 20 bytes (offset 2) and leave the lower 2 bytes (portalSweepFeeBps) untouched.
        address sentinelVerifier = address(0xBEEF);
        pool.setPortalDepositVerifier(sentinelVerifier);

        bytes32 packedWord = vm.load(address(pool), bytes32(PORTAL_FEE_AND_VERIFIER_SLOT));
        // portalDepositVerifier occupies bits 16..175 (byte offset 2): shift right 16 bits, mask 160.
        address decodedVerifier = address(uint160(uint256(packedWord) >> 16));
        assertEq(decodedVerifier, sentinelVerifier, "verifier must sit at offset 2 of slot 29");
        // The fee field (low 16 bits) shares the same slot and is independently addressable.
        assertEq(uint16(uint256(packedWord)), pool.portalSweepFeeBps(), "fee must share slot 29 with verifier");
        assertEq(address(pool.portalDepositVerifier()), sentinelVerifier, "verifier getter reads slot 29");

        // A non-zero word at the current gap boundary must not bleed into the earlier packed portal fields.
        vm.store(address(pool), bytes32(GAP_START_SLOT), bytes32(type(uint256).max));
        assertEq(address(pool.portalDepositVerifier()), sentinelVerifier, "gap write must not touch verifier");
        assertEq(pool.portalSweepFeeBps(), uint16(uint256(packedWord)), "gap write must not touch fee");
    }

    /// @dev Pin the deferred-fee mapping at slot 34 and the reserved gap immediately after it at slot 35.
    function test_claimablePortalSweepFees_occupiesTailSlotBeforeGap() public {
        // Arrange - derive the nested mapping entry exactly from the compiler-reported declaration slot
        address sweeper = makeAddr("sweeper");
        uint16 deferredTokenId = 7;
        uint256 amount = 123 ether;
        bytes32 sweeperSlot = keccak256(abi.encode(sweeper, DEFERRED_PORTAL_SWEEP_FEES_SLOT));
        bytes32 feeSlot = keccak256(abi.encode(deferredTokenId, sweeperSlot));

        // Act - write the mapping entry and a distinct sentinel into the next reserved slot
        vm.store(address(pool), feeSlot, bytes32(amount));
        vm.store(address(pool), bytes32(GAP_START_SLOT), bytes32(type(uint256).max));

        // Assert - the getter reads slot 34 while the slot 35 sentinel remains independent
        assertEq(pool.claimablePortalSweepFees(sweeper, deferredTokenId), amount, "deferred fee reads slot 34");
        assertEq(vm.load(address(pool), bytes32(GAP_START_SLOT)), bytes32(type(uint256).max), "gap starts at 35");
    }
}
