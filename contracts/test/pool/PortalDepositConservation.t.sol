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
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {MockERC20, MockVerifier, BindablePortal} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {PortalDepositEntry, EpochTreeState, TreeRootPair} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";

/// @dev A registrable, cap-honoring portal `E`: pushes min(balance, cap) of the token to the caller on
///      sweep (the pool re-measures the received delta). The mock sweep is intentionally ungated so the
///      handler can also drain a cancel-refund back out of `E` (keeping `E` empty between pool sweeps); the
///      real PortalDelegate.sweep is pool-only — that gate is exercised in PortalDelegate.t.sol, not here.
contract ConservationPortal is BindablePortal, IPortalSweepSource {
    function sweep(address token, uint256 cap) external override {
        uint256 bal = IERC20(token).balanceOf(address(this));
        uint256 amount = bal < cap ? bal : cap;
        IERC20(token).transfer(msg.sender, amount);
    }
}

/// @dev Stateless accepting portal-deposit verifier — credits are exercised end-to-end without a real proof
///      (the cryptographic verify is covered by test/ffi/PortalDepositFFI.t.sol). `view` so the pool's
///      staticcall succeeds.
contract AcceptingPortalVerifier {
    function verifyPortalDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }
}

/// @dev Invariant handler: drives random sequences of sweep / credit / cancel against the real pool and keeps
///      ghost totals so the value-conservation invariant can compare the pool's actual token balance against
///      the books. `E` is kept empty between pool sweeps (every cancel-refund is drained back out), so the
///      measured received delta of each sweep equals the freshly-minted amount.
contract Handler is Test {
    PrivacyBoost public pool;
    MockERC20 public token;
    ConservationPortal public portal;
    address public E;
    uint16 public tokenId;
    address public relay;
    uint16 public feeBps;
    uint8 public merkleDepth;
    uint256[8] internal dummyProof;

    uint256[] internal pendingIds; // escrowed records not yet credited or cancelled
    mapping(uint256 => uint96) internal grossOf; // measured gross per record

    // Ghost totals, all denominated in `token`.
    uint256 public gReceived; // Σ measured deltas swept into the pool
    uint256 public gCreditedNet; // Σ net amounts credited (stay in the pool, back the notes)
    uint256 public gFeesPaid; // Σ fees transferred out to sweepers
    uint256 public gReclaimedGross; // Σ gross refunded out of the pool on cancel
    uint256 public gEscrowedGross; // Σ gross of records still escrowed

    uint256 public sweeps;
    uint256 public credits;
    uint256 public cancels;

    constructor(
        PrivacyBoost _pool,
        MockERC20 _token,
        ConservationPortal _portal,
        uint16 _tokenId,
        address _relay,
        uint16 _feeBps,
        uint8 _merkleDepth
    ) {
        pool = _pool;
        token = _token;
        portal = _portal;
        E = address(_portal);
        tokenId = _tokenId;
        relay = _relay;
        feeBps = _feeBps;
        merkleDepth = _merkleDepth;
    }

    function pendingCount() external view returns (uint256) {
        return pendingIds.length;
    }

    /// @dev Sweep a fresh amount into the pool. `E` is empty beforehand, so the measured delta == minted.
    function sweep(uint96 amount) external {
        amount = uint96(bound(amount, 1, 1e24)); // comfortably under the uint96 record ceiling
        token.mint(E, amount);
        uint256 balBefore = token.balanceOf(address(pool));
        uint256 id = pool.requestPortalDeposit(E, tokenId); // msg.sender (this handler) is the sweeper
        uint96 delta = uint96(token.balanceOf(address(pool)) - balBefore);

        gReceived += delta;
        gEscrowedGross += delta;
        grossOf[id] = delta;
        pendingIds.push(id);
        sweeps++;
    }

    /// @dev Credit a batch of up to min(pending, maxBatchSize) escrowed records into the shielded tree.
    function credit(uint256 batch, uint256 rootSeed) external {
        uint256 n = pendingIds.length;
        if (n == 0) return;
        uint256 b = bound(batch, 1, n < 8 ? n : 8); // <= maxBatchSize (8) and <= pending

        uint256 activeTree = pool.currentTreeNumber();
        uint32 countOld = pool.treeCount(activeTree);
        // Stay strictly below tree capacity so the non-rollover path is always valid (rollover is unit-tested
        // separately in SubmitPortalDepositEpoch.t.sol; it is orthogonal to value conservation).
        if (uint256(countOld) + b > (uint256(1) << merkleDepth)) return;

        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(activeTree, pool.treeRoot(activeTree));
        EpochTreeState memory treeState = EpochHelpers.buildTreeState(
            usedRoots,
            activeTree,
            countOld,
            uint256(keccak256(abi.encode(rootSeed, countOld))), // arbitrary new root (mock verifier accepts)
            countOld + uint32(b),
            false
        );

        PortalDepositEntry[] memory entries = new PortalDepositEntry[](b);
        uint256[] memory commitments = new uint256[](b);
        uint256 batchFee;
        uint256 batchNet;
        uint256 grossSum;
        for (uint256 i = 0; i < b; i++) {
            uint256 id = pendingIds[n - 1 - i]; // take the last `b` pending records
            entries[i] = PortalDepositEntry({portalDepositId: id});
            commitments[i] = uint256(keccak256(abi.encode("commitment", id)));
            uint96 gross = grossOf[id];
            uint96 fee = uint96((uint256(gross) * feeBps) / 10_000); // mirrors LibPortal exactly
            batchFee += fee;
            batchNet += (gross - fee);
            grossSum += gross;
        }

        vm.prank(relay);
        pool.submitPortalDepositEpoch(treeState, entries, commitments, dummyProof);

        // Only on success: net stays in the pool, fee left to the sweeper, records leave escrow.
        gCreditedNet += batchNet;
        gFeesPaid += batchFee;
        gEscrowedGross -= grossSum;
        for (uint256 i = 0; i < b; i++) {
            pendingIds.pop();
        }
        credits++;
    }

    /// @dev Reclaim one escrowed record after the cancel delay; the gross refunds to `E`, which we drain back
    ///      out so it is not re-swept (keeping each sweep's measured delta == its minted amount).
    function cancel(uint256 seed) external {
        uint256 n = pendingIds.length;
        if (n == 0) return;
        uint256 idx = bound(seed, 0, n - 1);
        uint256 id = pendingIds[idx];
        uint96 gross = grossOf[id];

        vm.roll(block.number + 257); // past cancelDelay (256)
        pool.cancelPortalDeposit(id); // permissionless; refunds gross to E (the portal), never msg.sender
        portal.sweep(address(token), type(uint256).max); // drain the refund out of E to this handler

        gReclaimedGross += gross;
        gEscrowedGross -= gross;
        pendingIds[idx] = pendingIds[n - 1]; // swap-pop
        pendingIds.pop();
        cancels++;
    }
}

/// @dev Stateful fuzz/invariant test locking FUND CONSERVATION for the portal-deposit flow: across any random
///      sequence of sweeps, batch credits, and cancels, the pool can neither lose nor mint a wei of a swept
///      token. The handler keeps an independent ledger; the invariants compare it to the pool's real
///      `balanceOf`. A non-zero sweep fee is configured so the fee-out path is exercised. The user-stated
///      identity `Σ credited-net + Σ reclaimed-gross == Σ received` is the fee-zero, fully-settled corollary
///      of these (with a non-zero fee, `received == credited-net + fees + reclaimed-gross + still-escrowed`).
contract PortalDepositConservationInvariant is StdInvariant, Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockERC20 token;
    AcceptingPortalVerifier portalVerifier;
    ConservationPortal portal;
    Handler handler;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address relay = makeAddr("relay");
    address operator = makeAddr("operator");
    uint16 tokenId;
    uint16 constant FEE_BPS = 300; // 3% — exercises the fee-out path; conservation must still hold
    uint8 constant MERKLE_DEPTH = 20; // PoolDeployer default
    uint256 constant H = 0xB14D;

    function setUp() public {
        MockVerifier verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);

        portalVerifier = new AcceptingPortalVerifier();
        pool.setPortalDepositVerifier(address(portalVerifier));
        pool.setPortalSweepFeeBps(FEE_BPS);

        pool.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = relay;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        portal = new ConservationPortal();
        portal.initializePortal(H);

        handler = new Handler(pool, token, portal, tokenId, relay, FEE_BPS, MERKLE_DEPTH);

        // Drive only the handler's three actions.
        targetContract(address(handler));
        bytes4[] memory selectors = new bytes4[](3);
        selectors[0] = Handler.sweep.selector;
        selectors[1] = Handler.credit.selector;
        selectors[2] = Handler.cancel.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @dev Value conservation: the pool's token balance equals everything swept IN minus everything paid OUT
    ///      (fees to sweepers + reclaims to portals). Any wei the contract loses or mints breaks this.
    function invariant_poolBalanceEqualsInMinusOut() public view {
        assertEq(
            token.balanceOf(address(pool)),
            handler.gReceived() - handler.gFeesPaid() - handler.gReclaimedGross(),
            "pool balance != received - fees - reclaimed"
        );
    }

    /// @dev The pool's balance is exactly the still-escrowed gross (fully reclaimable) plus the credited net
    ///      (note backing) — the two categories that legitimately remain in the pool. Proves no escrow is
    ///      under-collateralized and no credited note is left unbacked.
    function invariant_poolBackingEqualsEscrowPlusCredited() public view {
        assertEq(
            token.balanceOf(address(pool)),
            handler.gEscrowedGross() + handler.gCreditedNet(),
            "pool balance != escrowedGross + creditedNet"
        );
    }
}
