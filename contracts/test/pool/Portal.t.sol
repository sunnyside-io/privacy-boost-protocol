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
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {PortalDelegate} from "src/PortalDelegate.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {IWETH} from "src/interfaces/IWETH.sol";
import {MockWETH} from "src/testnet/MockWETH.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {MockERC20, MockVerifier} from "test/helpers/Mocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";

/// @dev Behavior coverage for the EIP-7702 portal delegate exercised against the REAL pool: a fresh EOA is
///      delegated to the shared PortalDelegate impl and made a deposit address `E`. Companion to
///      PortalDelegate.t.sol, which unit-tests the delegate's access control against a mock pool; here every
///      path runs through the real requestPortalDeposit / cancelPortalDeposit / sweep machinery so the account
///      contract and the pool seam are tested together. Every test asserts an observable outcome that flips if
///      the feature — or one of its guards — were deleted, never a bare "didn't revert". The load-bearing
///      properties: the portal registers its binding at the pool via an explicit self-call (no constructor runs
///      on an EOA), the pool-only `sweep` push moves the balance into the pool while honoring the cap, the
///      self-only `withdraw` is the no-stuck-funds escape hatch for every "funds at E" case (cancel refund,
///      un-swept / unregistered token), and registration enforces the write-once and well-formedness invariants.
contract PortalTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    AuthRegistry authRegistry;
    MockVerifier verifier;
    MockERC20 token;
    MockWETH weth;
    PortalDelegate delegateImpl;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address rescueDest = makeAddr("rescueDest");
    address keeper = makeAddr("keeper");

    uint16 tokenId;
    uint16 wethTokenId;
    // A canonical, in-field, non-zero owner binding (Poseidon(DOMAIN_PORTAL_BIND, recipientMPK, blind)).
    uint256 constant H = 0xB14D;
    // Private keys for the portal EOAs. Each portal `E` is a distinct EOA delegated to the shared impl.
    uint256 constant PORTAL_PK = 0xA11CE;
    uint256 constant PORTAL_PK_2 = 0xB0B;
    // EIP-712 PortalBind typehashes for the relayed initializePortalWithSig path (mirror the delegate).
    bytes32 constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant PORTAL_BIND_TYPEHASH =
        keccak256("PortalBind(address portal,address pool,uint256 recipientBinding)");
    bytes32 constant LEGACY_PORTAL_BIND_TYPEHASH = keccak256("PortalBind(address portal,address pool,uint256 H)");
    // BN254 scalar field prime — the upper bound the delegate's binding guard enforces.
    uint256 constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    // Mirrors PortalDelegate.NATIVE_GAS_RESERVE, which is private so the dedicated deposit account
    // exposes no getter for it.
    uint256 constant NATIVE_GAS_RESERVE = 0.001 ether;

    function setUp() public {
        verifier = new MockVerifier();
        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        (pool, tokenRegistry, authRegistry) = PoolDeployer.deployFullStack(cfg);

        token = new MockERC20();
        tokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(token), 0);
        weth = new MockWETH();
        wethTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(weth), 0);

        // ONE shared delegate impl per chain; every portal EOA delegates to it (EIP-7702).
        delegateImpl = new PortalDelegate(IPrivacyBoost(address(pool)), IWETH(address(weth)));
    }

    /// @dev Delegate an EOA to the shared impl WITHOUT registering — for the registration-guard tests that must
    ///      observe an unregistered portal. After this the EOA runs the delegate code on calls to itself.
    function _delegateOnly(uint256 pk) internal returns (address E) {
        E = vm.addr(pk);
        vm.signAndAttachDelegation(address(delegateImpl), pk);
    }

    /// @dev Make an EOA a live portal: delegate to the impl, then self-initialize its owner binding in the
    ///      account's OWN storage (the 7702 analog of the former CREATE2 portal's constructor-time
    ///      registration). Returns the portal `E`.
    function _makePortal(uint256 pk, uint256 h) internal returns (address E) {
        E = _delegateOnly(pk);
        vm.prank(E);
        PortalDelegate(payable(E)).initializePortal(h);
    }

    /// @dev Sign a PortalBind(portal=E, pool, H) digest for the relayed account-side initialize. The delegate's
    ///      EIP-712 domain binds chainId + the account E itself (verifyingContract == E) and the struct binds the
    ///      target pool, so the signature is specific to this portal, pool, and chain; returns the (r,s,v) sig.
    function _signInitialize(uint256 pk, address E, uint256 h) internal view returns (bytes memory) {
        return _signInitializeWithTypehash(pk, E, h, PORTAL_BIND_TYPEHASH);
    }

    function _signInitializeWithTypehash(uint256 pk, address E, uint256 h, bytes32 typehash)
        internal
        view
        returns (bytes memory)
    {
        bytes32 domainSep = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256("PB:PrivacyBoost"), keccak256("1"), block.chainid, E)
        );
        bytes32 structHash = keccak256(abi.encode(typehash, E, address(pool), h));
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSep, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // ========== initialize: account-side owner binding (EIP-7201 storage) ==========

    /// @dev The owner self-initializes the binding in the portal EOA's OWN storage; the pool reads it back via
    ///      portalBinding(). Deleting the _setBinding write would leave portalBinding() == 0.
    function test_initializePortal_recordsBindingInAccountStorage() public {
        address E = _delegateOnly(PORTAL_PK);

        vm.prank(E);
        PortalDelegate(payable(E)).initializePortal(H);

        assertEq(PortalDelegate(payable(E)).portalBinding(), H, "binding stored in the portal EOA's own storage");
    }

    /// @dev portalBinding() returns 0 for a delegated-but-uninitialized portal — the unregistered sentinel the
    ///      pool treats as "not a portal".
    function test_portalBinding_zeroBeforeInitialize() public {
        address E = _delegateOnly(PORTAL_PK);
        assertEq(PortalDelegate(payable(E)).portalBinding(), 0, "uninitialized portal reports a zero binding");
    }

    /// @dev A relayer (not E) submits the binding once it carries E's own EIP-712 PortalBind signature, so the
    ///      owner pays no gas. The recovered signer must equal E (address(this) under 7702).
    function test_initializePortalWithSig_recordsBindingFromOwnerSig() public {
        address E = _delegateOnly(PORTAL_PK);
        bytes memory sig = _signInitialize(PORTAL_PK, E, H);

        vm.prank(keeper);
        PortalDelegate(payable(E)).initializePortalWithSig(H, sig);

        assertEq(PortalDelegate(payable(E)).portalBinding(), H, "relayed binding recorded under E's own signature");
    }

    /// @dev A signature from any key other than E's does not recover to E, so the relayed initialize reverts —
    ///      no third party can bind a portal they do not own.
    function test_initializePortalWithSig_revertWhen_wrongSigner() public {
        address E = _delegateOnly(PORTAL_PK);
        bytes memory sig = _signInitialize(PORTAL_PK_2, E, H);

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.InvalidPortalSignature.selector);
        PortalDelegate(payable(E)).initializePortalWithSig(H, sig);
    }

    function test_initializePortalWithSig_revertWhen_legacyFieldName() public {
        address E = _delegateOnly(PORTAL_PK);
        bytes memory sig = _signInitializeWithTypehash(PORTAL_PK, E, H, LEGACY_PORTAL_BIND_TYPEHASH);

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.InvalidPortalSignature.selector);
        PortalDelegate(payable(E)).initializePortalWithSig(H, sig);
    }

    /// @dev EIP-712 replay protection across chains: a PortalBind signature made under one chainId does not
    ///      validate on another. The delegate's domain separator binds block.chainid, so after vm.chainId
    ///      moves the chain the recovered signer no longer equals E and the relayed initialize reverts. A
    ///      domain that dropped chainId would let a signature captured on a testnet replay onto mainnet.
    function test_initializePortalWithSig_revertWhen_chainIdReplay() public {
        address E = _delegateOnly(PORTAL_PK);
        bytes memory sig = _signInitialize(PORTAL_PK, E, H); // signed under the current chainId

        vm.chainId(block.chainid + 1); // the same signature now targets a different chain

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.InvalidPortalSignature.selector);
        PortalDelegate(payable(E)).initializePortalWithSig(H, sig);
    }

    /// @dev EIP-712 replay protection across portals: a PortalBind signature valid for portal E1 does not
    ///      initialize a different portal E2. The domain separator binds address(this) (verifyingContract ==
    ///      E) and the struct binds the portal, so E1's signature submitted to E2 recovers to E1 (not E2) and
    ///      E2's relayed initialize reverts — the property that makes one owner key's signature portal-
    ///      specific rather than reusable across every portal they delegate.
    function test_initializePortalWithSig_revertWhen_crossPortalReplay() public {
        address E1 = _delegateOnly(PORTAL_PK);
        address E2 = _delegateOnly(PORTAL_PK_2);
        bytes memory sigForE1 = _signInitialize(PORTAL_PK, E1, H); // E1's own valid signature

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.InvalidPortalSignature.selector);
        PortalDelegate(payable(E2)).initializePortalWithSig(H, sigForE1);
    }

    /// @dev Self-gated: only the EOA's own key (msg.sender == address(this) under 7702) may self-initialize; a
    ///      stranger calling initializePortal reverts OnlySelf.
    function test_initializePortal_revertWhen_callerNotSelf() public {
        address E = _delegateOnly(PORTAL_PK);

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.OnlySelf.selector);
        PortalDelegate(payable(E)).initializePortal(H);
    }

    /// @dev Initialization is write-once: a second initialize on an already-bound portal reverts, so a binding
    ///      can never be silently overwritten through the delegate.
    function test_initializePortal_revertWhen_alreadyInitialized() public {
        address E = _delegateOnly(PORTAL_PK);
        vm.prank(E);
        PortalDelegate(payable(E)).initializePortal(H);

        vm.prank(E);
        vm.expectRevert(PortalDelegate.PortalAlreadyInitialized.selector);
        PortalDelegate(payable(E)).initializePortal(H + 1);
    }

    /// @dev A zero binding is the unregistered sentinel; the delegate rejects it so a portal can never be bound
    ///      to H == 0.
    function test_initializePortal_revertWhen_zeroBinding() public {
        address E = _delegateOnly(PORTAL_PK);

        vm.prank(E);
        vm.expectRevert(PortalDelegate.InvalidPortalBinding.selector);
        PortalDelegate(payable(E)).initializePortal(0);
    }

    /// @dev H must be a canonical field element: H >= PRIME would not survive gnark's public-input reduction in
    ///      the portal-deposit proof, so the delegate rejects it at initialization.
    function test_initializePortal_revertWhen_bindingAtScalarField() public {
        address E = _delegateOnly(PORTAL_PK);

        vm.prank(E);
        vm.expectRevert(PortalDelegate.InvalidPortalBinding.selector);
        PortalDelegate(payable(E)).initializePortal(PRIME);
    }

    // ========== requestPortalDeposit integration: the pool reads E's account-side binding ==========

    function test_requestPortalDeposit_wrapsEthAndStoresMeasuredWethDelta() public {
        // Arrange
        address E = _makePortal(PORTAL_PK, H);
        uint96 amount = 12 ether;
        vm.deal(E, amount);
        // The delegate withholds a native gas reserve, so the measured WETH delta is the balance above it.
        uint96 wrapped = amount - uint96(NATIVE_GAS_RESERVE);
        uint256 expectedId =
            LibDigest.computePortalDepositId(block.chainid, address(pool), E, wethTokenId, wrapped, 0, H);

        // Act
        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, wethTokenId);

        // Assert
        (,,,,, uint96 recordedAmount,, uint256 recordedH) = pool.portalPendingDeposits(id);
        assertEq(id, expectedId, "WETH request id uses the measured wrapped amount");
        assertEq(recordedAmount, wrapped, "pending record stores the measured WETH delta");
        assertEq(recordedH, H, "pending record retains the portal binding");
        assertEq(weth.balanceOf(address(pool)), wrapped, "pool escrowed the wrapped value");
        assertEq(E.balance, NATIVE_GAS_RESERVE, "portal kept the native gas reserve");
    }

    function test_revertWhen_requestPortalDepositWrappedAmountBelowDust() public {
        // Arrange
        address E = _makePortal(PORTAL_PK, H);
        uint96 amount = 12 ether;
        vm.deal(E, amount);
        pool.setPortalMinSweep(wethTokenId, amount + 1);
        // Only the balance above the delegate's native gas reserve is wrapped and measured.
        uint96 wrapped = amount - uint96(NATIVE_GAS_RESERVE);

        // Act
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(IPrivacyBoost.SweepBelowDust.selector, wrapped, amount + 1));
        pool.requestPortalDeposit(E, wethTokenId);

        // Assert
        assertEq(E.balance, amount, "pool revert restored the portal ETH balance");
        assertEq(weth.balanceOf(E), 0, "pool revert removed the temporary WETH mint");
        assertEq(weth.balanceOf(address(pool)), 0, "pool retained no rejected WETH");
        assertEq(pool.portalCounter(E), 0, "rejected request created no pending portal record");
    }

    /// @dev End-to-end proof of the binding-at-account switch: after the owner initializes the binding in the
    ///      portal EOA's own storage, the pool's requestPortalDeposit STATICCALLS E.portalBinding() to read H
    ///      and keys the record with it. The recomputed id matching the H the owner set proves the pool sourced
    ///      the binding from E's storage, not a pool registry; deleting the staticcall (or reading a zero
    ///      binding) would change the id or revert PortalNotRegistered.
    function test_initializePortal_makesPortalImmediatelySweepable() public {
        address E = _makePortal(PORTAL_PK, H);
        token.mint(E, 100 ether);

        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);

        uint256 expectedId = LibDigest.computePortalDepositId(block.chainid, address(pool), E, tokenId, 100 ether, 0, H);
        assertEq(id, expectedId, "swept right after initializing -> the pool read H from E's portalBinding()");
    }

    /// @dev Two independently delegated EOAs keep independent bindings in their OWN account storage
    ///      (EIP-7201), the basis for one-portal-per-counterparty with unlinkable `H` values. Each
    ///      portalBinding() returns only that account's binding with no cross-contamination — the isolation a
    ///      single shared pool-side portalH registry could only give per-key, now inherent to per-account
    ///      storage.
    function test_distinctPortals_haveIndependentBindings() public {
        address E1 = _makePortal(PORTAL_PK, H);
        address E2 = _makePortal(PORTAL_PK_2, H + 1);

        assertTrue(E1 != E2, "distinct EOAs are distinct portals");
        assertEq(PortalDelegate(payable(E1)).portalBinding(), H, "first portal keeps its own binding");
        assertEq(PortalDelegate(payable(E2)).portalBinding(), H + 1, "second portal keeps its own binding");
    }

    /// @dev Sweeping an address that is NOT delegated to the portal code reverts PortalNotRegistered: the typed
    ///      portalBinding() staticcall trips Solidity's empty-code check on a plain EOA, the try/catch falls
    ///      through, and the sweep rejects up front. This is the catch-branch companion to the delegated-but-
    ///      uninitialized (portalBinding() == 0) rejection — together they cover both unregistered shapes.
    function test_requestPortalDeposit_revertWhen_notDelegated() public {
        address plain = makeAddr("plainEOA"); // never delegated, carries no portal code
        token.mint(plain, 100 ether);

        vm.prank(keeper);
        vm.expectRevert(IPrivacyBoost.PortalNotRegistered.selector);
        pool.requestPortalDeposit(plain, tokenId);
    }

    // ========== sweep: the pool-invoked sweep push ==========

    /// @dev The pool-invoked sweep pushes the portal's balance into the pool and the pool measures the
    ///      received delta. Driven through the real requestPortalDeposit so the full push+measure path runs.
    ///      Deleting the safeTransfer in sweep makes the pool measure a zero delta and the call reverts.
    function test_sweep_pushesBalanceToPool() public {
        address E = _makePortal(PORTAL_PK, H);
        token.mint(E, 250 ether);

        uint256 poolBefore = token.balanceOf(address(pool));
        vm.prank(keeper);
        pool.requestPortalDeposit(E, tokenId);

        assertEq(token.balanceOf(address(pool)) - poolBefore, 250 ether, "pool received the swept balance");
        assertEq(token.balanceOf(E), 0, "portal fully swept");
    }

    /// @dev The push honors the cap: with a balance above the pool's uint96 record ceiling, the portal
    ///      pushes exactly the cap and the remainder stays at `E` for the next sweep — no value lost.
    ///      Deleting the `min(balance, cap)` clamp would push the whole balance and the pool's over-push
    ///      guard would reject it (SweepAmountOverflow), so this asserts the clamped split explicitly.
    function test_sweep_honorsCapLeavingRemainderAtE() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 ceiling = uint256(type(uint96).max);
        uint256 excess = 4321;
        token.mint(E, ceiling + excess);

        vm.prank(keeper);
        pool.requestPortalDeposit(E, tokenId);

        assertEq(token.balanceOf(address(pool)), ceiling, "pool received exactly the cap");
        assertEq(token.balanceOf(E), excess, "remainder stays at E for the next sweep");
    }

    /// @dev The cap-leaves-remainder property is only useful if that remainder is RECOVERABLE on the NEXT
    ///      sweep — the design's reusability claim (IPortalSweepSource doc: "any remainder above the
    ///      uint96 record ceiling stays at E for the next sweep"). One sweep leaving a residual proves a
    ///      remainder is LEFT but not that the same `E` is sweepable again. Here a first sweep caps at the
    ///      ceiling and leaves `excess` at `E`; a SECOND requestPortalDeposit on the same `E` must then sweep
    ///      that `excess` to the pool, drain `E`, and produce a record keyed at the incremented counter == 1.
    ///      A regression breaking the per-`E` counter increment (PrivacyBoost.sol:787-788) or leaving the
    ///      remainder unsweepable would fail this — the one-shot residual test above would still pass.
    function test_sweep_honorsCapLeavingRemainderAtE_secondSweepRecoversRemainder() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 ceiling = uint256(type(uint96).max);
        uint96 excess = 4321;
        token.mint(E, ceiling + excess);

        // First sweep: caps at the ceiling, leaves `excess` at E, and uses counter == 0.
        vm.prank(keeper);
        uint256 firstId = pool.requestPortalDeposit(E, tokenId);
        assertEq(token.balanceOf(E), excess, "first sweep leaves the remainder at E");
        assertEq(
            firstId,
            LibDigest.computePortalDepositId(block.chainid, address(pool), E, tokenId, uint96(ceiling), 0, H),
            "first record keyed at counter == 0"
        );

        // Second sweep on the SAME E: the remainder is below the cap, so the whole `excess` moves and E
        // drains. The new record is keyed at counter == 1 — proof the per-E counter advanced, so the two
        // sweeps produce distinct ids/notes rather than colliding.
        uint256 poolBefore = token.balanceOf(address(pool));
        vm.prank(keeper);
        uint256 secondId = pool.requestPortalDeposit(E, tokenId);

        assertEq(token.balanceOf(address(pool)) - poolBefore, excess, "second sweep recovers the remainder to the pool");
        assertEq(token.balanceOf(E), 0, "E fully drained after the second sweep");
        assertEq(
            secondId,
            LibDigest.computePortalDepositId(block.chainid, address(pool), E, tokenId, excess, 1, H),
            "second record keyed at the incremented counter == 1"
        );
        assertTrue(firstId != secondId, "the two sweeps produced distinct portalDepositIds");
    }

    // ========== sweep: direct pool-pranked unit coverage of the push branches ==========

    /// @dev Direct unit coverage of `sweep`'s zero-balance skip branch (PortalDelegate.sol:97). Every sweep
    ///      driven through requestPortalDeposit reverts SweepBelowDust before a zero push can be observed,
    ///      so the `if (amount > 0)` guard is otherwise never exercised directly. Pranking the pool calls
    ///      `sweep` past the OnlyPool gate with an empty `E`: it must NOT revert and must move nothing.
    ///      Deleting the zero-skip would attempt a zero-value transfer here (harmless on a standard ERC-20
    ///      but a needless external call); this pins the no-op contract.
    function test_sweep_directPoolCall_zeroBalanceNoOp() public {
        address E = _makePortal(PORTAL_PK, H);

        uint256 poolBefore = token.balanceOf(address(pool));
        vm.prank(address(pool));
        PortalDelegate(payable(E)).sweep(address(token), type(uint96).max); // must not revert on a zero balance

        assertEq(token.balanceOf(E), 0, "nothing moved from an empty portal");
        assertEq(token.balanceOf(address(pool)), poolBefore, "pool balance unchanged by a zero-balance sweep");
    }

    /// @dev Direct unit coverage of the cap-clamp `<` boundary (PortalDelegate.sol:94, `balance < cap`) at the
    ///      EXACT equality point, which the requestPortalDeposit-driven tests never hit (they pass cap ==
    ///      uint96.max while the balance is far below). With balance == cap the clamp must take the `cap`
    ///      branch and move the FULL balance, draining `E`. Flipping the comparison to `<=`/`>` would push
    ///      `cap` either way here, so the boundary is only pinned by also covering the strictly-above case
    ///      below — together they fix the comparison direction.
    function test_sweep_directPoolCall_balanceEqualsCapMovesFullBalance() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 cap = 250 ether;
        token.mint(E, cap);

        uint256 poolBefore = token.balanceOf(address(pool));
        vm.prank(address(pool));
        PortalDelegate(payable(E)).sweep(address(token), cap);

        assertEq(token.balanceOf(address(pool)) - poolBefore, cap, "full balance moved when balance == cap");
        assertEq(token.balanceOf(E), 0, "E drained at the balance == cap boundary");
    }

    /// @dev Direct unit coverage of the cap-clamp when balance STRICTLY exceeds cap: exactly `cap` moves and
    ///      the remainder stays at `E`. Paired with the balance == cap test above, this fixes the clamp's
    ///      comparison direction — a flipped comparison would push the whole balance here and over-shoot the
    ///      cap. This is the direct-call analog of the requestPortalDeposit-driven cap test, isolating the
    ///      delegate arithmetic from the pool's own over-push guard.
    function test_sweep_directPoolCall_balanceAboveCapMovesExactlyCap() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 cap = 250 ether;
        uint256 over = 30 ether;
        token.mint(E, cap + over);

        uint256 poolBefore = token.balanceOf(address(pool));
        vm.prank(address(pool));
        PortalDelegate(payable(E)).sweep(address(token), cap);

        assertEq(token.balanceOf(address(pool)) - poolBefore, cap, "exactly cap moved when balance > cap");
        assertEq(token.balanceOf(E), over, "the strictly-above remainder stays at E");
    }

    /// @dev `sweep` is pool-only: a non-pool caller reverts with OnlyPool and no tokens move. This is the
    ///      load-bearing security gate — without it anyone could trigger a push and drain `E`. Deleting the
    ///      `msg.sender != pool` check flips this from revert to a successful out-of-band drain.
    function test_sweep_revertWhen_callerNotPool() public {
        address E = _makePortal(PORTAL_PK, H);
        token.mint(E, 100 ether);

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.OnlyPool.selector);
        PortalDelegate(payable(E)).sweep(address(token), type(uint256).max);

        assertEq(token.balanceOf(E), 100 ether, "balance untouched by the rejected non-pool sweep");
    }

    // ========== withdraw: self-only resting-funds escape hatch ==========

    /// @dev The rescue-forward: the pool refunds a CANCELLED deposit to `E`, and the owner then
    ///      forwards it from `E` to a chosen destination. Full flow — register, sweep, advance past the cancel
    ///      delay, cancel (pool refunds gross to E), then withdraw to the rescue destination. The
    ///      funds end up at the rescue destination; deleting `withdraw` (or its self-gate) breaks this exit.
    function test_withdraw_rescueForwardsCancelRefund() public {
        address E = _makePortal(PORTAL_PK, H);
        uint96 amount = 500 ether;
        token.mint(E, amount);

        vm.prank(keeper);
        uint256 id = pool.requestPortalDeposit(E, tokenId);
        assertEq(token.balanceOf(E), 0, "swept into escrow");

        // Past the cancel delay, the reclaim refunds the gross amount back to E (the portal).
        vm.roll(block.number + 257);
        pool.cancelPortalDeposit(id);
        assertEq(token.balanceOf(E), amount, "cancel refunded the gross amount to E");

        // The owner forwards the refund out of E to the rescue destination (self-call).
        vm.prank(E);
        PortalDelegate(payable(E)).withdraw(address(token), rescueDest, amount);

        assertEq(token.balanceOf(rescueDest), amount, "refund forwarded to the owner's rescue destination");
        assertEq(token.balanceOf(E), 0, "nothing left stuck at E");
    }

    /// @dev `withdraw` recovers a token NEVER registered with the protocol — one that can never be swept,
    ///      so the escape hatch is the only way out. A second, unregistered token sent to `E` is pulled out
    ///      by the owner. This is the "funds resting at E that cannot be swept" case.
    function test_withdraw_recoversUnregisteredToken() public {
        address E = _makePortal(PORTAL_PK, H);

        MockERC20 stray = new MockERC20();
        stray.mint(E, 77 ether);

        vm.prank(E);
        PortalDelegate(payable(E)).withdraw(address(stray), rescueDest, 77 ether);

        assertEq(stray.balanceOf(rescueDest), 77 ether, "unregistered token recovered to the owner");
        assertEq(stray.balanceOf(E), 0, "no unregistered funds stuck at E");
    }

    /// @dev `withdraw` takes an explicit `amount`, so a PARTIAL rescue must leave the residual at `E`. The
    ///      owner withdraws less than the resting balance; the destination receives exactly `amount` and the
    ///      remainder stays at `E` (still recoverable by a later withdraw). Hard-coding `withdraw` to move
    ///      the whole balance — ignoring `amount` — would fail this residual assertion.
    function test_withdraw_partialLeavesResidualAtE() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 resting = 100 ether;
        uint256 take = 40 ether;
        token.mint(E, resting);

        vm.prank(E);
        PortalDelegate(payable(E)).withdraw(address(token), rescueDest, take);

        assertEq(token.balanceOf(rescueDest), take, "destination received exactly the partial amount");
        assertEq(token.balanceOf(E), resting - take, "the un-withdrawn residual stays at E");
    }

    /// @dev `withdraw` of more than the resting balance must REVERT (SafeERC20 surfacing the token's
    ///      insufficient-balance error), never silently no-op or transfer a truncated amount. Asserts the
    ///      balance is fully untouched, so a partial/clamped transfer would also fail this. This guarantees
    ///      an over-amount owner mistake fails loudly rather than moving a wrong amount.
    function test_withdraw_revertWhen_amountExceedsBalance() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 resting = 50 ether;
        token.mint(E, resting);

        vm.prank(E);
        vm.expectRevert(); // ERC20InsufficientBalance bubbled through SafeERC20
        PortalDelegate(payable(E)).withdraw(address(token), rescueDest, resting + 1);

        assertEq(token.balanceOf(E), resting, "balance untouched by the reverted over-amount withdraw");
        assertEq(token.balanceOf(rescueDest), 0, "destination received nothing on the reverted withdraw");
    }

    /// @dev The most common real "funds at E" case: a REGISTERED token simply arrived at `E` and
    ///      was never swept — directly withdrawable by the owner WITHOUT any cancel/refund first. The other
    ///      registered-token withdraw test only reaches `E` via a cancel refund; this proves the escape hatch
    ///      works for a token that just landed and was never escrowed. Deleting `withdraw` (or its self-gate)
    ///      would strand a registered token that, for any reason, was never swept.
    function test_withdraw_recoversRegisteredTokenRestingAtE() public {
        address E = _makePortal(PORTAL_PK, H);
        uint256 resting = 123 ether;
        token.mint(E, resting); // a registered token that arrived but was never swept into the pool

        vm.prank(E);
        PortalDelegate(payable(E)).withdraw(address(token), rescueDest, resting);

        assertEq(token.balanceOf(rescueDest), resting, "registered token resting at E recovered to the owner");
        assertEq(token.balanceOf(E), 0, "no registered funds left stuck at E");
    }

    /// @dev `withdraw` is self-only: a non-self caller reverts with OnlySelf and the funds stay at `E`.
    ///      Deleting the self-gate would let anyone drain resting funds. Asserts the exact selector so a
    ///      generic revert cannot satisfy it, plus the unchanged balance.
    function test_withdraw_revertWhen_callerNotSelf() public {
        address E = _makePortal(PORTAL_PK, H);
        token.mint(E, 100 ether);

        vm.prank(keeper);
        vm.expectRevert(PortalDelegate.OnlySelf.selector);
        PortalDelegate(payable(E)).withdraw(address(token), keeper, 100 ether);

        assertEq(token.balanceOf(E), 100 ether, "resting funds untouched by the unauthorized withdraw");
    }

    /// @dev `withdraw` rejects the zero destination, so an owner mistake cannot burn funds to address(0).
    function test_withdraw_revertWhen_zeroDestination() public {
        address E = _makePortal(PORTAL_PK, H);
        token.mint(E, 10 ether);

        vm.prank(E);
        vm.expectRevert(PortalDelegate.ZeroAddress.selector);
        PortalDelegate(payable(E)).withdraw(address(token), address(0), 10 ether);
    }
}
