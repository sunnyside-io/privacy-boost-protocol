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

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IPrivacyBoost, IPortalSweepSource} from "src/interfaces/IPrivacyBoost.sol";
import {IWETH} from "src/interfaces/IWETH.sol";

/// @title PortalDelegate
/// @notice Shared EIP-7702 delegation target for the hidden-recipient portal-deposit flow — the portal
///         account is the owner's own EOA, delegated to this code.
/// @dev A portal owner makes their EOA the portal deposit address by signing an EIP-7702 authorization whose
///      designator (`0xef0100 || address(this-impl)`) points at this shared implementation; the EOA then runs
///      this code on calls to itself. ONE instance is deployed per chain and reused by every portal EOA.
///
///      The recipient binding lives in the portal EOA's OWN storage, written once via {initializePortal} /
///      {initializePortalWithSig} and read back by the pool through {portalBinding}. Under 7702 delegation
///      `SSTORE`/`SLOAD` act on the EOA's storage, not the shared implementation's, so each portal account
///      keeps an independent binding even though the code is shared; the slot is EIP-7201-namespaced so a
///      portal EOA reused for another purpose cannot collide. This is the only per-portal state; the portal's
///      resting balance lives on the EOA itself.
///
///      It supports owner-binding initialization, sweep, token withdrawal, and plain ETH reception. Two
///      differences follow from the portal account being a delegated EOA, not a deployed contract:
///        1. No constructor-time initialization — an EOA runs no constructor — so the binding is recorded by
///           an explicit `initializePortal` / `initializePortalWithSig` call after delegating.
///        2. The self-custody gate is a self-call check (`msg.sender == address(this)`), not Ownable: under
///           delegated execution `address(this)` IS the EOA, so only the EOA's own key can authorize
///           `initializePortal`/`withdraw`. There is no separate owner role and no protocol-held key. The
///           relayed `initializePortalWithSig` instead authenticates the EOA's own EIP-712 signature.
///
///      Recipient hiding is unchanged: the delegate holds no `recipientMPK` and no spend secret;
///      `recipientBinding` is a one-way commitment, and credited shielded notes are spendable only with the
///      separate nullifyingKey.
/// @custom:security-contact contact@sunnyside.io
contract PortalDelegate is IPortalSweepSource {
    using SafeERC20 for IERC20;

    /// @notice BN254 scalar field prime. The recipient binding is a public input to the portal-deposit proof
    ///         and gnark reduces public inputs mod this prime, so an out-of-range value would diverge from the
    ///         in-circuit value.
    /// @dev Defined locally (matching PrivacyBoost.sol) rather than imported, so the delegate carries no
    ///      dependency on the pool's constant layout.
    uint256 private constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Native balance a portal EOA always keeps back from a WETH sweep, so its owner can still pay for
    ///         one self-gated {withdraw} call.
    /// @dev `requestPortalDeposit` is permissionless and the pool sweeps with an effectively unbounded cap, so
    ///      without a floor any third party could wrap and escrow the owner's entire gas balance the moment it
    ///      arrives, front-running every top-up and permanently denying the raw-token escape hatch. Reserving a
    ///      floor breaks that race: a top-up is only wrappable above the floor, so the owner can always fund one
    ///      more transaction. Sized for the OP-stack L2s this protocol targets, where a ~50,000-gas call settles
    ///      for orders of magnitude less than this, and small enough to be immaterial next to any sweep worth
    ///      escrowing. Private rather than public because `E` is a dedicated deposit account, not a
    ///      general-purpose wallet, so the floor is an internal invariant and not an ABI surface. The withheld
    ///      remainder is not stranded and needs no dedicated exit: `E` is the owner's own EOA, and a 7702
    ///      designator changes what runs when `E` is CALLED, never `E`'s ability to originate its own
    ///      transaction, so the owner's key moves native ETH out exactly as it would on any undelegated EOA.
    uint256 private constant NATIVE_GAS_RESERVE = 0.001 ether;

    // keccak256(abi.encode(uint256(keccak256("privacyboost.portal.delegate")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PORTAL_DELEGATE_STORAGE =
        0x6f15d7d1eed17be7454b30472f96e05216a5c7770ffec7ea6efbc3b7ab28e800;

    /// @dev EIP-712 domain + typehash for the owner's relayed initialization signature. The off-chain signer
    ///      builds the same `PortalBind` struct; the struct binds the target pool and the domain binds chainId
    ///      + this account (verifyingContract == the portal account), so a signature cannot replay to another
    ///      chain, another portal, or a delegate pointing at a different pool.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant _PORTAL_BIND_NAME_HASH = keccak256("PB:PrivacyBoost");
    bytes32 private constant _PORTAL_BIND_VERSION_HASH = keccak256("1");
    bytes32 private constant _PORTAL_BIND_TYPEHASH =
        keccak256("PortalBind(address portal,address pool,uint256 recipientBinding)");

    /// @notice The Privacy Boost pool every delegated portal pushes swept funds to.
    /// @dev Immutable, baked into the shared delegate code, so it resolves to the right pool when an EOA runs
    ///      this code under its 7702 designator. One pool per deployment: the sweep-push target is fixed, so
    ///      no second pool can solicit a push from a portal.
    IPrivacyBoost public immutable pool;

    /// @notice The registered wrapped native token used when sweeping ETH held by a portal EOA.
    IWETH public immutable wrappedNativeToken;

    /// @dev The deployed implementation address, baked into its runtime code. Under EIP-7702 execution,
    ///      `address(this)` is the delegated EOA instead, which distinguishes the intended receive context.
    address private immutable _IMPLEMENTATION = address(this);

    /// @custom:storage-location erc7201:privacyboost.portal.delegate
    /// @dev Namespaced per EIP-7201 so the binding cannot collide with any other storage a future reuse of
    ///      the portal EOA introduces. `recipientBinding == 0` is the unregistered sentinel.
    struct PortalDelegateStorage {
        uint256 recipientBinding;
    }

    /// @notice Emitted when this portal EOA records its recipient binding once. `portal` is the EOA itself.
    /// @param portal The portal EOA that recorded the binding
    /// @param recipientBinding The recipient binding written to the portal's own storage
    event PortalInitialized(address indexed portal, uint256 recipientBinding);

    /// @notice Emitted when this portal EOA receives a positive amount of native ETH.
    /// @param amount The amount of native ETH received
    event PortalETHReceived(uint256 amount);

    /// @notice Thrown when `sweep` is called by anyone other than the registered pool.
    error OnlyPool();

    /// @notice Thrown when a self-gated call (`initializePortal`/`withdraw`) is not made by the portal EOA.
    /// @dev Under 7702 delegation `address(this)` is the EOA, so `msg.sender == address(this)` holds only when
    ///      the EOA calls its own delegated code — the self-custody gate that replaces Ownable.
    error OnlySelf();

    /// @notice Thrown when a must-be-non-zero argument (the pool, a withdraw destination) is the zero address.
    error ZeroAddress();

    /// @notice Thrown when the recipient binding is zero or not a canonical field element.
    error InvalidPortalBinding();

    /// @notice Thrown when this portal already has a non-zero binding — initialization is write-once.
    error PortalAlreadyInitialized();

    /// @notice Thrown when a relayed `initializePortalWithSig` signature does not recover to this EOA.
    error InvalidPortalSignature();

    /// @notice Thrown when ETH is sent directly to the shared implementation rather than a delegated EOA.
    error DirectImplementationCall();

    /// @notice Thrown when the configured wrapped native token has no deployed code.
    error WrappedNativeTokenHasNoCode();

    /// @param pool_ The Privacy Boost pool every delegated portal sweeps into.
    /// @param wrappedNativeToken_ The WETH contract used to wrap native ETH during WETH sweeps.
    /// @dev Reject a zero pool so the shared delegate can never be deployed pointing at no pool, which would
    ///      brick sweep for every EOA that delegates to it. WETH must be deployed code because native ETH
    ///      cannot be recovered from a successful value call to a non-contract address.
    constructor(IPrivacyBoost pool_, IWETH wrappedNativeToken_) {
        if (address(pool_) == address(0) || address(wrappedNativeToken_) == address(0)) revert ZeroAddress();
        if (address(wrappedNativeToken_).code.length == 0) revert WrappedNativeTokenHasNoCode();
        pool = pool_;
        wrappedNativeToken = wrappedNativeToken_;
    }

    /// @notice Accept plain ETH transfers to preserve normal EOA reception while delegated under EIP-7702.
    /// @dev Reject direct transfers to the shared implementation because it has no key or native-ETH exit.
    ///      The positive-value event is the only additional work and remains safe under the 2,300-gas stipend.
    receive() external payable {
        if (address(this) == _IMPLEMENTATION) revert DirectImplementationCall();
        if (msg.value > 0) emit PortalETHReceived(msg.value);
    }

    /// @notice The recipient binding recorded in this portal EOA's own storage (0 if not yet initialized).
    /// @dev The pool staticcalls this at `requestPortalDeposit` to read the binding the deposit proof opens;
    ///      a zero return means the portal is unregistered.
    /// @return The recorded recipient binding, or 0 when the portal is unregistered
    function portalBinding() external view returns (uint256) {
        return _portalStorage().recipientBinding;
    }

    /// @notice Self-initialize this portal EOA's recipient binding (write-once), called by the EOA itself.
    /// @dev Self-gated: `msg.sender == address(this)` holds only when the EOA calls its own delegated code, so
    ///      no third party can initialize on its behalf. The gas-paying owner uses this; a relayer uses
    ///      {initializePortalWithSig}.
    /// @param recipientBinding The binding `Poseidon(DOMAIN_PORTAL_BIND, recipientMPK, blind)` to record.
    function initializePortal(uint256 recipientBinding) external {
        if (msg.sender != address(this)) revert OnlySelf();
        _setBinding(recipientBinding);
    }

    /// @notice Relayed initialize: record the recipient binding once the owner's EIP-712 `PortalBind`
    ///         signature authorizes it, so a relayer can pay the gas.
    /// @dev Verified with `ECDSA.recover` (NOT `SignatureChecker`): once the owner has delegated, this EOA has
    ///      code, and `SignatureChecker` would route a coded account through EIP-1271 — but the authority here
    ///      is the EOA's own key, which `ecrecover` recovers regardless of installed code. This enables the
    ///      gasless one-shot install+register: an EIP-7702 type-4 transaction installs this code via the
    ///      authorization list and calls this function in the same transaction.
    /// @param recipientBinding The recipient binding to record.
    /// @param sig The EOA owner's EIP-712 `PortalBind` signature.
    function initializePortalWithSig(uint256 recipientBinding, bytes calldata sig) external {
        bytes32 structHash =
            keccak256(abi.encode(_PORTAL_BIND_TYPEHASH, address(this), address(pool), recipientBinding));
        bytes32 domainSeparator = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _PORTAL_BIND_NAME_HASH, _PORTAL_BIND_VERSION_HASH, block.chainid, address(this)
            )
        );
        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, structHash);
        if (ECDSA.recover(digest, sig) != address(this)) revert InvalidPortalSignature();
        _setBinding(recipientBinding);
    }

    /// @inheritdoc IPortalSweepSource
    /// @dev Pool-only push: transfer `min(balance, cap)` to the pool, which re-measures the received delta
    ///      itself and does not trust this contract. A WETH sweep first wraps only the native balance needed
    ///      to fill the remaining cap, above {NATIVE_GAS_RESERVE}, preserving any native remainder for a later
    ///      sweep and always leaving the owner enough to fund one escape-hatch call. The only
    ///      security property required here is the caller gate — ONLY the registered pool may trigger a push,
    ///      otherwise anyone could drain the portal's balance to the pool out of band. Capping at `cap` (the
    ///      pool's uint96 record ceiling) leaves any remainder at the portal for the next sweep.
    function sweep(address token, uint256 cap) external override {
        if (msg.sender != address(pool)) revert OnlyPool();

        uint256 balance = IERC20(token).balanceOf(address(this));
        if (token == address(wrappedNativeToken) && balance < cap) {
            uint256 remainingCap = cap - balance;
            uint256 nativeBalance = address(this).balance;
            // Only the balance above the reserve is sweepable, so a griefer front-running a gas top-up can
            // skim the surplus but can never zero the account out from under its owner.
            uint256 wrappable = nativeBalance > NATIVE_GAS_RESERVE ? nativeBalance - NATIVE_GAS_RESERVE : 0;
            uint256 wrapAmount = wrappable < remainingCap ? wrappable : remainingCap;
            if (wrapAmount > 0) {
                // Credit `wrapAmount` directly instead of re-reading the balance. The high-level call already
                // bubbles a failed deposit, and the wrapped-native token is immutable and code-checked at
                // construction. An under-mint therefore cannot over-push: the transfer below would exceed the
                // real balance and revert, and the pool re-measures its own received delta regardless.
                wrappedNativeToken.deposit{value: wrapAmount}();
                balance += wrapAmount;
            }
        }
        uint256 amount = balance < cap ? balance : cap;
        // A zero push is harmless (the pool measures a 0 delta and reverts SweepBelowDust), but skip the
        // transfer to avoid a needless zero-value token call.
        if (amount > 0) {
            IERC20(token).safeTransfer(address(pool), amount);
        }
    }

    /// @notice Self-authenticated raw-token withdraw of funds resting at this portal EOA.
    /// @dev The single escape hatch for every "funds resting at the portal" case: a cancel refund the pool
    ///      returned to the portal, a token never registered with the protocol (so it can never be swept), or
    ///      an abandoned-portal remainder. Self-gated (the EOA's key is the sole authority — no owner role),
    ///      with the destination supplied per call so the owner routes reclaimed funds anywhere. It touches no
    ///      pool state and no binding, so it can never redirect a credit or alter escrow — it only moves
    ///      tokens already resting at the portal.
    /// @param token The ERC-20 token to withdraw.
    /// @param to The destination to send the tokens to.
    /// @param amount The amount to withdraw.
    function withdraw(address token, address to, uint256 amount) external {
        if (msg.sender != address(this)) revert OnlySelf();
        if (to == address(0)) revert ZeroAddress();
        IERC20(token).safeTransfer(to, amount);
    }

    /// @dev Validate and store the recipient binding write-once, then announce it. Zero is the unregistered
    ///      sentinel and a value at or above SNARK_SCALAR_FIELD would not survive gnark's public-input reduction;
    ///      mirrors the pool's former `_recordPortalBinding` guard. Write-once: a non-zero binding cannot be
    ///      overwritten through this delegate.
    function _setBinding(uint256 recipientBinding) private {
        if (recipientBinding == 0 || recipientBinding >= SNARK_SCALAR_FIELD) revert InvalidPortalBinding();
        PortalDelegateStorage storage $ = _portalStorage();
        if ($.recipientBinding != 0) revert PortalAlreadyInitialized();
        $.recipientBinding = recipientBinding;
        emit PortalInitialized(address(this), recipientBinding);
    }

    /// @dev EIP-7201 namespaced storage accessor for this portal EOA's binding.
    function _portalStorage() private pure returns (PortalDelegateStorage storage $) {
        assembly ("memory-safe") {
            $.slot := _PORTAL_DELEGATE_STORAGE
        }
    }
}
