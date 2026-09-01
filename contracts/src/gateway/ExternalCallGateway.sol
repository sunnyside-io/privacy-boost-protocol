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

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {GatewayAction, GatewaySlot} from "src/interfaces/IStructs.sol";
import {IGatewayExecutor} from "src/interfaces/IGateway.sol";

/// @notice Generic allowance-pull executor for signed external calls.
/// @dev The target call intentionally copies no returndata. Server-side policy is a liveness
///      filter only; on-chain safety comes from exact input consumption, measured output, and
///      PrivacyBoost fallback routing.
/// @custom:security-contact contact@sunnyside.io
contract ExternalCallGateway is IGatewayExecutor, Ownable2Step {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    /// @notice Allowlist policy for one external target and function selector.
    /// @param allowed Whether calls matching the policy may execute.
    /// @param inputTokenId Required input token ID, or zero to accept any registered input token.
    /// @param outputTokenId Required output token ID, or zero to accept any registered output token.
    struct CallPolicy {
        bool allowed;
        uint16 inputTokenId;
        uint16 outputTokenId;
    }

    /// @notice Enumerable view of an installed call policy.
    /// @param target Contract called by the gateway.
    /// @param selector Function selector allowed on the target.
    /// @param policy Token constraints associated with the target and selector.
    struct CallPolicyEntry {
        address target;
        bytes4 selector;
        CallPolicy policy;
    }

    /// @notice PrivacyBoost pool authorized to execute gateway settlements.
    address public immutable pool;

    /// @notice Whether new gateway execution is paused.
    bool public paused;
    /// @notice Account allowed to pause execution and remove call policies alongside the owner.
    address public guardian;

    mapping(bytes32 policyKey => CallPolicy policy) private _callPolicies;
    EnumerableSet.Bytes32Set private _policyKeys;

    /// @notice Emitted when the guardian account is set or cleared.
    /// @param guardian New guardian address, or the zero address when guardian authority is disabled.
    event GuardianUpdated(address indexed guardian);

    /// @notice Emitted when gateway execution is paused or resumed.
    /// @param paused True when new gateway calls are blocked, false when they are allowed again.
    event PausedUpdated(bool paused);

    /// @notice Emitted when a call policy is installed, replaced, or removed.
    /// @param target Contract the policy applies to.
    /// @param selector Function selector the policy applies to.
    /// @param allowed True when the policy is installed or replaced, false when it is removed.
    /// @param inputTokenId Required input token ID of the installed policy, zero when unconstrained or removed.
    /// @param outputTokenId Required output token ID of the installed policy, zero when unconstrained or removed.
    event CallPolicyUpdated(
        address indexed target, bytes4 indexed selector, bool allowed, uint16 inputTokenId, uint16 outputTokenId
    );

    /// @notice Thrown when settlement is called by any account other than the immutable pool.
    error NotPool();

    /// @notice Thrown when a pause or a policy removal is called by neither the owner nor the guardian.
    error NotGuardianOrOwner();

    /// @notice Thrown when a gateway call is attempted while execution is paused.
    error Paused();

    /// @notice Thrown when a sweep to the pool is attempted while execution is not paused.
    /// @dev Requiring the pause keeps the sweep from racing an in-flight settlement's balance accounting.
    error NotPaused();

    /// @notice Thrown when the constructor pool address is zero or holds no deployed code.
    error InvalidPool();

    /// @notice Thrown when the slot is not an external call, its target is zero, or its calldata carries no selector.
    error RouteMismatch();

    /// @notice Thrown when the low-level call to the external target reverts.
    error TargetCallFailed();

    /// @notice Thrown when the input token balance after the target call differs from the balance before the pull.
    /// @dev Equality with the pre-pull balance is what proves the target consumed exactly the pulled amount.
    error InputConsumedNotExact();

    /// @notice Thrown when settlement is requested with a zero input amount.
    error ZeroInputAmount();

    /// @notice Thrown when the measured output is below the slot receipt's minimum output amount.
    /// @dev Checked on the gateway delta and again on the pool balance, so a fee-on-transfer output cannot pass.
    error OutputBelowMin();

    /// @notice Thrown when an installed policy has a zero target, a zero selector, a codeless target, or is disabled.
    /// @dev Policies are withdrawn with `removeCallPolicy` rather than installed with `allowed` set to false.
    error InvalidCallPolicy();

    /// @notice Thrown when a policy index is at or past the policy count, or a page start is past it.
    /// @dev A page start equal to the policy count is accepted and returns an empty page.
    error PolicyIndexOutOfBounds();

    /// @notice Thrown when the batch target, selector, and policy arrays do not all have the same length.
    error PolicyBatchLengthMismatch();

    /// @notice Thrown when no enabled policy is installed for the slot's target and calldata selector.
    error CallNotAllowed();

    /// @notice Thrown when the settlement input token or the receipt output token violates the matched policy.
    /// @dev Only a nonzero policy token ID constrains a settlement, so a zero ID accepts any registered token.
    error PolicyTokenMismatch();

    /// @dev Restricts settlement execution to the immutable PrivacyBoost pool.
    modifier onlyPool() {
        if (msg.sender != pool) revert NotPool();
        _;
    }

    /// @dev Prevents new gateway calls while emergency pause is active.
    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    /// @notice Deploy the gateway for one PrivacyBoost pool and owner.
    /// @param pool_ PrivacyBoost pool that may invoke gateway settlement.
    /// @param initialOwner Account that administers guardians, policies, unpausing, and token sweeps.
    constructor(address pool_, address initialOwner) Ownable(initialOwner) {
        if (pool_ == address(0) || pool_.code.length == 0) revert InvalidPool();
        pool = pool_;
    }

    /// @notice Set the account allowed to pause execution and remove policies.
    /// @dev Setting the zero address disables guardian authority. Only the owner may call this function.
    /// @param newGuardian New guardian address.
    function setGuardian(address newGuardian) external onlyOwner {
        guardian = newGuardian;
        emit GuardianUpdated(newGuardian);
    }

    /// @notice Pause new gateway calls.
    /// @dev The owner or guardian may pause. Only the owner may unpause.
    function pause() external {
        if (msg.sender != owner() && msg.sender != guardian) revert NotGuardianOrOwner();
        paused = true;
        emit PausedUpdated(true);
    }

    /// @notice Resume gateway calls after an emergency pause.
    /// @dev Only the owner may call this function.
    function unpause() external onlyOwner {
        paused = false;
        emit PausedUpdated(false);
    }

    /// @notice Install or replace one allowed target and selector policy.
    /// @dev The target must be deployed code, the selector must be nonzero, and the policy must be enabled.
    /// @param target Contract that the gateway may call.
    /// @param selector Function selector allowed on the target.
    /// @param policy Enabled policy and optional input and output token constraints.
    function setCallPolicy(address target, bytes4 selector, CallPolicy calldata policy) external onlyOwner {
        _setCallPolicy(target, selector, policy);
    }

    /// @notice Install or replace multiple call policies in one transaction.
    /// @dev Reverts unless all arrays have equal length and every entry satisfies the single-policy validation.
    /// @param targets Contracts that the gateway may call.
    /// @param selectors Function selectors allowed on the corresponding targets.
    /// @param policies Enabled policies and token constraints for the corresponding target and selector pairs.
    function setCallPolicies(address[] calldata targets, bytes4[] calldata selectors, CallPolicy[] calldata policies)
        external
        onlyOwner
    {
        if (targets.length != selectors.length || targets.length != policies.length) {
            revert PolicyBatchLengthMismatch();
        }
        for (uint256 i = 0; i < targets.length; ++i) {
            _setCallPolicy(targets[i], selectors[i], policies[i]);
        }
    }

    /// @notice Remove an installed target and selector policy.
    /// @dev The owner or guardian may remove a policy. Removing an absent policy has no effect.
    /// @param target Contract whose policy is removed.
    /// @param selector Function selector whose policy is removed.
    function removeCallPolicy(address target, bytes4 selector) external {
        if (msg.sender != owner() && msg.sender != guardian) revert NotGuardianOrOwner();
        bytes32 key = _policyKey(target, selector);
        if (!_policyKeys.remove(key)) return;
        delete _callPolicies[key];
        emit CallPolicyUpdated(target, selector, false, 0, 0);
    }

    /// @notice Return the policy installed for a target and selector pair.
    /// @param target Contract used to derive the policy key.
    /// @param selector Function selector used to derive the policy key.
    /// @return The installed policy, or the zero-value policy when the key is absent.
    function getCallPolicy(address target, bytes4 selector) external view returns (CallPolicy memory) {
        return _callPolicies[_policyKey(target, selector)];
    }

    /// @notice Return the number of installed call policies.
    /// @return The number of enumerable policy keys.
    function policyKeyCount() external view returns (uint256) {
        return _policyKeys.length();
    }

    /// @notice Return one installed policy by enumerable index.
    /// @param i Zero-based index in the policy set.
    /// @return The target, selector, and policy stored at the index.
    function policyEntryAt(uint256 i) external view returns (CallPolicyEntry memory) {
        if (i >= _policyKeys.length()) revert PolicyIndexOutOfBounds();
        return _entryAt(i);
    }

    /// @notice Return a bounded page of installed policies.
    /// @dev The page is truncated at the current policy count. A start equal to the count returns an empty page.
    /// @param start Zero-based index of the first requested policy.
    /// @param count Maximum number of policies to return.
    /// @return entries Policies beginning at `start`, up to `count` entries or the end of the set.
    function policyEntries(uint256 start, uint256 count) external view returns (CallPolicyEntry[] memory entries) {
        uint256 total = _policyKeys.length();
        if (start > total) revert PolicyIndexOutOfBounds();
        uint256 end = start + count;
        if (end > total) end = total;
        entries = new CallPolicyEntry[](end - start);
        for (uint256 i = start; i < end; ++i) {
            entries[i - start] = _entryAt(i);
        }
    }

    /// @notice Sweep tokens stranded on the gateway by direct transfers or donations.
    /// @dev Steady-state balances are zero. Only the owner may sweep, the gateway must be paused, and funds
    ///      can move only to the pool so the sweep cannot race an in-flight settlement's balance accounting.
    /// @param token ERC-20 token whose full gateway balance is transferred to the pool.
    function sweepToPool(address token) external onlyOwner {
        if (!paused) revert NotPaused();
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance == 0) return;
        IERC20(token).safeTransfer(pool, balance);
    }

    /// @inheritdoc IGatewayExecutor
    function executeGatewayCall(
        uint16 inputTokenId,
        address inputTokenAddress,
        address outputTokenAddress,
        uint256 inputAmount,
        GatewaySlot calldata slot
    ) external onlyPool whenNotPaused {
        if (slot.action != GatewayAction.ExternalCall) revert RouteMismatch();
        if (slot.target == address(0) || slot.callData.length < 4) revert RouteMismatch();
        // Defense in depth: the pool already rejects a zero-amount withdrawal before routing here, but
        // the executor validates it too so it never relies on the caller for this invariant. A zero-input
        // settlement would pull nothing and could only measure a zero output delta.
        if (inputAmount == 0) revert ZeroInputAmount();

        bytes4 selector = bytes4(slot.callData[:4]);
        CallPolicy memory policy = _callPolicies[_policyKey(slot.target, selector)];
        if (!policy.allowed) revert CallNotAllowed();
        if (policy.inputTokenId != 0 && inputTokenId != policy.inputTokenId) revert PolicyTokenMismatch();
        if (policy.outputTokenId != 0 && slot.receipt.outputTokenId != policy.outputTokenId) {
            revert PolicyTokenMismatch();
        }

        IERC20 inputToken = IERC20(inputTokenAddress);
        IERC20 outputToken = IERC20(outputTokenAddress);

        uint256 inputBefore = inputToken.balanceOf(address(this));
        uint256 outputBefore = outputToken.balanceOf(address(this));
        uint256 poolOutputBefore = outputToken.balanceOf(pool);

        inputToken.safeTransferFrom(pool, address(this), inputAmount);

        inputToken.forceApprove(slot.target, inputAmount);
        bool ok = _callNoReturndataCopy(slot.target, slot.callData);
        if (!ok) revert TargetCallFailed();
        inputToken.forceApprove(slot.target, 0);

        if (inputToken.balanceOf(address(this)) != inputBefore) revert InputConsumedNotExact();

        uint256 outputDelta = outputToken.balanceOf(address(this)) - outputBefore;
        if (outputDelta < slot.receipt.minOutputAmount) revert OutputBelowMin();
        outputToken.safeTransfer(pool, outputDelta);
        if (outputToken.balanceOf(pool) < poolOutputBefore + slot.receipt.minOutputAmount) revert OutputBelowMin();
    }

    /// @dev Calls `target` with all remaining gas and deliberately copies no returndata, which bounds returndata
    ///      copy cost. The caller observes only whether the target call succeeded.
    /// @param target Contract receiving the call.
    /// @param callData Complete calldata forwarded to the target.
    /// @return ok Whether the low-level call succeeded.
    function _callNoReturndataCopy(address target, bytes calldata callData) internal returns (bool ok) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, callData.offset, callData.length)
            ok := call(gas(), target, 0, ptr, callData.length, 0, 0)
            mstore(0x40, add(ptr, and(add(callData.length, 0x3f), not(0x1f))))
        }
    }

    /// @dev Validates and stores one enabled policy, adds its packed key to the enumerable set, and emits an update.
    /// @param target Deployed contract that the gateway may call.
    /// @param selector Nonzero function selector allowed on the target.
    /// @param policy Enabled policy and optional token constraints.
    function _setCallPolicy(address target, bytes4 selector, CallPolicy calldata policy) internal {
        if (target == address(0) || selector == bytes4(0) || !policy.allowed) revert InvalidCallPolicy();
        // A codeless target can never satisfy the call, so reject the
        // misconfiguration when the policy is installed.
        if (target.code.length == 0) revert InvalidCallPolicy();
        bytes32 key = _policyKey(target, selector);
        _callPolicies[key] = policy;
        _policyKeys.add(key);
        emit CallPolicyUpdated(target, selector, true, policy.inputTokenId, policy.outputTokenId);
    }

    /// @dev Decodes the packed key at an enumerable-set index and loads its policy.
    /// @param i Zero-based index in the policy set.
    /// @return entry Target, selector, and policy stored at the index.
    function _entryAt(uint256 i) internal view returns (CallPolicyEntry memory entry) {
        bytes32 key = _policyKeys.at(i);
        (address target, bytes4 selector) = _decodePolicyKey(key);
        entry = CallPolicyEntry({target: target, selector: selector, policy: _callPolicies[key]});
    }

    /// @dev Packs the target into the high 20 bytes and the selector into the following 4 bytes.
    /// @param target Contract address encoded in the key.
    /// @param selector Function selector encoded in the key.
    /// @return Packed key used by the mapping and enumerable set.
    function _policyKey(address target, bytes4 selector) internal pure returns (bytes32) {
        return bytes32(bytes20(target)) | (bytes32(selector) >> 160);
    }

    /// @dev Reverses `_policyKey` by extracting the high 20-byte address and following 4-byte selector.
    /// @param key Packed policy key.
    /// @return target Contract address encoded in the key.
    /// @return selector Function selector encoded in the key.
    function _decodePolicyKey(bytes32 key) internal pure returns (address target, bytes4 selector) {
        // _policyKey stores the address in the high 20 bytes by construction.
        // forge-lint: disable-next-line(unsafe-typecast)
        target = address(bytes20(key));
        // Shifting moves the packed selector into the high 4 bytes before truncation.
        // forge-lint: disable-next-line(unsafe-typecast)
        selector = bytes4(key << 160);
    }
}
