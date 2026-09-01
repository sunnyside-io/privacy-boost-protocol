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
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {SPENDABLE_NPK_FLOOR} from "src/interfaces/Constants.sol";
import {
    Withdrawal,
    PendingDeposit,
    DepositOrigin,
    DepositCiphertext,
    GatewayAction,
    GatewayReceipt,
    GatewaySlot,
    GatewayRoute,
    GatewaySettlementOutcome,
    RescueKind
} from "src/interfaces/IStructs.sol";
import {IGatewayExecutor} from "src/interfaces/IGateway.sol";
import {IPrivacyBoost} from "src/interfaces/IPrivacyBoost.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPoolShared} from "src/lib/LibPoolShared.sol";

/// @title LibGateway
/// @notice Generic gateway execution and rescue logic extracted from PrivacyBoost to keep
///         the implementation bytecode under the EIP-170 limit. Functions are deployed as an external
///         (delegatecall) library: they execute against the pool's storage via the passed storage
///         references, so `address(this)` is the pool and `msg.sender` is preserved. Config immutables
///         (`tokenRegistry`, `cancelDelay`) cannot cross the delegatecall boundary
///         and are passed in by the core, which reads them from its own bytecode-baked values.
/// @custom:security-contact contact@sunnyside.io
library LibGateway {
    bytes32 internal constant AUTHORITY_RESCUE_DOMAIN = keccak256("PB:GATEWAY:AUTHORITY_RESCUE:v1");
    using SafeERC20 for IERC20;

    /// @dev BN254 scalar field modulus. Mirrors `PrivacyBoost.SNARK_SCALAR_FIELD`.
    uint256 private constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @dev Per-slot gas retained for everything that must still run after the untrusted gateway call
    ///      returns. The settlement loop reserves this amount for every outstanding Gateway slot, and
    ///      it is deliberately required in two distinct contexts:
    ///      - inside the isolated frame, for allowance cleanup, token-delta validation, and recording
    ///        the normal `Executed` or `Fallback` outcome;
    ///      - in the parent frame, for the fallback deposit record when the isolated frame itself runs
    ///        out of gas and the parent has to recover the slot locally.
    ///      Both uses are post-execution work, hence the name, and both must fit or a starved slot
    ///      would take the surrounding epoch down with it.
    uint256 private constant GATEWAY_POST_EXECUTION_GAS_RESERVE = 500_000;

    /// @dev Matches the relay's conservative allowance for one plain ERC-20 withdrawal.
    uint256 private constant PLAIN_WITHDRAWAL_GAS_RESERVE = 250_000;

    /// @dev Retained after all withdrawals for the tree update and EpochSubmitted event.
    uint256 private constant EPOCH_FINALIZATION_GAS_RESERVE = 250_000;

    /// @dev Parent-frame allowance for ABI-encoding a self-call and handling its result.
    ///      The calldata term prevents a large but permitted Gateway payload from consuming
    ///      gas reserved for later withdrawals while Solidity builds the isolated call.
    uint256 private constant GATEWAY_SELF_CALL_BASE_GAS_RESERVE = 100_000;
    uint256 private constant GATEWAY_SELF_CALL_GAS_PER_CALLDATA_BYTE = 16;

    /// @dev Domain tag for EIP-191 rescue signatures. Mirrors `PrivacyBoost._RESCUE_DOMAIN`.
    bytes32 private constant _RESCUE_DOMAIN = keccak256("PB:RESCUE:v1");

    // ─────────────── Route-aware withdrawal execution ───────────────

    /// @notice Route-aware withdrawal execution. An empty `gatewaySlots` collapses to the plain path:
    ///         route `None` transfers out, any gateway-routed withdrawal destination reverts
    ///         `MissingGatewaySlot`.
    ///         Per-slot outcomes are only observable through `processGatewayWithdrawalsForSim`;
    ///         the production path records settlement via events and pending deposits.
    /// @param gatewayRoute Per-address approved-route map
    /// @param pendingDeposits Pending-deposit map that gateway-origin redeposits are recorded into
    /// @param depositNonces Per-gateway nonce map used to derive unique redeposit request ids
    /// @param tokenRegistry Registry used to resolve token ids to their ERC-20 addresses
    /// @param withdrawals The withdrawals to settle
    /// @param gatewaySlots Gateway settlement slots, ascending by the withdrawal index they pair with
    function processGatewayWithdrawals(
        mapping(address => GatewayRoute) storage gatewayRoute,
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        ITokenRegistry tokenRegistry,
        Withdrawal[] calldata withdrawals,
        GatewaySlot[] calldata gatewaySlots
    ) external {
        _validateGatewaySlotsStrictAscending(gatewaySlots);

        // Settlement-gas budgeting exists solely to stop an untrusted gateway from starving the work
        // queued behind it. An epoch with no Gateway slots hands control to no such target, so it
        // carries no budget and no floor and keeps the plain-withdrawal gas profile it always had.
        // Enforcing the floor there would reject ordinary epochs the relay does not preflight.
        bool hasGatewayBudget = gatewaySlots.length != 0;
        uint256 remainingSettlementGas;
        if (hasGatewayBudget) {
            remainingSettlementGas = _buildSettlementGasBudget(withdrawals.length, gatewaySlots);
            _requireSettlementGas(remainingSettlementGas);
        }

        uint256 gatewayCursor = 0;
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            Withdrawal calldata withdrawal = withdrawals[i];
            GatewayRoute route = gatewayRoute[withdrawal.to];
            bool hasSlot =
                gatewayCursor < gatewaySlots.length && uint256(gatewaySlots[gatewayCursor].withdrawalIndex) == i;

            if (route == GatewayRoute.None) {
                if (hasSlot) revert IPrivacyBoost.UnexpectedGatewaySlot();
                if (hasGatewayBudget) {
                    _requireSettlementGas(remainingSettlementGas);
                    remainingSettlementGas -= PLAIN_WITHDRAWAL_GAS_RESERVE;
                }
                LibPoolShared.transferToken(tokenRegistry, withdrawal.tokenId, withdrawal.to, withdrawal.amount);
            } else if (route == GatewayRoute.Sync) {
                // Unreachable without slots: an empty `gatewaySlots` leaves `hasSlot` false and reverts.
                if (!hasSlot) revert IPrivacyBoost.MissingGatewaySlot();
                GatewaySlot calldata slot = gatewaySlots[gatewayCursor];
                uint256 selfCallGas = _gatewaySelfCallGasReserve(slot);
                remainingSettlementGas -= GATEWAY_POST_EXECUTION_GAS_RESERVE + selfCallGas;
                _settleGatewaySlotIsolated(
                    pendingDeposits, depositNonces, tokenRegistry, withdrawal, slot, remainingSettlementGas, selfCallGas
                );
                ++gatewayCursor;
            } else {
                revert IPrivacyBoost.RouteMismatch();
            }
        }
        if (gatewayCursor != gatewaySlots.length) revert IPrivacyBoost.InvalidGatewaySlot();
        if (hasGatewayBudget) _requireSettlementGas(EPOCH_FINALIZATION_GAS_RESERVE);
    }

    /// @notice Execute the route-aware withdrawal path and return each gateway slot outcome for simulation.
    /// @dev Executes by delegatecall against PrivacyBoost state. The pool invokes this path inside a self-call whose
    ///      parent always reverts, so token transfers and pending-deposit writes are rolled back after the outcomes
    ///      are encoded. Fatal slot errors are bubbled instead of being stored in the compatibility failure arrays.
    /// @param gatewayRoute Pool route map used to classify every withdrawal destination.
    /// @param pendingDeposits Pool pending-deposit map updated for executed output or fallback input.
    /// @param depositNonces Pool nonce map used to derive a unique gateway-origin deposit request.
    /// @param tokenRegistry Registry used to resolve withdrawal token addresses.
    /// @param withdrawals Ordered withdrawals processed by the route-aware settlement path.
    /// @param gatewaySlots Sparse gateway instructions ordered by strictly increasing withdrawal index.
    /// @return outcomes Settlement outcome for each gateway slot.
    /// @return receiptHashes Receipt hash recorded for each gateway slot.
    /// @return failureSelectors ABI-compatible failure selectors, left zero when the function returns successfully.
    /// @return failureReasons ABI-compatible failure data, left empty when the function returns successfully.
    function processGatewayWithdrawalsForSim(
        mapping(address => GatewayRoute) storage gatewayRoute,
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        ITokenRegistry tokenRegistry,
        Withdrawal[] calldata withdrawals,
        GatewaySlot[] calldata gatewaySlots
    )
        external
        returns (
            GatewaySettlementOutcome[] memory outcomes,
            bytes32[] memory receiptHashes,
            bytes4[] memory failureSelectors,
            bytes[] memory failureReasons
        )
    {
        outcomes = new GatewaySettlementOutcome[](gatewaySlots.length);
        receiptHashes = new bytes32[](gatewaySlots.length);
        failureSelectors = new bytes4[](gatewaySlots.length);
        failureReasons = new bytes[](gatewaySlots.length);

        _validateGatewaySlotsStrictAscending(gatewaySlots);

        // Mirrors the production budget gating above so simulation and settlement agree on which
        // epochs carry a settlement-gas floor.
        bool hasGatewayBudget = gatewaySlots.length != 0;
        uint256 remainingSettlementGas;
        if (hasGatewayBudget) {
            remainingSettlementGas = _buildSettlementGasBudget(withdrawals.length, gatewaySlots);
            _requireSettlementGas(remainingSettlementGas);
        }

        uint256 gatewayCursor = 0;
        for (uint256 i = 0; i < withdrawals.length; ++i) {
            Withdrawal calldata withdrawal = withdrawals[i];
            GatewayRoute route = gatewayRoute[withdrawal.to];
            bool hasSlot =
                gatewayCursor < gatewaySlots.length && uint256(gatewaySlots[gatewayCursor].withdrawalIndex) == i;

            if (route == GatewayRoute.None) {
                if (hasSlot) revert IPrivacyBoost.UnexpectedGatewaySlot();
                if (hasGatewayBudget) {
                    _requireSettlementGas(remainingSettlementGas);
                    remainingSettlementGas -= PLAIN_WITHDRAWAL_GAS_RESERVE;
                }
                LibPoolShared.transferToken(tokenRegistry, withdrawal.tokenId, withdrawal.to, withdrawal.amount);
            } else if (route == GatewayRoute.Sync) {
                if (!hasSlot) revert IPrivacyBoost.MissingGatewaySlot();
                GatewaySlot calldata slot = gatewaySlots[gatewayCursor];
                uint256 selfCallGas = _gatewaySelfCallGasReserve(slot);
                remainingSettlementGas -= GATEWAY_POST_EXECUTION_GAS_RESERVE + selfCallGas;
                (outcomes[gatewayCursor], receiptHashes[gatewayCursor]) = _settleGatewaySlotIsolated(
                    pendingDeposits, depositNonces, tokenRegistry, withdrawal, slot, remainingSettlementGas, selfCallGas
                );
                ++gatewayCursor;
            } else {
                revert IPrivacyBoost.RouteMismatch();
            }
        }
        if (gatewayCursor != gatewaySlots.length) revert IPrivacyBoost.InvalidGatewaySlot();
        if (hasGatewayBudget) _requireSettlementGas(EPOCH_FINALIZATION_GAS_RESERVE);
    }

    /// @notice Body of the isolated per-slot frame: run the untrusted gateway and record the settlement
    ///         outcome it produced. Reached only through `IPrivacyBoost.executeGatewaySlotIsolated`, so
    ///         every state change here is confined to that catchable frame.
    /// @dev Executes by delegatecall against PrivacyBoost storage and may record a gateway-origin pending deposit.
    ///      Only local gas exhaustion in this frame, meaning empty revert data or
    ///      `InsufficientGatewaySettlementGas`, is recovered as a fallback settlement outcome. Every other
    ///      revert is rethrown to the caller unchanged.
    /// @param pendingDeposits Pool pending-deposit map updated for executed output or fallback input.
    /// @param depositNonces Pool nonce map used to derive a unique gateway-origin deposit request.
    /// @param tokenRegistry Registry used to resolve the input and output token addresses.
    /// @param withdrawal Withdrawal whose input asset and gateway destination are settled.
    /// @param slot Signed target, receipt, fallback receipt, and expiry constraints for the withdrawal.
    /// @return outcome Whether the target executed or the input was recorded as a fallback deposit.
    /// @return receiptHash Hash of the receipt used to record the resulting pending deposit.
    function executeGatewaySlotAndRecordOutcome(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        ITokenRegistry tokenRegistry,
        Withdrawal calldata withdrawal,
        GatewaySlot calldata slot
    ) external returns (GatewaySettlementOutcome outcome, bytes32 receiptHash) {
        return _executeGatewayAndRecordOutcome(pendingDeposits, depositNonces, tokenRegistry, withdrawal, slot);
    }

    function _settleGatewaySlotIsolated(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        ITokenRegistry tokenRegistry,
        Withdrawal calldata withdrawal,
        GatewaySlot calldata slot,
        uint256 gasRequiredAfterSlot,
        uint256 selfCallGasReserve
    ) internal returns (GatewaySettlementOutcome outcome, bytes32 receiptHash) {
        _validateGatewayFallbackShape(withdrawal, slot);
        (, address inputToken,) = tokenRegistry.tokenOf(withdrawal.tokenId);
        if (inputToken == address(0)) revert IPrivacyBoost.InvalidWithdrawal();

        // Invariant: whatever the gateway does with `isolatedGas`, the parent frame still holds
        //   GATEWAY_POST_EXECUTION_GAS_RESERVE   this slot's local fallback recovery,
        // + gasRequiredAfterSlot                 every remaining gateway and plain withdrawal, plus
        //                                        EPOCH_FINALIZATION_GAS_RESERVE for the epoch tail,
        // + selfCallGasReserve                   encoding this self-call and handling its result.
        // The explicit gas cap is what makes that hold: an untrusted target cannot reach past it.
        uint256 minimumBeforeCall = gasRequiredAfterSlot + GATEWAY_POST_EXECUTION_GAS_RESERVE + selfCallGasReserve;
        _requireSettlementGas(minimumBeforeCall);

        uint256 isolatedGas = gasleft() - minimumBeforeCall;
        try IPrivacyBoost(address(this)).executeGatewaySlotIsolated{gas: isolatedGas}(withdrawal, slot) returns (
            GatewaySettlementOutcome isolatedOutcome, bytes32 isolatedReceiptHash
        ) {
            return (isolatedOutcome, isolatedReceiptHash);
        } catch (bytes memory reason) {
            if (!_isLocalGasExhaustion(reason)) _revertBytes(reason);
            _requireSettlementGas(gasRequiredAfterSlot + GATEWAY_POST_EXECUTION_GAS_RESERVE);
            return _recordFallbackDeposit(pendingDeposits, depositNonces, withdrawal, slot);
        }
    }

    /// @dev Executes the untrusted gateway, validates the resulting token deltas, and records the
    ///      `Executed` or `Fallback` deposit. Execution and recording stay in one frame on purpose: a
    ///      revert while recording rolls back the gateway's side effects rather than leaving the pool
    ///      drained with no matching deposit.
    function _executeGatewayAndRecordOutcome(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        ITokenRegistry tokenRegistry,
        Withdrawal calldata withdrawal,
        GatewaySlot calldata slot
    ) internal returns (GatewaySettlementOutcome outcome, bytes32 receiptHash) {
        _validateGatewayFallbackShape(withdrawal, slot);

        (, address inputToken,) = tokenRegistry.tokenOf(withdrawal.tokenId);
        if (inputToken == address(0)) revert IPrivacyBoost.InvalidWithdrawal();

        if (block.number > slot.expiryBlock) {
            _requireSettlementGas(GATEWAY_POST_EXECUTION_GAS_RESERVE);
            return _recordFallbackDeposit(pendingDeposits, depositNonces, withdrawal, slot);
        }

        _validateGatewayPrimaryShape(withdrawal, slot);

        (, address outputToken,) = tokenRegistry.tokenOf(slot.receipt.outputTokenId);
        if (outputToken == address(0)) revert IPrivacyBoost.InvalidWithdrawal();
        if (inputToken == outputToken) revert IPrivacyBoost.InvalidGatewaySlot();

        uint256 poolInputBefore = IERC20(inputToken).balanceOf(address(this));
        uint256 poolOutputBefore = IERC20(outputToken).balanceOf(address(this));

        _requireSettlementGas(GATEWAY_POST_EXECUTION_GAS_RESERVE);
        IERC20(inputToken).forceApprove(withdrawal.to, withdrawal.amount);
        uint256 executionGas = gasleft();
        executionGas =
            executionGas > GATEWAY_POST_EXECUTION_GAS_RESERVE ? executionGas - GATEWAY_POST_EXECUTION_GAS_RESERVE : 0;
        try IGatewayExecutor(withdrawal.to).executeGatewayCall{gas: executionGas}(
            withdrawal.tokenId, inputToken, outputToken, withdrawal.amount, slot
        ) {
            IERC20(inputToken).forceApprove(withdrawal.to, 0);
        } catch {
            _requireSettlementGas(GATEWAY_POST_EXECUTION_GAS_RESERVE);
            IERC20(inputToken).forceApprove(withdrawal.to, 0);
            if (IERC20(inputToken).balanceOf(address(this)) != poolInputBefore) {
                revert IPrivacyBoost.InputDeltaMismatch();
            }
            return _recordFallbackDeposit(pendingDeposits, depositNonces, withdrawal, slot);
        }

        _requireSettlementGas(GATEWAY_POST_EXECUTION_GAS_RESERVE);
        if (
            poolInputBefore < withdrawal.amount
                || IERC20(inputToken).balanceOf(address(this)) != poolInputBefore - withdrawal.amount
        ) {
            revert IPrivacyBoost.InputDeltaMismatch();
        }

        uint256 poolOutputDelta = IERC20(outputToken).balanceOf(address(this)) - poolOutputBefore;
        if (poolOutputDelta > type(uint96).max) revert IPrivacyBoost.OutputOverflow();
        if (poolOutputDelta < slot.receipt.minOutputAmount) revert IPrivacyBoost.OutputBelowMin();

        receiptHash = _gatewayReceiptHash(slot.receipt);
        _recordGatewayOriginDeposit(
            pendingDeposits,
            depositNonces,
            withdrawal.to,
            slot.receipt,
            // poolOutputDelta was bounded against type(uint96).max above.
            // forge-lint: disable-next-line(unsafe-typecast)
            uint96(poolOutputDelta),
            slot.action,
            GatewaySettlementOutcome.Executed,
            receiptHash
        );
        return (GatewaySettlementOutcome.Executed, receiptHash);
    }

    // ─────────────── Rescue lifecycle ───────────────

    /// @notice Rescue a gateway-origin pending deposit after `cancelDelay`.
    /// @param pendingDeposits Pending-deposit map the rescued request is read from and cleared
    /// @param processedDeposits Map marking requests already consumed by an epoch
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param cancelDelay The delay that must elapse before a rescue is allowed
    /// @param depositRequestId The gateway-origin pending deposit to rescue
    /// @param destination Address receiving the rescued funds
    /// @param rescueSalt Salt whose commitment the stored `rescueCommitment` opens
    /// @param rescueAuthority Authority whose commitment the stored `rescueCommitment` opens
    /// @param signature Signature from the rescue authority over this rescue
    function rescueGatewayDeposit(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(uint256 => bool) storage processedDeposits,
        ITokenRegistry tokenRegistry,
        uint256 cancelDelay,
        uint256 depositRequestId,
        address destination,
        bytes32 rescueSalt,
        address rescueAuthority,
        bytes calldata signature
    ) external {
        PendingDeposit storage pendingDeposit = _validateRescue(
            pendingDeposits, processedDeposits, cancelDelay, depositRequestId, destination
        );

        if (
            keccak256(abi.encode(AUTHORITY_RESCUE_DOMAIN, rescueAuthority, rescueSalt))
                == pendingDeposit.rescueCommitment
        ) {
            if (msg.sender != rescueAuthority) revert IPrivacyBoost.InvalidRescueAuthority();
            if (signature.length != 0) revert IPrivacyBoost.InvalidRescueSignature();
        } else {
            if (keccak256(abi.encode(rescueAuthority, rescueSalt)) != pendingDeposit.rescueCommitment) {
                revert IPrivacyBoost.InvalidRescueCommitment();
            }
            bytes32 digest = _rescueDigest(
                RescueKind.GatewayDeposit, depositRequestId, pendingDeposit.rescueCommitment, destination
            );
            if (ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(digest), signature) != rescueAuthority) {
                revert IPrivacyBoost.InvalidRescueSignature();
            }
        }
        _completeRescue(
            pendingDeposits, processedDeposits, tokenRegistry, depositRequestId, destination, pendingDeposit
        );
    }

    // ─────────────── Internal helpers ───────────────

    function _validateRescue(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(uint256 => bool) storage processedDeposits,
        uint256 cancelDelay,
        uint256 depositRequestId,
        address destination
    ) private view returns (PendingDeposit storage pendingDeposit) {
        pendingDeposit = pendingDeposits[depositRequestId];
        if (pendingDeposit.depositor == address(0)) revert IPrivacyBoost.InvalidDeposit();
        if (processedDeposits[depositRequestId]) revert IPrivacyBoost.DepositAlreadyProcessed();
        if (pendingDeposit.rescueCommitment == bytes32(0)) revert IPrivacyBoost.InvalidRescueCommitment();
        if (block.number < pendingDeposit.requestBlock + cancelDelay) revert IPrivacyBoost.RescueTooEarly();
        if (destination == address(0)) revert IPrivacyBoost.InvalidRescueDestination();
    }

    function _completeRescue(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(uint256 => bool) storage processedDeposits,
        ITokenRegistry tokenRegistry,
        uint256 depositRequestId,
        address destination,
        PendingDeposit storage pendingDeposit
    ) private {
        processedDeposits[depositRequestId] = true;
        uint96 amount = pendingDeposit.totalAmount;
        (, address tokenAddress,) = tokenRegistry.tokenOf(pendingDeposit.tokenId);
        delete pendingDeposits[depositRequestId];

        IERC20(tokenAddress).safeTransfer(destination, amount);
        emit IPrivacyBoost.GatewayDepositRescued(depositRequestId, destination);
    }

    function _validateGatewayFallbackShape(Withdrawal calldata withdrawal, GatewaySlot calldata slot) internal pure {
        if (slot.expiryBlock == 0) revert IPrivacyBoost.InvalidGatewaySlot();
        if (slot.action != GatewayAction.ExternalCall) revert IPrivacyBoost.RouteMismatch();
        _validateFallbackReceipt(withdrawal, slot.fallbackReceipt);
    }

    function _validateGatewaySlotsStrictAscending(GatewaySlot[] calldata gatewaySlots) internal pure {
        if (gatewaySlots.length == 0) return;
        uint32 prev = type(uint32).max;
        for (uint256 i = 0; i < gatewaySlots.length; ++i) {
            uint32 idx = uint32(gatewaySlots[i].withdrawalIndex);
            if (i > 0 && idx <= prev) revert IPrivacyBoost.GatewaySlotsNotStrictlyAscending();
            prev = idx;
        }
    }

    function _validateGatewayPrimaryShape(Withdrawal calldata withdrawal, GatewaySlot calldata slot) internal pure {
        if (slot.receipt.outputTokenId == 0) revert IPrivacyBoost.InvalidGatewaySlot();
        if (slot.receipt.outputTokenId == withdrawal.tokenId) revert IPrivacyBoost.InvalidGatewaySlot();
        if (slot.receipt.minOutputAmount == 0) revert IPrivacyBoost.InvalidGatewaySlot();
        // The zero key sits below the floor, so the single lower bound covers it too. A
        // gateway-origin credit is the one deposit path where the pool itself builds the
        // commitment, so refusing the reserved range here stops a caller from funding a note no
        // spend relation can ever open.
        if (slot.receipt.npk < SPENDABLE_NPK_FLOOR || slot.receipt.npk >= SNARK_SCALAR_FIELD) {
            revert IPrivacyBoost.InvalidGatewaySlot();
        }
        if (slot.receipt.rescueCommitment == bytes32(0)) revert IPrivacyBoost.InvalidGatewaySlot();
        if (slot.target == address(0) || slot.callData.length < 4) {
            revert IPrivacyBoost.InvalidGatewaySlot();
        }
    }

    function _validateFallbackReceipt(Withdrawal calldata withdrawal, GatewayReceipt calldata fallbackReceipt)
        internal
        pure
    {
        if (fallbackReceipt.outputTokenId != withdrawal.tokenId) revert IPrivacyBoost.InvalidGatewaySlot();
        if (fallbackReceipt.minOutputAmount != 0) revert IPrivacyBoost.InvalidGatewaySlot();
        if (fallbackReceipt.npk < SPENDABLE_NPK_FLOOR || fallbackReceipt.npk >= SNARK_SCALAR_FIELD) {
            revert IPrivacyBoost.InvalidGatewaySlot();
        }
        if (fallbackReceipt.rescueCommitment == bytes32(0)) revert IPrivacyBoost.InvalidGatewaySlot();
    }

    function _recordFallbackDeposit(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        Withdrawal calldata withdrawal,
        GatewaySlot calldata slot
    ) internal returns (GatewaySettlementOutcome outcome, bytes32 receiptHash) {
        receiptHash = _gatewayReceiptHash(slot.fallbackReceipt);
        _recordGatewayOriginDeposit(
            pendingDeposits,
            depositNonces,
            withdrawal.to,
            slot.fallbackReceipt,
            withdrawal.amount,
            slot.action,
            GatewaySettlementOutcome.Fallback,
            receiptHash
        );
        return (GatewaySettlementOutcome.Fallback, receiptHash);
    }

    /// @dev Records a one-commitment gateway-origin pending deposit. `commitmentsHash` uses the same
    ///      sequential Poseidon step as a normal one-commitment deposit so `submitDepositEpoch`
    ///      re-derivation matches. Emits the standard `DepositRequested` channel with the
    ///      user-provided ciphertext, while the event's `totalAmount` carries the authoritative amount.
    function _recordGatewayOriginDeposit(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(address => uint32) storage depositNonces,
        address gateway,
        GatewayReceipt calldata receipt,
        uint96 measuredOutputAmount,
        GatewayAction action,
        GatewaySettlementOutcome outcome,
        bytes32 receiptHash
    ) internal {
        uint32 nonce = depositNonces[gateway]++;
        (uint256 commitment, uint256 commitmentsHash, uint256 depositRequestId) = LibDigest.computeGatewayDepositData(
            gateway, receipt.outputTokenId, measuredOutputAmount, nonce, receipt.npk
        );

        if (pendingDeposits[depositRequestId].depositor != address(0)) revert IPrivacyBoost.DepositAlreadyExists();

        pendingDeposits[depositRequestId] = PendingDeposit({
            depositor: gateway,
            tokenId: receipt.outputTokenId,
            totalAmount: measuredOutputAmount,
            requestBlock: uint64(block.number),
            nonce: nonce,
            commitmentCount: 1,
            commitmentsHash: commitmentsHash,
            rescueCommitment: receipt.rescueCommitment
        });

        uint256[] memory commitmentsArr = new uint256[](1);
        commitmentsArr[0] = commitment;
        DepositCiphertext[] memory ciphertextsArr = new DepositCiphertext[](1);
        ciphertextsArr[0] = receipt.ciphertext;
        emit IPrivacyBoost.DepositRequested(
            depositRequestId,
            gateway,
            DepositOrigin.GatewayRedeposit,
            receipt.outputTokenId,
            measuredOutputAmount,
            1,
            commitmentsHash,
            commitmentsArr,
            ciphertextsArr
        );
        emit IPrivacyBoost.GatewayOriginDepositRecorded(
            depositRequestId, receiptHash, action, outcome, receipt.rescueCommitment, nonce
        );
    }

    function _buildSettlementGasBudget(uint256 withdrawalCount, GatewaySlot[] calldata gatewaySlots)
        private
        pure
        returns (uint256 remainingSettlementGas)
    {
        if (gatewaySlots.length > withdrawalCount) revert IPrivacyBoost.InvalidGatewaySlot();

        remainingSettlementGas =
            EPOCH_FINALIZATION_GAS_RESERVE + (withdrawalCount - gatewaySlots.length) * PLAIN_WITHDRAWAL_GAS_RESERVE;
        for (uint256 i = 0; i < gatewaySlots.length; ++i) {
            remainingSettlementGas += GATEWAY_POST_EXECUTION_GAS_RESERVE + _gatewaySelfCallGasReserve(gatewaySlots[i]);
        }
    }

    function _gatewaySelfCallGasReserve(GatewaySlot calldata slot) private pure returns (uint256) {
        return GATEWAY_SELF_CALL_BASE_GAS_RESERVE + slot.callData.length * GATEWAY_SELF_CALL_GAS_PER_CALLDATA_BYTE;
    }

    function _requireSettlementGas(uint256 minimumRequired) private view {
        uint256 available = gasleft();
        if (available <= minimumRequired) {
            revert IPrivacyBoost.InsufficientGatewaySettlementGas(available, minimumRequired);
        }
    }

    function _isLocalGasExhaustion(bytes memory reason) private pure returns (bool) {
        if (reason.length == 0) return true;
        if (reason.length < 4) return false;

        bytes4 selector;
        assembly ("memory-safe") {
            selector := mload(add(reason, 0x20))
        }
        return selector == IPrivacyBoost.InsufficientGatewaySettlementGas.selector;
    }

    function _revertBytes(bytes memory reason) internal pure {
        assembly ("memory-safe") {
            revert(add(reason, 0x20), mload(reason))
        }
    }

    /// @dev GatewayReceipt is a fully static 10-word ABI tuple. Hashing its calldata
    ///      directly preserves keccak256(abi.encode(receipt)) without allocating the tuple.
    function _gatewayReceiptHash(GatewayReceipt calldata receipt) internal pure returns (bytes32 receiptHash) {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            calldatacopy(ptr, receipt, 0x140)
            receiptHash := keccak256(ptr, 0x140)
        }
    }

    function _rescueDigest(RescueKind kind, uint256 requestId, bytes32 rescueCommitment, address destination)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(_RESCUE_DOMAIN, block.chainid, address(this), kind, requestId, rescueCommitment, destination)
        );
    }
}
