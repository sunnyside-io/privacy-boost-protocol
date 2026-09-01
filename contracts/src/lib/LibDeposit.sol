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
import {TOKEN_TYPE_ERC20} from "src/interfaces/Constants.sol";
import {
    PendingDeposit,
    DepositOrigin,
    DepositCiphertext,
    Output,
    DepositEntry,
    EpochTreeState
} from "src/interfaces/IStructs.sol";
import {IPrivacyBoost, IDepositVerifier} from "src/interfaces/IPrivacyBoost.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {LibPublicInputs} from "src/lib/LibPublicInputs.sol";

/// @title LibDeposit
/// @notice Standard-deposit helpers extracted from PrivacyBoost to keep the implementation bytecode under
///         the EIP-170 limit. Deployed as an external (delegatecall) library, exactly like LibEpoch, so
///         every function runs in the calling pool's context: `address(this)`, `msg.sender`, `block.*`,
///         and pool storage all resolve to the pool, not the library.
/// @dev {requestDeposit} is STORAGE-COUPLED: it receives the pool's deposit-storage mappings BY REFERENCE
///      (depositNonces, pendingDeposits) and reads/writes them directly under delegatecall. The
///      `tokenRegistry` and `maxBatchSize` immutables — baked into the pool's own bytecode, not its storage,
///      so a delegatecall library cannot see them — are passed by value. The pool keeps the `nonReentrant`
///      guard on its thin wrapper: the transient-storage guard is set before the delegatecall, so a
///      re-entrant call routes back through the guarded wrapper and reverts.
/// @custom:security-contact contact@sunnyside.io
library LibDeposit {
    using SafeERC20 for IERC20;

    /// @dev BN254 scalar field modulus; commitments must be strict field elements (mirrors PrivacyBoost's
    ///      own SNARK_SCALAR_FIELD — a delegatecall library cannot read the pool's private constant).
    uint256 private constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Construct a standard deposit request: validate the batch, pull the ERC-20 (fee-on-transfer
    ///         rejected), derive the request id, record the pending deposit, and emit DepositRequested.
    /// @dev Receives depositNonces + pendingDeposits by reference and the tokenRegistry/maxBatchSize
    ///      immutables by value; msg.sender and address(this) resolve to the pool under delegatecall, so the
    ///      depositor binding and the request-id digest are computed exactly as the inline version did.
    /// @param depositNonces Per-depositor nonce map used to derive a unique request id
    /// @param pendingDeposits Pending-deposit map this call writes the new request into
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param maxBatchSize Maximum commitments permitted in one request
    /// @param _tokenId The registered token being deposited
    /// @param _totalAmount The gross amount pulled from the depositor
    /// @param _commitments The note commitments this deposit will mint
    /// @param _ciphertexts Per-commitment deposit ciphertexts, index-aligned with `_commitments`
    /// @return depositRequestId The identifier recorded for the pending deposit
    function requestDeposit(
        mapping(address => uint32) storage depositNonces,
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        ITokenRegistry tokenRegistry,
        uint32 maxBatchSize,
        uint16 _tokenId,
        uint96 _totalAmount,
        uint256[] calldata _commitments,
        DepositCiphertext[] calldata _ciphertexts
    ) external returns (uint256 depositRequestId) {
        uint256 commitmentCount = _commitments.length;
        if (commitmentCount == 0 || commitmentCount > maxBatchSize) revert IPrivacyBoost.InvalidDeposit();
        // forge-lint: disable-next-line(unsafe-typecast) PrivacyBoost constrains maxBatchSize to uint16.
        uint16 commitmentCount16 = uint16(commitmentCount);
        if (_totalAmount == 0) revert IPrivacyBoost.InvalidDeposit();
        if (commitmentCount != _ciphertexts.length) revert IPrivacyBoost.InvalidArrayLengths();

        for (uint256 i = 0; i < commitmentCount; ++i) {
            uint256 commitment = _commitments[i];
            if (commitment == 0 || commitment >= SNARK_SCALAR_FIELD) revert IPrivacyBoost.InvalidDeposit();
        }
        // Sequential hash binds commitment order to prevent reordering attacks
        uint256 commitmentsHash = LibDigest.computeCommitmentsHash(_commitments);

        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(_tokenId);
        if (tokenAddress == address(0)) revert IPrivacyBoost.InvalidDeposit();
        if (tokenType != TOKEN_TYPE_ERC20) revert IPrivacyBoost.TokenNotSupported(tokenType);

        // Reject fee-on-transfer tokens to prevent accounting mismatch
        uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
        IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), _totalAmount);
        uint256 balanceAfter = IERC20(tokenAddress).balanceOf(address(this));
        if (balanceAfter - balanceBefore != _totalAmount) {
            revert IPrivacyBoost.FeeOnTransferNotSupported(_totalAmount, balanceAfter - balanceBefore);
        }

        uint32 nonce = depositNonces[msg.sender]++;
        depositRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(this), msg.sender, _tokenId, _totalAmount, nonce, commitmentsHash
        );

        if (pendingDeposits[depositRequestId].depositor != address(0)) {
            revert IPrivacyBoost.DepositAlreadyExists();
        }

        pendingDeposits[depositRequestId] = PendingDeposit({
            depositor: msg.sender,
            tokenId: _tokenId,
            totalAmount: _totalAmount,
            requestBlock: uint64(block.number),
            nonce: nonce,
            commitmentCount: commitmentCount16,
            commitmentsHash: commitmentsHash,
            rescueCommitment: bytes32(0)
        });

        emit IPrivacyBoost.DepositRequested(
            depositRequestId,
            msg.sender,
            DepositOrigin.UserShield,
            _tokenId,
            _totalAmount,
            commitmentCount16,
            commitmentsHash,
            _commitments,
            _ciphertexts
        );
    }

    /// @notice Cancel a pending deposit after the cancel delay and refund the depositor.
    /// @dev Receives pendingDeposits + processedDeposits by reference and the tokenRegistry/cancelDelay
    ///      immutables by value; msg.sender resolves to the pool's caller under delegatecall, so only the
    ///      original depositor can cancel and the refund goes to them.
    /// @param pendingDeposits Pending-deposit map the cancelled request is cleared from
    /// @param processedDeposits Map marking requests already consumed by an epoch
    /// @param tokenRegistry Registry used to resolve the token id to its ERC-20
    /// @param cancelDelay The delay that must elapse before a pending deposit may be cancelled
    /// @param _depositRequestId The pending request to cancel and refund
    function cancelDeposit(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(uint256 => bool) storage processedDeposits,
        ITokenRegistry tokenRegistry,
        uint256 cancelDelay,
        uint256 _depositRequestId
    ) external {
        PendingDeposit storage pendingDeposit = pendingDeposits[_depositRequestId];

        if (pendingDeposit.depositor != msg.sender) revert IPrivacyBoost.NotDepositor();
        if (processedDeposits[_depositRequestId]) revert IPrivacyBoost.DepositAlreadyProcessed();
        if (block.number < pendingDeposit.requestBlock + cancelDelay) revert IPrivacyBoost.CancelTooEarly();
        if (pendingDeposit.rescueCommitment != bytes32(0)) revert IPrivacyBoost.GatewayOriginCannotCancel();

        uint16 tokenId = pendingDeposit.tokenId;
        uint96 totalAmount = pendingDeposit.totalAmount;
        delete pendingDeposits[_depositRequestId];

        (, address tokenAddress,) = tokenRegistry.tokenOf(tokenId);
        IERC20(tokenAddress).safeTransfer(msg.sender, totalAmount);

        emit IPrivacyBoost.DepositCancelled(_depositRequestId);
    }

    /// @notice Process a deposit epoch's pending requests, build the public inputs, and verify the proof.
    /// @dev The per-request loop marks processedDeposits (double-process guard) and binds each request's
    ///      ordered commitments to its stored commitmentsHash; the caller's wrapper retains the tree-state
    ///      CAS, root validation, and the value-type currentTreeNumber advance. Receives the deposit/processed
    ///      mappings by reference and the depositVerifier by value (a delegatecall library cannot read the
    ///      caller's storage var without it); reverts on any bad request or a failed proof.
    /// @param pendingDeposits Pending-deposit map each processed request is read from
    /// @param processedDeposits Map marking requests already consumed, written as the double-process guard
    /// @param depositVerifier The deposit Groth16 verifier
    /// @param treeState The epoch's note-tree state, already CAS-validated by the caller
    /// @param nTotalCommitments Total commitments across every request in the epoch
    /// @param outputs The note outputs the epoch appends
    /// @param deposits The pending requests this epoch consumes
    /// @param proof The Groth16 proof over the built public inputs
    function submitDepositEpoch(
        mapping(uint256 => PendingDeposit) storage pendingDeposits,
        mapping(uint256 => bool) storage processedDeposits,
        IDepositVerifier depositVerifier,
        EpochTreeState calldata treeState,
        uint32 nTotalCommitments,
        Output[] calldata outputs,
        DepositEntry[] calldata deposits,
        uint256[8] calldata proof
    ) external {
        uint32 maxSlots = uint32(outputs.length);
        uint32 nRequests = uint32(deposits.length);

        uint256[] memory depositRequestIds = new uint256[](maxSlots);
        uint256[] memory totalAmounts = new uint256[](maxSlots);
        uint256[] memory commitmentCounts = new uint256[](maxSlots);
        uint256[] memory commitmentsOut = new uint256[](maxSlots);
        uint256 commitmentCursor = 0;

        for (uint256 r = 0; r < nRequests; ++r) {
            uint256 reqId = deposits[r].depositRequestId;
            PendingDeposit storage pendingDeposit = pendingDeposits[reqId];

            if (pendingDeposit.depositor == address(0)) revert IPrivacyBoost.InvalidDeposit();
            if (processedDeposits[reqId]) revert IPrivacyBoost.DepositAlreadyProcessed();
            processedDeposits[reqId] = true;

            depositRequestIds[r] = reqId;
            totalAmounts[r] = pendingDeposit.totalAmount;
            commitmentCounts[r] = pendingDeposit.commitmentCount;

            uint256 endCursor = commitmentCursor + pendingDeposit.commitmentCount;
            if (endCursor > nTotalCommitments) revert IPrivacyBoost.InvalidArrayLengths();
            uint256 computedHash = LibDigest.computeOutputsCommitmentsHash(outputs[commitmentCursor:endCursor]);
            for (; commitmentCursor < endCursor; ++commitmentCursor) {
                uint256 commitment = outputs[commitmentCursor].commitment;
                commitmentsOut[commitmentCursor] = commitment;
            }

            if (computedHash != pendingDeposit.commitmentsHash) revert IPrivacyBoost.InvalidDeposit();
        }

        if (commitmentCursor != nTotalCommitments) revert IPrivacyBoost.InvalidArrayLengths();

        uint256[] memory publicInputs = LibPublicInputs.buildDepositInputs(
            block.chainid,
            address(this),
            treeState,
            nRequests,
            nTotalCommitments,
            depositRequestIds,
            totalAmounts,
            commitmentCounts,
            commitmentsOut
        );

        depositVerifier.verifyDeposit(maxSlots, proof, publicInputs);
    }
}
