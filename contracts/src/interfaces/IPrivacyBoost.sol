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

import {
    Output,
    Transfer,
    Withdrawal,
    DepositOrigin,
    DepositCiphertext,
    DepositEntry,
    PortalDepositEntry,
    EpochTreeState,
    TreeRootPair,
    GatewaySlot,
    GatewayAction,
    GatewaySettlementOutcome,
    GatewayRoute
} from "src/interfaces/IStructs.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";

interface IEpochVerifier {
    /// @notice Verify an epoch circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param maxTransfers Circuit parameter: maximum number of transfers (batch size)
    /// @param maxInputsPerTransfer Circuit parameter: maximum inputs per transfer
    /// @param maxOutputsPerTransfer Circuit parameter: maximum outputs per transfer
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyEpoch(
        uint32 maxTransfers,
        uint32 maxInputsPerTransfer,
        uint32 maxOutputsPerTransfer,
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

interface IDepositVerifier {
    /// @notice Verify a deposit circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param batchSize Circuit parameter: maximum number of deposits processed in the batch
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyDeposit(uint32 batchSize, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}

interface IPortalDepositVerifier {
    /// @notice Verify a hidden-recipient portal-deposit circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    ///      Separate from IDepositVerifier because the portal circuit has its own verifying key and
    ///      public-input layout (E, counter, H, tokenId, amount, commitment per slot).
    /// @param batchSize Circuit parameter: maximum number of portal deposits processed in the batch
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyPortalDeposit(uint32 batchSize, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}

/// @notice Push interface the portal account E implements so the pool can sweep its balance.
/// @dev The portal PUSHES on a pool-invoked sweep; the pool measures the received
///      balance delta. Alternatives: the pool PULLS via an ERC-20 allowance E granted, or a
///      portal-initiated push that calls the pool. Change the seam here AND at requestPortalDeposit.
///      The pool, not the portal, is the source of truth for the credited amount: it caps the pull
///      at `cap` and measures the actual received delta, so a misbehaving portal can never inflate
///      the recorded amount. For the configured WETH token, the portal may first wrap native ETH above
///      its own gas reserve, up to the remaining cap. The portal then pushes min(its token balance, cap),
///      so any token or native remainder above the uint96 record ceiling stays at E for the next sweep.
interface IPortalSweepSource {
    /// @notice Push up to `cap` of `token` from this portal (E) to the calling pool.
    /// @dev MUST transfer min(balanceOf(E, token), cap) to msg.sender (the pool), after any configured
    ///      wrapped-native conversion. The pool measures the received delta itself and does not trust
    ///      portal-side accounting. Implemented by the EIP-7702-delegated portal EOA that holds the funds.
    /// @param token The ERC-20 token to sweep
    /// @param cap The maximum amount to push (the pool passes the uint96 record ceiling)
    function sweep(address token, uint256 cap) external;
}

/// @notice Read interface the EIP-7702-delegated portal account E implements so the pool can read the
///         owner binding H at sweep time.
/// @dev The binding lives in E's OWN account storage (written once via PortalDelegate.initializePortal),
///      not in pool storage. requestPortalDeposit staticcalls portalBinding() to read the H the deposit
///      proof must open; a zero return — or a call that reverts because E is not delegated to the portal
///      account code — means the portal is unregistered. Change the binding seam here AND at
///      requestPortalDeposit together.
interface IPortalDelegate {
    /// @notice The owner binding H = Poseidon(DOMAIN_PORTAL_BIND, recipientMPK, blind) recorded in E's
    ///         own storage, or 0 if E has not initialized a binding.
    /// @return The binding hash, or 0 when E has not initialized one
    function portalBinding() external view returns (uint256);
}

interface IForcedWithdrawVerifier {
    /// @notice Verify a forced withdrawal circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    /// @param maxInputs Circuit parameter: maximum number of inputs supported
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyForcedWithdraw(uint32 maxInputs, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);
}

interface IGiftClaimVerifier {
    /// @notice Verify a gift claim circuit Groth16 proof
    /// @dev Returns true on success; may revert on malformed inputs depending on implementation.
    ///      A gift claim epoch is a batch of single-input/single-output re-mints (one gift note
    ///      consumed, one canonical note minted per slot), so the circuit is parameterized by a
    ///      single batch-size value — mirroring IDepositVerifier.verifyDeposit rather than the
    ///      multi-dimensional IEpochVerifier.verifyEpoch shape. The batch-size param fixes the
    ///      Groth16 calldata proof offset and selects the verifying key.
    /// @param batchSize Circuit parameter: maximum number of gift claims processed in the batch
    /// @param proof Groth16 proof (8 field elements)
    /// @param publicInputs Flattened public inputs array for the circuit
    /// @return valid True if the proof is valid
    function verifyGiftClaim(uint32 batchSize, uint256[8] calldata proof, uint256[] calldata publicInputs)
        external
        view
        returns (bool);

    /// @notice Whether a verifying key is registered for the given gift-claim batch size
    /// @dev Non-reverting VK-presence query: lets the relay/SDK pre-validate a batch size off-chain before
    ///      proving, and lets submitGiftClaimEpoch fail fast on an unsupported batch size. Returns false
    ///      (never reverts) for an unregistered batch size.
    /// @param batchSize Circuit parameter: maximum number of gift claims in the registered shape
    /// @return registered True if a verifying key is registered for batchSize
    function hasVerifyingKey(uint32 batchSize) external view returns (bool registered);
}

/// @title IPrivacyBoost
/// @notice Interface for epoch-based private transfer pool
interface IPrivacyBoost {
    // ============ Errors ============

    /// @notice Thrown when caller is not an allowed relay
    error NotAllowedRelay();

    /// @notice Thrown when caller is not the operator
    error NotOperator();

    /// @notice Thrown when caller is not authorized to manage gateway routes
    error NotGatewayRouteManager();

    /// @notice Thrown when the gateway route manager is the zero address
    error InvalidGatewayRouteManager();

    /// @notice Thrown when gateway route migration is called by neither the owner nor proxy admin
    error NotGatewayRouteMigrationAdmin();

    /// @notice Thrown when operator address is zero
    error InvalidOperatorAddress();

    /// @notice Thrown when epoch state validation fails
    error InvalidEpochState();

    /// @notice Thrown when array lengths do not match
    error InvalidArrayLengths();

    /// @notice Thrown when epoch configuration is invalid (batch size, fee token count)
    error InvalidEpochConfig();

    /// @notice Thrown when deposit validation fails
    error InvalidDeposit();

    /// @notice Thrown when withdrawal validation fails
    error InvalidWithdrawal();

    /// @notice Thrown when the current gift-exit fee would pay less than the proof-bound minimum
    /// @param minNetAmount Minimum net payout authorized by the proof
    /// @param actualNetAmount Net payout produced by the current withdrawal fee
    error GiftExitSlippage(uint96 minNetAmount, uint96 actualNetAmount);

    /// @notice Thrown when withdrawalSlots are not strictly increasing (sorted and unique)
    /// @param index The index of the offending slot
    /// @param prev The previous slot value
    /// @param curr The current slot value
    error WithdrawalSlotsNotStrictAscending(uint256 index, uint32 prev, uint32 curr);

    /// @notice Thrown when token type is not supported
    /// @param tokenType The unsupported token type
    error TokenNotSupported(uint8 tokenType);

    /// @notice Thrown when fee exceeds maximum allowed (100%)
    error FeeExceedsMaximum();

    /// @notice Thrown when a provided root is not found in history
    error RootNotKnown();

    /// @notice Thrown when a public gift exit references an auth-key leaf that is no longer active
    error AuthLeafNotActive();

    /// @notice Thrown when a nullifier has already been spent
    error InvalidNullifierSet();

    /// @notice Thrown when a nullifier or commitment violates the active/inactive zero-padding invariant
    error InvalidSlotPadding();

    /// @notice Thrown when packed data has non-zero bits in padding slots (non-canonical encoding)
    error NonCanonicalEncoding();

    /// @notice Thrown when a deposit request ID already exists
    error DepositAlreadyExists();

    /// @notice Thrown when a deposit has already been processed
    error DepositAlreadyProcessed();

    /// @notice Thrown when caller is not the depositor
    error NotDepositor();

    /// @notice Thrown when sweeping a portal whose owner binding is missing: E's portalBinding() returns 0
    ///         (the unregistered sentinel), or E is not delegated to the portal account code so the
    ///         staticcall reverts or returns fewer than 32 bytes.
    /// @dev A sweep with no binding could never be credited — the proof has no H to open. Reject up front.
    error PortalNotRegistered();

    /// @notice Thrown when sweeping a portal whose owner binding is present but not a canonical BN254 field
    ///         element (>= the scalar field), so it could never match the in-circuit H (gnark reduces public
    ///         inputs mod the prime).
    /// @dev The binding lives in E's own re-delegatable account storage, so the pool re-validates the
    ///      staticcall return rather than trusting PortalDelegate's init-time H < SNARK_SCALAR_FIELD guard.
    error InvalidPortalBinding();

    /// @notice Thrown when a sweep receives nothing or less than the per-token dust threshold
    /// @param received The measured received balance delta
    /// @param minSweep The per-token minimum-sweep (dust) threshold in effect
    error SweepBelowDust(uint256 received, uint256 minSweep);

    /// @notice Thrown when a portal sweep pushes more than the uint96 record ceiling in one call
    /// @dev The pool caps the pull at type(uint96).max so any remainder stays at E; a compliant
    ///      portal can never trigger this, but a misbehaving one that over-pushes is rejected rather
    ///      than silently truncated, which would strand the truncated remainder in the pool.
    /// @param received The received balance delta that exceeded the uint96 record ceiling
    error SweepAmountOverflow(uint256 received);

    /// @notice Thrown when a sweep would create a portal deposit record that already exists
    /// @dev The (portal, counter) pair is unique by construction (counter is monotonic per E), so
    ///      this can only fire on a Poseidon collision or a storage bug; guard mirrors requestDeposit.
    error PortalDepositAlreadyExists();

    /// @notice Thrown when a portal deposit has already been credited or reclaimed
    /// @dev Portal analog of DepositAlreadyProcessed, keyed on processedPortalDeposits. Guards both
    ///      double-credit (re-submit of the same id) and credit-after-reclaim (submit after cancel).
    error PortalDepositAlreadyProcessed();

    /// @notice Thrown when a sweeper has no deferred fee for the requested token
    /// @param sweeper The account that has no deferred fee recorded
    /// @param tokenId The token the deferred fee was requested for
    error NoDeferredPortalSweepFee(address sweeper, uint16 tokenId);

    /// @notice Thrown when the isolated portal fee payment target is called by anything except the pool
    error PortalSweepFeePaymentOnlySelf();

    /// @notice Thrown when trying to cancel before the delay period
    error CancelTooEarly();

    /// @notice Thrown when forced withdrawal request does not exist
    error ForcedWithdrawalNotRequested();

    /// @notice Thrown when forced withdrawal has already been requested for a commitment.
    /// Commitment collisions between different users are cryptographically negligible.
    error ForcedWithdrawalAlreadyRequested();

    /// @notice Thrown when trying to execute forced withdrawal before the delay period
    error ForcedWithdrawalTooEarly();

    /// @notice Thrown when forced withdrawal parameters do not match the stored request
    error ForcedWithdrawalMismatch();

    /// @notice Thrown when the packed forced-withdrawal auth context is not canonical or supported
    error InvalidForcedAuthContext();

    /// @notice Thrown when the exact authorization is not live when a forced request is submitted
    error ForcedAuthorizationInvalid();

    /// @notice Thrown when the exact authorization has expired before a forced request is submitted
    error ForcedAuthorizationExpired();

    /// @notice Thrown when a snapshot forced-withdrawal cancellation caller is not the account owner
    error NotAccountOwner();

    /// @notice Thrown when batch configuration is invalid (empty roots or >16 roots)
    error InvalidBatchConfig();

    /// @notice Thrown when too many distinct trees in sparse array (>16)
    error TooManyDistinctTrees();

    /// @notice Thrown when tree number exceeds 15-bit maximum (32767)
    error TreeNumberOverflow();

    /// @notice Thrown when treasury is not set but withdraw fee is enabled
    error TreasuryNotSet();

    /// @notice Thrown when tokenRegistry address is zero or not a contract
    error InvalidTokenRegistryAddress();

    /// @notice Thrown when authRegistry address is zero or not a contract
    error InvalidAuthRegistryAddress();

    /// @notice Thrown when maxBatchSize is set to zero
    error MaxBatchSizeCannotBeZero();

    /// @notice Thrown when maxBatchSize cannot fit the uint16 deposit commitment count
    /// @param value The invalid configured batch size
    /// @param max The largest supported batch size
    error MaxBatchSizeOutOfRange(uint32 value, uint32 max);

    /// @notice Thrown when maxInputsPerTransfer is set to zero
    error MaxInputsPerTransferCannotBeZero();

    /// @notice Thrown when maxOutputsPerTransfer is set to zero
    error MaxOutputsPerTransferCannotBeZero();

    /// @notice Thrown when maxFeeTokens is set to zero
    error MaxFeeTokensCannotBeZero();

    /// @notice Thrown when maxForcedInputs is set to zero
    error MaxForcedInputsCannotBeZero();

    /// @notice Legacy error selector retained for ABI compatibility; forced v3 resolves an exact live auth leaf
    error InvalidForcedWithdrawalAuthStaleness();

    /// @notice Thrown when merkleDepth is out of supported range for zero hash preimages
    /// @param value The invalid merkleDepth value
    /// @param min The minimum allowed value
    /// @param max The maximum allowed value
    error MerkleDepthOutOfRange(uint8 value, uint8 min, uint8 max);

    /// @notice Thrown when a fee-on-transfer token is detected (received amount differs from requested)
    /// @param requested The amount requested to deposit
    /// @param received The actual amount received after transfer
    error FeeOnTransferNotSupported(uint256 requested, uint256 received);

    /// @notice Thrown when duplicate nullifiers are provided in the same request
    error DuplicateNullifier();

    /// @notice Thrown when duplicate input commitments are provided in the same request
    error DuplicateInputCommitment();

    /// @notice Thrown when duplicate tree numbers are provided in a sparse roots array
    error DuplicateTreeNumber();

    /// @notice Thrown when a sparse roots array contains an exact duplicate (treeNumber, root) pair
    /// @dev Epoch allows duplicate tree numbers (with different roots) but does not need exact duplicate pairs.
    error DuplicateTreeRootPair();

    /// @notice Thrown when a gift-claim epoch's attested currentBlock is in the future at submission
    /// @dev currentBlock is a circuit public input the relay attests; rejecting a future value keeps the
    ///      proof an attestation against a block that has occurred, so the refund branch's in-circuit
    ///      currentBlock >= refundAfterBlock check implies the deadline has genuinely passed.
    error GiftClaimBlockInFuture();
    /// @notice Thrown when the proving timestamp is in the future or older than MAX_PROOF_AGE
    error InvalidProvingTimestamp();

    // ============ Gateway errors ============

    /// @notice Thrown when a pending deposit recorded by gateway settlement is passed to `cancelDeposit`
    /// @dev The gateway is the recorded depositor, so recovery runs through `rescueGatewayDeposit` instead.
    error GatewayOriginCannotCancel();

    /// @notice Thrown when gateway slot withdrawal indices are not strictly increasing
    /// @dev Strict ordering lets one forward cursor pair slots to withdrawals and rules out duplicate slots.
    error GatewaySlotsNotStrictlyAscending();

    /// @notice Thrown when a gateway slot fails shape validation or does not pair with a withdrawal
    /// @dev Covers slot-to-withdrawal pairing plus every field constraint on the primary and fallback receipts.
    error InvalidGatewaySlot();

    /// @notice Thrown when a withdrawal whose destination carries a gateway route has no matching slot
    error MissingGatewaySlot();

    /// @notice Thrown when a gateway slot is paired with a withdrawal whose destination has no gateway route
    error UnexpectedGatewaySlot();

    /// @notice Thrown when a slot's action is not an external call, or a destination carries an unhandled route
    /// @dev `GatewayAction.Invalid` is the zero value, so an omitted action field fails closed here.
    error RouteMismatch();

    /// @notice Thrown when the pool's input token balance does not match what the settlement was allowed to move
    /// @dev A reverted gateway call must leave the balance untouched, a successful one must reduce it exactly.
    error InputDeltaMismatch();

    /// @notice Declared for ABI compatibility, with no settlement path that reverts with this selector
    /// @dev Output accounting rejects an oversized or short delta with `OutputOverflow` or `OutputBelowMin`.
    error OutputDeltaMismatch();

    /// @notice Thrown when a gateway settlement's measured output is below the slot receipt's minimum
    error OutputBelowMin();

    /// @notice Declared for ABI compatibility, with no settlement path that reverts with this selector
    /// @dev A settlement producing no output fails the nonzero minimum-output check and reverts `OutputBelowMin`.
    error OutputZero();

    /// @notice Thrown when a gateway settlement's measured output exceeds the uint96 note amount ceiling
    /// @dev The credited gateway-origin note stores the amount as a uint96, so it is rejected, not truncated.
    error OutputOverflow();

    /// @notice Thrown before Gateway settlement when the batch cannot preserve its remaining-work gas reserve.
    /// @param gasLeft Gas available at the settlement boundary.
    /// @param minimumRequired Minimum gas required for the current fallback, remaining withdrawals, and epoch tail.
    error InsufficientGatewaySettlementGas(uint256 gasLeft, uint256 minimumRequired);

    /// @notice Thrown by the simulation entry point on its success path, carrying one settlement result
    ///         per gateway slot.
    /// @dev All four arrays are index-aligned with the submitted `gatewaySlots`. `failureSelectors` and
    ///      `failureReasons` are retained for ABI compatibility. Fatal slot errors are reported via
    ///      `GatewayExecutionFailed`.
    /// @param outcomes Per-slot settlement outcome, `Executed` or `Fallback`
    /// @param receiptHashes Receipt hash recorded for each slot
    /// @param failureSelectors Retained for ABI compatibility
    /// @param failureReasons Retained for ABI compatibility
    error GatewaySimulationOutcomes(
        GatewaySettlementOutcome[] outcomes, bytes32[] receiptHashes, bytes4[] failureSelectors, bytes[] failureReasons
    );

    /// @notice Thrown when the simulated settlement call reverts instead of returning its outcomes
    /// @dev The simulation entry point always reverts, with `GatewaySimulationOutcomes` on the success path.
    /// @param reason Raw revert data bubbled from the simulated settlement call
    error GatewayExecutionFailed(bytes reason);

    /// @notice Declared for ABI compatibility, with no settlement or rescue path that reverts with this selector
    /// @dev Receipt field constraints are enforced during slot validation and revert `InvalidGatewaySlot`.
    error WrongReceiptCalldata();

    /// @notice Thrown when a deposit carries no rescue commitment, or the authority and salt do not open it
    error InvalidRescueCommitment();

    /// @notice Thrown when an authority-domain rescue is not sent by the committed rescue authority
    /// @dev Reached only when the commitment opens under the authority domain, which authorizes a direct call.
    error InvalidRescueAuthority();

    /// @notice Thrown when a rescue signature does not recover to the committed authority
    /// @dev An authority-domain rescue is a direct call, so supplying any signature is rejected here too.
    error InvalidRescueSignature();

    /// @notice Thrown when a gateway deposit rescue is attempted before the cancel delay has elapsed
    error RescueTooEarly();

    /// @notice Thrown when a gateway deposit rescue names the zero address as its destination
    error InvalidRescueDestination();

    // ============ Events ============

    /// @notice Emitted when a transfer/withdrawal epoch is submitted
    /// @param treeNum The tree that received the outputs
    /// @param rootNew The new root value
    /// @param countOld The leaf count before this epoch (0 if rollover to new tree)
    /// @param countNew The new leaf count
    event EpochSubmitted(uint256 indexed treeNum, uint256 indexed rootNew, uint32 countOld, uint32 countNew);

    /// @notice Emitted when a deposit epoch is submitted
    /// @param treeNum The tree that received the deposits
    /// @param rootNew The new root value
    /// @param countOld The leaf count before this epoch (0 if rollover to new tree)
    /// @param countNew The new leaf count
    event DepositEpochSubmitted(uint256 indexed treeNum, uint256 indexed rootNew, uint32 countOld, uint32 countNew);

    /// @notice Emitted when a hidden-recipient portal-deposit epoch is submitted
    /// @dev Same shape as DepositEpochSubmitted (the portal epoch appends to the SAME shared note tree),
    ///      emitted as a distinct event so an indexer can tell a portal-credit epoch apart from a normal
    ///      deposit epoch without decoding calldata. Like DepositEpochSubmitted it carries no per-output
    ///      data — portal-note discovery is driven entirely by the request-time PortalDepositRequested
    ///      event plus the off-chain registry, not by this epoch event.
    /// @param treeNum The tree that received the credited portal notes
    /// @param rootNew The new root value
    /// @param countOld The leaf count before this epoch (0 if rollover to new tree)
    /// @param countNew The new leaf count
    event PortalDepositEpochSubmitted(
        uint256 indexed treeNum, uint256 indexed rootNew, uint32 countOld, uint32 countNew
    );

    /// @notice Emitted when the active tree advances to a new tree
    /// @param oldTreeNumber The previous tree number
    /// @param newTreeNumber The new tree number
    event TreeAdvanced(uint256 oldTreeNumber, uint256 newTreeNumber);

    /// @notice Emitted when fee rates are updated
    /// @param withdrawFeeBps The new withdraw fee in basis points
    event FeesUpdated(uint16 withdrawFeeBps);

    /// @notice Emitted when a relay address is allowed or disallowed
    /// @param relay The relay address
    /// @param allowed Whether the relay is allowed
    event RelayUpdated(address relay, bool allowed);

    /// @notice Emitted when the operator address is updated
    /// @param oldOperator The previous operator address
    /// @param newOperator The new operator address
    event OperatorUpdated(address indexed oldOperator, address indexed newOperator);

    /// @notice Emitted when a deposit is requested
    /// @param depositRequestId The unique identifier for the deposit request
    /// @param depositor The address that made the deposit
    /// @param origin The source class for interpreting deposit ciphertexts
    /// @param tokenId The token ID from the registry
    /// @param totalAmount The total deposit amount (sum of hidden individual amounts)
    /// @param commitmentCount The number of commitments in this request
    /// @param commitmentsHash Sequential Poseidon hash of all commitments
    /// @param commitments The note commitments (for indexing)
    /// @param ciphertexts The encrypted deposit payloads for TEE decryption
    event DepositRequested(
        uint256 indexed depositRequestId,
        address indexed depositor,
        DepositOrigin indexed origin,
        uint16 tokenId,
        uint96 totalAmount,
        uint16 commitmentCount,
        uint256 commitmentsHash,
        uint256[] commitments,
        DepositCiphertext[] ciphertexts
    );

    /// @notice Emitted when a deposit is cancelled
    /// @param depositRequestId The deposit request that was cancelled
    event DepositCancelled(uint256 indexed depositRequestId);

    /// @notice Emitted on successful gateway-deposit rescue.
    /// @param depositRequestId The gateway deposit request that was rescued
    /// @param destination The address the rescued deposit was sent to
    event GatewayDepositRescued(uint256 indexed depositRequestId, address indexed destination);

    /// @notice Emitted with Gateway metadata for a gateway-origin DepositRequested event.
    /// @dev Keyed by depositRequestId so indexers can join it to the standard deposit channel.
    /// @param depositRequestId The deposit request this metadata joins to
    /// @param receiptHash The gateway receipt hash the slot settled against
    /// @param action The gateway action the slot performed
    /// @param outcome The settlement outcome recorded for the slot
    /// @param rescueCommitment keccak256(rescueAuthority, rescueSalt), which a later rescue must open
    /// @param nonce The per-gateway deposit counter that makes the request id unique
    event GatewayOriginDepositRecorded(
        uint256 indexed depositRequestId,
        bytes32 indexed receiptHash,
        GatewayAction action,
        GatewaySettlementOutcome outcome,
        bytes32 rescueCommitment,
        uint32 nonce
    );

    /// @notice Emitted when a gateway route is set/cleared.
    /// @param gateway The gateway address whose route changed
    /// @param route The route now assigned, `None` when the route was cleared
    event GatewayRouteUpdated(address indexed gateway, GatewayRoute route);

    /// @notice Emitted when gateway route authority is transferred.
    /// @param oldManager The account that previously held route authority
    /// @param newManager The account that now holds route authority
    event GatewayRouteManagerUpdated(address indexed oldManager, address indexed newManager);

    /// @notice Emitted when a forced withdrawal is requested
    /// @param submitter The relayer that submitted the permissionless request
    /// @param spenderAccountId The account whose live authorization was snapshotted at request time
    /// @param withdrawalTo The address to receive the withdrawal
    /// @param tokenId The token ID from the registry
    /// @param amount The withdrawal amount (gross, before fee)
    /// @param withdrawFeeBps The exact protocol fee snapshotted by the request
    /// @param nullifiers The nullifiers of the notes being spent
    /// @param inputCommitments The commitments of the notes being spent
    event ForcedWithdrawalRequested(
        address indexed submitter,
        uint256 indexed spenderAccountId,
        address indexed withdrawalTo,
        uint16 tokenId,
        uint96 amount,
        uint16 withdrawFeeBps,
        uint256[] nullifiers,
        uint256[] inputCommitments
    );

    /// @notice Emitted when a forced withdrawal is executed
    /// @param withdrawalTo The address that received the withdrawal
    /// @param tokenId The token ID from the registry
    /// @param amount The amount transferred to withdrawalTo, which equals the gross amount when no
    /// treasury is configured and the fee is therefore waived
    /// @param nullifiers The nullifiers of the notes that were spent
    /// @param inputCommitments The commitments of the notes that were spent
    event ForcedWithdrawalExecuted(
        address indexed withdrawalTo, uint16 tokenId, uint96 amount, uint256[] nullifiers, uint256[] inputCommitments
    );

    /// @notice Emitted when a forced withdrawal request is cancelled
    /// @param nullifiers The nullifiers from the cancelled request
    /// @param inputCommitments The commitments from the cancelled request
    event ForcedWithdrawalCancelled(uint256[] nullifiers, uint256[] inputCommitments);

    /// @notice Emitted when a competing nullifier spend made a pending request impossible and it was cleared
    /// @param nullifiers The nullifiers of the cleared request
    /// @param inputCommitments The input commitments of the cleared request
    event ForcedWithdrawalPruned(uint256[] nullifiers, uint256[] inputCommitments);

    /// @notice Emitted when the treasury address is updated
    /// @param oldTreasury The previous treasury address
    /// @param newTreasury The new treasury address
    event TreasuryUpdated(address oldTreasury, address newTreasury);

    /// @notice Emitted when the epoch verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event EpochVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the deposit verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event DepositVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the portal-deposit verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event PortalDepositVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted when the portal sweep fee rate is updated
    /// @param oldBps The previous sweep fee in basis points
    /// @param newBps The new sweep fee in basis points
    event PortalSweepFeeUpdated(uint16 oldBps, uint16 newBps);

    /// @notice Emitted when immediate payment of an earned portal sweep fee fails
    /// @param sweeper The recorded sweeper that earned the fee
    /// @param tokenId The registered token whose transfer failed
    /// @param amount The fee added to the sweeper's deferred balance
    event PortalSweepFeeDeferred(address indexed sweeper, uint16 indexed tokenId, uint256 amount);

    /// @notice Emitted when a sweeper claims a previously deferred portal sweep fee
    /// @param sweeper The sweeper that received the fee
    /// @param tokenId The registered token paid to the sweeper
    /// @param amount The claimed fee amount
    event PortalSweepFeeClaimed(address indexed sweeper, uint16 indexed tokenId, uint256 amount);

    /// @notice Emitted when a portal's balance is swept into escrow (step 1 of the portal deposit)
    /// @dev This is the indexer's sole discovery channel for portal notes: it carries no commitment
    ///      or ciphertext (the sweeper has no recipientMPK to encrypt for), so the indexer recomputes the
    ///      note from (E, counter) plus the off-chain (E -> recipientMPK, blind) registry.
    /// @param portalDepositId The unique identifier for the portal sweep record
    /// @param portal The portal address E that was swept
    /// @param counter The per-portal sweep counter snapshotted into this record (feeds noteRnd)
    /// @param tokenId The token ID from the registry
    /// @param amount The gross swept amount (measured received balance delta; the credited note is
    ///        amount minus the snapshotted fee, computed at epoch time)
    /// @param recipientBindH The recipient binding hash H (E's portalBinding()) snapshotted at sweep time; emitted so
    ///        the indexer's pending-sweep ingest is log-derived and never reads the portalPendingDeposits
    ///        storage slot, which a later cancel/reclaim deletes
    /// @param sweepFeeBps The sweep fee (bps) snapshotted at sweep time, from which the net credited amount is derived
    event PortalDepositRequested(
        uint256 indexed portalDepositId,
        address indexed portal,
        uint256 counter,
        uint16 tokenId,
        uint96 amount,
        uint256 recipientBindH,
        uint16 sweepFeeBps
    );

    /// @notice Emitted when the per-token minimum-sweep (dust) threshold is updated
    /// @param tokenId The token whose threshold changed
    /// @param oldMinSweep The previous threshold
    /// @param newMinSweep The new threshold
    event PortalMinSweepUpdated(uint16 indexed tokenId, uint96 oldMinSweep, uint96 newMinSweep);

    /// @notice Emitted when an escrowed portal deposit is reclaimed before it was credited
    /// @dev Portal analog of DepositCancelled. The full gross amount was refunded to the portal E; the
    ///      record is deleted and marked processed so it can be neither re-credited nor re-cancelled.
    /// @param portalDepositId The portal deposit record that was reclaimed
    event PortalDepositCancelled(uint256 indexed portalDepositId);

    /// @notice Emitted when the gift claim verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event GiftClaimVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /// @notice Emitted for each gift settled (re-minted) in a gift-claim epoch — claim or refund
    /// @dev A private claim and a private refund are deliberately indistinguishable on chain (identical
    ///      public shape, shared nullifier), so the contract emits ONE undifferentiated event rather than a
    ///      claim-vs-refund label: the actual branch is the gift-claim circuit's private `BranchType` witness
    ///      and is never revealed on chain. The operator recovers the true claim/refund branch from its own
    ///      off-chain request record; a public observer learns only that the gift was settled.
    /// @param giftNullifier The spent gift nullifier
    /// @param commitment The minted canonical note commitment
    event GiftSettled(uint256 indexed giftNullifier, uint256 commitment);

    /// @notice Emitted when a public gift exit is executed
    /// @param destination The address that received the exit payout
    /// @param tokenId The token ID from the registry
    /// @param amount The net amount received (after fee deduction)
    /// @param giftNullifier The gift nullifier that was spent
    event GiftExitExecuted(address indexed destination, uint16 tokenId, uint96 amount, uint256 giftNullifier);
    /// @notice Emitted when the forced withdrawal verifier is updated
    /// @param oldVerifier The previous verifier address
    /// @param newVerifier The new verifier address
    event ForcedVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // ============ Functions ============

    /// @notice Initialize the contract
    /// @param initialOwner The address of the initial owner
    /// @param epochVerifier_ The epoch verifier contract address
    /// @param depositVerifier_ The deposit verifier contract address
    /// @param forcedVerifier_ The forced withdrawal verifier contract address
    /// @param giftClaimVerifier_ The gift claim verifier contract address
    /// @param portalDepositVerifier_ The portal-deposit verifier contract address
    /// @param withdrawFeeBps_ Withdraw fee in basis points
    /// @param treasury_ The treasury address for fee collection
    function initialize(
        address initialOwner,
        address epochVerifier_,
        address depositVerifier_,
        address forcedVerifier_,
        address giftClaimVerifier_,
        address portalDepositVerifier_,
        uint16 withdrawFeeBps_,
        address treasury_
    ) external;

    /// @notice Set the operator address
    /// @dev Only callable by owner. Operator can manage relays and operational parameters.
    /// @param operator_ The new operator address
    function setOperator(address operator_) external;

    /// @notice Set allowed relay addresses
    /// @dev Only callable by operator. Relays can submit epochs on behalf of users.
    /// @param relays Array of relay addresses to update
    /// @param allowed Whether to allow or disallow the relays
    function setAllowedRelays(address[] calldata relays, bool allowed) external;

    /// @notice Set fee rates
    /// @dev Only callable by owner. Fees are in basis points (1/10000).
    /// @param withdrawFeeBps_ Withdraw fee in basis points
    function setFees(uint16 withdrawFeeBps_) external;

    /// @notice Set the epoch verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new epoch verifier address
    function setEpochVerifier(address verifier_) external;

    /// @notice Set the deposit verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new deposit verifier address
    function setDepositVerifier(address verifier_) external;

    /// @notice Set the portal-deposit verifier contract
    /// @dev Only callable by owner. The portal verifier is set post-deployment (it defaults to the
    ///      zero address) and is consumed by submitPortalDepositEpoch; the real mainnet VK is
    ///      registered after the trusted-setup ceremony.
    /// @param verifier_ The new portal-deposit verifier address
    function setPortalDepositVerifier(address verifier_) external;

    /// @notice Set the portal sweep fee rate in basis points
    /// @dev Only callable by owner; bounded by MAX_FEE_BPS. The fee is paid to the sweeper (not the
    ///      treasury), snapshotted into each pending record at sweep time. 0 in the operator-run MVP.
    /// @param portalSweepFeeBps_ The new portal sweep fee in basis points
    function setPortalSweepFeeBps(uint16 portalSweepFeeBps_) external;

    /// @notice Set the per-token minimum-sweep (dust) threshold
    /// @dev Only callable by owner. A sweep whose measured delta is below this threshold reverts, so
    ///      trivial balances are not swept at a loss once a fee is enabled. Defaults to 0 (any
    ///      non-zero delta passes). The threshold is a uint96 to match the record's amount field.
    /// @param tokenId The token to configure
    /// @param minSweep The minimum received delta required to sweep this token
    function setPortalMinSweep(uint16 tokenId, uint96 minSweep) external;

    /// @notice Sweep a registered portal's balance into escrow (step 1 of the portal deposit)
    /// @dev Permissionless: any caller may sweep (a keeper for the fee, or the owner for zero fee
    ///      paying only gas). nonReentrant — the measured-delta accounting depends on it. The pool
    ///      invokes the portal's push (the pool-invoked push), measures the received delta as the gross amount,
    ///      snapshots the current sweep fee, reads+increments the per-portal counter, and stores a
    ///      pending record keyed by portalDepositId. The owner binding is read from the portal's own account
    ///      storage via a staticcall to its portalBinding() (the binding lives there under EIP-7702, not in
    ///      pool storage), never supplied by the caller, so a sweeper who does not know the recipient cannot redirect
    ///      the credit. Only standard ERC-20s registered with the protocol may be swept; fee-on-
    ///      transfer / rebasing tokens are excluded by registration because the measured delta has no
    ///      caller-declared amount to validate against.
    /// @param portal The portal address to sweep (must have a registered binding)
    /// @param tokenId The registered ERC-20 token to sweep
    /// @return portalDepositId The identifier of the created pending record
    function requestPortalDeposit(address portal, uint16 tokenId) external returns (uint256 portalDepositId);

    /// @notice Set the gift claim verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new gift claim verifier address
    function setGiftClaimVerifier(address verifier_) external;
    /// @notice Set the forced withdrawal verifier contract
    /// @dev Only callable by owner.
    /// @param verifier_ The new forced withdrawal verifier address
    function setForcedVerifier(address verifier_) external;

    /// @notice Set the treasury address for fee collection
    /// @dev Only callable by owner.
    /// @param treasury_ The new treasury address
    function setTreasury(address treasury_) external;

    /// @notice Submit an epoch with mixed transfers and withdrawals
    /// @dev Only callable by allowed relays. Supports N inputs and M outputs per transfer slot.
    ///      The circuit uses IsWithdrawal flag to select the appropriate fee rate.
    ///      Auth roots may be current or superseded within `maxEpochAuthStalenessBlocks`.
    /// @param treeState Tree state with sparse roots (usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover)
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof;
    ///                      each must be current or recent within `maxEpochAuthStalenessBlocks`
    /// @param nTransfers Number of active transfers
    /// @param feeTokenCount Number of active fee tokens
    /// @param feeNPK Fee recipient's Note Public Key
    /// @param inputsPerTransfer Number of inputs for each transfer [maxTransfers]
    /// @param outputsPerTransfer Number of outputs for each transfer [maxTransfers]
    /// @param nullifiers Nullifiers per transfer slot [maxTransfers][maxInputsPerTransfer]
    /// @param transfers Transfer metadata with shared keys and outputs per transfer
    /// @param feeTransfer Fee transfer metadata with shared keys and fee outputs
    /// @param withdrawals Withdrawal details (sorted by slot index)
    /// @param withdrawalSlots Transfer slot indices for each withdrawal (sorted ascending)
    /// @param provingTimestamp Timestamp used by the circuit for auth expiry checks
    /// @param proof Groth16 proof
    /// @param gatewaySlots Sparse, strictly-ascending-by-`withdrawalIndex` gateway slots. Empty for a plain
    ///        epoch (every withdrawal routes `None`); a paired slot dispatches its withdrawal along the
    ///        target's registered route and binds the slot into the per-withdrawal
    ///        `PB:WITHDRAW:GATEWAY:v2` digest so a relay cannot mutate user intent.
    function submitEpoch(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint32 nTransfers,
        uint32 feeTokenCount,
        uint256 feeNPK,
        uint32[] calldata inputsPerTransfer,
        uint32[] calldata outputsPerTransfer,
        uint256[][] calldata nullifiers,
        Transfer[] calldata transfers,
        Transfer calldata feeTransfer,
        Withdrawal[] calldata withdrawals,
        uint32[] calldata withdrawalSlots,
        uint64 provingTimestamp,
        uint256[8] calldata proof,
        GatewaySlot[] calldata gatewaySlots
    ) external;

    /// @notice Execute the gateway withdrawal path in an eth_call and always revert with the outcome.
    /// @dev Success is encoded as `GatewaySimulationOutcomes(outcomes, receiptHashes, failureSelectors,
    ///      failureReasons)` with per-slot `Executed` or `Fallback` outcomes. Gateway settlement
    ///      failures are wrapped as `GatewayExecutionFailed(reason)`. This does not verify proofs,
    ///      nullifiers, or tree state.
    /// @param withdrawals The withdrawal set to simulate
    /// @param gatewaySlots The gateway slots to settle, index-aligned with the reported outcomes
    function simulateGatewayWithdrawals(Withdrawal[] calldata withdrawals, GatewaySlot[] calldata gatewaySlots) external;

    /// @notice Self-call-only boundary that executes one gateway slot and records its settlement outcome
    ///         in an isolated call frame.
    /// @dev Isolation is the security property: gas exhaustion inside this frame is catchable by the
    ///      settlement loop, so one gas-hungry gateway cannot revert the whole epoch. Gateway execution
    ///      and the resulting deposit record share this frame, so a failure while recording rolls the
    ///      gateway side effects back before the parent recovers. Only the pool itself may call it.
    /// @param withdrawal The withdrawal that owns the slot
    /// @param gatewaySlot The gateway slot to execute
    /// @return outcome The settlement outcome recorded for the slot
    /// @return receiptHash The receipt hash recorded for the slot
    function executeGatewaySlotIsolated(Withdrawal calldata withdrawal, GatewaySlot calldata gatewaySlot)
        external
        returns (GatewaySettlementOutcome outcome, bytes32 receiptHash);

    // ─────────────────────────── Gateway entry points ───────────────────────────

    /// @notice Route-manager-only: approve or revoke a gateway route.
    /// @param gateway The gateway address to approve or revoke
    /// @param route The route to assign, `None` to revoke
    function setGatewayRoute(address gateway, GatewayRoute route) external;

    /// @notice Assign the account allowed to approve and revoke gateway routes.
    /// @param manager The account granted route authority
    function setGatewayRouteManager(address manager) external;

    /// @notice One-time upgrade migration that initializes gateway route authority.
    /// @dev Call atomically through ProxyAdmin.upgradeAndCall for an existing proxy.
    /// @param manager The account seeded as the initial route manager
    function initializeGatewayRouteManager(address manager) external;

    /// @notice Resolve a registered token id to its ERC-20 address. Used by gateways for runtime
    ///         registry rechecks.
    /// @param tokenId The registered token id to resolve
    /// @return The ERC-20 address registered for that token id
    function tokenAddressOf(uint16 tokenId) external view returns (address);

    /// @notice Rescue a gateway-origin pending deposit after `cancelDelay`.
    /// @dev The committed domain selects authentication: a key credential uses an EIP-191
    ///      signature, while a domain-separated authority must call directly with an empty signature.
    /// @param depositRequestId Pending gateway-origin deposit to rescue.
    /// @param destination Nonzero address that receives the deposited tokens.
    /// @param rescueSalt Salt committed when the gateway-origin deposit was created.
    /// @param rescueAuthority Credential signer or direct-call authority committed by the rescue hash.
    /// @param signature EIP-191 credential signature, or empty bytes for direct authority authentication.
    function rescueGatewayDeposit(
        uint256 depositRequestId,
        address destination,
        bytes32 rescueSalt,
        address rescueAuthority,
        bytes calldata signature
    ) external;

    // ─────────────────────── Gateway view getters ───────────────────────

    /// @notice Approved route for an address; `None` means unapproved.
    /// @param gateway The address to look up
    /// @return The approved route, `None` when the address is unapproved
    function gatewayRoute(address gateway) external view returns (GatewayRoute);

    // ─────────────────────── Existing deposit / withdrawal surface ───────────────────────

    /// @notice Step 1 of 2-step deposit: Request a deposit with one or more commitments
    /// @dev Tokens are transferred from caller to contract. Deposits are fee-free.
    ///      Only standard ERC20 tokens are supported. Fee-on-transfer tokens will revert.
    ///      Rebasing tokens (stETH, AMPL) are NOT supported and may cause fund loss.
    ///      Individual commitment amounts are hidden; only totalAmount is public.
    /// @param _tokenId TokenRegistry token ID
    /// @param _totalAmount Total deposit amount (sum of hidden individual amounts)
    /// @param _commitments Note commitments for each output
    /// @param _ciphertexts Encrypted deposit payloads for TEE decryption
    /// @return depositRequestId The unique identifier for the deposit request
    function requestDeposit(
        uint16 _tokenId,
        uint96 _totalAmount,
        uint256[] calldata _commitments,
        DepositCiphertext[] calldata _ciphertexts
    ) external returns (uint256 depositRequestId);

    /// @notice Cancel a pending deposit and refund tokens
    /// @dev Can only be called by the depositor after cancelDelay blocks.
    /// @param _depositRequestId The deposit to cancel
    function cancelDeposit(uint256 _depositRequestId) external;

    /// @notice Step 2 of 2-step deposit: Process batch of pending deposits
    /// @dev Only callable by allowed relays. Deposits are fee-free.
    ///      TEE prover verifies deposit data without requiring user approval signatures.
    /// @param treeState Tree state with sparse roots (usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover)
    /// @param nTotalCommitments Total number of commitments across all deposits
    /// @param outputs Output metadata per commitment
    /// @param deposits Array of deposit entries (depositRequestId references)
    /// @param proof Groth16 proof
    function submitDepositEpoch(
        EpochTreeState calldata treeState,
        uint32 nTotalCommitments,
        Output[] calldata outputs,
        DepositEntry[] calldata deposits,
        uint256[8] calldata proof
    ) external;

    /// @notice Step 2 of the portal deposit: credit swept escrow into the shielded pool (relay-only)
    /// @dev Only callable by allowed relays. Mirrors submitDepositEpoch but for hidden-recipient portal
    ///      deposits: each entry references a portalDepositId whose record was escrowed by
    ///      requestPortalDeposit. The contract builds EVERY public input from the stored record — the
    ///      owner binding H, the counter, and the net credited amount (gross − snapshotted fee) — so a
    ///      malicious relay cannot substitute a different amount, recipient binding, or counter. The
    ///      caller supplies only the appended note commitment per entry (the sweeper has no recipientMPK to
    ///      build it at sweep time, so it cannot be bound earlier). The portal epoch appends to the SAME
    ///      note tree as the deposit/transfer epochs and inherits their exact-match tree-state CAS, so a
    ///      portal epoch racing another epoch reverts on stale state and is rebuilt+retried by the relay.
    ///      Any snapshotted sweep fee becomes owed at credit time (not at sweep) to the SWEEPER recorded on each
    ///      record. If the token rejects that recipient, the epoch records the fee for a same-recipient claim
    ///      and continues. The relay submitting the epoch never receives the fee.
    ///      VK requirement: this entrypoint sets maxSlots = commitments.length (the padded VK shape) and
    ///      nRequests = entries.length (the active count, nRequests <= maxSlots), mirroring submitDepositEpoch's
    ///      outputs/deposits split — the circuit zero-pads the trailing maxSlots - nRequests slots. The portal
    ///      verifier looks up the VK by maxSlots, so a portal VK MUST be registered for the batch SHAPE the
    ///      relay submits in [1, maxBatchSize]; an unregistered shape reverts VerifyingKeyNotFound (fails safe
    ///      — no mis-credit, a liveness break the relay avoids by only submitting registered shapes).
    /// @param treeState Tree state with sparse roots (usedRoots, activeTreeNumber, countOld, rootNew, countNew, rollover)
    /// @param entries Portal deposit entries (portalDepositId references) to credit in this epoch
    /// @param commitments Appended note commitments, one per entry, in entry order
    /// @param proof Groth16 proof for the DepositPortalCircuit
    function submitPortalDepositEpoch(
        EpochTreeState calldata treeState,
        PortalDepositEntry[] calldata entries,
        uint256[] calldata commitments,
        uint256[8] calldata proof
    ) external;

    /// @notice Claim the caller's deferred portal sweep fee for one registered token
    /// @dev Payment always goes to msg.sender. A token-level recipient restriction can make the claim revert,
    ///      in which case the deferred balance is restored atomically and can be retried after the restriction
    ///      is removed.
    /// @param tokenId The registered token whose deferred fee should be claimed
    function claimPortalSweepFee(uint16 tokenId) external;

    /// @notice Isolated self-call target for best-effort portal sweep fee payments
    /// @dev Only the pool may call this function. It exists so submitPortalDepositEpoch can catch one token's
    ///      transfer failure without weakening SafeERC20 behavior or reverting the entire epoch. The outer
    ///      submission is already nonReentrant, so this self-call target intentionally has no reentrancy guard.
    /// @param tokenId The token the sweep fee is paid in
    /// @param sweeper The account receiving the sweep fee
    /// @param amount The fee amount to transfer
    function payPortalSweepFee(uint16 tokenId, address sweeper, uint256 amount) external;

    /// @notice Reclaim an escrowed portal deposit that was never credited, refunding the gross to E
    /// @dev Permissionless and callable after cancelDelay blocks have passed since the sweep. Unlike
    ///      cancelDeposit (which restricts the caller to the depositor and refunds msg.sender), a portal
    ///      record has no depositor: the refund always goes to the portal address E recorded at sweep
    ///      time, never to the caller, so any party may trigger the reclaim on the owner's behalf. The
    ///      full gross amount is refunded — no fee is charged on a record that never reached an epoch —
    ///      and the record is deleted and marked processed so it can be neither re-credited nor
    ///      re-cancelled. Reverts if the record does not exist, was already credited or reclaimed, or the
    ///      cancel delay has not elapsed. This is the liveness backstop: a sweep the relay never finalizes
    ///      cannot strand funds.
    /// @param portalDepositId The portal deposit record to reclaim
    function cancelPortalDeposit(uint256 portalDepositId) external;

    /// @notice Step 1 of 2-step forced withdrawal: Request forced withdrawal with proof
    /// @dev The exact AuthRegistry leaf is checked once at request time. Acceptance snapshots authorization,
    ///      the current withdrawal fee, and the payout. Later auth revoke/rotation/expiry does not invalidate
    ///      the request; the account owner must explicitly cancel it before execution if desired.
    ///      The proof is not bound to msg.sender, so any relayer may submit it while authorization is live.
    /// @param knownRoots Sparse tree roots used in this batch
    /// @param forcedAuthData One forced-only pair: packed authContext in treeNumber and authId in root
    /// @param spenderAccountId Account ID for owner lookup (public input in ZK proof)
    /// @param nullifiers Nullifiers of the notes being spent
    /// @param inputCommitments Commitments of the notes being spent
    /// @param withdrawal Withdrawal details (amount is gross, before fee)
    /// @param proof Groth16 proof of note ownership
    function requestForcedWithdrawal(
        TreeRootPair[] calldata knownRoots,
        TreeRootPair[] calldata forcedAuthData,
        uint256 spenderAccountId,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint256[8] calldata proof
    ) external;

    /// @notice Step 2 of 2-step forced withdrawal: Execute forced withdrawal
    /// @dev Permissionless after forcedWithdrawalDelay blocks. AuthRegistry is deliberately not consulted.
    ///      Layout-frozen v2 requests accepted before the upgrade remain executable under the same snapshot rule.
    /// @param nullifiers Nullifiers from the original request
    /// @param inputCommitments Commitments from the original request
    function executeForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments) external;

    /// @notice Cancel a pending forced withdrawal request
    /// @dev The current account owner may cancel immediately. Request submitters, including legacy requesters,
    ///      have no cancellation authority. Anyone may prune a request after a competing nullifier spend makes
    ///      execution impossible.
    /// @param nullifiers Nullifiers from the original request
    /// @param inputCommitments Commitments from the original request
    function cancelForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments) external;

    /// @notice Submit a private gift-claim epoch (batched recipient claims / sender refunds)
    /// @dev Only callable by allowed relays. Each slot consumes exactly one gift note and mints one
    ///      canonical note; claim and refund go through the same path and are indistinguishable on chain.
    ///      The gift nullifier is spent through the shared `nullifierSpent` map, so a claim and a refund of
    ///      the same gift are mutually exclusive even across batches.
    /// @param treeState Tree state with sparse roots (funding-tree roots + active tree for the mint append)
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs for the auth trees referenced by this proof;
    ///                      relay epochs permit the configured short staleness window
    /// @param giftNullifiers Active gift nullifiers (length = nClaims)
    /// @param outputs Fixed-capacity minted output metadata. The first nClaims entries are active and the suffix is zero-padded.
    /// @param digestRootIndices Packed 4-bit indices (64 per word) declaring, per claim, its sparse
    ///                          treeState.usedRoots slot. Gift authorization v2 excludes mutable roots while
    ///                          the proof continues to bind gift membership and the active append root.
    /// @param currentBlock Relay-attested block bound as a circuit public input; must be <= block.number at submission
    /// @param provingTimestamp Recent UNIX timestamp used by the circuit for auth-key expiry checks;
    ///                         must not be in the future or older than MAX_PROOF_AGE
    /// @param proof Groth16 proof
    function submitGiftClaimEpoch(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256[] calldata giftNullifiers,
        Output[] calldata outputs,
        uint256[] calldata digestRootIndices,
        uint256 currentBlock,
        uint64 provingTimestamp,
        uint256[8] calldata proof
    ) external;

    /// @notice Permissionless 1-step public gift exit: pay a gift's funds to a bound destination without the relay
    /// @dev The single public exit for both recipient and sender. This verifies a public-payout gift-claim
    ///      proof and pays out in a single call. There is NO on-chain deadline check: the real deadline is a
    ///      private circuit witness bound into the gift note, and the gift-claim circuit's refund branch
    ///      enforces currentBlock >= refundAfterBlock against the caller-attested currentBlock, which the
    ///      contract validates is <= block.number — so refundAfterBlock <= currentBlock <= block.number proves
    ///      the deadline has genuinely passed without forcing the proof to anchor an exact inclusion block. A
    ///      recipient-claim payout proof is also structurally accepted (it has no in-circuit deadline) —
    ///      each branch proves its own authority and pays only the digest-bound destination, and the shared
    ///      nullifier keeps this mutually exclusive with a private claim/refund.
    ///      Emits {GiftExitExecuted}.
    /// @param knownRoots Sparse funding-tree roots used in this proof
    /// @param usedAuthRoots Sparse (treeNumber, root) pairs used by any key- or approval-authorized proof;
    ///                      empty only for a secret-bearer exit
    /// @param giftNullifier The gift nullifier being spent
    /// @param exitAuthLeaf Exact active key or Safe-approval leaf for a wallet-recipient or sender-refund exit,
    ///                     or zero for a secret-bearer exit
    /// @param authLeafLocation Packed auth-tree location (`treeNumber << 32 | leafIndex`), or zero for a
    ///                         secret-bearer exit
    /// @param destination The public exit destination (bound into the digest)
    /// @param tokenId The compact token ID
    /// @param amount The gift amount (gross, before fee)
    /// @param minNetAmount Minimum acceptable net payout after the current withdrawal fee; bound into the proof digest
    /// @param viewingKey Blinded sender viewing key bound into the digest
    /// @param teeWrapKey Wrapped TEE key bound into the digest
    /// @param activeTreeCount Leaf count paired with the active root and attested by the caller. Below capacity
    ///        it may describe a historical current-tree root so later appends do not stale the exit proof. At
    ///        capacity it must match the live full tip and selects the circuit's proof-only rollover representation
    /// @param currentBlock Caller-attested block bound as the proof's currentBlock public input; must be <= block.number at submission so an off-chain-built proof need not predict its exact inclusion block
    /// @param provingTimestamp Recent UNIX timestamp used by the circuit for auth-key expiry checks;
    ///                         must not be in the future or older than MAX_PROOF_AGE
    /// @param proof Groth16 proof of gift ownership
    function publicGiftExit(
        TreeRootPair[] calldata knownRoots,
        TreeRootPair[] calldata usedAuthRoots,
        uint256 giftNullifier,
        uint256 exitAuthLeaf,
        uint64 authLeafLocation,
        address destination,
        uint16 tokenId,
        uint96 amount,
        uint96 minNetAmount,
        bytes32 viewingKey,
        bytes32 teeWrapKey,
        uint32 activeTreeCount,
        uint256 currentBlock,
        uint64 provingTimestamp,
        uint256[8] calldata proof
    ) external;

    /// @notice Check if a root is known for a specific tree
    /// @dev For finalized trees, only the final root is valid.
    ///      For the current tree, checks the root history ring buffer.
    /// @param treeNum The tree number to check
    /// @param root_ The root to verify
    /// @return True if the root is known
    function isKnownTreeRoot(uint256 treeNum, uint256 root_) external view returns (bool);

    // ============ View Functions (State Variables) ============

    /// @notice Current active tree number
    /// @return The current active tree number
    function currentTreeNumber() external view returns (uint256);

    /// @notice Get the root of a specific tree
    /// @param treeNum The tree number
    /// @return The tree root
    function treeRoot(uint256 treeNum) external view returns (uint256);

    /// @notice Get the leaf count of a specific tree
    /// @param treeNum The tree number
    /// @return The number of leaves in the tree
    function treeCount(uint256 treeNum) external view returns (uint32);

    /// @notice Get a historical root from a tree's history
    /// @param treeNum The tree number
    /// @param idx The history index
    /// @return The historical root
    function treeRootHistory(uint256 treeNum, uint256 idx) external view returns (uint256);

    /// @notice Get the cursor position in the root history ring buffer
    /// @param treeNum The tree number
    /// @return The cursor position
    function treeRootHistoryCursor(uint256 treeNum) external view returns (uint256);

    /// @notice Check if a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if spent
    function nullifierSpent(uint256 nullifier) external view returns (bool);

    /// @notice Check if an address is an allowed relay
    /// @param relay The address to check
    /// @return True if allowed
    function allowedRelays(address relay) external view returns (bool);

    /// @notice Withdraw fee rate in basis points
    /// @return The withdraw fee rate in basis points
    function withdrawFeeBps() external view returns (uint16);

    /// @notice Maximum number of inputs for forced withdrawals
    /// @return The maximum number of inputs for forced withdrawals
    function maxForcedInputs() external view returns (uint32);

    /// @notice Maximum blocks a superseded auth root remains valid for relay-submitted epochs
    /// @return The maximum blocks a superseded auth root stays valid
    function maxEpochAuthStalenessBlocks() external view returns (uint64);

    /// @notice Legacy-named auth-root staleness bound used by public gift exits
    /// @dev Forced withdrawal v3 does not use root staleness; it reads an exact live auth leaf.
    /// @return The auth-root staleness bound applied to public gift exits
    function maxForcedWithdrawalAuthStalenessBlocks() external view returns (uint64);

    /// @notice Get a pending deposit by request ID
    /// @param depositRequestId The deposit request ID
    /// @return depositor The depositor address
    /// @return tokenId The token ID
    /// @return totalAmount The total deposit amount
    /// @return requestBlock The block number when deposit was requested
    /// @return nonce The depositor's nonce at request time
    /// @return commitmentCount The number of commitments in this request
    /// @return commitmentsHash Sequential Poseidon hash of all commitments
    function pendingDeposits(uint256 depositRequestId)
        external
        view
        returns (
            address depositor,
            uint16 tokenId,
            uint96 totalAmount,
            uint64 requestBlock,
            uint32 nonce,
            uint16 commitmentCount,
            uint256 commitmentsHash,
            bytes32 rescueCommitment
        );

    /// @notice Check if a deposit has been processed
    /// @param depositRequestId The deposit request ID
    /// @return True if processed
    function processedDeposits(uint256 depositRequestId) external view returns (bool);

    /// @notice Get deposit nonce for an address
    /// @param depositor The depositor address
    /// @return The current nonce
    function depositNonces(address depositor) external view returns (uint32);

    /// @notice Get a forced withdrawal request by key
    /// @param requestKey The request key
    /// @return requestBlock The block number when request was made
    /// @return requester Legacy field retained for storage compatibility; ignored by the current policy
    /// @return withdrawalTo The withdrawal recipient address
    /// @return tokenId The token ID
    /// @return amount The withdrawal amount (gross)
    /// @return withdrawFeeBps The withdraw fee at request time
    /// @return inputCount The number of input notes
    /// @return spenderAccountId The account ID for owner lookup
    /// @return nullifiersHash Bound nullifier-array hash
    /// @return commitmentsHash Bound commitment-array hash
    function forcedWithdrawalRequests(uint256 requestKey)
        external
        view
        returns (
            uint64 requestBlock,
            address requester,
            address withdrawalTo,
            uint16 tokenId,
            uint96 amount,
            uint16 withdrawFeeBps,
            uint8 inputCount,
            uint256 spenderAccountId,
            bytes32 nullifiersHash,
            bytes32 commitmentsHash
        );

    /// @notice Get the request key for a commitment
    /// @param commitment The note commitment
    /// @return The request key (0 if not requested)
    function commitmentToRequestKey(uint256 commitment) external view returns (uint256);

    /// @notice Treasury address for fee collection
    /// @return The treasury address fees are collected to
    function treasury() external view returns (address);

    /// @notice Operator address for operational functions
    /// @return The operator address
    function operator() external view returns (address);

    // ============ Immutable Variables ============

    /// @notice Token registry contract
    /// @return The token registry contract
    function tokenRegistry() external view returns (ITokenRegistry);

    /// @notice Auth registry contract
    /// @return The auth registry contract
    function authRegistry() external view returns (IAuthRegistry);

    /// @notice Maximum number of transfer slots per epoch
    /// @return The maximum number of transfer slots per epoch
    function maxBatchSize() external view returns (uint32);

    /// @notice Maximum inputs per transfer
    /// @return The maximum inputs per transfer
    function maxInputsPerTransfer() external view returns (uint32);

    /// @notice Maximum outputs per transfer
    /// @return The maximum outputs per transfer
    function maxOutputsPerTransfer() external view returns (uint32);

    /// @notice Maximum number of fee tokens
    /// @return The maximum number of fee tokens
    function maxFeeTokens() external view returns (uint32);

    /// @notice Delay before deposits can be cancelled
    /// @return The delay before deposits can be cancelled
    function cancelDelay() external view returns (uint256);

    /// @notice Delay before forced withdrawals can be executed
    /// @return The delay before forced withdrawals can be executed
    function forcedWithdrawalDelay() external view returns (uint256);

    /// @notice Epoch verifier contract
    /// @return The epoch verifier contract
    function epochVerifier() external view returns (IEpochVerifier);

    /// @notice Deposit verifier contract
    /// @return The deposit verifier contract
    function depositVerifier() external view returns (IDepositVerifier);

    /// @notice Forced withdrawal verifier contract
    /// @return The forced withdrawal verifier contract
    function forcedVerifier() external view returns (IForcedWithdrawVerifier);

    /// @notice Gift claim verifier contract
    /// @return The gift claim verifier contract
    function giftClaimVerifier() external view returns (IGiftClaimVerifier);
}
