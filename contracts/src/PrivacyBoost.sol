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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {
    TOKEN_TYPE_ERC20,
    MAX_NOTE_ROOTS_PER_PROOF,
    MAX_NOTE_TREE_DEPTH,
    MAX_NOTE_TREE_NUMBER,
    MAX_AUTH_ROOTS_PER_PROOF,
    ROOT_HISTORY_SIZE,
    MAX_PROOF_AGE
} from "src/interfaces/Constants.sol";
import {LibZeroHashes} from "src/lib/LibZeroHashes.sol";
import {
    Output,
    Transfer,
    Withdrawal,
    PendingDeposit,
    PortalPendingDeposit,
    DepositCiphertext,
    DepositEntry,
    PortalDepositEntry,
    ForcedWithdrawalRequest,
    EpochTreeState,
    TreeRootPair,
    GatewaySlot,
    GatewaySettlementOutcome,
    GatewayRoute
} from "src/interfaces/IStructs.sol";
import {
    IPrivacyBoost,
    IEpochVerifier,
    IDepositVerifier,
    IPortalDepositVerifier,
    IForcedWithdrawVerifier,
    IGiftClaimVerifier
} from "src/interfaces/IPrivacyBoost.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {ITokenRegistry} from "src/interfaces/ITokenRegistry.sol";
import {LibDeposit} from "src/lib/LibDeposit.sol";
import {LibEpoch} from "src/lib/LibEpoch.sol";
import {LibForced} from "src/lib/LibForced.sol";
import {LibGateway} from "src/lib/LibGateway.sol";
import {LibGift} from "src/lib/LibGift.sol";
import {LibPoolShared} from "src/lib/LibPoolShared.sol";
import {LibPortal} from "src/lib/LibPortal.sol";

/// @title PrivacyBoost
/// @notice Epoch-based private transfer pool (v2)
/// @custom:security-contact contact@sunnyside.io
contract PrivacyBoost is IPrivacyBoost, Ownable2StepUpgradeable, ReentrancyGuardTransient {
    bytes32 private constant ERC1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    /// @dev Maximum fee rate in basis points (10% = 1,000 bps).
    uint256 private constant MAX_FEE_BPS = 1_000;

    /// @notice Token registry contract
    ITokenRegistry public immutable tokenRegistry;

    /// @notice Auth registry contract
    IAuthRegistry public immutable authRegistry;

    /// @notice Maximum number of transfer slots per epoch
    uint32 public immutable maxBatchSize;

    /// @notice Maximum inputs per transfer
    uint32 public immutable maxInputsPerTransfer;

    /// @notice Maximum outputs per transfer
    uint32 public immutable maxOutputsPerTransfer;

    /// @notice Maximum number of fee tokens
    uint32 public immutable maxFeeTokens;

    /// @notice Delay before deposits can be cancelled
    uint256 public immutable cancelDelay;

    /// @notice Delay before forced withdrawals can be executed
    uint256 public immutable forcedWithdrawalDelay;

    /// @notice Maximum number of inputs for forced withdrawals
    uint32 public immutable maxForcedInputs;

    /// @notice Maximum blocks a superseded auth root remains valid for relay-submitted epochs
    uint64 public immutable maxEpochAuthStalenessBlocks;

    /// @notice Maximum blocks a superseded auth root remains valid for forced-withdrawal requests
    uint64 public immutable maxForcedWithdrawalAuthStalenessBlocks;

    /// @notice Note Merkle tree depth
    /// @dev Must match circuit parameter MERKLE_DEPTH.
    uint8 public immutable merkleDepth;

    /// @notice Epoch verifier contract
    IEpochVerifier public epochVerifier;

    /// @notice Deposit verifier contract
    IDepositVerifier public depositVerifier;

    /// @notice Forced withdrawal verifier contract
    IForcedWithdrawVerifier public forcedVerifier;

    /// @notice Current active tree number
    uint256 public currentTreeNumber;

    /// @notice Treasury address for fee collection
    address public treasury;

    /// @notice Operator address for operational functions
    address public operator;

    /// @notice Withdraw fee rate in basis points
    uint16 public withdrawFeeBps;

    /// @custom:deprecated Orphaned by the auth-layer v2 upgrade (was the auth-snapshot block interval).
    ///                    No longer read or written. Retained for storage-layout preservation; a later
    ///                    cleanup upgrade folds slots 6 and 18-25 into __gap.
    uint256 private authSnapshotInterval;

    /// @notice Get the root of a specific tree
    /// @dev Per-tree Merkle state
    mapping(uint256 treeNum => uint256 root) public treeRoot;

    /// @notice Get the leaf count of a specific tree
    mapping(uint256 treeNum => uint32 leafCount) public treeCount;

    /// @notice Get a historical root from a tree's history
    /// @dev Ring buffer for recent roots (allows proofs against slightly stale state)
    mapping(uint256 treeNum => uint256[ROOT_HISTORY_SIZE] roots) public treeRootHistory;

    /// @notice Get the cursor position in the root history ring buffer
    mapping(uint256 treeNum => uint256 cursor) public treeRootHistoryCursor;

    /// @notice Check if a nullifier has been spent
    mapping(uint256 nullifier => bool spent) public nullifierSpent;

    /// @notice Check if an address is an allowed relay
    mapping(address relay => bool allowed) public allowedRelays;

    /// @notice Get a pending deposit by request ID
    /// @dev 2-step deposit: request → (wait cancelDelay) → process or cancel
    mapping(uint256 depositRequestId => PendingDeposit deposit) public pendingDeposits;

    /// @notice Check if a deposit has been processed
    mapping(uint256 depositRequestId => bool processed) public processedDeposits;

    /// @notice Get deposit nonce for an address
    mapping(address depositor => uint32 nonce) public depositNonces;

    /// @notice Get a forced withdrawal request by key
    /// @dev 2-step forced withdrawal: request → wait forcedWithdrawalDelay → execute or cancel
    mapping(uint256 requestKey => ForcedWithdrawalRequest request) public forcedWithdrawalRequests;

    /// @notice Get the request key for a commitment
    mapping(uint256 commitment => uint256 requestKey) public commitmentToRequestKey;

    // The following nine slots (18-25, plus `authSnapshotInterval` at slot 6 above) are orphaned by
    // the auth-layer v2 upgrade, which replaced per-round auth snapshots with AuthRegistry root
    // freshness checks. They are no longer read or written and remain only to preserve the upgrade storage
    // layout. A later cleanup upgrade reclaims them.

    /// @custom:deprecated Orphaned: was the per-round auth snapshot root mapping.
    mapping(uint256 round => mapping(uint256 treeNum => uint256 root)) private authSnapshots;

    /// @custom:deprecated Orphaned: was the most recent round for which a snapshot was taken.
    uint256 private latestSnapshotRound;

    /// @custom:deprecated Orphaned: was the start block of the auth snapshot schedule segment.
    uint256 private authSnapshotStartBlock;

    /// @custom:deprecated Orphaned: was the start round of the auth snapshot schedule segment.
    uint256 private authSnapshotStartRound;

    /// @custom:deprecated Orphaned: was the monotonic version of the auth snapshot schedule.
    uint256 private authSnapshotScheduleVersion;

    /// @custom:deprecated Orphaned: was the pending authSnapshotInterval value.
    uint256 private pendingAuthSnapshotInterval;

    /// @custom:deprecated Orphaned: was the block at which the pending interval would activate.
    uint256 private pendingAuthSnapshotEffectiveBlock;

    /// @custom:deprecated Orphaned: was the round at which the pending interval would activate.
    uint256 private pendingAuthSnapshotStartRound;

    // ─────────────── Portal deposit storage (hidden-recipient deposit address) ───────────────
    // Appended at the end of the storage layout (before __gap) so existing slots are
    // untouched on upgrade. These declarations consume 5 storage slots: the three record
    // mappings + the portalMinSweep mapping each take one slot, plus one shared slot for the
    // packed pair portalSweepFeeBps (uint16, 2 bytes) and portalDepositVerifier (address,
    // 20 bytes) which fit one slot (2 + 20 = 22 <= 32). The packed pair is declared BEFORE
    // portalMinSweep so the fee/verifier slot stays put and only the trailing mapping is
    // appended. The owner binding H is NOT stored here: it lives in each portal account E's own
    // storage under EIP-7702 delegation (see PortalDelegate) and the sweep path staticcalls E for it.
    // __gap therefore shrinks by exactly 5 (44 -> 39) so the reserved region's end slot is preserved at
    // its original boundary — verify with `forge inspect src/PrivacyBoost.sol:PrivacyBoost storage`.

    /// @notice Per-portal sweep counter, snapshotted into each pending record then incremented
    /// @dev Feeds noteRnd = Poseidon(DOMAIN_PORTAL_NOTE, blind, E, counter) so repeated sweeps of the same
    ///      portal/token/amount still produce distinct notes rather than a colliding commitment.
    mapping(address portal => uint256 counter) public portalCounter;

    /// @notice Get a pending portal deposit by portal-deposit request ID
    /// @dev Portal analog of pendingDeposits: sweep (escrow) → epoch (credit) or cancel (reclaim).
    mapping(uint256 portalDepositId => PortalPendingDeposit deposit) public portalPendingDeposits;

    /// @notice Check if a portal deposit has been processed (credited or reclaimed)
    /// @dev Separate flag mapping mirroring processedDeposits; guards double-credit/double-reclaim.
    mapping(uint256 portalDepositId => bool processed) public processedPortalDeposits;

    /// @notice Sweep fee rate in basis points charged at epoch time (0 in the operator-run MVP)
    /// @dev Bounded by MAX_FEE_BPS; snapshotted into each record at sweep time so a later rate change
    ///      cannot alter the credited amount of an already-escrowed sweep.
    uint16 public portalSweepFeeBps;

    /// @notice Portal-deposit verifier contract (DepositPortalCircuit), consumed by submitPortalDepositEpoch
    /// @dev A fresh deployment sets this in initialize alongside the other verifiers; an existing deployment
    ///      being upgraded (where initialize has already run) populates it via setPortalDepositVerifier after
    ///      the upgrade. The dev VK is registered for Foundry/FFI tests, and the real mainnet VK is registered
    ///      after the trusted-setup ceremony on the verifier contract (a drop-in artifact regeneration).
    IPortalDepositVerifier public portalDepositVerifier;

    /// @notice Per-token minimum-sweep (dust) threshold; a sweep below it reverts
    /// @dev Owner-set via setPortalMinSweep, default 0 (any non-zero delta passes). Declared after the
    ///      packed fee/verifier slot so that slot's layout is unchanged; this mapping takes the next
    ///      slot. uint96 matches the record's amount field.
    mapping(uint16 tokenId => uint96 minSweep) public portalMinSweep;

    /// @notice Gift claim verifier contract (Claimable Transfer)
    /// @dev Appended at the end of the storage layout — NOT beside the other verifiers — so existing slot
    ///      positions stay stable for the upgradeable proxy. An existing deployment populates this slot via
    ///      setGiftClaimVerifier after the implementation upgrade; a fresh deployment sets it in initialize.
    IGiftClaimVerifier public giftClaimVerifier;

    // ─────────────── Gateway storage ───────────────

    /// @notice One-route map. None = unapproved; Sync = approved sync gateway.
    mapping(address gateway => GatewayRoute route) public gatewayRoute;

    /// @notice Account authorized to approve and revoke gateway routes independently of upgrade authority.
    address public gatewayRouteManager;

    /// @notice Portal sweep fees whose immediate ERC-20 payment failed
    /// @dev Appended at the true storage tail. The original sweeper can retry payment only to itself.
    mapping(address sweeper => mapping(uint16 tokenId => uint256 amount)) public claimablePortalSweepFees;

    // Gateway storage consumed two reserved slots. This claimable-fee mapping consumes one more at the true
    // tail, so __gap shrinks from 36 to 35 while preserving the reserved region's end slot. Forced requests
    // continue to reuse their layout-frozen mapping rather than adding another state machine here.
    uint256[35] private __gap;

    /// @custom:oz-upgrades-unsafe-allow constructor
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
    ) {
        if (tokenRegistry_ == address(0) || tokenRegistry_.code.length == 0) {
            revert InvalidTokenRegistryAddress();
        }
        if (authRegistry_ == address(0) || authRegistry_.code.length == 0) revert InvalidAuthRegistryAddress();
        if (maxBatchSize_ == 0) revert MaxBatchSizeCannotBeZero();
        if (maxBatchSize_ > type(uint16).max) {
            revert MaxBatchSizeOutOfRange(maxBatchSize_, type(uint16).max);
        }
        if (maxInputsPerTransfer_ == 0) revert MaxInputsPerTransferCannotBeZero();
        if (maxOutputsPerTransfer_ == 0) revert MaxOutputsPerTransferCannotBeZero();
        if (maxFeeTokens_ == 0) revert MaxFeeTokensCannotBeZero();
        if (maxForcedInputs_ == 0) revert MaxForcedInputsCannotBeZero();
        if (merkleDepth_ == 0 || merkleDepth_ > MAX_NOTE_TREE_DEPTH) {
            revert MerkleDepthOutOfRange(merkleDepth_, 1, MAX_NOTE_TREE_DEPTH);
        }
        tokenRegistry = ITokenRegistry(tokenRegistry_);
        authRegistry = IAuthRegistry(authRegistry_);
        maxBatchSize = maxBatchSize_;
        maxInputsPerTransfer = maxInputsPerTransfer_;
        maxOutputsPerTransfer = maxOutputsPerTransfer_;
        maxFeeTokens = maxFeeTokens_;
        cancelDelay = cancelDelay_;
        forcedWithdrawalDelay = forcedWithdrawalDelay_;
        maxForcedInputs = maxForcedInputs_;
        maxEpochAuthStalenessBlocks = maxEpochAuthStalenessBlocks_;
        maxForcedWithdrawalAuthStalenessBlocks = maxForcedWithdrawalAuthStalenessBlocks_;
        merkleDepth = merkleDepth_;
        _disableInitializers();
    }

    /// @inheritdoc IPrivacyBoost
    function initialize(
        address initialOwner,
        address epochVerifier_,
        address depositVerifier_,
        address forcedVerifier_,
        address giftClaimVerifier_,
        address portalDepositVerifier_,
        uint16 withdrawFeeBps_,
        address treasury_
    ) external initializer {
        __Ownable2Step_init();
        _transferOwnership(initialOwner);

        epochVerifier = IEpochVerifier(epochVerifier_);
        depositVerifier = IDepositVerifier(depositVerifier_);
        forcedVerifier = IForcedWithdrawVerifier(forcedVerifier_);
        giftClaimVerifier = IGiftClaimVerifier(giftClaimVerifier_);
        portalDepositVerifier = IPortalDepositVerifier(portalDepositVerifier_);
        treasury = treasury_;
        gatewayRouteManager = initialOwner;
        _setFees(withdrawFeeBps_);

        uint256 zeroRoot = _zeroRoot();
        currentTreeNumber = 0;
        treeRoot[0] = zeroRoot;
        treeRootHistory[0][0] = zeroRoot;
    }

    modifier onlyRelay() {
        _checkRelay();
        _;
    }

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    modifier onlyGatewayRouteManager() {
        if (msg.sender != gatewayRouteManager) revert NotGatewayRouteManager();
        _;
    }

    // ─────────────── Configuration ───────────────

    /// @inheritdoc IPrivacyBoost
    function setOperator(address operator_) external onlyOwner {
        if (operator_ == address(0)) revert InvalidOperatorAddress();
        address oldOperator = operator;
        operator = operator_;
        emit OperatorUpdated(oldOperator, operator_);
    }

    /// @inheritdoc IPrivacyBoost
    function setAllowedRelays(address[] calldata relays, bool allowed) external onlyOperator {
        for (uint256 i = 0; i < relays.length; ++i) {
            allowedRelays[relays[i]] = allowed;
            emit RelayUpdated(relays[i], allowed);
        }
    }

    /// @inheritdoc IPrivacyBoost
    function setFees(uint16 withdrawFeeBps_) external onlyOwner {
        _setFees(withdrawFeeBps_);
    }

    /// @inheritdoc IPrivacyBoost
    function setTreasury(address treasury_) external onlyOwner {
        if (treasury_ == address(0) && withdrawFeeBps > 0) {
            revert TreasuryNotSet();
        }
        address oldTreasury = treasury;
        treasury = treasury_;
        emit TreasuryUpdated(oldTreasury, treasury_);
    }

    /// @inheritdoc IPrivacyBoost
    function setEpochVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(epochVerifier);
        epochVerifier = IEpochVerifier(verifier_);
        emit EpochVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setDepositVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(depositVerifier);
        depositVerifier = IDepositVerifier(verifier_);
        emit DepositVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setForcedVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(forcedVerifier);
        forcedVerifier = IForcedWithdrawVerifier(verifier_);
        emit ForcedVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setGiftClaimVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(giftClaimVerifier);
        giftClaimVerifier = IGiftClaimVerifier(verifier_);
        emit GiftClaimVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setPortalDepositVerifier(address verifier_) external onlyOwner {
        address oldVerifier = address(portalDepositVerifier);
        portalDepositVerifier = IPortalDepositVerifier(verifier_);
        emit PortalDepositVerifierUpdated(oldVerifier, verifier_);
    }

    /// @inheritdoc IPrivacyBoost
    function setPortalSweepFeeBps(uint16 portalSweepFeeBps_) external onlyOwner {
        // Mirrors _setFees' MAX_FEE_BPS cap. Unlike the withdraw fee, the sweep fee is paid to the
        // sweeper (not the treasury), so the _setFees treasury!=0 guard deliberately does not apply.
        if (portalSweepFeeBps_ > MAX_FEE_BPS) {
            revert FeeExceedsMaximum();
        }
        uint16 oldBps = portalSweepFeeBps;
        portalSweepFeeBps = portalSweepFeeBps_;
        emit PortalSweepFeeUpdated(oldBps, portalSweepFeeBps_);
    }

    /// @inheritdoc IPrivacyBoost
    function setPortalMinSweep(uint16 tokenId, uint96 minSweep) external onlyOwner {
        uint96 oldMinSweep = portalMinSweep[tokenId];
        portalMinSweep[tokenId] = minSweep;
        emit PortalMinSweepUpdated(tokenId, oldMinSweep, minSweep);
    }

    // ─────────────── Transfer epoch ───────────────

    /// @inheritdoc IPrivacyBoost
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
    ) external nonReentrant onlyRelay {
        _validateProvingTimestamp(provingTimestamp);

        LibEpoch.verifyAndSpend(
            treeRoot,
            treeCount,
            treeRootHistory,
            treeRootHistoryCursor,
            nullifierSpent,
            authRegistry,
            epochVerifier,
            currentTreeNumber,
            LibEpoch.EpochSubmitConfig({
                maxBatchSize: maxBatchSize,
                maxInputsPerTransfer: maxInputsPerTransfer,
                maxOutputsPerTransfer: maxOutputsPerTransfer,
                maxFeeTokens: maxFeeTokens,
                maxEpochAuthStalenessBlocks: maxEpochAuthStalenessBlocks,
                merkleDepth: merkleDepth
            }),
            treeState,
            usedAuthRoots,
            nTransfers,
            feeTokenCount,
            feeNPK,
            inputsPerTransfer,
            outputsPerTransfer,
            nullifiers,
            transfers,
            feeTransfer,
            withdrawals,
            withdrawalSlots,
            provingTimestamp,
            proof,
            gatewaySlots
        );

        // Route-aware execution. An empty `gatewaySlots` collapses to the plain path: route `None`
        // transfers out, any gateway-routed `withdrawal.to` reverts `MissingGatewaySlot`.
        LibGateway.processGatewayWithdrawals(
            gatewayRoute, pendingDeposits, depositNonces, tokenRegistry, withdrawals, gatewaySlots
        );
        _updateTreeState(treeState.activeTreeNumber, treeState.rootNew, treeState.countNew, treeState.rollover);

        emit EpochSubmitted(
            currentTreeNumber, treeState.rootNew, treeState.rollover ? 0 : treeState.countOld, treeState.countNew
        );
    }

    // ─────────────── Deposit ───────────────

    /// @inheritdoc IPrivacyBoost
    function requestDeposit(
        uint16 _tokenId,
        uint96 _totalAmount,
        uint256[] calldata _commitments,
        DepositCiphertext[] calldata _ciphertexts
    ) external nonReentrant returns (uint256 depositRequestId) {
        // Deposit-request construction (batch validation, fee-on-transfer-checked ERC-20 pull, request-id
        // digest, pending-deposit record, and DepositRequested event) runs in LibDeposit under delegatecall
        // to keep PrivacyBoost under the EIP-170 size limit; the library shares the pool's storage and sees
        // the pool's msg.sender/address(this)/block.* (the nonReentrant guard stays on this wrapper).
        return LibDeposit.requestDeposit(
            depositNonces,
            pendingDeposits,
            tokenRegistry,
            maxBatchSize,
            _tokenId,
            _totalAmount,
            _commitments,
            _ciphertexts
        );
    }

    /// @inheritdoc IPrivacyBoost
    function cancelDeposit(uint256 _depositRequestId) external nonReentrant {
        // Deposit cancellation (depositor check, cancel-delay gate, record delete, ERC-20 refund, event) runs
        // in LibDeposit under delegatecall to keep PrivacyBoost under the EIP-170 size limit; the library
        // shares the pool's storage and sees the pool's msg.sender (the nonReentrant guard stays here).
        LibDeposit.cancelDeposit(pendingDeposits, processedDeposits, tokenRegistry, cancelDelay, _depositRequestId);
    }

    /// @inheritdoc IPrivacyBoost
    function submitDepositEpoch(
        EpochTreeState calldata treeState,
        uint32 nTotalCommitments,
        Output[] calldata outputs,
        DepositEntry[] calldata deposits,
        uint256[8] calldata proof
    ) external nonReentrant onlyRelay {
        uint32 maxSlots = uint32(outputs.length);
        uint32 nRequests = uint32(deposits.length);

        if (maxSlots == 0 || maxSlots > maxBatchSize) revert InvalidEpochConfig();
        if (nRequests == 0 || nRequests > maxSlots) revert InvalidEpochConfig();
        if (nTotalCommitments == 0 || nTotalCommitments > maxSlots) revert InvalidEpochConfig();

        // Tree state must match on-chain state exactly
        if (treeState.activeTreeNumber != currentTreeNumber) revert InvalidEpochState();
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert InvalidEpochState();

        // Validate sparse roots (deposit requires unique tree numbers for selectByTreeNumber safety)
        uint256 activeRoot = _validateKnownRoots(treeState.usedRoots, treeState.activeTreeNumber, false);
        // Epochs require the exact current root (append-only tree guarantees state consistency)
        if (activeRoot != treeRoot[treeState.activeTreeNumber]) revert InvalidEpochState();
        LibEpoch.validateTreeCapacity(
            merkleDepth, treeState.countOld, treeState.countNew, nTotalCommitments, treeState.rollover
        );

        // The per-request processing loop (pending-deposit reads + the processed-deposit double-process guard
        // + ordered commitment-hash binding), the deposit public-input build, and the proof verification run
        // in LibDeposit under delegatecall to keep the pool under the EIP-170 size limit. The value-type
        // currentTreeNumber advance in _updateTreeState stays here (a delegatecall library cannot write a
        // value-type state variable) and runs only after LibDeposit returns without reverting.
        LibDeposit.submitDepositEpoch(
            pendingDeposits, processedDeposits, depositVerifier, treeState, nTotalCommitments, outputs, deposits, proof
        );

        _updateTreeState(treeState.activeTreeNumber, treeState.rootNew, treeState.countNew, treeState.rollover);

        emit DepositEpochSubmitted(
            currentTreeNumber, treeState.rootNew, treeState.rollover ? 0 : treeState.countOld, treeState.countNew
        );
    }

    // ─────────────── Portal deposit ───────────────

    /// @inheritdoc IPrivacyBoost
    function requestPortalDeposit(address portal, uint16 _tokenId)
        external
        nonReentrant
        returns (uint256 portalDepositId)
    {
        return LibPortal.requestPortalDeposit(
            portalCounter, portalMinSweep, portalPendingDeposits, tokenRegistry, portalSweepFeeBps, portal, _tokenId
        );
    }

    /// @inheritdoc IPrivacyBoost
    function cancelPortalDeposit(uint256 portalDepositId) external nonReentrant {
        LibPortal.cancelPortalDeposit(
            portalPendingDeposits, processedPortalDeposits, tokenRegistry, cancelDelay, portalDepositId
        );
    }

    /// @inheritdoc IPrivacyBoost
    function submitPortalDepositEpoch(
        EpochTreeState calldata treeState,
        PortalDepositEntry[] calldata entries,
        uint256[] calldata commitments,
        uint256[8] calldata proof
    ) external nonReentrant onlyRelay {
        // One note per portal deposit: each real entry contributes exactly one credited note. Mirroring
        // submitDepositEpoch's outputs/deposits split, the VK shape (maxSlots) is the padded
        // `commitments.length` and the active-request count is `entries.length` (nRequests <= maxSlots):
        // the relay submits a registered batch size (commitments padded with trailing zeros to that shape)
        // carrying nRequests real escrowed records, and the circuit zero-pads the trailing maxSlots -
        // nRequests slots. The portal verifier keys its VK by maxSlots, so the relay MUST submit only batch
        // sizes for which a portal VK has been registered; an unregistered size reverts VerifyingKeyNotFound
        // at the verify call (fails safe — no mis-credit). See IPrivacyBoost docs.
        uint32 maxSlots = uint32(commitments.length);
        uint32 nRequests = uint32(entries.length);
        if (maxSlots == 0 || maxSlots > maxBatchSize) revert InvalidEpochConfig();
        if (nRequests == 0 || nRequests > maxSlots) revert InvalidEpochConfig();

        // Exact-match tree-state CAS, identical to submitDepositEpoch: the portal epoch appends to the
        // SAME shared note tree, so it must observe the current tree number, leaf count, and root exactly.
        // A portal epoch racing another epoch (deposit/transfer/portal) reverts here on stale state and is
        // rebuilt+retried by the relay (no shared-tree lock is added — calling-convention audit:
        // every existing appender uses this same optimistic CAS rather than a lock).
        if (treeState.activeTreeNumber != currentTreeNumber) revert InvalidEpochState();
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert InvalidEpochState();
        uint256 activeRoot = _validateKnownRoots(treeState.usedRoots, treeState.activeTreeNumber, false);
        if (activeRoot != treeRoot[treeState.activeTreeNumber]) revert InvalidEpochState();
        // Only the nRequests active deposits append a note; the trailing maxSlots - nRequests padded slots
        // carry no commitment, so the tree grows by nRequests, not by the VK shape.
        LibEpoch.validateTreeCapacity(
            merkleDepth, treeState.countOld, treeState.countNew, nRequests, treeState.rollover
        );

        // Advance the active tree number (the one value-type tree-state write) and emit TreeAdvanced HERE,
        // before delegating the rest: a delegatecall library cannot receive a storage reference to the
        // value-type `currentTreeNumber` (only mapping/struct/array types can be storage-ref params), and
        // performing this effect before the library's fee transfers keeps checks-effects-interactions
        // intact. A reverting verify inside the library unwinds this write atomically, so no spurious tree
        // advance survives a failed proof.
        if (treeState.rollover) {
            uint256 newTreeNumber = currentTreeNumber + 1;
            if (newTreeNumber > MAX_NOTE_TREE_NUMBER) revert InvalidEpochState();
            currentTreeNumber = newTreeNumber;
            emit TreeAdvanced(treeState.activeTreeNumber, newTreeNumber);
        }

        // Delegate the storage-heavy remainder (build the public inputs from escrow, verify the proof,
        // write the tree mappings, pay or defer keeper fees) to LibPortal to keep this contract under the
        // EIP-170 size limit. The library shares the pool's storage under delegatecall via the passed
        // mapping references; the tree-state CAS above already validated every input it consumes.
        LibPortal.submitPortalDepositEpoch(
            portalPendingDeposits,
            processedPortalDeposits,
            claimablePortalSweepFees,
            treeRoot,
            treeCount,
            treeRootHistory,
            treeRootHistoryCursor,
            portalDepositVerifier,
            treeState,
            entries,
            commitments,
            proof
        );

        emit PortalDepositEpochSubmitted(
            currentTreeNumber, treeState.rootNew, treeState.rollover ? 0 : treeState.countOld, treeState.countNew
        );
    }

    /// @inheritdoc IPrivacyBoost
    function claimPortalSweepFee(uint16 tokenId) external nonReentrant {
        LibPortal.claimPortalSweepFee(claimablePortalSweepFees, tokenRegistry, tokenId);
    }

    /// @inheritdoc IPrivacyBoost
    function payPortalSweepFee(uint16 tokenId, address sweeper, uint256 amount) external {
        if (msg.sender != address(this)) revert PortalSweepFeePaymentOnlySelf();
        LibPoolShared.transferToken(tokenRegistry, tokenId, sweeper, amount);
    }

    // ─────────────── Gift ───────────────

    /// @inheritdoc IPrivacyBoost
    function submitGiftClaimEpoch(
        EpochTreeState calldata treeState,
        TreeRootPair[] calldata usedAuthRoots,
        uint256[] calldata giftNullifiers,
        Output[] calldata outputs,
        uint256[] calldata digestRootIndices,
        uint256 currentBlock,
        uint64 provingTimestamp,
        uint256[8] calldata proof
    ) external nonReentrant onlyRelay {
        _validateProvingTimestamp(provingTimestamp);
        // Tree-state CAS + known/auth-root + capacity validation that needs the pool's internal helpers. The
        // gift-specific input validation (VK registry, array lengths, canonical digest-index encoding, the
        // currentBlock bound) runs at the top of LibGift.submitGiftClaimEpoch — moved off this wrapper with
        // the rest of the gift logic to keep the pool under the EIP-170 size limit. A revert there unwinds the
        // currentTreeNumber advance below atomically (mirrors submitPortalDepositEpoch's wrapper/library split).
        if (treeState.activeTreeNumber != currentTreeNumber) revert InvalidEpochState();
        if (treeState.countOld != treeCount[treeState.activeTreeNumber]) revert InvalidEpochState();
        // Claim allows duplicate tree numbers (each slot proves its own gift note; findPairMatch is OR-based).
        _validateKnownRoots(treeState.usedRoots, treeState.activeTreeNumber, true);
        // Private gift claims use the same relay-submitted auth-root freshness window as transfer epochs.
        _validateUsedAuthRoots(usedAuthRoots, maxEpochAuthStalenessBlocks);
        // Each slot mints exactly one canonical note; no fee outputs in v1 (recipient gets the full amount).
        // Same shared capacity check the deposit/portal wrappers use, so every appender enforces one invariant.
        LibEpoch.validateTreeCapacity(
            merkleDepth, treeState.countOld, treeState.countNew, giftNullifiers.length, treeState.rollover
        );

        // Advance the active tree number (the one value-type tree-state write) and emit TreeAdvanced HERE,
        // before delegating the storage-heavy remainder: a delegatecall library cannot receive a storage
        // reference to the value-type currentTreeNumber. A reverting verify inside LibGift unwinds this write
        // atomically, so no spurious advance survives a failed proof. Mirrors submitPortalDepositEpoch.
        if (treeState.rollover) {
            uint256 newTreeNumber = currentTreeNumber + 1;
            if (newTreeNumber > MAX_NOTE_TREE_NUMBER) revert InvalidEpochState();
            currentTreeNumber = newTreeNumber;
            emit TreeAdvanced(treeState.activeTreeNumber, newTreeNumber);
        }

        // Delegate the per-claim nullifier spend + digest loop, public-input build, proof verify, tree-mapping
        // writes, and settlement events to LibGift to keep this contract under the EIP-170 size limit. The
        // library shares the pool's storage under delegatecall via the passed mapping references.
        LibGift.submitGiftClaimEpoch(
            treeRoot,
            treeCount,
            treeRootHistory,
            treeRootHistoryCursor,
            nullifierSpent,
            giftClaimVerifier,
            maxBatchSize,
            treeState,
            usedAuthRoots,
            giftNullifiers,
            outputs,
            digestRootIndices,
            currentBlock,
            provingTimestamp,
            proof
        );
    }

    /// @inheritdoc IPrivacyBoost
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
    ) external nonReentrant {
        _validateProvingTimestamp(provingTimestamp);
        // Tree-number + exact auth-leaf validation that needs the pool's internal helpers. The input validation
        // (destination, nullifier, currentBlock bound, token registry, nullifier-unspent) runs at the top of
        // LibGift.publicGiftExit, moved off this wrapper to keep the pool under the EIP-170 size limit. There
        // is no on-chain deadline check here: the gift-claim circuit's refund branch enforces
        // currentBlock >= refundAfterBlock in-proof against the caller-attested currentBlock (validated
        // <= block.number in the library); a recipient-claim payout proof is also structurally valid.
        uint256 treeNum = currentTreeNumber;
        uint256 activeRoot = _validateKnownRoots(knownRoots, treeNum, false);
        uint256 treeCapacity = uint256(1) << merkleDepth;
        if (uint256(activeTreeCount) > treeCapacity) revert InvalidEpochState();
        bool fullTreeExit = uint256(activeTreeCount) == treeCapacity;
        // Rollover mode does not bind ActiveNoteTreeRoot to CountOld inside the circuit because appenders
        // start from a fresh tree. For a no-append exit, admit that representation only for the actual live
        // full tip; non-full exits retain their historical-root/count support below.
        if (fullTreeExit && (treeCount[treeNum] != treeCapacity || activeRoot != treeRoot[treeNum])) {
            revert InvalidEpochState();
        }
        // Key- and approval-authorized exits expose their exact auth leaf. Validate
        // that per-leaf state instead of the global tree tip: unrelated registrations
        // and approvals cannot stale the proof, while rotation or revocation deactivates
        // this leaf immediately. Safe approval expiry is enforced by the circuit against
        // the freshness-bounded proving timestamp. Only secret-bearer exits bind zero
        // and therefore have no auth-registry liveness dependency.
        if (exitAuthLeaf == 0) {
            // Secret-bearer exits must use the canonical empty lookup hint.
            if (authLeafLocation != 0) revert AuthLeafNotActive();
        } else {
            // High 32 bits = auth tree number, low 32 bits = leaf index. The
            // proof already binds exitAuthLeaf; this caller-supplied location is
            // only an O(1) lookup hint into the registry's existing leaf storage.
            if (!authRegistry.isCurrentAuthLeafAt(authLeafLocation, exitAuthLeaf)) {
                revert AuthLeafNotActive();
            }
        }

        // Delegate the exit digest, public-input build, proof verify, fee math, payout, and event to LibGift
        // to keep this contract under the EIP-170 size limit. The nullifier map is forwarded by reference and
        // the token registry + treasury/withdrawFeeBps by value, so the library settles against the pool's
        // storage under delegatecall (the same body previously inlined here now lives in LibGift).
        LibGift.publicGiftExit(
            nullifierSpent,
            giftClaimVerifier,
            tokenRegistry,
            treasury,
            withdrawFeeBps,
            knownRoots,
            usedAuthRoots,
            treeNum,
            activeRoot,
            activeTreeCount,
            _zeroRoot(),
            fullTreeExit,
            giftNullifier,
            exitAuthLeaf,
            destination,
            tokenId,
            amount,
            minNetAmount,
            viewingKey,
            teeWrapKey,
            currentBlock,
            provingTimestamp,
            proof
        );
    }

    // ─────────────── Forced withdrawal ───────────────

    /// @inheritdoc IPrivacyBoost
    function requestForcedWithdrawal(
        TreeRootPair[] calldata knownRoots,
        TreeRootPair[] calldata forcedAuthData,
        uint256 spenderAccountId,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint256[8] calldata proof
    ) external nonReentrant {
        uint256 inputLen = nullifiers.length;
        if (inputLen == 0 || inputLen != inputCommitments.length) revert InvalidArrayLengths();
        if (inputLen > maxForcedInputs) revert InvalidEpochConfig();
        if (inputLen > type(uint8).max) revert InvalidArrayLengths();
        if (withdrawal.to == address(0)) revert InvalidWithdrawal();

        // Validate tokenId at request time to prevent locking commitments for unexecutable requests.
        (uint8 tokenType, address tokenAddress,) = tokenRegistry.tokenOf(withdrawal.tokenId);
        if (tokenAddress == address(0)) revert InvalidWithdrawal();
        if (tokenType != TOKEN_TYPE_ERC20) revert TokenNotSupported(tokenType);

        // Validate sparse roots and get active tree root (forced withdrawal requires unique tree numbers).
        // These root checks are shared with epoch submission, so they stay in the core; the resolved
        // `activeRoot` is handed to {LibForced} for the proof build + request recording.
        _validateKnownRoots(knownRoots, currentTreeNumber, false);
        LibForced.requestForcedWithdrawalSuffix(
            nullifierSpent,
            commitmentToRequestKey,
            forcedWithdrawalRequests,
            forcedVerifier,
            authRegistry,
            maxForcedInputs,
            withdrawFeeBps,
            knownRoots,
            forcedAuthData,
            spenderAccountId,
            nullifiers,
            inputCommitments,
            withdrawal,
            proof
        );
    }

    /// @inheritdoc IPrivacyBoost
    function executeForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments)
        external
        nonReentrant
    {
        LibForced.executeForcedWithdrawal(
            nullifierSpent,
            commitmentToRequestKey,
            forcedWithdrawalRequests,
            tokenRegistry,
            treasury,
            forcedWithdrawalDelay,
            maxForcedInputs,
            nullifiers,
            inputCommitments
        );
    }

    /// @inheritdoc IPrivacyBoost
    function cancelForcedWithdrawal(uint256[] calldata nullifiers, uint256[] calldata inputCommitments)
        external
        nonReentrant
    {
        LibForced.cancelForcedWithdrawal(
            nullifierSpent,
            commitmentToRequestKey,
            forcedWithdrawalRequests,
            authRegistry,
            maxForcedInputs,
            nullifiers,
            inputCommitments
        );
    }

    // ─────────────── Gateway ───────────────

    /// @inheritdoc IPrivacyBoost
    function initializeGatewayRouteManager(address manager) external reinitializer(2) {
        if (msg.sender != owner()) {
            address proxyAdmin;
            bytes32 adminSlot = ERC1967_ADMIN_SLOT;
            assembly ("memory-safe") {
                proxyAdmin := sload(adminSlot)
            }
            if (msg.sender != proxyAdmin) revert NotGatewayRouteMigrationAdmin();
        }
        _setGatewayRouteManager(manager);
    }

    /// @inheritdoc IPrivacyBoost
    function setGatewayRouteManager(address manager) external onlyOwner {
        _setGatewayRouteManager(manager);
    }

    /// @notice Approve or revoke a gateway route. Each gateway address has at most one route.
    /// @param gateway The gateway address to approve or revoke, which must be non-zero
    /// @param route The route to assign, `None` to revoke and `Sync` to approve
    function setGatewayRoute(address gateway, GatewayRoute route) external onlyGatewayRouteManager {
        if (gateway == address(0)) revert InvalidWithdrawal();
        gatewayRoute[gateway] = route;
        emit GatewayRouteUpdated(gateway, route);
    }

    /// @inheritdoc IPrivacyBoost
    function rescueGatewayDeposit(
        uint256 depositRequestId,
        address destination,
        bytes32 rescueSalt,
        address rescueAuthority,
        bytes calldata signature
    ) external nonReentrant {
        LibGateway.rescueGatewayDeposit(
            pendingDeposits,
            processedDeposits,
            tokenRegistry,
            cancelDelay,
            depositRequestId,
            destination,
            rescueSalt,
            rescueAuthority,
            signature
        );
    }

    /// @inheritdoc IPrivacyBoost
    function simulateGatewayWithdrawals(Withdrawal[] calldata withdrawals, GatewaySlot[] calldata gatewaySlots)
        external
        nonReentrant
        onlyRelay
    {
        try this.simulateGatewayWithdrawalsInner(withdrawals, gatewaySlots) returns (
            GatewaySettlementOutcome[] memory outcomes,
            bytes32[] memory receiptHashes,
            bytes4[] memory failureSelectors,
            bytes[] memory failureReasons
        ) {
            revert GatewaySimulationOutcomes(outcomes, receiptHashes, failureSelectors, failureReasons);
        } catch (bytes memory reason) {
            revert GatewayExecutionFailed(reason);
        }
    }

    /// @notice Execute the route-aware withdrawal path inside the simulation rollback frame.
    /// @dev Only the contract itself may call this function. The outer simulation entry point always reverts after
    ///      collecting these values, which rolls back token transfers, nonce increments, and pending-deposit writes.
    /// @param withdrawals Ordered withdrawals processed by the route-aware settlement path.
    /// @param gatewaySlots Sparse gateway instructions ordered by strictly increasing withdrawal index.
    /// @return outcomes Settlement outcome for each gateway slot.
    /// @return receiptHashes Receipt hash recorded for each gateway slot.
    /// @return failureSelectors ABI-compatible failure selectors, left zero when the call returns successfully.
    /// @return failureReasons ABI-compatible failure data, left empty when the call returns successfully.
    function simulateGatewayWithdrawalsInner(Withdrawal[] calldata withdrawals, GatewaySlot[] calldata gatewaySlots)
        external
        returns (
            GatewaySettlementOutcome[] memory outcomes,
            bytes32[] memory receiptHashes,
            bytes4[] memory failureSelectors,
            bytes[] memory failureReasons
        )
    {
        if (msg.sender != address(this)) revert NotAllowedRelay();
        return LibGateway.processGatewayWithdrawalsForSim(
            gatewayRoute, pendingDeposits, depositNonces, tokenRegistry, withdrawals, gatewaySlots
        );
    }

    /// @inheritdoc IPrivacyBoost
    function executeGatewaySlotIsolated(Withdrawal calldata withdrawal, GatewaySlot calldata gatewaySlot)
        external
        returns (GatewaySettlementOutcome outcome, bytes32 receiptHash)
    {
        if (msg.sender != address(this)) revert NotAllowedRelay();
        return LibGateway.executeGatewaySlotAndRecordOutcome(
            pendingDeposits, depositNonces, tokenRegistry, withdrawal, gatewaySlot
        );
    }

    // ─────────────── Views ───────────────

    /// @notice Resolve a registered token id to its ERC-20 address. Used by gateways for runtime registry rechecks.
    /// @param tokenId The registered token id to resolve
    /// @return The ERC-20 address registered for that token id
    function tokenAddressOf(uint16 tokenId) external view returns (address) {
        (, address addr,) = tokenRegistry.tokenOf(tokenId);
        return addr;
    }

    /// @inheritdoc IPrivacyBoost
    function isKnownTreeRoot(uint256 treeNum, uint256 root_) public view returns (bool) {
        if (root_ == 0) return false;

        // O(1) fast path: current root matches for any tree
        if (treeRoot[treeNum] == root_) return true;

        // Finalized trees: only the final root is valid (checked above)
        if (treeNum < currentTreeNumber) return false;

        // Current tree: scan ring buffer for historical roots
        uint256 idx = treeRootHistoryCursor[treeNum];
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ++i) {
            if (treeRootHistory[treeNum][idx] == root_) return true;
            unchecked {
                idx = (idx + ROOT_HISTORY_SIZE - 1) % ROOT_HISTORY_SIZE;
            }
        }
        return false;
    }

    // ─────────────── Internal helpers ───────────────

    /// @dev Verify caller is an allowed relay
    function _checkRelay() internal view {
        if (!allowedRelays[msg.sender]) revert NotAllowedRelay();
    }

    /// @dev Set fee rates with validation
    function _setFees(uint16 withdrawFeeBps_) internal {
        if (withdrawFeeBps_ > MAX_FEE_BPS) {
            revert FeeExceedsMaximum();
        }
        if (withdrawFeeBps_ > 0 && treasury == address(0)) {
            revert TreasuryNotSet();
        }
        withdrawFeeBps = withdrawFeeBps_;
        emit FeesUpdated(withdrawFeeBps_);
    }

    /// @dev Shared setter for the gateway-route manager, rejecting the zero address. Reached from both the owner
    ///      path (setGatewayRouteManager) and the one-time reinitializer migration (initializeGatewayRouteManager).
    function _setGatewayRouteManager(address manager) internal {
        if (manager == address(0)) revert InvalidGatewayRouteManager();
        address oldManager = gatewayRouteManager;
        gatewayRouteManager = manager;
        emit GatewayRouteManagerUpdated(oldManager, manager);
    }

    /// @dev The empty-tree root at merkleDepth (the all-zeros-leaf subtree root a freshly rolled-over note tree
    ///      starts from), used to seed tree 0 in initialize.
    function _zeroRoot() internal view returns (uint256) {
        return LibZeroHashes.get()[merkleDepth];
    }

    /// @dev Reject a proof whose attested timestamp is in the future or older than MAX_PROOF_AGE, bounding how
    ///      stale a relay-submitted proof may be relative to current chain state.
    function _validateProvingTimestamp(uint64 provingTimestamp) internal view {
        if (provingTimestamp > block.timestamp || block.timestamp - provingTimestamp > MAX_PROOF_AGE) {
            revert InvalidProvingTimestamp();
        }
    }

    /// @dev Commit the post-epoch tree tip. On rollover, advance to a fresh tree and seed its root/count, otherwise
    ///      overwrite the active tree in place. Both branches push the new root into the ring buffer so recent roots
    ///      stay accepted by isKnownTreeRoot.
    function _updateTreeState(uint256 activeTreeNumber, uint256 rootNew, uint32 countNew, bool rollover) internal {
        if (rollover) {
            uint256 newTreeNumber = currentTreeNumber + 1;
            if (newTreeNumber > MAX_NOTE_TREE_NUMBER) revert InvalidEpochState();
            currentTreeNumber = newTreeNumber;
            treeRoot[newTreeNumber] = rootNew;
            treeCount[newTreeNumber] = countNew;
            LibPoolShared.pushTreeRoot(treeRootHistory, treeRootHistoryCursor, newTreeNumber, rootNew);

            emit TreeAdvanced(activeTreeNumber, newTreeNumber);
        } else {
            treeRoot[activeTreeNumber] = rootNew;
            treeCount[activeTreeNumber] = countNew;
            LibPoolShared.pushTreeRoot(treeRootHistory, treeRootHistoryCursor, activeTreeNumber, rootNew);
        }
    }

    /// @dev Validate sparse known roots. Returns the active tree's root.
    /// @param sparseRoots Sparse array with (treeNumber, root) pairs
    /// @param activeTreeNumber Must be included
    /// @return activeRoot The root provided for the active tree when required
    function _validateKnownRoots(
        TreeRootPair[] calldata sparseRoots,
        uint256 activeTreeNumber,
        bool allowDuplicateTreeNumbers
    ) internal view returns (uint256 activeRoot) {
        uint256 len = sparseRoots.length;
        if (len == 0 || len > MAX_NOTE_ROOTS_PER_PROOF) revert InvalidBatchConfig();

        bool foundActive = false;
        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = sparseRoots[i].treeNumber;
            uint256 root = sparseRoots[i].root;

            // Enforce uniqueness rules for sparse roots:
            // - Deposit/forced withdrawal require unique tree numbers (selectByTreeNumber safety).
            // - Epoch allows duplicate tree numbers because input spending uses findPairMatch (OR-based, safe with duplicates).
            //   Even in epoch, exact duplicate (treeNumber, root) pairs are rejected (no functional value, reduces malleability).
            if (allowDuplicateTreeNumbers) {
                for (uint256 j = 0; j < i; ++j) {
                    if (sparseRoots[j].treeNumber == treeNum && sparseRoots[j].root == root) {
                        revert DuplicateTreeRootPair();
                    }
                }
            } else {
                for (uint256 j = 0; j < i; ++j) {
                    if (sparseRoots[j].treeNumber == treeNum) revert DuplicateTreeNumber();
                }
            }

            // Validate root is known for this tree
            if (!isKnownTreeRoot(treeNum, root)) revert RootNotKnown();

            // Track active tree
            if (treeNum == activeTreeNumber) {
                activeRoot = root;
                foundActive = true;
            }
        }

        if (!allowDuplicateTreeNumbers && !foundActive) revert InvalidEpochState();
    }

    /// @dev Validate sparse auth roots. maxStalenessBlocks == 0 enforces current-root-only.
    function _validateUsedAuthRoots(TreeRootPair[] calldata usedAuthRoots, uint64 maxStalenessBlocks) internal view {
        uint256 len = usedAuthRoots.length;
        if (len == 0 || len > MAX_AUTH_ROOTS_PER_PROOF) revert InvalidBatchConfig();

        for (uint256 i = 0; i < len; ++i) {
            uint256 treeNum = usedAuthRoots[i].treeNumber;
            for (uint256 j = 0; j < i; ++j) {
                if (usedAuthRoots[j].treeNumber == treeNum) revert DuplicateTreeNumber();
            }
        }

        if (!authRegistry.areRecentAuthTreeRoots(usedAuthRoots, maxStalenessBlocks)) {
            revert RootNotKnown();
        }
    }
}
