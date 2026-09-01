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
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {
    GatewayReceipt,
    GatewaySlot,
    GatewayAction,
    GatewayRoute,
    Output,
    Transfer,
    Withdrawal,
    DepositCiphertext,
    EpochTreeState,
    TreeRootPair
} from "src/interfaces/IStructs.sol";
import {TOKEN_TYPE_ERC20, DOMAIN_NOTE} from "src/interfaces/Constants.sol";

import {ExternalCallGateway} from "src/gateway/ExternalCallGateway.sol";

import {MockERC20, MockVerifier, MockAuthRegistry} from "test/helpers/Mocks.sol";
import {MockERC4626} from "test/helpers/GatewayMocks.sol";
import {PoolDeployer, DeployConfig} from "test/helpers/PoolDeployer.sol";
import {EpochHelpers} from "test/helpers/EpochHelpers.sol";

/// @notice Shared scaffolding for Gateway integration tests. Uses the real `PrivacyBoost.submitEpoch`
///         entry point with the existing `MockVerifier` (no ZK constraints, but every other on-chain
///         check — dead-note commitment, balance deltas, route map, slot pairing, rescue signatures —
///         is real).
contract GatewayBaseTest is Test {
    PrivacyBoost pool;
    TokenRegistry tokenRegistry;
    MockAuthRegistry authRegistry;
    MockVerifier verifier;

    MockERC20 usdc;
    MockERC4626 vault4626;

    ExternalCallGateway externalGateway;

    address owner = address(this);
    address proxyAdmin = address(0xAD);
    address relayer = makeAddr("relayer");
    address operator = makeAddr("operator");
    address user = makeAddr("user");

    uint16 idUsdc;
    uint16 idVault4626;

    uint8 constant BATCH_SIZE = 2;
    uint8 constant MAX_FEE_TOKENS = 1;

    function setUp() public virtual {
        verifier = new MockVerifier();
        authRegistry = new MockAuthRegistry();

        DeployConfig memory cfg = PoolDeployer.defaultConfig(owner, proxyAdmin, address(verifier));
        cfg.batchSize = BATCH_SIZE;
        cfg.maxFeeTokens = MAX_FEE_TOKENS;
        cfg.cancelDelay = 10;

        (pool, tokenRegistry) = PoolDeployer.deployWithMockAuth(cfg, address(authRegistry));

        usdc = new MockERC20();
        vault4626 = new MockERC4626(usdc);

        idUsdc = tokenRegistry.register(TOKEN_TYPE_ERC20, address(usdc), 0);
        idVault4626 = tokenRegistry.register(TOKEN_TYPE_ERC20, address(vault4626), 0);

        externalGateway = new ExternalCallGateway(address(pool), owner);
        _allowExternalGatewayPolicy(address(vault4626), IERC4626.deposit.selector, idUsdc, idVault4626);
        _allowExternalGatewayPolicy(address(vault4626), IERC4626.redeem.selector, idVault4626, idUsdc);

        // Pool admin wiring.
        pool.setOperator(operator);
        address[] memory relays = new address[](1);
        relays[0] = relayer;
        vm.prank(operator);
        pool.setAllowedRelays(relays, true);

        pool.setGatewayRoute(address(externalGateway), GatewayRoute.Sync);

        // Fund pool with USDC representing prior deposits.
        usdc.mint(address(pool), 10_000 ether);
    }

    // ─── Helpers ───

    function _allowExternalGatewayPolicy(address target, bytes4 selector, uint16 inputTokenId, uint16 outputTokenId)
        internal
    {
        externalGateway.setCallPolicy(
            target,
            selector,
            ExternalCallGateway.CallPolicy({allowed: true, inputTokenId: inputTokenId, outputTokenId: outputTokenId})
        );
    }

    function _registerDepositVault(MockERC4626 vault) internal returns (uint16 outputTokenId) {
        outputTokenId = tokenRegistry.register(TOKEN_TYPE_ERC20, address(vault), 0);
        _allowExternalGatewayPolicy(address(vault), IERC4626.deposit.selector, idUsdc, outputTokenId);
    }

    /// @notice Build a GatewayReceipt with a strict-field-element npk.
    function _makeReceipt(uint16 outputTokenId, uint96 minOut, bytes32 rescueCommitment, uint256 npkSeed)
        internal
        pure
        returns (GatewayReceipt memory r)
    {
        r.outputTokenId = outputTokenId;
        r.minOutputAmount = minOut;
        r.npk = uint256(keccak256(abi.encode(npkSeed, outputTokenId, minOut))) % (uint256(1) << 250);
        r.rescueCommitment = rescueCommitment;
        // Gateway-origin ciphertext convention is (0, 0) plaintext — opaque on-chain.
        r.ciphertext = DepositCiphertext({
            viewingKey: bytes32(0),
            teeWrapKey: bytes32(0),
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes16(0)
        });
    }

    function _makeFallbackReceipt(uint16 inputTokenId, bytes32 rescueCommitment, uint256 npkSeed)
        internal
        pure
        returns (GatewayReceipt memory)
    {
        return _makeReceipt(inputTokenId, 0, keccak256(abi.encode(rescueCommitment, "fallback", npkSeed)), npkSeed);
    }

    function _erc4626DepositSlot(
        uint16 withdrawalIndex,
        uint96 amount,
        uint96 minOut,
        bytes32 rescueCommitment,
        uint256 seed
    ) internal view returns (GatewaySlot memory) {
        return _erc4626DepositSlotFor(vault4626, idVault4626, withdrawalIndex, amount, minOut, rescueCommitment, seed);
    }

    function _erc4626DepositSlotFor(
        MockERC4626 vault,
        uint16 outputTokenId,
        uint16 withdrawalIndex,
        uint96 amount,
        uint96 minOut,
        bytes32 rescueCommitment,
        uint256 seed
    ) internal view returns (GatewaySlot memory) {
        bytes memory callData = abi.encodeCall(IERC4626.deposit, (uint256(amount), address(externalGateway)));
        return GatewaySlot({
            withdrawalIndex: withdrawalIndex,
            action: GatewayAction.ExternalCall,
            expiryBlock: uint64(block.number + 100),
            target: address(vault),
            callData: callData,
            receipt: _makeReceipt(outputTokenId, minOut == 0 ? 1 : minOut, rescueCommitment, seed),
            fallbackReceipt: _makeFallbackReceipt(idUsdc, rescueCommitment, seed + 10_000)
        });
    }

    function _erc4626RedeemSlot(
        uint16 withdrawalIndex,
        uint96 shares,
        uint96 minOut,
        bytes32 rescueCommitment,
        uint256 seed
    ) internal view returns (GatewaySlot memory) {
        bytes memory callData = abi.encodeCall(
            IERC4626.redeem, (uint256(shares), address(externalGateway), address(externalGateway))
        );
        return GatewaySlot({
            withdrawalIndex: withdrawalIndex,
            action: GatewayAction.ExternalCall,
            expiryBlock: uint64(block.number + 100),
            target: address(vault4626),
            callData: callData,
            receipt: _makeReceipt(idUsdc, minOut == 0 ? 1 : minOut, rescueCommitment, seed),
            fallbackReceipt: _makeFallbackReceipt(idVault4626, rescueCommitment, seed + 10_000)
        });
    }

    /// @notice Build a single-withdrawal epoch with the matching dead-note in slot 0.
    /// @dev    The dead-note commitment is `Poseidon(DOMAIN_NOTE, to, tokenId, amount)`.
    function _buildSingleWithdrawalEpoch(Withdrawal memory w)
        internal
        returns (
            Output[] memory outputs,
            uint256[] memory nullifiers,
            Output[] memory feeOutputs,
            Withdrawal[] memory withdrawals,
            uint32[] memory withdrawalSlots
        )
    {
        outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(
            Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(w.to)), uint256(w.tokenId), w.amount)
        );
        outputs[1] = EpochHelpers.makeOutput(_uniq(uint256(uint160(w.to)) ^ uint256(w.amount))); // dummy

        nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = _uniq(uint256(keccak256(abi.encode("n0", w.to, w.amount))));
        nullifiers[1] = _uniq(uint256(keccak256(abi.encode("n1", w.to, w.amount))));

        feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(_uniq(uint256(keccak256("fee"))));

        withdrawals = new Withdrawal[](1);
        withdrawals[0] = w;
        withdrawalSlots = new uint32[](1);
        withdrawalSlots[0] = 0;
    }

    /// @dev Bundle of pre-built submit args. Pre-fetching all pool state into this struct lets
    ///      callers place `vm.expectRevert(...)` immediately before `_callSubmit` without it being
    ///      consumed by an intermediate state read.
    struct SubmitArgs {
        EpochTreeState tree;
        TreeRootPair[] usedAuthRoots;
        uint256[][] nullifiers;
        Transfer[] transfers;
        Transfer feeTransfer;
        Withdrawal[] withdrawals;
        uint32[] withdrawalSlots;
    }

    function _prepareSingleWithdrawal(Withdrawal memory w) internal returns (SubmitArgs memory args) {
        (
            Output[] memory outputs,
            uint256[] memory nullifiers,
            Output[] memory feeOutputs,
            Withdrawal[] memory withdrawals,
            uint32[] memory withdrawalSlots
        ) = _buildSingleWithdrawalEpoch(w);

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Two output commitments plus one fee note, minus the one withdrawal marker that never
        // becomes a leaf.
        args.tree = EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 2, false);
        args.usedAuthRoots = EpochHelpers.buildAuthRoots(0, 1);
        args.nullifiers = _wrap2D(nullifiers, 2);
        args.transfers = _buildTransfersN(outputs, 2);
        args.feeTransfer = EpochHelpers.buildFeeTransfer(feeOutputs);
        args.withdrawals = withdrawals;
        args.withdrawalSlots = withdrawalSlots;
    }

    function _prepareTwoWithdrawals(Withdrawal memory w0, Withdrawal memory w1)
        internal
        returns (SubmitArgs memory args)
    {
        Output[] memory outputs = new Output[](BATCH_SIZE);
        outputs[0] = EpochHelpers.makeOutput(
            Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(w0.to)), uint256(w0.tokenId), w0.amount)
        );
        outputs[1] = EpochHelpers.makeOutput(
            Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(w1.to)), uint256(w1.tokenId), w1.amount)
        );

        uint256[] memory nullifiers = new uint256[](BATCH_SIZE);
        nullifiers[0] = _uniq(uint256(keccak256(abi.encode("n0", w0.to, w0.amount))));
        nullifiers[1] = _uniq(uint256(keccak256(abi.encode("n1", w1.to, w1.amount))));

        Output[] memory feeOutputs = new Output[](MAX_FEE_TOKENS);
        feeOutputs[0] = EpochHelpers.makeOutput(_uniq(uint256(keccak256("fee-two-withdrawals"))));

        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        withdrawals[0] = w0;
        withdrawals[1] = w1;

        uint32[] memory withdrawalSlots = new uint32[](2);
        withdrawalSlots[0] = 0;
        withdrawalSlots[1] = 1;

        uint256 rootOld = pool.treeRoot(pool.currentTreeNumber());
        uint32 countOld = pool.treeCount(pool.currentTreeNumber());
        TreeRootPair[] memory usedRoots = EpochHelpers.buildUsedRoots(0, rootOld);

        // Both slots pay out publicly, so only the fee note survives as a leaf.
        args.tree = EpochHelpers.buildTreeState(usedRoots, 0, countOld, 1, countOld + 1, false);
        args.usedAuthRoots = EpochHelpers.buildAuthRoots(0, 1);
        args.nullifiers = _wrap2D(nullifiers, 2);
        args.transfers = _buildTransfersN(outputs, 2);
        args.feeTransfer = EpochHelpers.buildFeeTransfer(feeOutputs);
        args.withdrawals = withdrawals;
        args.withdrawalSlots = withdrawalSlots;
    }

    function _callSubmit(SubmitArgs memory args, GatewaySlot[] memory gatewaySlots) internal {
        vm.prank(relayer);
        pool.submitEpoch(
            args.tree,
            args.usedAuthRoots,
            2,
            1,
            1,
            _u32arr(1, 2),
            _u32arr(1, 2),
            args.nullifiers,
            args.transfers,
            args.feeTransfer,
            args.withdrawals,
            args.withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            gatewaySlots
        );
    }

    function _callSubmitWithGas(SubmitArgs memory args, GatewaySlot[] memory gatewaySlots, uint256 gasLimit) internal {
        vm.prank(relayer);
        pool.submitEpoch{gas: gasLimit}(
            args.tree,
            args.usedAuthRoots,
            2,
            1,
            1,
            _u32arr(1, 2),
            _u32arr(1, 2),
            args.nullifiers,
            args.transfers,
            args.feeTransfer,
            args.withdrawals,
            args.withdrawalSlots,
            uint64(block.timestamp),
            EpochHelpers.dummyProof(),
            gatewaySlots
        );
    }

    /// @notice Build + submit a single-withdrawal epoch. For expect-revert tests use the two-step
    ///         pattern: `args = _prepareSingleWithdrawal(w); vm.expectRevert(...); _callSubmit(args, slots);`.
    function _submitOneWithdrawal(Withdrawal memory w, GatewaySlot[] memory gatewaySlots) internal {
        SubmitArgs memory args = _prepareSingleWithdrawal(w);
        _callSubmit(args, gatewaySlots);
    }

    /// @notice Mint vault4626 shares to the pool by depositing USDC as a backer first.
    function _fundPoolWithVaultShares(uint256 underlyingAmount, address backer) internal returns (uint256 shares) {
        usdc.mint(backer, underlyingAmount);
        vm.startPrank(backer);
        usdc.approve(address(vault4626), underlyingAmount);
        shares = vault4626.deposit(underlyingAmount, backer);
        vault4626.transfer(address(pool), shares);
        vm.stopPrank();
    }

    // ─── Internal utilities ───

    uint256 internal _nonceCounter;

    function _uniq(uint256 base) internal returns (uint256) {
        _nonceCounter++;
        return uint256(keccak256(abi.encode(base, _nonceCounter))) & ((uint256(1) << 250) - 1);
    }

    function _u32arr(uint32 val, uint32 count) internal pure returns (uint32[] memory arr) {
        arr = new uint32[](count);
        for (uint32 i = 0; i < count; i++) {
            arr[i] = val;
        }
    }

    function _wrap2D(uint256[] memory nullifiers, uint32 nTransfers) internal pure returns (uint256[][] memory result) {
        result = new uint256[][](nTransfers);
        uint256 perTransfer = nullifiers.length / nTransfers;
        for (uint32 i = 0; i < nTransfers; i++) {
            result[i] = new uint256[](perTransfer);
            for (uint256 j = 0; j < perTransfer; j++) {
                result[i][j] = nullifiers[i * perTransfer + j];
            }
        }
    }

    function _buildTransfersN(Output[] memory outputs, uint32 nTransfers)
        internal
        pure
        returns (Transfer[] memory result)
    {
        result = new Transfer[](nTransfers);
        uint256 perTransfer = outputs.length / nTransfers;
        for (uint32 i = 0; i < nTransfers; i++) {
            Output[] memory transferOutputs = new Output[](perTransfer);
            for (uint256 j = 0; j < perTransfer; j++) {
                transferOutputs[j] = outputs[i * perTransfer + j];
            }
            result[i] = Transfer({viewingKey: bytes32(0), teeWrapKey: bytes32(0), outputs: transferOutputs});
        }
    }

    /// @dev Wraps memory GatewaySlot[] for calldata-typed external param via assembly-free pattern:
    ///      ABI encoder accepts memory arrays for calldata params in test contexts.
    function _toCalldataSlots(GatewaySlot[] memory s) internal pure returns (GatewaySlot[] memory) {
        return s;
    }

    function _slotArr1(GatewaySlot memory s) internal pure returns (GatewaySlot[] memory arr) {
        arr = new GatewaySlot[](1);
        arr[0] = s;
    }

    function _slotArr2(GatewaySlot memory a, GatewaySlot memory b) internal pure returns (GatewaySlot[] memory arr) {
        arr = new GatewaySlot[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function _emptyGatewayCallData(uint256 n) internal pure returns (bytes[] memory arr) {
        arr = new bytes[](n);
    }

    function _withdrawalArr2(Withdrawal memory a, Withdrawal memory b) internal pure returns (Withdrawal[] memory arr) {
        arr = new Withdrawal[](2);
        arr[0] = a;
        arr[1] = b;
    }
}
