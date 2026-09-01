// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";
import {LibDigest} from "src/lib/LibDigest.sol";
import {
    Output,
    Withdrawal,
    GatewaySlot,
    GatewayReceipt,
    GatewayAction,
    DepositCiphertext
} from "src/interfaces/IStructs.sol";

/// @notice Locks the canonical PB:WITHDRAW:GATEWAY:v2 digest. The Go encoder
///         (prover/witness.ComputeGatewayWithdrawalDigest) asserts the same
///         (hi, lo) over byte-identical inputs in
///         prover/witness/gateway_digest_test.go::TestGatewayDigestGoldenMatchesSolidity.
///         If either side drifts, gateway signatures will not verify on-chain.
contract GatewayDigestParityTest is Test {
    // Golden vector shared with the Go parity test.
    uint256 internal constant EXPECTED_HI = 76165050801055972420936205470495311933;
    uint256 internal constant EXPECTED_LO = 155307225255424959554389537027839685828;

    // Golden receiptHash shared with prover/witness.GatewayReceiptHash.
    bytes32 internal constant EXPECTED_RECEIPT_HASH =
        0x36c0ffd2b4a8b13967688a39a217b8ac81d72f9f2464f1fbc342b309f50d33f8;

    function _sampleReceipt() internal pure returns (GatewayReceipt memory) {
        return GatewayReceipt({
            outputTokenId: 7,
            minOutputAmount: 95_000_000,
            npk: 0xdeadbeef,
            rescueCommitment: bytes32(uint256(0x010203) << 232),
            ciphertext: DepositCiphertext({
                viewingKey: bytes32(uint256(0x11) << 248),
                teeWrapKey: bytes32(uint256(0x22) << 248),
                receiverWrapKey: bytes32(0),
                ct0: bytes32(uint256(0x33) << 248),
                ct1: bytes32(0),
                ct2: bytes16(uint128(0x44) << 120)
            })
        });
    }

    function _sampleFallbackReceipt() internal pure returns (GatewayReceipt memory) {
        GatewayReceipt memory r = _sampleReceipt();
        r.outputTokenId = 5;
        r.minOutputAmount = 0;
        r.npk = 0xbeefdead;
        r.rescueCommitment = bytes32(uint256(0x0a0b0c) << 232);
        return r;
    }

    /// @notice Locks keccak256(abi.encode(receipt)) — the contract's receiptHash —
    ///         to prover/witness.GatewayReceiptHash (Go).
    function test_gatewayReceiptHashMatchesGolden() public pure {
        assertEq(keccak256(abi.encode(_sampleReceipt())), EXPECTED_RECEIPT_HASH, "receiptHash drifted from Go");
    }

    function test_gatewayDepositDataMatchesIndividualHelpers() public view {
        GatewayReceipt memory receipt = _sampleReceipt();
        address gateway = address(uint160(0xbb));
        uint96 amount = 1234;
        uint32 nonce = 7;

        (uint256 commitment, uint256 commitmentsHash, uint256 depositRequestId) =
            LibDigest.computeGatewayDepositData(gateway, receipt.outputTokenId, amount, nonce, receipt.npk);
        uint256 expectedCommitment = LibDigest.computeNoteCommitment(receipt.npk, receipt.outputTokenId, amount);
        uint256 expectedHash = LibDigest.computeCommitmentsHashStep(0, expectedCommitment);
        uint256 expectedRequestId = LibDigest.computeDepositRequestId(
            block.chainid, address(this), gateway, receipt.outputTokenId, amount, nonce, expectedHash
        );

        assertEq(commitment, expectedCommitment);
        assertEq(commitmentsHash, expectedHash);
        assertEq(depositRequestId, expectedRequestId);
    }

    function test_gatewayDigestFixtureMatchesGolden() public view {
        uint256 chainId = 8453;
        address pool = address(uint160(0xaa));

        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 1;
        nullifiers[1] = 2;

        Output[] memory outputs = new Output[](1);
        outputs[0] = Output({
            commitment: 0xc0ffee,
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes32(0),
            ct3: bytes16(0)
        });

        Withdrawal memory w = Withdrawal({to: address(uint160(0xbb)), tokenId: 5, amount: 1000});

        bytes32 vk = bytes32(uint256(0xaa) << 248);
        bytes32 tk = bytes32(uint256(0xbb) << 248);

        GatewaySlot memory slot = GatewaySlot({
            withdrawalIndex: 0,
            action: GatewayAction.ExternalCall,
            expiryBlock: 1234,
            target: address(uint160(0xcc)),
            callData: hex"12345678",
            receipt: _sampleReceipt(),
            fallbackReceipt: _sampleFallbackReceipt()
        });

        (uint256 hi, uint256 lo) =
            this.computeGatewayWithdrawalDigest(chainId, pool, nullifiers, outputs, w, vk, tk, slot);

        assertEq(hi, EXPECTED_HI, "gateway digest hi drifted from the Go golden vector");
        assertEq(lo, EXPECTED_LO, "gateway digest lo drifted from the Go golden vector");
    }

    function computeGatewayWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256[] calldata nullifiers,
        Output[] calldata outputs,
        Withdrawal calldata withdrawal,
        bytes32 viewingKey,
        bytes32 teeWrapKey,
        GatewaySlot calldata slot
    ) external pure returns (uint256 hi, uint256 lo) {
        return LibDigest.computeGatewayWithdrawalDigest(
            chainId, pool, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey, slot
        );
    }
}
