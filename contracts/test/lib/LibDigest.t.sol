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

import {LibDigest} from "src/lib/LibDigest.sol";
import {Output, Withdrawal} from "src/interfaces/IStructs.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {DOMAIN_PORTAL_REQUEST} from "src/interfaces/Constants.sol";

contract LibDigestTest is Test {
    uint256 constant CHAIN_ID = 1;
    address constant POOL = address(0x1234);
    uint256 constant ROOT = 0xABCD;
    uint256 constant NULLIFIER = 0x1111;
    uint256 constant DEPOSIT_REQUEST_ID = 0x2222;

    function _singleNullifier() internal pure returns (uint256[] memory) {
        uint256[] memory nullifiers = new uint256[](1);
        nullifiers[0] = NULLIFIER;
        return nullifiers;
    }

    function _singleOutput(uint256 commitment) internal pure returns (Output[] memory) {
        Output[] memory outputs = new Output[](1);
        outputs[0] = Output({
            commitment: commitment,
            receiverWrapKey: bytes32(0),
            ct0: bytes32(0),
            ct1: bytes32(0),
            ct2: bytes32(0),
            ct3: bytes16(0)
        });
        return outputs;
    }

    function _dummyWithdrawal() internal pure returns (Withdrawal memory) {
        return Withdrawal({to: address(0xBEEF), tokenId: 1, amount: 1000 ether});
    }

    // ========== Transfer Digest ==========

    function test_computeTransferDigest_returnsSplitHash() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);

        (uint256 hi, uint256 lo) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers, outputs, bytes32(0), bytes32(0));

        bytes32 expectedDigest =
            keccak256(abi.encode("PB:TRANSFER:v2", CHAIN_ID, POOL, nullifiers, outputs, bytes32(0), bytes32(0)));

        assertEq(hi, uint256(expectedDigest) >> 128);
        assertEq(lo, uint256(expectedDigest) & ((uint256(1) << 128) - 1));
    }

    function test_computeTransferDigest_differentInputsProduceDifferentDigests() public {
        uint256[] memory nullifiers1 = _singleNullifier();
        uint256[] memory nullifiers2 = new uint256[](1);
        nullifiers2[0] = NULLIFIER + 1;
        Output[] memory outputs = _singleOutput(123456);

        (uint256 hi1, uint256 lo1) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers1, outputs, bytes32(0), bytes32(0));
        (uint256 hi2, uint256 lo2) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers2, outputs, bytes32(0), bytes32(0));

        assertTrue(hi1 != hi2 || lo1 != lo2);
    }

    // ========== Fee Transfer Digest ==========

    function test_computeFeeTransferDigest_returnsSplitHash() public pure {
        Output[] memory outputs = _singleOutput(123456);
        outputs[0].receiverWrapKey = bytes32(uint256(0x2222));
        outputs[0].ct0 = bytes32(uint256(0x3333));
        outputs[0].ct1 = bytes32(uint256(0x4444));
        outputs[0].ct2 = bytes32(uint256(0x5555));
        outputs[0].ct3 = bytes16(uint128(0x6666));
        bytes32 viewingKey = bytes32(uint256(0x7777));
        bytes32 teeWrapKey = bytes32(uint256(0x8888));

        (uint256 hi, uint256 lo) = LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, outputs, viewingKey, teeWrapKey);
        bytes32 expectedDigest =
            keccak256(abi.encode("PB:FEE_TRANSFER:v1", CHAIN_ID, POOL, outputs, viewingKey, teeWrapKey));

        assertEq(hi, uint256(expectedDigest) >> 128);
        assertEq(lo, uint256(expectedDigest) & ((uint256(1) << 128) - 1));
        assertEq(hi, 0x70df8cd3d25ae64dacb016310595895a);
        assertEq(lo, 0xb9048861945077ac9c0d9bf67f9387f);
    }

    /// @dev Every field the fee-metadata digest authenticates must move the digest.
    ///      A field silently dropped from the encoding is exactly the gap the
    ///      digest exists to close, so each one is mutated independently rather
    ///      than relying on a single representative ciphertext word.
    function test_computeFeeTransferDigest_everyAuthenticatedFieldChangesDigest() public pure {
        (uint256 baseHi, uint256 baseLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, _singleOutput(123456), bytes32(0), bytes32(0));

        Output[] memory mutated = _singleOutput(123456);
        mutated[0].commitment = 123457;
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        mutated = _singleOutput(123456);
        mutated[0].receiverWrapKey = bytes32(uint256(1));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        mutated = _singleOutput(123456);
        mutated[0].ct0 = bytes32(uint256(1));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        mutated = _singleOutput(123456);
        mutated[0].ct1 = bytes32(uint256(1));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        mutated = _singleOutput(123456);
        mutated[0].ct2 = bytes32(uint256(1));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        mutated = _singleOutput(123456);
        mutated[0].ct3 = bytes16(uint128(1));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));

        _assertFeeDigestDiffers(baseHi, baseLo, _singleOutput(123456), bytes32(uint256(1)), bytes32(0));
        _assertFeeDigestDiffers(baseHi, baseLo, _singleOutput(123456), bytes32(0), bytes32(uint256(1)));
    }

    /// @dev The chain id and pool address are what stop a fee-metadata digest
    ///      from being replayed against another deployment, so both must be
    ///      inside the preimage rather than merely available to the caller.
    function test_computeFeeTransferDigest_bindsChainAndPool() public pure {
        Output[] memory outputs = _singleOutput(123456);
        (uint256 baseHi, uint256 baseLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, outputs, bytes32(0), bytes32(0));

        (uint256 otherChainHi, uint256 otherChainLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID + 1, POOL, outputs, bytes32(0), bytes32(0));
        assertTrue(otherChainHi != baseHi || otherChainLo != baseLo);

        (uint256 otherPoolHi, uint256 otherPoolLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID, address(uint160(POOL) + 1), outputs, bytes32(0), bytes32(0));
        assertTrue(otherPoolHi != baseHi || otherPoolLo != baseLo);
    }

    /// @dev The final two bytes of ct2 are padding under the current fee-note
    ///      layout, so mutating them is inert in the indexer. They are still
    ///      inside the digest preimage, which is what keeps the format safe if
    ///      the layout ever reclaims them.
    function test_computeFeeTransferDigest_coversCt2PaddingBytes() public pure {
        (uint256 baseHi, uint256 baseLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, _singleOutput(123456), bytes32(0), bytes32(0));

        Output[] memory mutated = _singleOutput(123456);
        mutated[0].ct2 = bytes32(uint256(0xffff));
        _assertFeeDigestDiffers(baseHi, baseLo, mutated, bytes32(0), bytes32(0));
    }

    function test_computeFeeTransferDigest_outputOrderChangesDigest() public pure {
        Output[] memory ordered = new Output[](2);
        ordered[0] = _singleOutput(111)[0];
        ordered[1] = _singleOutput(222)[0];
        (uint256 orderedHi, uint256 orderedLo) =
            LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, ordered, bytes32(0), bytes32(0));

        Output[] memory swapped = new Output[](2);
        swapped[0] = _singleOutput(222)[0];
        swapped[1] = _singleOutput(111)[0];
        _assertFeeDigestDiffers(orderedHi, orderedLo, swapped, bytes32(0), bytes32(0));
    }

    function _assertFeeDigestDiffers(
        uint256 baseHi,
        uint256 baseLo,
        Output[] memory outputs,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) internal pure {
        (uint256 hi, uint256 lo) = LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, outputs, viewingKey, teeWrapKey);
        assertTrue(hi != baseHi || lo != baseLo);
    }

    // ========== Withdrawal Digest ==========

    function test_computeWithdrawalDigest_returnsSplitHash() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 hi, uint256 lo) =
            LibDigest.computeWithdrawalDigest(CHAIN_ID, POOL, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0));

        bytes32 expectedDigest = keccak256(
            abi.encode("PB:WITHDRAW:v2", CHAIN_ID, POOL, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0))
        );

        assertEq(hi, uint256(expectedDigest) >> 128);
        assertEq(lo, uint256(expectedDigest) & ((uint256(1) << 128) - 1));
    }

    function test_computeWithdrawalDigest_differentFromTransferDigest() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 transferHi, uint256 transferLo) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers, outputs, bytes32(0), bytes32(0));
        (uint256 withdrawHi, uint256 withdrawLo) =
            LibDigest.computeWithdrawalDigest(CHAIN_ID, POOL, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0));

        assertTrue(transferHi != withdrawHi || transferLo != withdrawLo);
    }

    // ========== Forced Withdrawal Digest ==========

    function test_computeForcedWithdrawalDigest_returnsFullHash() public {
        uint256[] memory nullifiers = new uint256[](2);
        nullifiers[0] = 0x1111;
        nullifiers[1] = 0x2222;
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 0xAAAA;
        commitments[1] = 0xBBBB;
        Withdrawal memory withdrawal = _dummyWithdrawal();

        bytes32 digest =
            LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, 12345, 0, nullifiers, commitments, withdrawal, 200);

        bytes32 expected = keccak256(
            abi.encode(
                "PB:FORCED_WITHDRAW:v3",
                CHAIN_ID,
                POOL,
                uint256(12345),
                uint8(0),
                nullifiers,
                commitments,
                withdrawal,
                uint16(200)
            )
        );

        assertEq(digest, expected);
    }

    function test_computeForcedWithdrawalDigest_differentNullifiersProduceDifferentDigests() public {
        uint256[] memory nullifiers1 = new uint256[](1);
        nullifiers1[0] = 0x1111;

        uint256[] memory nullifiers2 = new uint256[](1);
        nullifiers2[0] = 0x2222;
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 0xAAAA;

        Withdrawal memory withdrawal = _dummyWithdrawal();

        bytes32 digest1 =
            LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, 1, 0, nullifiers1, commitments, withdrawal, 0);
        bytes32 digest2 =
            LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, 1, 0, nullifiers2, commitments, withdrawal, 0);

        assertTrue(digest1 != digest2);
    }

    // ========== Withdrawal Commitment ==========

    function test_computeWithdrawalCommitment_returnsNonZero() public {
        address to = address(0xBEEF);
        uint16 tokenId = 1;
        uint96 amount = 1000 ether;

        uint256 commitment = LibDigest.computeWithdrawalCommitment(to, tokenId, amount);

        assertTrue(commitment != 0);
    }

    function test_computeWithdrawalCommitment_differentInputsProduceDifferentCommitments() public {
        uint256 commitment1 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);
        uint256 commitment2 = LibDigest.computeWithdrawalCommitment(address(0xCAFE), 1, 1000 ether);
        uint256 commitment3 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 2, 1000 ether);
        uint256 commitment4 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 2000 ether);

        assertTrue(commitment1 != commitment2);
        assertTrue(commitment1 != commitment3);
        assertTrue(commitment1 != commitment4);
    }

    function test_computeWithdrawalCommitment_sameInputsProduceSameCommitment() public {
        uint256 commitment1 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);
        uint256 commitment2 = LibDigest.computeWithdrawalCommitment(address(0xBEEF), 1, 1000 ether);

        assertEq(commitment1, commitment2);
    }

    // ========== Deposit Request ID ==========

    function test_computeDepositRequestId_returnsNonZero() public {
        uint256 requestId = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);

        assertTrue(requestId != 0);
    }

    function test_computeDepositRequestId_differentNoncesProduceDifferentIds() public {
        uint256 id1 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);
        uint256 id2 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 1, 12345);

        assertTrue(id1 != id2);
    }

    function test_computeDepositRequestId_sameInputsProduceSameId() public {
        uint256 id1 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);
        uint256 id2 = LibDigest.computeDepositRequestId(CHAIN_ID, POOL, address(0xBEEF), 1, 1000 ether, 0, 12345);

        assertEq(id1, id2);
    }

    // ========== Portal Deposit Request ID ==========

    address constant PORTAL = address(0xE);
    uint16 constant PORTAL_TOKEN = 1;
    uint96 constant PORTAL_AMOUNT = 100 ether;
    uint256 constant PORTAL_COUNTER = 5;
    uint256 constant PORTAL_H = 0xABCDEF;

    /// @dev The digest must equal the exact keccak256(abi.encode(...)) over
    ///      (DOMAIN_PORTAL_REQUEST, chainId, pool, E, tokenId, amount, counter, H) — the same
    ///      abi.encode'd preimage the Rust SDK reclaim helper and the Go cross-language vectors key,
    ///      so matching this formula keeps all three byte-identical. A wrong domain tag or a permuted
    ///      argument order fails here.
    function test_computePortalDepositId_matchesKeccakVector() public pure {
        uint256 actual = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );

        uint256 expected = uint256(
            keccak256(
                abi.encode(
                    DOMAIN_PORTAL_REQUEST,
                    CHAIN_ID,
                    uint256(uint160(POOL)),
                    uint256(uint160(PORTAL)),
                    uint256(PORTAL_TOKEN),
                    uint256(PORTAL_AMOUNT),
                    PORTAL_COUNTER,
                    PORTAL_H
                )
            )
        );

        assertEq(actual, expected);
    }

    /// @dev A zero recipientBindH is the sentinel for an unregistered portal (E's portalBinding() == 0); the
    ///      helper rejects it so a request can never be keyed against an unregistered binding,
    ///      mirroring requestDeposit's `commitment == 0` rejection (PrivacyBoost.sol:615).
    function test_revertWhen_recipientBindHZero() public {
        vm.expectRevert(LibDigest.PortalDigestRecipientBindZero.selector);
        LibDigest.computePortalDepositId(CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, 0);
    }

    /// @dev counter == 0 is valid: portalCounter[E] starts at 0, so the first sweep of a portal
    ///      must produce a usable id. Pins that counter == 0 yields a non-zero id — deleting the
    ///      `counter` field or rejecting zero would break the first deposit.
    function test_computePortalDepositId_counterZeroIsValid() public pure {
        uint256 id = LibDigest.computePortalDepositId(CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, 0, PORTAL_H);
        assertTrue(id != 0);
    }

    /// @dev keccak256 imposes NO field bound, so even type(uint256).max for every unbounded arg
    ///      (chainId, counter, recipientBindH) must succeed — unlike the Poseidon era there is no
    ///      `>= PRIME` rejection. Pins that the only input check is the zero-recipientBindH sentinel.
    function test_computePortalDepositId_acceptsFullUint256Range() public pure {
        uint256 id = LibDigest.computePortalDepositId(
            type(uint256).max, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, type(uint256).max, type(uint256).max
        );
        assertTrue(id != 0);
    }

    function test_computePortalDepositId_returnsNonZero() public pure {
        uint256 id = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        assertTrue(id != 0);
    }

    function test_computePortalDepositId_sameInputsProduceSameId() public pure {
        uint256 id1 = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 id2 = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        assertEq(id1, id2);
    }

    /// @dev Each field must change the id. The counter case is load-bearing: it is the
    ///      uniqueness guard that lets repeated sweeps of the same (portal, token, amount)
    ///      produce distinct records instead of a colliding key.
    function test_computePortalDepositId_eachFieldChangesId() public pure {
        uint256 base = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );

        uint256 diffChain = LibDigest.computePortalDepositId(
            CHAIN_ID + 1, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 diffPool = LibDigest.computePortalDepositId(
            CHAIN_ID, address(0x5678), PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 diffPortal = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, address(0xEEEE), PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 diffToken = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN + 1, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 diffAmount = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT + 1, PORTAL_COUNTER, PORTAL_H
        );
        uint256 diffCounter = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER + 1, PORTAL_H
        );
        uint256 diffH = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H + 1
        );

        assertTrue(base != diffChain, "chainId must change id");
        assertTrue(base != diffPool, "pool must change id");
        assertTrue(base != diffPortal, "portal must change id");
        assertTrue(base != diffToken, "tokenId must change id");
        assertTrue(base != diffAmount, "amount must change id");
        assertTrue(base != diffCounter, "counter must change id");
        assertTrue(base != diffH, "recipientBindH must change id");
    }

    /// @dev The portal id must not collide with the standard deposit id even when every
    ///      shared argument matches: the portal id is keccak256 over a DOMAIN_PORTAL_REQUEST-led
    ///      preimage while the deposit id is Poseidon over a DOMAIN_DEPOSIT_REQUEST-led one, so the
    ///      two key spaces are disjoint. Without this separation a portal record key could alias a
    ///      deposit record key.
    function test_computePortalDepositId_differsFromDepositRequestId() public pure {
        // Map the portal arg layout onto the deposit arg layout 1:1 (same 7 trailing
        // fields), so any difference is attributable solely to the domain separator.
        uint256 portalId = LibDigest.computePortalDepositId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, PORTAL_COUNTER, PORTAL_H
        );
        uint256 depositId = LibDigest.computeDepositRequestId(
            CHAIN_ID, POOL, PORTAL, PORTAL_TOKEN, PORTAL_AMOUNT, uint32(PORTAL_COUNTER), PORTAL_H
        );

        assertTrue(portalId != depositId);
    }

    // ========== Domain Separation ==========

    function test_digestDomainSeparation_allDomainsProduceDifferentDigests() public {
        uint256[] memory nullifiers = _singleNullifier();
        Output[] memory outputs = _singleOutput(123456);
        Withdrawal memory withdrawal = _dummyWithdrawal();

        (uint256 transferHi,) =
            LibDigest.computeTransferDigest(CHAIN_ID, POOL, nullifiers, outputs, bytes32(0), bytes32(0));
        (uint256 withdrawHi,) =
            LibDigest.computeWithdrawalDigest(CHAIN_ID, POOL, nullifiers, outputs, withdrawal, bytes32(0), bytes32(0));
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = 123456;
        bytes32 forcedDigest =
            LibDigest.computeForcedWithdrawalDigest(CHAIN_ID, POOL, 1, 0, nullifiers, commitments, withdrawal, 0);

        (uint256 feeHi,) = LibDigest.computeFeeTransferDigest(CHAIN_ID, POOL, outputs, bytes32(0), bytes32(0));

        assertTrue(transferHi != withdrawHi);
        assertTrue(bytes32(transferHi << 128) != forcedDigest);
        assertTrue(feeHi != transferHi);
        assertTrue(feeHi != withdrawHi);
    }

    // ========== Commitments Hash ==========

    function test_computeCommitmentsHash_array_returnsSequentialHash() public {
        uint256[] memory commitments = new uint256[](3);
        commitments[0] = 100;
        commitments[1] = 200;
        commitments[2] = 300;

        uint256 hashResult = LibDigest.computeCommitmentsHash(commitments);

        // Manually compute expected: Hash(Hash(Hash(0, 100), 200), 300)
        uint256 step1 = LibDigest.computeCommitmentsHashStep(0, 100);
        uint256 step2 = LibDigest.computeCommitmentsHashStep(step1, 200);
        uint256 step3 = LibDigest.computeCommitmentsHashStep(step2, 300);

        assertEq(hashResult, step3);
    }

    function test_computeCommitmentsHash_incremental_matchesArray() public {
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        uint256 arrayHash = LibDigest.computeCommitmentsHash(commitments);

        uint256 incrementalHash = 0;
        incrementalHash = LibDigest.computeCommitmentsHashStep(incrementalHash, 111);
        incrementalHash = LibDigest.computeCommitmentsHashStep(incrementalHash, 222);

        assertEq(arrayHash, incrementalHash);
    }

    function test_computeOutputsCommitmentsHash_matchesCommitmentsArray() public {
        Output[] memory outputs = new Output[](2);
        outputs[0] = _singleOutput(111)[0];
        outputs[1] = _singleOutput(222)[0];
        uint256[] memory commitments = new uint256[](2);
        commitments[0] = 111;
        commitments[1] = 222;

        uint256 outputHash = LibDigest.computeOutputsCommitmentsHash(outputs);
        uint256 commitmentsHash = LibDigest.computeCommitmentsHash(commitments);

        assertEq(outputHash, commitmentsHash);
    }

    function test_computeCommitmentsHash_emptyArray_returnsZero() public {
        uint256[] memory commitments = new uint256[](0);
        uint256 hashResult = LibDigest.computeCommitmentsHash(commitments);
        assertEq(hashResult, 0);
    }

    function test_computeCommitmentsHash_differentOrderProducesDifferentHash() public {
        uint256[] memory commitments1 = new uint256[](2);
        commitments1[0] = 100;
        commitments1[1] = 200;

        uint256[] memory commitments2 = new uint256[](2);
        commitments2[0] = 200;
        commitments2[1] = 100;

        uint256 hash1 = LibDigest.computeCommitmentsHash(commitments1);
        uint256 hash2 = LibDigest.computeCommitmentsHash(commitments2);

        assertTrue(hash1 != hash2);
    }
}
