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

import {Output, Withdrawal, GatewaySlot} from "src/interfaces/IStructs.sol";
import {
    DOMAIN_NOTE,
    DOMAIN_DEPOSIT_REQUEST,
    DOMAIN_PORTAL_REQUEST,
    DIGEST_HALF_BITS
} from "src/interfaces/Constants.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";

/// @title LibDigest
/// @notice Digest and hash computation for transaction authorization
/// @custom:security-contact contact@sunnyside.io
library LibDigest {
    string internal constant TRANSFER_DOMAIN = "PB:TRANSFER:v2";
    string internal constant FEE_TRANSFER_DOMAIN = "PB:FEE_TRANSFER:v1";
    string internal constant DEPOSIT_DOMAIN = "PB:DEPOSIT:v1";
    string internal constant GIFT_CLAIM_DOMAIN = "PB:GIFT_CLAIM:v2";
    string internal constant GIFT_EXIT_DOMAIN = "PB:GIFT_EXIT:v2";

    /// @dev BN254 scalar field prime — every Poseidon-hashed input must be a canonical field
    ///      element (< this value). Equals Poseidon2T4.PRIME and the pool's SNARK_SCALAR_FIELD;
    ///      kept as a named constant here so the digest helpers can enforce
    ///      the field-element precondition at their own boundary.
    uint256 internal constant SNARK_SCALAR_FIELD = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    /// @notice Thrown when a portal-deposit digest argument is not a canonical BN254 field element
    error PortalDigestRecipientBindZero();
    string internal constant WITHDRAW_DOMAIN = "PB:WITHDRAW:v2";
    string internal constant WITHDRAW_GATEWAY_DOMAIN = "PB:WITHDRAW:GATEWAY:v2";
    string internal constant FORCED_WITHDRAW_DOMAIN = "PB:FORCED_WITHDRAW:v3";

    // ─────────────── Signing digests ───────────────

    /// @notice Compute transfer approval digest
    /// @dev Digest = keccak256(abi.encode(TRANSFER_DOMAIN, chainId, pool, nullifiers, outputs, viewingKey, teeWrapKey)).
    ///      Split into hi/lo for circuit field compatibility.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param outputs The output metadata (commitments + ciphertexts)
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeTransferDigest(
        uint256 chainId,
        address pool,
        uint256[] calldata nullifiers,
        Output[] calldata outputs,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(TRANSFER_DOMAIN, chainId, pool, nullifiers, outputs, viewingKey, teeWrapKey)
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute the digest that binds active fee-note metadata to an epoch proof
    /// @dev Digest = keccak256(abi.encode(FEE_TRANSFER_DOMAIN, chainId, pool, outputs, viewingKey, teeWrapKey)).
    ///      The caller supplies only the active output prefix so inactive padding remains outside the statement.
    /// @param chainId The chain the digest is bound to
    /// @param pool The pool address the digest is bound to
    /// @param outputs The active fee-note outputs, excluding inactive padding
    /// @param viewingKey The fee-note viewing key
    /// @param teeWrapKey The wrapping key the fee metadata is sealed under
    /// @return hi High 128 bits of the digest
    /// @return lo Low 128 bits of the digest
    function computeFeeTransferDigest(
        uint256 chainId,
        address pool,
        Output[] calldata outputs,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(abi.encode(FEE_TRANSFER_DOMAIN, chainId, pool, outputs, viewingKey, teeWrapKey));
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute withdrawal approval digest
    /// @dev Digest = keccak256(
    ///          abi.encode(WITHDRAW_DOMAIN, chainId, pool, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey)
    ///      ).
    ///      Split into hi/lo for circuit field compatibility.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param outputs The output metadata (commitments + ciphertexts)
    /// @param withdrawal The public withdrawal details (recipient, token, amount)
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256[] calldata nullifiers,
        Output[] calldata outputs,
        Withdrawal calldata withdrawal,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(WITHDRAW_DOMAIN, chainId, pool, nullifiers, outputs, withdrawal, viewingKey, teeWrapKey)
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute gateway withdrawal approval digest. Binds the GatewaySlot's user-intent fields
    ///         to the authorization so a relay cannot mutate them.
    /// @dev Digest = keccak256(abi.encode(WITHDRAW_GATEWAY_DOMAIN, chainId, pool, nullifiers, outputs,
    ///                                      withdrawal, viewingKey, teeWrapKey,
    ///                                      gatewaySlot.action, gatewaySlot.expiryBlock,
    ///                                      gatewaySlot.target, keccak256(gatewaySlot.callData),
    ///                                      gatewaySlot.receipt, gatewaySlot.fallbackReceipt)).
    ///      `gatewaySlot.withdrawalIndex` is INTENTIONALLY excluded: it is the withdrawal's position in
    ///      the epoch's withdrawals[] array — a relay batching detail with no user-facing meaning,
    ///      assigned by the relay at batch time and enforced for routing by the strictly-ascending
    ///      pairing in processGatewayWithdrawals. Binding it would force the wallet to sign its batch
    ///      position, which it cannot know ahead of submission, and would needlessly cap an epoch to
    ///      one gateway withdrawal. Excluding it mirrors the position-independent plain withdrawal digest.
    ///      The circuit treats hi/lo as opaque field elements.
    function computeGatewayWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256[] calldata nullifiers,
        Output[] calldata outputs,
        Withdrawal calldata withdrawal,
        bytes32 viewingKey,
        bytes32 teeWrapKey,
        GatewaySlot calldata gatewaySlot
    ) internal pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(
                WITHDRAW_GATEWAY_DOMAIN,
                chainId,
                pool,
                nullifiers,
                outputs,
                withdrawal,
                viewingKey,
                teeWrapKey,
                gatewaySlot.action,
                gatewaySlot.expiryBlock,
                gatewaySlot.target,
                keccak256(gatewaySlot.callData),
                gatewaySlot.receipt,
                gatewaySlot.fallbackReceipt
            )
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute the snapshot-authorized forced withdrawal digest
    /// @dev The transaction submitter is intentionally not bound: a forced-withdrawal proof is an
    ///      emergency escape artifact that any relayer may submit while its authorization is live.
    ///      The exact protocol fee is bound because it is snapshotted when the request is accepted.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param spenderAccountId The shielded account authorizing the withdrawal
    /// @param authMode The forced authorization mode (key or dedicated approval)
    /// @param nullifiers The input nullifiers (spent notes)
    /// @param inputCommitments The commitments locked by the forced request
    /// @param withdrawal The public withdrawal details (recipient, token, amount)
    /// @param withdrawFeeBps The exact protocol fee at request acceptance
    /// @return digest The computed digest
    function computeForcedWithdrawalDigest(
        uint256 chainId,
        address pool,
        uint256 spenderAccountId,
        uint8 authMode,
        uint256[] calldata nullifiers,
        uint256[] calldata inputCommitments,
        Withdrawal calldata withdrawal,
        uint16 withdrawFeeBps
    ) external pure returns (bytes32) {
        return keccak256(
            abi.encode(
                FORCED_WITHDRAW_DOMAIN,
                chainId,
                pool,
                spenderAccountId,
                authMode,
                nullifiers,
                inputCommitments,
                withdrawal,
                withdrawFeeBps
            )
        );
    }

    /// @notice Compute the private-mint gift-claim approval digest (recipient claim / sender refund)
    /// @dev Digest = keccak256(abi.encode(GIFT_CLAIM_DOMAIN, chainId, pool, giftNullifier, output,
    ///      viewingKey, teeWrapKey)), split hi/lo for circuit field compatibility. Mirrors
    ///      computeTransferDigest: it binds the minted output COMMITMENT (which itself commits to the gift
    ///      token + amount via Poseidon(NOTE, npk, tokenId, amount)) and deliberately does NOT bind cleartext
    ///      token or amount, so a private claim/refund never reveals the gifted value on chain. The public
    ///      exit, which must reveal the amount to pay out the ERC-20, uses computeGiftExitDigest instead. The
    ///      contract recomputes this digest and never accepts a caller-supplied one.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param giftNullifier The gift nullifier spent by this claim/refund
    /// @param output The minted output metadata (commitment + ciphertext)
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeGiftClaimDigest(
        uint256 chainId,
        address pool,
        uint256 giftNullifier,
        Output calldata output,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(GIFT_CLAIM_DOMAIN, chainId, pool, giftNullifier, output, viewingKey, teeWrapKey)
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    /// @notice Compute the public-exit gift digest (permissionless, amount-revealing payout)
    /// @dev Digest = keccak256(abi.encode(GIFT_EXIT_DOMAIN, chainId, pool, giftNullifier, destination,
    ///      tokenId, amount, minNetAmount, viewingKey, teeWrapKey)), split hi/lo. Mirrors the withdrawal digest:
    ///      the exit pays an external destination, so it binds the cleartext destination + tokenId + gross amount
    ///      that the payout reveals. minNetAmount is a slippage floor: fee decreases keep a proof executable while
    ///      a fee increase that would pay less than the authorized minimum is rejected before proof verification.
    ///      A distinct domain (PB:GIFT_EXIT:v2) keeps an exit digest from ever being read as a private-claim digest.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param giftNullifier The gift nullifier spent by this exit
    /// @param destination The public payout destination
    /// @param tokenId The compact token ID of the gift
    /// @param amount The gift amount (gross, before fee)
    /// @param minNetAmount The minimum net amount the destination authorizes receiving after fees
    /// @param viewingKey Blinded sender viewing key included in the digest
    /// @param teeWrapKey Wrapped key for the TEE included in the digest
    /// @return hi Upper DIGEST_HALF_BITS bits of the digest
    /// @return lo Lower DIGEST_HALF_BITS bits of the digest
    function computeGiftExitDigest(
        uint256 chainId,
        address pool,
        uint256 giftNullifier,
        address destination,
        uint16 tokenId,
        uint96 amount,
        uint96 minNetAmount,
        bytes32 viewingKey,
        bytes32 teeWrapKey
    ) external pure returns (uint256 hi, uint256 lo) {
        bytes32 digest = keccak256(
            abi.encode(
                GIFT_EXIT_DOMAIN,
                chainId,
                pool,
                giftNullifier,
                destination,
                tokenId,
                amount,
                minNetAmount,
                viewingKey,
                teeWrapKey
            )
        );
        hi = uint256(digest) >> DIGEST_HALF_BITS;
        lo = uint256(digest) & ((uint256(1) << DIGEST_HALF_BITS) - 1);
    }

    // ─────────────── Commitments and request IDs ───────────────

    /// @notice Compute withdrawal commitment: Poseidon(DOMAIN_NOTE, to, tokenId, amount)
    /// @param to The withdrawal recipient
    /// @param tokenId The compact token ID
    /// @param amount The withdrawal amount (gross)
    /// @return commitment The Poseidon note commitment
    function computeWithdrawalCommitment(address to, uint16 tokenId, uint96 amount) external pure returns (uint256) {
        return Poseidon2T4.hash4(DOMAIN_NOTE, uint256(uint160(to)), uint256(tokenId), uint256(amount));
    }

    /// @notice Compute a note commitment from a nullifying public key: Poseidon(DOMAIN_NOTE, npk, tokenId, amount)
    /// @dev Kept external so callers route the Poseidon permutation through this library's deployed code
    ///      instead of inlining the full permutation into their own bytecode.
    /// @param npk The note's nullifying public key (already reduced into the scalar field)
    /// @param tokenId The compact token ID
    /// @param amount The note amount
    /// @return commitment The Poseidon note commitment
    function computeNoteCommitment(uint256 npk, uint16 tokenId, uint96 amount) external pure returns (uint256) {
        return Poseidon2T4.hash4(DOMAIN_NOTE, npk, uint256(tokenId), uint256(amount));
    }

    /// @notice Compute deposit request ID for circuit compatibility
    /// @dev depositRequestId = Poseidon2T4.hash8(
    ///          DOMAIN_DEPOSIT_REQUEST, chainId, uint256(uint160(pool)), uint256(uint160(depositor)),
    ///          tokenId, totalAmount, nonce, commitmentsHash
    ///      ).
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param depositor The depositor address
    /// @param tokenId The compact token ID
    /// @param totalAmount The total deposit amount (sum of hidden per-output amounts)
    /// @param nonce The depositor nonce used for uniqueness
    /// @param commitmentsHash Sequential Poseidon hash of all commitments in the request
    /// @return depositRequestId The computed deposit request ID
    function computeDepositRequestId(
        uint256 chainId,
        address pool,
        address depositor,
        uint16 tokenId,
        uint96 totalAmount,
        uint32 nonce,
        uint256 commitmentsHash
    ) external pure returns (uint256) {
        return Poseidon2T4.hash8(
            DOMAIN_DEPOSIT_REQUEST,
            chainId,
            uint256(uint160(pool)),
            uint256(uint160(depositor)),
            uint256(tokenId),
            uint256(totalAmount),
            uint256(nonce),
            commitmentsHash
        );
    }

    /// @notice Compute all hashes for a one-note gateway-origin deposit in one library call.
    /// @dev This library executes by delegatecall, so address(this) is the pool address.
    /// @param gateway Gateway address recorded as the deposit origin.
    /// @param tokenId Registered token ID credited by the deposit.
    /// @param amount Token amount committed into the note.
    /// @param nonce Gateway deposit nonce used to make the request identifier unique.
    /// @param npk Note public key committed into the output note.
    /// @return commitment Poseidon commitment for the gateway-origin output note.
    /// @return commitmentsHash Sequential commitments hash for the one-note request.
    /// @return depositRequestId Domain-separated identifier for the pending deposit record.
    function computeGatewayDepositData(address gateway, uint16 tokenId, uint96 amount, uint32 nonce, uint256 npk)
        external
        view
        returns (uint256 commitment, uint256 commitmentsHash, uint256 depositRequestId)
    {
        commitment = Poseidon2T4.hash4(DOMAIN_NOTE, npk, uint256(tokenId), uint256(amount));
        commitmentsHash = Poseidon2T4.hash2(0, commitment);
        depositRequestId = Poseidon2T4.hash8(
            DOMAIN_DEPOSIT_REQUEST,
            block.chainid,
            uint256(uint160(address(this))),
            uint256(uint160(gateway)),
            uint256(tokenId),
            uint256(amount),
            uint256(nonce),
            commitmentsHash
        );
    }

    /// @notice Compute portal-deposit request ID, the on-chain escrow + indexer discovery key.
    /// @dev portalDepositId = keccak256(abi.encode(
    ///          DOMAIN_PORTAL_REQUEST, chainId, uint256(uint160(pool)), uint256(uint160(portal)),
    ///          tokenId, amount, counter, recipientBindH
    ///      )).
    ///      Mirrors computeDepositRequestId's 8-input arity but binds to the registered owner
    ///      binding H instead of a caller-supplied commitments hash: a portal sweeper does not
    ///      know the recipient recipientMPK, so it cannot construct a commitment at sweep time. The
    ///      counter makes repeated sweeps of the same (portal, token, amount) hash to distinct
    ///      ids, so each sweep gets its own pending record and note.
    ///
    ///      keccak256 — not Poseidon2T4 — because this id is NEVER a circuit input: the portal
    ///      circuit binds the credit through `recipientBindH` and the note commitment, never the id,
    ///      so the id needs no SNARK-friendly hash and the far cheaper keccak (a few hundred gas vs
    ///      Poseidon2T4.hash8's ~344k) is sound. keccak256 is collision-resistant over the full
    ///      uint256 inputs, so unlike a Poseidon field-fold there is no `x` / `x + PRIME` aliasing to
    ///      guard against — the only check is the `recipientBindH == 0` sentinel for an unregistered
    ///      portal (E's portalBinding() == 0), mirroring requestDeposit's `commitment == 0` rejection. The
    ///      Rust SDK reclaim helper and the Go cross-language vectors key the same abi.encode'd
    ///      preimage byte-for-byte.
    /// @param chainId The chain ID used for domain separation
    /// @param pool The PrivacyBoost pool contract address
    /// @param portal The portal address E that was swept
    /// @param tokenId The compact token ID
    /// @param amount The gross swept amount (received pool balance delta)
    /// @param counter The per-portal sweep counter snapshotted at sweep time
    /// @param recipientBindH The owner binding H read from E's portalBinding(), never caller-supplied; MUST be non-zero
    /// @return portalDepositId The computed portal deposit request ID
    function computePortalDepositId(
        uint256 chainId,
        address pool,
        address portal,
        uint16 tokenId,
        uint96 amount,
        uint256 counter,
        uint256 recipientBindH
    ) external pure returns (uint256) {
        // recipientBindH == 0 is the unregistered-portal sentinel; reject it (defense in depth — the sweep
        // entrypoint already rejects an unregistered portal). The id is keccak256 over abi.encode'd 32-byte
        // words rather than Poseidon: it is never a circuit input (the portal circuit binds via H + the
        // commitment), so the cheaper hash is sound, and keccak256 is collision-resistant over the full
        // uint256 inputs — there is no x / x+PRIME field aliasing to guard against, so no range checks are
        // needed. The Rust SDK and the Go cross-language vectors key the same abi.encode'd preimage.
        if (recipientBindH == 0) revert PortalDigestRecipientBindZero();

        return uint256(
            keccak256(
                abi.encode(
                    DOMAIN_PORTAL_REQUEST,
                    chainId,
                    uint256(uint160(pool)),
                    uint256(uint160(portal)),
                    uint256(tokenId),
                    uint256(amount),
                    counter,
                    recipientBindH
                )
            )
        );
    }

    // ─────────────── Commitment-hash accumulation ───────────────

    /// @notice Sequential hash of commitments: Hash(Hash(...Hash(0, c0), c1), ..., cN)
    /// @param commitments The commitments to hash in order
    /// @return commitmentsHash The resulting sequential Poseidon hash
    function computeCommitmentsHash(uint256[] calldata commitments) external pure returns (uint256 commitmentsHash) {
        commitmentsHash = 0;
        for (uint256 i = 0; i < commitments.length; ++i) {
            commitmentsHash = Poseidon2T4.hash2(commitmentsHash, commitments[i]);
        }
    }

    /// @notice Incremental step for sequential hashing: newHash = Hash(prevHash, commitment)
    /// @param prevHash The previous hash value
    /// @param commitment The next commitment to include
    /// @return newHash The updated sequential Poseidon hash
    function computeCommitmentsHashStep(uint256 prevHash, uint256 commitment) external pure returns (uint256 newHash) {
        newHash = Poseidon2T4.hash2(prevHash, commitment);
    }

    /// @notice Sequential hash of output commitments: Hash(Hash(...Hash(0, c0), c1), ..., cN)
    /// @param outputs The outputs whose commitments to hash in order
    /// @return commitmentsHash The resulting sequential Poseidon hash
    function computeOutputsCommitmentsHash(Output[] calldata outputs) external pure returns (uint256 commitmentsHash) {
        commitmentsHash = 0;
        for (uint256 i = 0; i < outputs.length; ++i) {
            commitmentsHash = Poseidon2T4.hash2(commitmentsHash, outputs[i].commitment);
        }
    }
}
