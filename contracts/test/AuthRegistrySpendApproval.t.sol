// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {AuthRegistry} from "src/AuthRegistry.sol";
import {Poseidon2T4} from "src/hash/Poseidon2T4.sol";
import {IAuthRegistry} from "src/interfaces/IAuthRegistry.sol";
import {
    DOMAIN_REG_NODE,
    MAX_SPEND_APPROVAL_BATCH,
    SNARK_SCALAR_FIELD,
    SPEND_APPROVAL_BATCH_DEPTH
} from "src/interfaces/Constants.sol";
import {LibAuthZeroHashes} from "src/lib/LibAuthZeroHashes.sol";

interface ISpendApprovalPoseidonHash {
    function hash(uint256 len, uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        external
        pure
        returns (uint256);
}

contract AuthRegistrySpendApprovalTest is Test {
    using stdJson for string;

    AuthRegistry internal registry;

    address internal proxyAdmin = address(0xAD);
    address internal owner = address(0xA11CE);

    function setUp() public {
        AuthRegistry impl = new AuthRegistry(20);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(AuthRegistry.initialize, (address(this)))
        );
        registry = AuthRegistry(address(proxy));
    }

    function test_spendApprovalBatchCapacity_is256AtDepthEight() public pure {
        assertEq(SPEND_APPROVAL_BATCH_DEPTH, 8);
        assertEq(MAX_SPEND_APPROVAL_BATCH, 256);
        assertEq(MAX_SPEND_APPROVAL_BATCH, uint256(1) << SPEND_APPROVAL_BATCH_DEPTH);
    }

    /// @dev Distinct Poseidon commitments sorted ascending (the canonical batch encoding).
    function _commitments(uint256 n) internal view returns (uint256[] memory commitments) {
        commitments = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            commitments[i] = registry.computeSpendApprovalCommitment(11, 22, 33 + i);
        }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && commitments[j] < commitments[j - 1]; --j) {
                (commitments[j - 1], commitments[j]) = (commitments[j], commitments[j - 1]);
            }
        }
    }

    function _batchId(uint256 accountId, uint256[] memory commitments) internal view returns (bytes32) {
        return registry.computeSpendApprovalBatchId(accountId, registry.computeSpendApprovalBatchRoot(commitments));
    }

    function _manualTwoLeafRoot(uint256 leftLeaf, uint256 rightLeaf) internal view returns (uint256 current) {
        uint256[21] memory zeros = LibAuthZeroHashes.get();
        ISpendApprovalPoseidonHash poseidon = ISpendApprovalPoseidonHash(registry.authPoseidon());
        current = poseidon.hash(3, DOMAIN_REG_NODE, leftLeaf, rightLeaf, 0, 0);
        for (uint256 level = 1; level < 20; ++level) {
            current = poseidon.hash(3, DOMAIN_REG_NODE, current, zeros[level], 0, 0);
        }
    }

    function _manualRootForPrefix(uint256[] memory leaves, uint256 count) internal view returns (uint256 current) {
        uint256[21] memory zeros = LibAuthZeroHashes.get();
        ISpendApprovalPoseidonHash poseidon = ISpendApprovalPoseidonHash(registry.authPoseidon());
        uint256[] memory level = new uint256[](16);
        for (uint256 i = 0; i < level.length; ++i) {
            level[i] = i < count ? leaves[i] : zeros[0];
        }
        uint256 width = level.length;
        for (uint256 treeLevel = 0; treeLevel < 4; ++treeLevel) {
            width /= 2;
            for (uint256 i = 0; i < width; ++i) {
                level[i] = poseidon.hash(3, DOMAIN_REG_NODE, level[2 * i], level[2 * i + 1], 0, 0);
            }
        }
        current = level[0];
        for (uint256 treeLevel = 4; treeLevel < 20; ++treeLevel) {
            current = poseidon.hash(3, DOMAIN_REG_NODE, current, zeros[treeLevel], 0, 0);
        }
    }

    function test_createAccount_approveSpend_revokeByRoot() public {
        uint256 accountId;
        vm.prank(owner);
        accountId = registry.createAccount(123);

        assertEq(registry.ownerOf(accountId), owner);
        assertTrue(registry.approvalOnly(accountId));

        uint256 commitment = registry.computeSpendApprovalCommitment(11, 22, 33);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);
        bytes32 batchId = registry.computeSpendApprovalBatchId(accountId, batchRoot);

        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.SpendApproved(accountId, batchId, batchRoot, expiry, 0, 0, commitments);
        vm.prank(owner);
        registry.approveSpend(accountId, commitment, expiry);

        (uint16 treeNum, uint32 index, bool revoked, bool exists, uint256 leaf) =
            registry.getSpendApprovalBatchInfo(batchId);
        assertEq(treeNum, 0);
        assertEq(index, 0);
        assertFalse(revoked);
        assertTrue(exists);
        assertTrue(leaf != 0);
        assertEq(registry.authTreeCount(0), 1);

        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.SpendApprovalRevoked(accountId, batchId, 0, 0);
        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, batchRoot);

        (,, revoked, exists, leaf) = registry.getSpendApprovalBatchInfo(batchId);
        assertTrue(revoked);
        assertTrue(exists);
        assertEq(leaf, 0);
    }

    function test_approveSpendBatch_insertsSingleLeaf() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory commitments = _commitments(3);
        uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);
        bytes32 batchId = registry.computeSpendApprovalBatchId(accountId, batchRoot);

        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.SpendApproved(accountId, batchId, batchRoot, expiry, 0, 0, commitments);
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, commitments);

        // One tree insertion for the whole batch.
        assertEq(registry.authTreeCount(0), 1);

        (uint16 treeNum, uint32 index, bool revoked, bool exists,) = registry.getSpendApprovalBatchInfo(batchId);
        assertEq(treeNum, 0);
        assertEq(index, 0);
        assertFalse(revoked);
        assertTrue(exists);
    }

    function test_computeSpendApprovalBatchRoot_matchesPaddedFullTree() public view {
        uint256[] memory commitments = _commitments(3);

        // Reference: canonical full tree over 256 zero-padded slots.
        uint256[] memory level = new uint256[](uint256(MAX_SPEND_APPROVAL_BATCH));
        for (uint256 i = 0; i < commitments.length; ++i) {
            level[i] = commitments[i];
        }
        uint256 width = level.length;
        for (uint256 d = 0; d < SPEND_APPROVAL_BATCH_DEPTH; ++d) {
            width /= 2;
            for (uint256 i = 0; i < width; ++i) {
                level[i] = Poseidon2T4.hash2(level[2 * i], level[2 * i + 1]);
            }
        }

        assertEq(registry.computeSpendApprovalBatchRoot(commitments), level[0]);
    }

    function test_computeSpendApprovalBatchRoot_matchesCrossLanguageVectors() public view {
        string memory fixture = vm.readFile("../testdata/crypto_vectors.json");
        uint256 vectorIndex;
        while (fixture.keyExists(
                string.concat(".spend_approval_batch_root[", vm.toString(vectorIndex), "].expected")
            )) {
            string memory base = string.concat(".spend_approval_batch_root[", vm.toString(vectorIndex), "]");
            string[] memory commitmentHex = fixture.readStringArray(string.concat(base, ".commitments"));
            uint256[] memory commitments = new uint256[](commitmentHex.length);
            for (uint256 i = 0; i < commitmentHex.length; ++i) {
                commitments[i] = vm.parseUint(commitmentHex[i]);
            }
            uint256 expected = vm.parseUint(fixture.readString(string.concat(base, ".expected")));
            assertEq(
                registry.computeSpendApprovalBatchRoot(commitments),
                expected,
                string.concat("batch-root vector mismatch at index ", vm.toString(vectorIndex))
            );
            ++vectorIndex;
        }
        assertGe(vectorIndex, 4, "expected N=1, N=3, N=17, and N=32 vectors");
    }

    function test_approveSpendBatch_acceptsMaxBatchSize() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        uint256[] memory commitments = _commitments(uint256(MAX_SPEND_APPROVAL_BATCH));
        vm.prank(owner);
        registry.approveSpendBatch(accountId, uint64(block.timestamp + 1 days), commitments);
        assertEq(registry.authTreeCount(0), 1);
    }

    function test_approveSpendBatch_rejectsEmptyAndOversizedBatch() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalBatchSize.selector);
        registry.approveSpendBatch(accountId, expiry, new uint256[](0));

        uint256[] memory oversized = _commitments(uint256(MAX_SPEND_APPROVAL_BATCH) + 1);
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalBatchSize.selector);
        registry.approveSpendBatch(accountId, expiry, oversized);
    }

    function test_approveSpendBatch_rejectsUnsortedPair() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        uint256[] memory commitments = _commitments(3);
        (commitments[0], commitments[1]) = (commitments[1], commitments[0]);
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.UnsortedApprovalCommitments.selector);
        registry.approveSpendBatch(accountId, uint64(block.timestamp + 1 days), commitments);
    }

    function test_approveSpendBatch_rejectsAdjacentDuplicate() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        uint256[] memory commitments = _commitments(3);
        commitments[2] = commitments[1];
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.UnsortedApprovalCommitments.selector);
        registry.approveSpendBatch(accountId, uint64(block.timestamp + 1 days), commitments);
    }

    function test_approveSpendBatch_rejectsZeroFirstAndOutOfFieldLast() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory zeroFirst = _commitments(2);
        zeroFirst[0] = 0;
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalCommitment.selector);
        registry.approveSpendBatch(accountId, expiry, zeroFirst);

        uint256[] memory outOfField = _commitments(2);
        outOfField[1] = SNARK_SCALAR_FIELD;
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalCommitment.selector);
        registry.approveSpendBatch(accountId, expiry, outOfField);
    }

    function test_approveSpendBatch_rejectsIdenticalBatchReinsert() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory commitments = _commitments(2);
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, commitments);

        // Load-bearing for revocation integrity: a byte-identical re-insert
        // would move the recorded leaf position and leave the first leaf
        // beyond a later revoke's reach. Also holds under a different expiry
        // (batchId deliberately omits it), forcing fresh blindings.
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.SpendApprovalAlreadyExists.selector);
        registry.approveSpendBatch(accountId, expiry, commitments);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.SpendApprovalAlreadyExists.selector);
        registry.approveSpendBatch(accountId, expiry + 1, commitments);
    }

    function test_approveSpendBatch_allowsCommitmentReuseAcrossBatches() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory first = _commitments(2);
        uint256[] memory overlapping = _commitments(3);

        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, first);

        // Cross-batch commitment reuse is insertable by design: privacy
        // hygiene is monitored off-chain, safety comes from nullifiers.
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, overlapping);

        (,,, bool exists,) = registry.getSpendApprovalBatchInfo(_batchId(accountId, overlapping));
        assertTrue(exists);
        assertEq(registry.authTreeCount(0), 2);
    }

    function test_approveSpendBatch_allowsForeignCommitmentCopy() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        address otherOwner = address(0xBEEF);
        vm.prank(otherOwner);
        uint256 otherAccountId = registry.createAccount(456);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory commitments = _commitments(1);
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, commitments);

        // Commitments are public; a copier's leaf binds the copier's account,
        // and without the blinding the slot is unconsumable junk.
        vm.prank(otherOwner);
        registry.approveSpendBatch(otherAccountId, expiry, commitments);

        (,,, bool exists,) = registry.getSpendApprovalBatchInfo(_batchId(otherAccountId, commitments));
        assertTrue(exists);
    }

    function test_approveSpendBatch_rejectsNonOwner() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        uint256[] memory commitments = _commitments(2);
        vm.prank(address(0xB0B));
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.approveSpendBatch(accountId, uint64(block.timestamp + 1 days), commitments);
    }

    function test_revokeSpendApprovalBatch_sizeOneAndSizeN() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory single = _commitments(1);
        uint256[] memory many = _commitments(uint256(MAX_SPEND_APPROVAL_BATCH));
        vm.prank(owner);
        registry.approveSpend(accountId, single[0], expiry);
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, many);
        uint256 singleRoot = registry.computeSpendApprovalBatchRoot(single);
        uint256 manyRoot = registry.computeSpendApprovalBatchRoot(many);
        uint256 singleLeaf = registry.computeApprovalLeaf(accountId, singleRoot, expiry);
        uint256 manyLeaf = registry.computeApprovalLeaf(accountId, manyRoot, expiry);
        assertEq(registry.authTreeRoot(0), _manualTwoLeafRoot(singleLeaf, manyLeaf));
        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, singleRoot);
        assertEq(registry.authTreeRoot(0), _manualTwoLeafRoot(0, manyLeaf));
        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, manyRoot);

        (,, bool revokedSingle,,) = registry.getSpendApprovalBatchInfo(_batchId(accountId, single));
        (,, bool revokedMany,,) = registry.getSpendApprovalBatchInfo(_batchId(accountId, many));
        assertEq(registry.authTreeRoot(0), LibAuthZeroHashes.get()[20]);
        assertTrue(revokedSingle);
        assertTrue(revokedMany);
    }

    function test_revokeSpendApprovalBatch_indexFourMatchesIndependentFullTreeModel() public {
        // Arrange
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256[] memory leaves = new uint256[](9);
        uint256 targetBatchRoot;
        for (uint256 i = 0; i < leaves.length; ++i) {
            uint256[] memory commitments = new uint256[](1);
            commitments[0] = registry.computeSpendApprovalCommitment(11, 22, 100 + i);
            uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);
            leaves[i] = registry.computeApprovalLeaf(accountId, batchRoot, expiry);
            vm.prank(owner);
            registry.approveSpendBatch(accountId, expiry, commitments);
            if (i == 4) {
                targetBatchRoot = batchRoot;
            }
        }
        assertEq(registry.authTreeRoot(0), _manualRootForPrefix(leaves, leaves.length));

        // Act
        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, targetBatchRoot);
        leaves[4] = 0;

        // Assert
        assertEq(registry.authTreeRoot(0), _manualRootForPrefix(leaves, leaves.length));
    }

    function test_revokeSpendApprovalBatch_rejectsNonOwnerUnknownAndRepeat() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        vm.prank(address(0xB0B));
        vm.expectRevert(IAuthRegistry.NotAuthorized.selector);
        registry.revokeSpendApprovalBatch(accountId, 42);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.SpendApprovalNotFound.selector);
        registry.revokeSpendApprovalBatch(accountId, 42);

        uint256[] memory commitments = _commitments(1);
        vm.prank(owner);
        registry.approveSpend(accountId, commitments[0], uint64(block.timestamp + 1 days));
        uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);

        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, batchRoot);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.SpendApprovalAlreadyRevoked.selector);
        registry.revokeSpendApprovalBatch(accountId, batchRoot);
    }

    function test_postRevocation_identicalSetBlocked_freshBlindingSucceeds() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256[] memory commitments = _commitments(2);
        uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, commitments);
        vm.prank(owner);
        registry.revokeSpendApprovalBatch(accountId, batchRoot);

        // Identical commitment set stays blocked forever by batchId.
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.SpendApprovalAlreadyExists.selector);
        registry.approveSpendBatch(accountId, expiry, commitments);

        // Fresh blindings change every commitment and pass.
        uint256[] memory fresh = new uint256[](2);
        fresh[0] = registry.computeSpendApprovalCommitment(11, 22, 1033);
        fresh[1] = registry.computeSpendApprovalCommitment(11, 22, 1034);
        if (fresh[0] > fresh[1]) {
            (fresh[0], fresh[1]) = (fresh[1], fresh[0]);
        }
        vm.prank(owner);
        registry.approveSpendBatch(accountId, expiry, fresh);
    }

    function test_approveSpend_wrapperMatchesSizeOneBatch() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        address otherOwner = address(0xBEEF);
        vm.prank(otherOwner);
        uint256 otherAccountId = registry.createAccount(456);
        uint64 expiry = uint64(block.timestamp + 1 days);

        uint256 commitment = registry.computeSpendApprovalCommitment(11, 22, 33);
        uint256[] memory commitments = new uint256[](1);
        commitments[0] = commitment;
        uint256 batchRoot = registry.computeSpendApprovalBatchRoot(commitments);

        // The wrapper and the explicit size-1 batch must produce the same
        // batch root and the same leaf shape; only the account differs.
        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.SpendApproved(
            accountId, registry.computeSpendApprovalBatchId(accountId, batchRoot), batchRoot, expiry, 0, 0, commitments
        );
        vm.prank(owner);
        registry.approveSpend(accountId, commitment, expiry);

        vm.expectEmit(true, true, false, true);
        emit IAuthRegistry.SpendApproved(
            otherAccountId,
            registry.computeSpendApprovalBatchId(otherAccountId, batchRoot),
            batchRoot,
            expiry,
            0,
            1,
            commitments
        );
        vm.prank(otherOwner);
        registry.approveSpendBatch(otherAccountId, expiry, commitments);
    }

    function test_approveSpend_rejectsInvalidCommitment() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint64 expiry = uint64(block.timestamp + 1 days);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalCommitment.selector);
        registry.approveSpend(accountId, 0, expiry);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalCommitment.selector);
        registry.approveSpend(accountId, SNARK_SCALAR_FIELD, expiry);
    }

    function test_approveSpend_rejectsExpiredAndTooLongExpiry() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);
        uint256 commitment = registry.computeSpendApprovalCommitment(11, 22, 33);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalExpiry.selector);
        registry.approveSpend(accountId, commitment, uint64(block.timestamp));

        uint64 tooLongExpiry = uint64(block.timestamp + registry.MAX_APPROVAL_LIFETIME() + 1);
        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.InvalidApprovalExpiry.selector);
        registry.approveSpend(accountId, commitment, tooLongExpiry);
    }

    function test_register_revertsForApprovalOnlyAccount() public {
        vm.prank(owner);
        registry.createAccount(123);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.ApprovalOnlyAccount.selector);
        registry.register(123, 1, 2, 0, owner, bytes(""));
    }

    function test_rotate_revertsForApprovalOnlyAccount() public {
        vm.prank(owner);
        uint256 accountId = registry.createAccount(123);

        vm.prank(owner);
        vm.expectRevert(IAuthRegistry.ApprovalOnlyAccount.selector);
        registry.rotate(accountId, 1, 2, 3, 0, bytes(""));
    }
}
