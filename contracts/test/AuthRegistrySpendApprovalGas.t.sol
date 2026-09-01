// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.34;

import {Test, console2} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {AuthRegistry} from "src/AuthRegistry.sol";

/// @notice Steady-state gas measurements for batched spend approvals through
///         the proxy at the production tree depth. Logged, not asserted
///         beyond loose upper bounds, so design docs can be re-measured after
///         any Poseidon or registry change.
contract AuthRegistrySpendApprovalGasTest is Test {
    AuthRegistry internal registry;
    address internal implementation;
    address internal authPoseidon;
    uint256 internal accountId;
    uint64 internal expiry;

    address internal proxyAdmin = address(0xAD);
    address internal owner = address(0xA11CE);

    function setUp() public {
        AuthRegistry impl = new AuthRegistry(20);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(AuthRegistry.initialize, (address(this)))
        );
        registry = AuthRegistry(address(proxy));
        implementation = address(impl);
        authPoseidon = impl.authPoseidon();

        vm.prank(owner);
        accountId = registry.createAccount(123);
        expiry = uint64(block.timestamp + 1 days);

        // Each test starts from a committed non-empty tree, so the measured
        // SSTORE costs match a later standalone transaction.
        uint256 warmupCommitment = registry.computeSpendApprovalCommitment(999, 22, 33);
        vm.prank(owner);
        registry.approveSpend(accountId, warmupCommitment, expiry);
    }

    function _commitments(uint256 n, uint256 salt) internal view returns (uint256[] memory commitments) {
        commitments = new uint256[](n);
        for (uint256 i = 0; i < n; ++i) {
            commitments[i] = registry.computeSpendApprovalCommitment(salt, 22, 33 + i);
        }
        for (uint256 i = 1; i < n; ++i) {
            for (uint256 j = i; j > 0 && commitments[j] < commitments[j - 1]; --j) {
                (commitments[j - 1], commitments[j]) = (commitments[j], commitments[j - 1]);
            }
        }
    }

    function _measureApproveSpendBatch(uint256 size, uint256 salt) internal returns (uint256 gasUsed) {
        uint256[] memory commitments = _commitments(size, salt);

        // A transaction starts with its destination warm, while the first
        // DELEGATECALL and STATICCALL targets remain cold. Storage slots on
        // the proxy are cold even though the proxy address is warm.
        vm.cool(address(registry));
        vm.cool(implementation);
        vm.cool(authPoseidon);
        assertGt(address(registry).code.length, 0);

        vm.prank(owner);
        uint256 gasBefore = gasleft();
        registry.approveSpendBatch(accountId, expiry, commitments);
        gasUsed = gasBefore - gasleft();
        console2.log("approveSpendBatch N, gas:", size, gasUsed);
        assertLt(gasUsed, 10_000_000);
    }

    function test_gas_approveSpendBatch_sizeOne() public {
        _measureApproveSpendBatch(1, 1000);
    }

    function test_gas_approveSpendBatch_sizeEight() public {
        _measureApproveSpendBatch(8, 1001);
    }

    function test_gas_approveSpendBatch_sizeTwenty() public {
        _measureApproveSpendBatch(20, 1002);
    }

    function test_gas_approveSpendBatch_sizeThirtyTwo() public {
        _measureApproveSpendBatch(32, 1003);
    }

    function test_gas_approveSpendBatch_sizeTwoHundredFiftySix() public {
        _measureApproveSpendBatch(256, 1004);
    }
}
