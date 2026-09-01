// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IMulticall3 {
    struct Call {
        address target;
        bytes callData;
    }

    // Selector-compatible with canonical Multicall3.aggregate. The server uses
    // this only through eth_call, so the generated Go binding exposes a typed
    // read method even though the deployed contract marks aggregate payable.
    /// @notice Execute a batch of read-only calls and return their raw results.
    /// @param calls The target and calldata for each call in the batch
    /// @return blockNumber The block the batch was evaluated against
    /// @return returnData The raw return data of each call, index-aligned with `calls`
    function aggregate(Call[] calldata calls) external view returns (uint256 blockNumber, bytes[] memory returnData);
}
