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

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {TreeRootPair} from "src/interfaces/IStructs.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock", "MOCK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockFeeOnTransferToken is ERC20 {
    uint256 public constant FEE_PERCENT = 1; // 1% fee

    constructor() ERC20("FeeToken", "FEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        uint256 fee = amount * FEE_PERCENT / 100;
        uint256 netAmount = amount - fee;
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, netAmount);
        _burn(from, fee);
        return true;
    }
}

/// @dev Test base making a mock contract a registrable portal `E`: it stores the owner binding H that the
///      pool reads back via portalBinding() at sweep time — the account-side binding (PortalDelegate's
///      EIP-7201 storage) that replaced the pool's portalH registry. initializePortal stands in for
///      PortalDelegate.initializePortal; these mocks are plain deployed contracts used directly as E, so the
///      real delegate's self-call gate and range/write-once guards are intentionally omitted (those run
///      against the real delegate in Portal.t.sol / PortalDelegate.t.sol). A mock that never calls
///      initializePortal reports portalBinding() == 0, the unregistered sentinel the sweep path rejects.
abstract contract BindablePortal {
    uint256 private _binding;

    function initializePortal(uint256 H) external {
        _binding = H;
    }

    function portalBinding() external view returns (uint256) {
        return _binding;
    }
}

contract MockVerifier {
    function verifyEpoch(uint32, uint32, uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyPortalDeposit(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyWithdraw(uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyForcedWithdraw(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function verifyGiftClaim(uint32, uint256[8] calldata, uint256[] calldata) external pure returns (bool) {
        return true;
    }

    function hasVerifyingKey(uint32) external pure returns (bool) {
        return true;
    }
}

contract MockAuthRegistry {
    function registryRoot() external pure returns (uint256) {
        return 1;
    }

    function currentAuthTreeNumber() external pure returns (uint256) {
        return 0;
    }

    function authTreeRoot(uint256) external pure returns (uint256) {
        return 1;
    }

    function getAllAuthTreeRoots() external pure returns (uint256[] memory roots) {
        roots = new uint256[](1);
        roots[0] = 1;
    }

    function isCurrentAuthTreeRoot(uint256 treeNum, uint256 root) public pure returns (bool) {
        return treeNum == 0 && root == 1;
    }

    function isCurrentAuthLeafAt(uint64, uint256 authLeaf) external pure returns (bool) {
        return authLeaf != 0;
    }

    function isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64) external pure returns (bool) {
        return isCurrentAuthTreeRoot(treeNum, root);
    }

    function areRecentAuthTreeRoots(TreeRootPair[] calldata roots, uint64) external pure returns (bool) {
        for (uint256 i = 0; i < roots.length; ++i) {
            if (!isCurrentAuthTreeRoot(roots[i].treeNumber, roots[i].root)) {
                return false;
            }
        }
        return true;
    }
}

contract MockAuthRegistryMultiTree {
    uint256 private _treeCount;
    mapping(uint256 => uint256) private _roots;

    constructor() {
        _treeCount = 0;
        _roots[0] = 1;
    }

    function registryRoot() external pure returns (uint256) {
        return 1;
    }

    function currentAuthTreeNumber() external view returns (uint256) {
        return _treeCount;
    }

    function authTreeRoot(uint256 treeNum) external view returns (uint256) {
        return _roots[treeNum];
    }

    function getAllAuthTreeRoots() external view returns (uint256[] memory roots) {
        roots = new uint256[](_treeCount + 1);
        for (uint256 i = 0; i <= _treeCount; i++) {
            roots[i] = _roots[i];
        }
    }

    function isCurrentAuthTreeRoot(uint256 treeNum, uint256 root) public view returns (bool) {
        return root != 0 && treeNum <= _treeCount && _roots[treeNum] == root;
    }

    function isCurrentAuthLeafAt(uint64, uint256 authLeaf) external pure returns (bool) {
        return authLeaf != 0;
    }

    function isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64) external view returns (bool) {
        return isCurrentAuthTreeRoot(treeNum, root);
    }

    function areRecentAuthTreeRoots(TreeRootPair[] calldata roots, uint64) external view returns (bool) {
        for (uint256 i = 0; i < roots.length; ++i) {
            if (!isCurrentAuthTreeRoot(roots[i].treeNumber, roots[i].root)) {
                return false;
            }
        }
        return true;
    }

    function addAuthTree(uint256 root) external {
        _treeCount++;
        _roots[_treeCount] = root;
    }

    function setAuthTreeRoot(uint256 treeNum, uint256 root) external {
        _roots[treeNum] = root;
    }
}

contract MockRecentAuthRegistry {
    uint256 private _currentRoot = 1;
    uint256 private _recentRoot;
    uint64 private _recentSupersededBlock;

    function registryRoot() external view returns (uint256) {
        return _currentRoot;
    }

    function currentAuthTreeNumber() external pure returns (uint256) {
        return 0;
    }

    function authTreeRoot(uint256) external view returns (uint256) {
        return _currentRoot;
    }

    function getAllAuthTreeRoots() external view returns (uint256[] memory roots) {
        roots = new uint256[](1);
        roots[0] = _currentRoot;
    }

    function setCurrentRoot(uint256 root) external {
        _currentRoot = root;
    }

    function setRecentRoot(uint256 root, uint64 supersededBlock) external {
        _recentRoot = root;
        _recentSupersededBlock = supersededBlock;
    }

    function isCurrentAuthTreeRoot(uint256 treeNum, uint256 root) public view returns (bool) {
        return root != 0 && treeNum == 0 && root == _currentRoot;
    }

    function isCurrentAuthLeafAt(uint64, uint256 authLeaf) external pure returns (bool) {
        return authLeaf != 0;
    }

    function isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64 maxStalenessBlocks)
        external
        view
        returns (bool)
    {
        return _isRecentAuthTreeRoot(treeNum, root, maxStalenessBlocks);
    }

    function areRecentAuthTreeRoots(TreeRootPair[] calldata roots, uint64 maxStalenessBlocks)
        external
        view
        returns (bool)
    {
        for (uint256 i = 0; i < roots.length; ++i) {
            if (!_isRecentAuthTreeRoot(roots[i].treeNumber, roots[i].root, maxStalenessBlocks)) {
                return false;
            }
        }
        return true;
    }

    function _isRecentAuthTreeRoot(uint256 treeNum, uint256 root, uint64 maxStalenessBlocks)
        internal
        view
        returns (bool)
    {
        if (isCurrentAuthTreeRoot(treeNum, root)) return true;
        if (treeNum != 0 || root == 0 || root != _recentRoot || maxStalenessBlocks == 0) return false;
        return block.number >= _recentSupersededBlock && block.number - _recentSupersededBlock <= maxStalenessBlocks;
    }
}
