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

import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {PrivacyBoost} from "src/PrivacyBoost.sol";
import {TokenRegistry} from "src/TokenRegistry.sol";
import {AuthRegistry} from "src/AuthRegistry.sol";

struct DeployConfig {
    address owner;
    address proxyAdmin;
    address verifier;
    uint32 batchSize;
    uint32 maxInputsPerTransfer;
    uint32 maxOutputsPerTransfer;
    uint32 maxFeeTokens;
    uint256 cancelDelay;
    uint256 forcedWithdrawalDelay;
    uint32 maxForcedInputs;
    uint64 maxEpochAuthStalenessBlocks;
    uint64 maxForcedWithdrawalAuthStalenessBlocks;
    uint16 withdrawFeeBps;
    address treasury;
    uint8 merkleDepth;
    uint8 authTreeDepth;
}

library PoolDeployer {
    function defaultConfig(address owner, address proxyAdmin, address verifier)
        internal
        pure
        returns (DeployConfig memory)
    {
        return DeployConfig({
            owner: owner,
            proxyAdmin: proxyAdmin,
            verifier: verifier,
            batchSize: 8,
            maxInputsPerTransfer: 1,
            maxOutputsPerTransfer: 1,
            maxFeeTokens: 4,
            cancelDelay: 256,
            forcedWithdrawalDelay: 256,
            maxForcedInputs: 4,
            maxEpochAuthStalenessBlocks: 300,
            maxForcedWithdrawalAuthStalenessBlocks: 64,
            withdrawFeeBps: 0,
            treasury: address(0),
            merkleDepth: 20,
            authTreeDepth: 20
        });
    }

    function deployTokenRegistry(address owner, address proxyAdmin) internal returns (TokenRegistry) {
        TokenRegistry impl = new TokenRegistry();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(TokenRegistry.initialize, (owner))
        );
        return TokenRegistry(address(proxy));
    }

    function deployAuthRegistry(address owner, address proxyAdmin, uint8 authTreeDepth)
        internal
        returns (AuthRegistry)
    {
        AuthRegistry impl = new AuthRegistry(authTreeDepth);
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl), proxyAdmin, abi.encodeCall(AuthRegistry.initialize, (owner))
        );
        return AuthRegistry(address(proxy));
    }

    function deployPool(DeployConfig memory cfg, address authRegistryAddr, address tokenRegistryAddr)
        internal
        returns (PrivacyBoost)
    {
        PrivacyBoost impl = new PrivacyBoost(
            tokenRegistryAddr,
            authRegistryAddr,
            cfg.batchSize,
            cfg.maxInputsPerTransfer,
            cfg.maxOutputsPerTransfer,
            cfg.maxFeeTokens,
            cfg.cancelDelay,
            cfg.forcedWithdrawalDelay,
            cfg.maxForcedInputs,
            cfg.maxEpochAuthStalenessBlocks,
            cfg.maxForcedWithdrawalAuthStalenessBlocks,
            cfg.merkleDepth
        );
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            cfg.proxyAdmin,
            abi.encodeCall(
                PrivacyBoost.initialize,
                (
                    cfg.owner,
                    cfg.verifier,
                    cfg.verifier,
                    cfg.verifier,
                    cfg.verifier,
                    cfg.verifier,
                    cfg.withdrawFeeBps,
                    cfg.treasury
                )
            )
        );
        return PrivacyBoost(address(proxy));
    }

    function deployFullStack(DeployConfig memory cfg)
        internal
        returns (PrivacyBoost pool, TokenRegistry tokenReg, AuthRegistry authReg)
    {
        tokenReg = deployTokenRegistry(cfg.owner, cfg.proxyAdmin);
        authReg = deployAuthRegistry(cfg.owner, cfg.proxyAdmin, cfg.authTreeDepth);
        pool = deployPool(cfg, address(authReg), address(tokenReg));
    }

    function deployWithMockAuth(DeployConfig memory cfg, address mockAuthAddr)
        internal
        returns (PrivacyBoost pool, TokenRegistry tokenReg)
    {
        tokenReg = deployTokenRegistry(cfg.owner, cfg.proxyAdmin);
        pool = deployPool(cfg, mockAuthAddr, address(tokenReg));
    }
}
