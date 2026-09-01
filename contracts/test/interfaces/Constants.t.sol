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
import {
    DOMAIN_ACCOUNTID,
    DOMAIN_NOTE,
    DOMAIN_NULLIFIER,
    DOMAIN_REG_LEAF,
    DOMAIN_REG_NODE,
    DOMAIN_APPROVE,
    DOMAIN_DEPOSIT_REQUEST,
    DOMAIN_MPK,
    DOMAIN_PORTAL_BIND,
    DOMAIN_PORTAL_NOTE,
    DOMAIN_PORTAL_REQUEST
} from "src/interfaces/Constants.sol";

/// @dev Domain separators are the first input to every Poseidon hash; a value
///      collision between two separators silently lets one hash context forge
///      another's preimage. These tests pin the three portal separators to their
///      allocated slots and prove they collide with no existing domain. They must
///      stay in lockstep with the Go side (frontend/constants.go) — the portal
///      circuit and contract hash the same fields and a divergence would make
///      on-chain H / portalDepositId unverifiable against the proof.
contract ConstantsTest is Test {
    function test_portalDomainsHaveExpectedValues() public pure {
        // Act / Assert - the portal separators occupy the next three free slots
        // after the existing max of 8; these exact values are what the circuit
        // and indexer hash with, so a change here is a protocol-breaking change.
        assertEq(DOMAIN_PORTAL_BIND, 9, "DOMAIN_PORTAL_BIND must be 9");
        assertEq(DOMAIN_PORTAL_NOTE, 10, "DOMAIN_PORTAL_NOTE must be 10");
        assertEq(DOMAIN_PORTAL_REQUEST, 11, "DOMAIN_PORTAL_REQUEST must be 11");
    }

    function test_portalDomainsDoNotCollideWithExisting() public pure {
        // Arrange - the full domain-separator namespace, existing + portal.
        uint256[11] memory domains = [
            DOMAIN_ACCOUNTID,
            DOMAIN_NOTE,
            DOMAIN_NULLIFIER,
            DOMAIN_REG_LEAF,
            DOMAIN_REG_NODE,
            DOMAIN_APPROVE,
            DOMAIN_DEPOSIT_REQUEST,
            DOMAIN_MPK,
            DOMAIN_PORTAL_BIND,
            DOMAIN_PORTAL_NOTE,
            DOMAIN_PORTAL_REQUEST
        ];

        // Act / Assert - every separator is pairwise distinct. This fails the
        // moment a portal value is changed to reuse an existing slot, which is the
        // exact hash-collision hazard the domain separation is meant to prevent.
        for (uint256 i = 0; i < domains.length; i++) {
            for (uint256 j = i + 1; j < domains.length; j++) {
                assertTrue(domains[i] != domains[j], "domain separators must be unique");
            }
        }
    }
}
