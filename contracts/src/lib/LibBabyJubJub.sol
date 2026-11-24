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
pragma solidity ^0.8.34;

/// @title LibBabyJubJub
/// @notice BabyJubJub twisted Edwards curve validation (gnark BN254 parameterization)
/// @dev Curve equation: a*x^2 + y^2 = 1 + d*x^2*y^2 where a = -1
library LibBabyJubJub {
    uint256 internal constant PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant D = 12181644023421730124874158521699555681764249180949974110617291017600649128846;

    /// @notice Check if (x, y) is a valid BabyJubJub public key for EdDSA usage
    /// @dev The EdDSA verifier clears cofactors by computing A8 = 8*A. If A is a low-order torsion point,
    ///      then A8 is the identity (0,1) and the signature equation loses message binding.
    ///      We reject such keys by enforcing that 8*(x,y) != (0,1).
    function isValidPublicKey(uint256 x, uint256 y) internal pure returns (bool) {
        return _isOnCurve(x, y) && !_clearsToIdentity(x, y);
    }

    /// @notice Check if (x, y) lies on the BabyJubJub curve
    /// @param x The X coordinate
    /// @param y The Y coordinate
    /// @return True if the point satisfies the curve equation
    function _isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x >= PRIME || y >= PRIME) return false;

        uint256 x2 = mulmod(x, x, PRIME);
        uint256 y2 = mulmod(y, y, PRIME);

        // -x^2 + y^2 = 1 + d*x^2*y^2
        uint256 negX2 = x2 == 0 ? 0 : PRIME - x2;
        uint256 lhs = addmod(negX2, y2, PRIME);
        uint256 rhs = addmod(1, mulmod(D, mulmod(x2, y2, PRIME), PRIME), PRIME);

        return lhs == rhs;
    }

    /// @dev Returns true iff 8*(x,y) equals the Edwards identity (0,1).
    function _clearsToIdentity(uint256 x, uint256 y) private pure returns (bool) {
        // Projective coords (X:Y:Z) with affine (x,y) = (X/Z, Y/Z). Start with Z=1.
        uint256 X = x;
        uint256 Y = y;
        uint256 Z = 1;

        // Compute 8*P via 3 doublings.
        (X, Y, Z) = _doubleProjective(X, Y, Z);
        (X, Y, Z) = _doubleProjective(X, Y, Z);
        (X, Y, Z) = _doubleProjective(X, Y, Z);

        // In projective form, identity (0,1) is represented by X == 0 and Y == Z (with Z != 0).
        return X == 0 && Y == Z;
    }

    /// @dev Point doubling on a=-1 twisted Edwards curve in projective coordinates.
    ///      Reference: EFD twisted Edwards projective doubling ("dbl-2008-bbjlp"):
    ///      https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html
    ///      Uses the standard 3M + 4S + 1*a formula specialized to a = -1 with only mulmod/addmod.
    function _doubleProjective(uint256 X1, uint256 Y1, uint256 Z1)
        private
        pure
        returns (uint256 X3, uint256 Y3, uint256 Z3)
    {
        // A = X1^2
        uint256 A_ = mulmod(X1, X1, PRIME);
        // B = Y1^2
        uint256 B_ = mulmod(Y1, Y1, PRIME);
        // C = 2*Z1^2
        uint256 Z2 = mulmod(Z1, Z1, PRIME);
        uint256 C_ = addmod(Z2, Z2, PRIME);
        // D = a*A where a=-1 => D = -A
        uint256 D_ = PRIME - A_;
        // E = (X1+Y1)^2 - A - B
        uint256 E_ = addmod(X1, Y1, PRIME);
        E_ = mulmod(E_, E_, PRIME);
        E_ = addmod(E_, PRIME - A_, PRIME);
        E_ = addmod(E_, PRIME - B_, PRIME);
        // G = D + B
        uint256 G_ = addmod(D_, B_, PRIME);
        // F = G - C
        uint256 F_ = addmod(G_, PRIME - C_, PRIME);
        // H = D - B
        uint256 H_ = addmod(D_, PRIME - B_, PRIME);

        // X3 = E*F
        X3 = mulmod(E_, F_, PRIME);
        // Y3 = G*H
        Y3 = mulmod(G_, H_, PRIME);
        // Z3 = F*G
        Z3 = mulmod(F_, G_, PRIME);
    }
}
