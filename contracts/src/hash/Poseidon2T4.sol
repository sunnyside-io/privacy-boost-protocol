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

/// @title Poseidon2T4 (BN254 scalar field)
/// @notice Poseidon2 permutation with t=4, d=5, rounds_f=8, rounds_p=56
/// @dev Parameters match Barretenberg / bb.js `poseidon2Hash` used by Noir stdlib.
/// @custom:security-contact contact@sunnyside.io
library Poseidon2T4 {
    error InvalidHashLength();

    // BN254 scalar field prime
    uint256 internal constant PRIME = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 internal constant TWO_POW_64 = 0x1_0000_0000_0000_0000;

    // Internal matrix diagonal (Params::internal_matrix_diagonal)
    uint256 internal constant D0 = 0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7;
    uint256 internal constant D1 = 0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b;
    uint256 internal constant D2 = 0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15;
    uint256 internal constant D3 = 0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b;

    // Round constants packed as bytes (93 x 32-byte words).
    // Layout:
    // - 16 words for full rounds 0..3 (4 state elements each round)
    // - 56 words for partial rounds 4..59 (s0 constant only)
    // - 16 words for full rounds 60..63 (4 state elements each round)
    // - 5 words: PRIME, D0, D1, D2, D3 (must equal the named constants above)
    // The trailing PRIME/D words exist so _permute can keep these values on the stack:
    // referencing 32-byte literals inside the round loops makes solc's constant optimizer
    // materialize them via CODECOPY on every use at low optimizer-runs, which would
    // otherwise dominate the hash cost.
    // bytes constants ARE supported by solc; arrays are not.
    bytes internal constant RC_BYTES =
        hex"19b849f69450b06848da1d39bd5e4a4302bb86744edc26238b0878e269ed23e5265ddfe127dd51bd7239347b758f0a1320eb2cc7450acc1dad47f80c8dcf34d6199750ec472f1809e0f66a545e1e51624108ac845015c2aa3dfc36bab497d8aa157ff3fe65ac7208110f06a5f74302b14d743ea25067f0ffd032f787c7f1cdf82e49c43c4569dd9c5fd35ac45fca33f10b15c590692f8beefe18f4896ac949020e35fb89981890520d4aef2b6d6506c3cb2f0b6973c24fa82731345ffa2d1f1e251ad47cb15c4f1105f109ae5e944f1ba9d9e7806d667ffec6fe723002e0b99613da07dc64d428369873e97160234641f8beb56fdd05e5f3563fa39d9c22df4e0c009b84e650e6d23dc00c7dccef7483a553939689d350cd46e7b89055fd4738011f16b1c63a854f01992e3956f42d8b04eb650c6d535eb0203dec74befdca060ed69e5e383a688f209d9a561daa79612f3f78d0467ad45485df07093f36754904dba94a7b0ce9e221acad41472b6bbe3aec507f5eb3d33f463672264c9f789b0a3f2637d840f3a16eb094271c9d237b6036757d4bb50bf7ce732ff1d4fa28e8259a666f129eea198f8a1c502fdb38fa39b1f075569564b6e54a485d1182323f28bf7459c9b2f4c6d8e7d06a4ee3a47f7745d4271038e5157a32fdf7ede0d6a10a1ca941f057037526ea200f489be8d4c37c85bbcce6a2aeec91bd69414324470c6f8f958be0e93053d7fd4fc54512855535ed1539f051dcb43a26fd926361cf123106a93cd17578d426e8128ac9d90aa9e8a00708e296e084dd57e69caaf81126e1ba52ad9285d97dd3ab52f8e840085e8fa83ff1e8f1877b074867cd2dee751cb55cad7bd133de18a64c5c47b9c97cbe4d8b7bf9e095864471537e6a4ae2c51dcd73e46acd8f8e0e2c7ce04bde7f6d2a53043d5060a41c7143f08e6e9055d0011003e32f6d9c66f5852f05474a4def0cda294a0eb4e9b9b12b9bb4512e55742b1e809ac1d10ab29ad5f20d03a57dfebadfe5903f58bafed7c508dd2287ae8c2539de1785b735999fb4dac35ee17ed0ef995d05ab2fc5faeaa69ae87bcec0a50c246c5a2ef8ee0126497f222b3e0a0ef4e1c3d41c86d46e43982cb11d77951d192089c4974f68e95408148f7c0632edbb09e6a6ad1a1c2f3f0305f5d03b527b1eae0ad8ab68b2f06a0ee36eeb0d0c058529097d91096b756d8fdc2fb5a60d85179190e5d0e22179e46f8282872abc88db6e2fdc0dee99e69768bd98c5d06bfb29bb9e2c9076732576e9a81c7ac4b83214528f7db00f31bf6cafe794a9b3cd1c225d394e42207599403efd0c2464a90d52652645882aac35b10e590e6e691e08064760623c25c8cf753d238055b444532be13557451c087de09efd454b23fd5910ba3a0e01df92e87f301c4b716d8a394d67f4bf42a75c10922910a78f6b5b870e070bf53f8451b24f9c6e96b0c2a801cb511bc0c242eb9d361b77693f21471c1b94cd61b051b04dd39755ff93821a73ccd6cb11d2491d8aa7f921014de252fb1d7cb39bafb8c744e148787a2e70230f9d4e917d5713bb050487b5aa7d74070b2ec93189bd1ab4f69117d0fe980c80ff8785c2961829f701bb74ac1f303b17db2db366bfdd36d277a692bb825b86275beac404a19ae07a9082ea46bd83517926062100eb485db06269655cf186a68532985275428450359adc99cec6960711b80761d33c66614aaa570e7f1e8244ca1120243f92fa59e4f900c567bf41f5a59b20fc411a114d13992c2705aa034e3f315d78608a0f7de4ccf7a72e494855ad0d25b5c004a4bdfcb5add9ec4e9ab219ba102c67e8b3effb5fc3a30f317250bc5a23b1822d278ed632a494e58f6df6f5ed038b186d8474155ad87e7dff62b37f4b22734b4c5c3f9493606c4ba9012499bf0f14d13bfcfcccaa16102a29cc2f69e026c0c8fe09eb30b7e27a74dc33492347e5bdff409aa3610254413d3fad795ce5070dd0ccb6bd7bbae88eac03fa1fbb26196be3083a809829bbd626df348ccad912b6595bdb329b6fb043ba78bb28c3bec2c0a6de46d8c5ad6067c4ebfd4250da248d97d7f76283d63bec30e7a5876c11c06fca9b275c671c5e33d95bb7e8d7291a306d439d463b0816fc6fd64cc939318b45eb759ddde4aa106d15d9bd9baaaa28a8f8372e3c38daced7c00421cb4621f4f1b54ddc27821b0d62d3d6ec7c56cf0094975717f9a8a8bb35152f24d43294071ce320c829f388bc852183e1e2ce7e04d5ee4c3aa78f7d80fde60d716480d3593f74d4f653ae83f4103246db2e8d652a6cf5e9aa03d4336349ad6fb8ed2269c7bef54b8822cc76d08495c12efde1872304d31eaab960ba9274da43e19ddeb7f792180808fd6e43baae48d7efcba3f303fd9ac865a4b2a6d5e7009785817249bff08a7e0726fcb4e1c11d39d199f0b000b7258ded52bbda2248404d55ee5044798afc3a209193073f7954d4d63b0b64159f81ada0771799ec38fca2d4bf65ebb13d3a74f3298db36272c5ca65e92d9a1ef90e67437fbc8550237a75bc28e3bb9000130ea25f0c5471e144cf4264431f1e65f838515e5ff0196b49aa41a2d2568df739bc176b08ec95a79ed82932e30d2b1b045def3a166cec6ce768d079ba74b18c844e570e1f826575c1068c94c33f0832e5753ceb0ff6402543b1109229c165dc2d73bef715e3f1c6e07c168bb17302f614e9cedfb3dc6b762ae0a37d41bab1b841c2e8b6451bc5a8e3c390b6ad160e2427d38bd46a60dd640b8e362cad967370ebb777bedff40f6a0be27e7ed7050493630b7c670b6deb7c84d414e7ce79049f0ec098c3c7c50768bbe29214a53a22ead100e8e482674decdab17066c5a26bb1515355d5461a3dc06cc85327cea925b3e56e655b42cdaae2626ed2554d48583f1ae35626d04de5084e0b6d2a6f161e32752ada8836ef5837a6cde8ff13dbb599c336349e4c584b4fdc0a0cf6f9d02fa2a871c15a387cc50f68f6f3c3455b23c00995f05078f672a9864074d412e52f569b8a9a4424c9278e1db7311e889f54ccbf10661bab7fcd18e7c7a7d83505044cb455110a8fdd531ade530234c518a7df93f7332ffd2144165374b246b43d227808de93906d5d420246157f2e42b191fe8c90adfe118178ddc723a531902502fcca2934e046bc623adead873579865d03781ae090ad4a8579d2e7a68003550ef915f0ac120b876abccceb344a1d36bad3f3c5ab91a8ddcbec2e060d8befac1797130f4b7a3e1777eb757bc6f287f6ab0fb85f6be63b09f3b16ef2b1405d380a76225dc04170ae3306c85abab59e608c7f497c20156d4d36c668555decc6e51fffb9ec1992d66ba1e77a7b93209af6f8fa76d48acb664796174b5326a31a5c25721c4fc15a3f2853b57c338fa538d85f8fbba6c6b9c6090611889b797b9c5f0c817fd42d5f7a41215e3d07ba197216adb4c3790705da95eb63b982bfcaf75a13abe3f5239915d39f7e13c2c24970b6df8cf86ce00a22002bc15866e52b5a962106feea546224ea12ef7f39987a46c85c1bc3dc29bdbd7a92cd60acb4d391ce21ca859468a746b6aaa79474a37dab49f1ca5a28c748bc7157e1b3345bb0f95905ccd6255c1e6f0c5cf1f0df934194c62911d14d0321662a8f1a48999e34185b0f0e34a64b70a626e464d846674c4c8816c4fb267fe44fe6ea28678cb09490a40558531a4e25470c6157794ca36d0e9647dbfcfe350d64838f5b1a8a2de0d4bf09d3dca9173ed2faceea125157683d18924cadad3f655a60b72f5864961f14550328cbd54e8c0913493f866ed03d218bf23f92d68aaec48617d4c722e5bd43352bf07216e2aff0a223a487b1a7094e07e79e7bcc9798c648ee3347dd5329d34b1daf345a58006b736499c583cb76c316d6f78ed6a6dffc82111e11a63fe412df176563472456aaa746b694c60e1823611ef39039b2edc7ff391e6f2293d2c40430644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000110dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e70c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b";

    function loadRoundConstants() internal pure returns (bytes memory rc) {
        rc = RC_BYTES;
    }

    /// @dev Poseidon2 permutation as a single assembly block over caller-owned round constants.
    ///      Round structure, constants, and modular-arithmetic order are identical to the
    ///      Poseidon2 reference (initial external layer, 4 full rounds, 56 partial rounds,
    ///      4 full rounds); only the codegen is hand-tuned. The caller keeps `rc` alive and
    ///      may reuse it across multiple permutations.
    ///
    ///      Build requirements (unlike the previous loop-based Solidity version, which
    ///      compiled on the legacy pipeline):
    ///      - Requires via_ir = true (as set in foundry.toml). Legacy codegen cannot lay
    ///        out this function's stack and fails with stack-too-deep.
    ///      - Every inline-assembly block in a contract that inlines this library must be
    ///        annotated ("memory-safe"). One unannotated block disables the memoryguard
    ///        for that compilation unit, so via-ir cannot spill to memory and compilation
    ///        fails with stack-too-deep.
    function _permuteWithConstants(bytes memory rc, uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        internal
        pure
        returns (uint256, uint256, uint256, uint256)
    {
        assembly ("memory-safe") {
            // External linear layer (M_E), inlined at each use: (t3+t5, t5, t2+t4, t4) with
            // t0=s0+s1, t1=s2+s3, t2=2*s1+t1, t3=2*s3+t0, t4=4*t1+t3, t5=4*t0+t2
            function extl(a0, a1, a2, a3, p_) -> r0, r1, r2, r3 {
                let t0 := addmod(a0, a1, p_)
                let t1 := addmod(a2, a3, p_)
                let t2 := addmod(addmod(a1, a1, p_), t1, p_)
                let t3 := addmod(addmod(a3, a3, p_), t0, p_)
                let t4 := addmod(addmod(addmod(t1, t1, p_), addmod(t1, t1, p_), p_), t3, p_)
                let t5 := addmod(addmod(addmod(t0, t0, p_), addmod(t0, t0, p_), p_), t2, p_)
                r0 := addmod(t3, t5, p_)
                r1 := t5
                r2 := addmod(t2, t4, p_)
                r3 := t4
            }
            // Full round: add per-lane round constants at `o`, s-box all lanes (x^5),
            // then external layer
            function fullRound(a0, a1, a2, a3, o, p_) -> r0, r1, r2, r3 {
                {
                    let x := addmod(a0, mload(o), p_)
                    let x2 := mulmod(x, x, p_)
                    a0 := mulmod(mulmod(x2, x2, p_), x, p_)
                }
                {
                    let x := addmod(a1, mload(add(o, 0x20)), p_)
                    let x2 := mulmod(x, x, p_)
                    a1 := mulmod(mulmod(x2, x2, p_), x, p_)
                }
                {
                    let x := addmod(a2, mload(add(o, 0x40)), p_)
                    let x2 := mulmod(x, x, p_)
                    a2 := mulmod(mulmod(x2, x2, p_), x, p_)
                }
                {
                    let x := addmod(a3, mload(add(o, 0x60)), p_)
                    let x2 := mulmod(x, x, p_)
                    a3 := mulmod(mulmod(x2, x2, p_), x, p_)
                }
                r0, r1, r2, r3 := extl(a0, a1, a2, a3, p_)
            }

            let ptr := add(rc, 0x20)

            // Keep PRIME on the stack for the round loops (loaded from the RC_BYTES tail):
            // referencing the 32-byte literal at each use would make solc's constant
            // optimizer materialize it via CODECOPY per use at low optimizer-runs.
            let p := mload(add(ptr, 0xb00))

            // initial external linear layer
            s0, s1, s2, s3 := extl(s0, s1, s2, s3, p)

            // full rounds 0..3 (RC words 0..15, 4 words per round)
            for { let end := add(ptr, 0x200) } lt(ptr, end) { ptr := add(ptr, 0x80) } {
                s0, s1, s2, s3 := fullRound(s0, s1, s2, s3, ptr, p)
            }

            // partial rounds 4..59 (RC words 16..71, s0 constant only):
            // s-box on lane 0, then internal layer (M_I): s_i = s_i * D_i + sum(s)
            {
                // D0..D3 live at blob words 89..92. Load them from the scratch
                // blob inside the loop instead of reserving four stack slots, so
                // callers compile even when another assembly block disables the
                // via-IR memoryguard for their compilation unit.
                for { let end := add(ptr, 0x700) } lt(ptr, end) { ptr := add(ptr, 0x20) } {
                    let x := addmod(s0, mload(ptr), p)
                    let x2 := mulmod(x, x, p)
                    x := mulmod(mulmod(x2, x2, p), x, p)
                    let sum := addmod(addmod(x, s1, p), addmod(s2, s3, p), p)
                    s0 := addmod(mulmod(x, mload(add(rc, 0xb40)), p), sum, p)
                    s1 := addmod(mulmod(s1, mload(add(rc, 0xb60)), p), sum, p)
                    s2 := addmod(mulmod(s2, mload(add(rc, 0xb80)), p), sum, p)
                    s3 := addmod(mulmod(s3, mload(add(rc, 0xba0)), p), sum, p)
                }
            }

            // full rounds 60..63 (RC words 72..87)
            for { let end := add(ptr, 0x200) } lt(ptr, end) { ptr := add(ptr, 0x80) } {
                s0, s1, s2, s3 := fullRound(s0, s1, s2, s3, ptr, p)
            }
        }

        return (s0, s1, s2, s3);
    }

    function _permute(uint256 s0, uint256 s1, uint256 s2, uint256 s3)
        private
        pure
        returns (uint256, uint256, uint256, uint256)
    {
        bytes memory rc = loadRoundConstants();
        (s0, s1, s2, s3) = _permuteWithConstants(rc, s0, s1, s2, s3);

        assembly ("memory-safe") {
            mstore(0x40, rc)
        }

        return (s0, s1, s2, s3);
    }

    /// @notice Poseidon2 permutation for t=4.
    /// @dev Kept for compatibility (used internally by sponge; no known external call sites).
    function permutation(uint256[4] memory input) internal pure returns (uint256[4] memory out) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _permute(input[0], input[1], input[2], input[3]);
        out[0] = s0;
        out[1] = s1;
        out[2] = s2;
        out[3] = s3;
    }

    // === Sponge hashing (fixed-length) ===
    function _spongeInit(uint256 len) private pure returns (uint256 s0, uint256 s1, uint256 s2, uint256 s3) {
        s0 = 0;
        s1 = 0;
        s2 = 0;
        s3 = mulmod(len, TWO_POW_64, PRIME);
    }

    /// @notice Hash two to five field elements through one shared code path.
    /// @dev Reverts when the length is outside two through five. This form is useful for shared
    ///      external helpers: compiling one entry point avoids embedding a permutation per arity.
    function hashUpTo5(uint256 len, uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4)
        internal
        pure
        returns (uint256)
    {
        bytes memory rc = loadRoundConstants();
        uint256 result = hashUpTo5WithConstants(rc, len, a0, a1, a2, a3, a4);

        assembly ("memory-safe") {
            mstore(0x40, rc)
        }

        return result;
    }

    /// @dev Shared arity gate. Reverts when the length is outside two through five, which also
    ///      rejects every field-modular alias of a valid length. Callers that reuse one `rc`
    ///      allocation across a fold loop reach the sponge through here rather than `hashUpTo5`.
    function hashUpTo5WithConstants(
        bytes memory rc,
        uint256 len,
        uint256 a0,
        uint256 a1,
        uint256 a2,
        uint256 a3,
        uint256 a4
    ) internal pure returns (uint256) {
        if (len < 2 || len > 5) revert InvalidHashLength();

        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(len);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        if (len >= 3) s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permuteWithConstants(rc, s0, s1, s2, s3);
        if (len <= 3) return s0;

        s0 = addmod(s0, a3, PRIME);
        if (len == 5) s1 = addmod(s1, a4, PRIME);
        (s0,,,) = _permuteWithConstants(rc, s0, s1, s2, s3);
        return s0;
    }

    function hash1(uint256 a0) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(1);
        s0 = addmod(s0, a0, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash2(uint256 a0, uint256 a1) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(2);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash3(uint256 a0, uint256 a1, uint256 a2) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(3);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash4(uint256 a0, uint256 a1, uint256 a2, uint256 a3) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(4);
        // duplex 1: a0,a1,a2
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        // duplex 2: a3,0,0
        s0 = addmod(s0, a3, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash5(uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(5);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a3, PRIME);
        s1 = addmod(s1, a4, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash6(uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4, uint256 a5)
        internal
        pure
        returns (uint256)
    {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(6);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a3, PRIME);
        s1 = addmod(s1, a4, PRIME);
        s2 = addmod(s2, a5, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash7(uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4, uint256 a5, uint256 a6)
        internal
        pure
        returns (uint256)
    {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(7);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a3, PRIME);
        s1 = addmod(s1, a4, PRIME);
        s2 = addmod(s2, a5, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a6, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash8(uint256 a0, uint256 a1, uint256 a2, uint256 a3, uint256 a4, uint256 a5, uint256 a6, uint256 a7)
        internal
        pure
        returns (uint256)
    {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(8);
        // duplex 1: a0,a1,a2
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        // duplex 2: a3,a4,a5
        s0 = addmod(s0, a3, PRIME);
        s1 = addmod(s1, a4, PRIME);
        s2 = addmod(s2, a5, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        // duplex 3: a6,a7,0
        s0 = addmod(s0, a6, PRIME);
        s1 = addmod(s1, a7, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }

    function hash9(
        uint256 a0,
        uint256 a1,
        uint256 a2,
        uint256 a3,
        uint256 a4,
        uint256 a5,
        uint256 a6,
        uint256 a7,
        uint256 a8
    ) internal pure returns (uint256) {
        (uint256 s0, uint256 s1, uint256 s2, uint256 s3) = _spongeInit(9);
        s0 = addmod(s0, a0, PRIME);
        s1 = addmod(s1, a1, PRIME);
        s2 = addmod(s2, a2, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a3, PRIME);
        s1 = addmod(s1, a4, PRIME);
        s2 = addmod(s2, a5, PRIME);
        (s0, s1, s2, s3) = _permute(s0, s1, s2, s3);
        s0 = addmod(s0, a6, PRIME);
        s1 = addmod(s1, a7, PRIME);
        s2 = addmod(s2, a8, PRIME);
        (s0,,,) = _permute(s0, s1, s2, s3);
        return s0;
    }
}
