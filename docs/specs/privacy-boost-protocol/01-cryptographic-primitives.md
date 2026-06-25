# 1. Cryptographic Primitives

This section defines the cryptographic building blocks on which the protocol depends: the two
fields/curves, the Poseidon2 hash with its sponge construction, the in-circuit EdDSA scheme, the
domain-separation convention, and the canonical encoding rules for these primitives. These
definitions fix the compatibility surface for commitments, nullifiers, signatures, and digest
binding.

## 1. Fields and Curves

The protocol uses two algebraic structures simultaneously, by necessity.

These choices are compatibility-driven: BN254 matches Ethereum's pairing precompiles used for
on-chain Groth16 verification; BabyJubJub keeps EdDSA verification native to the circuit field; and
Poseidon2 provides an arithmetic-friendly hash over the same field. They are common choices for
EVM-compatible Groth16 systems, with BN254 generally characterized around the 100-bit security
level.

### 1.1 BN254 scalar field — the circuit field `r`

All Groth16 witnesses, Poseidon state elements, note commitments, nullifiers, Merkle roots, and
EdDSA scalars live in the BN254 scalar field:

```math
\mathbb{F}_r,\quad
r =
21888242871839275222246405745257275088548364400416034343698204186575808495617.
```

Every value referred to below as a "field element" is reduced modulo `r`.

| Name | Value | Notes |
|------|-------|--------|
| `r` (BN254 scalar field prime, circuit field) | `21888242871839275222246405745257275088548364400416034343698204186575808495617` = `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001` | (`PRIME`); (`SnarkScalarField`) |

The BN254 base field `q` (G1/G2 coordinate field) is only relevant to the Groth16 verifier
precompiles and is covered in the proof-system section.

### 1.2 BabyJubJub — the embedded EdDSA curve

EdDSA signatures must be verified *inside* a BN254 circuit. A signature over an external curve (e.g.
secp256k1) would require non-native bignum arithmetic and is prohibitively expensive in R1CS.
BabyJubJub is a twisted Edwards curve whose **base field equals the BN254 scalar field `r`**, so all
of its group operations are native circuit arithmetic. This is why both structures exist: `Fr` is
the circuit field, BabyJubJub is the curve embedded *in* that field for cheap in-circuit signature
checks.

The BabyJubJub curve is the twisted Edwards curve:

```math
a x^2 + y^2 = 1 + d x^2 y^2,\quad a = -1,
```

or equivalently:

```math
-x^2 + y^2 = 1 + d x^2 y^2.
```

| Parameter | Value | Notes |
|-----------|-------|--------|
| Base field prime (= BN254 `r`) | `21888242871839275222246405745257275088548364400416034343698204186575808495617` | (`PRIME`) |
| `a` | `-1` | Twisted Edwards parameter; external dependency v0.19.2 (`A.SetString("-1")`) |
| `d` | `12181644023421730124874158521699555681764249180949974110617291017600649128846` | (`D`); external dependency v0.19.2 |
| Cofactor `h` | `8` | external dependency v0.19.2 |
| Subgroup order `ℓ` | `2736030358979909402780800718157159386076813972158567259200215660948447373041` | external dependency v0.19.2; in-circuit |
| Base point `G.x` | `9671717474070082183213120605117400219616337014328744928644933853176787189663` | external dependency v0.19.2 |
| Base point `G.y` | `16950150798460657717958625567821834550301663161624707787222815936182638968203` | external dependency v0.19.2 |
| `B8 = 8·G` (`.x`) | `15836372343211832006828833031571087401945044377577570170285606102491215895900` | cofactor-cleared base point |
| `B8 = 8·G` (`.y`) | `7801528930831391612913542953849263092120765287178679640990215688947513841260` | cofactor-cleared base point |

`B8` is the cofactor-cleared base point used as the effective generator in the
[signature equation](#33-verification-equation):

```math
B_8 = 8G.
```

The circuit constant for `B8` MUST equal the cofactor-cleared generator defined above.

The on-chain `LibBabyJubJub` library carries the curve `PRIME` and `D` constant directly; it does not store `a`, `G`, `ℓ`, or `B8` because its
only job is the [registration-time validity check](#34-mandatory-in-circuit-checks-normative), which needs only on-curve arithmetic and
three doublings.

### 1.3 Groth16 over BN254 (pointer only)

Proofs are Groth16 on BN254, verified on-chain via the `ecAdd`/`ecMul`/`ecPairing` precompiles. The
verifying-key layout uses G1/G2 points plus an IC vector. Full treatment is in the proof-system section.

## 2. Poseidon2 over BN254 (`t = 4`)

Poseidon2 is the protocol's ZK-friendly hash. All commitments, nullifiers, Merkle nodes, account keys,
and the EdDSA message hash use Poseidon2 with state width `t = 4`. The construction follows the
[Poseidon2 paper](https://eprint.iacr.org/2023/323), and the parameter constants are derived from
the Poseidon2 [parameter-generation procedure](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage).
This specification relies on that standard parameterization and does not make an independent
cryptanalysis claim beyond the parameter choice.

### 2.1 Permutation parameters

| Parameter | Value | Notes |
|-----------|-------|--------|
| State width `t` | 4 | T4 permutation |
| Rate | 3 | lanes `s0..s2` |
| Capacity | 1 (lane `s3`) | capacity lane |
| S-box | `x⁵` | quintic S-box |
| Full rounds `R_F` | 8 (4 + 4) | four before and four after partial rounds |
| Partial rounds `R_P` | 56 | middle partial rounds |
| Total rounds | 64 | round-constant schedule `[64][4]` |
| Internal-matrix diagonal `D0..D3` | see below | optimized internal linear layer |
| Round constants | 64×4 schedule, packed as 88 words on-chain | Poseidon2 BN254 parameter schedule |

Internal-matrix diagonal:

```text
D0 = 0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7
D1 = 0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b
D2 = 0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15
D3 = 0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b
```

Round-constant provenance: the 88 32-byte words in `RC_BYTES` are generated by the Poseidon2
BN254, `t = 4` parameter procedure.
Layout: 16 words = full rounds 0..3 (4 lanes each),
then 56 words = partial rounds 4..59 (lane `s0` only), then 16 words = full rounds 60..63. The
Solidity indexer reads these via `_rc(rc, base+i)` for full rounds 0..3, `_rc(rc, r+12)`
for partial rounds, and `_rc(rc, 72+(r-60)*4+i)` for full rounds 60..63. Partial-round lanes
`s1..s3` use zero round constants.

### 2.2 Permutation round schedule

Let the Poseidon2 state be:

```math
s = (s_0, s_1, s_2, s_3).
```

The quintic S-box is:

```math
S(x) = x^5.
```

The permutation applies an initial external linear layer, then four full rounds, fifty-six partial
rounds, and four final full rounds. For a full round $r$, every lane receives a round constant,
the S-box, and the external matrix:

```math
s \leftarrow M_E\left(S(s + RC_r)\right).
```

For a partial round $r$, only lane $s_0$ receives the round constant and S-box before the
internal matrix:

```math
s_0 \leftarrow S(s_0 + RC_{r,0}),\qquad s \leftarrow M_I(s).
```

Equivalent pseudocode:

```text
permute(s0, s1, s2, s3):
    s = externalLinearLayer(s)

    for r in 0..3:
        for i in 0..3:
            s[i] = s[i] + RC[r][i]
            s[i] = s[i]^5
        s = externalLinearLayer(s)

    for r in 4..59:
        s[0] = s[0] + RC[r][0]
        s[0] = s[0]^5
        s = internalLinearLayer(s)

    for r in 60..63:
        for i in 0..3:
            s[i] = s[i] + RC[r][i]
            s[i] = s[i]^5
        s = externalLinearLayer(s)

    return s
```

`externalLinearLayer` (`M_E`) and `internalLinearLayer` (`M_I`) are the standard Poseidon2 `t = 4`
matrices. The internal layer is:

```math
s'_i = D_i s_i + \sum_{j=0}^{3} s_j.
```

The permutation MUST use the linear-layer arithmetic above and MUST apply the initial external layer
before the first round.

### 2.3 Sponge construction (this is a sponge, NOT a fixed 2-to-1 compression)

The hash is a sponge over the permutation, rate 3, capacity 1. The capacity lane is initialized to
an IV that binds the input length; there is no separate domain/capacity constant beyond this length
IV.

```math
s_3 = n \cdot 2^{64},
```

where `n` is the number of input field elements and:

```math
2^{64} = 18446744073709551616 = \texttt{0x1\_0000\_0000\_0000\_0000}.
```

Absorb/squeeze:

```text
sponge_hash(a[0], ..., a[n-1]):
    s0 = 0
    s1 = 0
    s2 = 0
    s3 = n * 2^64

    for i in 0..n-1:
        lane = i mod 3
        s[lane] = s[lane] + a[i]

        if lane == 2 or i == n-1:
            s = permute(s)

    return s0
```

The fixed-arity hash helpers unroll exactly this schedule. For example, `hash4` absorbs
`[a0,a1,a2]`, permutes, absorbs `[a3]`, and permutes again; `hash8` performs three permutations.
These unrolled forms MUST equal the generic sponge for the same arity.

### 2.4 n-to-1 and 2-to-1 hashing

There is no separate compression mode. "2-to-1" is just the sponge with `n=2` (`hash2`, used for
note-tree Merkle nodes and the sequential commitments hash). Domain-separated hashing prepends the
domain tag as the first absorbed element, so `H(domain, v0, v1, …)` is the `(k+1)`-arity sponge
(`HashDomainSeparated` / `PoseidonMD`). Note that prepending the domain changes `n`, hence changes
the IV; this is part of the domain separation.

Empty-input edge case: `n=0` still permutes once from the all-zero state and returns a fixed
non-zero value `11250791130336988991462250958918728798886439319225016858543557054782819955502`.
No protocol hash uses `n=0`.

### 2.5 Protocol hash domain separation

Protocol hashes use fixed first-element Poseidon tags where domain separation is required. At the
primitive level, `Poseidon(d, v0, v1, ...)` is the same sponge as above, with `d` absorbed as the
first field element. Deliberate un-domain-separated uses, such as note-tree Merkle
nodes and sequential commitment folding, are specified in the data-structure and flow sections.

The canonical domain-tag table is in
[Parameters, Constants & Domain Separators](13-parameters-constants.md). The structured hash
formulas for notes, commitments, nullifiers, auth leaves, and Merkle nodes are in
[Core Data Structures](03-core-data-structures.md); operation digest construction is in
[Public Inputs and Operation Digests](06-public-inputs-and-digests.md).

## 3. EdDSA over BabyJubJub with Poseidon

Transfers and forced withdrawals are authorized by an EdDSA signature verified inside the circuit,
keyed by the `authPk = (Ax, Ay)` bound in the AuthRegistry leaf.

### 3.1 Signature layout

| Field | Type | Meaning | Notes |
|-------|------|---------|--------|
| `R8 = (R8x, R8y)` | BabyJubJub point | Commitment point, already cofactor-cleared (signer computes `R8 = (8·r)·G`) |  |
| `S` | scalar in `Fr`, `0 ≤ S < ℓ` | Response scalar | same |
| `A = (Ax, Ay)` | BabyJubJub point | Signer public key (`A = sk·G`) |  |

The signer samples a nonce $r \in [1,\ell)$, computes:

```math
R_8 = (8r \bmod \ell)G,
```

and returns:

```math
S = (h \cdot sk + r) \bmod \ell.
```

### 3.2 Message-hash construction

The hashed message binds `R8`, the public key `A`, and the message scalar `M`. **Field ordering is
`(R8x, R8y, Ax, Ay, M)`**; this ordering is load-bearing and MUST NOT be permuted:

```math
h = \textsf{Poseidon2T4}(R_{8x}, R_{8y}, A_x, A_y, M).
```

The verifier reduces $h$ modulo $\ell$. The circuit feeds the field element directly to
scalar multiplication.

Here `M` is `approveMsg = Poseidon(DOMAIN_APPROVE, digestHi, digestLo)`, where `digestHi` and
`digestLo` are the two 128-bit halves of the relevant operation digest. Note the
EdDSA hash itself carries no domain tag; separation comes from `M` already being domain-bound.

### 3.3 Verification equation

```math
S \cdot B_8 = R_8 + h \cdot (8A).
```

with `B8 = 8·G` as defined in
[BabyJubJub](#12-babyjubjub--the-embedded-eddsa-curve) and `8·A` computed by three point-doublings. The
verifier computes the cofactor-cleared public key before multiplying by `h`. The cofactor `8` multiplications on
both base and key are intrinsic to this scheme's cofactor handling. The circuit assembles `right =
R8 + ScalarMul(8·A, h)` and `left = ScalarMul(B8, S)` and asserts equality of both coordinates.

### 3.4 Mandatory in-circuit checks (normative)

- The verifier MUST enforce `S < ℓ` (canonical scalar). `S` is range-decomposed to 254 bits and
 compared against `ℓ` via Circom's CompConstant; the resulting `sTooLargeBit` MUST be 0. The
 circuit enforces this with `AssertEqual(sTooLargeBit, 0)` or the gated `AssertEqualIf` variant.
 This blocks signature malleability via `S → S + ℓ`.
- `A` and `R8` MUST be asserted on the BabyJubJub curve before any group arithmetic. The circuit
 rejects off-curve public keys or commitment points.
- On-chain key registration MUST reject low-order / torsion public keys:
 `LibBabyJubJub.isValidPublicKey` requires the point be on-curve AND that `8·A ≠ identity (0,1)`. This is enforced at registration and rotation
 in `AuthRegistry`. Rationale: the verifier cofactor-clears via `8·A`; a low-order
 key would clear to identity and the equation would lose message binding. The identity test in
 projective coords is `X == 0 && Y == Z` after three doublings.

---
