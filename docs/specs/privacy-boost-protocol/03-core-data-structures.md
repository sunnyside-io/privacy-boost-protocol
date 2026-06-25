# 3. Core Data Structures: Notes, Commitments, Nullifiers, Merkle Trees

Privacy Boost is a UTXO ("note") shielded-pool protocol. Value is held as commitments in append-only
Poseidon Merkle trees; spending reveals a nullifier (not the commitment) so spends are unlinkable to
the note that was created. Commitments, nullifiers, keys, and Merkle nodes are BN254 scalar-field
elements. The Poseidon2 parameters, scalar modulus, domain tag values, tree capacities, and hash/KDF
literal constants are centralized in [Appendix B](13-parameters-constants.md); this section only
defines how those constants are used in the note data model.

## 1. Structured hash shapes

```math
\textsf{PoseidonMD}(d, v_0, v_1,\ldots)
= \textsf{Poseidon2T4Sponge}(d, v_0, v_1,\ldots).
```

Merkle internal nodes for the **note tree** use the *un-domain-separated* 2-input sponge:

```math
\textsf{NoteNode}(l,r)=\textsf{Poseidon2T4Sponge}(l,r).
```

AuthRegistry nodes use a different, domain-separated hash:

```math
\textsf{AuthNode}(l,r)=
\textsf{Poseidon2T4Sponge}(\texttt{DOMAIN\_REG\_NODE},l,r).
```

Do not confuse the two.

## 2. Key hierarchy

A note is owned via a key chain rooted at a per-account secret. The relevant derivations are:

```math
\begin{aligned}
\texttt{accountId} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_ACCOUNTID}, \texttt{uint160(owner)}, \texttt{salt}), \\
\texttt{mpk} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_MPK}, \texttt{accountId}, \texttt{nullifyingKey}), \\
\texttt{npk} &=
  \textsf{Poseidon}(\texttt{DOMAIN\_NOTE}, \texttt{mpk}, \texttt{noteRnd}).
\end{aligned}
```

- `owner` is the EOA address widened to a field element; `salt` is account randomness.
- `nullifyingKey` (`nk`) is the secret that authorizes spends; `mpk` is the public master key that
 binds an account to its `nk`.
- `npk` ("note public key") is a *fresh* per-note pseudonymous key: a new `noteRnd` per note makes
 two notes of the same owner unlinkable on-chain.

## 3. The note and its commitment

A **note** (UTXO) is the tuple below. The encrypted-payload plaintext layout is documented in the
encryption section.

| Field | Type / domain | Meaning |
|---|---|---|
| `npk` | field elt | note public key = `Poseidon(DOMAIN_NOTE, mpk, noteRnd)` |
| `tokenId` | uint16 (as field) | compact token id; see [token id encoding](#9-token-id-encoding-data-model-level) |
| `value` (`amount`) | uint96 (as field) | token amount, 12 bytes |
| `noteRnd` | 16 bytes (as field) | per-note blinding/randomness; binds `npk` |

The encrypted payload carries master public keys (`MPK`). Account ids are derived separately from
the owner and salt. Transfer/unshield `Output` plaintext is:

```text
senderMPK(32) + recipientMPK(32) + tokenId(2) + amount(12) + noteRnd(16) = 94 B
```

It is AES-256-GCM sealed to 110 B (94 B ciphertext + 16 B tag) and packed into the `Output`
calldata struct's `ct0..ct3` fields. `receiverWrapKey` is a separate wrapped-key field, not part of
the sealed ciphertext. Deposit/shield `DepositCiphertext` plaintext omits the sender and is:

```text
recipientMPK(32) + tokenId(2) + amount(12) + noteRnd(16) = 62 B
```

It is AES-256-GCM sealed to 78 B and packed into the `DepositCiphertext` ct fields. The
**commitment** (the Merkle leaf) is:

```math
\texttt{commitment} =
\textsf{Poseidon}(\texttt{DOMAIN\_NOTE}, \texttt{npk}, \texttt{tokenId}, \texttt{value}).
```

Note that `noteRnd` does *not*
appear directly in the commitment hash — its entropy enters only through `npk` (`npk =
Poseidon(DOMAIN_NOTE, mpk, noteRnd)`). The same `DOMAIN_NOTE` tag is reused for both `npk` and the
commitment; they are distinguished by arity (2 inputs vs 3 inputs after the tag), which the
fixed-length sponge IV keeps
collision-resistant across arities.

Field ordering is normative and MUST be `(npk, tokenId, value)` exactly. The commitment is what is
published on-chain in the `Output` calldata struct (`Output.commitment`) and appended to the tree; the preimage is delivered to
the recipient/TEE only in encrypted form (the `ct*` fields of `Output`/`DepositCiphertext`).

## 4. Nullifier derivation

When a note is spent, the circuit publishes a **nullifier** as the spend handle while keeping the
consumed commitment hidden:

```math
\begin{aligned}
\texttt{combinedDomain} &=
  \texttt{NullifierTreeNumberMultiplier} \cdot \texttt{treeNumber}
    + \texttt{DOMAIN\_NULLIFIER}, \\
\texttt{nullifier} &=
  \textsf{Poseidon}(\texttt{combinedDomain}, \texttt{nk}, \texttt{leafIndex}).
\end{aligned}
```

The multiplier is part of the protocol constant set. Properties an implementer must preserve:

- The nullifier is a function of the spend secret `nk` plus the note's **position** (`treeNumber`,
 `leafIndex`) — NOT of the commitment. This makes it deterministic (the same note always nullifies
 to the same value, enabling double-spend detection) yet unlinkable to the commitment (the
 commitment hash does not include `nk` or position).
- `treeNumber` is encoded into the domain
 (`treeNumber * NullifierTreeNumberMultiplier + DOMAIN_NULLIFIER`).
 This binds the nullifier to a specific tree so the same `(nk, leafIndex)` in two different trees
 yields distinct nullifiers. The multiplier and base domain are protocol constants in
 [Appendix B](13-parameters-constants.md).
- On-chain, spent nullifiers are recorded in `mapping(uint256 nullifier => bool spent)
 nullifierSpent`. A spend MUST revert if its nullifier is
 already set (or zero); this is the double-spend guard, enforced in `_spendNullifiers`
 (reverts `InvalidNullifierSet` on `nullifier == 0` or `nullifierSpent[nullifier]`). Each input note contributes exactly one nullifier.

## 5. Note-commitment Merkle tree: structure

| Property | Value | Notes |
|---|---|---|
| Arity | binary (2-ary) | note and auth trees are binary Merkle trees |
| Configured note depth (`merkleDepth` immutable) | 24 | registered verifier profile; note tree capacity is $2^{24}$ leaves |
| Max leaves per note tree | `2^merkleDepth` = 16,777,216 at depth 24 | bounded by configured profile depth |
| Constructor bound on `merkleDepth_` | 1..24 inclusive | rejects out-of-range depths |
| Node hash | injected `hash2(left,right) = Poseidon2T4(left,right)` (no domain tag) | differs from auth-tree domain-separated node hash |
| Empty-leaf value (`zeros[0]`) | `0` | zero roots are derived recursively |

The contract stores `merkleDepth` as a constructor immutable, and the verifier profile must use the
same compiled note-tree depth. The registered verifier profile uses note depth 24 and auth depth 20; the
full depth/zero-root distinction is centralized in
[Parameters, Constants & Domain Separators](13-parameters-constants.md).

**Zero/empty-leaf hashes** are precomputed as
`zeros[i] = hash2(zeros[i-1], zeros[i-1])`, `zeros[0]=0`. These fill all sibling positions of
unallocated leaves so a fixed-depth tree has a well-defined root before it is full. The same
iterative construction is reproduced client-side. The Solidity equivalent
`LibMerkleTree.computeZeroRoot(depth)` recomputes `current = hash2(current, current)` `depth` times
from 0. Selected values:

| Level | Zero hash |
|---|---|
| 0 | 0 |
| 1 | 5151499478991301833156025595048985053689893395646836724335623777508747990769 |
| 20 (`MERKLE_ZERO_ROOT`; note-hash zero root) | 12912536786691007423957206067517486813236154886763950786309034005218474477397 |
| 24 (**configured note** empty root, `zeros[24]`) | 6379059771196981783531842116523729103253487220527074934863013362203865842833 |

The auth tree uses a separate zero-root table because auth nodes are domain-separated. `LibZeroHashes`
covers `0..24` for the note tree constructor's permitted depth range.

## 6. Leaf insertion, frontier, and next-index

The contract does **not** store leaves or recompute the tree on-chain. It stores only the current
root and a leaf count per tree, and trusts the ZK proof to attest that `rootNew` is the correct
result of appending the batch's commitments to `rootOld` at the right indices (the
epoch/deposit/forced circuits constrain this). Off-chain the tree is maintained incrementally:

- **next-index / leaf count.** `mapping(uint256 treeNum => uint32 leafCount) treeCount`
 is the number of leaves placed and therefore the index of
 the next leaf. New commitments in an epoch are appended at consecutive indices starting at
 `countOld` (`SetLeaf(startIndex+i, commitment)`).
- **fixed-depth incremental insertion.** `SetLeaf(index, value)` writes the leaf then walks up
 `Depth` levels recomputing parents from `(left = node[idx & ~1], right = node[idx | 1])`. Unset siblings
 resolve to the level's zero hash.
- **frontier.** To append without holding the full tree, the client persists a *frontier*: for each
 level, the right-most filled node when that level's bit in `count` is set, else 0. An epoch reconstructs the partial tree via
 `SetFrontier(countOld, frontierOld)` then appends. The frontier is the minimal witness needed to extend the
 tree and compute `rootNew`.
- **Merkle path / inclusion.** A note's membership proof is the sibling along its index path, level
 by level. The proving path computes the root with the shared `computeRoot` helper, which
 decomposes `leafIndex` into depth bits via `api.ToBinary`;
 bit `i` selects whether `current` is the left or right input at level `i` (`left = Select(bit,
 sibling, current)`, `right = Select(bit, current, sibling)`), then `current =
 Poseidon2T4(left,right)`, finally asserting `current == Root`. The bit-ordering (LSB = level 0 =
 leaf level) and the left/right selection MUST match this exactly or proofs fail.

## 7. Multiple trees, capacity, and rollover

Each note tree holds at most `2^merkleDepth` leaves. When full, the protocol rolls over to a fresh
empty tree. Trees are identified by a monotonically increasing `currentTreeNumber`, initialized to 0 with `treeRoot[0] = _zeroRoot` and
`treeRootHistory[0][0] = _zeroRoot`.

| Constant | Value | Notes |
|---|---|---|
| `MAX_NOTE_TREE_NUMBER` | 32767 (= 2^15 − 1, fits 15 bits) |  |
| `MAX_NOTE_ROOTS_PER_PROOF` | 16 |  |
| `ROOT_HISTORY_SIZE` | 64 |  |

Capacity is enforced in `_validateTreeCapacity`:

```text
maxLeaves = 1 << merkleDepth // 2^24 = 16,777,216 at configured depth 24
expectedCountNew = rollover ? totalOutputs: countOld + totalOutputs
require !(rollover && countOld != maxLeaves) // rollover only when tree exactly full
require !(!rollover && countOld >= maxLeaves) // cannot append to a full tree
require countNew == expectedCountNew && expectedCountNew <= maxLeaves
```

Rollover semantics:

- **MUST** only roll over when the active tree is *exactly* full (`countOld == maxLeaves`), enforced
 by `_validateTreeCapacity`.
- On rollover: `currentTreeNumber += 1` (reverting `InvalidEpochState` if
 `> MAX_NOTE_TREE_NUMBER`), the new tree's root/count are set to the batch result, the new root is pushed to the new
 tree's history, and `TreeAdvanced(old,new)` is emitted. The batch's commitments are
 placed into the *new* tree starting at index 0 (`BuildNoteTreeForBatch` uses `startIndex=0,
 frontier=nil` when `rollover`).
- Without rollover: `treeRoot[active]` and `treeCount[active]` are updated in place and the new root
 is pushed to history.

A single batch never spans two trees: outputs land entirely in the active tree or entirely in the
new tree. Inputs (spends), however, may reference notes across multiple older trees — up to
`MAX_NOTE_ROOTS_PER_PROOF = 16` distinct `(treeNumber, root)` pairs may be supplied per proof.

## 8. Root history ring buffer

Each tree keeps a 64-slot ring buffer of recent roots so proofs can reference a slightly stale (but
still valid) root, tolerating concurrency between proof generation and on-chain state advance.

- Storage: `mapping(uint256 treeNum => uint256[ROOT_HISTORY_SIZE] roots) treeRootHistory` and
 `mapping(uint256 treeNum => uint256 cursor) treeRootHistoryCursor`.
- Push: `next = (cursor+1) % 64;
 history[next] = rootNew; cursor = next`. Slot 0 of tree 0 is seeded with the empty root at init.
- Lookup:
 - root `0` is never known;
 - O(1) fast path: matches the tree's current `treeRoot[treeNum]`;
 - for a **finalized** tree (`treeNum < currentTreeNumber`) ONLY its final root is accepted —
 historical roots of an already-rolled-over tree are rejected;
 - for the **current** tree, the ring buffer is scanned backward from `cursor` over all 64 slots.

`_validateKnownRoots` requires every supplied
`(treeNumber, root)` to pass `isKnownTreeRoot` (else `RootNotKnown`), requires the active
tree to be present (else `InvalidEpochState`), and enforces sparse-root uniqueness:
deposit/forced-withdraw paths (`allowDuplicateTreeNumbers == false`) reject duplicate `treeNumber`
(`DuplicateTreeNumber`); epoch paths (`true`) allow duplicate tree numbers but reject exact
duplicate `(treeNumber, root)` pairs (`DuplicateTreeRootPair`). A proof MAY reference any
root still resident in the current tree's 64-deep history or the final root of any finalized tree;
it MUST NOT reference a superseded mid-history root of a finalized tree.

## 9. Token id encoding (data-model level)

A note's `tokenId` is a **compact uint16** assigned by an append-only `TokenRegistry`, not a raw
address. This keeps the note commitment field small.

- Forward map: `mapping(uint16 tokenId => TokenInfo info) tokenOf` where `TokenInfo = { uint8
 tokenType; address tokenAddress; uint256 tokenSubId }`.
- Reverse map / dedupe: `idOf[keccak256(abi.encode(tokenType, tokenAddress, tokenSubId))]`.
- Assignment: `register` is `onlyOwner`, requires `tokenType == TOKEN_TYPE_ERC20` (0), non-zero
 **contract** address (`tokenAddress.code.length != 0`), checks the key is not already registered,
 then increments `nextId` and assigns `tokenId = ++nextId`. Thus **`tokenId` starts at 1; `0` means
 "unregistered"** and `idOf` returning 0 signals absence. Registration reverts `TokenIdOverflow`
 when `nextId == type(uint16).max`; because the overflow check precedes the pre-increment, the
 largest assignable id is `type(uint16).max` = 65535.
- Only `TOKEN_TYPE_ERC20 = 0` is currently supported. The `TokenType` enum also declares `ERC721`,
 but registration rejects any `tokenType != 0`. `tokenSubId` is reserved for multi-asset token
 types and is `0` for ERC20.

At the data-model level: the commitment binds the compact `tokenId` (a uint16 lifted to a field
element), and the contract resolves `tokenId -> tokenAddress` via `tokenOf` only at
deposit/withdrawal time when moving real ERC20 value (`_transferToken`). Two clients interoperate
only if they share the same registry assignment, since
`tokenId` is registry-order-dependent, not a deterministic function of the address.

## 10. Normative invariants summary

- A note commitment MUST be `Poseidon(DOMAIN_NOTE, npk, tokenId, value)` with that exact field order.
- A nullifier MUST be
 `Poseidon(treeNumber * NullifierTreeNumberMultiplier + DOMAIN_NULLIFIER, nk, leafIndex)`; each
 input note yields exactly one, and a repeated (or zero) nullifier MUST cause revert via the
 `nullifierSpent` registry.
- Note-tree internal nodes MUST use the non-domain-separated `hash2`; AuthRegistry nodes MUST use
 `Poseidon(DOMAIN_REG_NODE, l, r)`. These two trees are NOT
 interchangeable.
- Empty subtrees MUST use `zeros[i] = hash2(zeros[i-1], zeros[i-1])`, `zeros[0]=0`, and the empty-tree root is `zeros[merkleDepth]`.
- Outputs of one batch MUST all land in a single tree; rollover MUST occur only at exact fullness
 `countOld == 2^merkleDepth` and MUST advance `currentTreeNumber` by 1, capped at
 `MAX_NOTE_TREE_NUMBER=32767`.
- A referenced root MUST satisfy `isKnownTreeRoot`: the current root of any tree, the final root of
 a finalized tree, or one of the last 64 roots of the current tree.
- The on-chain `merkleDepth` SHOULD equal the compiled note-tree depth used by the registered
 verifier profile. This is enforced by deployment discipline, not by a runtime check; the
 constructor only bounds it to `1..24`.

---
