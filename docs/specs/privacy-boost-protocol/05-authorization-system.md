# 5. Authorization System (AuthRegistry & In-Circuit Auth)

## Overview

Privacy Boost separates **account ownership** (an on-chain EOA, secp256k1 ECDSA) from **spend
authorization** (an in-circuit EdDSA key on the BabyJubJub twisted-Edwards curve). The
`AuthRegistry` contract is a Poseidon Merkle registry: the EOA owner registers, rotates, and revokes
EdDSA "auth keys" via EIP-712 signatures, and each live key is committed as a leaf in an auth Merkle
tree. Spend circuits (transfer / unshield in the epoch circuit, and forced-withdraw) prove a spend
is authorized by (1) verifying an EdDSA signature over the operation digest inside the circuit, and
(2) proving Merkle membership of the signing key's leaf against a snapshotted auth root. The EOA key
never enters the circuit; the EdDSA key never signs anything on-chain.

This split lets the ZK circuit use a Poseidon-friendly EdDSA verification (cheap in-circuit) while
account control stays anchored to a standard Ethereum wallet (EOA or EIP-1271/ERC-7739 smart
wallet).

---

## Key Hierarchy and What Is Secret vs Public

| Key | Curve / type | Secret? | Role | Where used |
|-----|--------------|---------|------|-----------|
| EOA key | secp256k1 ECDSA | Secret (user wallet) | Root of account ownership; signs register/rotate/revoke EIP-712 messages. Never enters the TEE or circuit. | `AuthRegistry` mutations |
| Auth key (`authPkX`, `authPkY`) | BabyJubJub EdDSA | Private scalar secret; pubkey `(X,Y)` is public (in leaf + events) | Authorizes spends inside the circuit by signing the operation digest. | Spend circuits |
| Viewing key | secp256k1 ECDH key | Secret | ECDH encryption/decryption of tx metadata. Not part of auth or circuit authorization. | TEE / recipient decryption |
| Nullifying key | scalar | Secret | Nullifier + MPK derivation. Cannot spend alone. | Circuits (`domainMPK`, nullifier) |

Auth-key derivation note: the EdDSA auth keypair is generated client/SDK-side (its derivation from
the mnemonic/EOA is SDK-defined and not enforced on-chain). Account ownership is established at
registration by deriving `accountId = Poseidon(DOMAIN_ACCOUNTID, owner, salt)` in AuthRegistry. Live
spend circuits consume the already-derived `accountId` and enforce membership of the auth leaf
`Poseidon(DOMAIN_REG_LEAF, accountId, authPkX, authPkY, expiry)`. The spend path carries forward
`accountId`, `(authPkX, authPkY)`, `expiry`, the `owner` EOA, and the tree number/index.

---

## Account ID Derivation

`accountId` is derived on first registration and binds the account to an immutable owner EOA:

```text
accountId = Poseidon2T4.hash3(DOMAIN_ACCOUNTID, uint256(uint160(owner)), salt)
```

- MUST be non-zero: registration reverts `InvalidAccountId` if `accountId == 0`.
- The owner that first registers an `accountId` becomes its immutable on-chain owner; subsequent
 registrations under the same `accountId` MUST match or revert `OwnerMismatch`. The owner is
 queryable via `ownerOf(accountId)`. The leaf no longer embeds the owner.

Note: `register` is the account-registration entry point and always derives `accountId` internally
from `(expectedOwner, salt)` via `computeAccountId`; the caller never supplies a raw `accountId`.
`rotate`/`revoke` take `accountId` directly.

---

## Auth Leaf and Node Hashing (Domain Separation)

The auth tree uses a different Poseidon domain from the note-commitment tree, so an auth node can
never be reinterpreted as a note node and vice-versa. The exact domain tag values and Poseidon2T4
parameters are defined in [Appendix B](13-parameters-constants.md).

```text
authLeaf = Poseidon(DOMAIN_REG_LEAF, accountId, authPkX, authPkY, expiry) // 5 inputs (hash5)
authNode = Poseidon(DOMAIN_REG_NODE, left, right) // 3 inputs (hash3)
```

- Contract leaf: `computeLeaf` = `Poseidon2T4.hash5(DOMAIN_REG_LEAF, accountId, authPkX, authPkY,
 uint256(expiry))`.
- Contract node: `Poseidon2T4.hash3(DOMAIN_REG_NODE, left, right)`.
- Circuit node: `Poseidon2T4(api, domainRegNode, left, right)`.
- Circuit leaf: `Poseidon2T4(api, domainRegLeaf, SpenderAccountId, AuthPkX, AuthPkY, AuthExpiry)`.
- Native (server) parity: `AuthLeaf`/`AuthNode` = `PoseidonMD(DomainRegLeaf/DomainRegNode, …)`.

MUST: a computed leaf of zero is rejected (`InvalidLeaf`), because zero is the empty-slot sentinel
(revoked slots are set to 0).

---

## Auth Merkle Tree(s): Geometry and Zero Hashes

| Parameter | Value | Notes |
|-----------|-------|--------|
| Tree depth (`authTreeDepth`) | immutable constructor arg; configured auth depth = **20** (independent of the note tree's depth 24) | registered verifier profile |
| Leaves per auth tree | `1 << authTreeDepth` = 1,048,576 at depth 20 |  |
| `MAX_AUTH_TREE_NUMBER` | 32767 (15-bit, inclusive) |  |
| `AUTH_ROOT_HISTORY_SIZE` (per-tree ring buffer) | `ROOT_HISTORY_SIZE = 64` |  |
| `MAX_AUTH_ROOTS_PER_PROOF` | 16 |  |
| Tree-number packing width | 15 bits/slot × 16 slots |  |

Multiple trees: the registry is a sequence of fixed-depth trees indexed by `currentAuthTreeNumber`. When the active tree fills (`idx >= 1 << authTreeDepth`),
registration rolls over to `currentAuthTreeNumber + 1` (reverting `RegistryFull` if it would
exceed `MAX_AUTH_TREE_NUMBER`), initializing the new tree's root to the empty-tree root.

Zero hashes are the precomputed
`Poseidon(DOMAIN_REG_NODE, zeros[i-1], zeros[i-1])` chain with `zeros[0] = 0`, indices 0..24. The
array covers depths through 24; the configured auth depth is 20. The empty-tree root for a
depth-`d` tree is `zeros[d]`. At depth 20, `zeros[20] =
5126366598568957508996612635770875836246285197448927819410732545299241365093`, matching
`AUTH_ZERO_ROOT`. Incremental updates use these zeros for absent siblings.

Per-tree state is packed in `AuthTreeState { uint256 root; uint64 cursor; uint32 leafCount; }`. Each leaf update recomputes the root bottom-up,
writes it to the next ring-buffer slot `(cursor+1) % 64`, advances the cursor, and emits
`RootUpdated`. The current root is also kept in
`_authTreeState[treeNum].root`, read by `authTreeRoot(treeNum)`.

---

## AuthKeyInfo and Per-Account Key List

Multi-device: one `accountId` may hold many auth keys, keyed by `authKeyId =
keccak256(abi.encode(accountId, authPkX))`. Note: `authPkY` is *not* part of `authKeyId`; the
X-coordinate identifies the slot.

| `AuthKeyInfo` field | Type | Meaning | Notes |
|---------------------|------|---------|--------|
| `treeNumber` | uint16 | tree holding this key's leaf |  |
| `treeIndex` | uint32 | leaf index within that tree |  |
| `listIndex` | uint32 | 1-indexed position in `_authKeyList[accountId]` (0 = not present) |  |
| `revoked` | bool | revocation flag |  |

`AccountInfo { address owner; uint96 nonce; }` packs ownership and a monotonic replay nonce in one
slot. The nonce is bound into each EIP-712 struct
hash (read *before* verification at the current value) and incremented on every successful
register/rotate/revoke.

---

## Registry Mutations: EIP-712 Authorization

All three mutations require an EIP-712 signature from the account owner EOA over a typed struct that
includes the account `nonce`. Domain separator:

```text
DOMAIN_SEPARATOR = keccak256(abi.encode(
 keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"), // DOMAIN_TYPEHASH
 keccak256("PB:AuthRegistry:vNext"), // NAME_HASH
 keccak256("1"), // VERSION_HASH
 block.chainid,
 address(this)))
```

Type hashes:

```text
Register(uint256 accountId,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)
Rotate(uint256 accountId,uint256 oldAuthPkX,uint256 authPkX,uint256 authPkY,uint64 expiry,uint256 nonce)
Revoke(uint256 accountId,uint256 authPkX,uint64 expiry,uint256 nonce)
```

Final digest = `MessageHashUtils.toTypedDataHash(DOMAIN_SEPARATOR, structHash)`.

Signature verification:
1. Raw-first: `SignatureChecker.isValidSignatureNow(expectedOwner, rawDigest, sig)` — accepts EOAs
 (65-byte `r||s||v`, `v∈{27,28}`) and EIP-1271 wallets that accept the raw dapp digest. A legacy
 `EcdsaSig{v,r,s}` overload packs to `r||s||v`.
2. ERC-7739 fallback (only if `expectedOwner.code.length > 0`, else `InvalidSignature`):
 parses a trailing appendix and MUST satisfy all of:
 - signature length ≥ 2; the trailing uint16 appendix-length field `n` MUST equal
 `CONTENTS_DESCRIPTION_LENGTH (23)` and `sigLen > 66 + n`, else `InvalidSignatureLength`;
 - `appSep == DOMAIN_SEPARATOR` (cross-app replay defense, `InvalidERC7739AppDomain`);
 - contentsDescription keccak `== keccak256("Contents(bytes32 stuff)")`
 (`InvalidERC7739ContentsDescription`);
 - `contentsHash ∈ { rawDigest, keccak256(abi.encode(CONTENTS_DESCRIPTION_HASH, structHash)) }`
 (binds to this action incl. nonce, `InvalidERC7739ContentsHash`);
 - re-verify against `wrappedDigest = keccak256(0x1901 || appSep || contentsHash)`
 (`InvalidERC7739WrappedSignature`).

This binding is normatively required: without it, any 7739 signature ever produced against this
domain would replay across register/rotate/revoke and across `(accountId, authPk*, expiry, nonce)`
tuples.

Common preconditions:
- `expiry`: if non-zero, MUST be `>= block.timestamp`, i.e. revert `SignatureExpired` when
 `block.timestamp > expiry`. `expiry == 0` means no
 expiry.
- Auth pubkey validity: `LibBabyJubJub.isValidPublicKey(authPkX, authPkY)` MUST hold, i.e. on-curve
 AND not a low-order torsion point (`8·A != identity (0,1)`) — else `InvalidAuthPublicKey`. Rejecting
 torsion points matters because the EdDSA verifier clears cofactors via `A8 = 8·A`; a low-order `A`
 would make the signature equation lose message binding. Note the on-curve check uses `a = -1`, `D =
 12181644023421730124874158521699555681764249180949974110617291017600649128846`, `PRIME =
 21888242871839275222246405745257275088548364400416034343698204186575808495617`. In `register` the pubkey check happens before
 signature verification; in `rotate` it happens after.

---

## Register / Rotate / Revoke Semantics

**Register**: derives `accountId =
computeAccountId(expectedOwner, salt)`, then adds a new key. Reverts `AlreadyRegistered` if
`authKeyId` already exists. Assigns the next slot in the active tree (rolling to a new tree
on overflow), increments nonce, stores `AuthKeyInfo`, appends to `_authKeyList`, and writes the
leaf. Emits `Registered` (first key for a new account only — when `existingOwner == address(0)`) and
always `AuthKeyAdded`.

**Rotate**: identifies the existing key by `oldAuthPkX`;
MUST exist (`AuthKeyNotFound`) and MUST NOT be revoked (`AuthKeyAlreadyRevoked`).
Reuses the **same Merkle slot** (`treeNumber`, `treeIndex`). If `oldAuthPkX != newAuthPkX`, the new
id MUST be free (`AlreadyRegistered`), and the mapping/list entry are moved to `newAuthKeyId`
keeping `listIndex`. If `oldAuthPkX == newAuthPkX`, only `(authPkY, expiry)` change —
used to extend expiry or refresh on the same device. Writes the new leaf in-place; emits
`AuthKeyRotated`.

**Revoke**: MUST exist and not already be revoked. Sets
`info.revoked = true` and **zeros the leaf** (`_updateLeaf(treeNum, treeIndex, 0)`). Revocation is
permanent: the Merkle slot is permanently consumed and the same `authPkX` cannot be re-registered.
Note: this permanence is enforced indirectly — `_authKeyInfo[authKeyId]` is left in place with
`revoked=true` and `listIndex != 0`, so a re-`register` of the same `(accountId, authPkX)` hits
`AlreadyRegistered`; there is no explicit "revoked" re-registration guard beyond that.
Emits `AuthKeyRevoked`.

State-transition table (per `authKeyId`):

| From | Action | Guard | To | Leaf effect |
|------|--------|-------|----|-----|
| absent (`listIndex==0`) | register | id free, valid pubkey, owner sig, `accountId!=0`, leaf!=0 | active | leaf set at new slot |
| active | rotate (same X) | not revoked, owner sig, valid newPk | active (new `authPkY`/`expiry`) | same slot, leaf rewritten |
| active | rotate (X→X') | not revoked, X' free, owner sig | active under X' (same slot) | same slot, leaf rewritten; old id deleted |
| active | revoke | not revoked, owner sig | revoked (terminal) | slot set to 0 |
| revoked | rotate/revoke | — | revert `AuthKeyAlreadyRevoked` | none |
| revoked | register (same X) | — | revert `AlreadyRegistered` (`listIndex != 0`) | none |

There is **no timelock/epoch gating on the registry mutations themselves** — register/rotate/revoke
take effect immediately and update the tree root synchronously. Epoch/round gating applies only to
when a new root becomes *usable in a proof* via the snapshot mechanism below.

---

## Access Control on Registry Mutations

| Function | Authorization | Enforcing check |
|----------|---------------|-----------------|
| `register` | `msg.sender == expectedOwner` OR allowed relay; plus owner EIP-712 sig |  |
| `rotate` | `msg.sender == account.owner` OR allowed relay; plus owner EIP-712 sig |  |
| `revoke` | `msg.sender == account.owner` OR allowed relay; plus owner EIP-712 sig |  |
| `setOperator` | `onlyOwner` (Ownable2Step); non-zero |  |
| `setAllowedRelays` | `onlyOperator`; non-zero relay |  |
| `initialize` | `initializer`; sets owner via `_transferOwnership` |  |

Relays can submit the transaction but cannot forge authorization — the owner EIP-712 signature is
always verified regardless of caller. Ownership uses OZ `Ownable2StepUpgradeable` (two-step
transfer). Relays are managed in two tiers: the `owner` sets the `operator` (`setOperator`), and
only the `operator` adds/removes relays (`setAllowedRelays`).

---

## In-Circuit Authorization

The operation digest the EdDSA key signs is computed off-circuit  as a keccak256 over
an ABI-encoded message with a string domain tag, then split into two 128-bit halves passed as public
inputs.

```text
// off-circuit
digest256 = keccak256( abi.encode(DOMAIN_STR, chainId, poolAddress, root, nullifiers[], <body>) )
digestHi = digest256 >> 128 // high 128 bits
digestLo = digest256 & (2^128 - 1) // low 128 bits

// in-circuit message hash
approveMsg = Poseidon2T4(domainApprove, digestHi, digestLo) // hash3
```

The `<body>` differs by operation:
- **Transfer** (`ComputeTransferDigest`): `outputs[]` (Output{commitment,
 receiverWrapKey, ct0, ct1, ct2, ct3} where ct3 is `bytes16`), then `viewingKey` (bytes32), then
 `teeWrapKey` (bytes32).
- **Withdrawal/unshield** (`ComputeWithdrawalDigest`): `outputs[]`, then `withdrawal{to,
 tokenID(uint16), amount}`, then `viewingKey`, then `teeWrapKey`.
- **Forced withdraw** (`ComputeForcedDigest`): `withdrawal{to, tokenID, amount}` only —
 **no `outputs[]`, no `viewingKey`, no `teeWrapKey`**.

Domain strings: transfer `"PB:TRANSFER:v1"`, unshield/withdrawal
`"PB:WITHDRAW:v1"`, forced withdraw `"PB:FORCED_WITHDRAW:v1"`. `PB:DEPOSIT:v1` is declared in
`LibDigest` but is not used by live approval digests; deposits use the Poseidon
`DOMAIN_DEPOSIT_REQUEST` request-id path. The digest is split into hi/lo halves before being
supplied as public inputs.
`approveMsg` construction matches the native implementation.

**EdDSA verification**: on BabyJubJub (BN254 twisted
Edwards). Given pubkey `A=(ax,ay)`, signature `(R8, S)`, message `M = approveMsg`:

```text
h = Poseidon2T4(R8x, R8y, ax, ay, M) // hash5
check S < subgroupOrder (CompConstant, sTooLargeBit MUST be 0)
assert A on curve, R8 on curve
A8 = 8*A (3 doublings; cofactor clearing)
assert S*B8 == R8 + h*A8
 B8 = (15836372343211832006828833031571087401945044377577570170285606102491215895900,
 7801528930831391612913542953849263092120765287178679640990215688947513841260)
 subgroupOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041
```

`VerifyEdDSA` enforces unconditionally for forced withdrawals and asserts
`sTooLargeBit==0` plus coordinate equality for the resulting points
(`left.X == right.X` and `left.Y == right.Y`).
`VerifyEdDSAIf` enforces only when the per-transfer-slot `transferActive` selector is 1 (epoch
circuit). The
non-canonical-`S` rejection (`sTooLargeBit == 0`) is mandatory and computed via a Circom-style
CompConstant over 254 bits.

**Membership proof** (`AuthMerkleProof`; helper `computeDomainRoot`): the circuit recomputes the auth root from `authLeaf`,
`AuthLeafIndex`, and `AuthPathElements` using `Poseidon2T4(domainRegNode, left, right)` at each
level, then asserts the `(root, treeNumber)` pair matches one of the public `AuthKnownRoots` /
`AuthKnownTreeNumbersPacked` slots via `AssertRootWithTreeNumberIf`:

```text
authLeaf = Poseidon2T4(domainRegLeaf, SpenderAccountId, AuthPkX, AuthPkY, AuthExpiry)
authRoot = foldMerkle(authLeaf, AuthLeafIndex, AuthPathElements, AuthDepth, domainRegNode)
assertIf(active, exists i: authRoot == AuthKnownRoots[i] AND AuthTreeNumber == knownTreeNumbers[i])
```

The pair match is implemented as `OR_i ((AuthKnownRoots[i] == authRoot) AND (knownTreeNumbers[i] ==
AuthTreeNumber))` where `knownTreeNumbers` is unpacked from `AuthKnownTreeNumbersPacked` at 15
bits/slot. `AuthTreeNumber` is range-checked to `[0,
MaxAuthTreeNumber]`.
Because a revoked or never-registered key has a zero leaf (or no leaf), it cannot produce a
membership proof against a snapshot root that excludes that key. Enforcement is therefore
snapshot-mediated: an older accepted snapshot can still authorize a key until a newer usable
snapshot is cited and accepted. The `(root, treeNumber)` pairing prevents a valid root from one tree
being matched against another tree's number.

Public-input vector for auth (per spend):

| Name | Visibility | Meaning | Notes |
|------|-----------|---------|--------|
| `ApproveDigestHi`, `ApproveDigestLo` | public | high/low 128 bits of the operation digest | (arrays, one per transfer); (scalars) |
| `AuthKnownRoots[]` (≤16) | public | snapshotted auth roots eligible for membership |  |
| `AuthKnownTreeNumbersPacked` | public | 15-bit-packed tree numbers paired with the roots |  |
| `AuthPkX`, `AuthPkY`, `AuthExpiry`, `AuthTreeNumber`, `AuthLeafIndex`, `AuthPathElements`, `AuthSigR8x/y`, `AuthSigS` | private | witness for EdDSA + membership | forced equivalents are private |
| `SpenderAccountId` | **private** / **public** | binds leaf to account; forced exposes it for on-chain owner lookup | — |

Note: spend circuits do **not** independently re-check `block.timestamp <= expiry` on-chain in
`PrivacyBoost`; expiry is bound into the leaf (and thus the snapshotted root) but enforcement is via
membership against the snapshotted auth root, not a separate timestamp gate.

---

## Binding Circuit Auth Roots to the Live Registry (Snapshot / Round Gating)

`AuthKnownRoots` are not free inputs — `PrivacyBoost` validates them against an on-chain snapshot of
the registry, gated by a block-number-derived "round". Snapshots are stored in
`authSnapshots[round][treeNum]`.

- Round derivation: `authSnapshotRoundAt(blockNumber) = startRound + (blockNumber - startBlock) /
 interval`, with a pending-schedule override when `blockNumber >= pendingEffectiveBlock`. The interval used when configuring a schedule MUST be
 in `[MIN_AUTH_SNAPSHOT_INTERVAL=10, MAX_AUTH_SNAPSHOT_INTERVAL=100000]`, else
 `AuthSnapshotIntervalOutOfRange`.
- `_snapshotAuthTreeIfNeeded(round, treeNum)` lazily records `authRegistry.authTreeRoot(treeNum)`
 for the *current* round only (reverts `InvalidAuthSnapshotRound` if `targetRound !=
 currentRound`), after checking the tree exists (`treeNum <= currentAuthTreeNumber`, else
 `InvalidAuthTreeNumber`). Relays can pre-snapshot via
 `snapshotAuthTrees` (`onlyRelay`, batch size `1..MAX_AUTH_ROOTS_PER_PROOF`).
- `_validateAuthKnownRootsSparse(usedAuthRoots, round, allowLazySnapshot)`:
 - sparse set size MUST be `1..MAX_AUTH_ROOTS_PER_PROOF (16)`, else `InvalidBatchConfig`;
 - round MUST be in the accepted window: current, current−1 (grace), `latestSnapshotRound` (if >0),
 or `latestSnapshotRound−1` (if >0), else `InvalidAuthSnapshotRound`;
 - tree numbers MUST be unique (`DuplicateTreeNumber`);
 - each root MUST be non-zero (`RootNotKnown`) and MUST equal
 `authSnapshots[round][treeNum]` (`RootNotKnown`); for the current round only the
 lazy caller may snapshot on the fly, otherwise it MUST already be snapshotted
 (`AuthTreeNotSnapshotted`).
 - Epoch path passes `allowLazySnapshot = true`; the
 permissionless forced-withdraw path passes `false`, so a relay must have
 pre-snapshotted.

This gives a deterministic, bounded window during which a freshly registered/rotated/revoked key's
new root becomes usable: a mutation updates `authRegistry.authTreeRoot` immediately, but a proof can
only cite it once the corresponding round has been snapshotted into `PrivacyBoost`, and only within
the round-window grace period.

## Auth Key Lifecycle Limitations

Auth revocation and expiry are snapshot-mediated, not spend-time global checks:

- **Registry mutation time:** `register`, `rotate`, and `revoke` validate the owner EIP-712
 signature and update the live AuthRegistry tree immediately. `expiry` is checked only at mutation
 time: a non-zero expiry must not already be in the past.
- **Normal epoch spends:** the epoch path may lazily snapshot the current round
 (`allowLazySnapshot=true`). Revocation becomes effective for normal epochs once a proof references
 an accepted snapshot whose root was taken after the revocation. A proof that references an older
 still-accepted snapshot can continue to use the older leaf until that snapshot falls outside the
 accepted round window.
- **Forced withdrawals:** the forced path cannot create snapshots (`allowLazySnapshot=false`). A
 revoked or expired key that remains present in an older accepted snapshot can still authorize a
 forced-withdraw request until a newer relay-created snapshot excluding that leaf is available and
 used, or until the older snapshot is no longer accepted by the round-window rules.
- **Relay operational requirement:** after key rotation or revocation, relays must snapshot the
 updated auth tree for the change to become enforceable in proof validation. If relays stop before
 a newly registered key is snapshotted, that key cannot use forced withdrawal.
- **Expiry semantics:** `expiry` is hashed into the auth leaf, but `PrivacyBoost` does not compare
 it to block time during `submitEpoch` or `requestForcedWithdrawal`. Expiry is therefore a
 registry/admission attribute, not an independent spend-time gate.

Auth lifecycle outcome table:

| Case | Accepted snapshot contains key? | Normal epoch spend | Forced-withdraw request | Forced-withdraw execute | Owner cancellation |
|------|---------------------------------|--------------------|-------------------------|-------------------------|--------------------|
| Key registered, then snapshotted | Yes | Can succeed if digest/proof/nullifiers are valid | Can succeed if caller cites that snapshot and note/root checks pass | Can succeed after `forcedWithdrawalDelay` if nullifiers remain unspent | Owner can cancel after delay using `spenderAccountId` owner lookup |
| Key registered after final relay snapshot | No | Can succeed only if epoch path lazily snapshots current round or a relay snapshots first | Fails with missing auth snapshot because forced path has `allowLazySnapshot=false` | Not reachable |  |
| Key rotated before a newer snapshot | Older snapshot may contain old key; newer live root contains new key | Old key may remain usable through still-accepted older snapshot; new key usable after snapshot | Old key may force-withdraw through older snapshot; new key cannot until snapshotted | Existing pending request can execute unless canceled or nullifier spent | Owner can cancel a pending request after delay |
| Key revoked before a newer snapshot | Older snapshot may still contain revoked key | Revoked key is rejected only when proof uses a snapshot after revocation | Revoked key can still request forced withdrawal through an older accepted snapshot | Existing pending request can execute unless owner cancels or nullifier is spent | Owner can cancel after delay; this is a post-maturity mitigation, not a pre-maturity veto |
| `expiry` has passed after snapshot | Snapshot still contains the same leaf | Can succeed if the cited snapshot is accepted | Can succeed if the cited snapshot is accepted | Can execute after delay if request is valid | Owner can cancel after delay |
| Relay stops snapshotting | Last accepted snapshot remains the latest available root | Keys present in accepted snapshots can continue while the round-window rules accept them | Keys absent from the last snapshot cannot force-exit | Pending requests remain governed by delay/nullifier/cancel checks | Owner cancellation path remains permissionless after delay |

---

## Protocol Invariants (normative)

- An account's owner EOA MUST be the same across all keys of that `accountId`; mismatched owners
 MUST revert.
- Every register/rotate/revoke MUST carry an owner EIP-712 signature over the current account
 `nonce`; the nonce is incremented on each success.
 (The signed struct includes `nonce`; the contract enforces use of the current value, so a
 stale-nonce signature fails verification.)
- A revoked auth key's leaf MUST remain zero and its slot MUST NOT be reused; re-registration of the
 same `(accountId, authPkX)` is blocked by `AlreadyRegistered`.
- An auth pubkey MUST be on BabyJubJub and MUST NOT be low-order
 (`LibBabyJubJub.isValidPublicKey`).
- A spend MUST present a valid EdDSA signature over the `DOMAIN_APPROVE` message AND a Merkle
 membership proof of its leaf against a paired `(root, treeNumber)` known root.
- Non-canonical EdDSA `S` (≥ subgroup order) MUST be rejected.
- Auth-tree node hashing MUST use `DOMAIN_REG_NODE`(5) and leaf hashing `DOMAIN_REG_LEAF`(4),
 distinct from note-tree `DOMAIN_NOTE`(2), in both contract and circuit.
- Proof-cited auth roots MUST equal an on-chain snapshot for an in-window round;
 unknown/duplicate/zero roots MUST revert.

---
