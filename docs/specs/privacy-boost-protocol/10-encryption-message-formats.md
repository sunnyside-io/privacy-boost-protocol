# 10. Encryption & Message Formats (ECDH, AES-GCM, Note/Transfer Encryption)

This section specifies the note-encryption format published on-chain in `Output` and
`DepositCiphertext`. The format uses 3-way ECDH over secp256k1 plus AES-256-GCM so that both the
operator-side decryptor and the note recipient can independently recover each output note's secret
preimage. Transfer/unshield `Output[]` ciphertext is bound into the EdDSA approval digest; deposit
`DepositCiphertext[]` is event-associated with the `depositRequestId`.

Transport encryption, server API envelopes, operator key custody, and deployment attestation are
outside this protocol specification.

---

## 1. Note Encryption — 3-Way ECDH (secp256k1)

### 1.1 Curve, keys, and primitives

| Element | Value | Notes |
|---|---|---|
| Curve | secp256k1 | Used for viewing-key ECDH |
| KDF | HKDF-SHA256, **nil salt** | 32-byte output; exact `info` bytes below |
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag | Standard AES-GCM wire format |
| Operator note key | secp256k1 keypair; public key encoded compressed (33 bytes) | Distribution and custody are deployment concerns |
| Sender viewing key | secp256k1 keypair held by the sender |  |
| Recipient viewing key | secp256k1 keypair; public key is the recipient's published address-book entry |  |

### 1.2 Why dual-path (3-way) ECDH

A single ciphertext must be decryptable by two parties with *different* private keys: the
operator-side decryptor (to process requests before sequencing) and the recipient (to later
discover and, if the operator is unavailable, force-withdraw the note). The construction wraps a
fresh root key under independently-derived key-encryption keys. Deposit ciphertexts use that root
key directly, while transfer outputs derive per-output content keys from it. A fresh blinding scalar
`random` is mixed into every ECDH to blind the on-chain viewing key.

### 1.3 Key derivation

A fresh scalar `r` blinds the sender viewing public key before publication:

```math
\texttt{viewingKey} = x(r \cdot \texttt{SenderViewingPubKey}).
```

The sender derives two ECDH shared secrets with the same blinded scalar:

```math
\begin{aligned}
\texttt{teeSharedX} &= x(\texttt{SenderViewingPrivKey} \cdot r \cdot
  \texttt{OperatorEncPubKey}), \\
\texttt{receiverSharedX} &= x(\texttt{SenderViewingPrivKey} \cdot r \cdot
  \texttt{RecipientViewingPubKey}).
\end{aligned}
```

HKDF `info` labels are exact ASCII bytes: **`"tee-enc-key"`** for the operator wrap key and
**`"receiver-enc-key"`** for the recipient wrap key. `PadTo32` left-pads the big-endian X coordinate
to 32 bytes before HKDF. A fresh 32-byte `rootKey` is wrapped for the operator as:

```math
\texttt{teeWrapKey} = \texttt{rootKey} \oplus
  \textsf{HKDF}(\texttt{PadTo32(teeSharedX)}, \texttt{info="tee-enc-key"}).
```

For deposits, the same root key encrypts the deposit plaintext and is wrapped for the recipient with
the receiver ECDH key. For transfers, each output derives its own content key from the root key and
wraps that per-output key to the recipient.

**On-chain, only the X coordinate of `viewingKey` is stored.** Decryptors recompute the point by
trying both Y parities (`0x02`/`0x03` compressed prefixes) and accept whichever passes the GCM tag.

Decryption recovery:

| Party | Recovers key material as | Notes |
|---|---|---|
| Operator decryptor | `rootKey = teeWrapKey XOR HKDF(X(viewingKeyPoint * operatorEncPrivKey), "tee-enc-key")` | Root key for deposit ciphertexts and transfer per-output derivation |
| Transfer recipient | `outKey_i = receiverWrapKey_i XOR HKDF(X(viewingKeyPoint * RecipientPriv), "receiver-enc-key")` | Per-output transfer content key |
| Deposit recipient | `rootKey = receiverWrapKey XOR HKDF(X(viewingKeyPoint * RecipientPriv), "receiver-enc-key")` | Deposit content key |

### 1.4 AES-256-GCM parameters

```text
nonce(outputIdx) = 12 bytes; bytes[0:8]=0x00, bytes[8:12]=big_endian_uint32(outputIdx)
AAD = none (empty)
tag = 16 bytes (GCM default)
key = 32 bytes (content key from the derivation above)
```

**INVARIANT:** the nonce is
derived from `outputIdx` only and is **not** key-bound, so a given content key MUST encrypt at most
one plaintext. This is *not* enforced by an assertion; it is satisfied by construction because every
encryption draws a fresh root key and transfers derive a fresh per-output key. This is a
caller obligation; reuse breaks GCM catastrophically.

### 1.5 Deposit / shield ciphertext

Plaintext (**62 bytes**):

| Offset | Len | Field | Encoding |
|---|---|---|---|
| 0 | 32 | recipientMPK (master public key, not account id) | big-endian, PadTo32 |
| 32 | 2 | tokenId | big-endian uint16 |
| 34 | 12 | amount | last 12 bytes of big-endian (96-bit) |
| 46 | 16 | noteRnd | last 16 bytes (128-bit) |

GCM output = 62B ciphertext + 16B tag = **78B**. Packed into the on-chain `DepositCiphertext`:

| Field | Type | Bytes | Meaning |
|---|---|---|---|
| viewingKey | bytes32 | 32 | blinded sender viewing key (X only) |
| teeWrapKey | bytes32 | 32 | `rootKey XOR teeEncKey` |
| receiverWrapKey | bytes32 | 32 | `rootKey XOR receiverEncKey` |
| ct0 | bytes32 | 32 | ciphertext[0:32] |
| ct1 | bytes32 | 32 | ciphertext[32:62] + 2B zero pad |
| ct2 | bytes16 | 16 | GCM tag |

Total 176B. Deposits/shields use one fresh content key per `DepositCiphertext`; a multi-commitment
deposit request publishes one ciphertext per commitment and uses its commitment index as
`outputIdx`/nonce.

### 1.6 Transfer / unshield output ciphertext

Plaintext (**94 bytes**):

| Offset | Len | Field | Encoding |
|---|---|---|---|
| 0 | 32 | senderMPK | PadTo32 |
| 32 | 32 | recipientMPK | PadTo32 |
| 64 | 2 | tokenId | big-endian uint16 |
| 66 | 12 | amount | last 12 bytes |
| 78 | 16 | noteRnd | last 16 bytes |

GCM output = 94B + 16B = **110B**. Packed into on-chain `Output`:

| Field | Type | Bytes | Meaning |
|---|---|---|---|
| commitment | uint256 | 32 | note commitment (Merkle leaf) |
| receiverWrapKey | bytes32 | 32 | per-output recipient key wrap |
| ct0 | bytes32 | 32 | ciphertext[0:32] |
| ct1 | bytes32 | 32 | ciphertext[32:64] |
| ct2 | bytes32 | 32 | ciphertext[64:94] + 2B zero pad |
| ct3 | bytes16 | 16 | GCM tag |

Total 176B/output. The transfer-level `viewingKey` +
`teeWrapKey` are carried once in the parent `Transfer` struct
 and shared by
all its outputs; only `receiverWrapKey` and the ct fields are per-output. The on-chain calldata
`Output` struct does **not** repeat `viewingKey`/`teeWrapKey` per output — they live on `Transfer`.

---

## 2. Transfer Output Keying

Transfer/unshield outputs derive a distinct AES content key for each output from the transfer root
key (`rootKey`). The transfer-level `teeWrapKey` lets the operator recover the root key once, while
each recipient receives only the content key for its own output through `receiverWrapKey_i`. Deposits
use the single-key deposit format described above.

### 2.1 Per-output key derivation

```text
TRANSFER_OUTPUT_KEY_INFO = "pb-transfer-output-v2" # exact ASCII, 21 bytes
info_i = TRANSFER_OUTPUT_KEY_INFO || big_endian_uint32(outputIdx) # 25 bytes
outKey_i = HKDF-SHA256(secret=rootKey, salt=nil, info=info_i, L=32)
```
All implementations use the same `"pb-transfer-output-v2" || uint32_be(outputIdx)` info bytes.
`outputIdx` MUST be encodable as a big-endian uint32; encoders must reject values outside that range.

### 2.2 Transfer encryption and wrapping

| Step | Computation | Notes |
|---|---|---|
| Content key | `outKey_i = DeriveTransferOutputKey(rootKey, i)` | per-output HKDF key |
| Encrypt | `(ct, tag) = AES-256-GCM(outKey_i, plaintext94, nonce(i))` | 12-byte deterministic nonce for that output index |
| Receiver wrap | `receiverWrapKey_i = outKey_i XOR receiverEncKey` | recipient-specific wrap |
| Operator wrap | `teeWrapKey = rootKey XOR teeEncKey` | transfer-level wire field |

The operator-side decryptor unwraps the **root** key once (transfer-level `teeWrapKey`) and re-derives every
`outKey_i`. A recipient unwraps only `outKey_i` and cannot
derive any sibling `outKey_j` because HKDF is one-way and the root key never reaches them.
`receiverEncKey` is the per-recipient HKDF("receiver-enc-key") value from the ECDH derivation above.

If an output has no recipient-side decryptor, `receiverWrapKey` MUST be `0x00..00` and MUST NOT
publish `outKey_i XOR 0`. Recipient-side decryption unwraps only the recipient's own output key.

**Scope:** per-output keying applies to transfer/unshield/fee outputs only. Deposits/shields use the
single-key deposit format described above.

---

## 3. On-chain digest binding (integrity of ciphertext)

For transfer and withdraw flows, encrypted output metadata is bound into the EdDSA-signed approval
digest, so a malicious sequencer cannot substitute `Output[]` ciphertext without invalidating the
proof. Each approval digest is
`keccak256(abi.encode(...))` over ABI-encoded fields, split into `(hi, lo)` 128-bit halves
for BN254 field
compatibility, then re-hashed **in-circuit** as `Poseidon(DOMAIN_APPROVE, digestHi, digestLo)` where
`DOMAIN_APPROVE` is a Poseidon domain tag. Domain strings:

| Flow | Domain | ABI-encoded fields, in order (incl. ciphertext) | Notes |
|---|---|---|---|
| Transfer | `"PB:TRANSFER:v1"` | domain, chainId, pool, root, nullifiers, **outputs**, **viewingKey**, **teeWrapKey** |  |
| Withdraw | `"PB:WITHDRAW:v1"` | domain, chainId, pool, root, nullifiers, **outputs**, withdrawal{to,tokenId,amount}, **viewingKey**, **teeWrapKey** |  |
| Forced withdraw | `"PB:FORCED_WITHDRAW:v1"` | domain, chainId, pool, root, nullifiers, withdrawal — **no ciphertext** |  |

`outputs` here is the full `Output[]` including `receiverWrapKey` and `ct0..ct3`, so the per-output ciphertext is digest-bound. **Both the
transfer and the withdraw digest bind `outputs`, `viewingKey`, and `teeWrapKey`** — the only
structural difference is that the withdraw digest also includes the public `withdrawal` tuple
between `outputs` and `viewingKey`. Forced withdrawal carries no encrypted metadata, so its digest
omits `outputs`/`viewingKey`/`teeWrapKey`.

Deposits use the Poseidon request-id path:

```text
depositRequestId =
  Poseidon2T4.hash8(
    DOMAIN_DEPOSIT_REQUEST,
    chainId,
    pool,
    depositor,
    tokenId,
    totalAmount,
    nonce,
    commitmentsHash
  )
```

with `DOMAIN_DEPOSIT_REQUEST`. `LibDigest` also declares
`DEPOSIT_DOMAIN = "PB:DEPOSIT:v1"` as a reserved keccak domain, but live deposit processing does
not consume it as an approval digest. Deposit ciphertexts are event-associated with the request id;
on-chain deposit binding is through commitments, total amount, nonce, and `depositRequestId`.

For transfer/withdraw `Output[]`, the approval digest binds the published output bytes, including
`receiverWrapKey` and `ct0..ct3`; the contract does **not** separately assert ciphertext length or
the 2-byte zero padding of `ct2`. For deposit `DepositCiphertext[]`, no keccak/EdDSA approval digest
binds the ciphertext bytes; the ciphertext is carried in the `DepositRequested` event. A malformed
transfer/withdraw ciphertext that is nevertheless
signed and proof-consistent can only brick the affected note, not corrupt others.

---

## 4. On-chain Summary

| Artifact | Location | Curve / AEAD |
|---|---|---|
| `Output` (transfer/withdraw note secrets) | **on-chain** calldata, approval-digest-bound | secp256k1 3-way ECDH + AES-256-GCM |
| `DepositCiphertext` (deposit note secrets) | **on-chain** calldata/event data, emitted alongside `depositRequestId` | secp256k1 3-way ECDH + AES-256-GCM |
| Blinded `viewingKey`, `teeWrapKey`, `receiverWrapKey` | **on-chain** | secp256k1 |

---
