<p align="center">
  <img src="./assets/PB_logo_primary_symbol.png" alt="Privacy Boost" width="120" />
</p>

<h1 align="center">Privacy Boost Protocol</h1>

<p align="center">
  Onchain Privacy Infrastructure for Enterprises
</p>

<p align="center">
  <a href="https://www.privacyboost.io/">Website</a> &middot;
  <a href="https://docs.privacyboost.io/">Docs</a> &middot;
  <a href="LICENSE">Apache 2.0</a>
</p>

---

Privacy Boost enables private deposits, transfers, and withdrawals of ERC-20 tokens on any EVM chain. Zero-knowledge proofs (Groth16/BN254) hide sender, recipient, amount, and token type -- while preserving full self-custody.

This repository contains the **smart contracts** and **ZK circuits** that make up the core protocol.

## Overview

```
contracts/
  src/
    PrivacyBoost.sol        Core shielded pool
    AuthRegistry.sol        EdDSA key registry
    TokenRegistry.sol       Token ID mapping
    PortalDelegate.sol      EIP-7702 delegate for portal deposit addresses
    gateway/                External call gateway
    verifier/               Groth16 proof verifiers
    hash/                   Poseidon2 and authorization-tree hashing
    interfaces/             Shared types, constants and contract interfaces
    lib/                    Epoch, deposit, portal, gift, digest and BabyJubJub libraries

frontend/
    epoch_circuit.go        Batched transfer & withdrawal circuit
    deposit_epoch_circuit.go  Batched deposit circuit
    forced_withdraw_circuit.go  Emergency exit circuit (client-side)
```

## Circuit source

The circuit source matches backend release `ceremony/v0.0.5` (commit `b19e261440c38af65498a3e1aed0fab6e2428282`), apart from the public Go module import path. It uses gnark v0.16.3 and gnark-crypto v0.21.0 and requires Go 1.25.13 or later. This identifies the circuit source for ceremony round 3, not a new contract deployment or a re-audit of this repository.

## Key Properties

- **Self-custodial** -- Users can always exit via forced withdrawal using only their keys and onchain data, no server needed
- **Private** -- UTXO commitments hide all transfer details
- **High throughput** -- Epoch batching amortizes proof verification across many transactions
- **EVM compatible** -- Works with existing wallets and ERC-20 tokens

## License

[Apache 2.0](LICENSE) -- Copyright 2026 Sunnyside Labs Inc.
