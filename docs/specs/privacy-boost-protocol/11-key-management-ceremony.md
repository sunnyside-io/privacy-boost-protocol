# 11. Key Management & Trusted-Setup Ceremony

This section specifies the Groth16 trusted-setup ceremony that produces the proving/verifying keys
for every circuit and the deterministic encoding of those verifying keys into on-chain verifier
contracts. It does not specify server key custody, deployment attestation, application deployment, or
operator infrastructure.

**Evidence model.** Ceremony provenance is publicly inspectable through the Sunnyside Labs ceremony
repository and the production public verification bundle described below. Deployment evidence for
operator infrastructure is maintained outside this protocol specification.

The protocol uses the gnark Groth16 backend over BN254. Setup is a two-phase MPC: a universal Phase
1 (Powers of Tau, reused from the public Perpetual Powers of Tau ceremony) plus a per-circuit Phase
2. The per-circuit Phase 2 is the only ceremony Privacy Boost runs itself; it is implemented in
`circuit-setup/`.

## 1. Circuit Set and Setup Inputs

Each `(circuit type, shape)` tuple is a distinct R1CS and therefore a distinct Phase 2 transcript,
proving key (pk), and verifying key (vk). Three circuit types exist, selected by the `type` field of
a circuit spec.

| Type | Constructor | Verify fn / VK contract prefix | configKey / size key |
|------|--------------------------------------|--------------------------------|----------------------|
| `epoch` | `NewEpochCircuit(batch, maxInPerTx, maxOutPerTx, depth, authDepth, feeTokens, maxTrees, maxAuthTrees)` | `verifyEpoch` / `VKEpoch_<configKey>` | `configKey = (batch << 12) \| (maxInPerTx << 6) \| maxOutPerTx` |
| `deposit` | `NewDepositEpochCircuit(batch, depth, maxTrees)` | `verifyDeposit` / `VKDeposit_<batch>` | `batch` |
| `forced` | `NewForcedWithdrawCircuit(maxInputs, depth, authDepth, maxTrees, maxAuthTrees)` | `verifyForcedWithdraw` / `VKForced_<maxInputs>` | `maxInputs` |

The registered circuit profiles use `depth=24` for the note tree, `authDepth=20` for the auth
registry, `maxTrees=16`, and `maxAuthTrees=16`. Epoch profiles set `maxFeeTokens=4`; the forced
profile is `f8` with `maxInputs=8`.

The production ceremony is
`id="prod-ceremony-2026-01"`, `accessMode="public"`, `production=true`. Its circuit matrix is:
**fourteen** epoch shapes — `s1,s4,s8,s16,s32,s64,s100`, `m1,m4,m8`, `l1,l4,l8`, `sp1`; three
deposit shapes `d1,d8,d32` (`batchSize=1,8,32`); and one forced shape `f8` (`maxInputs=8`). Every
production epoch circuit uses `depth=24, authDepth=20, maxFeeTokens=4, maxTrees=16, maxAuthTrees=16`
(the `s/m/l` families differ in `maxInputsPerTransfer`/`maxOutputsPerTransfer`, encoded into
`configKey`).

**Phase 1 source.** Privacy Boost reuses the public Perpetual Powers of Tau Phase 1 artifact
(`phase1.sourceUrl` =
`https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_{power}.ptau`).
The required Phase 1 power is auto-derived from the compiled circuit's constraint count, not
configured (`phase1Power` config field is deprecated/ignored). The fetched `.ptau` MUST match a
pinned SHA-256 from `phase1.expectedSha256ByPower` (a required map); the production config pins
powers **14 through 23** (ten entries).

> **INV-SETUP-1.** The Phase 1 artifact for each circuit MUST match the pinned
> `expectedSha256ByPower[power]`; otherwise setup/verification fails. This binds the universal CRS
> to a known public ceremony and prevents coordinator substitution.

## 2. Phase 2 Transcript Mechanics

Phase 2 is a gnark-native MPC chain. The
domain-separation tag sealing Phase 1 into Phase 2 commons is the literal byte string below, used
identically in setup, finalize, and offline re-derivation.

```text
commons = Phase1.Seal([]byte("privacy-boost-phase1"))
```

**Origin (`_c0.ph2`).** `Engine.InitializeAndCapture`
loads Phase 1, seals commons, loads the R1CS, asserts Phase 1 capacity, then `ph2.Initialize(&r1cs,
&commons)`. Capacity check:

```text
requiredN = nextPow2DomainSize(r1cs.GetNbConstraints)
require len(commons.G1.Tau) >= (requiredN*2) - 1
```

**Contribution.** Each accepted contribution is one call to `ph2.Contribute`, applying a fresh random secret. The contributor runs
this **locally** and uploads only the resulting `.ph2`; the secret never leaves the contributor's
machine. The coordinator never sees contribution randomness — it only verifies the transition.

**Transition verification.** The coordinator validates `prev.Verify(&next)`, i.e. the new artifact
is a valid single-contribution successor of the previous accepted artifact.

> **INV-SETUP-2.** A contribution is accepted only if `prev.Verify(next)` succeeds; state does not
> advance otherwise. The full acceptance
> predicate also requires: active GitHub session, queue-head + lease acquisition, and successful
> persistence.

**Key extraction (finalize).** `ExportKeysFromPhase2`
 re-seals commons, deserializes the ordered
contribution chain, and calls `mpcsetup.VerifyPhase2(&r1cs, &commons, nil, contribs...)`
 which re-verifies the entire chain and returns
`(pk, vk)`. A cached-evaluations fast path (`ExportKeysFromPhase2WithCachedEvaluations`) walks the same chain with per-step
`prev.Verify(next)` and `Seal`s the head with the
cached setup evaluations (`prev.Seal(&commons, evals, nil)`). Keys are written with gnark's canonical
`pk.WriteTo` / `vk.WriteTo`.

> **INV-SETUP-3 (1-of-N trust).** Soundness of the Groth16 toxic-waste assumption holds if **at
> least one** Phase 2 contributor's secret was honestly generated and discarded. Because
> contributions are computed locally and only
> verified transitions are accepted, any single honest participant in the published transcript
> suffices. A verifier need not trust the coordinator, only that one transcript entry was honest,
> and that Phase 1 matches the pinned public ceremony.

## 3. Public Bundle and Manifest (the verification artifact)

Finalize emits a deterministic, portable public bundle under `<stateDir>/public`:

```text
manifest
configuration snapshot
circuits/<id>/origin.ph2
circuits/<id>/contributions/<index>.ph2
circuits/<id>/final.ph2
circuits/<id>/keys/<id>.pk
circuits/<id>/keys/<id>.vk
```

The V1 production ceremony is documented in the public ceremony repository:
`https://github.com/sunnyside-io/privacy-boost-ceremony`. Reviewers should use that repository's
`PUBLIC_VERIFICATION.md` and `ceremony verify-public` command, not the protocol-code repository, to
verify ceremony provenance.

The V1 production ceremony artifacts are published under the `prod-20260401` release label:

- Public verification bundle: `https://file.ceremony.privacyboost.io/prod-20260401-public.tar.gz`
- Derived key bundle: `https://file.ceremony.privacyboost.io/prod-20260401-keys.tar.gz`

The public verification bundle is the verifier-key provenance artifact for the V1 circuit set. It
contains the ceremony manifest, configuration snapshot, ordered Phase 2 transcript artifacts,
participant contribution records, proving keys, and verifying keys. The derived key bundle is a
convenience artifact; the public verification bundle is the authoritative provenance source.

Deployed verifier equivalence is verified from the public ceremony bundle together with the
deployment verifier map for the target network. That map associates each deployed verifier address
with the VK derived from the public bundle, plus the archive hashes used for the release.

Manifest schema, version pinned to
`ManifestVersion = 1`:

| Top-level field | Type | Meaning |
|-----------------|------|---------|
| `version` | int | MUST equal 1 |
| `ceremonyId` | string | Ceremony id |
| `generatedAt` | string | Generation timestamp |
| `configSnapshotPath` / `configSnapshotSha256` | string | Path + SHA-256 of the ceremony configuration snapshot |
| `bundleRootSha256` | string | Deterministic hash over all bundle files except the manifest itself |
| `participants` | []string | Sorted GitHub-login participant set |
| `totalContributions` | int | Sum of per-circuit contributions |
| `circuits` | []CircuitManifest | Per-circuit commitments |

Per circuit:
`circuitId`, `circuitSpecJson` + `circuitSpecSha256`, `phase1Sha256`, `derivedPhase1Power`,
`r1csSha256`, `originPhase2Sha256`, `finalPhase2Sha256`, **`pkSha256`** / **`vkSha256`**,
`contributionCount`, and an ordered `contributions[]` (with
`originPhase2Path`/`finalPhase2Path`/`pkPath`/`vkPath` recorded alongside the hashes). Each
contribution record (`ContributionManifest`) carries `index`, `participant`,
`createdAt`, `inputPath`, `inputSha256`, `outputPath`, `outputSha256`, and a `transcriptHash`.

**Bundle root**:
```text
for each file f outside the manifest:
 entry = "<relpath_slash_normalized>:<sha256hex(f)>"
sort(entries); bundleRoot = sha256( join(entries, "\n") )
```

**Transcript linkage hash**:
```text
transcriptHash = sha256( inputSha256 + "|" + outputSha256 + "|" + participant )
```

> **Participant identity** is the GitHub login string. It is bound into each `transcriptHash`, so
> contribution records cannot be reassigned without detection.

**Offline verification** has two depths. `VerifyIntegrity`
 recomputes every digest, the bundle
root, the config-snapshot hash,
the transcript adjacency chain (`inputSha256 == prior outputSha256`), per-step index ordering
(`rec.Index == i+1`), the per-step
`transcriptHash` recomputation, and
reconstructs the participant set and total count from circuit contents (not trusting the manifest
counters). The deeper `Verify` additionally
**re-derives pk/vk from `(phase1, R1CS, ordered Phase2 outputs)`** and compares hashes to the
manifest, recompiling the R1CS from `circuitSpecJson`
 and asserting `RequiredPhase1Power ==
derivedPhase1Power`.

## 4. Verifying Keys → On-chain Verifier Registries

The ceremony bundle contains gnark binary VKs at `circuits/<id>/keys/<id>.vk`. Release tooling
loads each VK with `vk.ReadFrom`, derives a JSON/Solidity representation, deploys the VK data into
SSTORE2-style data contracts, and registers the resulting pointers with the deployed verifier
registry for the relevant circuit shape.

**VK field layout registered on-chain**.
The deployed verifier registry stores a 448-byte `vkConstants` blob containing α (G1) and the
**negated** β, γ, δ (G2), plus separate SSTORE2 pointer arrays for the IC vector's X and Y
coordinates. G2 coordinates are stored EIP-197 order (A1 then A0, i.e. `x.c1, x.c0`); the negation
of β/γ/δ is what makes the pairing accumulate to identity:

| VK element | Source field | Registered data |
|------------|-------------------------------|-----------|
| α (G1) | `G1.Alpha.X,.Y` | `AlphaX, AlphaY` |
| −β (G2) | `(-G2.Beta)` | `BetaX1,X0,Y1,Y0` |
| −γ (G2) | `(-G2.Gamma)` | `GammaX1,X0,Y1,Y0` |
| −δ (G2) | `(-G2.Delta)` | `DeltaX1,X0,Y1,Y0` |
| IC (G1[]) | `G1.K[i].X,.Y` | `ICX[], ICY[]` |

The deployed verifier contracts (`Groth16EpochVerifier`, `Groth16DepositVerifier`, and
`Groth16ForcedVerifier`) select a registered VK by circuit shape:

- epoch: `(maxTransfers, maxInputsPerTransfer, maxOutputsPerTransfer)`;
- deposit: `batchSize`;
- forced withdrawal: `maxInputs`.

Each registered VK stores SSTORE2 pointers for IC X coordinates, IC Y coordinates, and the 448-byte
`vkConstants` blob (14 field elements: α(x,y), then −β, −γ, −δ each as `(x1,x0,y1,y0)`), plus
`icLen`. At verification time `_verifyProof` loads those blobs with `extcodecopy`, checks
`publicInputs.length + 1 == icLen`, rejects public inputs outside the BN254 scalar field, computes
`vk_x = IC[0] + Σ publicInputs[i]·IC[i+1]` via precompiles `0x07`/`0x06`, and runs the 4-pairing
check via precompile `0x08`, reverting `ProofInvalid` on failure.

> **INV-VK-1.** The on-chain verifier's α/β/γ/δ/IC are a pure deterministic re-encoding of the
> ceremony VK; they carry no independent secret. The encoding can be reproduced by re-running
> the published bundle and comparing the registered VK data against the deployed verifier map.

## 5. What a Verifier Must Trust

| Trust assumption | Mechanism that minimizes it | Residual trust |
|------------------|-----------------------------|----------------|
| Groth16 setup not back-doored | Per-circuit Phase 2 MPC; published transcript; `verify-public` re-derives pk/vk from transcript | At least 1 honest Phase 2 contributor (INV-SETUP-3) |
| Phase 1 CRS honest | Reuse of public Perpetual Powers of Tau, SHA-256 pinned (INV-SETUP-1) | The external PPoT ceremony's 1-of-N |
| On-chain verifier matches ceremony VK | Deterministic re-encoding, reproducible via `prover setup ceremony` (INV-VK-1) | Correctness of the re-encoder (reviewable, deterministic) |

The ceremony's net effect is to convert "trust the operator generated honest keys" into "trust one
of the public contributors, and verify everything else offline against a hash-committed public
bundle."

---
