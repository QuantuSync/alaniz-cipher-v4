# Project status

Last updated: May 2026.

## Verification status of each claim

Each claim made in the documentation is one of:

- ✓ **Verified**: backed by empirical data in this repo, reproducible.
- ⚠ **Partially verified**: components verified, full integration pending.
- 🟡 **Theoretical**: argued mathematically but not empirically tested.
- ❌ **Open**: stated as expected but not validated.

### Functionality

| Claim | Status | Evidence |
|-------|--------|----------|
| Scheme works end-to-end at (d=6, e=17, p=2⁶¹-1, tetra) | ✓ | `experiments/reproduce_e2e_d6.py`, 10 seeds verify=True |
| Scheme works end-to-end at (d=8, e=17) | ⚠ | Components verified; full pipeline timeout |
| Scheme works end-to-end at (d=12, e=17) — recommended params | ⚠ | All components individually verified, F4 RREF requires SageMath (matrix 4368×6188 over F_(2⁶¹-1)). State persisted in `experiments/data/d12_*.pkl` |
| Scheme works at non-tetra substrates (double_tet, octahedron) | ⚠ | Verified for small p (d=2,3), not at PQ-128 |

### Security analysis

| Claim | Status | Evidence |
|-------|--------|----------|
| v3 parameters (d=6, e=17) give ~74 bits classical | ✓ | `experiments/reproduce_hilbert_table.py` |
| Cubic system of decryptor is semi-regular at d=6 | ✓ | `experiments/reproduce_semireg_d6.py`, kernel=42 = 210-168 |
| Cubic system is semi-regular at d=12 | ❌ | Cannot verify in this environment (requires SageMath RREF at D=5) |
| Public system regularity matches Hilbert + gap | ✓ | 13 instances at d=2,3 (`reproduce_dreg_d23.py`, `reproduce_attack_public.py`) |
| Gap regression `gap ≈ -0.5n + 0.67d + 1.33e - 0.83` | ✓ | RMS residual 0.24 on 9 datapoints |
| Gap regression extrapolates correctly to d=12 | ❌ | Open question; recommended to verify at d=4-8 first |
| Specific attacks (Beullens, MinRank) fail | ✓ | Earlier experiments (exp11-14 in development logs) |
| σ_v non-injectivity does NOT enable side-channel attack | 🟡 | N=30 χ² tests show no significant correlation; needs larger N |
| Syzygy-hiding argument (decryptor's syzygies do not lift) | 🟡 | Structural argument formalized in `findings/SYZYGY_PROOF.md`, no rigorous algebraic proof |
| IND-CPA reduction under CSI | 🟡 | Sketched in `findings/CSI_AND_INDCPA.md`, not formalized |
| IND-CCA via Fujisaki-Okamoto | 🟡 | Standard transformation; no specific obstruction identified |

### Quantum security

| Claim | Status | Evidence |
|-------|--------|----------|
| Quantum F4 cost model (ω=2.0 conservative, ω=1.5 aggressive) | ✓ | Computational, `reproduce_quantum_analysis.py` |
| `pq128-q-cons` parameters give 147 bits quantum-conservative | ✓ | Computational under standard model |
| ω=1.5 is plausible upper bound on quantum F4 speedup | 🟡 | Heuristic; literature on quantum F4 is sparse |

### Implementation quality

| Claim | Status | Evidence |
|-------|--------|----------|
| Reference implementation correctly implements spec | ✓ | Verified by 10-seed roundtrip at d=6 |
| Implementation is timing-constant | ❌ | NOT timing-constant. Production deployment requires constant-time σ⁻¹. |
| Implementation is memory-safe | ⚠ | Python implementation; production deployment requires C/Rust with safety review |
| Implementation passes static analysis | ❌ | No static analysis performed |

## What works in this environment vs. what doesn't

**Works**:
- Pure Python implementation runs correctly with `numpy` + `galois`
- Reproducible experiments at d ≤ 6, p ≤ 257 (small primes) or p = 2⁶¹-1 with timing ~100s per decrypt
- Generation of all tables in `findings/EXPERIMENTAL_FINDINGS.md`

**Does NOT work in this environment** (but is straightforward elsewhere):
- F4 RREF of 4368×6188 over F_(2⁶¹-1) — requires SageMath or Magma. Estimated time on a modest workstation: 2–5 minutes.
- Direct F4 attack at d ≥ 4 — Macaulay matrix exceeds available memory.
- Side-channel statistical analysis at N ≥ 500 trials — sandbox time limits.

## Priority for external collaboration

If you want to help validate or extend this work, the highest-impact tasks are:

1. **Run `pending_validations/sage_d12_complete.sage`** (5 minutes of SageMath compute). Confirms verify=True at the recommended parameters.

2. **Empirically measure D_reg at d=4-8** using Magma's Gröbner basis solver. Validates the gap regression extrapolation.

3. **Independent review of `findings/SYZYGY_PROOF.md`** by a multivariate cryptography expert. The argument is structural, not formal.

4. **Implementation of optimized C/Rust version** with constant-time σ⁻¹. Necessary for any deployment context.

5. **Larger-N side-channel study** (1000+ ciphertexts per key, multiple keys). Confirms or refutes the marginal ρ(v_0, v_3) = -0.38 observation.

See [ROADMAP.md](ROADMAP.md) for the full priority list with rationale.

## Project history

See [HISTORY.md](HISTORY.md) for the version evolution v1 → v4r3 and key decisions.
