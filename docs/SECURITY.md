# Alaniz Cipher v4r3 — security analysis

This document summarizes the security analysis. For detailed technical content see [findings/SYZYGY_PROOF.md](findings/SYZYGY_PROOF.md), [findings/CSI_AND_INDCPA.md](findings/CSI_AND_INDCPA.md), and [findings/EXPERIMENTAL_FINDINGS.md](findings/EXPERIMENTAL_FINDINGS.md).

## Summary

The security of v4r3 is **heuristic**, like all multivariate cryptography. It rests on the difficulty of solving the public polynomial system

    σ_v(arg_v(α)) - c_v = 0    for v = 0, ..., n-1

which is a system of `n·d` polynomial equations of total degree `3e` in `d_msg = d` variables over F_p.

The best-known attack is computing a Gröbner basis via F4 or F5 followed by linearization. The cost is bounded below by the Bardet-Faugère formula:

    cost ≥ ω · log₂ C(d + D_reg, d)

where `D_reg` is the regularity degree predicted by the Hilbert series of a semi-regular system of `n·d` cubics of degree `3e`, and `ω` is the matrix-multiplication exponent (2.37 classical, ~2.0 quantum).

## Threat model

We consider:
1. **Classical adversary**: polynomial-time Turing machine.
2. **Quantum adversary (conservative)**: quantum computer that can run F4 with reduced matrix-multiplication exponent ω ≈ 2.0.
3. **Quantum adversary (aggressive/paranoid)**: ω ≈ 1.5, which is an upper bound on plausible quantum speedups on F4.

We do NOT claim resistance to:
- A breakthrough algorithm that bypasses Gröbner basis computation entirely.
- Side-channel attacks on implementations (timing, power, EM).
- Implementation bugs in deployments.

## Hard problem

We define the **Cubic-Sheaf-Inversion (CSI) problem** as follows:

> **CSI**: Given public parameters `(K, p, d, e, L, A, B, C, H_0)` and a ciphertext `(r, c)`, recover the plaintext `α ∈ F_p^d` such that `(r, c) = Enc(pk, α)`.

The security of v4r3 reduces (heuristically) to the assumption that CSI requires Gröbner basis computation on the public polynomial system, with cost no less than the Bardet-Faugère bound.

We give a sketch of IND-CPA reduction under the CSI assumption in [findings/CSI_AND_INDCPA.md](findings/CSI_AND_INDCPA.md). IND-CCA security is achievable via the standard Fujisaki-Okamoto transformation.

## Why the trapdoor is non-trivial to invert

The legitimate decryptor uses `β_v` to invert σ_v at each vertex, reducing the problem from degree `3e` to degree 3. The attacker without `β_v` faces the full degree-`3e` system.

We argue formally in [findings/SYZYGY_PROOF.md](findings/SYZYGY_PROOF.md) that the syzygies of the decryptor's cubic system (which would seemingly give shortcuts) cannot be lifted to syzygies of the attacker's system without the secret `β_v` and `L`. The lift requires symbolic inversion of σ, which requires the secret.

This is the same kind of structural argument that all multivariate schemes use; it is not a formal reduction but a defensible heuristic.

## Empirical validation of the Hilbert bound

We empirically measured the actual regularity degree `D_reg` of the public polynomial system at small scales (where the Macaulay matrix fits in memory):

| substrate | d | e | Hilbert prediction | empirical | gap |
|-----------|---|---|---------------------|-----------|-----|
| tetra (n=4) | 2 | 5 | 17 | 22 | +5 |
| double_tet (n=5) | 2 | 5 | 17 | 22 | +5 |
| octa (n=6) | 2 | 5 | 16 | 20 | +4 |
| tetra | 2 | 7 | 23 | 31 | +8 |
| double_tet | 5 | 2 | 7 | 30 | +7 |
| octa | 6 | 2 | 7 | 29 | +7 |
| tetra | 4 | 3 | 3 | 15 | +3 |
| double_tet | 5 | 3 | 3 | 14 | +3 |
| octa | 6 | 3 | 3 | 13 | +2 |

A linear regression fits: `gap ≈ -0.83 - 0.50·n + 0.67·d + 1.33·e` (RMS residual 0.24, all residuals ≤ 0.33 in absolute value).

**Implication**: the Hilbert prediction is a CONSERVATIVE LOWER BOUND on the regularity degree, and hence on the attacker's cost. The actual security is higher than the Hilbert prediction suggests.

## Resistance to specific attacks

We empirically verified that the following specific attacks do NOT break v4r3:

1. **Beullens-type attacks** (A, B, C variants from Beullens 2021–2023): none reduces the security below the Bardet-Faugère bound. Verified at d=6 with multiple seeds.
2. **MinRank attack**: applies but only reduces effective security by 2.1–2.3 bits at d=6. Negligible.
3. **Rank-1 specialized attacks**: succeed with probability 1/p per query, no advantage over brute force.

## Side-channel observations

The legitimate decryptor must enumerate multiple candidates from `σ_v⁻¹` because σ is not strictly injective. Empirically:

- Mean number of σ⁻¹ roots per vertex: ~2.1 at d=6 (over 30 trials)
- Distribution: 33% have 1 root, 37% have 2, 17% have 3, 10% have 4, 3% have 5.

A χ² independence test (N=30) on α-features (LSB, Hamming weight, mod 3, mod 5) vs. total combo count yields no statistically significant correlation. The only borderline observation is `ρ(v_0, v_3) ≈ -0.38` between two adjacent vertices, which is at the threshold of significance for N=30 and may warrant investigation.

**Recommendation for implementation**: use constant-time σ⁻¹ enumeration (always enumerate all possible roots, pad to a maximum, randomize order) to eliminate any timing-based side channel.

## Recommended parameters

See [PARAMETERS.md](PARAMETERS.md) for the full table. Summary:

| target | substrate | d | e | classical bits | quantum-conservative bits |
|--------|-----------|---|---|----------------|---------------------------|
| 128-bit classical | tetra | 12 | 17 | 150 | 126 (marginal) |
| 128-bit quantum | tetra | 12 | 31 | 174 | 147 |
| paranoid | octa | 12 | 17 | 158 | 133 |
| ultra-paranoid | tetra | 14 | 61 | 200+ | 170+ |

These figures incorporate the empirical gap regression. Without the gap correction (Hilbert prediction only), subtract ~25 bits.

## What we have NOT verified

1. **End-to-end correctness at d=12** (the parameters recommended for PQ-128). Pipeline components verified individually; full integration requires more compute resources than were available. Reproducing this in SageMath should take 2–5 minutes. See [pending_validations/README.md](../pending_validations/README.md).

2. **Empirical D_reg at d ≥ 4** for the public system. Limited by Macaulay matrix size in our environment. SageMath/Magma should handle this.

3. **Side-channel resistance at scale** (N ≥ 500 trials).

4. **Independent external cryptanalysis**. This requires time and visibility.

## Position relative to NIST PQ catalogue

v4r3 is NOT meant to compete with Kyber or other NIST finalists as a primary algorithm. Its role is:

1. **Diversification**: provide an option in a mathematical region disjoint from lattice-based cryptography.
2. **Hybrid mode**: combine with a NIST algorithm so that an attacker must break both.
3. **Sovereign technical option**: an open-source, auditable alternative for critical infrastructure.

For deployment, hybrid mode (Kyber+v4r3) is strongly recommended over standalone use, until v4r3 has received years of external analysis.
