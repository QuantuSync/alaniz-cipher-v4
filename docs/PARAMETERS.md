# Recommended parameters

This document specifies parameter sets for different security levels, along with the rationale.

## Parameter sets

| Set name | Use case | Substrate | d | e | p | Classical bits | Q-conservative bits | Q-aggressive bits |
|----------|----------|-----------|---|---|---|----------------|---------------------|-------------------|
| `pq128-classic` | 128-bit classical only | tetrahedron (n=4) | 12 | 17 | 2⁶¹-1 | 150 | 126 ⚠ | 95 |
| **`pq128-q-cons`** | **128-bit quantum recommended** | tetrahedron | 12 | 31 | 2⁶¹-1 | 174 | **147** ✓ | 110 |
| `pq128-octa` | 128-bit margin via larger substrate | octahedron (n=6) | 12 | 17 | 2⁶¹-1 | 158 | **133** ✓ | 99 |
| `pq128-paranoid` | High margin against unknown attacks | tetrahedron | 14 | 31 | 2⁶¹-1 | 201 | 170 | 127 |
| `pq192` | 192-bit security | tetrahedron | 14 | 61 | 2⁶¹-1 | 248 | 209 | 157 |
| `pq256` | 256-bit security | tetrahedron | 16 | 127 | 2⁶¹-1 | 305+ | 257+ | 193+ |

**Bit counts incorporate the empirical gap regression** `gap ≈ -0.83 - 0.50·n + 0.67·d + 1.33·e` derived from 13 empirical instances at small scale.

The 128-bit-quantum recommended set is `pq128-q-cons` (tetra d=12 e=31), which has 19 bits of margin over the target under the conservative quantum threat model.

## How the figures were computed

For each parameter set:

1. Compute the Hilbert series semi-regular `D_reg`:
   ```
   D_reg = first D ≥ 0 where coefficient of t^D in (1-t^{3e})^{n·d} / (1-t)^d is ≤ 0
   ```

2. Apply the empirical gap correction:
   ```
   D_reg_emp = D_reg + gap, where gap = round(-0.83 - 0.50·n + 0.67·d + 1.33·e)
   ```

3. Compute the bit cost:
   ```
   bit_cost(ω) = ω · log₂ C(d + D_reg_emp, d)
   ```
   for `ω ∈ {2.37 classical, 2.0 quantum-conservative, 1.5 quantum-aggressive}`.

A clean reproduction is in [`experiments/reproduce_quantum_analysis.py`](../experiments/reproduce_quantum_analysis.py).

## Why prime `p = 2⁶¹ − 1` (Mersenne)

This is a 61-bit Mersenne prime. Choosing a Mersenne prime allows efficient modular reduction without division (`x mod p = (x & p) + (x >> 61)` after one or two iterations). Other primes are usable but slower.

The choice of `p` affects security only marginally. The dominant parameters are `(d, e)`.

## Why these `(d, e)` combinations and not others

The constraint `gcd(e, p^d - 1) = 1` (needed for σ to be a permutation of F_q) limits the choice of `e` for each `(p, d)`:

| d | smallest valid e (for p in our range) |
|---|----------------------------------------|
| 2 | 3 or 5 (depends on p mod factor) |
| 3 | 3 or 5 |
| 4 | 7 (e=3, 5 always blocked by Fermat) |
| 6 | 17 typical |
| 8 | 17 typical |
| 10 | 17 or 31 |
| 12 | 17 typical |

For the recommended `pq128-q-cons`, we chose **d=12, e=31** because:
- d=12 puts the system in the regime where rows/cols ≥ 0.75 at D_reg (the Hilbert prediction is tight).
- e=31 (vs. e=17) gives ~21 bits of margin against the quantum-conservative threat.
- Computing σ⁻¹ at e=31 vs e=17 is ~3.3× slower (degree-31 polynomial root-finding vs degree-17), but absolute time is still small (single-digit seconds in optimized C).

## Decryption performance estimates

These are estimated tip-of-iceberg timings for optimized C implementation (not Python prototype):

| Set | Setup | KeyGen | Encrypt | Decrypt (with σ⁻¹ + F4) |
|-----|-------|--------|---------|--------------------------|
| `pq128-q-cons` | <1s | <10ms | ~5ms | 2-10s |
| `pq128-octa` | <1s | <10ms | ~10ms | 5-20s |
| `pq128-classic` | <1s | <10ms | ~5ms | 1-5s |
| `pq256` | ~1s | <50ms | ~20ms | 30-60s |

For reference, our Python prototype takes 50–250s for `pq128-classic` decrypt — entirely Python overhead.

## Sizes

| Set | Public key | Private key | Ciphertext per message |
|-----|------------|-------------|------------------------|
| `pq128-q-cons` | ~50 KB | ~370 bytes | ~370 bytes (d=12 elements × 61 bits) |
| `pq128-octa` | ~80 KB | ~550 bytes | ~550 bytes |
| `pq256` | ~250 KB | ~520 bytes | ~520 bytes |

These are larger than NIST Kyber-768 (1.2 KB / 2.4 KB / 1.1 KB) and similar to Kyber-1024 with some overhead.

The public key size is dominated by `A, B, C` matrices over F_p; storage in field representation could compress further. This is implementation work, not a fundamental limit.

## What if the empirical gap regression is wrong?

The gap was measured at d ≤ 3 and extrapolated to d ≤ 14. If the gap turns out to be ZERO at d=12 (worst case for the defender), the security degrades to the pure Hilbert prediction:

| Set | with gap | without gap (pure Hilbert) |
|-----|----------|----------------------------|
| `pq128-classic` | 150 / 126 | 144 / 121 |
| `pq128-q-cons` | 174 / 147 | 167 / 141 |
| `pq128-octa` | 158 / 133 | 152 / 128 |
| `pq128-paranoid` | 201 / 170 | 192 / 162 |

Even in the worst case (no gap), `pq128-q-cons` still gives 141 bits of quantum-conservative security, exceeding the 128-bit target by 13 bits.

## Open question: gap behavior at large d

We have NOT empirically measured the gap at d ≥ 4. The regression assumes the same linear law holds; if the gap behaves non-linearly at higher d (positive or negative), the security estimates need adjustment. This is one of the priority items in [pending_validations/README.md](../pending_validations/README.md).
