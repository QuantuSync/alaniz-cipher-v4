# Version history

This document records the evolution of the scheme through versions v1, v2, v3, v4r1, v4r2, v4r3, and the key decisions made at each step.

## v1 — initial concept (2024)

First proposal combining sheaf-theoretic structure with cryptographic permutation. Initial constructions explored without formal security analysis.

Status: superseded.

## v2 — refined construction (early 2025)

Introduced the cellular sheaf substrate explicitly. Vertex/edge/triangle contributions defined but coupling was via Hadamard product.

Issue identified: Hadamard product decouples coordinate axes, making the polynomial system separable.

Status: superseded.

## v3 — first formally analyzed version (mid 2025)

Published at Zenodo: DOI [10.5281/zenodo.19746033](https://doi.org/10.5281/zenodo.19746033).

Title: *Alaniz Cipher v3: Sheaf-Based Post-Quantum Encryption via Vector-Valued Finite Field Permutations*.

Key elements:
- Cellular sheaf on tetrahedron substrate.
- F_q-multiplication coupling (replacing Hadamard).
- σ vector-valued of degree e=17.
- Proposed parameters: d=6, e=17, p=2⁶¹-1.
- Claimed PQ-128 security.

**Issue identified during this work (v4 development)**: the claimed PQ-128 security at (d=6, e=17) is INCORRECT. Bardet-Faugère analysis gives ~74 bits, not 128. This is a critical security parameter error in v3.

**Action taken in v4**: corrected parameters with full quantitative analysis. See `docs/PARAMETERS.md`.

Status: superseded. The v3 paper should be either retracted or annotated with the security error.

## v4r1 — first revision attempt (early 2026)

Attempted minor parameter adjustments to fix v3's security. Insufficient: the underlying analysis methodology in v3 was the issue, not just the numbers.

Status: superseded.

## v4r2 — structural revision (early 2026)

Reworked the bilinear coupling to use full F_q-multiplication tensor (not just diagonal). This is what made the public polynomial system truly multivariate-hard rather than separable.

Status: superseded by v4r3 (which extended this to trilinear contributions and resolved several bugs).

## v4r3 — current version (May 2026)

Current proposal. Differences from v3:

1. **Trilinear contributions through triangles** added. v3 had only linear + bilinear; v4r3 includes the natural extension via the 2-simplex structure.

2. **Hand-rolled F_{p^d} arithmetic** (`field_pd.py`) replaces reliance on the `galois` library, which hangs for p = 2⁶¹-1 at d ≥ 4. Custom Rabin irreducibility test (`irreducible.py`) added.

3. **σ⁻¹ enumeration**: discovered that σ_v has 1-3 roots per inversion (not always 1). Implementation enumerates all candidates and tries combinations.

4. **F4 linearization solver** (`f4_solver.py`) replaces sympy Gröbner (which fails at PQ-128 scale).

5. **Parameter correction**: recommended `pq128-q-cons` is now tetra d=12, e=31 (not d=6, e=17). Other parameter sets also defined.

6. **Comprehensive empirical validation**: 13 instances of the empirical D_reg measurement at small scale, leading to the gap regression model.

7. **Formal documentation**: CSI problem definition, IND-CPA reduction sketch, syzygy-hiding argument.

**Status**: current proposal. Not deployment-ready. See `docs/STATUS.md`.

## Bugs found and fixed during v4 development

The following bugs in the v3 implementation or analysis were identified during v4 development:

1. **`field_pd.find_irreducible`**: the heuristic "use x^d + c for some c" fails when no such c yields an irreducible polynomial (e.g., p=5, d=6 because gcd(3, p-1)=1 makes every element a cube). Fixed by using `galois.irreducible_poly` and falling back to a Rabin test for parameters where galois hangs.

2. **`from_int` vs `from_scalar`**: positional vs. scalar encoding mismatch for binomial coefficients in σ⁻¹ root finding. Bug invisible at PQ-128 because C(17, k) << p, but theoretically important. Fixed.

3. **σ⁻¹ returns only one root**: implementation assumed σ_v injective on the relevant subset. Empirically σ_v has 1-3 roots; enumeration of all roots and combinations of (root choices across vertices) is required. Fixed.

4. **Parameter sub-estimation**: v3's PQ-128 parameters do not provide 128 bits against F4 direct attack. Identified and corrected via quantitative Hilbert series analysis.

## Key design decisions in v4r3

For each major decision, the rationale:

**Why tetrahedron as default substrate**:
- Smallest non-trivial 2-simplicial complex (4 vertices, 6 edges, 4 triangles).
- Sufficient algebraic complexity for the construction.
- Larger substrates (octahedron, icosahedron) give larger keys with marginal security gain.

**Why F_p^d via polynomial basis ι (not coordinate basis)**:
- ι allows F_q multiplication to be inherited from F_p[X] arithmetic.
- Coordinate basis would force a tensor structure that's no harder for the attacker.

**Why σ_v of degree e (not e=2 or e=p-1)**:
- e=2 (squaring) is known to be weak in characteristic > 2.
- e=p-1 makes σ_v ≈ trivial.
- e ≥ 3 with gcd(e, q-1) = 1 gives a genuine permutation polynomial.

**Why vector-valued σ (not coordinate-wise)**:
- Coordinate-wise σ would decouple the d output coordinates, making the polynomial system separable.
- Vector-valued (= via ι, in F_q) mixes coordinates intrinsically.

**Why message space d_msg = dim H^0(K; F_p^d)**:
- The global-sections space is the natural domain compatible with the sheaf structure.
- For tetrahedron with the standard sheaf at d=12, d_msg = d. Higher-genus substrates can give larger d_msg.

## What's preserved across versions

The core idea — cellular sheaf + vector-valued σ over a 2-simplicial complex — has been stable from v2 onward. v4r3 differs from v3 mainly in (a) trilinear contributions, (b) implementation correctness, (c) parameter correction, and (d) empirical validation.

## Future versioning

If material design changes (rather than parameter updates), the next version would be v5. Reasons that would justify v5:

- Discovery of a structural attack requiring a different trapdoor.
- Significant simplification (e.g., proof that triangles are not needed).
- Hybrid construction combining v4r3 with another mathematical primitive.

Pure parameter updates within v4r3 use suffixes (e.g., `pq128-q-cons`) and are documented in `docs/PARAMETERS.md` without bumping the version number.
