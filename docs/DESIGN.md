# Alaniz Cipher v4r3 — design specification

This document specifies the v4r3 encryption scheme. For motivation and security analysis see [SECURITY.md](SECURITY.md). For parameter choices see [PARAMETERS.md](PARAMETERS.md).

## Notation

- `p` — a prime > 3·e (where e is the σ exponent, defined below).
- `d` — extension degree, integer ≥ 2.
- `q = p^d` — size of extension field.
- `F_p`, `F_q` — finite fields of orders p and q.
- `F_q = F_p[X]/⟨f(X)⟩` for an irreducible `f ∈ F_p[X]` of degree d.
- `ι: F_p^d → F_q` — embedding via the polynomial basis: `(a_0, ..., a_{d-1}) ↦ a_0 + a_1·X + ... + a_{d-1}·X^{d-1}`.
- `K = (V, E, T)` — a 2-simplicial complex: vertices V (|V|=n), edges E (|E|=m_e), triangles T (|T|=m_t).
- `e` — integer exponent ≥ 3 with `gcd(e, q-1) = 1`. This ensures `x → x^e` is a permutation of F_q.
- `L ∈ F_q\{0}` — public field constant.
- `β_v ∈ F_q\{0, 1}` for each `v ∈ V` — secret per-vertex constants.
- `A_v ∈ M_d(F_p)` for each `v ∈ V`, `B_e ∈ M_d(F_p)` for each `e ∈ E`, `C_t ∈ M_d(F_p)` for each `t ∈ T` — secret matrices.
- `H_0 ∈ M_{n·d, d_msg}(F_p)` — basis of H^0(K; F_p^d), the space of global sections. Public.

## Substrate: cellular sheaf over a 2-simplicial complex

The sheaf assigns to each vertex `v` the F_p-vector space `F_p^d`. To each edge `e = (u, v)` it assigns a restriction map `ρ_{u←e}, ρ_{v←e} ∈ GL_d(F_p)` such that the cocycle condition is satisfied on every triangle. The "global sections" are tuples `s = (s_v)_{v ∈ V}` with `s_v ∈ F_p^d` compatible with all edge restrictions.

In practice we represent the global-sections space by computing a basis `H_0` of its kernel-equation system. This is done deterministically given (K, p, d, rng_seed) and is part of public parameters.

## σ-permutation per vertex

For each vertex `v`, define the **vector-valued σ_v**: a function F_q → F_q given by

    σ_v(τ) = β_v · τ + (β_v - 1) · (L · τ + 1)^e.

By construction, σ_v is a polynomial of degree e in τ. It is a **permutation** of F_q (i.e., bijective) when `gcd(e, q-1) = 1` and the corresponding choice of `(L, β_v)` does not yield degeneracies. In practice we sample `L`, `β_v` uniformly from non-zero/non-trivial values; degeneracy probability is negligible.

Inverting σ_v requires solving the degree-e equation `σ_v(τ) - w = 0` in F_q, which the legitimate holder of β_v can do via Cantor-Zassenhaus root-finding. Without β_v, this is a structured polynomial-inversion problem.

## Encryption

**Input**: a message `α ∈ F_p^{d_msg}`.

**Step 1 — Section**: compute `s = H_0 · α ∈ F_p^{n·d}`. Denote by `s_v ∈ F_p^d` the v-th block (vertex contribution).

**Step 2 — Arguments**: for each vertex `v`, compute

    arg_v(α) = A_v · s_v
            + Σ_{e=(u,v) ∋ v} B_e · ι⁻¹(ι(s_u) · ι(s_v))
            + Σ_{t=(a,v,b) ∋ v} C_t · ι⁻¹(ι(s_a) · ι(s_v) · ι(s_b))

where the products `ι(s_u) · ι(s_v)` and the triple product are in F_q, and `ι⁻¹` brings the result back to F_p^d for matrix multiplication. Thus `arg_v: F_p^{d_msg} → F_p^d` is a polynomial map of total degree 3 in `α`.

**Step 3 — Mask**: sample a nonce `r ← {0,1}^λ` and derive per-vertex masks `r_v = PRG(r, "v", v) ∈ F_p^d`.

**Step 4 — Apply σ**: for each vertex `v`, compute `τ_v = ι(arg_v(α) + r_v) ∈ F_q`. Then `w_v = σ_v(τ_v) ∈ F_q`. Take `c_v = ι⁻¹(w_v) - r_v ∈ F_p^d`.

**Output**: ciphertext `(r, c_0, c_1, ..., c_{n-1})`.

## Decryption

**Input**: ciphertext `(r, c)`, secret key `(β_v, A_v, B_e, C_t)`.

**Step 1 — Mask recovery**: derive `r_v = PRG(r, "v", v)` for each `v`.

**Step 2 — σ_v inversion**: for each vertex `v`, find all `τ_v ∈ F_q` with `σ_v(τ_v) = ι(c_v + r_v)` using Cantor-Zassenhaus root-finding on `f(x) = σ_v(x) - w_v`. This yields a set of candidate values for `arg_v_recovered = ι⁻¹(τ_v) - r_v ∈ F_p^d`.

**Step 3 — Combo enumeration**: for each combination of (τ_v candidates across vertices), set up the cubic polynomial system

    F_{v,k}(α) = arg_v(α)[k] - arg_v_recovered[k] = 0,   for v ∈ V, k = 0, ..., d-1.

This is m·d cubic polynomials in d_msg variables.

**Step 4 — F4 solving**: solve the cubic system via Macaulay-matrix linearization at degree D = D_reg (the regularity degree, ~5 for typical parameters). The system is semi-regular (empirically verified at d=6); kernel dimension 1 yields a unique solution α.

**Step 5 — Verification**: re-encrypt α and check ciphertext matches. If yes, output α. If no, try next combo. If no combo works, decryption fails (this happens with negligible probability for honestly-generated ciphertexts).

## Key generation

Sample uniformly:
- `L ← F_q\{0}`
- For each `v ∈ V`: `β_v ← F_q\{0,1}`, `A_v ← GL_d(F_p)`.
- For each `e ∈ E`: `B_e ← M_d(F_p)`.
- For each `t ∈ T`: `C_t ← M_d(F_p)`.

Compute `H_0` deterministically from `(K, p, d, rng_seed)`.

**Public key**: `(K, p, d, e, L, A, B, C, H_0)`.
**Secret key**: `(β_0, β_1, ..., β_{n-1})`.

Note: only `β_v` are truly secret. `A, B, C` are public because their effect on `arg_v` is visible through ciphertext oracle queries; their role is to act as a "blender" within `arg_v`, not as a trapdoor.

## Parameter selection

See [PARAMETERS.md](PARAMETERS.md) for the discussion of (n, d, e, p) and recommended values for different security levels.

## Notes on the construction

**Why a 2-simplicial complex**: gives a discrete combinatorial structure that allows a sheaf with non-trivial cocycles. The substrate is small (4-6 vertices, fewer than 10 simplices total) so all operations remain tractable.

**Why F_q-multiplication and not Hadamard product**: the Hadamard product `s_u ⊙ s_v` couples corresponding coordinates only. Field multiplication `ι(s_u) · ι(s_v)` mixes all coordinates via the structure constants of F_q. This gives a richer algebraic entanglement, making the polynomial system harder to decouple.

**Why σ vector-valued**: a per-vertex permutation of F_q (rather than F_p^d viewed as a product) provides a non-linear trapdoor that operates jointly on all d coordinates. The exponentiation degree e is the dominant security parameter against direct F4 attack on the public system.

**Why m = n·d cubics with d_msg variables**: this gives an over-determined system (m·d ≥ d_msg) so that the Gröbner basis approach can recover α uniquely.

## Implementation reference

The reference implementation in `/src/crypto/protocol_v4r3_pq128.py` follows this specification exactly. The `pq128` suffix indicates parameter ranges suitable for PQ-128 security level; the core logic is parameter-independent.
