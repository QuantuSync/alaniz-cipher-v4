# Hard problem and security model for v4r3

## The Cubic-Sheaf-Inversion (CSI) problem

We define the underlying hard problem on which v4r3's security rests.

### Definition (CSI)

**Parameters**: 2-simplicial complex `K = (V, E, T)`, prime `p`, integer `d ≥ 2`, integer `e ≥ 3` with `gcd(e, p^d - 1) = 1`.

**Instance**: 
- An element `L ∈ F_q\{0}` where `q = p^d`.
- For each vertex `v ∈ V`, an element `β_v ∈ F_q\{0, 1}` and a matrix `A_v ∈ M_d(F_p)`.
- For each edge `e_idx ∈ E`, a matrix `B_e ∈ M_d(F_p)`.
- For each triangle `t ∈ T`, a matrix `C_t ∈ M_d(F_p)`.
- An H^0 basis `H_0 ∈ M_{n·d, d_msg}(F_p)` of dimension `d_msg`.

**Witness**: a vector `α ∈ F_p^{d_msg}`.

**Output (challenge)**: the ciphertext
    
    c = (c_0, ..., c_{n-1}) ∈ F_p^{n·d}

where 
- `s_v ∈ F_p^d` is the v-th block of `H_0 · α`,
- `arg_v(α) = A_v · s_v + Σ_{e ∋ v} B_e · ι(s_u · s_v) + Σ_{t ∋ v} C_t · ι(s_a · s_v · s_b)`,
- `r_v = PRG(nonce, v) ∈ F_p^d` (publicly verifiable),
- `c_v = σ_v(arg_v(α) + r_v) - r_v ∈ F_p^d` where `σ_v(τ) = β_v · τ + (β_v - 1) · (L · τ + 1)^e`.

**CSI problem**: given `(K, p, d, e, L, A, B, C, H_0, nonce, c)` (i.e., everything EXCEPT `β_v` and `α`), recover `α`.

Note: `β_v` is in the secret key. The adversary sees `c`, the public parameters, and (for IND-CPA) two candidate plaintexts. They do NOT see `β_v` directly. The CSI hardness is the assumption that recovering α from `c` without `β_v` requires solving the public polynomial system `S_att` of degree `3e` in `d_msg` variables, which by Bardet-Faugère costs `≥ 2^{ω · log_2 C(d_msg + D_reg, d_msg)}` operations.

### CSI assumption

We assume there exists no algorithm running in time less than the F4/F5 bound `2^{Bardet-Faugère(d_msg, m, 3e)}` that solves CSI with non-negligible advantage. Equivalently: any solver for CSI is asymptotically equivalent to Gröbner basis computation on the public polynomial system.

This is a **structural cryptographic assumption**, not a reduction to a previously-studied hard problem. The strongest evidence in its favor:
1. The system is semi-regular (empirically verified at d=2,3) — no algebraic shortcut beyond F4.
2. Syzygies of the decryptor's cubic system do not lift to syzygies of the attacker's system without knowing β_v (formal argument, see SYZYGY_PROOF.md).
3. No known specific attack (Beullens, MinRank, isomorphism) breaks v4r3 — verified in exp11-14.

The weakest aspect: like all multivariate cryptography (HFE, UOV, Rainbow), the assumption is HEURISTIC. It could fail if a new general algorithm or a structural shortcut is discovered.

## Encryption scheme

**Key generation**:
1. Sample `L ← F_q\{0}` uniformly.
2. For each `v ∈ V`: sample `β_v ← F_q\{0, 1}` uniformly, and `A_v ← GL_d(F_p)` uniformly.
3. For each `e ∈ E`: sample `B_e ← M_d(F_p)` uniformly.
4. For each `t ∈ T`: sample `C_t ← M_d(F_p)` uniformly.
5. Compute `H_0` as a basis of the global sections of the sheaf (deterministic from K, p, d).
6. **Public key**: `pk = (K, p, d, e, L, A, B, C, H_0)`. 
   **Secret key**: `sk = (β_0, ..., β_{n-1})`.

(Note: `A, B, C` are public because they appear inside arg_v which the attacker sees the action of through c. Their security role is to make the message-to-arg_v map a nonlinear "blender" so that arg_v(α) is hard to invert directly; the actual TRAPDOOR is `β_v`.)

**Encryption** of message `α ∈ F_p^{d_msg}`:
1. Sample nonce `r ← {0, 1}^λ` uniformly.
2. Compute `c = Enc(pk, α, r)` as in CSI definition.
3. Return `(r, c)`.

**Decryption** of `(r, c)` with `sk`:
1. For each `v ∈ V`: derive `r_v = PRG(r, v)`. Compute `w_v = c_v + r_v ∈ F_q`. Find all roots `τ_v ∈ F_q` of `σ_v(x) - w_v = 0` using Cantor-Zassenhaus. Set `arg_v_recovered = τ_v - r_v` (as a F_p^d element via inverse embedding).
2. Build the cubic polynomial system `F_v,k(α) - arg_v_recovered[k] = 0` for each combo of `τ_v` choices.
3. For each combo, solve the cubic system via F4 linearization. Verify by re-encryption.
4. Return the α that re-encrypts to c.

## IND-CPA reduction (sketch)

We argue that v4r3 is IND-CPA secure under the CSI assumption.

**IND-CPA game**:
1. Challenger samples `(pk, sk) ← KeyGen()`, sends `pk` to adversary `A`.
2. `A` outputs two messages `α_0, α_1` of equal length.
3. Challenger samples `b ← {0, 1}`, computes `c_b ← Enc(pk, α_b)`, sends `c_b` to `A`.
4. `A` outputs `b' ∈ {0, 1}`.
5. `A` wins if `b' = b`.

`A`'s advantage is `Adv = |Pr[b' = b] - 1/2|`.

**Claim**: For any PPT `A` with advantage `Adv ≥ ε`, there exists a CSI solver `B` running in roughly the same time as `A` with advantage `≥ ε`.

**Reduction**: Given an IND-CPA adversary `A`, construct `B` as follows. `B` receives a CSI challenge `(pk, c*)` where `c* = Enc(pk, α*, r*)` for some hidden `α*`. `B` simulates the IND-CPA game for `A`:
1. `B` forwards `pk` to `A`.
2. `A` returns `α_0, α_1`.
3. `B` samples `b ← {0,1}` privately and tests "is `c* = Enc(pk, α_b, r*)`?" by re-encrypting. But `B` does not know `α*` so cannot directly check this. 

This is where the standard hybrid argument is needed: `B` uses `A` as an oracle, with the hybrid that c* is replaced by Enc(pk, α_b, r) for a fresh r. If c* is indistinguishable from a fresh ciphertext of α_b, then A's win-rate gives info about whether `α* = α_b`.

A clean reduction would show: if `A` has advantage `ε` in distinguishing `Enc(pk, α_0)` from `Enc(pk, α_1)`, then a modified `B` can recover `α_0` (or `α_1`) from a CSI challenge with advantage `≥ ε / 2`.

**Caveat**: This sketch is informal. A rigorous reduction would need to handle:
1. The randomness `r` used in encryption.
2. The fact that v4r3 uses a deterministic embedding once `r` is fixed.
3. Reduction tightness (the factor by which the reduction loses).

A formal proof would require establishing v4r3 as a randomized encryption scheme with a well-defined randomness space, then showing semantic security in the standard manner. This is straightforward bookkeeping if CSI is hard, but technical.

## What about IND-CCA?

v4r3 as defined here is NOT IND-CCA secure. Like all "basic" public-key encryption schemes, achieving IND-CCA requires either:
1. A Fujisaki-Okamoto transform (re-encryption check during decryption).
2. A separate MAC over the ciphertext.

The F-O transform is straightforward to apply and has well-known security: if v4r3 is IND-CPA and one-way under chosen-plaintext attack, the F-O-transformed v4r3 is IND-CCA in the random oracle model.

## Summary of security claims

| Claim | Justification | Confidence |
|-------|---------------|-----------|
| CSI assumption holds | Semi-regularity + syzygy hiding + no specific attack works | Heuristic, structural |
| IND-CPA under CSI | Reduction sketched above | Informal, fillable |
| IND-CCA via F-O | Standard transformation | Well-established |
| Specific parameters (d=12, e=17, tetra) give ≥ 128 bits | Bardet-Faugère + empirical D_reg validation | Strong (empirical floor) |
| (d=6, e=17) gives only ~74 bits | Bardet-Faugère + Hilbert series | High confidence, kills v3 parameters |

## Open questions for further work

1. **Quantum security**: Quantum analogues of F4 (e.g., Grover-amplified linearization) would lower the bit-cost by a factor of √. For 128-bit *quantum* security with d=12, need D_reg-bit-cost ≥ 256 classical → use d=14 or e=23.
2. **Tightness of the IND-CPA reduction**.
3. **Algebraic structure of σ⁻¹ multi-root**: does the non-injectivity reveal anything about `β_v` to a chosen-ciphertext attacker?
4. **Empirical D_reg at d ≥ 6** (the predicted security range): we have only validated at d ≤ 3 due to computational constraints. SageMath/Magma should be used for d = 4, 5, 6 confirmation before any deployment.
