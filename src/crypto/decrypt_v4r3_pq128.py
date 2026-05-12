"""
crypto/decrypt_v4r3_pq128.py — Full v4r3 decryption at PQ-128 parameters.

Pipeline:
  1. σ_v⁻¹ at each vertex via Cantor-Zassenhaus (poly_pd.find_unique_root_in_Fq).
  2. Build cubic system arg_v(α) = arg_v_recovered for v = 0,...,n-1.
     Uses F_{p^d} structure constants computed from field_pd.
  3. Solve via Macaulay-matrix linearization (f4_solver.solve_polysystem_linearization)
     at degree D = D_reg (4 for tetrahedron from semi-regular Hilbert series; 5 fallback).
  4. Recover α from solution.
"""
from __future__ import annotations
import os
import sys
import time
from math import comb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from crypto.field_pd import FpdField
from crypto.poly_pd import find_unique_root_in_Fq, find_all_roots_in_Fq
from crypto.f4_solver import solve_polysystem_linearization
from crypto.protocol_v4r3_pq128 import (prg_vec, matrix_mul_fp,
                                          matrix_inverse_fp, matvec_mul_fp,
                                          ParamsPQ128, KeyPQ128)


def field_struct_tensor(F: FpdField):
    """T[i][j][l] s.t. (X^i)·(X^j) = Σ_l T[i][j][l] · X^l in F_{p^d}."""
    d = F.d
    T = [[[0]*d for _ in range(d)] for _ in range(d)]
    for i in range(d):
        ei = [0]*d; ei[i] = 1
        for j in range(d):
            ej = [0]*d; ej[j] = 1
            prod = F.mul(tuple(ei), tuple(ej))
            for l in range(d):
                T[i][j][l] = prod[l]
    return T


def triple_struct_tensor(F: FpdField):
    """T3[i][j][m][q] s.t. (X^i)·(X^j)·(X^m) = Σ_q T3[i][j][m][q] · X^q."""
    d = F.d
    T = [[[[0]*d for _ in range(d)] for _ in range(d)] for _ in range(d)]
    for i in range(d):
        ei = [0]*d; ei[i] = 1
        for j in range(d):
            ej = [0]*d; ej[j] = 1
            for m in range(d):
                em = [0]*d; em[m] = 1
                prod = F.mul(F.mul(tuple(ei), tuple(ej)), tuple(em))
                for q in range(d):
                    T[i][j][m][q] = prod[q]
    return T


def sigma_inverse_at_vertex(params: ParamsPQ128, key: KeyPQ128,
                              ciphertext, nonce, vertex):
    """Recover ONE candidate arg_v ∈ F_p^d via σ_v⁻¹ (single root)."""
    cands = sigma_inverse_all_candidates(params, key, ciphertext, nonce, vertex)
    return cands[0] if cands else None


def sigma_inverse_all_candidates(params: ParamsPQ128, key: KeyPQ128,
                                   ciphertext, nonce, vertex):
    """Recover ALL candidate arg_v ∈ F_p^d satisfying σ_v(arg_v + r_v) = c_v + r_v."""
    F = params.F
    p, d, e = params.p, params.d, params.exponent
    L = params.L
    beta = key.beta[vertex]
    one = F.one()

    r_v = prg_vec(nonce, "v", vertex, d, p)
    c_v = ciphertext[vertex*d:(vertex+1)*d]
    w_vec = [(int(c_v[i]) + r_v[i]) % p for i in range(d)]
    w_gf = tuple(w_vec)

    coefs = [F.zero()] * (e + 1)
    beta_minus_1 = F.sub(beta, one)
    coefs[0] = F.sub(F.mul(beta_minus_1, one), w_gf)
    L_pow = L
    coefs[1] = F.add(F.mul(beta_minus_1, F.mul(F.from_scalar(e), L_pow)), beta)
    for k in range(2, e + 1):
        L_pow = F.mul(L_pow, L)
        coefs[k] = F.mul(F.mul(beta_minus_1, F.from_scalar(comb(e, k))), L_pow)

    roots = find_all_roots_in_Fq(F, coefs, max_roots=8)
    args = []
    for root in roots:
        arg_v = [(root[i] - r_v[i]) % p for i in range(d)]
        args.append(arg_v)
    return args


def get_R_at(params: ParamsPQ128):
    """Extract R_v matrix per vertex from H0_basis: R_v[i][col] = H0_basis[col][v*d + i]."""
    p, d = params.p, params.d
    K = params.K
    R = {}
    for v in range(K.n):
        mat = [[0]*d for _ in range(d)]
        for col in range(d):
            for i in range(d):
                mat[i][col] = int(params.H0_basis[col][v*d + i]) % p
        R[v] = mat
    return R


def build_cubic_system_structure(params: ParamsPQ128, key: KeyPQ128,
                                    T_struct, T_triple, R):
    """Build the polynomial structure M_v[k][m] = coef of monomial m in
    arg_v(α)[k]. Returns dict {(v, k): {mono: coef}} — equations WITHOUT
    the right-hand side constant.

    Optimised with multi-step tensor contractions: instead of an O(d^7) loop
    for the trilinear contribution per (vertex, triangle), we do four
    O(d^5)-class contractions. Critical for d=12 where the naive nested
    loop is ~35M ops per (v,t).
    """
    p, d = params.p, params.d
    K = params.K
    n_var = d

    edges_at = {v: [] for v in range(K.n)}
    for e_idx, (u_, w_) in enumerate(K.edges):
        edges_at[u_].append((e_idx, u_, w_))
        edges_at[w_].append((e_idx, u_, w_))
    triangles_at = {v: [] for v in range(K.n)}
    for t_idx, t in enumerate(K.triangles):
        for v_ in t:
            triangles_at[v_].append((t_idx, t))

    structure = {}

    for v in range(K.n):
        polys_per_k = [dict() for _ in range(d)]

        # Linear: M_lin = A_v · R_v
        A_v = key.A[v]
        R_v = R[v]
        M_lin = matrix_mul_fp(A_v, R_v, p)
        for k in range(d):
            for j in range(n_var):
                if M_lin[k][j] != 0:
                    mono = tuple(1 if i == j else 0 for i in range(n_var))
                    polys_per_k[k][mono] = M_lin[k][j]

        # ── Bilinear (3-step contraction) ──
        # contrib[k, a, b] = Σ_{l,i,j} B_e[k,l] · T[i][j][l] · R_u[i,a] · R_v[j,b]
        # Step 1: A1[l, j, a]  = Σ_i T[i,j,l] · R_u[i,a]          (d³·d ops)
        # Step 2: Q[l, a, b]   = Σ_j A1[l, j, a] · R_v[j,b]       (d³·d ops)
        # Step 3: contrib[k,a,b] = Σ_l B_e[k,l] · Q[l, a, b]       (d²·d ops)
        for e_idx, u_v, w_v in edges_at[v]:
            other = u_v if w_v == v else w_v
            R_u = R[other]
            B_e = key.B[e_idx]

            # Step 1: A1[l, j, a] = Σ_i T_struct[i, j, l] · R_u[i, a]
            A1 = [[[0]*n_var for _ in range(d)] for _ in range(d)]
            for l_ in range(d):
                for j in range(d):
                    Tij = [T_struct[i][j][l_] for i in range(d)]
                    for a in range(n_var):
                        s = 0
                        for i in range(d):
                            tij = Tij[i]
                            if tij == 0: continue
                            ria = R_u[i][a]
                            if ria == 0: continue
                            s += tij * ria
                        A1[l_][j][a] = s % p

            # Step 2: Q[l, a, b] = Σ_j A1[l, j, a] · R_v[j, b]
            Q = [[[0]*n_var for _ in range(n_var)] for _ in range(d)]
            for l_ in range(d):
                for a in range(n_var):
                    Aja = [A1[l_][j][a] for j in range(d)]
                    for b in range(n_var):
                        s = 0
                        for j in range(d):
                            aja = Aja[j]
                            if aja == 0: continue
                            rjb = R_v[j][b]
                            if rjb == 0: continue
                            s += aja * rjb
                        Q[l_][a][b] = s % p

            # Step 3: contrib[k, a, b] = Σ_l B_e[k, l] · Q[l, a, b]
            for k in range(d):
                Bk = B_e[k]
                for a in range(n_var):
                    for b in range(n_var):
                        s = 0
                        for l_ in range(d):
                            bkl = Bk[l_]
                            if bkl == 0: continue
                            qlab = Q[l_][a][b]
                            if qlab == 0: continue
                            s += bkl * qlab
                        s = s % p
                        if s != 0:
                            mono = [0]*n_var
                            mono[a] += 1
                            mono[b] += 1
                            mono = tuple(mono)
                            polys_per_k[k][mono] = (polys_per_k[k].get(mono, 0) + s) % p

        # ── Trilinear (4-step contraction) ──
        # contrib[k,a,b,c] = Σ_{q,i,j,m} C_t[k,q]·T3[i,j,m,q]·R_a[i,a]·R_v[j,b]·R_b[m,c]
        # Step 1: A1[q, j, m, a] = Σ_i T3[i,j,m,q] · R_a[i,a]          (d^4·d = d^5 ops)
        # Step 2: A2[q, m, a, b] = Σ_j A1[q, j, m, a] · R_v[j, b]        (d^5 ops)
        # Step 3: A3[q, a, b, c] = Σ_m A2[q, m, a, b] · R_b[m, c]        (d^5 ops)
        # Step 4: contrib[k,a,b,c] = Σ_q C_t[k, q] · A3[q, a, b, c]      (d^5 ops)
        for t_idx, t in triangles_at[v]:
            others = [x for x in t if x != v]
            ax, bx = others[0], others[1]
            R_ax = R[ax]
            R_bx = R[bx]
            C_t = key.C[t_idx]

            # Step 1
            A1 = [[[[0]*n_var for _ in range(d)] for _ in range(d)] for _ in range(d)]
            for q in range(d):
                for j in range(d):
                    for m in range(d):
                        Tij = [T_triple[i][j][m][q] for i in range(d)]
                        for a in range(n_var):
                            s = 0
                            for i in range(d):
                                tij = Tij[i]
                                if tij == 0: continue
                                ria = R_ax[i][a]
                                if ria == 0: continue
                                s += tij * ria
                            A1[q][j][m][a] = s % p

            # Step 2
            A2 = [[[[0]*n_var for _ in range(n_var)] for _ in range(d)] for _ in range(d)]
            for q in range(d):
                for m in range(d):
                    for a in range(n_var):
                        Aja = [A1[q][j][m][a] for j in range(d)]
                        for b in range(n_var):
                            s = 0
                            for j in range(d):
                                aja = Aja[j]
                                if aja == 0: continue
                                rjb = R_v[j][b]
                                if rjb == 0: continue
                                s += aja * rjb
                            A2[q][m][a][b] = s % p

            # Step 3
            A3 = [[[[0]*n_var for _ in range(n_var)] for _ in range(n_var)] for _ in range(d)]
            for q in range(d):
                for a in range(n_var):
                    for b in range(n_var):
                        Ama = [A2[q][m][a][b] for m in range(d)]
                        for c in range(n_var):
                            s = 0
                            for m in range(d):
                                ama = Ama[m]
                                if ama == 0: continue
                                rmc = R_bx[m][c]
                                if rmc == 0: continue
                                s += ama * rmc
                            A3[q][a][b][c] = s % p

            # Step 4
            for k in range(d):
                Ck = C_t[k]
                for a in range(n_var):
                    for b in range(n_var):
                        for c in range(n_var):
                            s = 0
                            for q in range(d):
                                ckq = Ck[q]
                                if ckq == 0: continue
                                a3 = A3[q][a][b][c]
                                if a3 == 0: continue
                                s += ckq * a3
                            s = s % p
                            if s != 0:
                                mono = [0]*n_var
                                mono[a] += 1
                                mono[b] += 1
                                mono[c] += 1
                                mono = tuple(mono)
                                polys_per_k[k][mono] = (polys_per_k[k].get(mono, 0) + s) % p

        for k in range(d):
            structure[(v, k)] = polys_per_k[k]

    return structure


def specialise_to_combo(structure, arg_recovered, d, p, n_vertices):
    """Subtract arg_recovered constants to get final equations."""
    eqs = []
    for v in range(n_vertices):
        for k in range(d):
            poly = dict(structure[(v, k)])
            const_mono = tuple([0]*d)
            poly[const_mono] = (poly.get(const_mono, 0) - int(arg_recovered[v][k])) % p
            poly = {m: c for m, c in poly.items() if c % p != 0}
            if poly:
                eqs.append(poly)
    return eqs


def build_cubic_system(params: ParamsPQ128, key: KeyPQ128,
                        T_struct, T_triple, R, arg_recovered):
    """Compatibility wrapper: build structure + specialise."""
    structure = build_cubic_system_structure(params, key, T_struct, T_triple, R)
    return specialise_to_combo(structure, arg_recovered, params.d, params.p,
                                  params.K.n)


def decrypt_pq128(params: ParamsPQ128, key: KeyPQ128, ciphertext, nonce,
                    verbose=False, try_D_values=(4, 5, 6)):
    """Full decryption: σ⁻¹ at each vertex + F4 linearization, with
    enumeration over σ⁻¹ candidate combinations when σ is non-bijective.

    Returns (α, timings)."""
    F = params.F
    p, d = params.p, params.d
    K = params.K
    timings = {}

    # σ⁻¹ candidates at each vertex
    cands_per_vertex = []
    sigma_total = 0
    for v in range(K.n):
        t0 = time.time()
        cands = sigma_inverse_all_candidates(params, key, ciphertext, nonce, v)
        elapsed = time.time() - t0
        sigma_total += elapsed
        if not cands:
            if verbose:
                print(f"  σ⁻¹ at vertex {v}: NO CANDIDATES")
            return None, timings
        cands_per_vertex.append(cands)
        if verbose:
            print(f"  σ⁻¹ at vertex {v}: {len(cands)} candidate(s) in {elapsed:.2f}s")
    timings["sigma_inverse_total"] = sigma_total

    # Enumerate combinations
    n_combos = 1
    for cands in cands_per_vertex:
        n_combos *= len(cands)
    if verbose:
        print(f"  σ⁻¹ combinations to try: {n_combos}")

    # Build static structure once (independent of σ⁻¹ candidate combo)
    t0 = time.time()
    T_struct = field_struct_tensor(F)
    T_triple = triple_struct_tensor(F)
    R = get_R_at(params)
    structure = build_cubic_system_structure(params, key, T_struct, T_triple, R)
    structure_time = time.time() - t0
    timings["struct_setup"] = structure_time
    if verbose:
        print(f"  cubic system structure built in {structure_time:.2f}s")

    # Iterate combinations (Cartesian product)
    from itertools import product
    f4_total = 0.0
    spec_total = 0.0
    combo_idx = 0
    for combo in product(*cands_per_vertex):
        combo_idx += 1
        arg_recovered = {v: combo[v] for v in range(K.n)}

        t0 = time.time()
        eqs = specialise_to_combo(structure, arg_recovered, d, p, K.n)
        spec_total += time.time() - t0

        for D in try_D_values:
            t0 = time.time()
            sol = solve_polysystem_linearization(eqs, d=d, p=p, D_reg=D)
            elapsed = time.time() - t0
            f4_total += elapsed
            if verbose and combo_idx <= 3:
                print(f"  combo {combo_idx} F4 D={D}: {elapsed:.2f}s "
                      f"({'OK' if sol is not None else 'None'})")
            if sol is not None:
                # Verify by re-encryption
                from crypto.protocol_v4r3_pq128 import encrypt_pq128
                _, c_check = encrypt_pq128(params, key, sol, nonce=nonce)
                if list(c_check) == list(ciphertext):
                    timings["build_cubic"] = spec_total
                    timings["f4_total"] = f4_total
                    timings["f4_D_used"] = D
                    timings["combos_tried"] = combo_idx
                    return sol, timings
                elif verbose and combo_idx <= 3:
                    print(f"    F4 found α but verification FAILED, "
                          f"trying next combo")

    timings["build_cubic"] = spec_total
    timings["f4_total"] = f4_total
    timings["combos_tried"] = combo_idx
    return None, timings
