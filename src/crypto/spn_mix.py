"""
crypto/spn_mix.py — sheaf-inspired LINEAR mixing layer for the AO SPN (Phase 2b).

The discarded construction coupled vertices through the multiplication tensor
of F_{p^d} (nonlinear degree-3 mixing, secret matrices) and was broken in one
round (A6-CICO). Here the sheaf structure over a 2-complex K = (V, E, T) is
landed as a plain t×t matrix over F_p (t = |V|) with PUBLIC parameters, so the
algebraic degree grows only by round composition (the governing lesson).

Definition (weighted, sign-free sheaf-Laplacian pattern; a_v, w_e, c_T public):

    M[u][u] = a_u + Σ_{e ∋ u} w_e + Σ_{T ∋ u} c_T
    M[u][v] = w_{uv} + Σ_{T ⊇ {u,v}} c_T      if (u,v) ∈ E   (u ≠ v)
    M[u][v] = 0                                if (u,v) ∉ E   (u ≠ v)

Structural consequence measured by this module: an MDS matrix has no zero
entries (1×1 minors), so the sheaf pattern can be MDS only if the 1-skeleton
of K is complete (tetrahedron). Any missing edge caps the branch number.

Metrics: exact differential branch number (exhaustive support/rank enumeration,
valid for t <= ~12), full MDS minor test, and the Poseidon2 M4 / Cauchy-MDS
references for comparison at equal t.
"""
from __future__ import annotations

from itertools import combinations

from crypto.linalg_fp import matrix_det_fp, matrix_rank_fp
from crypto.sampling import prg_vec


# ─────────────────────────── construction ───────────────────────────

def _nonzero_weights(seed: bytes, label: str, count: int, p: int) -> list:
    """count public non-zero weights in F_p from the audited PRG (rejection)."""
    vals = []
    idx = 0
    while len(vals) < count:
        v = prg_vec(seed, label, idx, 1, p)[0]
        idx += 1
        if v != 0:
            vals.append(v)
    return vals


def sheaf_mix_matrix(K, p: int, seed: bytes) -> list:
    """Public t×t sheaf-patterned mixing matrix over F_p for the complex K.

    All weights derive from `seed` via the domain-separated PRG (public,
    reproducible). Weights are non-zero so no coupling silently vanishes;
    zero entries appear exactly at non-adjacent vertex pairs.
    """
    a = _nonzero_weights(seed, "spn-mix/vertex", K.n, p)
    w = _nonzero_weights(seed, "spn-mix/edge", K.m, p)
    c = _nonzero_weights(seed, "spn-mix/triangle", K.l, p)
    M = [[0] * K.n for _ in range(K.n)]
    for v in range(K.n):
        M[v][v] = a[v]
    for e_idx, (u, v) in enumerate(K.edges):
        M[u][v] = (M[u][v] + w[e_idx]) % p
        M[v][u] = (M[v][u] + w[e_idx]) % p
        M[u][u] = (M[u][u] + w[e_idx]) % p
        M[v][v] = (M[v][v] + w[e_idx]) % p
    for t_idx, tri in enumerate(K.triangles):
        for u in tri:
            M[u][u] = (M[u][u] + c[t_idx]) % p
        for u, v in combinations(tri, 2):
            M[u][v] = (M[u][v] + c[t_idx]) % p
            M[v][u] = (M[v][u] + c[t_idx]) % p
    return M


# ─────────────────────────── references ───────────────────────────

def poseidon2_m4(p: int) -> list:
    """The 4×4 external-round matrix M4 of Poseidon2 (eprint 2023/323), mod p.

    Chosen by the Poseidon2 authors to be MDS while applying in 8 additions
    (+ doublings). MDS-ness is field-dependent: verified per-p by is_mds in
    the experiments, not assumed.
    """
    return [[x % p for x in row] for row in
            [[5, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]]]


def cauchy_mds(t: int, p: int) -> list:
    """t×t Cauchy matrix M[i][j] = 1/(x_i + y_j), provably MDS for p > 3t.

    x_i = i, y_j = t + j: all x_i distinct, all y_j distinct, x_i + y_j in
    [t, 3t-2] never 0 mod p. Every square submatrix of a Cauchy matrix is
    Cauchy, hence non-singular -> branch number t+1 (the MDS bound).
    """
    if p <= 3 * t:
        raise ValueError("p too small for this Cauchy parameterization")
    return [[pow(i + t + j, p - 2, p) for j in range(t)] for i in range(t)]


# ─────────────────────────── metrics ───────────────────────────

def is_mds(M: list, p: int) -> bool:
    """True iff every square minor of M is non-zero over F_p (branch = t+1)."""
    t = len(M)
    for k in range(1, t + 1):
        for rows in combinations(range(t), k):
            for cols in combinations(range(t), k):
                sub = [[M[r][c] for c in cols] for r in rows]
                if matrix_det_fp(sub, p) == 0:
                    return False
    return True


def branch_number(M: list, p: int) -> int:
    """Exact differential branch number  min_{x != 0} wt(x) + wt(Mx)  over F_p.

    Exhaustive over supports: an x != 0 with supp(x) ⊆ S and (Mx)|_Z = 0
    exists iff rank(M[Z, S]) < |S|; such a pair witnesses a value of at most
    |S| + (t - |Z|), and the true minimizer is enumerated exactly (S = its
    support, Z = the zero set of its image). 2^t · 2^t rank computations —
    fine for t <= ~12.
    """
    t = len(M)
    best = t + 1  # always achievable bound: wt(x)=1, wt(Mx) <= t
    for s_mask in range(1, 1 << t):
        cols = [j for j in range(t) if (s_mask >> j) & 1]
        s = len(cols)
        if s + 1 >= best:  # even a full-zero image can't beat best
            continue
        for z_mask in range(1 << t):
            rows = [i for i in range(t) if (z_mask >> i) & 1]
            val = s + (t - len(rows))
            if val >= best:
                continue
            sub = [[M[r][c] for c in cols] for r in rows]
            if matrix_rank_fp(sub, p) < s:
                best = val
    return best


def zero_entries(M: list) -> list:
    """Positions (i, j) with M[i][j] == 0 — each one is a broken 1×1 minor."""
    return [(i, j) for i, row in enumerate(M) for j, x in enumerate(row) if x == 0]


def nnz(M: list) -> int:
    """Non-zero entry count = F_p multiplications per matrix application."""
    return sum(1 for row in M for x in row if x != 0)
