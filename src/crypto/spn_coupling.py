"""
crypto/spn_coupling.py — sheaf structure as NON-LINEARITY (Camino 1).

Previous result (commit d1ddcb2): the sheaf structure as a LINEAR mixing layer
buys no algebraic security (D_I = 7^(R·m), independent of branch number). Here we
move the geometry into the layer that DOES govern D_I: the coupling between
S-boxes, driven by the 2-simplices (triangles) of the complex.

Hard design constraint (lesson A5a): the coupling MUST be bijective. The literal
form y_v = x_v^7 + Σ w·(x_u·x_v) is NOT a bijection (fixing earlier vertices it
becomes x_v^7 + c·x_v, not a permutation polynomial). So the coupling is made
TRIANGULAR: y_v depends only on S-boxes of EARLIER vertices (u < v in the fixed
order), never on x_v itself inside the coupling term. Then each vertex inverts by
a single 7th-root, and the whole layer is a bijection by construction (proved
exhaustively in tests/test_coupling.py).

Fixed vertex order: 0 < 1 < ... < t-1. Sheaf coupling from triangles T:
for each triangle {u, u', v} in T with v = max(u,u',v), vertex v receives the
quadratic cross term x_u · x_{u'} (both earlier), weighted by a public PRG scalar.

Three coupling modes (measured side by side at the Step-2 gate):
  * "indep" — baseline A: y_v = x_v^7                       (round degree 7)
  * "add"   — B-add:  y_v = x_v^7 + Σ c·x_u·x_{u'}          (round degree 7)
  * "input" — B-in:   y_v = (x_v + Σ c·x_u·x_{u'})^7        (round degree 14)

All three are triangular ⇒ bijective. "add" adds the cross term AFTER the power
(subdominant to x_v^7); "input" folds it into the S-box INPUT (its 7th power
raises the round degree to 14 — the variant that can actually accelerate D_I,
and the one FreeLunch/CheapLunch target).
"""
from __future__ import annotations

from crypto.linalg_fp import matrix_inverse_fp, matvec_mul_fp, vec_add_fp, vec_sub_fp
from crypto.sampling import prg_vec
from crypto.spn_field import sbox, sbox_exponents, sbox_inv
from crypto.spn_mix import cauchy_mds


def triangle_coupling(K):
    """For each vertex v, the list of (u, u') with u<u'<v and {u,u',v} a triangle.

    These are the 2-simplices whose largest vertex is v: the earlier-only pairs
    that couple into v (keeps the layer triangular ⇒ bijective).
    """
    at = {v: [] for v in range(K.n)}
    for tri in K.triangles:
        a, b, c = sorted(tri)
        at[c].append((a, b))   # largest vertex c receives the pair (a,b)
    return at


def triangle_terms(K):
    """Ordered list of coupling terms (v, a, b), a<b<v, from the 2-simplices.

    Canonical order: by target vertex v DESCENDING (highest = most downstream,
    reached soonest by any free branch through the MDS layer), then by (a, b).
    Truncating this list to the first k gives the density-k coupling; k=1 is the
    minimal (single-term) coupling.
    """
    terms = []
    at = triangle_coupling(K)
    for v in sorted(range(K.n), reverse=True):
        for (a, b) in sorted(at[v]):
            terms.append((v, a, b))
    return terms


def at_from_terms(terms):
    """Build the per-vertex coupling dict v -> [(a,b), ...] from a term list."""
    at = {}
    for (v, a, b) in terms:
        at.setdefault(v, []).append((a, b))
    return at


def pattern_terms(K, pattern):
    """Triangular coupling term lists for the sheaf-vs-generic CONTROL.

    All patterns are triangular (a<b<v) hence bijective; they differ only in the
    incidence (which earlier pair couples into v), so the control isolates whether
    the +1-bit/round effect needs the SHEAF incidence or is generic to any
    input-coupling.
      'sheaf'   : pairs from the complex's 2-simplices (== triangle_terms).
      'dense'   : ALL pairs a<b<v for every v (complete triangular; ignores K).
      'chain'   : v couples to (v-2, v-1) for v>=2 (local, non-sheaf).
      'star'    : v couples to (0, 1) for v>=2 (fixed, non-sheaf).
    """
    n = K.n
    if pattern == "sheaf":
        return triangle_terms(K)
    if pattern == "dense":
        return [(v, a, b) for v in range(n - 1, -1, -1)
                for a in range(n) for b in range(a + 1, n) if b < v]
    if pattern == "chain":
        return [(v, v - 2, v - 1) for v in range(n - 1, 1, -1)]
    if pattern == "star":
        return [(v, 0, 1) for v in range(n - 1, 1, -1)]
    raise ValueError(f"unknown pattern {pattern!r}")


def coupling_at(K, density):
    """Coupling structure at the requested density.

    density=None or 'full' -> all triangle terms; an int k -> the first k terms
    of triangle_terms(K) (k=1 is minimal).
    """
    terms = triangle_terms(K)
    if density not in (None, "full"):
        terms = terms[:density]
    at = {v: [] for v in range(K.n)}
    at.update(at_from_terms(terms))
    return at, terms


def coupling_weights(at, p, seed):
    """Public PRG weight per coupling term (a,b)->v, keyed (a,b,v)."""
    w = {}
    idx = 0
    for v in sorted(at):
        for (a, b) in at[v]:
            val = 0
            while val == 0:
                val = prg_vec(seed, "couple", idx, 1, p)[0]
                idx += 1
            w[(a, b, v)] = val
    return w


def coupling_forward(mode, K, x, w, at, p, d):
    """Apply the (triangular) coupling S-box layer to state x ∈ F_p^t."""
    y = [0] * K.n
    for v in range(K.n):
        cross = 0
        for (a, b) in at[v]:
            cross = (cross + w[(a, b, v)] * x[a] * x[b]) % p
        if mode == "indep":
            y[v] = sbox(x[v], p, d)
        elif mode == "add":
            y[v] = (sbox(x[v], p, d) + cross) % p
        elif mode == "input":
            y[v] = sbox((x[v] + cross) % p, p, d)
        else:
            raise ValueError(f"unknown coupling mode {mode!r}")
    return y


def coupling_inverse(mode, K, y, w, at, p, d_inv):
    """Invert the coupling layer. Triangular: recover x_0, x_1, ... in order,
    each from a single 7th root plus the already-known earlier vertices."""
    x = [0] * K.n
    for v in range(K.n):
        cross = 0
        for (a, b) in at[v]:              # a, b < v already recovered
            cross = (cross + w[(a, b, v)] * x[a] * x[b]) % p
        if mode == "indep":
            x[v] = sbox_inv(y[v], p, d_inv)
        elif mode == "add":
            x[v] = sbox_inv((y[v] - cross) % p, p, d_inv)
        elif mode == "input":
            x[v] = (sbox_inv(y[v], p, d_inv) - cross) % p
        else:
            raise ValueError(f"unknown coupling mode {mode!r}")
    return x


# ─────────────────────────── coupled permutation ───────────────────────────

class CoupledParams:
    """Public params of the coupled AO SPN.  Round: x -> M·coupling(x) + rc,
    with M a NEUTRAL Cauchy-MDS layer (identical across coupling modes so the
    only variable under study is the coupling itself)."""

    def __init__(self, K, p, R, mode, seed=b"coupling/v1", d=None, density=None,
                 terms=None):
        self.K = K
        self.t = K.n
        self.p = p
        self.R = R
        self.mode = mode
        self.density = density
        self.d, self.d_inv = sbox_exponents(p, d)
        self.M = cauchy_mds(K.n, p)
        self.Minv = matrix_inverse_fp(self.M, p)
        if terms is not None:                               # explicit override
            self.terms = list(terms)
            self.at = {v: [] for v in range(K.n)}
            self.at.update(at_from_terms(self.terms))
        else:
            self.at, self.terms = coupling_at(K, density)   # density=None -> full
        self.w = coupling_weights(self.at, p, seed + b"/couple")
        self.rc = [prg_vec(seed + b"/rc", "round", r, self.t, p) for r in range(R)]
        self.rc_init = prg_vec(seed + b"/rc", "init", 0, self.t, p)

    def n_coupling_terms(self):
        return len(self.terms)

    def __repr__(self):
        return (f"CoupledParams(t={self.t}, p={self.p}, R={self.R}, "
                f"mode={self.mode!r}, density={self.density}, "
                f"terms={self.n_coupling_terms()})")


def permute(params, x):
    p = params.p
    state = vec_add_fp(x, params.rc_init, p)
    for r in range(params.R):
        state = coupling_forward(params.mode, params.K, state, params.w,
                                 params.at, p, params.d)
        state = matvec_mul_fp(params.M, state, p)
        state = vec_add_fp(state, params.rc[r], p)
    return state


def permute_inverse(params, y):
    p = params.p
    state = list(y)
    for r in reversed(range(params.R)):
        state = vec_sub_fp(state, params.rc[r], p)
        state = matvec_mul_fp(params.Minv, state, p)
        state = coupling_inverse(params.mode, params.K, state, params.w,
                                 params.at, p, params.d_inv)
    return vec_sub_fp(state, params.rc_init, p)


# ─────────────────────────── CICO model (FreeLunch-style) ───────────────────

from crypto.spn_cico import _poly_from_terms, _signed_term, var  # noqa: E402


def _cross_terms(params, r, j, sign):
    """signed terms for  sign * Σ_{(a,b)∈at[j]} w_{abj}·x{r}_a·x{r}_b."""
    p = params.p
    terms = []
    for (a, b) in params.at[j]:
        c = (sign * params.w[(a, b, j)]) % p
        term = _signed_term(c, f"{var(r, a)}*{var(r, b)}", p)
        if term:
            terms.append(term)
    return terms


def build_coupled_cico(params, c, seed_rhs=b"coupled-cico", witness=None):
    """CICO system for the coupled construction (mode in {indep, add, input}).

    Variables: x{r}_i (coupling inputs). For mode "input" we also introduce the
    S-box-input variables a{r}_i = x{r}_i + cross (FreeLunch-faithful, keeps the
    system degree at 7 and parenthesis-free — msolve mis-parses parentheses).
    Fixes c input coords and t-c output coords ⇒ square 0-dim system.
    """
    p, t, R, M, d = params.p, params.t, params.R, params.M, params.d
    if not (1 <= c <= t - 1):
        raise ValueError("capacity c must satisfy 1 <= c <= t-1")
    if witness is None:
        witness = prg_vec(seed_rhs, "in", 0, t, p)
    out = permute(params, witness)
    use_a = params.mode == "input"

    fixed_in = list(range(t - c, t))
    fixed_out = list(range(0, t - c))

    # ---- witness assignment for every variable (consistency guard) ----
    x_states, a_states = [], []
    s = vec_add_fp(witness, params.rc_init, p)
    for r in range(R):
        x_states.append(s)
        a_vec = [0] * t
        for j in range(t):
            cross = sum(params.w[(a, b, j)] * s[a] * s[b]
                        for (a, b) in params.at[j]) % p
            a_vec[j] = (s[j] + cross) % p if use_a else s[j]
        a_states.append(a_vec)
        y = coupling_forward(params.mode, params.K, s, params.w, params.at, p, d)
        s = vec_add_fp(matvec_mul_fp(M, y, p), params.rc[r], p)

    variables = [var(r, i) for r in range(R) for i in range(t)]
    if use_a:
        variables += [f"a{r}_{i}" for r in range(R) for i in range(t)]
    polys = []

    def sbox_out_terms(r, j, coefM):
        """signed terms for coefM * (S-box output of vertex j at round r)."""
        terms = []
        if use_a:                      # output = a{r}_j^7
            term = _signed_term(coefM % p, f"a{r}_{j}^7", p)
            if term:
                terms.append(term)
        else:                          # output = x{r}_j^7  (+ cross for "add")
            term = _signed_term(coefM % p, f"{var(r, j)}^7", p)
            if term:
                terms.append(term)
            if params.mode == "add":
                for (a, b) in params.at[j]:
                    cc = (coefM * params.w[(a, b, j)]) % p
                    tt = _signed_term(cc, f"{var(r, a)}*{var(r, b)}", p)
                    if tt:
                        terms.append(tt)
        return terms

    # (def) for "input": a{r}_i - x{r}_i - cross_i = 0
    if use_a:
        for r in range(R):
            for i in range(t):
                terms = [("+", f"a{r}_{i}"), ("-", var(r, i))]
                terms += _cross_terms(params, r, i, -1)
                polys.append(_poly_from_terms(terms))

    # (link) x{r+1}_i - Σ_j M[i][j]·sbox_out(r,j) - rc[r][i]
    for r in range(R - 1):
        for i in range(t):
            terms = [("+", var(r + 1, i))]
            for j in range(t):
                terms += sbox_out_terms(r, j, (-M[i][j]) % p)
            tt = _signed_term((-params.rc[r][i]) % p, "", p)
            if tt:
                terms.append(tt)
            polys.append(_poly_from_terms(terms))

    # (in) x{0}_i - (witness_i + rc_init_i)
    for i in fixed_in:
        val = (witness[i] + params.rc_init[i]) % p
        terms = [("+", var(0, i))]
        tt = _signed_term((-val) % p, "", p)
        if tt:
            terms.append(tt)
        polys.append(_poly_from_terms(terms))

    # (out) Σ_j M[i][j]·sbox_out(R-1,j) + rc[R-1][i] - out_i
    for i in fixed_out:
        terms = []
        for j in range(t):
            terms += sbox_out_terms(R - 1, j, M[i][j] % p)
        rhs = (params.rc[R - 1][i] - out[i]) % p
        tt = _signed_term(rhs, "", p)
        if tt:
            terms.append(tt)
        polys.append(_poly_from_terms(terms))

    meta = {"n_vars": len(variables), "n_eqs": len(polys),
            "fixed_in": fixed_in, "fixed_out": fixed_out, "witness": witness,
            "x_states": x_states, "a_states": a_states, "use_a": use_a, "c": c}
    return variables, polys, meta
