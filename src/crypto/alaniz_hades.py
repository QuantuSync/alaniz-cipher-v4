"""
crypto/alaniz_hades.py — HADES (full-partial-full) variant of Alaniz-AO.

Poseidon2's cost lever: replace most full rounds with PARTIAL rounds that apply the
S-box on a SINGLE lane; the MDS layer still diffuses the nonlinearity to the whole
state, so fewer S-boxes give (claimed) the same security. Alaniz-AO can do this
because its linear layer is MDS. This module lets us RE-MEASURE the algebraic
security (the partial rounds change the structure), not assume it.

Schedule: R_full/2 full rounds, then R_part partial rounds, then R_full/2 full
rounds. A full round S-boxes all t lanes (with input coupling); a partial round
S-boxes only lane L = t-1 (which is coupled to (t-3, t-2)), identity elsewhere.
Both are followed by the Cauchy-MDS layer and a round constant.

All layers are bijections (triangular input coupling => 7th-root inverse per
S-boxed lane; identity + MDS invertible), so the permutation is invertible.
"""
from __future__ import annotations

from crypto.linalg_fp import matrix_inverse_fp, matvec_mul_fp, vec_add_fp, vec_sub_fp
from crypto.sampling import prg_vec
from crypto.spn_field import GOLDILOCKS_P, sbox, sbox_exponents, sbox_inv
from crypto.spn_mix import cauchy_mds


def chain_coupling(t):
    return {v: [(v - 2, v - 1)] for v in range(2, t)}


class HadesAO:
    def __init__(self, t, r_full, r_part, p=GOLDILOCKS_P, seed=b"AlanizHADES/v1",
                 partial_lane=None):
        assert r_full % 2 == 0, "R_full must be even (split half/half)"
        self.t = t
        self.p = p
        self.r_full = r_full
        self.r_part = r_part
        self.L = t - 1 if partial_lane is None else partial_lane
        self.d, self.d_inv = sbox_exponents(p)
        self.M = cauchy_mds(t, p)
        self.Minv = matrix_inverse_fp(self.M, p)
        self.at = chain_coupling(t)
        # schedule of S-boxed lanes per round: full = all lanes, partial = {L}
        full = list(range(t))
        part = [self.L]
        self.schedule = ([full] * (r_full // 2) + [part] * r_part
                         + [full] * (r_full // 2))
        self.rounds = len(self.schedule)
        self.w = {}
        idx = 0
        for v in range(t):
            for (a, b) in self.at.get(v, []):
                val = 0
                while val == 0:
                    val = prg_vec(seed + b"/couple", "w", idx, 1, p)[0]
                    idx += 1
                self.w[(a, b, v)] = val
        self.rc = [prg_vec(seed + b"/rc", "round", r, t, p) for r in range(self.rounds)]
        self.rc_init = prg_vec(seed + b"/rc", "init", 0, t, p)

    def _cross(self, x, v):
        s = 0
        for (a, b) in self.at.get(v, []):
            s = (s + self.w[(a, b, v)] * x[a] * x[b]) % self.p
        return s

    def _sb_forward(self, x, mask):
        p, d = self.p, self.d
        y = list(x)
        for v in mask:
            y[v] = sbox((x[v] + self._cross(x, v)) % p, p, d)
        return y

    def _sb_inverse(self, y, mask):
        p, di = self.p, self.d_inv
        x = list(y)
        # only S-boxed lanes changed; recover each from its 7th root minus coupling.
        # coupling of lane v uses lanes < v; for the single partial lane t-1 all
        # coupling inputs are non-S-boxed (identity) => known directly from y.
        for v in sorted(mask):
            cross = 0
            for (a, b) in self.at.get(v, []):
                cross = (cross + self.w[(a, b, v)] * x[a] * x[b]) % p
            x[v] = (sbox_inv(y[v], p, di) - cross) % p
        return x

    def permute(self, x):
        p = self.p
        s = vec_add_fp(x, self.rc_init, p)
        for r, mask in enumerate(self.schedule):
            s = self._sb_forward(s, mask)
            s = matvec_mul_fp(self.M, s, p)
            s = vec_add_fp(s, self.rc[r], p)
        return s

    def permute_inverse(self, y):
        p = self.p
        s = list(y)
        for r in reversed(range(self.rounds)):
            s = vec_sub_fp(s, self.rc[r], p)
            s = matvec_mul_fp(self.Minv, s, p)
            s = self._sb_inverse(s, self.schedule[r])
        return vec_sub_fp(s, self.rc_init, p)

    def sbox_count(self):
        """Total S-box evaluations (R1CS driver, together with coupling mults)."""
        return sum(len(m) for m in self.schedule)

    def coupling_mults(self):
        """Coupling multiplications per permutation (one per S-boxed COUPLED lane)."""
        return sum(1 for mask in self.schedule for v in mask if self.at.get(v))


from crypto.spn_cico import _poly_from_terms, _signed_term, var  # noqa: E402


def build_hades_cico(h, c_fixed, seed_rhs=b"hades-cico", witness=None):
    """CICO for a HADES permutation. `c_fixed` = number of fixed input lanes (the
    LAST c_fixed lanes); free branches m = t - c_fixed; m output lanes (the first
    m) are constrained. For the balanced sponge use c_fixed = kappa (= capacity),
    which fixes the capacity input and frees the rate => m = kappa.

    FreeLunch-faithful intermediate-variable model: one S-box-input variable
    a{r}_j per S-BOXED lane (identity lanes carry no variable), so partial rounds
    add only one degree-7 relation. Returns (variables, polys, meta)."""
    p, t, M = h.p, h.t, h.M
    kappa = c_fixed
    if witness is None:
        witness = prg_vec(seed_rhs, "in", 0, t, p)
    out = h.permute(witness)

    fixed_in = list(range(t - kappa, t))     # last c_fixed input lanes (capacity)
    fixed_out = list(range(0, t - kappa))    # first m = t-c output lanes (rate)

    # witness assignment for consistency guard
    x_states, a_states = [], []
    s = vec_add_fp(witness, h.rc_init, p)
    for r, mask in enumerate(h.schedule):
        x_states.append(list(s))
        a_states.append({j: (s[j] + h._cross(s, j)) % p for j in mask})
        s = vec_add_fp(matvec_mul_fp(M, h._sb_forward(s, mask), p), h.rc[r], p)

    variables = [var(r, i) for r in range(h.rounds) for i in range(t)]
    variables += [f"a{r}_{j}" for r in range(h.rounds) for j in h.schedule[r]]
    polys = []

    def out_terms(r, j, coefM):
        """signed terms for coefM * (S-box output of lane j in round r)."""
        if j in h.schedule[r]:                 # S-boxed: a{r}_j^7
            term = _signed_term(coefM % p, f"a{r}_{j}^7", p)
        else:                                  # identity: x{r}_j
            term = _signed_term(coefM % p, var(r, j), p)
        return [term] if term else []

    # (a-def) a{r}_j - x{r}_j - Σ w x_a x_b = 0
    for r, mask in enumerate(h.schedule):
        for j in mask:
            terms = [("+", f"a{r}_{j}"), ("-", var(r, j))]
            for (a, b) in h.at.get(j, []):
                tt = _signed_term((-h.w[(a, b, j)]) % p, f"{var(r,a)}*{var(r,b)}", p)
                if tt:
                    terms.append(tt)
            polys.append(_poly_from_terms(terms))

    # (link) x{r+1}_i - Σ_j M[i][j]*out_j - rc[r][i]
    for r in range(h.rounds - 1):
        for i in range(t):
            terms = [("+", var(r + 1, i))]
            for j in range(t):
                terms += out_terms(r, j, (-M[i][j]) % p)
            tt = _signed_term((-h.rc[r][i]) % p, "", p)
            if tt:
                terms.append(tt)
            polys.append(_poly_from_terms(terms))

    # (in) fix capacity input lanes
    for i in fixed_in:
        val = (witness[i] + h.rc_init[i]) % p
        terms = [("+", var(0, i))]
        tt = _signed_term((-val) % p, "", p)
        if tt:
            terms.append(tt)
        polys.append(_poly_from_terms(terms))

    # (out) constrain rate output lanes
    for i in fixed_out:
        terms = []
        for j in range(t):
            terms += out_terms(h.rounds - 1, j, M[i][j] % p)
        rhs = (h.rc[h.rounds - 1][i] - out[i]) % p
        tt = _signed_term(rhs, "", p)
        if tt:
            terms.append(tt)
        polys.append(_poly_from_terms(terms))

    meta = {"n_vars": len(variables), "n_eqs": len(polys), "m": kappa,
            "fixed_in": fixed_in, "fixed_out": fixed_out,
            "x_states": x_states, "a_states": a_states, "witness": witness}
    return variables, polys, meta
