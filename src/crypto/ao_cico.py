"""
crypto/ao_cico.py — build the CICO polynomial system for the Alaniz AO round.

See docs/AO_SPEC.md. In the AO model the permutation is PUBLIC, so we build the
system by evaluating the public forward map (crypto.ao_permutation.ao_forward) at
chosen points and interpolating each output coordinate as a polynomial in the free
input variables. The interpolation linear solve uses python-flint (nmod_mat) which
is ~20x faster than pure Python and makes d>=4 feasible.

Two builders:
  - build_cico_message_recovery: input restricted to Im(H0) (free vars = α, dim d),
    all n·d outputs fixed to z* = c* + r. This is the A6 message-recovery system.
  - build_cico_general: fix arbitrary input coords and output coords.
"""
from __future__ import annotations

import numpy as np

from crypto.f4_solver import all_monomials
from crypto.ao_permutation import ao_forward, section_from_alpha


def _pow_mono(a, mono, p):
    r = 1
    for i, ei in enumerate(mono):
        if ei:
            r = (r * pow(a[i], ei, p)) % p
    return r


def interpolate_polys(eval_fn, n_vars, out_dim, degree, p, seed=20260705):
    """Interpolate out_dim output coords as polys (dict {mono:coef}) of total
    degree <= `degree` in n_vars free variables over F_p.

    eval_fn(free_vec) -> list of length out_dim (evaluation of the public map).
    Uses flint nmod_mat to invert the n_mono x n_mono sample matrix ONCE and apply
    it to all out_dim right-hand sides.
    """
    import flint

    monos, _ = all_monomials(n_vars, degree)
    n_mono = len(monos)
    if p ** n_vars < n_mono:
        raise RuntimeError(
            f"field too small: p^n_vars={p**n_vars} < n_mono={n_mono} "
            f"(need larger p for n_vars={n_vars}, degree={degree})")

    rng = np.random.default_rng(seed)
    seen = set()

    def fresh():
        while True:
            if len(seen) >= p ** n_vars:
                raise RuntimeError("exhausted all p^n_vars distinct points")
            a = tuple(int(rng.integers(0, p)) for _ in range(n_vars))
            if a not in seen:
                seen.add(a)
                return a

    # Build sample matrix V (n_mono x n_mono) and outputs Y (n_mono x out_dim).
    V_data = [0] * (n_mono * n_mono)
    Y_data = [0] * (n_mono * out_dim)
    pts = []
    for r in range(n_mono):
        a = fresh()
        pts.append(a)
        base = r * n_mono
        for c_i, m in enumerate(monos):
            V_data[base + c_i] = _pow_mono(a, m, p)
        yv = eval_fn(list(a))
        yb = r * out_dim
        for i in range(out_dim):
            Y_data[yb + i] = int(yv[i]) % p

    V = flint.nmod_mat(n_mono, n_mono, V_data, p)
    # Retry singular sample matrices by replacing rows with fresh points.
    tries = 0
    while tries < 60:
        try:
            Vinv = V.inv()
            break
        except Exception:
            tries += 1
            r = tries % n_mono
            a = fresh()
            base = r * n_mono
            for c_i, m in enumerate(monos):
                V_data[base + c_i] = _pow_mono(a, m, p)
            yv = eval_fn(list(a))
            yb = r * out_dim
            for i in range(out_dim):
                Y_data[yb + i] = int(yv[i]) % p
            V = flint.nmod_mat(n_mono, n_mono, V_data, p)
    else:
        raise RuntimeError("interpolation matrix singular after retries")

    Y = flint.nmod_mat(n_mono, out_dim, Y_data, p)
    coef = Vinv * Y  # n_mono x out_dim; coef[j, i] = coef of monomial j in output i

    polys = []
    for i in range(out_dim):
        poly = {}
        for j in range(n_mono):
            c = int(coef[j, i]) % p
            if c:
                poly[monos[j]] = c
        polys.append(poly)
    return polys, monos


def build_cico_message_recovery(params, key, z_star, nonce, variant="impl",
                                 seed=20260705):
    """Message-recovery CICO: free vars = α (dim d), input = H0·α, outputs fixed
    to z_star (= c* + r). Returns (equations, monos): equations[i] = {mono:coef}
    for  R(H0·α)[i] - z_star[i] = 0."""
    p, d, K = params.p, params.d, params.K
    e = params.exponent
    degree = 3 * e
    out_dim = K.n * d

    def eval_fn(alpha):
        s = section_from_alpha(params, alpha)
        return ao_forward(params, key, s, nonce, variant=variant)

    polys, monos = interpolate_polys(eval_fn, d, out_dim, degree, p, seed=seed)
    const = tuple([0] * d)
    equations = []
    for i in range(out_dim):
        poly = dict(polys[i])
        poly[const] = (poly.get(const, 0) - int(z_star[i])) % p
        poly = {m: c for m, c in poly.items() if c % p != 0}
        equations.append(poly)
    return equations, monos


def build_cico_general(params, key, nonce, fixed_in, fixed_out, variant="impl",
                       seed=20260705):
    """General CICO on the full state.

    fixed_in : dict {coord_index: value}  (input coords held constant)
    fixed_out: dict {coord_index: value}  (output coords constrained)
    Free variables = the input coords NOT in fixed_in.
    Returns (equations, monos, free_idx): one equation per fixed_out coord,
    polynomials in the free input variables (total degree <= 3e).
    """
    p, d, K = params.p, params.d, params.K
    e = params.exponent
    degree = 3 * e
    n_state = K.n * d
    free_idx = [i for i in range(n_state) if i not in fixed_in]
    n_free = len(free_idx)
    out_idx = sorted(fixed_out.keys())

    def eval_fn(free_vec):
        x = [0] * n_state
        for i, val in fixed_in.items():
            x[i] = val % p
        for pos, i in enumerate(free_idx):
            x[i] = free_vec[pos] % p
        y = ao_forward(params, key, x, nonce, variant=variant)
        return [y[i] for i in out_idx]

    polys, monos = interpolate_polys(eval_fn, n_free, len(out_idx), degree, p,
                                     seed=seed)
    const = tuple([0] * n_free)
    equations = []
    for k, i in enumerate(out_idx):
        poly = dict(polys[k])
        poly[const] = (poly.get(const, 0) - int(fixed_out[i])) % p
        poly = {m: c for m, c in poly.items() if c % p != 0}
        equations.append(poly)
    return equations, monos, free_idx
