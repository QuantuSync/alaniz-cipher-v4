"""
crypto/poly_pd.py — Polynomial arithmetic over F_{p^d}.

Used for σ⁻¹ at PQ-128 size where galois cannot construct the field in
reasonable time. Implements:
  - poly multiplication / division / gcd
  - poly power x^k via repeated squaring
  - root finding via Cantor-Zassenhaus-style gcd(f, x^q - x)

Coefficients are F_{p^d} elements as tuples (handled by FpdField).
A polynomial is a list of coefficients in ASCENDING degree:
    poly = [c_0, c_1, ..., c_n]   represents c_0 + c_1·x + ... + c_n·x^n
"""
from __future__ import annotations
from crypto.field_pd import FpdField


def poly_strip(F: FpdField, p: list) -> list:
    """Remove trailing zeros."""
    while p and F.is_zero(p[-1]):
        p = p[:-1]
    return p


def poly_deg(p: list) -> int:
    return len(p) - 1


def poly_add(F: FpdField, p: list, q: list) -> list:
    n = max(len(p), len(q))
    out = [F.zero()] * n
    for i in range(n):
        a = p[i] if i < len(p) else F.zero()
        b = q[i] if i < len(q) else F.zero()
        out[i] = F.add(a, b)
    return poly_strip(F, out)


def poly_sub(F: FpdField, p: list, q: list) -> list:
    n = max(len(p), len(q))
    out = [F.zero()] * n
    for i in range(n):
        a = p[i] if i < len(p) else F.zero()
        b = q[i] if i < len(q) else F.zero()
        out[i] = F.sub(a, b)
    return poly_strip(F, out)


def poly_mul(F: FpdField, p: list, q: list) -> list:
    if not p or not q:
        return []
    out = [F.zero()] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if F.is_zero(a): continue
        for j, b in enumerate(q):
            if F.is_zero(b): continue
            out[i + j] = F.add(out[i + j], F.mul(a, b))
    return poly_strip(F, out)


def poly_scalar_mul(F: FpdField, p: list, c: tuple) -> list:
    return [F.mul(coef, c) for coef in p]


def poly_divmod(F: FpdField, p: list, d: list):
    """Polynomial long division. Returns (quotient, remainder).

    Optimised for monic divisors (the common case in σ⁻¹ pipeline): skips
    F.inv computation entirely, saving an O(log q) F_q exponentiation per call.
    """
    p = list(p)
    d = poly_strip(F, list(d))
    if not d:
        raise ZeroDivisionError("poly division by zero")
    n_d = len(d) - 1            # degree of d
    leading_d = d[-1]
    one = F.one()
    is_monic = (leading_d == one)
    if not is_monic:
        leading_d_inv = F.inv(leading_d)

    q = []
    r = list(p)
    r = poly_strip(F, r)
    while len(r) - 1 >= n_d and r:
        n_r = len(r) - 1
        leading_r = r[-1]
        if is_monic:
            coef = leading_r       # × 1, skip mul
        else:
            coef = F.mul(leading_r, leading_d_inv)
        shift = n_r - n_d
        # subtract coef * d * x^shift from r
        for i, dc in enumerate(d):
            if F.is_zero(dc): continue
            r[shift + i] = F.sub(r[shift + i], F.mul(coef, dc))
        # extend q if needed
        while len(q) <= shift:
            q.append(F.zero())
        q[shift] = coef
        r = poly_strip(F, r)
    return q, r


def poly_mod(F: FpdField, p: list, d: list) -> list:
    _, r = poly_divmod(F, p, d)
    return r


def poly_gcd(F: FpdField, a: list, b: list) -> list:
    """Polynomial gcd, monic-normalised."""
    a = poly_strip(F, list(a))
    b = poly_strip(F, list(b))
    while b:
        _, r = poly_divmod(F, a, b)
        a, b = b, r
    if not a:
        return []
    # Make monic
    leading = a[-1]
    leading_inv = F.inv(leading)
    return [F.mul(c, leading_inv) for c in a]


def poly_pow_mod(F: FpdField, base: list, exp: int, mod: list) -> list:
    """Compute base^exp mod (mod_poly). Square-and-multiply on polynomial."""
    result = [F.one()]
    base = poly_mod(F, base, mod)
    e = exp
    while e > 0:
        if e & 1:
            result = poly_mod(F, poly_mul(F, result, base), mod)
        base = poly_mod(F, poly_mul(F, base, base), mod)
        e >>= 1
    return poly_strip(F, result)


def poly_pow_q_mod(F: FpdField, base: list, mod: list) -> list:
    """Compute base^q mod f where q = p^d.

    Direct exponentiation, kept as alias for explicitness.
    """
    return poly_pow_mod(F, base, F.p ** F.d, mod)


def find_unique_root_in_Fq(F: FpdField, f: list) -> tuple:
    """
    Find a single F_q-rational root of f(x) ∈ F_q[x] where q = p^d.
    Uses gcd(f(x), x^q - x). If σ is bijective at a vertex, this gcd has
    degree 1 and the root is read off directly. If degree > 1, returns
    one root via random splitting.

    Returns the root as F_q element, or None if no root found.
    """
    roots = find_all_roots_in_Fq(F, f, max_roots=1)
    return roots[0] if roots else None


def find_all_roots_in_Fq(F: FpdField, f: list, max_roots: int = 32) -> list:
    """Find ALL F_q-rational roots of f(x). Returns list (possibly empty)."""
    q = F.p ** F.d
    f = poly_strip(F, list(f))
    if len(f) <= 1:
        return []
    # gcd(f, x^q - x) = product of distinct linear factors
    x_poly = [F.zero(), F.one()]
    xq_mod_f = poly_pow_mod(F, x_poly, q, f)
    diff = poly_sub(F, xq_mod_f, x_poly)
    g = poly_gcd(F, f, diff)
    g = poly_strip(F, g)
    if not g or poly_deg(g) == 0:
        return []
    return _factor_squarefree_split_roots(F, g, q, max_roots)


def _factor_squarefree_split_roots(F: FpdField, g: list, q: int,
                                     max_roots: int) -> list:
    """Recursively split g (squarefree, all linear factors) into its roots."""
    g = poly_strip(F, list(g))
    if not g or poly_deg(g) == 0:
        return []
    if poly_deg(g) == 1:
        c0 = g[0]; c1 = g[1]
        c1_inv = F.inv(c1)
        return [F.mul(F.neg(c0), c1_inv)]
    # Cantor-Zassenhaus split using random α
    import secrets
    attempts = 0
    while attempts < 50:
        attempts += 1
        alpha_int = secrets.randbelow(q)
        alpha = F.from_int(alpha_int)
        if F.is_zero(alpha):
            continue
        x_plus_alpha = [alpha, F.one()]
        powered = poly_pow_mod(F, x_plus_alpha, (q - 1) // 2, g)
        if not powered:
            powered = [F.neg(F.one())]
        else:
            powered = list(powered)
            powered[0] = F.sub(powered[0], F.one())
            powered = poly_strip(F, powered)
        h = poly_gcd(F, g, powered)
        if not h or poly_deg(h) == 0 or poly_deg(h) == poly_deg(g):
            continue
        # Found split: h is non-trivial factor of g
        # Get the cofactor h2 = g / h
        h2_q, h2_r = poly_divmod(F, g, h)
        # Recurse on both
        roots_left = _factor_squarefree_split_roots(F, h, q, max_roots)
        if len(roots_left) >= max_roots:
            return roots_left[:max_roots]
        roots_right = _factor_squarefree_split_roots(F, h2_q, q, max_roots - len(roots_left))
        return roots_left + roots_right
    # Failed to split after many attempts (very unlikely for squarefree g over F_q)
    return []
