"""
crypto/irreducible.py — Find irreducible polynomials of degree d over F_p
without relying on galois.irreducible_poly (which hangs for large p, d ≥ 4).

Uses Rabin's irreducibility test: f ∈ F_p[X] of degree d is irreducible iff
  (1) X^{p^d} ≡ X (mod f)
  (2) For each prime q | d: gcd(X^{p^(d/q)} - X, f) = 1
"""
from __future__ import annotations


# ─────────────────────── F_p[X] polynomial arithmetic ───────────────────────

def poly_deg_fp(a: list) -> int:
    for i in range(len(a) - 1, -1, -1):
        if a[i] != 0:
            return i
    return -1


def poly_strip_fp(a: list, p: int) -> list:
    a = [x % p for x in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def poly_add_fp(a: list, b: list, p: int) -> list:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out[i] = (x + y) % p
    return poly_strip_fp(out, p)


def poly_sub_fp(a: list, b: list, p: int) -> list:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out[i] = (x - y) % p
    return poly_strip_fp(out, p)


def poly_mul_fp(a: list, b: list, p: int) -> list:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        if a[i] == 0: continue
        for j in range(len(b)):
            if b[j] == 0: continue
            out[i + j] = (out[i + j] + a[i] * b[j]) % p
    return poly_strip_fp(out, p)


def poly_divmod_fp(a: list, b: list, p: int) -> tuple:
    """Return (quotient, remainder) such that a = q·b + r, deg(r) < deg(b)."""
    a = poly_strip_fp(list(a), p)
    b = poly_strip_fp(list(b), p)
    if poly_deg_fp(b) < 0:
        raise ZeroDivisionError
    if poly_deg_fp(a) < poly_deg_fp(b):
        return [0], a
    lead_b = b[-1]
    inv_lead = pow(lead_b, p - 2, p)
    q = [0] * (poly_deg_fp(a) - poly_deg_fp(b) + 1)
    r = list(a)
    while poly_deg_fp(r) >= poly_deg_fp(b):
        d = poly_deg_fp(r) - poly_deg_fp(b)
        c = (r[poly_deg_fp(r)] * inv_lead) % p
        q[d] = c
        for i in range(len(b)):
            r[d + i] = (r[d + i] - c * b[i]) % p
        r = poly_strip_fp(r, p)
    return poly_strip_fp(q, p), r


def poly_mod_fp(a: list, b: list, p: int) -> list:
    _, r = poly_divmod_fp(a, b, p)
    return r


def poly_gcd_fp(a: list, b: list, p: int) -> list:
    a = poly_strip_fp(list(a), p)
    b = poly_strip_fp(list(b), p)
    while poly_deg_fp(b) >= 0:
        a, b = b, poly_mod_fp(a, b, p)
    # Normalize to monic
    if poly_deg_fp(a) >= 0 and a[-1] != 1:
        inv = pow(a[-1], p - 2, p)
        a = [(c * inv) % p for c in a]
    return a


def poly_pow_mod_fp(base: list, exp: int, mod: list, p: int) -> list:
    """Compute base^exp mod (mod) in F_p[X]. Square-and-multiply."""
    result = [1]
    cur = poly_mod_fp(base, mod, p)
    while exp > 0:
        if exp & 1:
            result = poly_mod_fp(poly_mul_fp(result, cur, p), mod, p)
        exp >>= 1
        if exp:
            cur = poly_mod_fp(poly_mul_fp(cur, cur, p), mod, p)
    return result


# ─────────────────────── Rabin irreducibility test ───────────────────────

def _prime_divisors(n: int):
    result = []
    nn = n
    q = 2
    while q * q <= nn:
        if nn % q == 0:
            result.append(q)
            while nn % q == 0:
                nn //= q
        q += 1
    if nn > 1:
        result.append(nn)
    return result


def is_irreducible_rabin(f: list, p: int) -> bool:
    """Rabin's irreducibility test for f ∈ F_p[X] of degree d ≥ 1."""
    f = poly_strip_fp(list(f), p)
    d = poly_deg_fp(f)
    if d < 1:
        return False
    if d == 1:
        return True

    # Compute X^{p^k} mod f iteratively.
    # We need X^{p^d} and X^{p^(d/q)} for each prime q dividing d.
    primes = _prime_divisors(d)
    targets = sorted(set([d // q for q in primes] + [d]))  # smallest first

    x_poly = [0, 1]
    cur = x_poly                      # X^{p^0} = X
    cur_k = 0                         # current k means X^{p^k} mod f
    powers = {}
    for k in targets:
        # iterate from cur_k to k: each step computes x → x^p mod f
        while cur_k < k:
            cur = poly_pow_mod_fp(cur, p, f, p)
            cur_k += 1
        powers[k] = cur

    # Condition (1): X^{p^d} ≡ X (mod f)
    diff = poly_sub_fp(powers[d], x_poly, p)
    if poly_deg_fp(diff) >= 0:
        return False

    # Condition (2): for each prime q | d, gcd(X^{p^(d/q)} - X, f) = 1
    for q in primes:
        e = d // q
        diff = poly_sub_fp(powers[e], x_poly, p)
        g = poly_gcd_fp(f, diff, p)
        if poly_deg_fp(g) != 0:
            return False
    return True


def find_irreducible_rabin(p: int, d: int, max_tries: int = 1000) -> list:
    """Random search for an irreducible polynomial of degree d over F_p.
    Returns ascending coefficients [c_0, ..., c_d] with c_d = 1.
    """
    import secrets
    if d <= 3:
        # Fall back to galois (fast for small d, even huge p)
        try:
            import galois
            poly = galois.irreducible_poly(p, d)
            desc = [int(c) for c in poly.coeffs]
            while len(desc) < d + 1:
                desc.insert(0, 0)
            return desc[::-1]
        except Exception:
            pass

    for trial in range(max_tries):
        # Try simple forms first (sparse polynomials)
        if trial < 30:
            # Trinomial X^d + a*X + b (length d+1)
            a = trial % 10 + 1
            b = (trial // 10) % 10 + 1
            f = [b, a] + [0] * (d - 2) + [1]
        elif trial < 100:
            # Random sparse polynomial
            f = [0] * (d + 1)
            f[d] = 1
            n_nonzero = 3 + (trial % 4)
            for _ in range(n_nonzero):
                pos = secrets.randbelow(d)
                f[pos] = (f[pos] + secrets.randbelow(p)) % p
        else:
            # Fully random
            f = [secrets.randbelow(p) for _ in range(d)] + [1]

        # Skip degenerate
        if f[0] == 0:
            f[0] = 1
        try:
            if is_irreducible_rabin(f, p):
                return f
        except Exception:
            continue

    raise RuntimeError(f"Could not find irreducible poly p={p}, d={d} after {max_tries} tries")
