"""
crypto/spn_cico.py — CICO polynomial model of the AO SPN for msolve (Phase 3b).

This builds the FreeLunch-style **intermediate-variable** modeling (eprint
2024/347, §modeling), NOT a single high-degree interpolated map. The A6-CICO
break of the old construction came precisely from a one-round map whose S-box
could be inverted directly; here we keep one variable per S-box input at every
round so the system degree stays 7 (deg grows only through the round chain),
which is the setting FreeLunch / CheapLunch / resultant attacks target.

Variables:  x{r}_{i}   for r = 0..R-1 (round), i = 0..t-1 (vertex)
            = the S-box INPUT of round r at coordinate i  (t·R variables).

Equations (all reduced mod p):
  (link)  for r = 0..R-2, each i:
             x{r+1}_i - ( Σ_j M[i][j] · x{r}_j^7 ) - rc[r][i] = 0        (deg 7)
  (in)    x{0}_i - (input_i + rc_init_i) = 0   for i in the fixed input set (deg 1)
  (out)   ( Σ_j M[i][j] · x{R-1}_j^7 ) + rc[R-1]_i - w_i = 0
             for i in the fixed output set                                (deg 7)

CICO capacity c: fix c input coords (indices t-c..t-1) and (t-c) output coords
(indices 0..t-c-1). Total equations = t·(R-1) + c + (t-c) = t·R = #variables,
so the system is square / 0-dimensional generically. Sweeping c lets us report
the attacker-optimal (cheapest) instance.

The `input`/`w` right-hand sides come from an actual permutation evaluation on a
random-but-fixed seed, so the system is guaranteed consistent (has a solution).
"""
from __future__ import annotations

from crypto.spn_permutation import permute, sbox_layer


def var(r, i):
    return f"x{r}_{i}"


# msolve's polynomial parser mis-handles parentheses (verified: `x-(y+1)` is
# parsed incorrectly), so every polynomial below is emitted FULLY EXPANDED with
# explicit per-term signs and no grouping.

def _signed_term(coef, monomial, p):
    """Return (sign_char, 'coef*monomial') with coef reduced to (0, p)."""
    c = coef % p
    if c == 0:
        return None
    if monomial:
        return "+", f"{c}*{monomial}"
    return "+", f"{c}"


def _poly_from_terms(terms):
    """Assemble a parenthesis-free msolve polynomial from (sign, body) terms."""
    if not terms:
        return "0"
    s, body = terms[0]
    out = ("-" + body) if s == "-" else body
    for s, body in terms[1:]:
        out += ("-" if s == "-" else "+") + body
    return out


def build_cico_system(params, c, seed_rhs=b"cico-rhs", witness=None):
    """Return (variables, polys, meta) for the CICO system at capacity c.

    variables : list of msolve variable names (t·R of them)
    polys     : list of polynomial strings (msolve syntax, = 0)
    meta      : dict with n_vars, n_eqs, fixed_in, fixed_out, witness
    """
    p, t, R, M = params.p, params.t, params.R, params.M
    if not (1 <= c <= t - 1):
        raise ValueError("capacity c must satisfy 1 <= c <= t-1")

    # A consistent instance: pick a witness input, evaluate the permutation.
    if witness is None:
        from crypto.sampling import prg_vec
        witness = prg_vec(seed_rhs, "in", 0, t, p)
    out = permute(params, witness)

    fixed_in = list(range(t - c, t))        # last c input coords fixed
    fixed_out = list(range(0, t - c))       # first t-c output coords fixed

    # S-box inputs of each round for the witness (to pin the RHS constants).
    xin = [(witness[i] + params.rc_init[i]) % p for i in range(t)]  # x^(0)
    states = [xin]
    s = xin
    for r in range(R - 1):
        after = sbox_layer(s, p, params.d)
        nxt = [0] * t
        for i in range(t):
            acc = 0
            for j in range(t):
                acc = (acc + M[i][j] * after[j]) % p
            nxt[i] = (acc + params.rc[r][i]) % p
        states.append(nxt)
        s = nxt

    variables = [var(r, i) for r in range(R) for i in range(t)]
    polys = []

    # (link)  x{r+1}_i - Σ_j M[i][j]·x{r}_j^7 - rc[r][i]
    for r in range(R - 1):
        for i in range(t):
            terms = [("+", var(r + 1, i))]
            for j in range(t):
                c = (-M[i][j]) % p
                term = _signed_term(c, f"{var(r, j)}^7", p)
                if term:
                    terms.append(term)
            term = _signed_term((-params.rc[r][i]) % p, "", p)
            if term:
                terms.append(term)
            polys.append(_poly_from_terms(terms))

    # (in)  x{0}_i - (witness_i + rc_init_i)
    for i in fixed_in:
        val = (witness[i] + params.rc_init[i]) % p
        terms = [("+", var(0, i))]
        term = _signed_term((-val) % p, "", p)
        if term:
            terms.append(term)
        polys.append(_poly_from_terms(terms))

    # (out)  Σ_j M[i][j]·x{R-1}_j^7 + rc[R-1][i] - w_i
    for i in fixed_out:
        terms = []
        for j in range(t):
            term = _signed_term(M[i][j], f"{var(R - 1, j)}^7", p)
            if term:
                terms.append(term)
        rhs = (params.rc[R - 1][i] - out[i]) % p
        term = _signed_term(rhs, "", p)
        if term:
            terms.append(term)
        polys.append(_poly_from_terms(terms))

    meta = {
        "n_vars": len(variables), "n_eqs": len(polys),
        "fixed_in": fixed_in, "fixed_out": fixed_out,
        "witness": witness, "output": out, "states": states, "c": c,
    }
    return variables, polys, meta


def to_msolve(variables, polys, p):
    """Serialize to msolve input format.

    IMPORTANT: msolve's parser does NOT tolerate carriage returns. On Windows,
    Python text-mode writes translate '\\n' -> '\\r\\n', which silently corrupts
    every polynomial and makes msolve report a spurious empty variety ([-1] /
    GB=[1]). Callers MUST write the returned string with LF endings, e.g.
        open(path, "w", newline="\\n").write(to_msolve(...))
    (see write_msolve below, which enforces this).
    """
    lines = [",".join(variables), str(p)]
    lines.append(",\n".join(polys))
    return "\n".join(lines) + "\n"


def write_msolve(path, variables, polys, p):
    """Write an msolve input file with LF line endings (never CRLF)."""
    with open(path, "w", newline="\n") as fh:
        fh.write(to_msolve(variables, polys, p))
