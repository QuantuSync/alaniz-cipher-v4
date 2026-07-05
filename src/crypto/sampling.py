"""
crypto/sampling.py — unbiased sampling helpers for the reference (pq128) path.

Consolidates all key-material sampling in ONE place so that the Phase-0 fix for
H3 (module-bias / entropy collapse) lives in a single audited location.

The two bugs this module fixes:

  1. **H3 entropy collapse (catastrophic).** The old code drew
         int(rng.integers(0, 2**62)) % (p**d)
     for β and L. With p = 2^61-1 and d ≥ 2 the field has ~2^366 elements but
     the draw never exceeds 2^62, so `from_int` produced elements of the form
     (a0, a1, 0, ..., 0) with a1 ∈ {0,1,2,3}. β and L were confined to a
     ~2^62 near-scalar subset. Fix: `uniform_int_below` draws a full-width
     integer in [0, N) by rejection sampling over exact bit-length blocks.

  2. **Module bias (minor but real).** `int(rng.integers(0, 2**62)) % p` for
     matrix entries and `int.from_bytes(chunk) % p` in the PRG are non-uniform
     whenever p does not divide the draw range. Fixed by per-value rejection.

All helpers are deterministic given a seeded `numpy.random.Generator` or, for
the PRG, given (nonce, label, idx): fixed seeds ⇒ reproducible experiments.
"""
from __future__ import annotations

import hashlib

# Explicit domain-separation tag for the PRG. Bump the version suffix if the
# PRG construction ever changes (it changes all derived masks).
_PRG_DOMAIN = b"AlanizCipher/v4r3/PRG/v1"


# ─────────────────────────── uniform integers ───────────────────────────

def uniform_int_below(rng, N: int) -> int:
    """Return a uniform integer in [0, N) using rejection sampling.

    Deterministic given the seeded numpy Generator `rng`. Works for arbitrary
    big-int N (e.g. p**d ≈ 2^366). Unbiased: draws exact bit-length blocks and
    rejects out-of-range candidates (acceptance probability > 1/2).
    """
    if N <= 0:
        raise ValueError("N must be positive")
    if N == 1:
        return 0
    nbits = (N - 1).bit_length()
    nbytes = (nbits + 7) // 8
    excess = nbytes * 8 - nbits  # top bits to mask off to reduce rejection
    while True:
        raw = rng.bytes(nbytes)
        val = int.from_bytes(raw, "big")
        if excess:
            val >>= excess
        if val < N:
            return val


def uniform_fp(rng, p: int) -> int:
    """Uniform element of F_p as an int in [0, p)."""
    return uniform_int_below(rng, p)


# ─────────────────────────── field elements ───────────────────────────

def random_fq_element(F, rng, exclude_ints=()):  # -> tuple
    """Uniform element of F_q = F_{p^d}, excluding the given integer encodings.

    `from_int` is a bijection [0, p^d) → F_q (positional base-p), so a uniform
    integer maps to a uniform field element. `exclude_ints` are integer codes
    to reject (e.g. () for none, (0,) for non-zero, (0, 1) for β ∉ {0, 1}).
    """
    N = F.p ** F.d
    exclude = set(exclude_ints)
    while True:
        n = uniform_int_below(rng, N)
        if n not in exclude:
            return F.from_int(n)


# ─────────────────────────── matrices over F_p ───────────────────────────

def random_matrix_fp(p: int, d: int, rng) -> list:
    """Uniform d×d matrix over F_p (each entry unbiased)."""
    return [[uniform_int_below(rng, p) for _ in range(d)] for _ in range(d)]


def random_invertible_matrix_fp(p: int, d: int, rng) -> list:
    """Uniform d×d invertible matrix over F_p (unbiased entries + GL check).

    Rejection over uniform matrices; a uniform random matrix is invertible with
    probability Π_{i=1..d}(1 - p^{-i}) > 0.28 for all p, d, so this terminates
    quickly.
    """
    from crypto.linalg_fp import matrix_det_fp
    while True:
        M = random_matrix_fp(p, d, rng)
        if matrix_det_fp(M, p) != 0:
            return M


# ─────────────────────────── PRG (mask derivation) ───────────────────────────

def _shake_block(seed_material: bytes, counter: int, nbytes: int) -> bytes:
    """One deterministic SHAKE-256 block keyed by (seed_material, counter)."""
    h = hashlib.shake_256()
    h.update(seed_material)
    h.update(counter.to_bytes(4, "big"))
    return h.digest(nbytes)


def _domain_input(nonce: bytes, label: str, idx: int) -> bytes:
    """Length-prefixed, domain-separated PRG input.

    Length-prefixing every variable-length field prevents concatenation
    ambiguity (e.g. distinct (label, idx) pairs can never collide into the
    same byte string).
    """
    lbl = label.encode("utf-8")
    return (
        _PRG_DOMAIN
        + len(nonce).to_bytes(2, "big") + nonce
        + len(lbl).to_bytes(2, "big") + lbl
        + idx.to_bytes(4, "big")
    )


def prg_vec(nonce: bytes, label: str, idx: int, d: int, p: int) -> list:
    """Derive an unbiased F_p^d vector from (nonce, label, idx).

    Uses SHAKE-256 as an XOF with explicit domain separation and per-coordinate
    rejection sampling, so each coordinate is EXACTLY uniform over F_p (no
    module bias). Deterministic: identical inputs ⇒ identical output, which is
    required for encrypt/decrypt mask agreement.
    """
    seed = _domain_input(nonce, label, idx)
    nbits = (p - 1).bit_length()
    nbytes = (nbits + 7) // 8
    excess = nbytes * 8 - nbits
    # Pull SHAKE output in blocks; each coordinate consumes `nbytes`, rejecting
    # candidates ≥ p. Block size is generous so rejection rarely crosses blocks.
    BLOCK = max(64, nbytes * d * 2)
    vals = []
    counter = 0
    buf = _shake_block(seed, counter, BLOCK)
    pos = 0
    while len(vals) < d:
        if pos + nbytes > len(buf):
            counter += 1
            buf = _shake_block(seed, counter, BLOCK)
            pos = 0
        chunk = buf[pos:pos + nbytes]
        pos += nbytes
        v = int.from_bytes(chunk, "big")
        if excess:
            v >>= excess
        if v < p:
            vals.append(v)
    return vals
