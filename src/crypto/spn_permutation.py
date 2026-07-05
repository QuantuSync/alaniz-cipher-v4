"""
crypto/spn_permutation.py — AO SPN permutation over F_p^t (Phase 3a).

State lives in F_p^t (one field element per vertex v ∈ V, t = |V|); the sheaf
mixing already couples the t coordinates, so — unlike the discarded construction
— there is NO field extension F_{p^d} here. Everything is public.

One round (full SPN, all S-boxes active):

    R_r(x) = M · SB(x) + rc^(r)          SB(x)_i = x_i^7   (componentwise)

with M the public sheaf mixing matrix (crypto.spn_mix.sheaf_mix_matrix) and
rc^(r) the r-th round-constant vector (PRG, domain-separated). The full
permutation applies an initial constant addition then R rounds:

    P(x) = R_{R-1} ∘ ... ∘ R_0 (x + rc^(init))

Governing lesson (A6-CICO): algebraic degree grows by ROUND COMPOSITION
(deg 7^R), never by an expensive one-shot S-box. Each round is bijective:
SB is a bijection (gcd(7,p-1)=1), M is invertible, +rc is a translation, so P
is a permutation and P^{-1} is exact.

NOTE (optimization deferred): a Poseidon2-style partial-round strategy (one
S-box per internal round) would cut cost; it is a later optimization and is
NOT modeled here — we analyze the conservative full-SPN first.
"""
from __future__ import annotations

from crypto.linalg_fp import matrix_inverse_fp, matvec_mul_fp, vec_add_fp, vec_sub_fp
from crypto.sampling import prg_vec
from crypto.spn_field import sbox, sbox_exponents, sbox_inv
from crypto.spn_mix import sheaf_mix_matrix


class SPNParams:
    """Public parameters of the AO SPN permutation."""

    def __init__(self, K, p, R, seed=b"spn/v1", d=None):
        self.K = K
        self.t = K.n
        self.p = p
        self.R = R
        self.seed = seed
        self.d, self.d_inv = sbox_exponents(p, d)  # d = 7 for Goldilocks-like p
        self.M = sheaf_mix_matrix(K, p, seed + b"/mix")
        self.Minv = matrix_inverse_fp(self.M, p)
        # Round constants: R round vectors + 1 initial, each F_p^t, PRG-derived.
        self.rc = [prg_vec(seed + b"/rc", "round", r, self.t, p)
                   for r in range(R)]
        self.rc_init = prg_vec(seed + b"/rc", "init", 0, self.t, p)

    def __repr__(self):
        return f"SPNParams(t={self.t}, p={self.p}, R={self.R}, d={self.d})"


def sbox_layer(x, p, d):
    return [sbox(xi, p, d) for xi in x]


def sbox_layer_inv(y, p, d_inv):
    return [sbox_inv(yi, p, d_inv) for yi in y]


def permute(params, x):
    """Forward permutation P(x) on state x ∈ F_p^t."""
    p, d = params.p, params.d
    state = vec_add_fp(x, params.rc_init, p)
    for r in range(params.R):
        state = sbox_layer(state, p, d)
        state = matvec_mul_fp(params.M, state, p)
        state = vec_add_fp(state, params.rc[r], p)
    return state


def permute_inverse(params, y):
    """Inverse permutation P^{-1}(y)."""
    p, d_inv = params.p, params.d_inv
    state = list(y)
    for r in reversed(range(params.R)):
        state = vec_sub_fp(state, params.rc[r], p)
        state = matvec_mul_fp(params.Minv, state, p)
        state = sbox_layer_inv(state, p, d_inv)
    state = vec_sub_fp(state, params.rc_init, p)
    return state
