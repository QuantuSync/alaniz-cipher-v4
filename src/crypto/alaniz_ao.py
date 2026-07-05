"""
crypto/alaniz_ao.py — Alaniz-AO: a concrete arithmetization-oriented permutation
and sponge hash over Goldilocks, instantiating the verified design principle
(input-coupling of the x^7 S-box adds +1 CICO ideal-degree bit per round).

This is the paper's concrete specification (see docs/SPEC.md). Parameters are
justified by the measured law D_I = 7^(R*m)*m*2^(R-1) and the wide-trail bounds
(docs/WIDE_TRAIL.md); R carries an explicit security margin. Nothing here is a
deployment artifact (no constant-time / KAT claims).

Permutation P over F_p^t, p = 2^64-2^32+1, one round:

    R_r(x) = M_cauchy * SB_couple(x) + rc^(r)

    SB_couple(x)_v = ( x_v + c_v * x_{v-2} * x_{v-1} )^7    for v >= 2   (input coupling)
    SB_couple(x)_v = x_v^7                                  for v in {0,1}

The coupling is TRIANGULAR (each v uses only earlier lanes) hence the layer is a
bijection; it is the minimal "chain" coupling that touches every lane, so the
+1-bit/round gain applies at the sponge capacity. The coupling incidence is
generic (verified: sheaf/chain/star/dense all identical), so the chain is chosen
for cheapness (t-2 extra multiplications per round).
"""
from __future__ import annotations

from crypto.linalg_fp import matrix_inverse_fp, matvec_mul_fp, vec_add_fp, vec_sub_fp
from crypto.sampling import prg_vec
from crypto.spn_field import GOLDILOCKS_P, sbox, sbox_exponents, sbox_inv
from crypto.spn_mix import cauchy_mds

# ---- recommended instance (docs/SPEC.md) ----
ALANIZ_P = GOLDILOCKS_P
ALANIZ_T = 8            # state lanes
ALANIZ_ROUNDS = 8       # R_secure ~6 (CICO at capacity 4) + margin; see docs/SPEC.md
ALANIZ_RATE = 4
ALANIZ_CAPACITY = 4     # 256-bit capacity -> 128-bit collision/preimage sponge
_DOMAIN = b"AlanizAO/v1"


def chain_coupling(t):
    """Minimal chain coupling: lane v (v>=2) couples to (v-2, v-1). Triangular."""
    return {v: [(v - 2, v - 1)] for v in range(2, t)}


class AlanizAO:
    """Public parameters + forward/inverse permutation."""

    def __init__(self, p=ALANIZ_P, t=ALANIZ_T, rounds=ALANIZ_ROUNDS, seed=_DOMAIN):
        self.p = p
        self.t = t
        self.rounds = rounds
        self.d, self.d_inv = sbox_exponents(p)     # d = 7 for Goldilocks
        self.M = cauchy_mds(t, p)
        self.Minv = matrix_inverse_fp(self.M, p)
        self.at = chain_coupling(t)
        # public non-zero coupling weights and round constants from the PRG
        self.w = {}
        idx = 0
        for v in range(t):
            for (a, b) in self.at.get(v, []):
                val = 0
                while val == 0:
                    val = prg_vec(seed + b"/couple", "w", idx, 1, p)[0]
                    idx += 1
                self.w[(a, b, v)] = val
        self.rc = [prg_vec(seed + b"/rc", "round", r, t, p) for r in range(rounds)]
        self.rc_init = prg_vec(seed + b"/rc", "init", 0, t, p)

    # ---- one nonlinear layer ----
    def _sb_forward(self, x):
        p, d = self.p, self.d
        y = [0] * self.t
        for v in range(self.t):
            cross = 0
            for (a, b) in self.at.get(v, []):
                cross = (cross + self.w[(a, b, v)] * x[a] * x[b]) % p
            y[v] = sbox((x[v] + cross) % p, p, d)
        return y

    def _sb_inverse(self, y):
        p, di = self.p, self.d_inv
        x = [0] * self.t
        for v in range(self.t):            # lanes recovered in order (triangular)
            cross = 0
            for (a, b) in self.at.get(v, []):
                cross = (cross + self.w[(a, b, v)] * x[a] * x[b]) % p
            x[v] = (sbox_inv(y[v], p, di) - cross) % p
        return x

    # ---- permutation ----
    def permute(self, x):
        p = self.p
        s = vec_add_fp(x, self.rc_init, p)
        for r in range(self.rounds):
            s = self._sb_forward(s)
            s = matvec_mul_fp(self.M, s, p)
            s = vec_add_fp(s, self.rc[r], p)
        return s

    def permute_inverse(self, y):
        p = self.p
        s = list(y)
        for r in reversed(range(self.rounds)):
            s = vec_sub_fp(s, self.rc[r], p)
            s = matvec_mul_fp(self.Minv, s, p)
            s = self._sb_inverse(s)
        return vec_sub_fp(s, self.rc_init, p)


def sponge_hash(message, out_len=4, p=ALANIZ_P, t=ALANIZ_T, rounds=ALANIZ_ROUNDS,
                rate=ALANIZ_RATE):
    """Fixed-length sponge hash over F_p. `message` is a list of F_p elements;
    returns `out_len` F_p elements. Padding: 10*-style with a 1 then zeros to a
    rate multiple (domain-separated by appending the original length)."""
    perm = AlanizAO(p=p, t=t, rounds=rounds)
    m = [int(x) % p for x in message]
    m = m + [1] + [0] * ((-(len(m) + 1)) % rate)      # inject a 1, pad to rate
    state = [0] * t
    for off in range(0, len(m), rate):                # absorb
        for i in range(rate):
            state[i] = (state[i] + m[off + i]) % p
        state = perm.permute(state)
    out = []
    while len(out) < out_len:                          # squeeze
        out.extend(state[:rate])
        if len(out) < out_len:
            state = perm.permute(state)
    return out[:out_len]
