"""
core/sheaf2d.py — Cellular sheaf on a 2-complex.

Stalks are F_p^d at every cell. Restriction maps:
  rho_ve[(v,e)] : F_p^d → F_p^d   for v ∈ e
  rho_et[(e,t)] : F_p^d → F_p^d   for e ∈ ∂t

Coboundaries:
  (δ⁰s)_e = ρ_{v,e} s_v − ρ_{u,e} s_u                   for e=[u,v], u<v
  (δ¹ζ)_t = ρ_{(v,w),t} ζ_{v,w} − ρ_{(u,w),t} ζ_{u,w}
                                  + ρ_{(u,v),t} ζ_{u,v}  for t=[u,v,w]
"""
from __future__ import annotations
import numpy as np
import galois
from .complex2d import Complex2D


class Sheaf2D:
    def __init__(self, K: Complex2D, d: int, p: int,
                 rho_ve: dict | None = None,
                 rho_et: dict | None = None,
                 rng: np.random.Generator | None = None):
        self.K = K
        self.d = d
        self.p = p
        self.GF = galois.GF(p)
        rng = rng or np.random.default_rng(0xA1A2)

        # Vertex → edge restrictions
        if rho_ve is None:
            self.rho_ve = {}
            for e_idx, (u, v) in enumerate(K.edges):
                for vert in (u, v):
                    self.rho_ve[(vert, e_idx)] = self._random_gl(rng)
        else:
            self.rho_ve = rho_ve

        # Edge → triangle restrictions
        if rho_et is None:
            self.rho_et = {}
            for t_idx, t in enumerate(K.triangles):
                u, v, w = t
                for e in [(u, v), (u, w), (v, w)]:
                    e_idx = K.edge_idx[e]
                    self.rho_et[(e_idx, t_idx)] = self._random_gl(rng)
        else:
            self.rho_et = rho_et

    def _random_gl(self, rng) -> "galois.FieldArray":
        """Random invertible matrix over F_p."""
        while True:
            M = self.GF(rng.integers(0, self.p, size=(self.d, self.d)).astype(np.int64))
            try:
                _ = np.linalg.inv(M)
                return M
            except Exception:
                continue

    # ───────────────────────────────────────────────────────── Coboundaries

    def coboundary_0_matrix(self) -> "galois.FieldArray":
        """δ⁰: F_p^{nd} → F_p^{md}. Returns matrix of shape (md, nd)."""
        n, m, d = self.K.n, self.K.m, self.d
        D = self.GF.Zeros((m * d, n * d))
        for e_idx, (u, v) in enumerate(self.K.edges):
            r = e_idx * d
            D[r:r + d, u * d:u * d + d] = -self.rho_ve[(u, e_idx)]
            D[r:r + d, v * d:v * d + d] = self.rho_ve[(v, e_idx)]
        return D

    def coboundary_1_matrix(self) -> "galois.FieldArray":
        """δ¹: F_p^{md} → F_p^{ld}. Returns matrix of shape (ld, md)."""
        m, l, d = self.K.m, self.K.l, self.d
        D = self.GF.Zeros((l * d, m * d))
        for t_idx, (u, v, w) in enumerate(self.K.triangles):
            e_uv = self.K.edge_idx[(u, v)]
            e_uw = self.K.edge_idx[(u, w)]
            e_vw = self.K.edge_idx[(v, w)]
            r = t_idx * d
            D[r:r + d, e_uv * d:e_uv * d + d] = self.rho_et[(e_uv, t_idx)]
            D[r:r + d, e_uw * d:e_uw * d + d] = -self.rho_et[(e_uw, t_idx)]
            D[r:r + d, e_vw * d:e_vw * d + d] = self.rho_et[(e_vw, t_idx)]
        return D

    # ───────────────────────────────────────────────────────── Cohomology

    def cohomology_dims(self) -> dict:
        """Compute dim H⁰, dim Z¹, dim H¹, dim H²."""
        n, m, l, d = self.K.n, self.K.m, self.K.l, self.d
        D0 = self.coboundary_0_matrix()
        D1 = self.coboundary_1_matrix()
        rank0 = int(np.linalg.matrix_rank(D0))
        rank1 = int(np.linalg.matrix_rank(D1))
        dim_C0 = n * d
        dim_C1 = m * d
        dim_C2 = l * d
        return {
            "dim_C0": dim_C0, "dim_C1": dim_C1, "dim_C2": dim_C2,
            "dim_H0": dim_C0 - rank0,
            "dim_Z1": dim_C1 - rank1,
            "dim_B1": rank0,
            "dim_H1": dim_C1 - rank1 - rank0,
            "dim_H2": dim_C2 - rank1,
            "rank_D0": rank0,
            "rank_D1": rank1,
        }

    def H0_basis(self) -> "galois.FieldArray":
        """Basis of H⁰ as columns. Shape (nd, k0)."""
        D0 = self.coboundary_0_matrix()
        # null_space() returns rows; transpose to columns
        ns = D0.null_space()
        return ns.T

    def Z1_basis(self) -> "galois.FieldArray":
        """Basis of Z¹ as columns. Shape (md, k_z1)."""
        D1 = self.coboundary_1_matrix()
        ns = D1.null_space()
        return ns.T

    # ───────────────────────────────────────────────────────── Helpers

    def is_global_section(self, s_flat) -> bool:
        """Check δ⁰s = 0 for s ∈ F_p^{nd} flat."""
        D0 = self.coboundary_0_matrix()
        s = self.GF(np.asarray(s_flat, dtype=np.int64) % self.p)
        return bool(np.all(D0 @ s == 0))

    def is_cocycle(self, eta_flat) -> bool:
        """Check δ¹η = 0 for η ∈ F_p^{md} flat."""
        D1 = self.coboundary_1_matrix()
        e = self.GF(np.asarray(eta_flat, dtype=np.int64) % self.p)
        return bool(np.all(D1 @ e == 0))

    @classmethod
    def cocycle_compatible(cls, K: Complex2D, d: int, p: int,
                           rng: np.random.Generator | None = None,
                           h0_target: int | None = None) -> "Sheaf2D":
        """
        Build a sheaf whose vertex→edge restrictions admit a non-trivial H⁰
        of dimension at least max(d, h0_target if given).

        Strategy: pick rho_ve such that for some basis section s* ∈ (F_p^d)^V
        the consistency δ⁰s* = 0 holds. We do this by choosing all rho_ve
        such that there is a 'reference' family of sections that are kernels.
        """
        rng = rng or np.random.default_rng(0xC0C0)
        GF = galois.GF(p)
        # Pick rho_ve such that for each vertex v, rho_{v,e} = M_e · T_v for some
        # invertible M_e (per edge) and T_v (per vertex). Then ρ_{v,e} s_v − ρ_{u,e} s_u =
        # M_e (T_v s_v − T_u s_u). For this to vanish, T_v s_v is constant over v.
        # That gives dim H⁰ = d (after the change of variable).
        T = {v: cls._gen_random_gl(GF, d, rng) for v in range(K.n)}
        rho_ve = {}
        for e_idx, (u, v) in enumerate(K.edges):
            M_e = cls._gen_random_gl(GF, d, rng)
            rho_ve[(u, e_idx)] = M_e @ T[u]
            rho_ve[(v, e_idx)] = M_e @ T[v]

        # For triangles, generate independent random restrictions (no special structure).
        rho_et = {}
        for t_idx, t in enumerate(K.triangles):
            u, v, w = t
            for e in [(u, v), (u, w), (v, w)]:
                e_idx = K.edge_idx[e]
                rho_et[(e_idx, t_idx)] = cls._gen_random_gl(GF, d, rng)

        return cls(K, d, p, rho_ve=rho_ve, rho_et=rho_et)

    @staticmethod
    def _gen_random_gl(GF, d: int, rng) -> "galois.FieldArray":
        p = int(GF.order)
        while True:
            M = GF(rng.integers(0, p, size=(d, d)).astype(np.int64))
            try:
                np.linalg.inv(M)
                return M
            except Exception:
                continue

    def __repr__(self) -> str:
        dims = self.cohomology_dims()
        return (f"Sheaf2D({self.K}, d={self.d}, p={self.p}, "
                f"H0={dims['dim_H0']}, Z1={dims['dim_Z1']}, H1={dims['dim_H1']})")
