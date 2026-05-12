"""
core/complex2d.py — 2-dimensional simplicial complex.

A complex K = (V, E, T) where:
  V = {0, ..., n-1}
  E ⊆ {(u,v) : u < v}
  T ⊆ {(u,v,w) : u < v < w, all 3 edges in E}

Triangle orientation convention: t = [u,v,w] with u<v<w; oriented boundary
  ∂t = +(v,w) − (u,w) + (u,v).
"""
from __future__ import annotations
from typing import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class Complex2D:
    n: int                         # |V|
    edges: tuple                   # tuple of (u,v) with u<v
    triangles: tuple               # tuple of (u,v,w) with u<v<w

    def __post_init__(self):
        # Sanity checks
        for e in self.edges:
            u, v = e
            assert 0 <= u < v < self.n, f"Bad edge {e}"
        ei = self.edge_idx
        for t in self.triangles:
            u, v, w = t
            assert 0 <= u < v < w < self.n, f"Bad triangle {t}"
            for e in [(u, v), (u, w), (v, w)]:
                assert e in ei, f"Triangle {t} missing edge {e}"

    @property
    def m(self) -> int:
        return len(self.edges)

    @property
    def l(self) -> int:
        return len(self.triangles)

    @property
    def edge_idx(self) -> dict:
        if not hasattr(self, "_edge_idx_cache"):
            object.__setattr__(self, "_edge_idx_cache",
                               {e: i for i, e in enumerate(self.edges)})
        return self._edge_idx_cache

    def euler_char(self) -> int:
        return self.n - self.m + self.l

    @classmethod
    def tetrahedron(cls) -> "Complex2D":
        """χ = 2, sphere."""
        n = 4
        edges = tuple(sorted((i, j) for i in range(n) for j in range(i + 1, n)))
        triangles = tuple(sorted(
            (i, j, k) for i in range(n)
            for j in range(i + 1, n) for k in range(j + 1, n)
        ))
        return cls(n, edges, triangles)

    @classmethod
    def octahedron(cls) -> "Complex2D":
        """χ = 2, sphere with 6 vertices, 12 edges, 8 triangles."""
        # Vertex layout: 0=N pole, 1=S pole, 2-5=equator (CCW)
        edges = sorted({
            *((0, i) for i in (2, 3, 4, 5)),
            *((1, i) for i in (2, 3, 4, 5)),
            (2, 3), (3, 4), (4, 5), (2, 5),
        })
        triangles = sorted({
            (0, 2, 3), (0, 3, 4), (0, 4, 5), (0, 2, 5),
            (1, 2, 3), (1, 3, 4), (1, 4, 5), (1, 2, 5),
        })
        return cls(6, tuple(edges), tuple(triangles))

    @classmethod
    def torus(cls, m: int, n: int) -> "Complex2D":
        """
        Triangulated flat torus: m × n grid with (i,j)→(i+1,j+1) diagonal.
        χ = 0.  Each cell is split into two triangles: lower (i,j),(i+1,j),(i+1,j+1)
        and upper (i,j),(i,j+1),(i+1,j+1).
        Indices are sorted to maintain u<v<w convention.
        """
        N = m * n
        idx = lambda i, j: (i % m) * n + (j % n)
        edges = set()
        triangles = set()
        for i in range(m):
            for j in range(n):
                a = idx(i, j)
                b = idx(i, j + 1)
                c = idx(i + 1, j)
                e = idx(i + 1, j + 1)
                # 6 edges around this cell that we own (the right and bottom borders + diag)
                for u, v in [(a, b), (a, c), (a, e), (b, e), (c, e)]:
                    if u != v:
                        edges.add(tuple(sorted((u, v))))
                # Triangles, sorted
                t1 = tuple(sorted((a, b, e)))
                t2 = tuple(sorted((a, c, e)))
                # Skip degenerate
                if len(set(t1)) == 3:
                    triangles.add(t1)
                if len(set(t2)) == 3:
                    triangles.add(t2)
        return cls(N, tuple(sorted(edges)), tuple(sorted(triangles)))

    @classmethod
    def double_tetrahedron(cls) -> "Complex2D":
        """Two tetrahedra glued on a face: 5 vertices, 9 edges, 6 triangles. χ=2."""
        edges = tuple(sorted({
            (0, 1), (0, 2), (0, 3),
            (1, 2), (1, 3), (2, 3),
            (1, 4), (2, 4), (3, 4),
        }))
        triangles = tuple(sorted({
            (0, 1, 2), (0, 1, 3), (0, 2, 3),
            (1, 2, 4), (1, 3, 4), (2, 3, 4),
        }))
        return cls(5, edges, triangles)

    def __repr__(self) -> str:
        return (f"Complex2D(V={self.n}, E={self.m}, T={self.l}, "
                f"χ={self.euler_char()})")
