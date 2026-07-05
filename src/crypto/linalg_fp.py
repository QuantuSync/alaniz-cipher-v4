"""
crypto/linalg_fp.py — minimal dense linear algebra over F_p for the reference
(pq128) path. Consolidated here (Phase 0) so the reference path has ONE home for
F_p matrix/vector arithmetic instead of copies scattered across modules.

Matrices are list-of-lists of Python ints; vectors are lists of Python ints.
All operations reduce mod p. No numpy/galois dependency.
"""
from __future__ import annotations


def matrix_det_fp(M: list, p: int) -> int:
    """Determinant of a d×d matrix over F_p via Gaussian elimination."""
    d = len(M)
    A = [row[:] for row in M]
    sign = 1
    for col in range(d):
        pv = -1
        for r in range(col, d):
            if A[r][col] % p != 0:
                pv = r
                break
        if pv == -1:
            return 0
        if pv != col:
            A[col], A[pv] = A[pv], A[col]
            sign = -sign
        inv = pow(A[col][col], p - 2, p)
        for r in range(col + 1, d):
            factor = (A[r][col] * inv) % p
            for c in range(col, d):
                A[r][c] = (A[r][c] - factor * A[col][c]) % p
    det = sign
    for i in range(d):
        det = (det * A[i][i]) % p
    return det % p


def matrix_rank_fp(M: list, p: int) -> int:
    """Rank of a (possibly rectangular) matrix over F_p via Gaussian elimination."""
    if not M or not M[0]:
        return 0
    A = [[x % p for x in row] for row in M]
    nrows, ncols = len(A), len(A[0])
    rank = 0
    for col in range(ncols):
        pv = -1
        for r in range(rank, nrows):
            if A[r][col] != 0:
                pv = r
                break
        if pv == -1:
            continue
        A[rank], A[pv] = A[pv], A[rank]
        inv = pow(A[rank][col], p - 2, p)
        for r in range(rank + 1, nrows):
            if A[r][col] != 0:
                factor = (A[r][col] * inv) % p
                for c in range(col, ncols):
                    A[r][c] = (A[r][c] - factor * A[rank][c]) % p
        rank += 1
        if rank == nrows:
            break
    return rank


def matrix_mul_fp(A: list, B: list, p: int) -> list:
    """Matrix product A·B over F_p."""
    d = len(A)
    C = [[0] * d for _ in range(d)]
    for i in range(d):
        for k in range(d):
            if A[i][k] == 0:
                continue
            aik = A[i][k]
            for j in range(d):
                C[i][j] = (C[i][j] + aik * B[k][j]) % p
    return C


def matrix_inverse_fp(M: list, p: int) -> list:
    """Inverse of a d×d matrix over F_p via Gauss-Jordan. Raises if singular."""
    d = len(M)
    A = [row[:] + [1 if i == j else 0 for j in range(d)] for i, row in enumerate(M)]
    for col in range(d):
        pv = -1
        for r in range(col, d):
            if A[r][col] % p != 0:
                pv = r
                break
        if pv == -1:
            raise ValueError("Singular matrix")
        if pv != col:
            A[col], A[pv] = A[pv], A[col]
        inv = pow(A[col][col], p - 2, p)
        for c in range(2 * d):
            A[col][c] = (A[col][c] * inv) % p
        for r in range(d):
            if r != col and A[r][col] % p != 0:
                factor = A[r][col] % p
                for c in range(2 * d):
                    A[r][c] = (A[r][c] - factor * A[col][c]) % p
    return [row[d:] for row in A]


def matvec_mul_fp(M: list, v: list, p: int) -> list:
    """Matrix-vector product M·v over F_p."""
    d = len(M)
    out = []
    for i in range(d):
        s = 0
        row = M[i]
        for j in range(d):
            s = (s + row[j] * v[j]) % p
        out.append(s)
    return out


def vec_add_fp(a: list, b: list, p: int) -> list:
    return [(a[i] + b[i]) % p for i in range(len(a))]


def vec_sub_fp(a: list, b: list, p: int) -> list:
    return [(a[i] - b[i]) % p for i in range(len(a))]
