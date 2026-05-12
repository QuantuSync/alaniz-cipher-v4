"""
Experiment 27 — Quantum security analysis of v4r3.

The relevant quantum threat to multivariate cryptography is NOT Shor's algorithm
(which doesn't apply — multivariate has no abelian group structure). It's the
quantum speedup of Gröbner basis algorithms.

Two main quantum approaches:
(A) Grover-amplified brute force: try all α ∈ F_p^d, check encryption. Cost
    O(p^{d/2}) field operations. Trivially exponential, no help for v4r3 at PQ-128
    because p^d is huge (2^732 for d=12). Already accounted for in classical search
    cost being dominated by F4.

(B) Quantum-accelerated linear algebra inside F4. The F4 algorithm's bottleneck is
    Gaussian elimination on a Macaulay matrix of size N × N where N = C(d+D, D).
    Best known quantum speedup for matrix multiplication / GE: subquadratic but
    NOT cube-root. Specifically:
    
    Classical Strassen-like:  N^ω  with ω ≈ 2.37
    Quantum Grover (search):  N^2 → N · √N = N^{1.5}  for SEARCH within row
                              but full GE is harder than search
    Best known quantum GE:     N^{2.5}  via QRAM-style techniques
    
    Conservative: assume quantum F4 cost ≈ N^{2.0} (so quantum speeds up by
    a factor ω/2 = 1.185 in the exponent).
    
    Aggressive (Faugère's pessimistic analysis): quantum F4 cost ≈ N^{1.5}.

For 128-bit QUANTUM security, we want quantum-F4-cost ≥ 2^128.

We compute parameters that achieve this under both conservative and aggressive
quantum cost models.
"""

from math import comb, log2


def hilbert_dreg(m: int, d: int, deg: int, max_D: int = 5000) -> int:
    for D in range(max_D + 1):
        coef = 0
        k = 0
        while deg * k <= D:
            if k > m: break
            sign = -1 if k & 1 else 1
            coef += sign * comb(m, k) * comb(d - 1 + D - deg*k, d - 1)
            k += 1
        if coef <= 0:
            return D
    return None


def cost_classical_F4(D_reg: int, d: int, omega: float = 2.37) -> float:
    N = comb(d + D_reg, D_reg)
    return omega * log2(N)


def cost_quantum_F4_conservative(D_reg: int, d: int) -> float:
    """Quantum F4 with exponent ω → 2.0 (subquadratic GE)."""
    N = comb(d + D_reg, D_reg)
    return 2.0 * log2(N)


def cost_quantum_F4_aggressive(D_reg: int, d: int) -> float:
    """Quantum F4 with exponent ω → 1.5 (Grover-style on search subroutines).
    
    This is an upper bound on quantum speedup; in practice unlikely achievable
    because F4 elimination isn't purely a search problem.
    """
    N = comb(d + D_reg, D_reg)
    return 1.5 * log2(N)


def main():
    print("=" * 80)
    print(" Experiment 27: quantum security analysis under Grover-amplified F4")
    print("=" * 80)
    print()
    print("Threat model: adversary has quantum computer of size required to run F4")
    print("with reduced exponent ω. Conservative ω=2.0, aggressive ω=1.5.")
    print()
    print("Goal: find (d, e) achieving 128-bit QUANTUM security.")
    print()

    print(f"  {'substrate':<10s} {'d':>3s} {'e':>4s} {'deg':>5s} {'m':>4s} {'D_reg':>6s} "
          f"{'C(ω=2.37)':>10s} {'Q(ω=2.0)':>9s} {'Q(ω=1.5)':>9s}")
    print("  " + "-" * 76)

    # Tetra
    n = 4
    for d in [6, 8, 10, 12, 14, 16, 20]:
        for e_val in [17, 31, 61, 127, 257, 503, 1019]:
            m = n * d
            deg = 3 * e_val
            D_reg = hilbert_dreg(m, d, deg)
            if D_reg is None:
                continue
            c_cost = cost_classical_F4(D_reg, d)
            q_cost_cons = cost_quantum_F4_conservative(D_reg, d)
            q_cost_aggr = cost_quantum_F4_aggressive(D_reg, d)
            flag_q = " ✓Q" if q_cost_cons >= 128 else ""
            print(f"  tetra      {d:>3d} {e_val:>4d} {deg:>5d} {m:>4d} {D_reg:>6d} "
                  f"{c_cost:>10.1f} {q_cost_cons:>9.1f} {q_cost_aggr:>9.1f}{flag_q}")
        print()

    print()
    print("=" * 80)
    print(" Smallest (d, e) per substrate reaching 128-bit QUANTUM security")
    print("=" * 80)
    print()
    print(" Under CONSERVATIVE quantum (ω=2.0):")
    for n_vertices, label in [(4, "tetra"), (5, "double_tet"), (6, "octa")]:
        smallest_d = None
        smallest_e = None
        smallest_cost = None
        for d in [6, 8, 10, 12, 14, 16, 20, 24]:
            for e_val in [17, 31, 61, 127, 257, 503, 1019, 2003, 4001]:
                m = n_vertices * d
                deg = 3 * e_val
                D_reg = hilbert_dreg(m, d, deg)
                if D_reg is None: continue
                q_cost = cost_quantum_F4_conservative(D_reg, d)
                if q_cost >= 128 and (smallest_d is None or
                                         (d < smallest_d or (d == smallest_d and e_val < smallest_e))):
                    smallest_d = d
                    smallest_e = e_val
                    smallest_cost = q_cost
                    break  # smallest e for this d
            if smallest_d == d:
                break  # found minimum
        if smallest_d:
            print(f"  {label}: d={smallest_d}, e={smallest_e}, quantum cost = 2^{smallest_cost:.1f}")

    print()
    print(" Under AGGRESSIVE quantum (ω=1.5):")
    for n_vertices, label in [(4, "tetra"), (5, "double_tet"), (6, "octa")]:
        smallest_d = None
        smallest_e = None
        smallest_cost = None
        for d in [6, 8, 10, 12, 14, 16, 20, 24, 32]:
            for e_val in [17, 31, 61, 127, 257, 503, 1019, 2003, 4001, 8009]:
                m = n_vertices * d
                deg = 3 * e_val
                D_reg = hilbert_dreg(m, d, deg)
                if D_reg is None: continue
                q_cost = cost_quantum_F4_aggressive(D_reg, d)
                if q_cost >= 128 and (smallest_d is None or
                                         (d < smallest_d or (d == smallest_d and e_val < smallest_e))):
                    smallest_d = d
                    smallest_e = e_val
                    smallest_cost = q_cost
                    break
            if smallest_d == d:
                break
        if smallest_d:
            print(f"  {label}: d={smallest_d}, e={smallest_e}, quantum cost = 2^{smallest_cost:.1f}")

    print()
    print("=" * 80)
    print(" Decryption feasibility check for recommended parameters")
    print("=" * 80)
    print()
    print(" Decryption cost = σ⁻¹ × n_vertices + F4 D=5 over cubic system")
    print(" σ⁻¹ cost grows as O(e² · log(p^d)) per vertex")
    print(" F4 D=5 cost: matrix C(d+5,5) wide, ~ (m C(d+2,2)) tall")
    print()
    for d in [12, 14, 16]:
        for e_val in [17, 31, 61, 257]:
            n_mono_F4 = comb(d + 5, 5)
            sigma_cost = e_val ** 2 * d * 61  # rough proxy
            f4_cost = n_mono_F4 ** 2.37
            ratio = sigma_cost / f4_cost
            print(f"  d={d}, e={e_val}: σ⁻¹ proxy={sigma_cost:.2e}, F4 D=5 proxy={f4_cost:.2e}, "
                  f"σ/F4 ratio = {ratio:.2g}")

    print()
    print("=" * 80)


if __name__ == "__main__":
    main()
