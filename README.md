# Alaniz Cipher — arithmetization-oriented permutation study

**Status: reproducible research record (not a product).** This repository documents,
with reproducible experiments, the design-and-cryptanalysis arc of a symmetric
arithmetization-oriented (AO) primitive, ending in one positive central result and
several negative results along the way.

> Secure-round counts (R\*) and cost figures are **extrapolations** of a *measured*
> law, under an explicit cost model (ω=2). Nothing is called "secure" without that
> label. See [docs/STATUS.md](docs/STATUS.md) for per-claim status.

**Start here:** [docs/RESULTS.md](docs/RESULTS.md) — the executive summary (what was
sought, the arc, the central result, the Alaniz-AO primitive, and the flank table).
Then [docs/SPEC.md](docs/SPEC.md) (the concrete primitive),
[docs/CRYPTANALYSIS.md](docs/CRYPTANALYSIS.md) (the attack log),
[docs/OPEN_PROBLEMS.md](docs/OPEN_PROBLEMS.md) (what's left), and
[docs/REPRODUCE.md](docs/REPRODUCE.md) (one command per result).

## Central result (verified)

In an algebraic SPN over F_p (S-box `x⁷` over Goldilocks `p = 2⁶⁴−2³²+1`, MDS linear
layer), **coupling the S-boxes at their INPUT with a triangular quadratic term adds
+1 bit of CICO ideal degree per round**:

```
D_I(independent baseline)   = 7^(R·m)
D_I(input coupling)         = 7^(R·m) · m · 2^(R-1)      (m = free branches)
```

All measured in a real Gröbner engine (msolve):

- **Real, not a nominal-degree trap.** The F4 solving degree *rises* (does not
  collapse), and an x-only model reproduces D_I exactly (auxiliary variables do not
  inflate it). A resolved large point **(R=2,m=2)=9604** rules out the rivals
  (base-14 = 19208; null = 2401).
- **Generic, not sheaf-specific.** Four triangular incidences (sheaf/simplicial,
  dense, chain, star) give **identical** D_I and F4. The cellular-sheaf structure over
  the simplicial complex was the *inspiration*, not the mechanism. It restates as an
  AO design principle: *the non-linear placement of the coupling (S-box input — not
  the linear layer, not additive after the power) is what buys degree*.
- **Density-independent.** A single coupling term per round keeps the full gain, so
  the defended construction is the **minimal** one (1 mult/round): net **0.87–0.89×**
  the baseline in R1CS constraints, and the tetrahedron **0.73×** Poseidon2.
- **Resists FreeLunch, CheapLunch, resultants** (eprint 2024/347, 2025/2040,
  2025/259+2026/1281): all three are D_I-bound and were *run*, not just argued
  (CICO-2 gives larger D_I than CICO-1; the resultant eliminant degree equals D_I).
  D_I is invariant under the monomial order and modeling, so the cost follows the
  nominal curve. See [docs/CRYPTANALYSIS.md](docs/CRYPTANALYSIS.md).
- **Differential/linear covered.** S-box MDP=2⁻⁶¹, MLC=2⁻²⁹; with an MDS layer the
  wide-trail secure rounds R\*_difflin=2 ≪ the algebraic bound, and the input
  coupling does not degrade the per-S-box uniformity. See
  [docs/WIDE_TRAIL.md](docs/WIDE_TRAIL.md).
- **Transfers across characteristic.** D_I and the F4 solving degree are identical
  over proxy primes from 5 to 31 bits ⇒ structural ⇒ carries to Goldilocks (running
  the actual 64-bit system is out of the engine's reach; kept open).

## Instantiation

A concrete permutation and sponge hash — **Alaniz-AO** (t=8, R=8, x⁷ over
Goldilocks, Cauchy-MDS layer, minimal chain input-coupling, rate/capacity 4) — is
specified in [docs/SPEC.md](docs/SPEC.md) and implemented in
`src/crypto/alaniz_ao.py`. The sponge capacity flank is closed (effective m=4;
R=8 gives ≥179-bit preimage, 128-bit collision). Its **HADES (full-partial-full)
variant** (`src/crypto/alaniz_hades.py`) uses partial rounds — verified (at m=1) to
be as algebraically effective as full rounds for the ideal degree — to drop the
cost from ~1.30× to **0.74× Poseidon2** in R1CS (moderate split R_f=4). Round
counts and cost are extrapolated under ω=2; the minimal secure full-round count is
documented as open.

```python
import sys; sys.path.insert(0, "src")
from crypto.alaniz_ao import sponge_hash
print(sponge_hash([1, 2, 3, 4, 5]))     # 4 Goldilocks field elements
```

## The arc (negative results preserved)

1. **Sheaf-based multivariate PKE (v4)** → dropped: encryption needs the secret (H1);
   the scheme was symmetric, not public-key.
2. **Entropy collapse in sampling (H3)** → detected and fixed (β/L near-scalar
   ~62 bits → ~366 bits).
3. **High-degree σ in one round (AO model)** → broken: A6-CICO solves at cubic degree
   independent of e; an expensive S-box buys no AO security in a single layer.
4. **Sheaf structure as a LINEAR layer** → no algebraic advantage (D_I=7^(R·m),
   independent of branch number); a "sheaf diffusion vs MDS" comparison.
5. **Sheaf structure as NON-LINEARITY (S-box input)** → **the positive result**: the
   +1 bit/round above, later shown to be generic.

Dated verdicts in [docs/DECISION.md](docs/DECISION.md); full attack log in
[docs/CRYPTANALYSIS.md](docs/CRYPTANALYSIS.md).

## Reproducing

Needs Python 3 (`pip install -r requirements.txt`) and, for the Gröbner attacks,
**msolve** on WSL/Linux (`sudo apt install msolve`); see
[docs/WSL_SETUP.md](docs/WSL_SETUP.md). Fixed seeds ⇒ deterministic results.

```bash
pytest -q                                     # full suite (green)

# Sheaf-as-linear-layer phase: law D_I=7^(R·m), cost vs Poseidon2
python experiments/03_mix_branch_number.py
python experiments/04_spn_cico_attacks.py     # needs msolve (WSL)
python experiments/05_spn_cost.py

# Path 1 (input coupling): the central result
python experiments/06_coupling_grade_gate.py        # add vs input (needs msolve)
python experiments/08_coupling_density_sweep.py     # density independence
python experiments/09_coupling_sheaf_vs_generic.py  # sheaf-vs-generic control
python experiments/07_coupling_cost_verdict.py      # R* and cost (extrapolated, ω=2)
python attacks/A_freelunch_minimal.py               # FreeLunch on the minimal build
python attacks/A_cheaplunch_resultant.py            # CheapLunch + resultant (run, not argued)
python experiments/10_wide_trail.py                 # differential/linear (wide-trail)
python experiments/11_transfer_proxies.py           # proxy -> Goldilocks transfer (needs msolve)
```

msolve-invoking scripts call it as `wsl msolve -f <file> [-g 2] [-t 16]`. Engine
fidelity notes (CRLF, primes that segfault, syntax) are in
[docs/CRYPTANALYSIS.md](docs/CRYPTANALYSIS.md).

## Layout

- `src/` — reference implementation (field, S-box, mixing layer, coupling, CICO model).
- `experiments/` — reproducible measurements (diffusion, cost, degree sweeps).
- `attacks/` — cryptanalysis suite (A6-CICO, FreeLunch, …).
- `docs/` — `STATUS.md` (per-claim status), `DECISION.md` (verdicts),
  `CRYPTANALYSIS.md` (attacks), design specs (`SPN_SPEC.md`, `COUPLING_SPEC.md`,
  `AO_SPEC.md`, `HARDNESS.md`). Earlier-proposal docs (`DESIGN.md`, `SECURITY.md`,
  `PARAMETERS.md`, `HISTORY.md`, `findings/`) are kept as historical record — read
  them together with `STATUS.md`, which supersedes their quantitative claims.
- `tests/` — `pytest`, including exhaustive bijection and law regressions.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

> Alaniz Pintos, L. (2026). *Alaniz Cipher: an arithmetization-oriented permutation
> study.* Preprint. [DOI when assigned]

## Author and contact

**Lucas Alaniz Pintos**
Research AI Engineer — Critical Infrastructure & Quantum Systems
INECO (Ingeniería y Economía del Transporte, S.M.E., M.P., S.A.)

- Email: <lucas.alaniz@ineco.com>
- GitHub: [@QuantuSync](https://github.com/QuantuSync)
- LinkedIn: [linkedin.com/in/lualaniz](https://www.linkedin.com/in/lualaniz)
- ORCID: [0009-0008-5179-2534](https://orcid.org/0009-0008-5179-2534)

## Disclaimer

Research-grade work. Do not deploy in production. Do not use to protect sensitive
data. The security statements in the documentation are heuristic and contingent on
open validation work; see [docs/STATUS.md](docs/STATUS.md).
