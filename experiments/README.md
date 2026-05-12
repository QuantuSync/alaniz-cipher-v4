# Reproduction scripts

This directory contains scripts that reproduce the empirical findings reported in `docs/findings/EXPERIMENTAL_FINDINGS.md` and elsewhere in the documentation.

## Mapping: claim → script

| Claim in documentation | Script | Approximate runtime |
|------------------------|--------|---------------------|
| Pipeline works end-to-end at d=6 (10 seeds) | `reproduce_e2e_d6.py` | 5-20 min |
| Cubic system of decryptor is semi-regular at d=6 (kernel=42 at D=4) | `reproduce_semireg_d6.py` | <1 min |
| Hilbert table proving v3 parameters give 74 bits | `reproduce_hilbert_table.py` | <1 sec |
| Empirical D_reg validation at d=2,3 | `reproduce_dreg_d23.py` | 5-15 min |
| Direct F4 attack on public system (small scale) | `reproduce_attack_public.py` | 5-30 min depending on case |
| Quantum security parameter sweep | `reproduce_quantum_analysis.py` | <5 sec |
| σ⁻¹ side-channel analysis (N=30) | `reproduce_sidechannel.py` | 10-15 min |

## Helper scripts

- `run_seeds.py`: utility to run a specific seed of the d=6 pipeline with persisted output. Used by `reproduce_e2e_d6.py`.

## Persisted data

The `data/` subdirectory contains intermediate pickle files needed for the d=12 SageMath validation:

- `d12_state.pkl`, `d12_structure.pkl`, `d12_cands_v[0-3].pkl`: state from the d=12 pipeline run.
- `pq128_results.jsonl`: results of the 10-seed d=6 verification (used by `reproduce_e2e_d6.py` to skip already-done seeds).
- `sidechan_state.jsonl`: results of the side-channel study.

These exist to allow continuation of partial runs and to enable the SageMath completion script in `pending_validations/`.

## Reproducing all findings

To reproduce everything that can be run in Python within a reasonable time:

```bash
# Setup
pip install -r ../requirements.txt

# Fast reproductions (each <5 min)
python reproduce_hilbert_table.py
python reproduce_quantum_analysis.py
python reproduce_semireg_d6.py
python reproduce_dreg_d23.py

# Slower (15-30 min each)
python reproduce_attack_public.py
python reproduce_sidechannel.py

# Slowest (1+ hour cumulative)
python reproduce_e2e_d6.py
```

For the d=12 verification (~2-5 min in SageMath, infeasible in Python):

```bash
cd ../pending_validations
sage sage_d12_complete.sage
```

## Reproducibility notes

- All scripts use `numpy.random.default_rng(seed)` with explicit seeds for determinism.
- Outputs are deterministic given the seed; numerical values in `docs/findings/` were produced with seeds 0, 1, 2, 7, 13, 42, 99, 100, 200, 314, 555, 2024 (depending on the experiment).
- Some scripts persist intermediate state to `/tmp/` or to `data/` for resumability. Check the script source for exact file names.

## Hardware requirements

| Script | RAM | Disk | Time |
|--------|-----|------|------|
| `reproduce_hilbert_table.py` | <100 MB | <1 MB | <1 sec |
| `reproduce_quantum_analysis.py` | <100 MB | <1 MB | <5 sec |
| `reproduce_semireg_d6.py` | ~500 MB | <1 MB | <1 min |
| `reproduce_dreg_d23.py` | ~500 MB | <1 MB | 5-15 min |
| `reproduce_attack_public.py` | ~1 GB | <1 MB | 5-30 min |
| `reproduce_sidechannel.py` | ~500 MB | <10 MB | 10-15 min |
| `reproduce_e2e_d6.py` | ~1 GB | <10 MB | 5-20 min |

All Python scripts work in standard environments (Linux/macOS, Python 3.10+). Windows is untested but should work with the same dependencies.
