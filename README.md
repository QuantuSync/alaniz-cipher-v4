# Alaniz Cipher v4

A proposal for a multivariate post-quantum public-key encryption scheme based on cellular sheaves over 2-simplicial complexes.

> **Status: research proposal.** This is not a production-ready cryptosystem. It is a proposal for academic and technical review, with partial empirical validation. See [docs/STATUS.md](docs/STATUS.md) for current state and [pending_validations/README.md](pending_validations/README.md) for validations still required.

## What this is

Alaniz Cipher v4 is a candidate post-quantum encryption scheme in the **multivariate** family. The security rests on the difficulty of solving large systems of polynomial equations over finite fields — a problem believed to be hard even for quantum computers (the relevant attack is Faugère's F4/F5 algorithm with Grover-amplified linear algebra).

The novel construction is a **cellular sheaf over a 2-simplicial complex** (tetrahedron, octahedron, etc.), where vertices, edges, and triangles each contribute polynomial constraints — linear, bilinear, and trilinear respectively — entangled through arithmetic in the finite field F_{p^d}.

This places Alaniz Cipher in a different mathematical region from lattice-based schemes (Kyber, Dilithium) recommended by NIST, providing algorithmic diversity for critical infrastructure that should not depend on a single mathematical family.

## What this is not

- **Not a deployable product.** Years of external cryptanalysis are required before any deployment.
- **Not a replacement for NIST PQ standards.** Intended as a hybrid-mode complement or a fallback option.
- **Not formally proven secure.** Like all multivariate schemes, security rests on heuristic structural arguments rather than reduction to a previously-studied hard problem.

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Run end-to-end verification at d=6 (multiple seeds)
python experiments/reproduce_e2e_d6.py

# Compute quantum security parameters
python experiments/reproduce_quantum_analysis.py
```

The simplest possible test:

```python
import sys; sys.path.insert(0, "src")
import numpy as np
from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import decrypt_pq128

K = Complex2D.tetrahedron()
rng = np.random.default_rng(42)
params = setup_pq128(K, d=6, p=257, rng=rng)
key = keygen_pq128(params, rng=rng)

alpha = [int(rng.integers(0, 100)) for _ in range(6)]
nonce, ciphertext = encrypt_pq128(params, key, alpha)
alpha_recovered, _ = decrypt_pq128(params, key, ciphertext, nonce)

assert list(alpha_recovered) == alpha
print("OK — message recovered correctly")
```

Or run `python example.py` from the repo root.

## Documentation

| File | Purpose |
|------|---------|
| [docs/DESIGN.md](docs/DESIGN.md) | The scheme construction (formal) |
| [docs/SECURITY.md](docs/SECURITY.md) | Security analysis |
| [docs/PARAMETERS.md](docs/PARAMETERS.md) | Recommended parameters with justification |
| [docs/STATUS.md](docs/STATUS.md) | Current state of validation and what is verified |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Open work and priorities |
| [docs/HISTORY.md](docs/HISTORY.md) | Version history (v1 → v4r3) |
| [docs/findings/](docs/findings/) | Detailed technical findings |

## Key claims (with status)

1. **The previously-published v3 parameters (d=6, e=17) provide approximately 74 bits of classical security, not 128.** Verified via Hilbert series + Bardet-Faugère analysis. ✓
2. **Corrected parameters (tetra d=12, e=31) provide ~147 bits of quantum-conservative security.** Verified by computation; empirical validation pending at d=12. ⚠
3. **The scheme is functional end-to-end at d=6.** Verified in 10 independent seeds. ✓
4. **Known specific attacks (Beullens, MinRank) do not break the scheme.** Verified empirically. ✓
5. **The empirical regularity degree of the attack system exceeds the Hilbert prediction by a positive offset.** Verified in 13 instances at d=2,3. ✓

## Reproducing the results

See [experiments/README.md](experiments/README.md) for the full mapping of which script reproduces which table or claim in the documentation.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Citation

If you reference this work, please cite:

> Alaniz Pintos, L. (2026). *Alaniz Cipher v4: A Sheaf-Based Multivariate Post-Quantum Encryption Scheme.* Preprint. [DOI when assigned]

## Author and contact

**Lucas Alaniz Pintos**  
Research AI Engineer — Critical Infrastructure & Quantum Systems  
INECO (Ingeniería y Economía del Transporte, S.M.E., M.P., S.A.)

- Email: <lucas.alaniz@ineco.com>
- GitHub: [@QuantuSync](https://github.com/QuantuSync)
- LinkedIn: [linkedin.com/in/lualaniz](https://www.linkedin.com/in/lualaniz)
- ORCID: [0009-0008-5179-2534](https://orcid.org/0009-0008-5179-2534)

## Acknowledgments

This work was conducted as part of research into algorithmic diversity for post-quantum cryptography, with the goal of supporting sovereign technical options for critical infrastructure in the European context.

## Disclaimer

This is research-grade work. Do not deploy in production. Do not use to protect sensitive data. The cryptographic guarantees described in the documentation are heuristic, contingent on validation work that remains open. See [pending_validations/README.md](pending_validations/README.md).
