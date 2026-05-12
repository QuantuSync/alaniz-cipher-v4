# Roadmap

This document lists the work that remains, in priority order. Each item lists what is needed and why.

## Priority 1: validation that proves correctness at PQ-128 parameters

### 1.1 Verify=True at d=12, e=17 (SageMath)

**What**: Load the persisted state from `experiments/data/d12_*.pkl` into SageMath, complete the F4 RREF step that our Python prototype cannot finish in this environment, confirm that decryption recovers the original message.

**Why**: This is the **single most important validation gap**. Without it, the claim "the scheme works at recommended parameters" is unsupported empirically.

**Effort**: 2-5 minutes of SageMath compute on a modest workstation. Hours of setup. Days if SageMath is unfamiliar.

**Status**: Persisted state ready. Sage script template in `pending_validations/sage_d12_complete.sage`.

### 1.2 Verify the gap regression at d=4, 5, 6

**What**: Repeat the empirical D_reg measurement methodology of `experiments/reproduce_attack_public.py` at d=4, 5, 6 for the public polynomial system. Verify that the regression formula `gap ≈ -0.5n + 0.67d + 1.33e - 0.83` continues to hold.

**Why**: Our regression is fit on data at d=2,3 and extrapolates to d=12. Bridging the gap to d ≥ 4 dramatically strengthens the security argument.

**Effort**: 1-2 weeks of compute on a Magma or SageMath workstation. The Macaulay matrices at d=4-5 are large (10k–60k square) but feasible.

**Status**: Open. Requires external collaborator with Magma/Sage license and time.

## Priority 2: implementation quality

### 2.1 Optimized C/Rust implementation

**What**: Reference implementation in a systems language with constant-time σ⁻¹, optimized field arithmetic for F_(2⁶¹-1), and BLAS-optimized F4 RREF.

**Why**: 
- Python prototype is 100-1000× slower than achievable.
- Constant-time is required to eliminate the marginal side-channel observation (ρ(v_0, v_3) = -0.38).
- Memory safety must be verified for any deployment.

**Effort**: 6-12 months for one experienced cryptographic engineer. Includes test vectors, KATs, side-channel testing.

**Status**: Open. Project work, not research.

### 2.2 Test vectors / KAT

**What**: Generate test vectors at each parameter set with known answers, suitable for cross-implementation testing.

**Why**: Required for any independent implementation to verify correctness.

**Effort**: 1-2 weeks once the SageMath verification (1.1) is complete.

**Status**: Open.

## Priority 3: security analysis depth

### 3.1 Independent cryptanalysis review

**What**: External experts in multivariate cryptography (the Patarin/Faugère/Beullens community) examine the construction and try to find attacks.

**Why**: Heuristic security only becomes credible with external scrutiny. No author can adequately analyze their own scheme.

**Effort**: 6 months minimum of external attention, ideally 2-3 years.

**Status**: Open. Requires preprint publication and outreach.

### 3.2 Formal syzygy-lifting argument

**What**: Strengthen the structural argument in `findings/SYZYGY_PROOF.md` into a rigorous algebraic proof in a ring with secret transcendentals.

**Why**: The current argument is structural, not formal. A rigorous proof would silence one class of skepticism.

**Effort**: 3-6 months of work by a researcher comfortable with commutative algebra.

**Status**: Open.

### 3.3 Larger-N side-channel study

**What**: With optimized implementation, run 1000+ ciphertexts per key over multiple keys, measure σ⁻¹ root count distributions and timing, perform rigorous χ² tests on many α features.

**Why**: Our N=30 study had only a marginal hint (ρ(v_0, v_3) = -0.38) that could be coincidence or real coupling. Needs a larger sample.

**Effort**: 1 week of compute after optimized implementation exists.

**Status**: Blocked on 2.1.

### 3.4 Algebraic structure of σ⁻¹

**What**: Theoretical analysis of why σ_v has mean ~2 roots per vertex (not the random expectation of 1). Is this a structural property exploitable by an adversary?

**Why**: An exploitable structural property here would invalidate the security argument.

**Effort**: 1-3 months of analysis.

**Status**: Open.

## Priority 4: deployment-readiness

### 4.1 Hybrid-mode integration with Kyber

**What**: Specification of how to combine Alaniz Cipher v4r3 with Kyber-768/1024 in hybrid public-key encryption (KEM combiner).

**Why**: Hybrid mode is the safe deployment path: an attacker must break both schemes. Standard hybrid combiners (like the one used in TLS 1.3 PQ drafts) apply directly but need specification.

**Effort**: 2-4 weeks once the optimized implementation exists.

**Status**: Open.

### 4.2 Integration testing in TLS / Noise / Signal protocols

**What**: Demonstrate that v4r3 (or v4r3+Kyber hybrid) can be plugged into common cryptographic protocols.

**Why**: Without protocol integration, the scheme remains theoretical.

**Effort**: 1-3 months per protocol.

**Status**: Open, follows 2.1 and 4.1.

## Priority 5: outreach

### 5.1 Preprint publication

**What**: Submit comprehensive whitepaper to IACR ePrint Archive and/or Zenodo with DOI.

**Why**: Visibility for the research community. Necessary precondition for 3.1.

**Effort**: Whitepaper draft writing (3-4 weeks); preprint submission is automatic.

**Status**: Roadmap exists for whitepaper structure. Drafting can begin.

### 5.2 Conference / workshop presentations

**What**: Present at relevant venues: CCN-CERT jornadas STIC (Spain), ENISA workshops, IACR Real World Crypto, ETSI Quantum Safe.

**Why**: Direct engagement with deployment-side and analysis-side communities.

**Effort**: 1-2 weeks per venue (paper/abstract + travel).

**Status**: Open, follows 5.1.

### 5.3 Academic collaboration

**What**: Approach Spanish/European universities with cryptography groups (UPM, UC3M, IMDEA, INRIA, ENS, TU Eindhoven) for joint analysis.

**Why**: Independent eyes; potential PhD or postdoc-level deep dives; reputational legitimacy.

**Effort**: Long-term engagement, 1-3 years.

**Status**: Open.

## What is explicitly NOT planned

We do NOT propose:
- **Submission to NIST PQC competition rounds**. The competition is closed for primary algorithms. The "additional signatures" track is signature-only.
- **Replacing NIST PQ schemes for production deployment**. Hybrid mode is the realistic deployment path.
- **Cryptanalysis of NIST schemes**. Out of scope.

## Open questions in the design

These are aspects of the design we considered but did not investigate deeply:

1. **Choice of substrate**: tetrahedron vs. octahedron vs. larger complexes. Trade-offs in key size, security margin, decrypt cost.
2. **Use of σ with structure**: alternative σ functions (e.g., based on monomials of multiple degrees) might offer better non-injectivity properties.
3. **Multi-vertex decryption parallelism**: σ⁻¹ at different vertices is independent; can be parallelized.
4. **Compression of public key**: A, B, C matrices have algebraic structure that may allow shorter representations.
