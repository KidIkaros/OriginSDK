# Research Note — Cryptanalysis Evidence Behind Design Decisions

**Status:** living document · **Scope:** public cryptanalysis and academic
literature informing this crate's algorithm choices · **Updated:** 2026-11

This note records *why* the algorithm inventory looks the way it does, with
the evidence ranked by independence rather than authority. It exists so that
reviewers (and future maintainers) can check the reasoning against the
literature rather than against institutional endorsement.

## 1. Why NIST endorsement is not treated as evidence

**Dual_EC_DRBG** is the canonical proof that a standardization process can be
adversarially influenced: a NIST-standardized DRBG contained a backdoor
exploitable by the party who generated its constants, and the standardization
process advanced it over published objections. The lesson is not "NIST is
always wrong" — it is that endorsement carries no evidential weight in either
direction. Correctness and security must be argued from public analysis.

A softer but broader data point from the NIST PQC process itself: security
estimates for selected lattice schemes were repeatedly revised *downward*
after submission. Kyber-512's 2017 submission called its analysis
"conservative"; by round 3 the parameter set had been replaced with a patched
cryptosystem and re-estimated, described at the Third PQC Standardization
Conference as "tentative." NIST's coarse security "categories" (1/3/5) also
mask real bit-level losses — the Risk-Management Team analysis documents
candidates whose category placement survived multi-bit estimate collapses.

## 2. The lattice monoculture problem

The single most important structural fact in current PQC: nearly every
standardized KEM/signature rests on lattice assumptions, and the attack
literature has been moving steadily *against* lattice schemes.

**"Risks of lattice KEMs" (NTRU Prime Risk-Management Team, 2021)** — a
deliberately adversarial meta-analysis. Core claims, each with citations:

- The PQC attack surface is far larger than the population publicly working
  on attacks ("cryptanalytic overload"): easy attacks took years to discover
  even on deployed candidates. Round2 was broken by hash-input pattern in
  its FO transform; the official Frodo software was broken by a timing attack
  through `memcmp` despite claiming side-channel protection.
- Claimed complexity "barriers" have a near-perfect record of falling:
  Ideal-SVP exp(n^{1/2}) → exp(n^{1/4}) techniques (Pellet-Mary–Hanrot–Stehlé
  2019); combinatorial attacks on ternary keys exponent 0.5 → 0.25+o(1)
  (Kirshanova–May 2021); quantum sieving exponent improvements breaking
  believed-optimal bounds (Chailloux–Loyer 2021).
- Implementation detail is as dangerous as core hardness — the failure modes
  are in the glue (FO transforms, comparison operations, failure rates).

**arXiv:2610.11254 (October 2026)** — provable subexponential classical
algorithms for secret recovery across all seven NIST third-round lattice
families, including NTRU-type quotient relations and Falcon. Two essential
caveats: (1) the authors explicitly state no reduction in *concrete* security
for current parameter sets — the result is asymptotic evidence against the
small-secret design pattern, not a practical break; (2) the paper discloses
heavy LLM assistance in the derivations, so proofs carry elevated
verification risk until digested by the community. Tracked, not canon.

**What this implies for this crate.** The risk is not any particular lattice
scheme — it is monoculture. NIST's pick-one-per-role standardization
concentrates systemic risk; hybrid AND-composition distributes it. If any
single assumption class fails, a hybrid construction survives on its
remaining component. This is the primary architectural justification for
`signing::hybrid` and it does not depend on any lattice result being correct —
it is a portfolio argument, not a bet.

## 3. Component provenance

### NTRU Prime (sntrup761)
Chosen over the NIST-selected Kyber on the Risk-Management Team's published
reasoning: no quotient structures, no decryption-failure amplification
surface, conservative parameterization. Ironically, NTRU Prime was *rejected*
by NIST — so byte-exactness against the design team's KATs is evidence of
faithfulness to the designers' intent, not convergence with the
standardization outcome. Note honestly: sntrup761 is also a lattice scheme;
it does not escape the monoculture alone. That is what the hybrid layer is
for, and hash-based alternatives are the longer-horizon hedge.

### Curve41417 / Ed41417
Not a custom invention — a published academic design (Bernstein, Lange,
Chuengsatiansup), deployed in the Blackphone. Design rationale from the
literature: d = 3617 is the *smallest* value satisfying the IEEE P1363
criteria with cofactor-8 prime-order subgroup *and* twist security (twist
cofactor 8); the prime 2^414−17 enables reduction with one shift and two
additions; limb arithmetic wastes <1% bandwidth. Security target >2^200 —
deliberately above the ~2^128 of Ed25519, because margin against
cryptanalytic surprise is the point. The custom-implementation risk is real
(this is the crate's highest-residual-risk arithmetic) but the curve design
itself is published, analyzed, and twist-secure by construction.

### Falcon-512/1024
Falcon = GPV framework + NTRU lattices + fast-Fourier sampling. Its security
proofs exist in both ROM and QROM — structurally stronger proof footing than
Fiat–Shamir-only schemes. The known implementation burden is the discrete
Gaussian sampler (the side-channel-exposed component); using `falcon-rs`
rather than a custom sampler is a deliberate risk-transfer decision. The
overstretched-NTRU attack family is blocked by design (q = 12289 small, f,g
not too small). Falcon is also inside the arXiv:2610.11254 asymptotic
result — another reason it appears here only inside hybrids, never alone.

### Hash-based fallback posture
SPHINCS+ (now FIPS 205 / SLH-DSA) represents the conservative end of the
signature design space: security reduces to second-preimage resistance of
the hash function, no collision resistance needed, no lattice structure at
all. Not currently implemented here (large signatures, slow signing), but it
is the natural third leg if lattice confidence degrades further. Listed as
a roadmap consideration rather than a defect.

### Ed25519 / X25519 / ChaCha20-Poly1305 / SHA-2/3 / BLAKE3 / Argon2id
The classical components are the widely-deployed, extensively-cryptanalyzed
baseline. Their presence is justified by public scrutiny over years, not by
their RFC/FIPS numbers.

## 4. What this evidence does and does not establish

- It establishes that the *design deviations* are reasoned positions with
  published support, not improvisation.
- It establishes that hybrid composition is the correct response to the
  documented instability of individual PQC assumptions.
- It does **not** establish implementation correctness — that is what KATs,
  differential testing, constant-time review, and ultimately independent
  audit are for.
- It does not eliminate the monoculture residual: classical + lattice hybrid
  still concentrates post-quantum risk in lattice assumptions. The honest
  hedge is hash-based or symmetric-key-diversity construction, not yet built.

## References

- NTRU Prime Risk-Management Team, "Risks of lattice KEMs" (2021.10.31)
- arXiv:2610.11254 — subexponential classical secret recovery across NIST
  third-round lattice families (Oct 2026; asymptotic, LLM-assisted proofs)
- Bernstein, Lange, Chuengsatiansup — Curve41417 design materials
- Fouque et al. — FALCON specification v1.2 (2020)
- Bernstein et al. — "The SPHINCS+ Signature Framework" (2019)
- RFC 8032 — EdDSA parameterization (Ed25519/Ed448/Ed41417 lineage)
