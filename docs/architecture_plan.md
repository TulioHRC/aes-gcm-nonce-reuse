# Architecture & Hierarchical Implementation Plan

This document defines the architecture and layer hierarchy for the implementation of the course project: **"Breaking AES-GCM Authenticity Under Nonce Reuse"**.

---

## 1. Architectural Hierarchy

The codebase strictly adheres to the cryptographic dependency model, isolating mathematical primitives, cipher modes of operation, higher-order polynomial algebra for cryptanalysis, attack automation, and user-facing demos.

```
                   Layer 4: [ATTACKS]
           Nonce Reuse, Root Finding, & Forgery
                     ▲                ▲
                     │                │
             Layer 2: [MODES]   Layer 3: [ALGEBRA]
               ├── GCM            Polynomials over GF(2^128)
               ├── CTR (AES-CTR)      (gcd, div, factor)
               └── GHASH              ▲
                     ▲                │
                     │                │
           Layer 1: [PRIMITIVES]      │
               ├── AES-128            │
               └── GF(2^128) Arithmetic ─┘
```

---

## 2. Directory Structure

```text
aes_gcm_attack/
├── docs/
│   └── architecture_plan.md   # This document
│
├── src/
│   ├── primitives/            # Layer 1: Core Mathematical & Block Cipher Primitives
│   │   ├── __init__.py
│   │   ├── gf128.py           # Finite field GF(2^128) arithmetic, reduction mod f(x)
│   │   └── aes.py             # AES-128 block cipher (pure implementation from scratch)
│   │
│   ├── modes/                 # Layer 2: Cipher & Authentication Modes of Operation
│   │   ├── __init__.py
│   │   ├── ctr.py             # Counter Mode (CTR) block cipher mode
│   │   ├── ghash.py           # GHASH universal hash / polynomial authenticator
│   │   └── gcm.py             # Galois/Counter Mode (AES-GCM AEAD, NIST SP 800-38D)
│   │
│   ├── algebra/               # Layer 3: Polynomial Ring Operations for Cryptanalysis
│   │   ├── __init__.py
│   │   └── poly.py            # Univariate polynomials in GF(2^128)[X] (div, gcd, mod, roots)
│   │
│   ├── attacks/               # Layer 4: Nonce Reuse Exploitation
│   │   ├── __init__.py
│   │   ├── nonce_reuse.py     # Difference polynomial g(X) builder from colliding pairs
│   │   ├── root_finding.py    # Root-finding & factorization (Cantor-Zassenhaus over GF(2^128))
│   │   ├── key_recovery.py    # Authenticator key H & mask Ek(J0) recovery
│   │   └── forgery.py         # Universal tag forgery engine
│   │
│   └── demo/                  # Layer 5: End-to-End Application & Scenarios
│       ├── __init__.py
│       ├── cli.py             # Interactive CLI demo showcasing full attack pipeline
│       └── scenarios.py       # Practical attack simulation (e.g. TLS packet tampering)
│
├── tests/                     # Hierarchical Test Suite
│   ├── test_primitives/       # Unit tests for AES & GF(2^128) NIST Known-Answer Tests
│   ├── test_modes/            # Unit tests for CTR, GHASH, and AES-GCM (NIST SP 800-38D)
│   ├── test_algebra/          # Unit tests for polynomial arithmetic & gcd over GF(2^128)
│   └── test_attacks/          # Tests for root finding, candidate elimination & tag forgery
│
└── benchmarks/                # Performance & Reliability Analysis
    ├── bench_factorization.py # Recovery time vs polynomial degree (message block count)
    └── bench_collisions.py    # Uniqueness rate vs number of nonce collisions
```

---

## 3. Layer Breakdown & Responsibilities

### Layer 1: Primitives (`src/primitives/`)
* **`gf128.py`**: Field arithmetic over $\mathbb{F}_{2^{128}} \cong \mathbb{F}_2[x] / (x^{128} + x^7 + x^2 + x + 1)$.
  * Addition / Subtraction: Bitwise XOR.
  * Multiplication: Carry-less multiplication with polynomial reduction by standard GCM modulus $R = \mathtt{0xE1} \ll 120$.
  * Inversion / Division: Extended Euclidean Algorithm or Fermat's Little Theorem ($a^{-1} = a^{2^{128}-2}$).
  * Bit/byte endianness transformations conforming to NIST SP 800-38D.
* **`aes.py`**: Pure, from-scratch implementation of the AES-128 block cipher.
  * Key expansion (10 rounds, 11 round keys).
  * State transformations: `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`.
  * Single-block 128-bit encryption $E_k(P)$.

### Layer 2: Modes of Operation (`src/modes/`)
* **`ctr.py`**: Counter Mode (CTR) stream encryption/decryption.
  * Takes a block cipher instance and a 128-bit counter block.
  * Generates keystream blocks $E_k(\text{counter} + i)$ and XORs with plaintext/ciphertext.
  * Supports arbitrary length (handling partial final blocks).
* **`ghash.py`**: GHASH polynomial authenticator.
  * Evaluates authenticated data and ciphertext blocks under hash key $H = E_k(0^{128})$.
  * Horner's rule accumulation in $\mathbb{F}_{2^{128}}$.
  * Length block formulation: $[ \mathrm{len}(A)_{64} \,\|\, \mathrm{len}(C)_{64} ]$.
* **`gcm.py`**: Full AES-GCM AEAD construction (NIST SP 800-38D).
  * Counter initialization $J_0$ (handles both standard 96-bit nonces and arbitrary-length nonces via GHASH).
  * Computes one-time mask $E_k(J_0)$.
  * Orchestrates CTR encryption and GHASH authentication tag computation:
    $$T = \mathrm{GHASH}_H(A, C) \oplus E_k(J_0)$$

### Layer 3: Cryptanalytic Algebra (`src/algebra/`)
* **`poly.py`**: Univariate polynomial arithmetic over $\mathbb{F}_{2^{128}}[X]$.
  * Polynomial representation with coefficients in $\mathbb{F}_{2^{128}}$.
  * Operations: addition, multiplication, degree query, monic normalization.
  * Polynomial division with remainder: $A(X) = Q(X) B(X) + R(X)$.
  * Greatest Common Divisor ($\gcd$) via Euclidean algorithm.
  * Modular exponentiation: $X^{2^k} \pmod{g(X)}$ for root isolation.

### Layer 4: Attacks (`src/attacks/`)
* **`nonce_reuse.py`**: Setting up the attack equation.
  * Takes colliding ciphertexts $(C, T)$ and $(C', T')$ produced under the same nonce.
  * Forms the difference polynomial $g(X)$ where the mask $E_k(J_0)$ cancels out:
    $$g(X) = \sum_{i=1}^n (C_i \oplus C'_i) X^{n-i+2} \oplus (L \oplus L') X \oplus (T \oplus T')$$
* **`root_finding.py`**: Root extraction over $\mathbb{F}_{2^{128}}$.
  * Isolate linear factors: $h(X) = \gcd(g(X), X^{2^{128}} - X)$.
  * Factor $h(X)$ into linear components using Cantor-Zassenhaus / trace-map splitting for characteristic 2 fields.
* **`key_recovery.py`**: Isolating true key $H$ and mask $E_k(J_0)$.
  * Tests candidate roots against additional oracle queries or colliding pairs to identify the unique $H$.
  * Computes one-time counter mask: $E_k(J_0) = T \oplus \mathrm{GHASH}_H(A, C)$.
* **`forgery.py`**: Universal tag forgery.
  * Modifies existing ciphertexts or creates arbitrary new ciphertexts.
  * Computes authentic tags $T^* = \mathrm{GHASH}_H(A^*, C^*) \oplus E_k(J_0)$ without knowledge of the master key $k$.

### Layer 5: Demo & Benchmarks (`src/demo/`, `benchmarks/`)
* Interactive demonstration walkthrough with formatted terminal outputs.
* Benchmarking attack runtimes across varying polynomial degrees (message block lengths) and analyzing uniqueness of recovered keys.
