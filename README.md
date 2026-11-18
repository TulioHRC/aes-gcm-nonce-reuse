# Breaking AES-GCM Authenticity Under Nonce Reuse

An educational, from-scratch implementation and cryptanalysis of Galois/Counter Mode (AES-GCM) under nonce reuse (the Joux "Forbidden Attack"), developed for the Cryptography course (2026/2) at DCC/ICEx/UFMG.

---

## 1. Project Hierarchy

The project follows a strict architectural hierarchy based on cryptographic layer dependencies:

```text
aes-gcm-nonce-reuse/
├── docs/                      # Architectural specifications and design notes
├── src/
│   ├── primitives/            # Layer 1: GF(2^128) arithmetic and AES-128 block cipher
│   ├── modes/                 # Layer 2: CTR mode, GHASH authenticator, AES-GCM AEAD
│   ├── algebra/               # Layer 3: Univariate polynomials over GF(2^128) (div, gcd)
│   ├── attacks/               # Layer 4: Nonce-reuse polynomial formulation, root finding, forgery
│   └── demo/                  # Layer 5: End-to-end interactive demonstration
├── tests/
│   ├── test_primitives/       # Unit tests for GF(2^128) and AES
│   ├── test_modes/            # NIST SP 800-38D test vectors for GHASH and GCM
│   ├── test_algebra/          # Polynomial ring arithmetic tests
│   └── test_attacks/          # Full attack and forgery verification tests
└── benchmarks/                # Performance benchmarks vs. message lengths
```

---

## 2. Requirements & Setup

* **Python 3.10+**

### Setting Up the Virtual Environment

Create and activate the virtual environment, then install the dependencies from `requirements.txt`:

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it (Linux / macOS)
source .venv/bin/activate

# Install dependencies (pytest and optional cryptography reference library)
pip install -r requirements.txt
```

---

## 3. How to Run

Make sure your virtual environment is activated (`source .venv/bin/activate`).

### Running the End-to-End Demonstration

To run the interactive demonstration showing nonce collision, authentication key $H$ recovery, mask recovery, and tag forgery:

```bash
# From the project root
python3 -m src.demo.cli
```

### Running the Test Suite

The test suite validates each layer against NIST SP 800-38D known-answer vectors:

```bash
# Using standard unittest (built-in, no dependencies)
python3 -m unittest discover -s tests

# Or using pytest (if installed)
pytest tests/
```

### Running Benchmarks

To benchmark key-recovery runtime across varying message block lengths:

```bash
python3 benchmarks/bench_factorization.py
```

---

## 4. References

* Antoine Joux. *Authentication Failures in NIST Version of GCM*. 2006.
* Hanno Böck, Aaron Zauner, Sean Devlin, Juraj Somorovsky, Philipp Jovanovic. *Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS*. USENIX WOOT 2016.
* NIST SP 800-38D. *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*. 2007.
