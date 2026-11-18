"""Interactive end-to-end demonstration of the Joux forbidden attack against
AES-GCM under nonce reuse.

Run with:
    python3 -m src.demo.cli

Walks through: two messages accidentally encrypted under the same (key,
nonce); building the difference polynomial; finding its roots over
GF(2^128); disambiguating the true key H with a third ciphertext; forging
a tampered, still-"authentic" ciphertext; and confirming the victim's own
decrypt() accepts it.
"""

import os
import sys
import time

from src.attacks.forgery import forge_ciphertext, tamper_ciphertext
from src.attacks.key_recovery import recover_key_material
from src.attacks.nonce_reuse import CollidingCiphertext, build_difference_polynomial
from src.attacks.root_finding import find_roots
from src.modes.gcm import AESGCM, AuthenticationError
from src.primitives.gf128 import GF128Element

WIDTH = 78


def _banner(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(title.center(WIDTH))
    print("=" * WIDTH)


def _step(n: int, title: str) -> None:
    print()
    print(f"--- Step {n}: {title} " + "-" * max(0, WIDTH - len(f"--- Step {n}: {title} ")))


def _kv(label: str, value: str) -> None:
    print(f"  {label:<28} {value}")


def _pause() -> None:
    if sys.stdin.isatty():
        input("\n  (press Enter to continue) ")


def _encrypt_and_wrap(gcm: AESGCM, nonce: bytes, pt: bytes, aad: bytes) -> CollidingCiphertext:
    ct = gcm.encrypt(nonce, pt, aad)
    return CollidingCiphertext(aad=aad, ciphertext=ct.ciphertext, tag=ct.tag)


def _hex_preview(data: bytes, limit: int = 32) -> str:
    h = data.hex()
    if len(h) <= limit:
        return h
    return h[:limit] + f"... ({len(data)} bytes total)"


def main() -> None:
    _banner("AES-GCM Nonce Reuse: the Joux \"Forbidden Attack\"")
    print(
        "\nThis demo shows how re-using a single (key, nonce) pair for two"
        "\nAES-GCM encryptions destroys authenticity: an attacker who"
        "\nobserves the two ciphertexts can recover the GHASH key H and"
        "\nforge valid tags for arbitrary messages, with no knowledge of"
        "\nthe AES master key."
    )

    key = os.urandom(16)
    nonce = os.urandom(12)
    victim = AESGCM(key)

    _step(1, "The victim's secret key and nonce (unknown to the attacker)")
    _kv("Master key k", _hex_preview(key))
    _kv("Reused nonce", nonce.hex())
    print("\n  (the attacker will never learn k directly)")
    _pause()

    _step(2, "The victim accidentally encrypts two messages under the same nonce")
    plaintext_a = b"Transfer 10 USD to Alice account #4471"
    aad_a = b"txn-header-v1"
    plaintext_b = os.urandom(60)
    aad_b = os.urandom(6)

    sample_a = _encrypt_and_wrap(victim, nonce, plaintext_a, aad_a)
    sample_b = _encrypt_and_wrap(victim, nonce, plaintext_b, aad_b)

    _kv("Message A (plaintext)", plaintext_a.decode())
    _kv("Message A ciphertext", _hex_preview(sample_a.ciphertext))
    _kv("Message A tag", sample_a.tag.hex())
    _kv("Message B ciphertext", _hex_preview(sample_b.ciphertext))
    _kv("Message B tag", sample_b.tag.hex())
    _pause()

    _step(3, "Attacker builds the difference polynomial g(X)")
    t0 = time.perf_counter()
    g = build_difference_polynomial(sample_a, sample_b)
    elapsed = time.perf_counter() - t0
    _kv("deg(g)", str(g.degree()))
    _kv("build time", f"{elapsed * 1000:.2f} ms")
    print(
        "\n  g(X) = GHASH_X(A, C_A) XOR GHASH_X(B, C_B) XOR (T_A XOR T_B)."
        "\n  The one-time mask E_k(J0) cancels between the two equations,"
        "\n  leaving a polynomial whose roots in GF(2^128) include H."
    )
    _pause()

    _step(4, "Attacker finds every root of g(X) over GF(2^128)")
    t0 = time.perf_counter()
    candidates = find_roots(g)
    elapsed = time.perf_counter() - t0
    _kv("candidate roots found", str(len(candidates)))
    _kv("root-finding time", f"{elapsed:.2f} s")
    for i, c in enumerate(candidates):
        marker = " <-- true H" if c == GF128Element(victim.h_subkey) else ""
        _kv(f"  candidate[{i}]", c.to_bytes().hex() + marker)
    _pause()

    _step(5, "Attacker disambiguates H with one more intercepted ciphertext")
    plaintext_c = os.urandom(45)
    aad_c = os.urandom(3)
    sample_c = _encrypt_and_wrap(victim, nonce, plaintext_c, aad_c)

    material = recover_key_material(candidates, sample_a, [sample_c])
    _kv("recovered H", material.h_subkey.to_bytes().hex())
    _kv("recovered mask E_k(J0)", material.mask.hex())
    _kv("H correct?", str(material.h_subkey == GF128Element(victim.h_subkey)))
    _kv(
        "mask correct?",
        str(material.mask == victim.cipher.encrypt_block(nonce + b"\x00\x00\x00\x01")),
    )
    _pause()

    _step(6, "Forgery #1: tamper with the intercepted transaction")
    forged_plaintext = b"Transfer 99 USD to Mallory acct #00000"
    assert len(forged_plaintext) == len(plaintext_a), "demo patch must match length"
    patch = bytes(a ^ b for a, b in zip(plaintext_a, forged_plaintext))
    tampered = tamper_ciphertext(material, aad_a, sample_a.ciphertext, 0, patch)

    try:
        recovered = victim.decrypt(nonce, tampered.ciphertext, tampered.tag, tampered.aad)
        print(f"\n  Victim's decrypt() ACCEPTED the tampered ciphertext.")
        _kv("decrypted (forged) plaintext", recovered.decode(errors="replace"))
    except AuthenticationError:
        print("\n  Victim's decrypt() rejected the forgery (unexpected!).")
    _pause()

    _step(7, "Forgery #2: author an entirely new authenticated message")
    forged = forge_ciphertext(material, b"attacker-controlled-aad", b"\x00" * 32)
    try:
        victim.decrypt(nonce, forged.ciphertext, forged.tag, forged.aad)
        print("\n  Victim's decrypt() ACCEPTED a brand-new attacker-chosen ciphertext.")
        print("  (its *plaintext* is garbage without the keystream, but the")
        print("   AUTHENTICITY check — the entire point of GCM's tag — passed.)")
    except AuthenticationError:
        print("\n  Victim's decrypt() rejected the forgery (unexpected!).")

    _banner("Attack complete: authenticity broken without recovering k")
    print(
        "\nTakeaway: nonce reuse under AES-GCM is catastrophic for"
        "\nauthenticity even though AES-128 itself, CTR, and GHASH are all"
        "\nimplemented and verified correctly above — this is a protocol-"
        "\nlevel failure (NIST SP 800-38D explicitly forbids nonce reuse),"
        "\nnot an implementation bug.\n"
    )


if __name__ == "__main__":
    main()
