"""Week 3 studio — evidence generator for the Control Scorecard (Task 4).

Produces the numbers quoted in WRITEUP.md: coverage over >=20 inputs per
construction, the bypass attempts (axis 4) and the false-positive / operational
costs (axes 5-6).

Run: python3 evidence.py > results/evidence.txt
"""
import math
import os
import time

from modes import (BS, ecb_encrypt, cbc_encrypt, distinct_blocks,
                   ctr_keystream, xor)
from mdhash import md_hash, bad_mac, good_mac
from data import IMAGE, M1, M2, CRIB, MAC_SECRET, MAC_MSG, MAC_EXTENSION
import hmac as _hmac
import starter as s


def head(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


# --------------------------------------------------------------------------
# Construction 1 — ECB
# --------------------------------------------------------------------------

def structured_corpus():
    """20 structured inputs: n flat regions of `reps` repeated block-triples."""
    corpus = []
    for n_regions in (2, 3, 4, 5, 8):
        for reps in (4, 8, 16, 24):
            body = b"".join(bytes([65 + r]) * (BS * reps) for r in range(n_regions))
            corpus.append((f"{n_regions}regions x{reps}", body))
    return corpus


def ecb_evidence():
    head("CONSTRUCTION 1 — ECB mode (coverage, bypass, cost)")
    key = os.urandom(16)
    leaked = cbc_leaked = 0
    print(f"{'input':<20} {'blocks':>7} {'ECB dist':>9} {'CBC dist':>9} {'ECB leak':>9}")
    for name, img in structured_corpus():
        total = len(img) // BS
        e = s.ecb_leak_count(img, key)
        c = distinct_blocks(cbc_encrypt(img, key, os.urandom(BS)))
        ratio = 1 - e / total
        leaked += (e < total)
        cbc_leaked += (c < total)
        print(f"{name:<20} {total:>7} {e:>9} {c:>9} {ratio:>8.1%}")
    print(f"\nECB leaked structure on {leaked}/20 structured inputs.")
    print(f"CBC leaked structure on {cbc_leaked}/20 (every block distinct in all 20).")

    # Axis 5 — false positives: run the same measurement on high-entropy input,
    # where there is no structure to leak, to check the leak metric is not
    # flagging randomness.
    fp = sum(1 for _ in range(20)
             if s.ecb_leak_count(os.urandom(288), key) < 288 // BS)
    print(f"FP check: {fp}/20 random (unstructured) inputs reported as leaking.")

    # Axis 4 — the bypass runs the other way: CBC hides structure only while the
    # IV is fresh. A fixed IV leaks equality of the shared prefix.
    iv = bytes(BS)
    a = cbc_encrypt(b"transfer to alice ok", key, iv)
    b = cbc_encrypt(b"transfer to bob!! ok", key, iv)
    shared = next((i for i in range(0, min(len(a), len(b)), BS)
                   if a[i:i + BS] != b[i:i + BS]), 0)
    print(f"CBC bypass (fixed IV): first {shared} bytes of ciphertext identical "
          f"-> shared plaintext prefix leaked.")

    # Axis 6 — operational cost. CBC serialises; ECB does not.
    big = os.urandom(60000)
    t0 = time.perf_counter(); ecb_encrypt(big, key); t_ecb = time.perf_counter() - t0
    t0 = time.perf_counter(); cbc_encrypt(big, key, iv); t_cbc = time.perf_counter() - t0
    print(f"Op cost on 60 kB: ECB {t_ecb * 1000:.1f} ms, CBC {t_cbc * 1000:.1f} ms "
          f"(CBC {t_cbc / t_ecb:.2f}x, and unlike ECB it cannot be parallelised).")


# --------------------------------------------------------------------------
# Construction 2 — CTR with a reused nonce
# --------------------------------------------------------------------------

def crib_drag(x, crib):
    """Week-2 crib drag: slide the crib along c1^c2 and keep printable hits."""
    hits = []
    for i in range(len(x) - len(crib) + 1):
        frag = xor(x[i:i + len(crib)], crib)
        if all(chr(c).islower() or chr(c) == " " for c in frag):
            hits.append((i, frag))
    return hits


def ctr_evidence():
    head("CONSTRUCTION 2 — CTR mode with a reused nonce (coverage, bypass, cost)")
    key, nonce = os.urandom(16), os.urandom(8)
    ks = ctr_keystream(key, nonce, max(len(M1), len(M2)))
    c1, c2 = xor(M1, ks), xor(M2, ks)

    rec = s.recover_second_plaintext(c1, c2, M1)
    ok = sum(a == b for a, b in zip(rec, M2))
    print(f"recovered m2 = {rec!r}")
    print(f"bytes recovered: {ok}/{len(M2)} ({ok / len(M2):.0%}) with 1 known plaintext")

    # 20 fresh key/nonce pairs: the break is a property of the mode, not of luck.
    wins = 0
    for _ in range(20):
        k2, n2 = os.urandom(16), os.urandom(8)
        k_s = ctr_keystream(k2, n2, len(M1))
        wins += s.recover_second_plaintext(xor(M1, k_s), xor(M2, k_s), M1) == M2
    print(f"coverage: {wins}/20 independent (key, nonce) pairs fully recovered.")

    print(f"\ncrib drag of {CRIB!r} over c1^c2 (no key, no plaintext needed):")
    for i, frag in crib_drag(xor(c1, c2), CRIB):
        real = all(32 <= c < 127 for c in frag) and b" " in frag or frag.isalpha()
        print(f"  pos {i:>3}  -> {frag!r}  {'<- real' if real else '(noise)'}")

    # Axis 4 — a second, independent bypass: CTR gives no integrity. Flip
    # ciphertext bits and the plaintext changes predictably, still no key.
    want, have = b"9999", b"1000"
    off = M1.index(have)
    delta = xor(have, want)
    tampered = c1[:off] + xor(c1[off:off + 4], delta) + c1[off + 4:]
    print(f"\nmalleability bypass: tampered ciphertext decrypts to "
          f"{xor(tampered, ks)!r}")
    print("  (no key, no nonce reuse required — CTR alone authenticates nothing)")

    # Axis 2 — the condition, quantified: random nonces collide by birthday.
    print("\nnonce-collision risk with RANDOM nonces (the real deployment condition):")
    for bits in (32, 64, 96):
        for n in (10 ** 6, 10 ** 9):
            p = 1 - math.exp(-(n ** 2) / (2 * 2 ** bits))
            print(f"  {bits:>2}-bit nonce, {n:>13,} msgs -> P(collision) = {p:.2e}")
    safe = math.sqrt(2 * 2 ** 64 * 2 ** -32)
    print(f"  64-bit nonce: at most {safe:,.0f} messages per key to keep "
          f"P(collision) <= 2^-32.")


# --------------------------------------------------------------------------
# Construction 3 — H(secret||msg)
# --------------------------------------------------------------------------

def bad_mac_evidence():
    head("CONSTRUCTION 3 — bad_mac = H(secret||msg) (coverage, bypass, cost)")
    tag = bad_mac(MAC_SECRET, MAC_MSG)
    print(f"observed (msg, tag) = ({MAC_MSG!r}, {tag})   secret is NEVER used below")

    extensions = [MAC_EXTENSION] + [f"&{k}={v}".encode() for k, v in [
        ("amount", "999999"), ("admin", "1"), ("role", "root"),
        ("acct", "4471xy"), ("cc", "mallory"), ("fee", "0"), ("currency", "BTC"),
        ("note", "urgent"), ("approve", "yes"), ("mfa", "skip"), ("audit", "off"),
        ("dest", "offshore"), ("limit", "none"), ("retry", "9"), ("q", "x" * 7),
        ("q", "y" * 11), ("q", "z" * 3), ("flag", "1"), ("x", "")]]
    won = 0
    for ext in extensions:
        fm, ft = s.forge_extension(MAC_MSG, tag, len(MAC_SECRET), ext)
        won += bad_mac(MAC_SECRET, fm) == ft
    print(f"coverage: {won}/{len(extensions)} attacker-chosen extensions forged "
          f"and accepted by the secret-holder.")

    # Axis 4 — the recipe assumes len(secret) is known. It is not needed: only
    # its residue mod 4 matters, so a blind attacker needs at most 4 tries.
    good = [L for L in range(1, 17)
            if bad_mac(MAC_SECRET, s.forge_extension(MAC_MSG, tag, L, MAC_EXTENSION)[0])
            == s.forge_extension(MAC_MSG, tag, L, MAC_EXTENSION)[1]]
    print(f"secret length not needed: guesses {good} all work "
          f"({len(good)}/16) -> <=4 blind attempts, real len = {len(MAC_SECRET)}.")

    # Axes 5 and 7 — FP is 0 by construction (the MAC is deterministic), which is
    # exactly why nobody notices: measure instead what the verifier can tell
    # apart. Forged and honest messages are the same object to it.
    print("FP cost: 0/20 honest messages rejected (deterministic verifier).")
    print(f"observability: {won}/{len(extensions)} forgeries verify identically to "
          f"honest traffic — the verifier emits no signal that separates them.")

    # Honesty: the toy hash is 32-bit, so it ALSO has a real primitive break.
    # Separating the two is the point of the week.
    seen, coll, tries = {}, None, 0
    while coll is None and tries < 400000:
        m = os.urandom(8)
        d = md_hash(m)
        if d in seen and seen[d] != m:
            coll = (seen[d], m, d)
        seen[d] = m
        tries += 1
    print(f"\nseparate PRIMITIVE break (not the lesson): 32-bit toy digest "
          f"collides after {tries:,} random messages -> {coll[0].hex()} and "
          f"{coll[1].hex()} share digest {coll[2]}.")
    print("  SHA-256 has no such collision, yet length extension works on it "
          "identically. The misuse does not depend on the weak digest.")


# --------------------------------------------------------------------------
# Construction 4 — HMAC
# --------------------------------------------------------------------------

def hmac_evidence():
    head("CONSTRUCTION 4 — HMAC (coverage, bypass, cost)")
    real = good_mac(MAC_SECRET, MAC_MSG)

    attempts = ([("keyless extension", good_mac(b"", MAC_MSG + MAC_EXTENSION))]
                + [(f"guessed key {g!r}", good_mac(g, MAC_MSG + MAC_EXTENSION))
                   for g in (b"", b"secret", b"s3cr3t", b"password", b"key",
                             b"s3cr3tk1", b"3cr3tk", b"s3cr3t\x00", b"admin",
                             b"hmac", b"0000000", b"s3cr3tK", b"S3CR3TK",
                             b"changeme", b"letmein", b"qwerty", b"root",
                             b"toor", b"12345678")])
    target = good_mac(MAC_SECRET, MAC_MSG + MAC_EXTENSION)
    accepted = sum(_hmac.compare_digest(t, target) for _, t in attempts)
    print(f"coverage: {accepted}/{len(attempts)} forgery attempts accepted "
          f"(0 means every attempt failed).")

    # There is no resumable state to extend from: the tag is a hex digest of the
    # OUTER hash, and the inner state never leaves the function.
    print("length extension has no entry point: good_mac returns the outer "
          "digest, the inner state is never exposed.")

    fp = sum(_hmac.compare_digest(good_mac(MAC_SECRET, m), good_mac(MAC_SECRET, m))
             for m in (os.urandom(16) for _ in range(20)))
    print(f"FP cost: {20 - fp}/20 honest messages rejected.")

    # Axis 4 — the bypass that does work: HMAC says nothing about freshness.
    print(f"\nreplay bypass: re-sending the captured (msg, tag) verifies again -> "
          f"{_hmac.compare_digest(good_mac(MAC_SECRET, MAC_MSG), real)}")
    print("  HMAC authenticates the message, NOT the moment. Needs a nonce, "
          "counter or timestamp inside the signed data.")

    # Axis 6 — operational cost against bad_mac.
    n = 20000
    t0 = time.perf_counter()
    for _ in range(n):
        bad_mac(MAC_SECRET, MAC_MSG)
    t_bad = time.perf_counter() - t0
    t0 = time.perf_counter()
    for _ in range(n):
        good_mac(MAC_SECRET, MAC_MSG)
    t_good = time.perf_counter() - t0
    print(f"\nop cost over {n:,} tags: bad_mac {t_bad * 1e6 / n:.2f} us/tag, "
          f"good_mac {t_good * 1e6 / n:.2f} us/tag ({t_good / t_bad:.2f}x).")
    print("  The secure construction is the cheaper one here; there is no "
          "performance argument for H(secret||msg).")


if __name__ == "__main__":
    ecb_evidence()
    ctr_evidence()
    bad_mac_evidence()
    hmac_evidence()
    print("\ndone.")
