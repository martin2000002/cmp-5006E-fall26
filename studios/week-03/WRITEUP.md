# Week 3 Studio — Modes and Misuse

Code: [`starter.py`](starter.py) (Tasks 1–3). All four provided tests pass.
Evidence: [`results/evidence.txt`](results/evidence.txt) · [`results/penguin.png`](results/penguin.png)

```bash
cd studios/week-03
python3 test_modes.py     # 4/4 pass
python3 evidence.py       # scorecard measurements
python3 penguin.py        # the ECB penguin (README bonus)
```

AES and SHA-256 are intact in all four exploits below. Every break is a misuse of
the mode or the construction wrapped around them.

---

## Task 1 — ECB vs CBC

`ecb_leak_count` = `distinct_blocks(ecb_encrypt(image, key))`. ECB is stateless,
so identical plaintext blocks map to identical ciphertext blocks and the count of
distinct ciphertext blocks *is* the count of distinct plaintext blocks.

| Input | Blocks | ECB distinct | CBC distinct |
|---|---|---|---|
| provided `IMAGE` | 96 | **2** | **96** |
| penguin bitmap (96×96) | 3072 | **17** — identical to the plaintext | 3063–3072 |

Over 20 structured inputs (2–8 flat regions), ECB leaked on **20/20**, hiding
75.0 %–95.8 % of the block structure less than CBC did; CBC leaked on **0/20**.
Same image, same cipher, same key — the **mode** decided.

![ECB penguin](results/penguin.png)

## Task 2 — CTR nonce reuse

`recover_second_plaintext` = `xor(xor(c1, c2), known_m1)`. Same key *and* same
nonce ⇒ same keystream ⇒ it cancels: `c1 ⊕ c2 = m1 ⊕ m2`.

- **39/39 bytes of M2 recovered (100 %)**, on **20/20** independent (key, nonce) pairs.
- Crib-dragging `b"transfer"` over `c1 ⊕ c2` — no key, no plaintext — hits
  position **0** → `b'the quar'`, the true start of M2. One hit, no noise: the
  crib sits at its real offset in M1.
- This is week 2's two-time pad verbatim. The mode is modern; the break is not new.

**Fast-finisher question — unique nonce but the key reused across a million messages?**
Confidentiality holds. The condition was never "fresh key per message", it is
**the (key, nonce) pair must never repeat, and counter blocks must never overlap
between messages**. A counter-based nonce satisfies that for 10⁶ messages. A
*random* nonce does not automatically:

| Nonce size | 10⁶ messages | 10⁹ messages |
|---|---|---|
| 32-bit | P(collision) ≈ 1 | ≈ 1 |
| 64-bit | 2.7 × 10⁻⁸ | 2.7 × 10⁻² |
| 96-bit | ~0 | 6.3 × 10⁻¹² |

With random 64-bit nonces, **92,682 messages per key** is the ceiling to keep
P(collision) ≤ 2⁻³². Integrity is a separate matter — CTR never provides it (see
the malleability bypass below).

## Task 3 — Length extension

`forge_extension` replicates the hash's internal padding and resumes hashing from
the observed tag, because a Merkle–Damgård digest *is* the internal state:

```
pad        = bytes((-(secret_len + len(observed_msg))) % 4)
forged_msg = observed_msg + pad + extension
forged_tag = md_hash(extension, iv=observed_tag)
```

- **20/20** attacker-chosen extensions forged and accepted by the secret-holder,
  with the secret never used: `amount=100&to=alice` → `...\x00\x00&to=attacker`.
- The secret's **length is not needed either**. Only its residue mod 4 changes the
  glue padding, so guesses `[3, 7, 11, 15]` all produce a valid tag (real length
  = 7) — **≤ 4 blind attempts**.
- HMAC defeats the same attack: **0/20** forgery attempts accepted, including 19
  guessed keys. Nesting hides the resumable inner state; there is no entry point.

---

## Task 4 — Control Scorecard

Shared threat model unless noted: an attacker who observes ciphertexts/tags on the
wire, can inject and modify messages, chooses plaintext extensions, holds **no
key**, and has bounded compute.

### 1 · ECB mode

| Axis | Before (plaintext) | After control | Evidence |
|---|---|---|---|
| Threat model | passive observer reads everything | unchanged — observer now reads *structure* | `evidence.py` |
| **Guarantee** | none | confidentiality of an **individual block only**, *provided no plaintext block ever repeats* — a condition no real data satisfies | — |
| Coverage | 0/20 | **0/20** structured inputs protected; 75.0–95.8 % of block structure preserved 1:1 | `results/evidence.txt` |
| **Bypass** | — | **no bypass needed — read the image.** Penguin: 17/3072 distinct blocks in plaintext, **17/3072 in ciphertext** | `results/penguin.png` |
| FP cost | n/a | 0 % — a cipher blocks nothing; 0/20 random inputs misreported as leaking | `results/evidence.txt` |
| Op cost | — | 26.0 ms / 60 kB; parallelisable, random-access — the only reasons anyone picked it | `results/evidence.txt` |
| Observability | — | **none.** Output is valid ciphertext; nothing logs that structure survived | — |
| Failure mode | — | **fails silently open.** No error, no alert, correct decryption — the leak is visible only if someone looks at the ciphertext | — |
| **Verdict** | | **misuse** — the primitive did exactly what a deterministic permutation does | |

### 2 · CTR mode with a reused nonce

| Axis | Before (plaintext) | After control | Evidence |
|---|---|---|---|
| Threat model | passive observer | + attacker who collects two ciphertexts under one (key, nonce) and knows/guesses one plaintext | `test_modes.py` |
| **Guarantee** | none | confidentiality of the message, **provided the (key, nonce) pair is never reused and counter blocks never overlap**. **No integrity, ever, under any condition** | — |
| Coverage | 0/1 | **0/20** — M2 fully recovered on 20/20 independent (key, nonce) pairs, 39/39 bytes | `results/evidence.txt` |
| **Bypass** | — | **two, both working.** (1) Nonce reuse → `c1 ⊕ c2 = m1 ⊕ m2`, crib `transfer` hits pos 0 → `the quar`. (2) **Malleability, no reuse required**: flipping ciphertext bits turned `transfer 1000 dollars` into `transfer 9999 dollars` with no key | `results/evidence.txt` |
| FP cost | n/a | 0 % — not a detector | — |
| Op cost | — | keystream is precomputable and parallel; cost is **discipline**: a nonce counter that survives restarts, VM clones and backup restores | — |
| Observability | — | **none.** A reused nonce produces high-entropy ciphertext that looks correct in isolation; only XOR-ing two ciphertexts reveals it | `results/evidence.txt` |
| Failure mode | — | **fails silently open**, and retroactively: every message ever sent under the repeated pair is compromised at once | — |
| **Verdict** | | **misuse** — AES was never touched; the condition on its guarantee was | |

### 3 · `bad_mac` = `H(secret‖msg)`

| Axis | Before (no MAC) | After control | Evidence |
|---|---|---|---|
| Threat model | anyone can forge any message | attacker observing one `(msg, tag)` pair, **without the secret** | `test_modes.py` |
| **Guarantee** | none | *claims* only the secret-holder can produce a valid tag. **The claim is false** — it holds only against an attacker who cannot append, which is not a threat model | `test_length_extension_breaks_bad_mac_guarantee` |
| Coverage | 0/20 | **0/20** — every attacker-chosen extension forged and accepted | `results/evidence.txt` |
| **Bypass** | — | **found: length extension.** 20/20 forgeries accepted; the secret's length is not even required (`[3, 7, 11, 15]` all work) → **≤ 4 blind attempts** | `results/evidence.txt` |
| FP cost | n/a | **0 %** — 0/20 honest messages rejected. That is why it ships: it never inconveniences anyone | `results/evidence.txt` |
| Op cost | — | 8.06 µs/tag — **more expensive than HMAC** (3.65 µs). There is no performance argument for it | `results/evidence.txt` |
| Observability | — | **none.** 20/20 forgeries verify identically to honest traffic; the verifier emits no signal that separates them | `results/evidence.txt` |
| Failure mode | — | **fails open, silently, and authoritatively** — the forged message is stamped "authenticated" downstream | — |
| **Verdict** | | **misuse** — SHA-256 is not broken; `H(k‖m)` was never a MAC | |

### 4 · HMAC

| Axis | Before (`bad_mac`) | After control | Evidence |
|---|---|---|---|
| Threat model | forger with `(msg, tag)` and length extension | same attacker, plus 19 guessed keys | `evidence.py` |
| **Guarantee** | forgeable by extension | existential unforgeability, **provided the key is secret, ≥ hash-output length, and used only for this purpose**. Says **nothing about freshness** | `test_hmac_rejects_the_same_forgery` |
| Coverage | 0/20 forgeries stopped | **20/20 stopped** | `results/evidence.txt` |
| **Bypass** | — | **length extension: no entry point** — the tag is the outer digest, the inner state never leaves the function. **Replay works**: re-sending a captured `(msg, tag)` verifies again (`True`). HMAC authenticates the message, not the moment | `results/evidence.txt` |
| FP cost | 0 % | **0 %** — 0/20 honest messages rejected | `results/evidence.txt` |
| Op cost | 8.06 µs/tag | **3.65 µs/tag (0.45×)** plus key management | `results/evidence.txt` |
| Observability | none | verification failures are catchable and loggable — but only if the caller checks with `compare_digest` and logs the result | — |
| Failure mode | fails open | **fails closed** if used correctly; **fails open** if compared with `==` on a non-constant-time path, or if the key leaks | — |
| **Verdict** | | correct construction — remaining gaps (replay, key handling) are the caller's, not the primitive's | |

### Primitive break vs misuse

| Construction | Primitive intact? | Classification |
|---|---|---|
| ECB | AES fine | **misuse of the mode** |
| CTR + reused nonce | AES fine | **misuse of the mode** |
| `H(secret‖msg)` | SHA-256 fine | **misuse of the construction** |
| HMAC | SHA-256 fine | correct use |

**4/4 are misuses.** Not one attack needed a weakness in AES or SHA-256.

### Self-scored against the rubric (0–4)

| Construction | Threat | Guar. | Cov. | Bypass | FP | Op | Obs. | Fail | Notes |
|---|---|---|---|---|---|---|---|---|---|
| ECB | 3 | 4 | 4 | 4 | 3 | 3 | 3 | 3 | corpus is synthetic (see below) |
| CTR nonce reuse | 3 | 4 | 4 | 4 | 3 | 2 | 3 | 3 | op cost argued, not measured |
| `H(secret‖msg)` | 3 | 4 | 4 | 4 | 3 | 4 | 4 | 3 | |
| HMAC | 3 | 4 | 3 | 4 | 3 | 4 | 3 | 3 | 19 guessed keys is a token key-search |

---

## Where we may have been unfair, and what we did not test

- **The toy primitives are weaker than the real ones, in ways that flatter us.**
  `md_hash` is a 32-bit multiplicative digest: we found a collision after 112,291
  random messages (birthday expectation ≈ 2¹⁶). That is a genuine **primitive
  break** and it is *not* the lesson — length extension works identically against
  real SHA-256, which has no such collision. We kept the two separate on purpose;
  a reader who conflates them would draw the wrong conclusion from this studio.
- **CBC does not always reach 3072/3072 distinct blocks.** Over 15 runs on the
  penguin we saw a mean of 1.5 collisions (birthday expectation 0.28), clustered
  in groups of 5–12. The toy block is 3 bytes = 24 bits, so once two ciphertext
  blocks collide the flat regions keep them colliding. With AES's 128-bit block
  that bound is unreachable. **The toy exaggerates CBC's weakness, not ECB's** —
  the ECB result transfers unchanged.
- **The ECB corpus is synthetic.** 20 inputs of our own construction, all flat
  regions. Real images, disk sectors and TLS records leak differently; we did not
  test compressed or high-entropy data, where ECB leaks much less.
- **We gave the attacker more than the defender in Task 3.** The attacker gets
  `(msg, tag, len(secret))` and unlimited forgery attempts; the "server" only
  recomputes a tag. We did not test rate limiting, nonces in the signed data, or
  a message format that would reject the trailing null padding — any of which
  would blunt this specific forgery without fixing the construction.
- **The HMAC key search is a token effort**: 19 guessed keys, no dictionary, no
  offline brute force. We claim 20/20 forgeries stopped, and make **no claim**
  about a real key-recovery budget.
- **We measured no timing side channel.** We assert `compare_digest` matters and
  did not demonstrate a timing leak from `==`. Untested.
- **Not tried for lack of time:** CBC bit-flipping / padding-oracle attacks
  (we showed only the fixed-IV prefix leak, 12 bytes), and GCM nonce reuse, which
  is strictly worse than CTR's — it also leaks the authentication subkey and
  destroys integrity for every message under that key, not just the two involved.
