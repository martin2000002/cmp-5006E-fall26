# Week 2 Studio — Control Scorecard: the One-Time Pad

Code: [`starter.py`](starter.py) (Tasks 1-3). All four provided tests pass.

Reproduce: `cd studios/week-02 && python3 test_otp.py`

---

## Task 1 — Entropy & unicity

`unicity_for_substitution()` → **H(K) = 88.4 bits**, **U = 27.6 characters**.

- **Why did week 1's frequency attack succeed?** The plaintext was hundreds of
  characters, far past the unicity distance (U ≈ 27.6), so enough ciphertext was
  available to statistically pin down the one key consistent with readable English.
- **At what length would the break become ambiguous?** Below ≈ 28 characters —
  short enough that multiple keys would each decrypt the ciphertext to some
  plausible English fragment, with no way to tell which is the real key.

## Task 3 — The two-time-pad break: cribs, positions, chaining

`x = c1 XOR c2 = p1 XOR p2` (key cancels — no key or plaintext needed to start).

| Crib | Hit position | Revealed fragment | Real or noise? |
|---|---|---|---|
| `please` | **0** | `the la` | **real** — `please` sits at its true start in P2 (pos 0), so the fragment is P1 at that offset (`the la…`) |
| `please` | 48 | `ei  jk` | noise — lowercase+space by chance, not an English fragment |
| `target` | **38** | `t whil` | **real** — `target` sits at its true position in P1 (pos 38, "…the **target** is…"), so the fragment is P2 at that offset (`…cat t whil…` → "cat while") |
| `target` | 65 | `ekwklx` | noise |

`printable_word` only filters lowercase+space, so half the hits per crib are
coincidental noise (must be told apart from signal by eye — "the la" and
"t whil" read like English, "ei  jk" and "ekwklx" do not).

**Chaining to full messages:** starting from the confirmed anchor at position 0
(`please` → `the la…`), we extended the crib character-by-character
(`the la` → `the launch` → …), re-running `crib_drag` at that fixed position to
pull out more of P1 each time, the classic crib-dragging technique. The `target`
anchor at position 38 did the same in the other direction, extending into
`while i am…` on the P2 side. Once enough overlapping words were stitched into a
full guess for P1 (`"the launch code is four seven two the target is the north
bridge tonight"`), `recover_other_plaintext(c1, c2, P1)` took over: keystream =
`c1 XOR P1`, then `c2 XOR keystream` gave P2 back **exactly**
(`"please water my plants and feed the cat while i am away for the weekend
ok"`), no further guessing needed — verified byte-for-byte in
`test_two_time_pad_leaks_and_crib_drag_recovers`.

---

## Task 4 — Control Scorecard row (one-time pad)

| Axis | Before (no crypto) | After control (OTP, key used once) | Evidence |
|---|---|---|---|
| **Threat model** | ciphertext-only adversary, unbounded compute, holds full ciphertext, no key, no plaintext | unchanged | `test_otp.py` |
| **Guarantee** | none — plaintext read directly | **perfect secrecy**: ciphertext statistically independent of plaintext, against *unbounded* compute, **provided** key is uniform-random, ≥ message length, and used **exactly once** | `test_otp_perfect_secrecy_when_key_used_once` |
| **Coverage** | 0/1 — message fully exposed | 1/1 — condition met, no known or theoretical attack, not even brute force (every key is equally consistent with every plaintext) | `key_that_decrypts_to`: same ciphertext decrypts to `ATTACK AT DAWN` and to `RETREAT NOW!!!` under two different keys |
| **Bypass** | — | **found: key reuse (two-time pad).** `c1 XOR c2 = p1 XOR p2` — the key cancels, attacker never needed it. Crib `please` hit position 0, crib `target` hit position 38; with one full plaintext as crib, `recover_other_plaintext` pulled the keystream (`c1 XOR p1`) and the second plaintext fell out **in full** | `test_two_time_pad_leaks_and_crib_drag_recovers`; crib hits `please`→[0, 48], `target`→[38, 65] |
| **FP cost** | n/a | n/a — OTP is a confidentiality primitive, not a detector; it blocks nothing, so there is no legitimate traffic to misclassify | — |
| **Op cost** | none | **severe**: true-random key material equal in length to *all* plaintext ever sent, generated once, distributed over a channel as secure as the one being protected, stored until use and destroyed after — no reuse, ever | — |
| **Observability** | n/a | **none built in.** Reuse produces a ciphertext that is still high-entropy and looks fine in isolation; nothing logs or alerts that a key was reused — the break is only visible to an analyst who thinks to XOR two ciphertexts together | — |
| **Failure mode** | — | **fails silently open.** Reusing the key doesn't crash, doesn't alert, doesn't degrade gracefully — it collapses to a **total** break (both plaintexts recovered in full) with zero signal at encryption time | `recover_other_plaintext` recovers `P1`/`P2` exactly, both directions |

**Why does essentially nobody deploy the one provably-unbreakable cipher?**
Key distribution is exactly as hard as message distribution: to send `n` bytes of
plaintext you must first share `n` bytes of true-random key over a channel at
least as secure as the one you don't trust for the message itself — and that key
can never be reused. It only pushes the confidentiality problem earlier in time
instead of solving it, so it doesn't scale to bulk or interactive traffic the way
computational security (AES, weeks 3-4) does.

### Where we may have been unfair, and what we did not test

- Only one misuse mode tested: **exactly two** reuses of the key (two-time pad).
  Real-world key-reuse incidents are often N-time (N > 2); we did not measure
  whether crib-dragging gets easier or harder as N grows.
- Cribs (`please`, `target`) were chosen because we knew the plaintext in advance
  (same corpus as the notebook). A real analyst without a good guess at
  probable words would need a larger dictionary and more attempts — coverage of
  the *attack* over a realistic crib list was not measured, only that it works
  given good cribs.
- `printable_word` only accepts lowercase letters and spaces; punctuation,
  digits, or capitalization in real traffic would suppress true hits and this
  was not tested against noisier plaintext.
- English redundancy (`D ≈ 3.2 bits/char`) is a language-level constant; we did
  not test non-English or already-compressed plaintext, where both the unicity
  argument (Task 1) and the crib-drag success rate would change.
- We did not attempt to *defend* against key reuse (e.g., detecting duplicate
  key material operationally) — only to attack it. That defense is out of scope
  for this studio but would be the natural next control to evaluate.
