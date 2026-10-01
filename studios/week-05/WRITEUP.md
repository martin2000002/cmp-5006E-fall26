# Week 5 Studio — Diffie–Hellman, MITM & the Trust Anchor

Code: [`starter.py`](starter.py) (Tasks 1 & 3). All six provided tests pass.

```bash
cd studios/week-05
python3 test_dh_pki.py    # 6/6 pass
python3 starter.py        # honest DH, MITM, and the poisoning before/after
```

Python 3.14.3. Secrets below are shown as their first 64 bits.

---

## Warm-up

DH gives Alice a secret shared with **whoever answered**. Nothing in the exchange
says who that is, so an attacker who can rewrite traffic simply answers both
sides. What closes the gap is **authentication**: a signature over the exchange,
made with a key that PKI binds to a name.

## Task 1 — DH + the man-in-the-middle

`dh_public` and `dh_shared` are each a single `pow`. In `mitm_keys`, Mallory
replaces `A` and `B` on the wire with her own `M`, so each side runs an honest DH
exchange with her.

With the test exponents (`a = 0x1a2b…`, `b = 0x99aa…`, `m = 0xdead…`):

| Run | Alice's key | Bob's key | Mallory's keys | Alice = Bob? |
|---|---|---|---|---|
| Honest | `0xaf4d0c201032fc3c` | `0xaf4d0c201032fc3c` (= `g^(ab) mod p`) | — | **yes** |
| MITM | `0x2dffb53aace6e621` | `0x685c81c605dd8ed1` | `0x2dff…e621` with Alice, `0x685c…8ed1` with Bob | **no** |

Each leg is still perfectly secret from a passive observer. The problem is that
Alice's secret leg ends at Mallory.

**Guarantee, as a conditional:** DH gives two parties a shared secret that a
passive eavesdropper cannot compute, **provided the endpoints are authenticated**
(and the discrete log in the group is hard, and the exponents are long enough;
both conditions are questioned below). Remove the authentication proviso and the
MITM succeeds without solving any discrete log. **Misuse, not a primitive break.**

**Where the "authenticated" in TLS 1.3 comes from:** the server signs the
handshake transcript, which includes both DH key shares, in `CertificateVerify`
using the private key of the certificate whose chain the client validated to a
trusted root (§2). Mallory cannot swap in her key share without a signing key
the trust store vouches for.

## Task 2 — Cert-chain validation & forgery rejection

| Chain | `validate(…, clean store)` | Reason |
|---|---|---|
| `bank.example.com` ← ACME Intermediate ← ACME Root | **True** | chain valid |
| self-signed `bank.example.com` (Mallory's key) | **False** | `anchor 'bank.example.com' is not a trusted root` |
| `bank.example.com` ← Rogue CA | **False** | `anchor 'Rogue CA' is not a trusted root` |

Both forgeries carry **valid** signatures: the self-signature verifies, and so
does the Rogue CA's signature on the leaf. Both pass the signature loop and are
rejected at the same line, `root["pub"] not in trust_store`.

**Why, in one sentence:** Mallory can sign anything she likes, but she cannot get
her signing key into your trust store, so the check that stops her is set
membership, not mathematics.

## Task 3 — The trust-store attack

`poison_trust_store` returns `set(trust_store) | {rogue_root["pub"]}`. That is a
new set: the caller's store still has 1 anchor and the poisoned one has 2.

| Store | Rogue chain | Legit ACME chain | Self-signed forgery |
|---|---|---|---|
| clean (1 anchor) | **REJECTED**: `anchor 'Rogue CA' is not a trusted root` | valid | rejected |
| poisoned (+ Rogue CA) | **ACCEPTED**: `chain valid — key is authentically bound to the name` | valid | rejected |

The same certificate bytes were checked twice; only the anchor set changed. Two
details matter here:

- The real bank chain **still validates**. Both certificates look valid, so the
  user gets no failure signal (axis 7: nothing to observe).
- The self-signed forgery is still rejected, because it chains to Mallory's leaf
  key and not to the rogue root. Poisoning trusts one key, and that key can then
  vouch for **any** name. For the rogue CA, `bank.example.com` is just one more
  signature.

**Real-world mapping:**

| Case | What happened | In our model |
|---|---|---|
| **DigiNotar (2011)** | An attacker compromised the CA and issued a valid `*.google.com` cert, used to MITM Gmail for users in Iran. Chrome's pinning for Google domains caught it, and the fix was removing DigiNotar from trust stores. | The rogue key was **already** in the store. The remedy is deleting it from the set. |
| **Superfish (Lenovo, 2015)** | Preinstalled adware added its own root CA, with the same private key on every machine. | `poison_trust_store` performed by software the user never chose. |
| **Mis-issuance** | An honest but negligent CA signs a cert it should not have. | A legitimate anchor signs `rogue_leaf`, and the chain is valid with no poisoning at all. |

Certificate Transparency makes issuance public, so a mis-issued cert is
**detectable** after the fact. It is a detective control, not a preventive one.

## Task 4 — Control Scorecard

| Mechanism | Guarantee (axis 2) | Its condition / failure | Evidence | Primitive break or misuse? |
|---|---|---|---|---|
| **Diffie–Hellman** | a shared secret `g^(ab) mod p` that a passive eavesdropper cannot compute | **provided the endpoints are authenticated**, the DLP in the group is hard at its real size, and the exponents have enough entropy. With no authentication, the MITM gives Mallory one key per side and Alice and Bob share nothing. | Task 1: `alice = mallory_alice`, `bob = mallory_bob`, `alice_equals_bob = False` | **misuse**: no discrete log was solved; Mallory ran two honest exchanges |
| **Certificate chain** | binds a public key to a name, **provided** every signature verifies up to an anchor in the trust store **and** the validator checks what the client actually uses | only as trustworthy as the **root trust store**: one rogue anchor and every chain under it validates. Also only as good as the validator (see below). | Task 2: 2 of 2 forgeries rejected at the anchor check. Task 3: the same rogue chain goes False → True after adding 1 key. | **misuse**: no signature was forged; the anchor set was changed |
| **TLS 1.3** | a confidential, authenticated, forward-secret channel to the named server | **every** condition below must hold at once: authenticated DH (`CertificateVerify` over the transcript), a correct trust store, no AEAD nonce reuse under a key (wk3), keys from good entropy (wk4) | none; asserted from the composition, not tested here | n/a; any failure would be a misuse of one row above or of wk3/wk4 |

On the rubric's evidence scale, the DH and certificate rows are **2** (one payload
each) and the TLS row is **1** (asserted).

## Where we may have been unfair, and what we did not test

- **The "1024-bit group 2" prime is actually the 768-bit group 1.**
  `DH_P.bit_length()` is **768** (192 hex digits, a safe prime ending
  `…A63A3620FFFFFFFFFFFFFFFF`). That is RFC 2409 Oakley **group 1**. The README,
  the `dh_pki.py` docstring, `fixtures.json` and the notebook all say 1024. A
  768-bit prime-field discrete log was computed publicly in 2016 (Kleinjung et
  al.). For a fixed, widely shared prime like this one, the precomputation is
  paid once and amortized over every exchange that uses it, which is the Logjam
  argument. Our passive-secrecy claim for DH therefore rests on a group size
  already within reach of academics. We accepted the label until we measured it.
- **The test exponents are 64-bit.** When the exponent is known to be
  `< 2^64`, Pollard's kangaroo recovers it in about `2^32` group operations,
  whatever the size of `p`. The "honest DH" test therefore has roughly 32-bit
  security against a passive eavesdropper. `starter.py`'s smoke run uses 256-bit
  exponents; the tests do not. We did not run the attack.
- **The given validator verifies `body` but trusts the `pub` and `subject`
  fields, and never checks that they match `body`.** We checked each tamper
  once, outside the deliverable, and each one validates under the **clean**
  store with no poisoning:

  | Tamper | `validate(…, clean store)` |
  |---|---|
  | Legit chain, leaf's `pub` swapped for Mallory's key (body and sig untouched) | **True** |
  | Legit intermediate's `pub` swapped for Mallory's key, plus a leaf for `bank.example.com` that Mallory signs herself | **True** |
  | Bank's leaf key (not a CA) signs a `mail.google.com` cert, chain `[google, bank, inter, root]` | **True** |
  | Leaf relabeled `subject = "anything.example"` | **True** |

  The signature binds a string, and the client reads fields the string never
  constrains. `validate` also has no CA flag (the same bug class as Internet
  Explorer's 2002 basicConstraints flaw), takes no hostname, and checks no expiry
  or revocation. All four bypasses beat Task 3 because none needs access to the
  victim's machine. Our "2 of 2 forgeries rejected" only tested the forgeries the
  fixture handed us.
- **The signing keys are 128-bit toy RSA** (two 64-bit primes, as in week 4).
  General-purpose factoring tools split a ~39-digit semiprime in seconds or less.
  Mallory could recover the ACME intermediate's private key and sign a perfect
  chain without touching the store. We did not try. In our own model, "Mallory
  cannot sign with a trusted key" is false.
- **We showed the attack but never the fix.** Week 4 re-ran the attack against
  the patched oracle. Here we never built signed DH to check that the MITM
  fails once `A` and `B` are authenticated. The scorecard's DH condition is
  supported only by the failure side.
- **One payload per claim.** One fixed triple of exponents and one fixture
  chain. `dh_shared` also accepts any public value. Sending `1` forces the
  secret to `1` (checked once), and we did not explore that class of attack any
  further.
