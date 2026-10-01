# Week 6 Studio — Injection, Confirmed by an Oracle, and a Duel

Code: [`starter.py`](starter.py) (Tasks 1 & 2).

```bash
PYTHONPATH="$(git rev-parse --show-toplevel)" python3 studios/week-06/test_studio.py
```

> **Status:** all 6 provided tests pass. Upstream's week-6 commit added `labs/`
> but **not** `projects/duel-2-web/ground_truth.json`, so we supply a local
> stand-in: the honest, source-derived ground truth
> `{sqli@do_login, xss@do_reflect, cmdi@do_ping}` (the three commented `# VULN`
> sinks), in the exact shape `load_ground_truth()` reads. Replace it with the
> professor's fixture when it lands and re-run — the numbers are unchanged if, as
> expected, the fixtures agree.

## Recap

A reflected payload is not a finding because **reflection is not execution**. The
server echoing `<script>` back proves the byte survived the round trip, not that it
ran in a browser in the victim's origin. A finding is real only when a sound oracle
confirms a security-relevant *effect*: an exfiltrated row, an unescaped tag, a
metacharacter reaching a command.

## Task 1 — Three confirmed findings

All three sinks are deterministic (the oracle fired on every trial), so
`reliability = 1.0` throughout and there is no axis-9 flakiness to report — unlike
the model targets of weeks 9–13.

| Sink | Endpoint | Oracle (the security-relevant effect) | Attack payloads | Result | Benign control |
|---|---|---|---|---|---|
| **SQLi** | `POST /login` | canary `FLAG-sqli-` appears in the response (a row we exfiltrated) | `admin' OR '1'='1` · `admin'--` · `' UNION SELECT user, secret FROM users--` | **3/3 confirmed** | `alice` + wrong pw → **0/1** |
| **XSS** | `GET /?name=` | the raw `<script>` survives **unescaped** in the body | `<script>alert('XSS-FIRED-7f3a')</script>` | **confirmed** on `/` | same payload on `/safe` → **not confirmed** |
| **cmdi** | `POST /ping` | JSON `injection_detected is True` (a shell metacharacter reached the command) | `127.0.0.1; whoami` · `… && whoami` · `… \| whoami` · `$(whoami)` | **4/4 confirmed** | `127.0.0.1` → **not confirmed** |

Three notes on oracle discipline, one per sink:

- **SQLi — why a canary, not "the page changed".** `admin' OR '1'='1` logs in, but
  so would any logic that flips a boolean. The proof is that the response carries
  `FLAG-sqli-9f2c-admin-session`, the admin's secret column — data the caller had
  no right to. The benign control (`alice`, wrong password) returns `{"ok": false}`
  and does **not** contain the canary, so the oracle is confirming extraction, not
  merely a status change. A false positive here would poison every number in the
  report.
- **XSS — why a custom oracle, not `contains_oracle`.** The payload *is* the marker,
  so `contains_oracle(payload)` would confirm the moment the string is reflected —
  the exact false positive the week is about. The sound necessary condition is that
  the `<script>` comes back **un-encoded**. On `/safe`, `html.escape` turns it into
  `&lt;script&gt;`, the oracle does not fire, and we carry that true negative into
  the duel.
- **cmdi — why `injection_detected`, not the echo.** The sink simulates execution
  (`would_run: "ping -c 1 …"`) instead of calling the shell, so it is safe to run.
  Confirming on the echoed command string would confirm any input; we confirm on
  the flag that a metacharacter (`;&|`$()`) actually reached the command context.
  The benign host has none, so it stays clean.

The one bug in three costumes: untrusted data crossed into SQL, into HTML, and into
a shell. The fixes rhyme — parameterize, encode (`/safe`), don't build the command
from strings.

## Task 2 — The duel: LLM vs. scanner

Both arms point at the **same file** (`vulnweb_app.py`), scored against the
hand-built ground truth of the three real sinks.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| regex-scanner (classical) | 2 | 0 | 1 | **100%** | 67% | 0.80 |
| LLM (canned review) | 3 | 2 | 0 | 60% | **100%** | 0.75 |

The shape is the whole lesson: the scanner is **precise but narrow**, the LLM is
**complete but cries wolf**. The interesting cells are not the F1 scores.

**1. The LLM's best hallucination.** `[HIGH] Broken Access Control in do_login` —
confident, severity-High, and **false**. The app has no sessions, no roles, no auth
code at all; there is nothing to bypass. Its second false positive is subtler:
`[MEDIUM] Reflected XSS in do_reflect_safe`, flagging the endpoint that is
*correctly* `html.escape`'d. The model pattern-matched "parameter reflected back"
and missed that `do_reflect_safe` is the fix. Both are analyst time spent on
nothing.

**2. The scanner's worst miss.** The **SQLi** (`sqli@do_login`) — the highest-impact
bug in the file. Its rule is line-oriented (`re.search`, `.` does not cross
newlines) and the query is split across two string literals:

```python
query = (f"SELECT user, secret FROM users "      # no '{' on this line
         f"WHERE user = '{user}' AND pw = '{pw}'")
```

The `f"SELECT…{…}"` pattern never matches a single line, so the scanner is silent on
the one bug that leaks the admin secret. That is a genuine failure mode, not a
contrivance: real line-oriented rules miss multi-line sinks constantly. The LLM,
reading for meaning, caught it.

**3. Broken Access Control — did either find it?** **No, and that is the point.**
The scanner has no rule for it. The LLM "found" it, but as a false positive — it
guessed, and guessed wrong. Access control is about **intent** (who *should* reach
this record), which neither a regex nor a next-token prediction can read off the
syntax. OWASP 2021 moved Broken Access Control to **#1**, and it is exactly the
class automation is worst at. The most important bug is the one the tools can't see.

> **Non-determinism (axis 9).** Our LLM arm is a *canned* string, so it is
> reproducible by construction. Against a real `seclab.LLM`, the README's warning
> applies: run it ≥2× and the findings drift. A scan you cannot reproduce is not
> evidence — and that drift is the subject of weeks 9–13.

## Task 3 — Control Scorecard (axes 1–4, one finding: the SQLi) + disclosure

| Axis | Entry |
|---|---|
| **1 · Threat model** | Unauthenticated remote attacker who can `POST /login`. No credentials, no prior access, network reachability only. |
| **2 · Guarantee + condition** | The vulnerable code guarantees **nothing**. The fix — parameterized queries (`DB.execute("… WHERE user=? AND pw=?", (user, pw))`) — guarantees user input is treated as *data, never as SQL*, **provided every query that touches user input is parameterized**. One string-built query anywhere reintroduces the bug; the guarantee is over the whole data path, not one call site. |
| **3 · Coverage** | 3/3 attack payloads confirmed by the canary oracle (auth-bypass, comment-out, UNION-dump); benign control 0/1 (no false positive). Deterministic, so `reliability = 1.0`. Sample, not the full input space. |
| **4 · Bypass** | Against the deck's "Medium" defense — a blocklist / `mysql_real_escape_string` that escapes quotes — the `admin'--` and `OR '1'='1` family still need quotes, but UNION dumps and keyword-casing (`UnIoN SeLeCt`) plus `/**/` comment separators evade naive keyword/quote filters. **Blocklists lose.** Only the axis-2 fix (parameterization) closes the class, because it removes the data/control boundary the attacker is crossing rather than enumerating bad strings. |

**Classification:** this is a **misuse**, not a broken primitive. SQLite is fine; the
application concatenated untrusted input into the control channel.

**Responsible-disclosure note (what / where / impact / fix), as if authorized:**

> SQL injection in `vulnweb_app.py` `do_login` (`POST /login`, `user` field): the
> query is built by f-string interpolation, so `' UNION SELECT user, secret FROM
> users--` exfiltrates the admin secret and `admin'--` bypasses authentication.
> Fix: use parameterized queries (`?` placeholders) for every user-supplied value;
> do not rely on escaping or input filtering.

## Where we may have been unfair, and what we did not test

- **The ground truth is ours, not the course's.** Upstream had not pushed
  `projects/duel-2-web/ground_truth.json`, so every duel number above is scored
  against a local stand-in **we** derived by reading the source. The README's own
  warning applies to us: "a ground truth that is just whatever a tool found rigs
  the game." Ours was built from the three commented `# VULN` sinks, not from a
  tool's output, but it is unverified against the professor's fixture until that
  file lands — the sixth test is the only thing that would catch a disagreement.
- **The cmdi sink never runs a shell.** `do_ping` *simulates* execution with a
  regex `re.search(r"[;&|`$()]", host)`. We confirmed that a metacharacter reaches
  the command context — we did **not** demonstrate code execution, and our oracle
  trusts the app's own `injection_detected` flag rather than observing a real
  side effect. Against a real `os.system`, whether the second command runs depends
  on the shell and quoting we never exercised.
- **The XSS oracle is a necessary condition, not a sufficient one.** "Unescaped
  `<script>` survived" is required for reflected XSS but does not prove execution:
  CSP, a browser's XSS auditor, or the injection context (inside an attribute vs.
  a text node) could still block it. We never ran a browser. We proved the server's
  failure to encode, which is the server-side half of the bug.
- **The LLM arm is a fixed string, so we tested none of what makes LLMs hard.** No
  non-determinism, no prompt sensitivity, no drift across runs — the canned review
  removes exactly the axis-9 property the scorecard says is the substance of AI
  security. Our precision/recall for the LLM is a single sample of one model on one
  file and generalizes to nothing.
- **Three payloads per sink is a coverage sample, not the space.** Especially for
  SQLi: we did not try blind/time-based extraction, stacked queries, or
  second-order injection, and the `UNION` dump worked only because we knew the
  column shape by reading the source — a luxury a black-box attacker lacks.
- **The scanner is a strawman we were handed.** A three-rule line-oriented regex is
  weaker than real Semgrep/CodeQL, which have multi-line and dataflow rules and
  would likely catch this SQLi. Our "the scanner misses it" result is honest about
  *this* scanner; it is not a claim about classical scanning in general, and Duel 2
  (week 8) with the real tools is where that claim would actually be tested.
