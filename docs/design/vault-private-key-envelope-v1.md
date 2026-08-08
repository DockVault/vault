# Account private-key envelope, version 1

Status: **frozen for implementation**. This document defines the successor to the current
unversioned private-key envelope. It is written and reviewed before the new writer exists, so the
grammar, bounds, authenticated transcript, legacy acceptance and downgrade behaviour are fixed
before any code depends on them.

## 1. What the envelope is, and what it is not

A DockVault account that uses zero-knowledge vaults holds a P-384 identity keypair. The public key
is registered with the server in the clear. The private key never reaches the server in usable
form: the browser encrypts it under a key derived from the account passphrase and uploads only the
resulting opaque blob, which the server stores verbatim and returns verbatim.

That blob is the *envelope*. The server does not parse it, cannot decrypt it, and must never be
able to. Everything here is therefore a **client-side** contract. The server's only obligation is
to store and return the string faithfully; it performs no validation today, and this document does
not ask it to start.

The envelope protects the private key at rest against anyone who reads the database. It does not
protect against an operator who serves modified JavaScript to the browser — that is a separate
problem (signed clients, key transparency) and this format does not claim to solve it.

### 1.1 Two envelopes, one format

The same format is produced in two different places, and this matters more than it first appears:

1. **The stored account envelope**, held server-side and returned to the browser at unlock.
2. **The recovery kit**, encrypted under a separate recovery passphrase and *downloaded as a file*
   the user keeps.

They share a writer today. The difference is trust: the stored envelope arrives from the server,
whereas **the recovery kit arrives from a file the user selects at restore time**. Both are
untrusted input — a database-level attacker controls the stored envelope's fields just as fully —
but the kit is the one an ordinary user can be socially engineered into supplying, and it is the
reason the bounds in §4 and §7 are load-bearing rather than theoretical. Any statement about
parsing, bounds or rejection applies to both unless it says otherwise.

**The kit is not a bare envelope.** It is a JSON file that *contains* one:

```json
{ "type": "dockvault-zk-recovery-key", "version": 1,
  "user_id": "...", "fingerprint": "...", "public_key": "<PEM>",
  "recovery": { <envelope> } }
```

The envelope lives at `.recovery` and must satisfy §4 (v1) or §5 (legacy) exactly as a stored
envelope does. The wrapper is a separate structure with its own obligations, because its members
are equally attacker-supplied:

- The file as read from disk must be rejected above **65,536 bytes before it is parsed at all**.
  A genuine kit is well under 2 KB; the margin is for future wrapper fields, not for an attacker.
- `type` must equal `"dockvault-zk-recovery-key"` and `version` must equal `1`.
- `user_id`, `fingerprint` and `public_key` are strings with a maximum length of 4,096 each.
  `public_key` is compared against the account's registered key; it is never a source of trust and
  never substitutes for the §6 consistency check.
- Unknown wrapper members are ignored rather than rejected, so a future field does not break an
  older reader. This differs deliberately from the envelope itself, where an unexpected member is a
  structural error.

## 2. Why version 1 exists

The current envelope is a three-key JSON object:

```json
{ "encrypted": "<base64 iv12 || ciphertext || tag16>", "salt": "<base64 32 bytes>", "iterations": 600000 }
```

It works, and every deployed account uses it. Four properties are missing:

1. **It is not self-identifying.** No version, no named KDF, no named cipher. A reader must infer
   all three from field names, and a second format cannot be introduced unambiguously.
2. **There is no format domain separation.** Nothing distinguishes this format from the legacy
   shape, or from a future one that reuses the same passphrase, salt and iteration count with
   different plaintext framing. (Separating the *stored envelope* from the *recovery kit* is
   deliberately **not** in scope — see §4.2 — because they wrap the same key under different
   passphrases and a swap already fails to decrypt.)
3. **The work factor is unbounded.** A reader attempts whatever integer it is given. For the
   recovery kit, that integer comes from an untrusted file: a value of 2,000,000,000 hangs the tab.
4. **Nothing is validated before use.** Field types, base64 validity and salt/IV/ciphertext lengths
   are all assumed, and malformed input surfaces as an opaque platform exception.

Version 1 fixes exactly those four. It does not change the cryptography: same PBKDF2-SHA256, same
AES-256-GCM, same 600,000 iterations, same 32-byte salt, 12-byte IV and 16-byte tag. **No existing
envelope needs to be rewritten and no key material changes.**

## 3. Evidence: the work factor

Getting this wrong in the strict direction is unrecoverable, so it is derived from evidence.

**Every envelope has been written at 600,000 iterations.** The helper that produces envelopes has
set that value unconditionally since the commit that introduced it, and every distinct version of
the crypto module in this repository's history carries it. The envelope also records its own count
on every writer success path, so no reader has ever had to guess.

The `key_salt` and `key_iterations` fields the registration endpoint accepts are discarded — no
column has ever existed for them — so the JSON blob is the only durable record of the parameters.

Note what *is* rewritten: a passphrase change and a recovery restore both re-encrypt the private key
and replace the stored envelope. What has never happened is a **bulk migration** that rewrites
envelopes at rest. So the set of stored envelopes is not frozen, but nothing has ever moved it off
600,000.

**Measured cost.** PBKDF2-HMAC-SHA256 deriving 256 bits, measured on one modern x86-64 desktop via
Node's WebCrypto. Treat these as a lower bound on real-world cost — a low-end phone is roughly an
order of magnitude slower, and other runtimes differ:

| Iterations | This machine |
|---|---|
| 600,000 | ~0.12 s |
| 1,000,000 | ~0.16 s |
| 4,000,000 | ~0.67 s |
| 10,000,000 | ~1.6 s |
| 20,000,000 | ~3.6 s |

### 3.1 Why there is a ceiling but no policy floor

**Ceiling: `iter` must not exceed 10,000,000.** This is a denial-of-service bound and it is real,
because the recovery kit supplies this value from an untrusted file. Ten million is roughly sixteen
times current policy — enough headroom that raising the policy later needs no reader change, which
is what allows a readers-first rollout — while capping the worst accepted case at seconds here and
tens of seconds on a slow device. It is checked before any derivation, so a hostile value costs
nothing.

**Floor: `iter` must simply be a positive integer. There is deliberately no policy floor.** An
earlier draft of this document set the floor at 600,000. That was wrong, for two independent
reasons:

- **A read-side floor protects nothing.** The envelope is already written. An attacker who rewrites
  a stored envelope with a low iteration count cannot produce a ciphertext that authenticates —
  they do not have the passphrase — so the unlock fails regardless of the floor. Refusing to read a
  weak-but-genuine envelope does not make it stronger.
- **The failure is unrecoverable.** Registration returns `409 Conflict` once a keypair exists, and
  removing the keypair would orphan every vault wrap. A reader that rejects a user's own envelope
  therefore destroys their access permanently, with no self-service path back.

The asymmetry decides it. A permissive floor risks nothing, because the floor was never protecting
anything. A strict floor risks total, irreversible loss of a user's vaults if the historical
evidence is ever incomplete — and this repository's history begins with a squashed import, so it
cannot prove what ran before that point.

Writers emit exactly 600,000. Readers accept any positive integer up to the ceiling. Those are
different numbers on purpose.

**The correct remedy for a weak stored work factor is re-wrapping, not rejection** — at unlock the
browser legitimately holds the plaintext key and could rewrite the envelope at current policy. That
is deliberately *not* specified here: replacing a stored envelope is not yet proof-bound, and adding
an automatic write to the unlock path before it is would exercise an unauthenticated replacement.
It belongs with that work.

## 4. The v1 grammar

A v1 envelope is a JSON **object** with exactly these seven members and no others:

| Field | Type | Value |
|---|---|---|
| `v` | integer | exactly `1` |
| `kdf` | string | exactly `"PBKDF2-SHA256"` |
| `iter` | integer | 1 … 10,000,000 |
| `cipher` | string | exactly `"AES-256-GCM"` |
| `salt` | string | canonical base64 of exactly 32 bytes |
| `iv` | string | canonical base64 of exactly 12 bytes |
| `ct` | string | canonical base64 of ciphertext ‖ 16-byte tag |

- **The IV is its own field.** The legacy format prefixes it to the ciphertext; separating it
  removes offset arithmetic a reader would otherwise have to trust.
- **`ct` carries the tag appended**, as WebCrypto produces it. Decoded length at least 17 bytes and
  at most 8,192.
- **Canonical base64**: standard alphabet, correct padding, no whitespace, no URL-safe variant. A
  string that decodes but is not the canonical encoding of its own bytes is rejected.
- Serialized envelope at most 16,384 bytes.

### 4.1 Writer obligations

Normative, because the re-wrap paths are where these are most likely to be violated:

- Each write MUST draw a **fresh 32-byte salt and a fresh 12-byte IV from a CSPRNG**.
- An IV MUST NOT be reused under a derived key.
- A re-wrap — passphrase change, recovery export, recovery restore — MUST NOT carry the previous
  salt or IV forward, even though the old values are in hand at that moment.

This is not boilerplate. The plaintext is a PKCS#8 PEM with a fixed armour prefix and trailer and
highly predictable structure. Two ciphertexts under one key and IV yield the XOR of two nearly
identical known-format plaintexts and also expose the GHASH subkey, which permits tag forgery.

### 4.2 The authenticated transcript

AES-GCM additional authenticated data is the UTF-8 encoding of exactly:

```
dockvault-private-key-envelope-v1|PBKDF2-SHA256|<iter>|AES-256-GCM|<salt>
```

`<iter>` is the decimal integer, no padding or separators. `<salt>` is the canonical base64 string
exactly as it appears in the envelope. Note that `v` is **not** interpolated: the leading label
already carries the version, and `v` is validated to exactly `1` before this string is built.

**What this does and does not buy, stated precisely.** The AAD provides *version and format domain
separation*. It does not add substitution resistance for `iter` or `salt`: both are PBKDF2 inputs,
so a tampered value already produces a different key and a failing tag. It does not police `kdf` or
`cipher` either — those are validated to single fixed values before use and appear in the
transcript as constants.

What it genuinely adds is that a v1 ciphertext cannot be repackaged into the legacy shape of §5,
which derives the same key from the same salt and iterations but authenticates no AAD, and that a
future version sharing passphrase, salt and iteration count but differing in plaintext framing
cannot be cross-decrypted.

The cheap-rejection property a reader needs comes from the pre-derivation checks in §3.1 and §7,
**not** from the AAD. An implementer must not read this section as licence to drop those checks.

Because the transcript is a new byte-exactness surface, any drift in how it is constructed — a
stray space, a different delimiter, salt bytes rather than the salt string, a locale-dependent
integer rendering — would render affected envelopes permanently unreadable. The implementation must
therefore pin a v1 fixture reproduced independently by both reference implementations, as the
existing pinned formats already are.

### 4.3 Deriving the key

```
K = PBKDF2-HMAC-SHA256(passphrase_utf8, salt, iter, dkLen = 32)
plaintext = AES-256-GCM-Decrypt(key = K, iv = iv, aad = transcript, input = ct)
```

The plaintext is the PKCS#8 PEM text of the P-384 private key exactly as the browser formats it:
the `-----BEGIN PRIVATE KEY-----` armour line, base64 body wrapped at 64 characters (the final body
line being shorter), the `-----END PRIVATE KEY-----` armour line, joined with `\n` and with no
trailing newline.

## 5. Legacy acceptance and dispatch

Readers accept **both** formats. Dispatch is by shape, in this order:

1. Not a JSON object, or an array, or `null` → reject.
2. Has a `v` member → v1. `v` must be exactly `1`; any other value is an unknown version and is
   rejected rather than guessed at.
3. Otherwise, has `encrypted` and `salt` → legacy: `encrypted` is base64 of
   `iv12 ‖ ciphertext ‖ tag16`, `salt` is base64 of 32 bytes, `iterations` is optional and defaults
   to 600,000 when absent. No AAD.
4. Otherwise → reject.

**Legacy parsing stays exactly as permissive as it is today**, with two additions, both
denial-of-service bounds that apply to any envelope because any envelope may arrive from an
untrusted file: the `iter` ceiling of §3.1, and the 16,384-byte serialized cap. Neither can reject
a genuine legacy envelope — real ones carry 600,000 iterations and serialize to 534 bytes.

Everything else — canonical-base64 strictness, the v1 field set, and the salt, IV and ciphertext
length rules — applies to **v1 only**. §7 states the scoping rule by rule. Tightening decoding on a
format that is already deployed can only reject envelopes that currently work; there is nothing to
gain and a user's vault access to lose.

**Legacy remains writable for initial registration during the compatibility window.** Stale browser
tabs still produce it, and refusing it would break first-key registration for a client that is
merely out of date. Official clients write v1 once that writer is enabled.

**Downgrade of an existing envelope is deliberately not solved here.** A session can replace the
stored blob, so nothing in this format prevents a replacement being written in the legacy shape.
Proof-bound replacement is separate, later work. This document claims only that a v1 envelope
cannot be *misparsed* as legacy or the reverse.

## 6. Key-consistency check

Decrypting successfully proves the passphrase was right. It does not prove the recovered key is
*the account's* key — and today the normal unlock path does not check, so any structurally valid
P-384 private key unlocks without complaint.

After decrypting and before caching anything, the client:

1. imports the recovered PKCS#8 private key;
2. obtains its public point — WebCrypto cannot derive a public key from a private key directly, so
   this is done by exporting the imported key as JWK, removing the private component `d`, and
   re-importing the remainder as a public key;
3. exports both that key and the account's registered public key as **raw uncompressed P-384
   points** — 97 bytes, `0x04 ‖ X(48) ‖ Y(48)`;
4. compares those byte strings.

An ordinary comparison is correct here. Both operands are public keys, so there is no secret for a
timing difference to leak, and a constant-time guarantee is not reliably achievable in JavaScript
anyway. Demanding one would be cargo-cult precision that an implementer cannot honour.

Exporting to a raw point is what makes the comparison canonical: it normalises away PEM line
wrapping, whitespace, trailing newlines, base64 padding and SPKI header encoding, none of which are
key material. A PEM string comparison would report a mismatch between two encodings of the same key.

Step 2 requires importing the private key as extractable. That is acceptable because the plaintext
PEM is already in the caller's hands at this point, but it must not be treated as licence to keep
an extractable handle: the extractable import is used for this check and discarded.

**Where the registered public key comes from, and what if it is missing.** It is the account public
key the server returns alongside the envelope. If it is absent, unparseable, or not a P-384 point,
the check cannot be performed — and the operation **fails closed**: no private key, no derived key
and no vault key is cached. Treating "cannot check" as "check passed" would make the whole section
optional in exactly the circumstances an attacker controls.

For the **recovery kit**, the registered public key is likewise the account's, obtained from the
server during restore.

On mismatch: nothing is cached and the operation fails.

**The limit, stated plainly.** This proves the recovered private key is consistent with the public
key *the server returned*. It does not defend against a server that substitutes both halves at
once. Defeating that requires the client to hold an independent notion of the account's identity,
which it does not. The actor this check does defeat is anyone who can alter the stored envelope but
not the registered public key — including database-level tampering and a mixed-up or transplanted
envelope.

## 7. Validation and error behaviour

All shape, type, encoding, length and policy checks happen **before** any key derivation, so
malformed input is rejected at negligible cost. They also happen before the user is asked for a
passphrase where the flow allows it, so a corrupt recovery kit fails immediately rather than after
a prompt.

**Every rule below is scoped to a format. An unscoped checklist is precisely how legacy gets
tightened by accident, and tightening legacy can only reject envelopes that work today.**

| Rule | v1 | Legacy |
|---|---|---|
| Not a JSON object, or an array, or `null` | reject | reject |
| Serialized envelope over 16,384 bytes | reject | reject |
| Work factor above the §3.1 ceiling | reject | reject |
| Work factor not a positive integer | reject | **accept** — see below |
| Missing, extra or wrong-typed member | reject | not applied |
| Unknown `v`, `kdf` or `cipher` | reject | n/a |
| Non-canonical or invalid base64 | reject | not applied |
| Salt not exactly 32 decoded bytes | reject | not applied |
| IV not exactly 12 decoded bytes | reject | n/a — legacy has no `iv` member |
| `ct` outside 17 … 8,192 decoded bytes | reject | not applied |
| Authentication failure | reject | reject |

Two entries need their reasoning stated, because both look like oversights and are not:

- **The two size bounds apply to both shapes.** They are denial-of-service bounds of the same kind
  as the ceiling, and §3.1's argument — that any envelope may arrive from an untrusted file —
  applies to a hostile kit in the legacy shape just as much as a v1 one. They are also provably
  safe to extend: a genuine legacy envelope serializes to 534 bytes, so a 16,384-byte cap
  has around thirty times the headroom and cannot reject a real one.
- **Legacy keeps today's lenient handling of a non-integer `iterations`.** Today's reader coerces
  it and falls back to 600,000 when it is absent or unusable. Rejecting instead would be a new
  failure mode on already-deployed data, for no gain — the ceiling already bounds the expensive
  direction, and a nonsense value simply derives the wrong key and fails authentication.

Everything not listed as applying to legacy is **v1 only**. Legacy parsing is otherwise exactly as
permissive as it is today, per §5.

Errors identify **which rule** failed, never the value that failed it, and no message, thrown value
or console output composed by this code includes envelope bytes, ciphertext, salt, IV, passphrase or
PEM text. The honest limit: platform exceptions from the underlying crypto and JSON implementations
are not authored here, so the contract is that this code does not *add* material to an error and
does not pass a raw platform exception through to the user interface — not that no underlying
runtime can ever produce a diagnostic of its own.

Wrong passphrase and corrupt ciphertext are both authentication failures and are reported
identically. A key-consistency mismatch (§6) is a distinct, third outcome and is reported as such:
it is not a passphrase problem, and telling the user it is would send them to the wrong remedy.

## 8. Compatibility summary

| Concern | Behaviour |
|---|---|
| Existing envelopes | Still read. Nothing is rewritten or migrated. The only new rejection applied to them is the `iter` ceiling, which no genuine envelope approaches. |
| Existing key material | Unchanged. The keypair, its registration and every vault wrap are untouched. |
| Server | Unaffected. Stores and returns an opaque string, as before, with no validation added. |
| Older clients | Read legacy, as always. They cannot read v1. |
| Newer clients | Read both. Write v1 **only once the writer is enabled** — see §8.1. |

### 8.1 Rollout, and the rollback trap

**A v1 envelope cannot be read by a client that predates this document.** That is inherent to
introducing a format, and it is why the writer ships behind a gate that is off by default and is
enabled as a separate, recorded decision rather than by merging code.

For a self-hosted product the realistic lockout is not a stale tab — it is **an operator rolling the
image back**. Once any client has written a v1 envelope, downgrading the deployment to an image
whose reader predates v1 makes that envelope unreadable, and because registration is refused when a
keypair exists there is no self-service recovery. Deploying readers everywhere first is what makes
the *forward* step safe; it does nothing for the backward one.

Therefore: enabling the v1 writer is a **forward-only** decision for a deployment. The operator
documentation must say so at the point of enabling, and the gate must not be enabled by default in
any release that an operator might roll back across.

## 9. Out of scope

- Changing the KDF, the cipher, or the iteration count. Same primitives, same cost.
- Proof-bound replacement of a stored envelope, and re-wrapping a weak envelope at unlock.
- Any defence against an operator serving modified client code.
- Any server-side parsing or validation of the envelope. The server stays format-agnostic.
