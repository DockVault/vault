# Client crypto failure contract, version 1

Status: **frozen for implementation**. Written and reviewed before the client changes, so the code
set, what each code may and may not be used for, and the diagnostics rules are fixed before any
call site depends on them.

## 1. The problem

Every failure the browser crypto module can produce is currently a bare `Error` carrying a
human-readable sentence. Two consequences follow, and both are already visible in shipped code.

**The interface cannot tell failures apart, so it guesses — and one guess recommends a destructive
action the server refuses.** Unlocking a private key parses the envelope inside `catch (_)` and
rethrows *"Stored encryption key is incomplete or corrupt — re-register your key."* That one
sentence is produced when the envelope is not JSON, when it parses but declares a version this
build does not implement, and when it is genuinely corrupt.

For the middle case the advice is actively harmful. The envelope is fine; the build is old.
Re-registration is refused — `POST /ecc/keys/register` returns `409 Conflict` while a keypair
exists — and if it somehow succeeded it would orphan every wrapped vault key, because there is no
key rotation. So the interface tells the user to do something that cannot work, in the one
situation where doing nothing and upgrading is the correct answer.

File decryption is worse served still. `downloadFile` renders *"Failed to decrypt file: "* plus
whatever the module said. The passphrase has already succeeded by then — the private key unlocked,
the vault key unwrapped — so a damaged file is not a passphrase problem, and must never be
presented as one.

**Diagnostics leak the platform, unconditionally.** The module makes 31 `console` calls, of which 3
are gated behind its existing `DEBUG` flag, leaving **28 running in production**. Those include
`console.error('❌ … failed:', error)`, which prints the raw platform exception. **13** throw sites
interpolate `${error.message}` into the message the user is shown. Six further `console.error(…, e)`
calls on zero-knowledge paths live in the application file rather than the module.

## 2. Scope

**The contract covers every rejection the module's public API can produce — not merely its `throw`
statements.** This distinction is the single most important thing in this document, because most
of the module has no `try` at all: key derivation, PEM point extraction, DEK wrapping, both proof
computations, name encryption and decryption, and blind indexing all reject with a raw
`DOMException` or `TypeError`. A contract written only over `throw` sites would leave the majority
of real failures uncoded.

Two places deserve naming because they defeat the obvious reading:

- **Legacy envelope base64 is decoded with bare `atob`.** The strict base64 helper is v1-only by
  design. A legacy envelope with malformed base64 therefore escapes envelope parsing as an
  `InvalidCharacterError` — so `ENVELOPE_INVALID` is *not* currently raised for one of the cases it
  exists for.
- **Key derivation inside private-envelope decryption sits outside that method's `try`.** A failure
  there is not an authentication failure and must not be reported as one.

Every public method needs a boundary that converts a non-`CryptoError` rejection into one.

**Not in scope:** any format, protocol, ciphertext, or server behaviour. This changes how failures
are *described*, never whether an operation succeeds. Every envelope readable before is readable
after. No endpoint, status code, or response body changes.

## 3. The codes

Stable `SCREAMING_SNAKE` strings — they appear in logs a human reads, and a grep for them cannot
collide with prose.

| Code | Means | Remedy it implies |
|---|---|---|
| `CRYPTO_UNAVAILABLE` | No usable WebCrypto. | Use a supported browser over a secure origin. |
| `ENVELOPE_INVALID` | Not structurally an envelope this build accepts. | The stored key is damaged; restore from a recovery kit. |
| `ENVELOPE_UNSUPPORTED` | Structurally valid, declares something unimplemented here. | Upgrade this deployment. **Do not re-register.** |
| `WORK_FACTOR_REJECTED` | Declared KDF work factor outside the accepted range. | Refuse; possibly hostile input. |
| `AUTH_FAILED` | Authenticated decryption of a **passphrase-derived** key failed. | Re-enter the passphrase. |
| `CONTENT_AUTH_FAILED` | Authenticated decryption of **vault-key-encrypted content** failed. | The item is damaged. **Not a passphrase problem.** |
| `KEY_UNUSABLE` | Key material could not be imported, parsed, or derived. | The key is malformed. |
| `KEY_MISMATCH` | Key does not match the account it was compared against. | This key belongs to a different account. |
| `WRAP_FAILED` | Wrapping or unwrapping a data key failed. | The vault-key grant is damaged. |
| `RECOVERY_KIT_INVALID` | The supplied file is not a well-formed recovery kit. | Wrong or damaged file. |
| `RECOVERY_KIT_UNSUPPORTED` | A well-formed kit of a version this build does not implement. | Upgrade this deployment. |
| `INVALID_INPUT` | The caller passed something the operation cannot use. | A programming error. |
| `CRYPTO_OPERATION_FAILED` | A WebCrypto primitive rejected for a reason that is not authentication, not policy, and not input. | Unexpected; report it. |

Thirteen codes for eight required categories, because the required list is a minimum and because
each code above implies a **different action by the user**. That is the admission test: two
failures share a code only when no user could act differently on them.

Three rules the set exists to enforce:

**`AUTH_FAILED` covers both a wrong passphrase and tampered ciphertext, and that is not a policy
choice.** AES-GCM authentication fails identically for a key derived from the wrong passphrase and
for altered bytes. The distinction does not exist to be reported, and any future code claiming to
separate them would be lying.

**`CONTENT_AUTH_FAILED` is separate from `AUTH_FAILED` because the user supplied no secret.** By
the time content is decrypted the passphrase has already succeeded. A code raised by an operation
the user supplied no secret to must never be rendered as a passphrase failure. This is a rule about
*every* code, not only this one.

**`ENVELOPE_UNSUPPORTED`, `KEY_UNUSABLE` and `KEY_MISMATCH` must never be reported as
`AUTH_FAILED`.** These are the cases current code mislabels. `KEY_UNUSABLE` and `KEY_MISMATCH` are
kept apart because they send the user to different remedies, a distinction the recovery-restore
path already makes deliberately in prose and which must survive into the code channel.

The set is closed for v1. Adding a code is a change to this document first.

### 3.1 Two exclusions

**Transport failures never get a crypto code.** Point decompression calls a server endpoint and
throws on a non-OK status. That endpoint is authenticated and rate-limited, so a 429 or 403 would
otherwise arrive dressed as a crypto failure. A transport failure inside the crypto module stays a
transport failure.

**No code may be raised from a server response field.** In particular, *"this recipient has no
encryption key"* is decided by reading `has_keypair` from a response. The server deliberately
guards that endpoint against key-existence enumeration — it is gated on managing a vault and rate
limited. Turning its answer into a stable machine-readable code would rebuild the oracle the server
is defending, on the client, which is this phase's stop condition. It stays an application-level
message with no code.

## 4. The error type

```js
class CryptoError extends Error {
    constructor(code, operation, cause) { … }
}
```

- `code` — one of §3, taken from a frozen exported constant set, never a bare string literal at a
  call site. A typo in a literal becomes an unrecognised code and silently takes the §5 fallback; a
  constant makes it a reference error. A test enumerates the codes used in application code against
  the exported set.
- `operation` — a short stable label for *where* it happened. Diagnostics only; never branch on it.
  Labels must not be bare method names: an existing test asserts that certain method names do not
  appear outside their defining function, and a label reusing one would fail it for an unrelated
  reason.
- `cause` — the original platform exception, when there was one. Retained on the object, rendered
  only in debug mode.
- `message` — **`CryptoError(<CODE>@<operation>)`**, deliberately shaped so it cannot be mistaken
  for a sentence. If it ever reaches a user, that reads as a bug rather than as plausible advice.

`instanceof` is not the branching mechanism. The module is loaded as a classic script in the
browser and via `require` in seven Node harnesses; `.code` is the only property that survives both.
For the same reason `module.exports = ECCCryptoLibrary` is preserved unchanged — the error class
and the code set hang off the class, so `require` and the classic-script global see one shape.

The existing note at private-envelope decryption, that the platform exception "is not ours to vouch
for" and is not propagated, is superseded here: the cause is retained on the object but is not
rendered outside debug mode, which serves the same intent without discarding the diagnostic.

## 5. How call sites use it

Branch on `.code`, from the constant set. Never on `.message`, and never on a substring of it.

**One seam owns user-facing wording:** a single `safeMessageForCode(code, flow)` function. The
interface calls it; individual `catch` blocks do not invent sentences. A code may legitimately
produce different wording in different flows — `AUTH_FAILED` during a passphrase change speaks of
the *current* passphrase, the same code during a recovery restore speaks of the *recovery*
passphrase — which is why the flow is a parameter. Without this seam the phase's required
"UI message selection" test has nothing to target.

**No generic handler may render `.message` when `.code` is present.** This is the rule that keeps
`message` from reaching users, and it has to be stated because several handlers do exactly that
today: the unlock handler, the file-download and preview handlers, three "zero-knowledge encryption
failed" handlers, and the four catch-alls for setup, passphrase change, recovery export and
recovery restore. All are in scope for this phase.

**An error with no `.code`, or a `.code` this build does not recognise, is an unexpected failure.**
Show the flow's generic failure sentence, log `operation` and `code || 'UNCODED'`, and **never fall
back to a passphrase prompt.** Uncoded is the common case during migration, so this path must
degrade safely rather than guess. Guessing is how an unsupported envelope became "wrong passphrase"
in the first place.

**Cancellation is not an error code.** Several flows signal user cancellation as a thrown sentence
and match it by substring. That is application control flow, not a crypto failure; it keeps its
current handling and gets no code. Coding it without converting every matching site would turn
every user cancel into an error toast.

**A swallow-all catch must still surface `CRYPTO_UNAVAILABLE`.** Listing-name decryption currently
absorbs every per-row failure into a placeholder label, which would hide a browser with no
WebCrypto behind an entire directory of "encrypted name" rows.

## 6. Diagnostics

Production console output may contain **the operation and the code, and nothing else** — no raw
platform exception, no envelope bytes, no key material, no passphrase, no ciphertext, no account
identifier.

**This rule applies to every console call on a crypto path, in the module and in the application
file alike.** The six `console.error(…, e)` calls on zero-knowledge paths in the application are in
scope: developer tools expand an error's `cause`, so retaining the cause plus logging the whole
object puts the platform exception in the production console by another route.

The raw cause is available only when the module's debug flag is on. That flag is a source constant,
off by default, like the versioned-writer gate — enabling verbose diagnostics is a deliberate,
reviewable change, not something a query parameter can switch on in a deployment. **A test pins it
off**, as one already pins the writer gate; an unpinned default is one careless edit from shipping
enabled.

Success traces are removed rather than gated, including the three already behind the flag. They run
on every operation, and each is a place a future edit can append something sensitive.

## 7. Oracles: what is safe, and why

The stop condition for this work is that no stable distinction may expose a server-side account or
key existence oracle. The naive argument — *every code is decided in the browser from bytes the
caller already has* — is **not true as stated**, and the two exceptions matter more than the rule.

**Where it does hold.** The account envelope is fetched by its authenticated owner and by no one
else, so telling that owner why their own envelope failed reveals nothing they could not determine
by reading it. The recovery kit is a file the caller supplied, already carrying its account id,
fingerprint and public key in cleartext; distinguishing "unsupported version" from "wrong
passphrase" on a file the attacker chose tells them only what they already know about their own
file. `CRYPTO_UNAVAILABLE` is a property of the browser.

**Where it does not, and why each is still acceptable:**

- **`KEY_MISMATCH` is evaluated against a server-supplied public key** — the one returned by the
  account's own public-key endpoint. It is acceptable because that key is the caller's own
  registered key, which that caller may already read; the comparison discloses nothing new. It is
  not acceptable to extend this to *another* account's key.
- **Point decompression consults the server.** Excluded from the code set entirely by §3.1, so a
  rate-limit or authorization response can never surface as a crypto code.

**The prohibition that keeps this true** is §3.1's second exclusion: no code may be derived from a
server response field. The recipient-has-no-key branch is the concrete case, and it is exactly the
one the server rate-limits. Any future code must be tested against that rule before being added.

Server-side error surfaces are unchanged, including the deliberately neutral proof-failure
response, whose distinctness rules live in `vault-private-key-update-pop-v1.md` §8.

## 8. Relationship to the envelope contract

`vault-private-key-envelope-v1.md` §7 commits to errors that *"identify which rule failed, never
the value that failed it"*, and tabulates roughly a dozen distinct v1 validation rules. Under this
contract all of them map to `ENVELOPE_INVALID`, `ENVELOPE_UNSUPPORTED` or `WORK_FACTOR_REJECTED`.

That is deliberate, and the two documents are reconciled as follows: **rule identity survives as
the debug-only diagnostic; the code channel is coarser on purpose, because no caller can act on
rule identity.** Knowing the initialisation vector was the wrong length rather than the salt
changes nothing a user or a call site would do. The envelope document's sentence is amended in the
same change to say so, rather than being left to contradict this one — a test already pins
document-to-code agreement there, and silent inter-document drift is a live failure mode here.

One consequence for implementation: the v1 work-factor check currently raises a single error for
three conditions — non-integer, below one, and above the ceiling. Only the last is
`WORK_FACTOR_REJECTED`; the first two are `ENVELOPE_INVALID`, so that condition must be split.
Existing tests already exercise all three.

Similarly, an availability probe must run **before** any operation that can raise `AUTH_FAILED`.
Private-envelope decryption currently maps every exception from the decrypt call to authentication
failure, so a present-but-unusable algorithm would be reported as a wrong passphrase — the very
mislabeling this phase removes. A single private accessor for `crypto.subtle`, raising
`CRYPTO_UNAVAILABLE`, gives every operation that guard and is also the only way to make
`CRYPTO_UNAVAILABLE` reachable in a test at all.

## 9. What this does and does not defend against

**Does:** a user destroying a good envelope, or attempting a refused re-registration, because the
interface told them the wrong thing. A deployment printing platform internals into a console that
support staff or a bug reporter will copy. A future call site branching on a sentence a later edit
rewords.

**Does not:** anything about an attacker who already holds the envelope bytes. This is a
correctness and diagnostics contract, not a confidentiality boundary. An attacker in possession of
an envelope learns its version and work factor by reading it; that is inherent to a self-describing
format and is accepted in `vault-private-key-envelope-v1.md`.

## 10. Out of scope

- Server-side error taxonomy.
- Localisation of user-facing sentences.
- The three `error.message.includes(...)` branches **in the vault-file listing loader**. Verified:
  no crypto error can reach that catch — the only crypto call in its `try` handles every error
  internally and never rethrows — so they read HTTP errors only. They are the same anti-pattern and
  worth fixing, but they are not this contract's surface. **Other message-rendering sites in the
  file and folder interface are in scope** and are listed in §5.

## 11. Note for the test harnesses

Both Node harnesses replace `console` with a silent stub. A console-sentinel test that reuses them
unchanged passes vacuously and proves nothing. Such a test must install its own capturing console.
