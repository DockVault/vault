# Zero-knowledge envelope family, version 2

Status: **reviewed. Every construction in this document is implementable.** The team wraps were
blocked in the first revision; §11.1 records the decision that unblocked them, and what it
deliberately leaves unsolved.

Two independent reviews are folded in. They found largely different problems, and on one question
they reached opposite conclusions. §12 records that disagreement and how it was settled, because
the losing recommendation would have caused permanent data loss.

## 1. What binds nothing today

Four constructions carry zero-knowledge material. Read from the shipped source and confirmed
independently by both reviews:

| Construction | Key agreement | Key derivation | Cipher | Binds |
|---|---|---|---|---|
| Direct DEK wrap | ECDH P-384 | HKDF-SHA256, empty salt, info `vault-key-wrapping` | AES-KW | recipient key |
| Team **DEK** wrap | *the same function* | *the same* | AES-KW | recipient key |
| Team **private-key** wrap | ECDH P-384 | HKDF-SHA256, empty salt, info `team-privkey-wrapping-v1` | AES-GCM | recipient key |
| File content | — | — | AES-GCM, random IV, **no AAD** | nothing |

**A wrap says who may open it and nothing about what it is.** ECDH binds the recipient's key. There
is no version, purpose, vault, DEK epoch, or recipient identifier. Everything deciding *which* wrap
the client is handed is server-selected routing the ciphertext does not commit to.

**The team-DEK wrap and the direct wrap are the same function.** Byte-indistinguishable, and both
read back through one `unwrapVaultDEK`. A wrap minted for one role can be served in the other's
place and no reader can tell.

**That confusion has an exact server-side twin, and v2 as first drafted fixed only the client
half.** Direct and team-private rows share one `vault_member_keys` table and are separated *only*
by a server-writable `String(50)`, `wrapping_algorithm` — which is also a filter in the stale-key
prune's `db.delete`. A wrapped **team private key** is even stored in a column named `wrapped_dek`.
§6.4 addresses this; it is the reason this document has a §6.4 at all.

**Content binds nothing.** `IV || ciphertext||tag`, portable between objects, vaults and epochs for
anyone holding the DEK, with no authenticated statement of length, ordering or completeness.

## 2. Scope

**In:** the byte grammar for direct DEK wraps, team-private wraps, team-DEK wraps, and chunk-framed
content; how a reader tells v2 from legacy; what a reader does with anything else.

**Out:** transport, authorization, and `zk2:` object-bound names, which stay as they are. Streaming
and memory behaviour are deliberately left to later work, which must emit and consume
**byte-identical** v2 envelopes —
a constraint that decided §7.4's shape.

**Not a migration.** Existing envelopes are never rewritten. There is no server-side conversion,
because the server cannot read any of this and a migration that could damage opaque bytes is a
stop-condition for the phase.

## 3. The constraint that shapes everything

**AES-KW has no associated-data channel.** A wrap built on it can bind context only through the
HKDF `info` that derives the wrapping key. AES-GCM has an AAD and can bind context in a form a
reviewer reads off the wire.

v2 therefore uses **AES-256-GCM with a 128-bit tag** for every construction, including the DEK
wraps that use AES-KW today. **No server code performs AES-KW (RFC 3394) and the server never
unwraps zero-knowledge material** — verified by search and already enforced by a static guard test.
(The server does perform an unrelated Fernet credential unwrap at boot; that is not this.)

Two consequences of the switch that are easy to miss:

- The cross-implementation test oracle **does** contain a Python AES-KW codec. Moving to GCM
  requires a v2 codec there and new pinned vectors; it is not client-only work.
- **AES-KW was silently enforcing a length.** A 40-byte AES-KW input can only unwrap to a 32-byte
  key. AES-GCM returns whatever length it was given, so §7.1 and §7.2 must reject an unwrapped DEK
  that is not exactly 32 bytes before importing it — otherwise a writer bug or a database-level
  adversary can hand a reader a 16-byte "DEK" that `importKey` will accept as AES-128.

## 4. Shared conventions

### 4.1 Canonical encoding

- **UUIDs** — lowercase hyphenated ASCII, exactly 36 bytes. Never raw 16-byte form.
- **Integers** — unsigned big-endian; **4 bytes** for every epoch field, 8 bytes where stated. The
  backing columns are signed 32-bit, so a writer MUST reject anything outside `1 .. 2^31 - 1`
  rather than encode it: `struct.pack('>I', -1)` raises in Python while `DataView.setUint32(-1)`
  writes `0xFFFFFFFF`, and that divergence is a permanently unreadable wrap.
- **Labels** — ASCII, lowercase, hyphen-separated.
- **Concatenation** — single `0x00` separator, field order fixed per construction.
  **Injectivity comes from fixed widths alone.** The separators are decoration, not delimiters: the
  integer encoding is not `0x00`-free (`dek_epoch = 1` is `00 00 00 01`), so no parser can split on
  them. Any future variable-width field therefore needs an explicit length prefix.

This rule governs **v2 transcripts only.** The shipped `zk2:` name AAD uses pipe-separated text with
a decimal epoch; §2 scopes it out and this rule does not retrofit it.

Note also that this product already contains a chunk-framing grammar — the Standard-vault GCM
stream — which uses **raw 16-byte UUIDs**, the opposite convention. Two grammars with opposite
conventions is a footgun; the divergence is deliberate (that format is not zero-knowledge and is
pinned by its own fixtures) and is recorded here so an implementer of both readers is not surprised.

### 4.2 Domain separation

Distinct `info` prefixes, not a shared prefix plus a discriminator, so a truncation in one cannot
produce another's transcript:

```
dockvault-zk-dek-direct-v2
dockvault-zk-dek-team-v2
dockvault-zk-teampriv-v2
dockvault-zk-content-v2
```

### 4.3 HKDF

`HKDF-SHA256`, salt = the 32-byte ASCII label `dockvault-zk-envelope-v2-salt-01`, `info` per
construction. A fixed non-secret salt at Extract with per-construction context at Expand is the
conventional RFC 5869 split. The ephemeral public key is **not** in the salt: the shared secret
already depends on it, and NIST SP 800-56A places ephemeral keys in FixedInfo, not the Extract salt.

### 4.4 Ephemeral key validation

Every ephemeral public key is server-supplied and is fed into ECDH against a **long-term** private
key. A reader MUST validate it as a 97-byte X9.62 uncompressed point on P-384 and reject otherwise.
P-384 has cofactor 1, so on-curve validation is sufficient. This is normative because this document
is what a third implementation will be written from; the shipped runtimes happen to validate, and
an implementation that did not would leak the recipient's private key to repeated queries.

A fresh ephemeral keypair MUST be minted for every wrap. Each wrapping key then encrypts exactly one
message, so the wrap nonce budget is a non-issue.

## 5. Both channels

Every v2 construction binds its context twice: in the HKDF `info` and in the AEAD's AAD.

- **The AAD is the readable one** — a reviewer and a test can see what a ciphertext claims.
- **The `info` is the one that survives a mistake** — if an AAD is ever passed inconsistently, the
  derived key still differs per context, so the failure is a decryption failure rather than a
  silent cross-context accept.

They must carry the same values, which is enforceable only if one function builds both. A reader
cannot *distinguish* an `info` mismatch from an AAD mismatch — both are authentication failures —
so the auditability benefit accrues to reviewers and tests, not to runtime error handling.

## 6. Discrimination and downgrade

### 6.1 The header

```
offset 0   4 bytes   magic     "DVZ2"
offset 4   1 byte    version   0x02
offset 5   1 byte    purpose   0x01 direct DEK | 0x02 team DEK | 0x03 team private | 0x04 content
offset 6   2 bytes   reserved  0x0000, MUST be zero
```

Covered by the AAD, so the purpose byte cannot be rewritten to steer a payload into another reader.

There is deliberately **no cipher-suite field**: every choice (P-384, HKDF-SHA256, AES-256-GCM,
12-byte nonce, 128-bit tag) is implicit in `version`. A suite change is a version bump, not a
negotiation. The reserved bytes are a **breaking-change** channel, not an extension channel — the
strict-reject rule makes any future use invisible to old readers, which is the intent.

### 6.2 Telling v2 from legacy

A **v2 DEK wrap is exactly 68 bytes** (8 header + 12 nonce + 32 DEK + 16 tag) and a legacy one is
exactly 40 (RFC 3394 over a 32-byte key). Both are fixed, so the reader dispatches on length and
rejects any other length before parsing.

For team-private wraps and content there is no such length rule, and discrimination is magic-only:
a legacy payload whose random IV begins with `DVZ2` (p = 2⁻³²) would be dispatched to the v2 reader.
To keep that from becoming unrecoverable loss, **"is v2" requires the whole header to validate** —
magic, `version == 0x02`, a known `purpose`, `reserved == 0`, and for content a `chunk_size` in
range and a total length consistent with the framing. Only a payload passing all of that is
committed to the v2 path.

### 6.3 Downgrade

- A payload that **commits** to v2 by §6.2 and then fails its tag **fails closed**. It is not
  retried as legacy; retrying is what turns a tampering signal into a parser oracle.
- A payload with the magic but a structural failure (unknown version or purpose, non-zero reserved)
  is rejected as *unsupported*, distinguishably from *damaged* — see §6.5, which is a hard
  precondition rather than an aspiration.
- A **legacy reader must reject a v2 payload** rather than interpret the header as ciphertext.

### 6.4 The server's `wrapping_algorithm` column is load-bearing, and v2 must not break it

The first draft called this column decorative. It is not:

- It is the **only** discriminator separating direct-DEK rows from team-private rows in the shared
  `vault_member_keys` table, and every hierarchical query filters on it.
- The rekey path **re-stamps** it when carrying rows to a new epoch.
- The stale-key prune selects rows by `(wrapping_algorithm, key_version)` and **deletes** them.

So a v2 writer that changes the label would stop the prune matching v2 rows, and **a revoked
member's stale-epoch wrap would survive pruning** — a security regression introduced by the fix. A
v2 writer that keeps the label leaves the column permanently lying.

**Requirement:** v2 introduces new labels (`ECDH-P384-AES-GCM-DIRECT-V2`,
`ECDH-P384-AES-GCM-TEAMPRIV-V2`), and the server-side queries and prune filters must be widened to
match both generations **before** any v2 writer ships. That is a server change, so it does not
follow the readers-before-writers ordering in §10 — it must land first, on its own.

The column still must **never be trusted for parsing**. It is routing metadata the server can
rewrite; the authenticated header is the discriminator.

### 6.5 The error contract must be amended first

§6.3 needs an *unsupported* outcome distinguishable from *damaged*. That distinction exists in
`vault-client-crypto-errors-v1.md` — but its codes are **envelope-scoped**: `ENVELOPE_UNSUPPORTED`
speaks about the account's stored key ("saved by a newer version… do not re-register your key"),
and content has exactly one code, `CONTENT_AUTH_FAILED`, whose message says the item is damaged.

So a v2 content payload met by a reader that does not implement it would today be reported as a
**damaged file** — precisely the mislabel that contract was written to eliminate. That contract is
explicitly closed ("adding a code is a change to this document first"), so:

**Precondition, before any v2 writer or reader ships:** amend `vault-client-crypto-errors-v1.md` to add content- and
wrap-scoped *unsupported* and *structural* codes, with wording that tells the operator to update
rather than that their data is damaged.

## 7. The constructions

### 7.1 Direct DEK wrap — purpose `0x01`

```
shared   = ECDH(ephemeral_priv, recipient_account_pub)                    384 bits
info     = "dockvault-zk-dek-direct-v2" 0x00 vault_id 0x00 recipient_user_id 0x00 dek_epoch
key      = HKDF-SHA256(shared, salt §4.3, info)                           32 bytes
aad      = header || vault_id 0x00 recipient_user_id 0x00 dek_epoch
payload  = header || nonce(12) || AES-256-GCM(key, nonce, DEK, aad)       exactly 68 bytes
```

**`dek_epoch` is `vault_member_keys.key_version`** (equal to `vaults.dek_version`). It is
**not** `vaults.key_version`, which is the Standard-vault Fernet counter and unrelated. The
codebase has seven `*version` columns and four could plausibly be meant; binding the wrong one
mints wraps that are permanently unreadable and fail as authentication errors indistinguishable
from tampering.

The reader MUST reject an unwrapped plaintext that is not exactly 32 bytes (§3).

**On `recipient_user_id`:** ECDH already binds the recipient, so this field adds little. Its one
real benefit is distinguishing two accounts that share key material — a recovery kit imported into
a second account. Against a lying server it is **self-DoS only**, not a confidentiality control,
because a wrap for Alice served to Bob still needs Alice's private key. The load-bearing bindings
here are `vault_id`, the epoch, and the purpose byte. The reader takes the id from the authenticated
session; the API should echo the account id the row was selected for, so the reader does not have to
reason about boot ordering to satisfy this sentence.

### 7.2 Team DEK wrap — purpose `0x02`

```
shared   = ECDH(ephemeral_priv, vault_team_pub)                           384 bits
info     = "dockvault-zk-dek-team-v2" 0x00 vault_id
key      = HKDF-SHA256(shared, salt §4.3, info)                           32 bytes
aad      = header || vault_id
payload  = header || nonce(12) || AES-256-GCM(key, nonce, DEK, aad)       exactly 68 bytes
```

The reader MUST reject an unwrapped plaintext that is not exactly 32 bytes (§3), and dispatches on
the same fixed 68-byte length as §7.1.

**There is no recipient field, and that is not an omission.** This wrap's recipient *is* the vault's
team keypair, which ECDH already binds — there is no per-user choice to record. One wrap serves every
member, which is the whole point of the hierarchical mode: adding a member is O(1) because the DEK is
never re-wrapped for them.

**The team epoch is deliberately absent.** See §11. It is not available to the writer, and no amount
of wanting it changes that.

### 7.3 Team private wrap — purpose `0x03`

```
shared   = ECDH(ephemeral_priv, recipient_account_pub)                    384 bits
info     = "dockvault-zk-teampriv-v2" 0x00 vault_id 0x00 recipient_user_id
key      = HKDF-SHA256(shared, salt §4.3, info)                           32 bytes
aad      = header || vault_id 0x00 recipient_user_id
payload  = header || nonce(12) || AES-256-GCM(key, nonce, team_priv_pkcs8, aad)
```

The plaintext is a PKCS8 private key, so unlike the two DEK wraps this payload has **no fixed
length** and the §6.2 length rule does not apply to it. Discrimination is magic-plus-full-header
only, exactly as §6.2 describes for the non-fixed constructions, and the reader MUST therefore
validate every header field before committing — there is no length to disagree with first.

The reader MUST enforce a maximum payload length before allocating. A P-384 PKCS8 key is ~185 bytes;
**8 KiB** is the ceiling, generous by a factor of forty and far below anything that troubles a
browser.

`recipient_user_id` is bound here for the same reason as §7.1 and with the same honest caveat: ECDH
already binds the recipient, so against a lying server this is self-DoS only.

It is available at both ends, but "available" is doing some work in that sentence and an implementer
should know where. Both writers hold the id directly — the share path takes it as a parameter, and
the rotation loop iterates over member ids. The reader is the awkward one: the function that unwraps
a team private key is handed only the vault, the epoch and the two blobs, so the id has to be
threaded in from its caller, which does have it from the keys response. That is a small change and
an easy one to skip, and skipping it does not fail loudly — an absent field becomes `undefined`, the
transcript is built from it anyway, and the result is a wrap that authenticates against nothing the
writer produced. A reader MUST therefore treat a missing recipient id as a structural error rather
than encoding it, which is the same rule §4.1 already applies to a malformed epoch.

**The team epoch and the team public key's fingerprint are both deliberately absent.** See §11.

### 7.2/7.3 — what these transcripts do not prevent

Stated plainly, because a bound field list invites the assumption that everything else is covered.
Neither construction binds *which generation of the team keypair* it belongs to. A vault that has
rotated its team keypair holds wraps from several generations, and nothing in the bytes distinguishes
them; the server's `key_version` column does, and that column is not authenticated. So an adversary
who can write the database can serve a member an older generation's team-private wrap in place of the
current one. The member's own key opens it — it was genuinely issued to them — and they end up
holding a retired team key.

That is a real gap and §11 explains why it is not closed here. It is worth measuring against what
exists today: the shipped wraps bind *nothing at all*, not even the vault, so v2 strictly improves
matters even without the epoch.

### 7.4 Content chunk framing — purpose `0x04`

```
file        = file_header || chunk_0 || ... || chunk_n
file_header = header(8) || chunk_size(4) || blob_id(16)
chunk_i     = nonce(12) || AES-256-GCM(key, nonce, plaintext_chunk, aad_i)

key    = HKDF-SHA256(DEK, salt §4.3,
                     info = "dockvault-zk-content-v2" 0x00
                            vault_id 0x00 object_id 0x00 dek_epoch 0x00 blob_id)

aad_i  = file_header || vault_id 0x00 object_id 0x00 dek_epoch
                     || index(8) || final(1)
         and, on the final chunk only:
                     || total_chunks(8) || total_plaintext(8)
```

**`blob_id`** is 16 random bytes minted by the writer at the start of an upload attempt and folded
into the **key derivation**. It exists because `object_id` is deliberately stable across a resumed
upload, so without it two attempts at the same object derive the *same* key with the *same* AADs —
making chunks from two attempts freely interchangeable, both authenticating. A continued resume
keeps its `blob_id`; a restarted upload gets a new one. Cost: 16 bytes per file.

**Totals appear only in the final chunk's AAD.** The first draft put them in every chunk for early
truncation detection, which was the wrong trade: it forced the writer to know the length before
chunk zero, which forecloses a future streaming producer, and it left the *reader* with no specified
source for two AAD inputs it needs before decrypting anything. Truncation is still detected — a
truncated stream simply ends with no chunk that carries totals, and the reader rejects it. An
attacker cannot forge a final chunk at position `k` because the real final chunk's AAD binds
`index = n-1`.

**Framing rules, all normative:**

- `chunk_size` is the plaintext chunk length, bounded **4096 .. 8388608** (8 MiB). The ceiling was
  raised from 4 MiB because the shipped transport chunk is 5 MiB and an implementer will align them.
  A crypto chunk need not equal a transport chunk, but the grammar must not forbid it.
- Every chunk except the last holds exactly `chunk_size` plaintext bytes.
- `total_chunks == max(1, ceil(total_plaintext / chunk_size))`. The `max(1, …)` matters: an empty
  file is one chunk, and `ceil(0/n)` is 0.
- A zero-length final chunk is **forbidden except for the empty file**, so a file whose length is an
  exact multiple of `chunk_size` has exactly one valid encoding. Without this, deterministic vectors
  are not deterministic.
- A file of length ≤ 28 (header plus an empty chunk's overhead) is rejected; "no chunks" is always
  an error, never an empty file.
- Nonces are random per chunk, never index-derived: a resumed writer re-encrypting a chunk under the
  same derived key would otherwise reuse a nonce, which leaks the keystream and enables GCM
  authentication-key recovery. ~2³² chunks is the collision bound for a 96-bit random nonce, and the
  4 KiB floor puts that beyond 16 TiB in one object.

**`object_id` availability.** The client-minted file id is threaded end to end and is the id the
server adopts. But the server currently **swallows a malformed completion body and assigns its own
id instead** — for names that costs a name, for content it would cost the file. Making that
fallback an error for zero-knowledge uploads is a **precondition for the content work**, not an implementation
detail.

## 8. What is deliberately not bound

**Shared content does not pretend to bind a recipient.** It is read by everyone holding the DEK;
naming one would be a false claim that restricts nobody.

**No sender or provenance field**, and the consequence should be stated rather than implied:
**a database-level adversary can author content that clients render as authentic.** The server can
mint its own ephemeral, wrap an attacker-chosen DEK to a victim with a perfectly correct transcript
— every bound field is one the server already controls — and replace the blobs. Binding constrains
*consistency*, not *origin*. There is no cheap fix: the account keys are created ECDH-only and
WebCrypto will not let one key serve both ECDH and ECDSA, so provenance needs a second keypair with
its own registration and rotation story. `granted_by` in a transcript would be theatre.

**No timestamps** — neither side has a verifiable clock.

**No key commitment.** AES-GCM is not key-committing, and it does not matter for any construction
here: wraps give each recipient a distinct key *and* a distinct ciphertext, content has one key per
object, and every key comes from ECDH or a CSPRNG rather than a low-entropy secret. **The trigger
condition to revisit:** any feature that derives a content key from a passphrase.

## 9. What the implementation must prove

Per construction: per-field binding (a case where only that field differs and decryption fails, for
every field); both channels proven independently; every construction's payload rejected by every
other's reader; the pinned legacy fixture still readable and a v2 payload rejected by the legacy
reader; deterministic vectors reproduced by the independent implementation; tamper on header, magic,
version, purpose, reserved, nonce, tag, and for content the index, final flag and totals; and for
content: empty, one chunk, partial final chunk, reorder, duplicate, drop, truncate, append, and a
cross-attempt splice attempt defeated by `blob_id`.

**Missing baseline:** there is no pinned legacy fixture for the **team-DEK** wrap. §10 and §9 both
presuppose one. It must be captured as a baseline fixture before anything changes.

## 10. Rollout

Readers ship before writers. But the private-key envelope's precedent **does not transfer**, and
the first draft borrowed it wrongly.

That envelope is read only by the account that wrote it, so its worst case is an operator rolling
an image back. **Every v2 construction except that one is written by one user and read by others:**
one member's browser mints wraps for every remaining member during a rekey; a hierarchical rotation
writes a single team-DEK wrap that every member reads; content written by one user is read by all.

So **one user on a v2-writing build performing one rekey locks out every member still on an older
bundle**, and the server cannot re-wrap — by design. The delivery mechanism makes this reachable
rather than theoretical: the bundle is two classic scripts behind a hand-maintained cache-buster,
so a stale tab or a forgotten version bump is enough.

The writer gate must therefore be justified **against the worst reader, not the deployment**. The
mechanism is the one the private-key envelope actually uses, which should be named rather than
alluded to: a source constant, off by default, pinned false by a test, with a single choke-point
writer, and operator documentation at the point of enabling.

Order: amend the error contract (§6.5) → widen the server's algorithm filters (§6.4) → direct
wraps → content → team wraps. The first two have landed and direct wraps are written; the
ordering constraint that remains is only that readers precede writers within each construction.

## 11. Why the team wraps bind so little

Both team transcripts failed the phase's stop-condition — *"stop if any transcript field is
unavailable at both encryption and decryption time"* — in opposite directions.

**The team key fingerprint is unavailable at decryption time.** `Vault.team_public_key` holds only
the *current* key and is overwritten on rotation; no history is kept. After a team rotation, reading
a file from an earlier DEK epoch is an ordinary path: the server serves the old epoch's wrap and the
*current* public key. The client cannot recompute the retired point either — the team private key is
imported non-extractable with `deriveBits` only, and WebCrypto cannot derive a public key from it.
Binding the fingerprint would make every pre-rotation file permanently unreadable.

**The team epoch is unavailable at encryption time.** The server assigns it — on member-add it reads
the vault's current value, on rotation it increments. The client never proposes it. Fetching it first
turns member-add into a read-then-write race: the wrap binds T, a concurrent rotation lands the row
at T+1, and the member is silently locked out of the vault.

**Options:**

1. Bind neither. Team wraps get version, purpose and vault only — weaker than direct wraps, and the
   team-DEK/direct confusion is still fixed by the purpose byte, which was the main goal.
2. Add team-public-key history, making the fingerprint available at decryption.
3. Make the team epoch client-proposed with an optimistic-lock 409, mirroring the existing
   `from_version` mechanism on the DEK axis.

### 11.1 The decision: bind neither

**Option 1 was chosen** (2026-08-09). §7.2 and §7.3 are specified accordingly and are implementable
without any protocol change.

What that buys, and what it does not:

- **Bought.** A team wrap can no longer be moved between vaults, and the purpose byte plus distinct
  `info` labels make the three constructions mutually unreadable — a team-DEK wrap fed to the
  team-private reader, or to the direct reader, fails rather than being misinterpreted. That
  cross-construction confusion was the goal that justified this family of changes.
- **Not bought.** Generation rollback within one vault, described at the end of §7.3. The database
  column that distinguishes generations stays unauthenticated.

**Options 2 and 3 are deferred, not rejected.** Either would close the rollback gap, and each is a
protocol change deserving its own design: option 2 adds a stored history of retired team public keys
and a migration; option 3 changes member-add into a client-proposed, optimistically-locked write,
which is the same shape as the fix already applied to the direct DEK axis and is therefore the
cheaper of the two if the gap is later judged worth closing.

Recording the reasoning matters more than recording the choice. If someone later reads §7.2 and
wonders why a construction that clearly *should* bind its epoch does not, the answer is not that
nobody thought of it: it is that the writer cannot know the value the server will assign, and
reading it first turns adding a member into a race that silently locks that member out.

## 12. Where the two reviewers disagreed

On the team recipient identifier, one reviewer recommended the fingerprint — self-authenticating,
computable locally, no server dependency — and the other showed it is unavailable at decryption
after a rotation.

**The second is right, and the first would have caused permanent data loss.** Verified directly:
`team_public_key` is a single overwritten column, and the team private key is imported
non-extractable with `deriveBits` only. The fingerprint argument is correct about everything except
whether the value can be obtained, which is the one property that matters.

Recorded because the phase says not to start the next subround to hide a disagreement — and because
the disagreement is the strongest argument for having run two independent reviews rather than one.
Neither reviewer alone found all nine blockers, and their overlap was two.
