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

**Out:** authorization, and `zk2:` object-bound names, which stay as they are. Streaming and memory
behaviour are deliberately left to later work, which must emit and consume **byte-identical** v2
envelopes — a constraint that decided §7.4's shape.

**Transport was originally out too, and §7.4 pulled part of it back in.** Content framing cannot be
specified without it: the fields its key derivation binds are chosen when an upload session opens,
and the party that decides whether a new upload resumes an existing one is the server, not the
writer. So §7.4 imposes three requirements on the upload protocol — `object_id`, `dek_epoch` and
`blob_id` declared at session open and compared on resume — and nothing beyond those three. Chunk
sizes, retry behaviour, expiry and everything else about transport remain out of scope.

**Not a migration.** Existing envelopes are never rewritten. There is no server-side conversion,
because the server cannot read any of this and a migration that could damage opaque bytes is a
stop-condition for this work.

**Not hidden: storage-structure metadata.** These envelopes seal contents and names, but the on-disk
storage layout still reveals STRUCTURE to anyone who can read the volume: vault/file/folder counts, each
encrypted file's size (to within the format's fixed per-record overhead), and modification times.
Closing this residual channel would need size padding and access-pattern obfuscation this work does not
attempt, so it is an explicit non-goal; host full-disk encryption (see the README) is the control
against a volume reader.

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

The purpose is bound into the AAD — but as the value the READER EXPECTED, not as the byte that
arrived. Every construction rebuilds the eight header bytes from its own purpose constant and
authenticates that; the wire header is never copied into the AAD.

That distinction matters, because "covered by the AAD" invites two wrong implementations. One
copies the wire bytes into the AAD and produces a format nobody else can read. The other concludes
that AAD coverage makes it safe to pick a reader from the wire byte — which is the exact attack
this document denies, and which AAD coverage would not prevent, since a payload steered into
another reader is authenticated under that reader's transcript.

**The protection is that the reader is chosen by the call site and never by the wire** (§6.3), and
the expected purpose in the AAD is what makes a mismatch fail rather than silently succeed. A
reader may additionally compare the wire header against the one it rebuilt — content does, because
it is a public entry point a streaming caller can reach without passing the dispatch in §6.2 — but
that comparison is a second line, not the first.

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
magic, `version == 0x02`, a known `purpose`, `reserved == 0`. A payload passing all four is
committed to the v2 path; one failing any of them is not v2 and is read as legacy.

**The commit point is the header and nothing beyond it.** An earlier draft added "and for content a
`chunk_size` in range and a total length consistent with the framing" to that list, which cannot be
right: it would mean a payload failing those falls back to the legacy reader, and falling back
after committing is precisely the retry §6.3 forbids — it turns a tampering signal into a parser
oracle. `chunk_size` and framing are validated *after* the commit and are hard failures.

The residual is a legacy payload whose random IV happens to begin `DVZ2`, then `0x02`, then a byte
in `0x01..0x04`, then two zero bytes: about 2⁻⁶². That is the price of a magic-only discriminator
and it is accepted here rather than paid for with a fall-back path.

### 6.3 Downgrade

- A payload that **commits** to v2 by §6.2 and then fails its tag **fails closed**. It is not
  retried as legacy; retrying is what turns a tampering signal into a parser oracle.
- A payload with the magic but a structural failure is rejected distinguishably from *damaged* —
  see §6.5, which is a hard precondition rather than an aspiration. Which of the two answers it
  gets is not a free choice, and an earlier draft of this bullet gave the wrong one for two of the
  three cases:
  - **`version` above the one this build knows → *unsupported*.** It is a real format from a newer
    build, and the honest sentence is "update this deployment", not "your file is damaged".
  - **`version` below `0x02`, or a `purpose` outside the known range, or `reserved != 0` →
    *malformed*.** None of these can be a future format. §6.1 makes the reserved bytes a
    breaking-change channel with a strict-reject rule, so a non-zero value means bytes this build
    cannot reason about — malformed, not new. Calling it *unsupported* would tell an operator to
    upgrade in response to corruption, and would make the reserved channel behave like the
    extension channel §6.1 says it deliberately is not.
- A **legacy reader must reject a v2 payload** rather than interpret the header as ciphertext.
- **The expected purpose is chosen by the call site and compared against the wire byte. It is never
  read off the wire to select a transcript.** This is what §6.1's assurance actually rests on: if a
  reader derived its transcript from the purpose it found, rewriting that byte would steer a payload
  into another reader, which is the attack the assurance denies. Both DEK wraps are 68 bytes, so
  length cannot separate them — only the call site's expectation can. An implementation that
  satisfied every other sentence here and still selected on the wire byte would lose the property
  this document exists to establish.

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
info     = "dockvault-zk-dek-team-v2" 0x00 vault_id 0x00 dek_epoch
key      = HKDF-SHA256(shared, salt §4.3, info)                           32 bytes
aad      = header || vault_id 0x00 dek_epoch
payload  = header || nonce(12) || AES-256-GCM(key, nonce, DEK, aad)       exactly 68 bytes
```

**`dek_epoch` is `vaults.dek_version`** — the same field §7.1 binds, and NOT the team epoch. The
distinction is the whole reason this construction was blocked once and is not blocked now, so it is
worth being exact about: they are different columns on different axes, and a routine DEK rotation
advances one while leaving the other alone.

The team epoch is server-assigned and cannot be bound (§11). The DEK epoch can: the rotating client
proposes it as `to_version`, the server verifies it against the live value under a row lock and
returns 409 on a mismatch, and the wrap is then stored under exactly that key. At creation it is 1.
An earlier draft of this section omitted it, having treated "the team epoch" as one thing.

The reader MUST reject an unwrapped plaintext that is not exactly 32 bytes (§3), and dispatches on
the same fixed 68-byte length as §7.1.

**There is no recipient field, and that is not an omission.** This wrap's recipient *is* the vault's
team keypair, which ECDH already binds — there is no per-user choice to record. One wrap serves every
member, which is the whole point of the hierarchical mode: adding a member is O(1) because the DEK is
never re-wrapped for them.

**The TEAM epoch is deliberately absent** — see §11 — and only that one. It is not available to the
writer, and no amount of wanting it changes that.

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

The reader MUST bound the payload on both sides before allocating. The floor is **36 bytes**
(8 header + 12 nonce + 16 tag, i.e. an empty plaintext); anything shorter cannot be this
construction. The ceiling is **8 KiB measured over the whole payload**, header included: a P-384
PKCS8 key is about 185 bytes, so this is generous by a factor of forty and far below anything that
troubles a browser.

The recovered plaintext MUST parse as a P-384 private key, and MUST be imported **non-extractable,
with key agreement as its only permitted use**. That is a property of the construction and not an
implementation detail: the team private key exists to unwrap a DEK, and a reader that imported it
extractably would let anything holding it export the key that every member's access depends on.

`recipient_user_id` is bound here for the same reason as §7.1 and with the same honest caveat: ECDH
already binds the recipient, so against a lying server this is self-DoS only.

It is available at both ends, but "available" is doing some work in that sentence and an implementer
should know exactly where.

**Three writers, not two.** The share path takes the recipient as a parameter and the rotation loop
iterates over member ids; both are straightforward. The third is vault creation, and it is the one
that needs care — see §7.5.

**Two readers, and they take different ids.** One is the function that unwraps a team private key
for ordinary use: it is handed only the vault, the epoch and the two blobs, so the id must be
threaded in from its caller, which has it from the keys response. The other is inline in the share
path, three lines above the writer, and takes the SHARER's own id while the writer beside it takes
the RECIPIENT's. Both are in scope there under similar names, and choosing wrongly produces a wrap
that fails as an authentication error indistinguishable from tampering.

Skipping the threading does not fail loudly either: an absent field becomes `undefined`, the
transcript is built from it anyway, and the result authenticates against nothing the writer
produced. A reader MUST therefore treat a missing or empty recipient id as a structural error rather
than encoding it, which is the same rule §4.1 applies to a malformed epoch.

**The team epoch and the team public key's fingerprint are both deliberately absent.** See §11.

### 7.5 Creation, and the prerequisite these constructions carry

Both team wraps are minted by the browser into the create request, before the vault exists — so at
that moment there is no vault id to bind, exactly as was true for §7.1.

**§7.1's escape hatch does not transfer, and that is the important part.** A direct vault created on
the legacy writer converts wholesale at its first rotation, because a rotation re-wraps every
member. A hierarchical vault does not: sharing writes only the new member's team-private wrap, and
the stored team-DEK wrap is rewritten only when a member is REVOKED. So a hierarchical vault that
never removes anyone would keep its creation-time wraps unbound forever, and §7.2 and §7.3 would
never be reached on it at all.

**Prerequisite — met.** The creating client must choose the vault id and send it, the same way the
direct path does. Both halves have landed: the server accepts a chosen id for any zero-knowledge
vault, hierarchical included, and the browser mints one before building the request and binds it
into both wraps. These two constructions are therefore reachable, not merely specified.

This paragraph previously said the client half was missing and told an implementer to build it
first. It is left here, corrected rather than deleted, because the natural reading of the old text
— that the create path does not yet pick an id — invites adding a second id-minting site, and a
vault whose id is chosen in two places is the bug this binding exists to prevent.

The recipient id has the same shape of problem at creation — the recipient is the creator, and the
only local source for their account id is session state this design rejects elsewhere (§7.1). The
same fix serves both: the keys endpoint already echoes the account id, and the create path can take
it from the same response it takes the public key from.

### 7.2/7.3 — what these transcripts do not prevent

Stated plainly, because a bound field list invites the assumption that everything else is covered.
Neither construction binds *which generation of the team keypair* it belongs to. A vault that has
rotated its team keypair holds wraps from several generations, and nothing in the bytes distinguishes
them; the server's `key_version` column does, and that column is not authenticated. So an adversary
who can write the database can serve a member an older generation's team-private wrap in place of the
current one. The member's own key opens it — it was genuinely issued to them — and they end up
holding a retired team key.

That is a real gap and §11 explains why it is not closed here.

Two honest qualifications. First, it composes with anything else left unbound: a revoked member
whose removal forced a team rotation could, given a served retired generation, read content written
after their removal — which is precisely what the server's rotation enforcement exists to prevent.
Binding the DEK epoch (§7.2) closes one half of that; the team generation remains.

Second, "better than today" is true per wrap and weaker per deployment. Legacy wraps stay readable
indefinitely and this document sets no point at which a reader refuses them, so a hostile server can
always offer the unbound format instead. Retiring legacy reads is a separate decision with its own
data-loss risk, and it is not taken here.

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

One thing this framing newly exposes, recorded because the product claim is that the server
learns nothing: the cleartext `file_header` tells the server which format and which chunk size
wrote each object, where a legacy blob begins with a random IV and is indistinguishable from noise.
That is a fingerprint of the writing build and its flag state, not of the user's data — the exact
plaintext length was already derivable from the stored length under both framings, and the chunk
boundaries are at fixed offsets rather than content-defined, so they carry no structural signal.
It is inherent to having a version discriminator at all (§6.1), and worth knowing before anyone
treats the stored bytes as opaque for traffic-analysis purposes.

`blob_id` is **16 raw bytes** wherever it appears — in the `file_header`, in the `info`, and in the
AAD. §4.1's "never raw 16-byte form" rule governs **UUIDs**, and `blob_id` is not one: it is opaque
random bytes with no textual form, and the `file_header` is fixed-width. An implementer who reaches
for the UUID encoder here produces a 48-byte header and a format nobody else can read.

**A writer that mints a new `blob_id` MUST open a fresh upload session and MUST NOT inherit any
previously received **transport** chunk set.** This is normative and it is the rule the whole
construction rests on. "Transport chunk" here means an upload-session chunk as the server buffers
and indexes it, which this document elsewhere distinguishes from a crypto chunk — the two need not
be the same size, and this rule is about the former. The obvious "let the user re-pick the file and carry on" implementation violates it: it keeps
`object_id` — which it must, because the name is sealed against it — mints a new `blob_id` because
it is a new encryption, and then adopts the buffered transport indices the server reports. The result is a
file whose header names one attempt's key and whose early chunks were encrypted under another's.
Nothing on the write path notices, and the reader cannot repair it.

Enforcing that at the writer alone is not enough, because the *server* decides whether a new upload
resumes an existing session, and it matches on fields that are identical across two independent
encryptions of the same plaintext. The server MUST therefore treat `blob_id` as an opaque
per-attempt token: it is declared when the session opens, stored, and compared on any resume, and a
mismatch is refused before a byte is accepted. The server never derives anything from the value and
never needs to understand it.

Store it as **16 opaque bytes** — a `BYTEA(16)` column, or fixed-width hex text. The warning above
about the UUID encoder applies to the schema as much as to the header: the nearest precedent for a
declared-at-init token is a `UUID` column, which round-trips as hyphenated text and reintroduces
exactly the width the fixed header cannot carry.

**Determining `final` is the reader's problem, and it is not a wire field.** `final` is an AAD
input, so a reader must decide which interpretation to use *before* it can authenticate anything.
It MUST derive that from the stored length using the closed form above — computing `total_chunks`
up front and treating index `total_chunks - 1` as final. A reader always has `L`, so this is
always available to it, whatever the writer did.

A consumer reading a stream whose total length is genuinely not yet known — a proxy relaying a
producer's output — instead holds **one chunk of lookahead**: buffer `28 + chunk_size` bytes, and
treat a chunk as final exactly when no byte follows it. Note that a final chunk with `r =
chunk_size` is full-width and is still final; length alone does not mark it.

**Trial decryption under both interpretations is forbidden.** It is not a confidentiality hole, but it doubles the work on every final chunk and
leaves a normative document with two acceptable behaviours where it needs one.

**Totals appear only in the final chunk's AAD.** The first draft put them in every chunk for early
truncation detection, which was the wrong trade: it forced the writer to know the length before
chunk zero, which forecloses a future streaming producer, and it left the *reader* with no specified
source for two AAD inputs it needs before decrypting anything. Truncation is still detected — a
truncated stream simply ends with no chunk that carries totals, and the reader rejects it. An
attacker cannot forge a final chunk at position `k` because the real final chunk's AAD binds
`index = n-1`.

**No plaintext may be released to a consumer until the chunk carrying `final = 1` has
authenticated.** What this construction provides is prefix integrity plus an authenticated
end-of-stream marker, which is *not* all-or-nothing integrity: every chunk of a truncated file
authenticates, and only the absence of the terminator reveals the truncation. A reader that hands
bytes onward as each chunk authenticates has therefore already delivered attacker-chosen-length
output by the time it detects the problem. Today's whole-file reader satisfies this by accident,
because it buffers; the streaming reader this grammar exists to enable does not, and must hold or
mark its output until the terminator is in.

**What shipped, measured against that rule.** The streaming reader releases each record to its
`write` callback as it authenticates, and the callback's contract requires the caller to keep those
bytes somewhere it can still discard -- which the buffered consumer does, holding them as parts it
never hands over until the reader resolves. That consumer satisfies this rule.

The service-worker download sink does not. It writes each record into a download the browser owns,
and a page cannot retract that, so an under-declared length delivers a genuine prefix of the object
into the user's Downloads before the terminator is reached. Measured on the shipped reader: with a
length short by exactly one record, two of four records were handed over before the refusal.

That sink is therefore **off by default and recommended against** -- see
`vault-download-sink-and-policy.md`, which reaches the same conclusion from an unrelated direction
(it does not reduce memory either). This paragraph is the security half of that case: a consumer
that cannot discard what it has been given cannot satisfy the rule above, whatever else it buys.

**Framing rules, all normative:**

- `chunk_size` is the plaintext chunk length, bounded **4096 .. 8388608** (8 MiB). The ceiling was
  raised from 4 MiB because the shipped transport chunk is 5 MiB and an implementer will align them.
  A crypto chunk need not equal a transport chunk, but the grammar must not forbid it. This build's
  writer picks **1 MiB** and does not try to align them: the 28-byte file header and the 28 bytes
  each chunk adds mean a crypto boundary and a transport boundary coincide only periodically and
  never usefully, so alignment buys nothing to pay for. A megabyte keeps the overhead at three
  thousandths of a percent while staying small enough for a bounded streaming writer to hold. That
  is a writer-side choice, revisable without touching the grammar — the size is recorded in each
  file's header and a reader takes it from there.
- Every chunk except the last holds exactly `chunk_size` plaintext bytes.
- `total_chunks == max(1, ceil(total_plaintext / chunk_size))`. The `max(1, …)` matters: an empty
  file is one chunk, and `ceil(0/n)` is 0.
- A zero-length final chunk is **forbidden except for the empty file**, so a file whose length is an
  exact multiple of `chunk_size` has exactly one valid encoding. Without this, deterministic vectors
  are not deterministic. This binds the **reader** as well as the writer: a reader that encounters a
  zero-length final chunk on a non-empty file MUST reject it rather than treat it as a harmless
  terminator. Read as a writer-only constraint it would leave two encodings acceptable on the read
  side, which is the ambiguity the rule exists to remove.
- The smallest valid file is **56 bytes**: the 28-byte `file_header`, plus one empty chunk's
  12-byte nonce and 16-byte tag. Anything shorter is rejected — "no chunks" is always an error,
  never an empty file. (An earlier draft said 28, which is the header *alone*; that would admit a
  30-byte input which cannot be valid under any reading.)
- **Parsing a file of stored length `L` is closed-form**, given `chunk_size` from the header. Each
  non-final chunk occupies `28 + chunk_size` stored bytes and the final one occupies `28 + r` with
  `1 ≤ r ≤ chunk_size` (or `r = 0`, only for the empty file):

  ```
  total_chunks     = ceil((L - 28) / (28 + chunk_size))
  total_plaintext  = L - 28 - 28 * total_chunks
  ```

  Both hold at the boundaries — the empty file (`L = 56`, one chunk, zero plaintext) and a length
  that is an exact multiple of `chunk_size`. What makes them exact is that per-chunk overhead is
  **strictly positive**, so `L` cannot be ambiguous between two chunk counts; the zero-length-final
  rule earns its place in encoding determinism, not here.
- **The closed form has a domain, and a reader MUST check it.** Between the valid lengths for `n`
  chunks and for `n + 1` sits a 28-byte-wide gap that no valid file can occupy, and the formulae
  answer confidently for those inputs — `L = 4153` at `chunk_size = 4096` yields `2, 4069`, whose
  implied final chunk is one byte, shorter than a nonce and tag together. Derive the final chunk's
  plaintext length and reject unless it is in range:

  ```
  r = total_plaintext - (total_chunks - 1) * chunk_size
  valid iff (1 <= r <= chunk_size) or (r == 0 and total_chunks == 1)
  ```

  Check `L >= 56` first, or `L = 28` derives a self-consistent-looking `0, 0`.
- **The totals are not on the wire, and there is nothing to cross-check them against.**
  `total_chunks` and `total_plaintext` appear only in the final chunk's AAD, which is *supplied* by
  the reader, never parsed from storage. A reader derives them from `L`, feeds them to the AAD, and
  a disagreement with what the writer used surfaces as an **authentication failure on the final
  chunk** — which MUST be fatal. An implementer who reads this expecting a stored field will not
  find one.
- Nonces are random per chunk, never index-derived: a resumed writer re-encrypting a chunk under the
  same derived key would otherwise reuse a nonce, which leaks the keystream and enables GCM
  authentication-key recovery. **2³² invocations is the NIST SP 800-38D §8.3 cap for randomly
  generated 96-bit nonces**, chosen so the probability of IV reuse stays under the 2⁻³² ceiling §8
  mandates — it is not the point at which that probability is reached (at 2³² the figure is nearer
  2⁻³³), and it is not the birthday point, which is near 2⁴⁸. The limit is the conservative one and is the one to size against; an implementer who
  reads "the collision bound" and sizes something else off it is out by 2¹⁶. The count is **per
  derived key** — SP 800-38D counts "all instances of the authenticated encryption function with
  the given key" — so a resumed writer that re-encrypts chunks it already sent spends from the same
  budget. Passes under a *different* `blob_id` derive a different key and start a fresh one. The 4 KiB floor puts 2³² chunks
  beyond 16 TiB in one object.

**Encodings for this construction.** Integers are unsigned big-endian: `chunk_size` **4 bytes**,
`index` 8, `total_chunks` 8, `total_plaintext` 8, and `dek_epoch` 4 per §4.1. `final` is one byte,
`0x00` or `0x01` — a writer MUST emit no other value, and test vectors MUST NOT contain one. Note
that `final`, `index` and the totals are AAD inputs and never appear on the wire, so "accepted" here
constrains writers and vectors, not a parser. `vault_id` and `object_id` follow §4.1's 36-byte
textual UUID form; `blob_id` does not, per the rule above.

`chunk_size` is the first **4-byte non-epoch integer** in this family. §4.1 says "4 bytes for every
epoch field, 8 bytes where stated" and did not anticipate one; this clause is the statement, and an
implementer working from §4.1 alone would encode it as 8.

**`object_id` and `dek_epoch` availability.** Both are bound into the key derivation and into every
AAD, so a session that does not know them cannot produce readable bytes — and for content, unlike
for a name, getting one wrong costs the whole file rather than its label.

It is not sufficient that the completion fallback becomes an error. Both fields MUST be **required
when the upload session opens**, for zero-knowledge uploads, and both MUST be compared on any
resume. A server that accepts a session declaring neither still has to guess at commit time, and a
server that accepts a *second* session declaring neither will hand the second attempt the first
attempt's buffered chunks — the two are indistinguishable to a matcher that keys on the blind index,
total size and chunk count, all of which are identical across two encryptions of the same plaintext.
These are **preconditions for the content work**, not implementation details.

They are **complementary to** the `blob_id` comparison above, not the same requirement one field
over, and it is worth being exact about which one does what. `object_id` is deliberately *stable*
across attempts at the same object — the name is sealed against it — so requiring and comparing it
cannot distinguish two attempts: both declare the same value. **Only `blob_id` separates attempts.**
What requiring `object_id` and `dek_epoch` at session open buys is different and also necessary: it
removes the server's need to guess at commit time, and it closes the case where one party declares a
field and the other does not, which at completion is indistinguishable from an older client that
never declared anything at all.

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

**For content specifically, §7.4 creates seven further obligations**, each of which is a rule a
reader can get wrong while still decrypting ordinary files correctly — which is what makes them
worth enumerating rather than leaving to the prose that states them:

- a zero-length final chunk on a non-empty file is rejected;
- a stored length below 56, and a length in the 28-byte gap between two valid chunk counts, are
  both rejected before any decryption is attempted;
- no plaintext reaches a consumer before the chunk carrying `final = 1` has authenticated;
- `final` is decided from the stored length, never by trial decryption under both interpretations;
- a resume declaring a different `blob_id` is refused by the server before a byte is accepted;
- `object_id` and `dek_epoch` are required when the upload session opens, not only at completion;
- `final` is `0x00` or `0x01` in every emitted vector.

**Missing baseline:** there is no pinned legacy fixture for the **team-DEK** wrap. §10 and §9 both
presuppose one. It was not captured before the team wraps shipped, so it is now a debt to settle
rather than a gate that held.

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

Order, as planned: amend the error contract (§6.5) → widen the server's algorithm filters (§6.4)
→ direct wraps → content → team wraps.

**What actually shipped took the team wraps before content.** The error contract, the algorithm
filters, the direct wrap and both team wraps are in, and content is now in as well — the reader
first, then the writer behind its own gate. Every writer is gated off and the canonical algorithm
label is still generation 1, so nothing in this tree can write a v2 row without a source change.

The content writer's gate is a second constant rather than a reuse of the wrap gate, because the
two protect against different readers. A wrap is read by *other members*, so writing one early
locks people out and there is no way back. Content is read by whoever can already open the vault,
and every such reader has understood this format since the reader shipped — so the exposure is
other TABS, not other people, and a file already written keeps reading if the gate goes back off.
Sharing one constant would have forced the stricter of the two conditions onto both and, worse,
made turning one on turn the other on with it.

One obligation went unmet on the way: §9 requires the team-DEK wrap's legacy form to be captured as
a baseline fixture *before anything changes*, and the team wraps shipped without one. That is a
team-wrap debt rather than a content gate, but it should not be discovered by inference later.

Content carried preconditions the wraps did not (§7.4): the object id, the DEK epoch and the
per-attempt `blob_id` must each be declared when the upload session opens and compared on resume.
**Those landed first, each on its own, before either the content reader or the content writer** —
which is why content could then ship in the two halves described above.

## 11. Why the team wraps bind so little

Both team transcripts failed the stop-condition this work adopted — *"stop if any transcript field is
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

Recorded rather than quietly resolved, because burying a disagreement of this kind is how the
losing argument gets rediscovered later — and because
the disagreement is the strongest argument for having run two independent reviews rather than one.
Neither reviewer alone found all nine blockers, and their overlap was two.
