# Proof of key for zero-knowledge key changes, version 1

Status: **shipped in 0.33.2**. The transcript, the MACs, the header, the stored material and the refusal
contract below are fixed; both implementations reproduce the frozen vectors in
`tests/fixtures/crypto/zk-key-proof-v1/`. Where this document and the code differ, that is a bug in one of
them. The server's side is `app/services/zk_key_proof.py` and the routes in `app/api/ecc_router.py`; the
browser's side is `static/js/ecc_crypto.js` (the cryptography) and `static/js/app.js` (the requests); the
test suite's reference implementation is `tests/zk_key_proof_reference.py`.

Advisory: `zero-knowledge-key-changed-through-a-taken-over-account`, in `docs/upgrade-matrix.json`.

---

## 1. The problem

Four requests hand out or fix zero-knowledge key material:

| Request | What it does |
|---|---|
| `POST /ecc/vaults/{id}/rekey` | rotates the vault to a new key (a new DEK epoch) |
| `POST /ecc/vaults/{id}/members` | gives a member a copy of the vault's current key |
| `PUT /ecc/vaults/{id}/index-key` | sets the name-index key every member then uses |
| `POST /vaults` with `type: zero_knowledge` | creates a vault under a key the client supplies |

Before 0.33.2 each was checked against the **account**, not against the **keys** the person holds. A
rotation needed no old key at all: the browser minted a new DEK and wrapped it to each remaining member's
*public* key. A share re-wrapped "the current key" for someone else, and the server could not tell a real key
from a chosen one. Creating a vault needed only the owner's public key.

So whoever could act as the account of someone who holds a vault's key could rotate the vault to a key of
their choosing, replace a member's copy of the key, set a name-index key they know, or create a vault in
that person's name under a key they know. Acting as an account needs only its sign-in: an administrator who
set the person's password, made them a reset link, reset their second factor or changed their email
address could do it, and so could anyone holding a stolen session. Files uploaded after such a change were
readable to that person; files uploaded before were not; members noticed nothing.

The server never holds a zero-knowledge key, so it cannot check a key by looking at it. What it can check is
a **proof**: a MAC the browser computes with the keys it holds, over a one-time challenge and over the exact
request, which only a holder of those keys can produce.

---

## 2. Threat model

This sits inside the zero-knowledge boundary as it was: the server cannot read zero-knowledge content, and a
host operator who serves the JavaScript can still attack a browser client. It does not move that boundary; it
closes a hole inside it.

### 2.1 Who it is about

| Adversary | Has | Lacks | Outcome |
|---|---|---|---|
| **A session without the key**: an administrator who set or reset the person's password, reset their second factor or changed their email, or anyone with a stolen session | a session as the person; perhaps captured requests (a shared HAR file, a proxy that logs) | the person's zero-knowledge passphrase, identity private key and DEKs | every one of the four changes is refused, and so are setting up a key check and resetting the vault's key; nothing captured can be replayed |
| **Someone who knows the key without holding it**: a member removed without a rotation, a holder whose key rows were deactivated, a deleted member | the vault's DEK, perhaps its proof key, perhaps a session of a *different* holder | that holder's identity private key | refused, through any account |
| **An insider**: a manager who really holds the key and acts maliciously | everything a holder has | - | cannot make things worse than before; the owner can repair (§4.4) |
| **A database reader** (a backup, a read-only hole), alone or with a session | database rows | `.env`, live keys | cannot forge a proof: the one secret a proof is checked with is sealed with `ENCRYPTION_KEY` |
| **A downgrade**: an old client, a request without a proof, a rollback, the enforcement switch | - | - | fails safe; never silently lowers the requirement (§3.8, §9) |
| **A database writer** who is not the code | row writes | the JavaScript | server checks cannot stop it; the stored key check and lineage tag let members' clients detect a substituted key (§3.5, §3.6) |
| **A host operator** who serves the code | everything | - | out of reach in the browser, as before |

Out of scope: script injection on the vault's origin; a member whose passphrase is compromised (they *are* that
member); retroactive secrecy for content a removed member could already read.

### 2.2 Why the identity key is what a takeover lacks

- The zero-knowledge passphrase is separate from the sign-in password, is typed only into the browser and
  never reaches the server. The stored identity envelope is PBKDF2-SHA256 (600,000 iterations) and
  AES-256-GCM (see `vault-private-key-envelope-v1.md`). A password reset changes nothing about it.
- Once unlocked, the identity private key lives in memory as a non-extractable WebCrypto key and is dropped on
  idle lock, lock-all and sign-out. A stolen token carries no key.
- The registered public key cannot be replaced from a session: registration is first-write-wins and needs its
  own proof of possession; replacing the envelope needs a proof by the registered key
  (`vault-private-key-update-pop-v1.md`) and keeps the public key.

### 2.3 What this does not remove

- **A weak passphrase.** A session can download the passphrase-encrypted envelope and guess offline. A
  guessed passphrase makes the attacker that member. This bounds every zero-knowledge guarantee, this one
  included. Choose a long passphrase.
- **An account with no identity key yet.** Whoever registers first owns the account's identity. If someone
  signs in as a person before that person has registered a key, and an honest manager then shares a vault to
  that account, the key goes to the attacker's key.
- **An account that wrongly holds a current key row** (a bug, a database edit) passes the setup of a direct
  epoch that has no proof key yet (§4). Members' clients can detect it with the key check (§3.5); the owner
  repairs it with an owner reset (§4.4).
- **The switch set to false, or a rollback below 0.33.2,** accepts changes without a proof again (§3.8, §9).
- **History.** A vault whose key someone else chose before 0.33.2 keeps that key. Nothing can detect that after
  the fact: check the `zk_vault_rekeyed`, `zk_member_key_granted` and `zk_index_key_wrapped` audit entries made
  after an administrator changed a member's sign-in details, and have a key holder rotate any vault with a change
  nobody recognises.

---

## 3. Design

### 3.1 Three proofs, one challenge

| Role | Private key the browser uses | Public key the server checks against |
|---|---|---|
| **identity** | the caller's identity private key | the account's registered public key |
| **current-key** | hierarchical vault: the team private key of the current team epoch; direct vault: the current DEK epoch's **proof private key**, opened with that DEK | hierarchical: the vault's team public key; direct: the epoch's proof public key |
| **new-key** | the private half of the public key the request installs | the public key in the request body |

Each role is an ECDH key confirmation against the same one-time server key, the construction that already
guards private-key replacement, in a domain of its own (§5.3). The server decides which roles a request needs
from the operation and the vault's state, never from the request (§5.5).

- **identity** is what a taken-over account lacks. It is required on every operation: a current-key proof
  alone could be made by someone who kept an old copy of the key, using another person's session.
- **current-key** makes the rule literal: only someone who holds the key in use may change it. It does not
  depend on the key rows being right, and it anchors the per-epoch material members check.
- **new-key** keeps an invariant: every public key the server stores as a verifier has a private half someone
  proved they hold. A buggy or hostile client cannot install a verifier nobody can answer.

### 3.2 Direct vaults: a proof keypair per epoch

A direct vault's members each hold the DEK wrapped to their own key; the server has nothing to check a DEK
against. So for each DEK epoch *n*, whoever establishes the epoch (the creator at *n* = 1, the rotator at
*n* + 1, or the manager who sets up an epoch made before 0.33.2) generates a fresh P-384 ECDH keypair `H_n`
and stores its public half as the epoch's verifier and its private half sealed under the epoch's DEK:

```
P_n      = SPKI PEM of H_n.public                                   the verifier
P_point  = the 97-byte uncompressed point of H_n.public
context  = vault_id (36 ASCII, lowercase) || 0x00 || u32be(n) || 0x00 || SHA-256(P_point)
header   = "DVZ2" 0x02 0x07 0x00 0x00                               version-2 family, purpose 0x07 "key proof key"
info     = "dockvault-zk-key-proof-key-v2" || 0x00 || context
aad      = header || context
K_seal   = HKDF-SHA256(raw DEK_n, V2 salt, info) -> AES-256-GCM key (refused for a DEK that is not AES-256-GCM)
           V2 salt is "dockvault-zk-envelope-v2-salt-01", the salt of every version-2 derivation
S_n      = header || nonce (12) || AES-256-GCM(K_seal, nonce, PKCS8(H_n.private), aad)
bounds   = 36..8192 bytes, as the team private-key wrap; a P-384 PKCS8 seals to about 225
```

- **Only DEK holders can open it.** `K_seal` comes from the 256-bit DEK.
- **The pair cannot be separated.** `SHA-256(P_point)` is in both `info` and `aad`, so `S_n` opens only with the
  `P_n` it was sealed for. After opening, the browser also compares the recovered key's public point with `P_n`
  and fails closed (`KEY_MISMATCH`): AES-GCM is not key-committing, and the comparison is what makes a successful
  open prove that the opener's DEK is the one the installer sealed with.
- **Least privilege.** The opened key is re-imported non-extractable, usable only for `deriveBits`.
- **Domain separation.** The label is distinct from every other DEK-derived label (content, resume MAC, the key
  check and lineage labels below, the name blind index), and every label ends in `0x00` before its context, so
  none is a prefix of another. Purpose byte `0x07` is registered in `vault-zk-envelope-v2.md`.
- **Nothing to guess offline.** `P_n` is a random public key and `S_n` is sealed under a key from a 256-bit DEK;
  neither involves the passphrase.

Not chosen: a hash of a DEK-derived value as the verifier (presenting it would put a bearer token in every
request body, which a captured request replays, and it binds neither the request nor the person); a keypair
derived from the DEK (WebCrypto cannot compute a public point from a scalar); ECDSA signatures (as strong, but a
second primitive and a different key type from the team key, where key confirmation lets one verifier shape
serve both modes).

### 3.3 Hierarchical vaults: the team key is the verifier

Every member who holds a hierarchical vault's current key holds the team private key of the current team epoch,
and the vault's team public key has been stored since creation. It is the verifier: no new material, nothing to
set up. From 0.33.2:

- the team public key is validated as a P-384 SPKI key at creation and at every team rotation;
- installing a new one needs the new-key proof;
- whether a rotation changes the team key is decided by comparing **points**, not PEM text. A re-encoded copy of
  the current key used to count as a new key: the team epoch advanced while the keypair stayed, and a member
  removed in that rotation kept the team private key. A team rotation that reinstalls the current point is now
  refused (400).

### 3.4 Storage

Two tables. No existing column changes, so an older release ignores them; their foreign keys are declared with
`ON DELETE` rules in the database, so the cascades still fire under an older release.

**`vault_key_proofs`**, one row per DEK epoch made from 0.33.2 on, in both modes:

| Column | Notes |
|---|---|
| `id` | UUID primary key |
| `vault_id` | references `vaults.id`, `ON DELETE CASCADE`; unique together with `dek_epoch` |
| `dek_epoch` | the epoch |
| `format` | the format of the stored material, 1 (§8) |
| `proof_public_key` | direct: `P_n`; NULL for hierarchical |
| `sealed_private_key` | direct: base64 of `S_n`; the server checks only its header and bounds |
| `dek_check` | direct: base64 of 32 bytes (§3.5) |
| `lineage_tag` | base64 of 32 bytes (§3.6); NULL at epoch 1, after a setup, and on an owner reset whose owner could not open the previous epoch |
| `source` | `create`, `rotate`, `bootstrap` or `owner_reset` |
| `created_by` | references `users.id`, `ON DELETE SET NULL` |
| `created_at` | |

- **Rows are immutable.** No route updates one; damaged material is repaired only through a new epoch (§4.4).
  A client can therefore treat any change to an epoch's material as tampering.
- A direct row carries all three direct columns, or the row is hierarchical and carries none (a database
  constraint).
- Rows are **deleted only** with their vault, and by `retire-version`, which prunes rows with
  `dek_epoch < min(retired floor, current epoch)`: the current epoch's row stays even if a file ever declared an
  epoch above the current one. The rows authorize key changes; nothing reads data with them, so they never hold
  the retire floor up.
- **No row** means the epoch was made before 0.33.2, while rolled back to an older release, or by a request
  without a proof while enforcement was off (§3.8).

**`zk_key_proof_challenges`**, a table of its own (a challenge for one protocol is unreachable from another's
verifier, not merely filtered out):

| Column | Notes |
|---|---|
| `id` | the challenge id |
| `user_id` | references `users.id`, `ON DELETE CASCADE`; bound at issuance |
| `vault_id` | bound at issuance; no foreign key, because a create names a vault that does not exist yet |
| `op` | `rekey`, `share`, `index_key`, `bootstrap`, `create` or `owner_reset` |
| `server_private_key_sealed` | the server's one-time private key, sealed with the deployment key |
| `nonce` | base64 of 32 bytes |
| `mode`, `dek_epoch`, `team_epoch` | the vault's state at issuance |
| `verifier_sha256` | SHA-256 of the current verifier's point at issuance, NULL when there is none |
| `created_at` | a challenge lives 300 seconds |

- **The server's one-time key is sealed.** ECDH is symmetric: anyone who reads a live, plaintext one-time key
  can compute the MAC the server expects for any public key. Sealed with the deployment key, a database read
  alone is not enough. It is opened with a strict decrypt that refuses anything this deployment did not seal, so
  a planted plaintext row never verifies.
- **Up to 32 live challenges per account.** A bulk share asks for one challenge per person, in parallel, so they
  must not evict one another. Issuing the 33rd deletes the oldest; issuance is serialized on the account's row
  and deletes the account's expired challenges, and the periodic session-data cleanup sweeps the rest.

### 3.5 The key check (direct vaults)

The sealed proof key is released only to managers (§5.6). So that a plain member can also confirm the DEK they
were given, each direct row carries a key check:

```
kc_ctx    = vault_id (36) || 0x00 || u32be(n)
k_check   = HKDF-SHA256(raw DEK_n, V2 salt, "dockvault-zk-dek-check-v1" || 0x00 || kc_ctx), as an HMAC-SHA256 key
dek_check = HMAC-SHA256(k_check, "dockvault-zk-dek-check-v1" || 0x00 || kc_ctx)             32 bytes
```

A MAC under a 256-bit key over public data: useless offline. A member whose DEK does not reproduce it holds the
wrong key: a bad share, a wrap substituted by a key-holding manager, or a database edit. 0.33.2 writes the key
check at create, rotation and setup; the member-side check that reads it comes in a later release, and rows are
immutable, so a row written by 0.33.2 is complete when that release reads it.

A hierarchical vault needs no key check: all members read the same team DEK wrap. A member who opens the team
private key of the current epoch can instead compare its public point with the vault's team public key
(`teamPrivateKeyMatchesPublic`).

### 3.6 The lineage tag (both modes)

A rotation from DEK epoch *p* to *p* + 1 carries a tag only a holder of DEK_p can compute:

```
k_line = HKDF-SHA256(raw DEK_p, V2 salt,
                     "dockvault-zk-key-lineage-v1" || 0x00 || vault_id (36) || 0x00 || u32be(p)), as an HMAC-SHA256 key
msg    = SHA-256( "dockvault-zk-key-lineage-v1" || 0x00 || vault_id || 0x00 || u32be(p) || 0x00 || u32be(p+1)
                  || 0x00 || mode (1 byte) || 0x00 || u32be(team epoch at p+1)
                  || 0x00 || SHA-256(point of the verifier at p+1: P_{p+1}, or the team public key at p+1)
                  || 0x00 || dek_check at p+1 (32 bytes; 32 zero bytes in hierarchical mode)
                  || 0x00 || SHA-256(base64-decoded team DEK wrap at p+1; 32 zero bytes in direct mode) )
lineage_tag = HMAC-SHA256(k_line, msg)
```

In hierarchical mode the team DEK wrap is what the tag binds, so it must be present and non-empty: the browser
refuses to compute a tag over no wrap (`INVALID_INPUT`), and a verification that cannot compute the tag answers
false.

A member who held DEK_p can verify the tag when they first load *p* + 1, then check their own DEK_{p+1} against
the key check (direct) or their team key against the team public key (hierarchical). Together that says "the
key I now hold was introduced by someone who held the one before". The server cannot forge it, so it can show a
database writer who rotated a vault by writing new wraps to members' public keys. An absent tag on a row that
should have one is not a pass. 0.33.2 writes the tag on every proven rotation (the server refuses a proven
rotation without one, except an owner reset); the member-side verification comes in a later release.

### 3.7 Creation is covered too

`POST /vaults` for a zero-knowledge vault needs a proof with the identity and new-key roles (op `create`). The
new key is `P_1` for a direct vault (the body also carries `S_1` and the key check) or the team public key for a
hierarchical one. The challenge binds the vault id the client chose, so a proof made for one create cannot
create another vault. Every check happens **before** anything is created: a refused create leaves no vault.

This closes the vault a taken-over account could create "as" its victim, and gives every vault created from
0.33.2 on its first material from a proven creator. The cost is that creating a zero-knowledge vault now needs
the identity key unlocked, which the name-index key set right after creation needed anyway.

### 3.8 The enforcement switch

`ZK_KEY_PROOF_ENFORCE` in `.env`, **default `true`**.

- **On:** a guarded request without a proof gets 428.
- **Off:** a request *without* a proof runs as before 0.33.2 and writes the audit entry `zk_key_proof_absent`. A
  request *with* a proof is still fully checked and refused if the proof fails. Material is stored only from a
  request whose proofs verified, so an unproven request never installs a verifier (an epoch it creates has no
  row and is set up later). Setting up a key check and an owner reset always need a proof.
- **Environment only.** It is not a settings-page key, and a settings save that names it is refused, so an
  application administrator cannot turn the defence off. The host operator can, but the host operator already
  controls the code.
- The web container says at startup when it is off.
- **Why a switch at all:** the only thing enforcement refuses is these changes from clients that predate the
  proof (stale browser tabs; a DockVault Desktop build whose built-in web app predates 0.33.2). An operator whose
  users depend on such a client can postpone enforcement without rolling back, which would reopen the hole *and*
  drop every other fix in the release. Off reopens the hole.

---

## 4. Setting up older epochs, and the owner reset

### 4.1 What needs setting up

- **Hierarchical vaults: nothing.** The team public key has been the verifier since creation.
- **Direct vaults:** every epoch with no `vault_key_proofs` row. Until it has one, a change that must prove the
  current key answers 428 `zk-key-proof-setup-required`, and the web app sets it up and retries.

### 4.2 Who may set it up

`PUT /ecc/vaults/{id}/key-proof` (op `bootstrap`) is one of the two operations that accept a proof without the
current-key role, since there is no verifier to prove against yet. It needs, checked under the vault's row lock:

- an interactive session (a temporary credential is refused before the rate budget is charged);
- a manager of the vault who holds an active key row at the current epoch;
- a direct vault whose current epoch has no row;
- the **identity** proof, and the **new-key** proof for the `P_n` it installs.

Any manager who holds the key may do it, not only the owner, so an absent owner cannot stall an urgent removal.

### 4.3 Why a taken-over account cannot use it or get there first

- A session without the key lacks the identity private key, so it can neither set up a check nor plant material
  before an honest manager does.
- Someone who knows the key through a *different* account lacks that account's identity key; through their own
  account they hold no current key row.
- Nothing can push a vault back to "no row": rows are immutable, deleted only below the current epoch or with the
  vault, and every epoch created by a proven request gets its row in the same transaction.
- Before its epoch is set up, a direct vault is still protected by the identity proof: "no row" means "no
  current-key proof yet", not "unprotected".

### 4.4 Owner reset

If an epoch's proof material is damaged (a client bug, a database edit, material planted by a malicious holder),
nobody can pass the current-key proof at that epoch. The owner is the vault's guaranteed key holder (every
rotation must re-wrap them), so the owner has a way out that does not need the current-key proof:

- `POST /ecc/vaults/{id}/rekey` with `"owner_reset": true`, on a challenge issued for op `owner_reset`;
- the caller is the vault's owner, holds an active key row at the current epoch (even a damaged one), uses an
  interactive session, and passes a **fixed step-up**: whenever the owner has a second factor enrolled, the reset
  needs it, whatever the administrator's step-up settings say. It is asked for before the challenge is consumed,
  so the retry after the prompt still finds it;
- proofs: identity and new-key; no current-key;
- it always creates a **new epoch with fresh material** (a new DEK and proof keypair; for a hierarchical vault a
  new team keypair and DEK). Existing rows are never replaced;
- the new row carries a lineage tag whenever the owner can still open the previous epoch's DEK; only when the
  owner cannot does it have `source = owner_reset` and no tag;
- recorded as `zk_owner_key_reset`, in the rotation's own transaction.

It is safe because it still needs the owner's identity private key. Sharing and the name-index key get no such
exception: only a rotation produces fresh material.

### 4.5 When setup runs

- **On demand:** a 428 `zk-key-proof-setup-required` makes the web app set the epoch up and retry once.
- **Races:** two setups at once: the lock and the unique constraint let one win; the other gets 409
  `zk-key-proof-exists` (the same material again from the same person gets 200 `"unchanged": true`, an
  idempotent retry). A setup racing a rotation fails the state pin (409) and sets up the new epoch if it still has
  no row.
- Vaults nobody changes stay without a row and remain protected at the identity level.

---

## 5. Protocol

### 5.1 Challenge

`POST /ecc/vaults/{vault_id}/key-proof/challenge` with `{"op": "rekey" | "share" | "index_key" | "bootstrap" |
"create" | "owner_reset"}`, and for `create` only `"mode": "direct" | "hierarchical"` (default `direct`): the
vault does not exist yet, so its mode, which the transcript binds, comes from the request, and the create must
then be for a vault of that mode. Every other operation takes the mode from the vault.

Checks, in order:
- `bootstrap` and `owner_reset`: a temporary credential is refused (403 `zk-key-proof-interactive-only`) before
  the rate budget is charged.
- The rate budget `key_proof_challenge`: 400 per minute per account.
- `create`: the caller passes the same checks `POST /vaults` makes (from the same helpers), the id is unused and
  was never used, and the caller has an encryption key.
- Every other operation: the caller reaches the vault (a stranger gets the same 403 whether or not the vault
  exists), may use its key under their credential's policy, manages it, holds its current key, and has an
  encryption key. `owner_reset`: the caller is the owner. `bootstrap`: a direct vault whose current epoch has no
  row, else 409 `zk-key-proof-exists`. These checks are advisory: the guarded request repeats them under the
  vault's row lock.
- Issued under the account-row lock, applying the cap of §3.4.

The route itself writes no audit entry; a refused or failed proof is recorded by the route it guards.

Answer:

```
{ challenge_id, server_ephemeral_public_key (PEM), nonce (base64, 32 bytes), expires_in: 300,
  mode, dek_epoch, team_epoch,
  verifier: null | { public_key, source, lineage_tag, sealed_private_key and dek_check (direct only) } }
```

`verifier` is null for `create`, for `bootstrap`, and when the current direct epoch has no row.

### 5.2 Transcript

```
T = SHA-256( L 0x00 op 0x00 cid 0x00 nonce 0x00 uid 0x00 vid 0x00 mode 0x00 de 0x00 te
             0x00 h_id 0x00 h_cur 0x00 h_new 0x00 h_body )

L      ASCII "dockvault-zk-key-proof-v1"
op     1 byte: 0x01 rekey, 0x02 share, 0x03 index_key, 0x04 bootstrap, 0x05 create, 0x06 owner_reset
cid    the challenge id, 36 bytes, lowercase canonical UUID
nonce  32 raw bytes (base64-decoded)
uid    the signed-in account's id, 36 bytes, lowercase
vid    the vault id, 36 bytes, lowercase (for create: the id in the create request)
mode   1 byte: 0x01 direct, 0x02 hierarchical
de, te the challenge's DEK epoch and team epoch, 4 bytes big-endian each (create: 1, 1)
h_id   SHA-256 of the 97-byte uncompressed point of the account's registered public key
h_cur  SHA-256 of the verifier's point, or 32 zero bytes for an operation that proves no current key
       (bootstrap, create, owner_reset)
h_new  SHA-256 of the point of the public key the request installs, or 32 zero bytes when it installs none
h_body SHA-256 of the exact request body bytes
```

Every field after the label has a fixed width, so the encoding is injective; the `0x00` bytes are readability.
Ids must be whole UUIDs (an id with anything after it is refused, not bound). Points, not PEMs, are hashed, so a
cosmetic re-encoding of a stored key cannot break a genuine proof.

**The body is bound as bytes.** The browser serializes the body once, hashes those UTF-8 bytes, and sends the same
string. The server hashes the body exactly as it arrived, after every middleware; the body-size limit buffers a
body and passes on the same bytes, and nothing rewrites one. A proof therefore authorizes exactly one request:
any other body, including one that differs only in a field the server ignores, fails. A rotation for the largest
membership, 512 members with realistic wraps, is well under the 1 MiB limit for these routes, and the proof adds
under 2 KB.

### 5.3 MACs and header

```
K_role   = HKDF-SHA256(IKM = ECDH(private key of the role, server one-time public key) (48 bytes),
                       salt = "dv-zk-key-proof-v1", info = role, length 32)
role     = "identity" | "current-key" | "new-key"
mac_role = HMAC-SHA256(K_role, T)

X-ZK-Key-Proof: v1.<challenge id>.<mac_identity>.<mac_current or ->.<mac_new or ->
```

MACs are unpadded base64url of 32 bytes; `-` marks a MAC the operation does not use. The server computes each
expected MAC with its sealed one-time private key and the role's public key, and compares in constant time. The
salt, role names, label and table differ from registration (`dv-ecc-pop-v1`) and from envelope replacement
(`dv-ecc-update-pop-v1`) and from every wrap derivation, so no MAC, key or challenge crosses protocols.

Three MACs rather than one over concatenated secrets: the security is the same (each is over the same transcript
and challenge), and the server can record *which* role failed. A failed identity proof from a genuine session
almost always means someone else is using it.

**The server is not an oracle.** A malicious server could choose its one-time key equal to the ephemeral key of
one of a member's wraps, so that the browser's ECDH output equals that wrap's shared secret. The browser releases
only an HMAC under an HKDF key in a separate domain, which says nothing about the wrap key. WebCrypto and the
server's library reject off-curve points, and P-384 has cofactor 1.

A header rather than a body field: one helper guards every route, the body hash is well defined, and a future
`v2` is a prefix change. The name uses hyphens, which common proxies pass by default.

### 5.4 What each request carries

| Request | Op | Roles | Body additions |
|---|---|---|---|
| `POST /ecc/vaults/{id}/members` | share | identity, current-key | direct: `dek_version` is required with a proof |
| `PUT /ecc/vaults/{id}/index-key` | index_key | identity, current-key | none |
| `POST .../rekey`, direct | rekey | identity, current-key, new-key (`P_{n+1}`) | `next_key_proof: {public_key, sealed_private_key, dek_check}` for the new epoch, `lineage_tag` |
| `POST .../rekey`, hierarchical, DEK only | rekey | identity, current-key | `lineage_tag` |
| `POST .../rekey`, hierarchical, new team key | rekey | identity, current-key, new-key (the body's `team_public_key`) | `lineage_tag` |
| `POST .../rekey` with `owner_reset: true` | owner_reset | identity, new-key | as the matching rotation; `lineage_tag` when the owner can open the previous epoch; a hierarchical reset must replace the team key |
| `PUT /ecc/vaults/{id}/key-proof` | bootstrap | identity, new-key (`P_n`) | `{dek_epoch, public_key, sealed_private_key, dek_check}` |
| `POST /vaults`, zero-knowledge | create | identity, new-key (`P_1` or `team_public_key`) | direct: `key_proof: {public_key, sealed_private_key, dek_check}`; `id` is required with a proof |

An older server ignores the new body fields: none of these request models forbids extra fields.

The server cannot check that `S_{n+1}` really is sealed under DEK_{n+1}, and does not try: the rotator has just
proved they hold epoch *n*, and chose DEK_{n+1} anyway, so bogus material gives them no power they lack. The key
check lets members detect it.

### 5.5 How the server chooses the roles

From the operation in the challenge row and the locked vault, never from the request: the mode from the vault,
whether a verifier exists from its `vault_key_proofs` row, whether new material is installed from the operation
and mode. The only request input that lowers the bar is `owner_reset`, which needs a challenge issued for that
operation, the owner, a current key row, an interactive session and the step-up. A MAC the server does not
require is ignored.

### 5.6 Read side

`GET /ecc/vaults/{id}/keys` carries `key_proof` for the returned key version, only to someone with access:

- direct with a row: `{state: "set", source, created_at, public_key, dek_check, lineage_tag}`, plus
  `sealed_private_key` **only for someone who may manage the vault** (only managers make the guarded changes;
  plain members verify with the key check);
- direct without a row: `{state: "missing"}`;
- hierarchical: `{state: "team", source, lineage_tag}` when a row exists, else `{state: "team"}`.

`/keys?key_version=p` is how a member fetches an older epoch's tag and check. No read of files, names or keys
consults `vault_key_proofs`.

### 5.7 Refusal contract

Every refusal is a JSON body `{"detail": "<sentence>", "reason": "<slug>"}` with a plain-string `detail`, never a
401. Clients read only `detail`, with a substring test, and the web app, including the older one DockVault Desktop
bundles, signs a person out on a 403 whose detail contains `inactive`, `terminated` or `locked`, and treats one
containing `password`, `Password`, `Unauthorized` or `401` as a sign-in problem. No sentence contains any of these
(`locked` also rules out "unlocked").

| Status | When | `detail` | `reason` |
|---|---|---|---|
| 428 | no proof, enforcement on | "This change needs proof that you hold this vault's key, which this version of the app cannot give. Reload the page (or update DockVault Desktop) and try again." | `zk-key-proof-required` |
| 428 | a direct epoch without a proof key | "This vault's key check has not been set up yet. Open the vault once as a manager who holds its key, then try again." | `zk-key-proof-setup-required` |
| 400 | a malformed header or material (nothing consumed) | a sentence naming the shape problem | `zk-key-proof-malformed` |
| 403 | any failed proof: no live challenge, an expired one, a wrong MAC | "The proof that you hold this vault's key did not check out. Try again." | `zk-key-proof-failed` |
| 403 | a temporary credential at setup or owner reset | "A temporary credential cannot set up or reset a vault's key check." | `zk-key-proof-interactive-only` |
| 409 | the vault's key state moved since the challenge | "This vault's key changed while the change was being prepared. Try again." | `zk-key-proof-stale` |
| 409 | setting up an epoch that has a row | "This vault's key check was just set up by someone else. Try again." | `zk-key-proof-exists` |
| 409 | a team public key that is not a usable P-384 key | "This vault's key record is inconsistent. Its owner can reset the key." | `zk-key-proof-verifier-unusable` |

One sentence covers every failed proof: telling a caller which part failed helps only an attacker. The owner
reset's step-up keeps the existing step-up 403, which the web app answers with its prompt and a retry.

---

## 6. Server checks and their order

### 6.1 Rules every guarded route follows

1. **Shapes before consuming.** The header's syntax and the shape of every key and value in the body (a P-384
   PEM; a sealed key of 36..8192 bytes with the `DVZ2` header and purpose `0x07`; a 32-byte key check and lineage
   tag) are checked first. A malformed request gets 400 and consumes nothing, so an honest client cannot destroy
   its own challenge.
2. **The owner reset's step-up before consuming,** so the retry after the prompt still finds the challenge.
3. **Consume before the vault lock, in its own commit.** The challenge whose id, account, vault and operation all
   match is locked, captured and deleted, and that is committed. Missing or expired: 403, recorded. Consumption
   never depends on the outcome, so each guess costs a fresh, rate-limited challenge.
4. **Under the vault's row lock, in this order:** the caller holds the current key; the **state pin** (the live
   mode, DEK epoch, team epoch and the SHA-256 of the live verifier's point must equal the challenge's, else 409
   `zk-key-proof-stale`); the required MACs (else roll back, record the role that failed, 403). Only then is
   anything in the body used beyond hashing it and checking its shape.
5. **No commit between the lock and the final commit.** Failure paths roll back before recording.
6. With enforcement off and no proof, the route runs as before 0.33.2, records `zk_key_proof_absent`, and stores
   no proof material.

### 6.2 Per route

- **Rotation** (`POST /ecc/vaults/{id}/rekey`): the owner-reset step-up; the rate budget; the vault and the
  manager check; the header (428 when enforcing and absent); shapes; consume (`rekey`, or `owner_reset` when the
  body says so; a challenge issued for the other one is 400); the orphan-key cleanup; the lock; key holder;
  state pin; for an owner reset, the owner; MACs (current-key against the team public key or the epoch's row,
  skipped for an owner reset; new-key against the new proof key or the new team key; identity always). Then the
  existing checks and writes, with the team public key validated as P-384 and the point comparison of §3.3. The
  new epoch's `vault_key_proofs` row is inserted in the rotation's single commit.
- **Share** (`POST /ecc/vaults/{id}/members`): the existing checks that read only the target; the header, shapes,
  consume (`share`; a direct vault's proven share must name its `dek_version`); the lock; key holder; state pin;
  MACs; then the existing grant, which refuses a share made for any epoch but the current one.
- **Name-index key** (`PUT /ecc/vaults/{id}/index-key`): header, shapes, consume (`index_key`); the lock; key
  holder; state pin; MACs; the existing logic.
- **Setup** (`PUT /ecc/vaults/{id}/key-proof`): §4.2; the row is inserted with `source = bootstrap`, and a
  unique-constraint conflict becomes 409 `zk-key-proof-exists`.
- **Create** (`POST /vaults`, zero-knowledge): everything before the vault is built. The id is required with a
  proof, and the encryption-key check comes first; header, shapes, consume (`create`, for the requested id); no
  vault lock (the id is new and the primary key keeps it unique); MACs against the caller's registered key and
  `P_1` or the team public key; then the vault is created with its epoch-1 row in the same transaction,
  `source = create`.

### 6.3 Audit

| Action | Level | When |
|---|---|---|
| `zk_key_proof_failed` | warning | a proof failed; `reason` is `no_live_challenge`, `expired`, `identity`, `current_key` or `new_key` |
| `zk_key_proof_absent` | warning | a change accepted without a proof while enforcement is off |
| `zk_key_proof_bootstrapped` | notice | an epoch's key check was set up |
| `zk_owner_key_reset` | warning | the owner reset the vault's key |

`zk_vault_rekeyed`, `zk_member_key_granted` and `zk_index_key_wrapped` carry `proof`: `key`, `owner_reset` or
`absent`. The key-proof details are `op`, `reason`, `mode`, the epochs and `proof`; no entry holds a MAC, a nonce,
a challenge id or the body, and the `X-ZK-Key-Proof` header is never recorded.

---

## 7. Clients

### 7.1 `static/js/ecc_crypto.js`

| Operation | Does |
|---|---|
| `sealKeyProofKey(dek, vaultId, dekEpoch)` | makes `H_n`: its public PEM, `S_n`, the key check, and the private key re-imported non-extractable |
| `openKeyProofKey(sealed, publicKeyPem, dek, vaultId, dekEpoch)` | opens `S_n` and compares points; `WRAP_INVALID`, `WRAP_FAILED` or `KEY_MISMATCH` on failure |
| `dekCheck(dek, vaultId, dekEpoch)` | the key check of §3.5 |
| `keyLineageTag(prevDek, fields)`, `verifyKeyLineageTag(prevDek, fields, tag)` | the lineage tag of §3.6 |
| `teamPrivateKeyMatchesPublic(pkcs8, publicKeyPem)` | the team-key point comparison |
| `keyProofTranscript(params)`, `computeKeyProof(params, keys)` | the transcript of §5.2 and the header of §5.3 |

Error codes and their meaning are in `vault-client-crypto-errors-v1.md` §4.1. `ZK_KEY_PROOF_WRITE_FORMAT` is 1.

### 7.2 `static/js/app.js`

Every guarded request goes through one helper, `zkKeyProofRequest`:

1. Serialize the body once.
2. Unlock the identity key and get the current key material: the team private key, or the DEK at the body's epoch
   and the opened proof key. Prompts happen here, before the challenge, so its five minutes cover only computing.
   Concurrent callers share one unlock, so a locked bulk share asks for the passphrase once.
3. Ask for a challenge. A **404 whose body has no `reason`** means the server predates key proofs (an older or
   rolled-back server): the request is sent without a proof. A server with key proofs never answers the challenge
   route with 404 (a missing vault is 403), and only a server that checks proofs can refuse one, so this is safe.
4. Compare the challenge's mode and epochs with what the body was built for; a mismatch is a stale error the
   caller's retry handles. No verifier on a direct operation that needs one: set the epoch up, then start again
   once.
5. Open and check the verifier before using it (open `S_n` and compare points).
6. Compute the MACs and send with the header. On `zk-key-proof-failed`, retry once with a fresh challenge (which
   covers an expired one); on `zk-key-proof-setup-required`, set up and retry once; `zk-key-proof-stale` goes to
   the caller's own retry.

Creating a vault seals `H_1` (direct) or proves the new team key; a rotation opens the current proof key, makes
the next epoch's material and the lineage tag, and proves all three roles. **Removing a member is never held up by
the proof:** when the rotation that removal starts with fails on a key-proof reason, the web app offers "Remove
access now without rotating", which removes access and deactivates the person's key rows, and the vault then asks
its key holders to rotate. When the owner's proof key will not open, the web app offers the owner reset.

### 7.3 The compatibility rule

1. **Server.** A guarded request without a proof never half-applies. It gets 428 with a plain-string `detail` and a
   `reason`, never a 401 and none of the sign-out words. Reading, uploading, downloading and syncing never depend
   on proof material.
2. **New client, old server.** A client with key proofs recognises an older server by a 404 without a `reason` from
   the challenge route, and sends the request without a proof.
3. **Old client, new server.** A client without key proofs loses exactly the four changes, and, because removing a
   member from a zero-knowledge vault starts with a rotation, member removal. Everything else works and nobody is
   signed out. The operator can postpone enforcement with `ZK_KEY_PROOF_ENFORCE=false` while such clients are
   updated; each change then made without a proof is recorded as `zk_key_proof_absent`.
4. **Protocol changes.** A new header version is accepted by servers at least one minor release before any client
   sends it, and `v1` stays accepted while any supported DockVault Desktop build sends it. A new stored-material
   `format` ships its reader at least one minor release before its writer.

**DockVault Desktop** forwards API requests unchanged and serves a built-in web app. A build whose web app
predates 0.33.2, against a server that enforces the proof:

| Action | Result |
|---|---|
| Create a zero-knowledge vault | refused (428); nothing is created. Standard vaults are unaffected |
| Share a zero-knowledge vault | refused at the key grant, which that web app sends before the access grant, so no access is granted |
| Remove a member from a zero-knowledge vault | that web app rotates first, the rotation is refused, and it reports that access was not revoked; the member keeps access |
| Set the name-index key | refused, and ignored by that web app, which then uses its per-epoch name indices |
| Read, upload, download, sync | unchanged; nobody is signed out |

A build whose web app includes key proofs needs nothing from the operator. Syncing uses device credentials that
reach no zero-knowledge vault, and is unaffected either way.

### 7.4 Reverse proxies

The proof is a MAC over the exact request body, carried in the `X-ZK-Key-Proof` request header. A reverse proxy
must pass both on unchanged: it must not drop or rename the header, and must not re-encode, re-serialize or
decompress-and-rewrite JSON request bodies. Stock nginx and HAProxy do neither; the proxy matrix
(`.github/workflows/proxy-matrix.yml`) creates a zero-knowledge vault and rotates its key with proofs behind
nginx, nginx with TLS, two nginx in a chain, and HAProxy. A proxy that strips the header shows as
`zk-key-proof-required` on every such change; one that rewrites the body shows as `zk-key-proof-failed`.

---

## 8. Formats

- **No format any reader needs to open data changed.** DEK wraps, team wraps, file content, names and the identity
  envelope are untouched, and so are the key-wrap algorithm labels.
- **Proofs never become a read requirement.** No read path consults `vault_key_proofs`; a missing, damaged or
  unknown-format row can block a key change, never a read.
- **The new format (purpose `0x07`) is read only to make a proof or run a check,** by the web app the same server
  serves, so the writer and every reader ship together.
- **A future change** to the sealed key, the key check, the lineage tag or the transcript gets a new `format`
  value (the column on each row, and `ZK_KEY_PROOF_WRITE_FORMAT` in the browser module) and ships its reader at
  least one minor release before its writer, and not before DockVault Desktop's built-in web app contains the
  reader. The server stores material without parsing its format.

---

## 9. Upgrade and rollback

- **Upgrading to 0.33.2** adds the two tables; nothing is migrated or deleted. Hierarchical vaults are covered at
  once; a direct vault's current epoch gets its key check the first time a manager who holds the key makes one of
  these changes (the web app does it on demand). Reload browser tabs opened before the upgrade.
- **Rolling back below 0.33.2** strands nothing: the older release ignores the tables, their delete rules still
  fire, and no wrap, content, name or envelope format changed. The protection is off while rolled back. A browser
  tab of 0.33.2 left open against the older server recognises it (§7.2) and keeps working.
- **Upgrading again:** a direct epoch rotated while rolled back has no row; it reads `state: missing` and is set up
  the next time a manager changes it. Changes without a proof are refused again. This is tested with real Docker
  (`tests/test_zk_key_proof_rollback_drill.py`).

---

## 10. Tests

| Kind | Where |
|---|---|
| Frozen vectors (transcripts per operation and mode, MACs per role, headers, the seal, key checks, lineage tags), reproduced by the server, the reference and `ecc_crypto.js` under Node; domain separation; the strict decrypt | `tests/test_zk_key_proof_v1.py`, `tests/fixtures/crypto/zk-key-proof-v1/` |
| The refusal contract and the forbidden words | `tests/test_zk_key_proof_refusals.py` |
| The switch, and the settings page refusing it | `tests/test_zk_key_proof_switch.py`, `tests/test_zk_key_proof_switch_live.py` |
| The tables, their constraints and delete rules, the challenge purge | `tests/test_zk_key_proof_schema.py`, `tests/test_zk_key_proof_schema_live.py` |
| The challenge route: its checks, sealing, the cap, the budget | `tests/test_zk_key_proof_challenge.py`, `tests/test_zk_key_proof_challenge_live.py` |
| Each guarded route with the lock observable: consumption, shapes, roles, the state pin, the switch, setup, owner reset | `tests/test_zk_key_proof_handler.py` |
| Source pins: the order of checks in each route; every writer of key material is a guarded route; only setup and the owner reset skip the current key | `tests/test_zk_key_proof_pins.py` |
| Live: a session without the identity key changes nothing; knowing the key is not enough; replay and body binding; races under the lock; rotations; create; setup; owner reset; the read side; retire; audit rows hold no proof | `tests/test_zk_key_proof_live.py` |
| The web app: every guarded request goes through the helper; the string proved is the string sent; an older server is recognised | `tests/test_zk_key_proof_client.py`, `tests/test_ui_zk_key_proof.py` |
| The v0.27.0 web app against an enforcing server | `tests/test_ui_zk_key_proof_old_bundle.py` |
| A rollback and a return, with real Docker | `tests/test_zk_key_proof_rollback_drill.py` |
| Behind each proxy | `.github/scripts/proxy_matrix.py` |
| This document against the code: the labels, bytes, bounds, limits, refusals, audit actions and switch it states | `tests/test_zk_key_proof_doc.py` |
