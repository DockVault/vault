# Proof-bound private-key replacement, version 1

Status: **frozen for implementation**. Written and reviewed before the endpoint changes, so the
transcript, domain separation, issuance and consumption rules, rate budget and error behaviour are
fixed before anything depends on them.

## 1. The problem

A DockVault account's zero-knowledge identity is a P-384 keypair. The public key is registered once
and is effectively permanent: registration is first-write-wins, there is no rotation, and every
vault key the account can open is wrapped to that public key. The private key is stored only as an
opaque passphrase-encrypted envelope (see `vault-private-key-envelope-v1.md`).

Registering that public key already requires proof that the caller holds the matching private key.
**Replacing the stored envelope does not.** `PUT /ecc/keys/private` accepts a new blob from any
ordinary session for that account.

That is not a disclosure problem — the server cannot read either the old or the new blob, and the
attacker gains no key material. It is an **availability and recovery-integrity** problem, and the
damage is permanent:

- Overwrite the envelope with anything, and the legitimate owner can no longer decrypt their
  identity key. Every wrapped vault key remains wrapped to a public key whose private half is now
  unreachable.
- There is no way back. Registration returns `409 Conflict` while a keypair exists, and removing
  the keypair would orphan every wrap. Recovery only helps if the user still holds a recovery kit
  made *before* the overwrite.

So a session that should only be able to *read* an account's vaults can instead destroy access to
all of them, silently, and the account owner discovers it at the next unlock.

The fix is to require the caller to prove — at replacement time — that they hold the private key
that is currently registered.

## 2. What this does not change

- **The public key, its fingerprint, and every wrapped DEK stay exactly as they are.** This is a
  passphrase change, not a key rotation. Nothing re-wraps.
- **The server still never sees private-key material.** It verifies a MAC computed by the client;
  it does not, and must not, need the plaintext key to do so.
- **Recovery keeps working.** A valid recovery kit reconstructs the *same* private key, so the
  recovery client can answer the challenge exactly as the normal client does. Recovery is the flow
  that most needs replacement to work, and it is the flow least able to tolerate a false refusal.
- **A malicious holder of the genuine key can still self-lock.** Proof of possession proves
  possession, nothing more. Someone who legitimately holds the key can always replace the envelope
  with a wrong one. That is out of scope and cannot be solved here.
- **The replacement path stays format-blind.** It accepts whatever byte string the client produces,
  in either the legacy or the v1 envelope shape, and the server never distinguishes them. This is
  load-bearing, not incidental: it is what keeps enabling the v1 writer a client-only decision
  instead of a coordinated client-and-server release. It deserves a test that a legacy-shape and a
  v1-shape replacement each succeed against an unchanged server.

## 3. Domain separation from registration

Registration PoP already exists. It derives its MAC key by ECDH against a server ephemeral key,
through HKDF with salt `dv-ecc-pop-v1` and info `registration-pop`, and MACs `nonce ‖ public_key_pem`.

Update PoP reuses the *shape* — a server ephemeral key, ECDH, HKDF, HMAC — because that shape is
already implemented, reviewed and understood. It must not reuse the *domain*:

| | Registration | Update |
|---|---|---|
| HKDF salt | `dv-ecc-pop-v1` | `dv-ecc-update-pop-v1` |
| HKDF info | `registration-pop` | `private-key-update-pop` |
| Storage | `ecc_registration_challenges` | `ecc_key_update_challenges` |
| Transcript | `nonce ‖ public_key_pem` | §4 below |

**Separate tables, not a `purpose` column.** A shared table with a discriminator makes cross-use a
query-filter bug away; two tables make it a type error. A challenge issued for one purpose is not
merely rejected by the other — it is not reachable by it.

The distinct HKDF domain means that even if a challenge row were somehow presented to the wrong
verifier, the derived MAC key differs and the MAC cannot validate.

## 4. The transcript

The client proves possession by MACing a transcript that binds *what is being replaced with what*,
not merely *that a key is held*. Without that binding, a MAC captured from one replacement could
authorise a different one.

```
transcript = SHA-256(
    "dockvault-private-key-update-pop-v1"  ‖ 0x00 ‖
    challenge_id_canonical_uuid_ascii      ‖ 0x00 ‖
    nonce_bytes                            ‖ 0x00 ‖
    user_uuid_canonical_ascii              ‖ 0x00 ‖
    SHA-256(registered_public_point_97)    ‖ 0x00 ‖
    SHA-256(replacement_envelope_utf8)
)
mac = HMAC-SHA256(mac_key, transcript)
```

Each element earns its place:

- **The protocol label** separates this from every other MAC in the system, including a future v2.
- **The challenge id and nonce** make the proof one-time and tie it to this exact issuance.
- **The user UUID** stops a proof produced for one account being presented for another, even if an
  attacker could induce a victim's client to sign.
- **The registered public point**, hashed as the canonical uncompressed 97-byte form, binds the
  proof to the key actually on record. Hashing the *point* rather than the PEM means cosmetic
  re-encoding of the stored PEM cannot invalidate a genuine proof — the same reasoning as the
  consistency check in the envelope design.
- **The replacement envelope digest** is what makes the proof *bound* rather than merely present.
  A MAC that authorised one replacement cannot be reused to install a different one, because the
  transcript would differ. The digest is over the exact UTF-8 bytes the client will send, so the
  server verifies against precisely what it is about to store — not a re-serialisation of it.

**`0x00` separators.** Every element is fixed-length or hex/ASCII except the nonce, and the
separators make the concatenation unambiguous regardless. This costs nothing and removes a class of
ambiguity attack outright.

The MAC key is derived exactly as registration derives it, but under the update domain:

```
shared  = ECDH(server_ephemeral_private, registered_public_key)
mac_key = HKDF-SHA256(shared, salt="dv-ecc-update-pop-v1", info="private-key-update-pop", len=32)
```

ECDH against the **registered** public key is what makes this a proof of possession: only the
holder of the matching private key can derive the same shared secret.

### 4.1 Encoding, pinned

To leave nothing for two implementers to resolve differently: both SHA-256 results and the outer
transcript digest are **32 raw bytes**, fed to HMAC as bytes rather than as hex; `nonce_bytes` is
the base64-**decoded** nonce, not the base64 text the issuance endpoint returns; and both UUIDs are
RFC 4122 lowercase canonical form.

The implementation must pin a v1 transcript fixture — the six inputs, the resulting transcript
digest and the MAC — reproduced by **both** the Python verifier and the real shipped browser module
executed under the existing Node vector harness. A Python-only mirror does not discharge this: it
agrees with the server by construction and would leave a browser-side divergence green in CI. The
sibling envelope design already requires the same treatment for a far simpler transcript, and the
infrastructure to do it exists.

Unlike the envelope, drift here is **not** unrecoverable — a mismatched transcript refuses the
write and leaves both the stored envelope and any recovery kit untouched. The fixture is about
catching a client/server divergence before it reaches a user, not about preventing data loss.

## 5. Issuance

`POST /ecc/keys/private/challenge`, authenticated, returns
`{challenge_id, server_ephemeral_public_key, nonce}`.

- **Interactive sessions only.** A temporary credential may not issue or consume an update
  challenge, mirroring the existing refusal on registration and on `PUT /ecc/keys/private`. A
  scoped credential has no business replacing the account's permanent identity envelope.
- **Requires an existing keypair.** With no keypair there is nothing to replace and nothing to
  prove against; return the same refusal shape as any other ineligible caller.
- **Exactly one live challenge per user.** Issuance takes a row lock on the owning user
  (`SELECT … FOR UPDATE`), deletes any prior challenge for that user, inserts the new one, and
  commits. The lock is the point: without it two concurrent issuances can interleave their
  delete/insert and leave two live challenges, which multiplies the attacker's attempts per
  round-trip. A newer challenge always invalidates the older.
- **Five-minute TTL**, measured server-side from `created_at`. Expiry is checked *after* the
  challenge is consumed, so an expired challenge is spent rather than left for a retry.

## 6. Consumption, and the order that matters

`PUT /ecc/keys/private` now requires `{encrypted_private_key, pop: {challenge_id, mac}}`.

The order is deliberate and is the security-relevant part of this design:

1. **Validate the request first — without parsing the envelope.** `encrypted_private_key` is
   present and a non-empty string whose UTF-8 encoding is at most 16,384 bytes; `pop.challenge_id`
   is a canonical UUID; `pop.mac` is a non-empty string. That is all.

   **The server does not parse the envelope and must not learn its format.** The envelope design
   keeps the server format-agnostic and says so explicitly, and the transcript's
   `SHA-256(replacement_envelope_utf8)` already binds the stored bytes to the proof, so parsing
   would add coupling without adding a guarantee. It would also actively break things: the v1
   writer ships disabled, so today's client submits the legacy shape — a server that enforced the
   v1 grammar would reject every replacement the shipping client makes.

   The size cap is on **UTF-8 bytes**, not characters, so it cannot drift from the client-side
   check as soon as a non-ASCII byte appears.

   A request failing these checks is rejected here and **does not consume a challenge**.

   *Why that ordering, stated honestly:* it is not a defence against a determined attacker. A
   same-account attacker can read the current envelope from `GET /ecc/keys/private` and resubmit it
   with a wrong MAC, burning an in-flight challenge whatever the ordering. What it does buy is that
   an honest client does not destroy its own in-flight challenge with a malformed request, and that
   the server does not do work on unbounded input. The rate budget in §7, plus one-time
   consumption, is what actually bounds an attacker.
2. **Then claim the challenge**, under a row lock, and **delete it in the same transaction, before
   verifying the MAC.** Consumption must not depend on the verification result. If a failed MAC
   left the challenge alive, an attacker could brute-force MACs against one issuance; the whole
   point of one-time is that a wrong answer costs a round-trip to the issuance endpoint, which is
   itself rate-limited.
3. **Then check expiry**, then verify the MAC, then write.

So: *malformed never consumes; well-formed always consumes, pass or fail.*

The update is applied only after a valid MAC. The public key, fingerprint and every
`vault_member_keys` row are untouched by this path.

## 7. Rate budget

Both routes carry their own bounded, authenticated rate limit, separate from the registration
bucket so that exhausting one cannot lock out the other:

- issuance: 10 per 15 minutes per user;
- verification: 10 per 15 minutes per user.

These are deliberately generous relative to legitimate use — a passphrase change or a recovery
restore is a once-in-a-long-while action — and tight relative to guessing. Combined with one-time
consumption, an attacker gets at most ten MAC attempts per quarter hour, each requiring a fresh
issuance, against a 256-bit MAC.

## 8. Errors

Every failure on the replacement path returns **one status and one message**: `400`, with a single
neutral detail. Distinguishing "no such challenge" from "expired" from "wrong MAC" from "wrong
user" would tell an attacker which part of their attempt was wrong, and none of those distinctions
help a legitimate client, whose only correct response to any of them is to request a fresh
challenge and retry.

The one case reported distinctly is a **malformed request** — a missing or empty field, a
challenge id that is not a UUID, or a replacement over the size cap. That is a client-side bug the
caller can act on, it is detected before any challenge is consumed, and it reveals nothing about
the challenge, the key, or the envelope's contents. Note this is a statement about the request
envelope's *shape*, not its *format*: per §6 the server never learns whether the replacement is a
legacy or a v1 envelope.

No error, log or audit record contains envelope bytes, MAC bytes, nonce, passphrase or key
material.

## 9. Audit

A successful replacement writes one audit event recording that the account's private-key envelope
was replaced, with the user and timestamp.

**Failed proofs are audited too**, with a short reason code and never the attempted MAC, nonce or
envelope bytes. This follows the pattern already used for a failed second-factor proof elsewhere in
the product, which records the failure and a reason code but never the attempted value.

An earlier draft argued failures should go unrecorded because auditing them would let a flood fill
the table. That reasoning does not survive contact with the code: both routes are authenticated,
§7 caps failures at ten per fifteen minutes per user, and genuinely unauthenticated failed logins
are already audited. Suppressing failures would have discarded the one signal that shows this
control firing while keeping the one outcome §11 admits it cannot prevent.

Two limits stated plainly rather than implied:

- **The audit log is operator-visible, not owner-visible.** Its endpoints are admin-only, and the
  product has no user-facing security-event feed for this. So these records inform whoever runs the
  deployment; they do not notify the account owner that someone tried to replace their key. If
  owner notification is wanted it is separate work, and it should reuse the existing per-user
  notification channel rather than pretend an audit row does the job.
- **The rate limiter fails open.** It defaults to allowing requests when its backing store is
  unavailable, so during such an outage there is no rate limit on these routes. Auditing failures
  is what keeps an attempt burst visible in exactly that window, which is a second reason not to
  suppress them.

No audit record contains envelope bytes, MAC bytes, nonce, passphrase or key material.

## 10. Recovery

Recovery restore is the flow this must not break. The sequence is unchanged except that the final
write now carries a proof:

1. The user supplies a recovery kit and its passphrase.
2. The client decrypts it to the account private key and — per the envelope design — verifies that
   key against the registered public key as canonical raw points.
3. The client requests an update challenge and answers it **with the recovered key**, which is by
   definition the registered one.
4. The client re-wraps under the new passphrase and submits envelope plus proof.

This works precisely because recovery reconstructs the same key. If it did not, the check in step 2
would already have failed and the flow would have stopped before touching the stored envelope.

**The official client verifies the replacement plaintext before submitting**: it decrypts what it
is about to upload and confirms it recovers the same key. A client bug that produced an
undecryptable envelope would otherwise be indistinguishable, to the server, from a correct one.

## 11. What this does and does not defend against

Defended: any session that does not hold the registered private key can no longer replace the
stored envelope. That closes the account-wide availability attack described in §1.

Not defended, and not claimed:

- A holder of the genuine private key replacing the envelope with a bad one. Possession is what is
  proven; intent is not provable.
- An operator serving modified client JavaScript, who can capture the passphrase or the key
  directly and does not need this path at all.
- Loss of both the passphrase and every recovery kit. That remains unrecoverable by design, and no
  amount of proof-binding changes it.

## 12. Out of scope

- Key rotation, or any change to the registered public key.
- Re-wrapping vault keys.
- Any server-side parsing, validation or format-awareness of the envelope. The server stores the
  bytes the proof covers, verbatim, exactly as the envelope design requires.
