# DockVault public crypto compatibility vectors

These fixtures pin the persisted and browser-side cryptographic formats that
DockVault `v0.10.0` (commit `1a1b8fa9e1e80ca78d9a4154cfdb391f3f3c53a8`)
could read. They are compatibility contracts, not examples for deployments.

Every key, private scalar, passphrase, nonce, IV, and plaintext here is public,
deterministic test material. Never copy any of it into a real deployment.

The vectors are generated and checked by the independent implementation in
`tests/crypto_reference_vectors.py`, which intentionally imports no application
module. `tests/js/crypto_compatibility_vectors.js` additionally exercises the
real shipped `static/js/ecc_crypto.js` through Node's Web Crypto implementation.
The manifest contains the SHA-256 of every JSON vector and rejects unreviewed
additions.

The set covers:

- Standard-vault AES-GCM chunk stream version `0x10`;
- the legacy Standard-vault Fernet chunk stream reader;
- unversioned zero-knowledge content (`iv || ciphertext || tag`);
- the password-encrypted identity-private-key envelope;
- direct ECDH/HKDF/AES-KW DEK wrapping;
- hierarchical ECDH/HKDF/AES-GCM team-private-key wrapping;
- legacy `zk1:` and object-bound `zk2:` encrypted names and blind indexes.

The identity-private-key plaintext is the exact PEM text produced by the shipped
browser exporter. Its PKCS#8 DER is canonical and runtime-derived from the public
test scalar; the PEM text has no terminal newline. That final-byte rule is part
of the writer compatibility contract and is tested explicitly without storing a
private-key encoding in the fixture set.

Changing a readable encoding requires an additive reader/migration decision and
new vectors. Existing published bytes must not be silently reinterpreted.
