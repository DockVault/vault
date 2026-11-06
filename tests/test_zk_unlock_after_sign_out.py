"""An unlock of the account key still running at a sign-out keeps nothing for the next person on the tab
(static/js/app.js: _zkSteps, _zkUnlockOnce, zkEnsureUnlocked, zkGetVaultIndexKey, zkMintOwnIndexKey), run under
Node with the shipped functions lifted out verbatim and every step of the unlock answered when the test chooses.

Held here: a sign-out at any step of an unlock (the envelope read, the public key read, the passphrase prompt, the
key's derivation, the check against the registered key, the key's import) ends it there: the key is not kept, no
later step is begun (no request with the next person's session), and its promise never settles (nothing of it is
shown to the next person); without a sign-out it unlocks as before. The next person's first unlock is their own,
and the finish of the earlier one does not end it. A name-index key read or minted across a sign-out is kept in
the cache it was read for, not in the next person's. The same holds for the four operations of the encryption key
dialog (zkRegisterNewKeypair, zkChangePassphrase, zkExportRecoveryKey, zkRestoreFromRecoveryKey): a sign-out at any
of their steps ends them there, with no later prompt, request, key or recovery kit download.
tests/test_ui_zk_unlock_sign_out.py holds the same in a real browser.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name: str) -> str:
    decl = re.search(r"^(async )?function " + re.escape(name) + r"\(", APP, re.M)
    assert decl, name
    return APP[decl.start():APP.index("\n}\n", decl.start()) + 3]


SHIPPED = "".join(_function(n) for n in ("_zkLeftBehind", "_zkSteps", "zkEnsureUnlocked", "_zkUnlockOnce"))

# Each step of the unlock is a promise the test settles; `signOut` is what logout() does to the unlock.
HARNESS = """
let _zkUnlockInFlight = null;
let _zkSignOuts = 0;
const zkState = { privateKey: null };
const begun = [];
const waiting = {};
const held = (name) => (...args) => { begun.push(name); return new Promise((resolve, reject) => { waiting[name] = { resolve, reject }; }); };
const zkFetchPrivateEnvelope = held('envelope');
const apiRequest = held('public');
const showPrompt = held('prompt');
const lib = {
  parsePrivateEnvelope: () => ({}),
  decryptPrivateEnvelope: held('derive'),
  privateKeyMatchesRegisteredPublicKey: held('match'),
  importPrivateKeyPEM: held('import'),
};
const eccLib = () => lib;
const safeMessageForCode = () => 'could not unlock';
let armed = 0;
const zkArmIdleLock = () => { armed++; };
const zkAfterUnlock = () => {};
const zkNudgeWeakPassphrase = () => {};
const signOut = () => { _zkSignOuts += 1; _zkUnlockInFlight = null; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const ANSWERS = {
  envelope: { has_keypair: true, encrypted_private_key: 'sealed' },
  public: { public_key: 'PUB' },
  prompt: 'the passphrase',
  derive: 'PEM',
  match: true,
  import: 'THE-KEY',
};
const STEPS = ['envelope', 'public', 'prompt', 'derive', 'match', 'import'];
const outcome = (p) => Promise.race([
  p.then((v) => 'unlocked: ' + v, (e) => 'failed: ' + e.message),
  new Promise((r) => setTimeout(() => r('pending'), 50)),
]);
"""


def _node(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=HARNESS + SHIPPED + "\n(async () => {\n" + script + "\n})();\n",
                          capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


STEPS = ["envelope", "public", "prompt", "derive", "match", "import"]


@pytest.mark.parametrize("at", STEPS + [None])
def test_a_sign_out_during_any_step_of_an_unlock_keeps_no_key_and_begins_no_later_step(at):
    out = _node(f"""
const at = {json.dumps(at)};
const p = zkEnsureUnlocked();
for (const name of STEPS) {{
  await tick();
  if (!waiting[name]) break;
  if (name === at) signOut();
  waiting[name].resolve(ANSWERS[name]);
}}
await tick();
console.log(JSON.stringify({{ got: await outcome(p), key: zkState.privateKey, armed, begun, inFlight: _zkUnlockInFlight === null ? null : 'kept' }}));
""")
    if at is None:      # the control: no sign-out, the key is unlocked and kept
        assert out == {"got": "unlocked: THE-KEY", "key": "THE-KEY", "armed": 1, "begun": STEPS, "inFlight": None}
    else:
        assert out["got"] == "pending" and out["key"] is None and out["armed"] == 0, out
        assert out["begun"] == STEPS[:STEPS.index(at) + 1], out
        assert out["inFlight"] is None, out


@pytest.mark.parametrize("signed_out", [True, False])
@pytest.mark.parametrize("at", STEPS)
def test_a_step_that_fails_after_a_sign_out_says_nothing(at, signed_out):
    """A step that fails once the person has signed out (a read refused for want of a session, the prompt answered
    as cancelled by the sign-out) is not reported to the next person; without a sign-out it is (the control)."""
    out = _node(f"""
const p = zkEnsureUnlocked();
p.catch(() => {{}});                         // read below; not a rejection nobody handles
for (const name of STEPS) {{
  await tick();
  if (!waiting[name]) break;
  if (name === {json.dumps(at)}) {{
    if ({json.dumps(signed_out)}) signOut();
    waiting[name].reject(new Error('refused'));
    break;
  }}
  waiting[name].resolve(ANSWERS[name]);
}}
await tick();
console.log(JSON.stringify({{ got: await outcome(p), key: zkState.privateKey }}));
""")
    if signed_out:
        assert out == {"got": "pending", "key": None}
    else:
        assert out["got"].startswith("failed: ") and out["key"] is None, out


def test_the_next_persons_first_unlock_is_their_own():
    """Signed out while the first person's key is derived: the next person's first unlock asks for their own envelope
    (it does not join the first one's, which would hand them its key), and the first one's end leaves it running."""
    out = _node("""
const first = zkEnsureUnlocked();
for (const name of ['envelope', 'public', 'prompt']) { await tick(); waiting[name].resolve(ANSWERS[name]); }
await tick();
signOut();                                   // the key's derivation is still running
const firstDerive = waiting.derive;
delete waiting.envelope;
begun.length = 0;
const next = zkEnsureUnlocked();             // the next person's first unlock
await tick();
const nextBegan = begun.slice();
firstDerive.resolve('PEM');                  // the first one's derivation ends
await tick();
console.log(JSON.stringify({ nextBegan, nextInFlight: _zkUnlockInFlight !== null, first: await outcome(first),
  next: await outcome(next), key: zkState.privateKey }));
""")
    assert out == {"nextBegan": ["envelope"], "nextInFlight": True, "first": "pending", "next": "pending",
                   "key": None}


def test_work_not_yet_begun_is_not_begun_after_a_sign_out():
    """A step begun after a sign-out (the setup's registration, the change's or restore's new envelope, after a key
    derivation that ran across it) is not begun: no request goes with the next person's session."""
    out = _node("""
const step = _zkSteps();
signOut();
const p = step(() => { begun.push('write'); return Promise.resolve('sent'); });
const same = _zkSteps();
const q = same(() => { begun.push('own'); return Promise.resolve('sent'); });
console.log(JSON.stringify({ got: await outcome(p), own: await outcome(q), begun }));
""")
    assert out == {"got": "pending", "own": "unlocked: sent", "begun": ["own"]}


INDEX = "".join(_function(n) for n in ("zkGetVaultIndexKey",)) + """
const zkState = { vaultIndexKeys: {} };
let answer;
const apiRequest = () => new Promise((resolve) => { answer = resolve; });
const zkEnsureUnlocked = async () => 'priv';
const eccLib = () => ({ unwrapNameIndexKeyV2: async () => 'THEIR-KEY' });
"""


@pytest.mark.parametrize("reply", [{"index_key": "w", "ephemeral_public_key": "e", "recipient_user_id": "u"}, {}])
def test_a_name_index_key_read_across_a_sign_out_is_kept_in_the_cache_it_was_read_for(reply):
    node = shutil.which("node")
    assert node, "Node is required"
    script = INDEX + f"""
(async () => {{
  const before = zkState.vaultIndexKeys;
  const p = zkGetVaultIndexKey('V');
  zkState.vaultIndexKeys = {{}};              // a sign-out (or a lock) replaces the cache
  answer({json.dumps(reply)});
  const got = await p;
  console.log(JSON.stringify({{ got, next: zkState.vaultIndexKeys, before }}));
}})();
"""
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    out = json.loads(done.stdout)
    assert out["next"] == {}, "kept in the next person's cache"
    assert out["before"] == {"V": out["got"] if out["got"] is not None else False}


# The four operations of the encryption key dialog, lifted out verbatim with the steps they run on. Every prompt,
# request, derivation and import is held until the test answers it, in the order the operation asks.
KEYOPS_SHIPPED = "".join(_function(n) for n in (
    "_zkLeftBehind", "_zkSteps", "zkRegisterNewKeypair", "zkChangePassphrase", "zkExportRecoveryKey",
    "zkRestoreFromRecoveryKey"))

KEYOPS_HARNESS = """
let _zkUnlockInFlight = null;
let _zkSignOuts = 0;
const zkState = { privateKey: null };
const begun = [];
const queue = [];
const held = (name) => (...args) => { begun.push(name); return new Promise((resolve, reject) => { queue.push({ name, resolve, reject }); }); };
const showConfirm = held('confirm');
const showPrompt = held('prompt');
const zkFetchPrivateEnvelope = held('envelope');
const zkPutPrivateEnvelope = held('put');
const zkWrapPrivateKey = held('wrap');
const apiRequest = (path) => held('api ' + path)();
const lib = {
  parsePrivateEnvelope: () => ({}),
  parseRecoveryKitFile: () => ({ kit: { public_key: 'PUB', recovery: 'sealed for recovery' } }),
  decryptPrivateEnvelope: held('derive'),
  derivePublicKeyPEMFromPrivatePEM: held('public from private'),
  privateKeyMatchesRegisteredPublicKey: held('match'),
  importPrivateKeyPEM: held('import'),
  generateKeypair: held('generate'),
  exportPublicKeyPEM: held('export public'),
  exportPrivateKeyPEM: held('export private'),
  computeRegistrationPoP: held('proof'),
};
const eccLib = () => lib;
const safeMessageForCode = () => 'could not';
const zkPassphraseProblem = () => null;
const zkIsPossessionChallengeRefusal = () => false;
let armed = 0;
const zkArmIdleLock = () => { armed++; };
const downloads = [];
const document = {
  createElement: () => ({ click() { downloads.push(this.download); }, remove() {} }),
  body: { appendChild() {} },
};
const ANSWER = {
  confirm: true,
  prompt: 'a long enough passphrase',
  envelope: { has_keypair: true, encrypted_private_key: 'sealed' },
  put: {},
  wrap: { sealed: 'anew' },
  'api /ecc/keys/public': { has_keypair: true, public_key: 'PUB', user_id: 'u', fingerprint: 'fp' },
  'api /ecc/keys/register/challenge': { server_ephemeral_public_key: 'E', nonce: 'N', challenge_id: 'C' },
  'api /ecc/keys/register': {},
  derive: 'PEM',
  'public from private': 'PUB',
  match: true,
  import: 'THE-KEY',
  generate: { publicKey: 'pk', privateKey: 'sk' },
  'export public': 'PUB',
  'export private': 'PEM',
  proof: 'MAC',
};
const OPS = {
  setup: () => zkRegisterNewKeypair(),
  change: () => zkChangePassphrase(),
  export: () => zkExportRecoveryKey(),
  restore: () => zkRestoreFromRecoveryKey('{}'),
};
const signOut = () => { _zkSignOuts += 1; _zkUnlockInFlight = null; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const outcome = (p) => Promise.race([
  p.then(() => 'done', (e) => 'failed: ' + e.message),
  new Promise((r) => setTimeout(() => r('pending'), 50)),
]);
"""

# What each operation asks for, in order, when nobody signs out.
KEYOPS = {
    "setup": ["confirm", "prompt", "prompt", "generate", "export public", "export private", "wrap",
              "api /ecc/keys/register/challenge", "proof", "api /ecc/keys/register", "import"],
    "change": ["envelope", "prompt", "derive", "api /ecc/keys/public", "match", "prompt", "prompt", "wrap", "import",
               "put", "import"],
    "export": ["envelope", "prompt", "derive", "api /ecc/keys/public", "match", "prompt", "prompt", "wrap"],
    "restore": ["api /ecc/keys/public", "prompt", "derive", "public from private", "match", "prompt", "prompt", "wrap",
                "import", "put", "import"],
}


def _keyop(op: str, at, fail: bool = False) -> dict:
    """Run one operation, answering each step in turn; at step `at` (an index, or None) the person signs out while
    it is on its way, and it then succeeds, or fails when `fail`."""
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = KEYOPS_HARNESS + KEYOPS_SHIPPED + f"""
(async () => {{
  const p = OPS[{json.dumps(op)}]();
  p.catch(() => {{}});                         // read below; not a rejection nobody handles
  for (let i = 0; ; i++) {{
    await tick();
    const w = queue.shift();
    if (!w) break;
    if (i === {json.dumps(at)}) {{
      signOut();
      if ({json.dumps(fail)}) {{ w.reject(new Error('refused')); continue; }}
    }} else if ({json.dumps(fail)} && {json.dumps(at)} === null && i === 0) {{
      w.reject(new Error('refused'));
      continue;
    }}
    w.resolve(ANSWER[w.name]);
  }}
  await tick();
  console.log(JSON.stringify({{ got: await outcome(p), key: zkState.privateKey, armed, begun, downloads: downloads.length }}));
}})();
"""
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("op", sorted(KEYOPS))
def test_a_key_operation_nobody_signs_out_of_runs_to_its_end(op):
    """The control: every step is asked for in turn, and the key is kept (or, for the export, the kit downloaded)."""
    out = _keyop(op, None)
    assert out["begun"] == KEYOPS[op] and out["got"] == "done", out
    if op == "export":
        assert out["downloads"] == 1 and out["key"] is None and out["armed"] == 0, out
    else:
        assert out["key"] == "THE-KEY" and out["armed"] == 1 and out["downloads"] == 0, out


@pytest.mark.parametrize("op,at", [(op, at) for op in sorted(KEYOPS) for at in range(len(KEYOPS[op]))])
def test_a_key_operation_signed_out_of_at_any_step_ends_there(op, at):
    """A sign-out while a step is on its way ends the operation when that step comes back: no later step (no
    prompt, no request with the next person's session), no key kept, no recovery kit downloaded, nothing said."""
    out = _keyop(op, at)
    assert out == {"got": "pending", "key": None, "armed": 0, "begun": KEYOPS[op][:at + 1], "downloads": 0}


@pytest.mark.parametrize("op,at", [(op, at) for op in sorted(KEYOPS) for at in range(len(KEYOPS[op]))])
def test_a_key_operation_step_failing_after_a_sign_out_says_nothing(op, at):
    """A step that fails once the person has signed out (a read refused for want of a session, a prompt answered as
    cancelled by the sign-out) is not reported to the next person."""
    out = _keyop(op, at, fail=True)
    assert out == {"got": "pending", "key": None, "armed": 0, "begun": KEYOPS[op][:at + 1], "downloads": 0}


@pytest.mark.parametrize("op", sorted(KEYOPS))
def test_a_key_operation_step_failing_while_signed_in_is_reported(op):
    """The control: the same failure without a sign-out ends the operation with an error its caller shows."""
    out = _keyop(op, None, fail=True)
    assert out["got"].startswith("failed: ") and out["begun"] == KEYOPS[op][:1] and out["key"] is None, out
