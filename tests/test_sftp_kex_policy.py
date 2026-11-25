"""How an SFTP connection agrees its session keys (app/sftp/kex_policy.py, SFTP_KEX_POLICY; the transport in
app/sftp/sftp_server.py).

File bytes of a Standard vault travel inside SSH. What is recorded today can be decrypted later by whoever breaks
the classical key exchange; the hybrid exchange mlkem768x25519-sha256 (ML-KEM-768 with X25519) is not broken by
that. The SSH library offers it first. The policy only takes away: nothing by default, every other exchange
under pq-required. The exchange a connection agreed is kept on its transport and said once in the log.
test_sftp_post_quantum_live.py drives real clients against a running stack.
"""
import inspect
import socket
import types
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HYBRID = "mlkem768x25519-sha256"
CLASSICAL = ("curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256")


def _library(with_the_hybrid=True):
    """A stand-in for the SSH library's transport class: what it offers, in its order."""
    return types.SimpleNamespace(_preferred_kex=((HYBRID,) if with_the_hybrid else ()) + CLASSICAL)


def test_the_policy_takes_nothing_away_by_default_and_everything_else_when_the_hybrid_is_required():
    from app.sftp import kex_policy as K
    assert K.HYBRID == HYBRID and K.POLICIES == ("default", "pq-required")
    assert K.policy(None) == K.policy("") == K.policy("nonsense") == "default"
    assert K.policy(" PQ-Required ") == "pq-required" and K.policy("default") == "default"
    # No third value: one that "prefers" the hybrid exchange could do nothing the default does not, because the
    # client's order picks the exchange. Given directly, it is read as the default it always was.
    assert K.policy("pq-preferred") == "default" and not hasattr(K, "PREFERRED")
    for value in ("default", None, "", "nonsense"):
        assert K.disabled_kex(value, _library()) == [], value
        assert K.disabled_kex(value, _library(with_the_hybrid=False)) == [], value      # classical clients connect
    assert K.disabled_kex("pq-required", _library()) == list(CLASSICAL)
    assert K.offered(_library()) == (HYBRID,) + CLASSICAL and K.offered(types.SimpleNamespace()) == ()
    assert K.hybrid_available(_library()) is True and K.hybrid_available(_library(with_the_hybrid=False)) is False
    assert K.is_hybrid(HYBRID) and not K.is_hybrid("curve25519-sha256@libssh.org") and not K.is_hybrid(None)


def test_the_exchange_a_connection_chose_is_named_from_the_librarys_table_first():
    """The SSH library's X25519 engine carries no name of its own: the name is the one the library's table has
    for the engine's class."""
    import paramiko
    from paramiko.kex_curve25519 import KexCurve25519
    from paramiko.kex_mlkem import KexMLKEM768X25519
    from app.sftp import kex_policy as K
    table = paramiko.Transport._kex_info
    assert K.name_of(KexCurve25519.__new__(KexCurve25519), table) == "curve25519-sha256@libssh.org"
    assert K.name_of(KexMLKEM768X25519.__new__(KexMLKEM768X25519), table) == HYBRID
    for name, made_by in table.items():                     # every exchange the library has, by its own name
        assert K.name_of(made_by.__new__(made_by), table) == name, name
    # An engine the table does not know is named by itself, and one with no name is nothing.
    assert K.name_of(types.SimpleNamespace(name="new-exchange"), table) == "new-exchange"
    assert K.name_of(types.SimpleNamespace(), table) is None and K.name_of(None, table) is None
    assert K.name_of(types.SimpleNamespace(name="new-exchange"), None) == "new-exchange"


def test_the_hybrid_required_where_it_cannot_be_offered_is_an_error_that_says_what_to_set():
    """Offering nothing would refuse every client with no word why."""
    from app.sftp import kex_policy as K
    with pytest.raises(K.HybridUnavailable) as refused:
        K.disabled_kex("pq-required", _library(with_the_hybrid=False))
    said = str(refused.value)
    assert "SFTP_KEX_POLICY=pq-required" in said and HYBRID in said and "SFTP is not started" in said
    assert "where the web side runs in the same container, the vault stops with it" in said
    assert "Set SFTP_KEX_POLICY=default" in said and "pq-preferred" not in said


def test_the_transport_keeps_the_exchange_it_agreed_and_says_it_once(monkeypatch):
    set_bare_api_env()
    import paramiko
    from app.sftp import sftp_server as S
    # The method overridden is paramiko's own: a paramiko that renames it fails here.
    assert callable(getattr(paramiko.Transport, "_parse_kex_init", None))
    assert S._Transport._parse_kex_init is not paramiko.Transport._parse_kex_init
    said = []
    monkeypatch.setattr(S, "safe_event", lambda code, *a, **fields: said.append((code, fields)))
    monkeypatch.setattr(paramiko.Transport, "_parse_kex_init",
                        lambda self, m: setattr(self, "kex_engine", types.SimpleNamespace(name=self.chosen)))
    peer = ("203.0.113.9", 40222)

    def transport(chosen):
        t = S._Transport.__new__(S._Transport)
        t.agreed_kex, t._peer, t.chosen = None, peer, chosen
        return t
    hybrid = transport(HYBRID)
    hybrid._parse_kex_init(object())
    assert hybrid.agreed_kex == HYBRID and said == [("kex.agreed.hybrid", {"peer": peer})]
    hybrid._parse_kex_init(object())                       # the keys agreed again later in the session
    assert len(said) == 1
    classical = transport("curve25519-sha256@libssh.org")
    classical._parse_kex_init(object())
    assert classical.agreed_kex == "curve25519-sha256@libssh.org"
    assert said[-1] == ("kex.agreed.classical", {"peer": peer}) and len(said) == 2
    # An exchange that chose nothing (refused before it): nothing kept, nothing said.
    nothing = transport(None)
    nothing._parse_kex_init(object())
    assert nothing.agreed_kex is None and len(said) == 2


def test_a_log_write_that_fails_does_not_end_the_key_exchange(monkeypatch):
    set_bare_api_env()
    import paramiko
    from app.sftp import sftp_server as S

    def broken(*a, **k):
        raise OSError("the log is gone")
    monkeypatch.setattr(S, "safe_event", broken)
    monkeypatch.setattr(paramiko.Transport, "_parse_kex_init",
                        lambda self, m: setattr(self, "kex_engine", types.SimpleNamespace(name=HYBRID)))
    t = S._Transport.__new__(S._Transport)
    t.agreed_kex, t._peer = None, ("203.0.113.9", 40222)
    t._parse_kex_init(object())
    assert t.agreed_kex == HYBRID


def _handshake(monkeypatch, configured, client_offers=None):
    """A real key exchange in this process: the server's own transport, made as the server makes it (what the
    policy takes away in disabled_algorithms), and the SSH library as the client, over a socket pair. Returns
    whether the keys were agreed, what the server's transport kept, and what it said."""
    set_bare_api_env()
    import paramiko
    from app.sftp import kex_policy as K
    from app.sftp import sftp_server as S
    said = []
    monkeypatch.setattr(S, "safe_event", lambda code, *a, **fields: said.append(code))
    left, right = socket.socketpair()
    server = S._Transport(left, disabled_algorithms={"kex": K.disabled_kex(configured, S._Transport)},
                          peer=("203.0.113.9", 40222))
    client = paramiko.Transport(right)
    try:
        server.add_server_key(paramiko.ECDSAKey.generate())
        server.start_server(event=types.SimpleNamespace(set=lambda: None), server=paramiko.ServerInterface())
        if client_offers:
            client.get_security_options().kex = client_offers
        try:
            client.start_client(timeout=20)
            agreed = True
        except (paramiko.SSHException, EOFError):
            agreed = False
        return agreed, server.agreed_kex, [code for code in said if code.startswith("kex.")]
    finally:
        client.close()
        server.close()
        left.close()
        right.close()


def test_a_real_handshake_agrees_the_hybrid_exchange_and_a_classical_one_only_where_the_policy_lets_it(monkeypatch):
    classical = ("curve25519-sha256@libssh.org",)
    # The default policy: the hybrid exchange with a client that offers it, a classical one with one that does not.
    assert _handshake(monkeypatch, "default") == (True, HYBRID, ["kex.agreed.hybrid"])
    assert _handshake(monkeypatch, "default", classical) == (True, classical[0], ["kex.agreed.classical"])
    # The client's order picks: one that lists a classical exchange before the hybrid one agrees the classical
    # one under the default, and nothing a server sets short of taking the classical ones away changes that.
    assert _handshake(monkeypatch, "default", classical + (HYBRID,)) == (True, classical[0], ["kex.agreed.classical"])
    # Only the hybrid exchange: a client that offers it connects, a classical one finds nothing in common.
    assert _handshake(monkeypatch, "pq-required") == (True, HYBRID, ["kex.agreed.hybrid"])
    assert _handshake(monkeypatch, "pq-required", (HYBRID,)) == (True, HYBRID, ["kex.agreed.hybrid"])
    assert _handshake(monkeypatch, "pq-required", classical) == (False, None, [])
    assert _handshake(monkeypatch, "pq-required", CLASSICAL) == (False, None, [])


def test_the_server_applies_the_policy_to_every_connection_and_checks_it_before_it_listens():
    set_bare_api_env()
    from app.sftp import sftp_server as S
    source = inspect.getsource(S)
    assert "'kex': kex_policy.disabled_kex(settings.sftp_kex_policy, _Transport)," in source
    start = inspect.getsource(S.start_sftp_server)
    steps = ("kex_policy.disabled_kex(settings.sftp_kex_policy, _Transport)",
             "except kex_policy.HybridUnavailable as unavailable:", "raise SystemExit(str(unavailable))",
             "server_socket.bind((settings.sftp_host, settings.sftp_port))")
    assert all(step in start for step in steps), [step for step in steps if step not in start]
    order = [start.index(step) for step in steps]
    assert order == sorted(order), order
    for code in ("kex.policy.hybrid-required-unavailable", "kex.policy.hybrid-unavailable", "kex.policy.hybrid-only",
                 "kex.policy.hybrid-first"):
        assert f"safe_event('{code}')" in start, code
    # The transport starts with nothing agreed.
    assert "self.agreed_kex = None" in inspect.getsource(S._Transport.__init__)


@pytest.mark.parametrize("raw, read", [("default", "default"), (" PQ-Required ", "pq-required"),
                                       ("Default", "default"), ("pq_required", None), ("required", None),
                                       ("pq-require", None), ("", None), ("yes", None), ("pq-preferred", None)])
def test_a_value_that_is_not_one_of_the_two_stops_the_server_at_its_start(monkeypatch, raw, read):
    """A value that only looks like pq-required, taken for the default, would leave the classical exchanges on
    offer with nobody the wiser: the settings refuse it, as they refuse any other bad setting."""
    set_bare_api_env()
    from pydantic import ValidationError
    from app.core.config import Settings
    monkeypatch.setenv("SFTP_KEX_POLICY", raw)
    if read is not None:
        assert Settings().sftp_kex_policy == read
        return
    with pytest.raises(ValidationError) as refused:
        Settings()
    assert "SFTP_KEX_POLICY must be one of default, pq-required" in str(refused.value)


def test_left_unset_the_policy_is_the_default(monkeypatch):
    set_bare_api_env()
    from app.core.config import Settings
    monkeypatch.delenv("SFTP_KEX_POLICY", raising=False)
    assert Settings().sftp_kex_policy == "default"


def test_one_container_stops_whole_when_its_sftp_half_does_not_start():
    """What the setting's help says of pq-required rests on this: the supervisor of the one-container shape
    stops the container when either half ends."""
    supervisor = (ROOT / "run_combined.py").read_text(encoding="utf-8")
    assert '_spawn("app.sftp.sftp_server", "sftp")' in supervisor
    watch = supervisor[supervisor.index("# Supervise: if a running child exits, take the whole container down"):]
    assert "rc = p.poll()" in watch and "_terminate_all()" in watch and "sys.exit(rc if rc != 0 else 1)" in watch
    words = (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8")
    assert "the whole vault stops with it until the" in words.replace("\n    # ", " ")


def test_the_setting_has_its_default_its_words_and_its_place_in_the_setup_tool():
    set_bare_api_env()
    from app.core.config import Settings
    assert Settings.model_fields["sftp_kex_policy"].default == "default"
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "\nSFTP_KEX_POLICY=default\n" in example.replace("\r\n", "\n")
    words = example[example.index("# How an SFTP connection agrees its session keys."):example.index("SFTP_KEX_POLICY=default")]
    # Two values, and none that says it prefers: nowhere in what an operator reads or the server takes.
    for text in (example, (ROOT / "app" / "core" / "config.py").read_text(encoding="utf-8"),
                 (ROOT / "app" / "sftp" / "kex_policy.py").read_text(encoding="utf-8"),
                 (ROOT / "dockvault.py").read_text(encoding="utf-8")):
        assert "pq-preferred" not in text and "pq_preferred" not in text
    for said in ("mlkem768x25519-sha256", "pq-required: the classical exchanges are taken away", "can no longer connect",
                 "default: nothing is taken away. The client's order decides",
                 "every client that lists it before any classical exchange this server supports",
                 "Any other value stops the server at its start",
                 "default is the recommended value",
                 "Under pq-required a server that cannot offer the hybrid exchange does not start SFTP at all",
                 "the whole vault stops with it until the setting is changed"):
        assert said in words.replace("\n# ", " ").replace("\r", ""), said
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    assert 'if sftp_active and _kex_policy == "pq-required":\n        bare("SFTP_KEX_POLICY", _kex_policy)' in tool
    assert '"sftp_kex_policy": (current_env.get("SFTP_KEX_POLICY") or "").strip() or None,' in tool


def test_the_pinned_ssh_library_is_the_one_that_has_the_hybrid_exchange():
    wanted = "paramiko==5.1.0"
    listed = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    locked = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    assert wanted in listed.split() and "paramiko==5.0.0" not in listed
    assert locked.count(wanted) == 1 and "paramiko==5.0.0" not in locked
    block = locked[locked.index(wanted):]
    block = block[:block.index("# via")]
    assert block.count("--hash=sha256:") == 2, block


def test_the_installed_ssh_library_offers_the_hybrid_exchange_first():
    """The library as it is installed here, not a stand-in: the pinned version, with the hybrid exchange at the
    head of what it offers, in server mode too. A library without it would fall back to a classical exchange
    with no word, on every connection."""
    import paramiko
    from paramiko.kex_mlkem import KexMLKEM768X25519
    from app.sftp import kex_policy as K
    assert paramiko.__version__ == "5.1.0", "the tests run with the pinned SSH library"
    assert KexMLKEM768X25519.name == HYBRID and KexMLKEM768X25519.is_available() is True
    assert K.offered(paramiko.Transport)[0] == HYBRID and K.hybrid_available(paramiko.Transport) is True
    assert paramiko.Transport._kex_info[HYBRID] is KexMLKEM768X25519
    assert callable(getattr(KexMLKEM768X25519, "_parse_hybrid_init", None))             # the server's side
    assert K.disabled_kex("pq-required", paramiko.Transport) == [
        name for name in paramiko.Transport._preferred_kex if name != HYBRID]
