"""What `dockvault.py status` says about the key exchange an SFTP connection uses (SFTP_KEX_POLICY): the policy in
force where SFTP runs, and a value the vault refuses to start with wherever it is. Offline."""
import importlib.util
import types
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_status", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

LABEL = "  SFTP key exchange: "
REQUIRED = (LABEL + "pq-required - only the hybrid post-quantum exchange (mlkem768x25519-sha256): a client without it "
            "(OpenSSH before 9.9, many older SFTP programs) cannot connect.")
DEFAULT = (LABEL + "default - the hybrid post-quantum exchange with every client that lists it first (the client's "
           "order decides); other clients connect with a classical one.")


def _status(monkeypatch, tmp_path, env, profiles="combined"):
    """The lines status prints for ``env``, each with the colour it is painted in."""
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    tool = dv.DockVault.__new__(dv.DockVault)
    tool.pal = types.SimpleNamespace(paint=lambda text, colour=None: "%s|%s" % (colour, text))
    tool.root = str(tmp_path)
    (tmp_path / ".env").write_text("COMPOSE_PROFILES=%s\n" % profiles, encoding="utf-8")
    monkeypatch.setattr(tool, "_load_env", lambda: dict(env, ALLOWED_HOSTS="vault.example.com"))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: None)
    monkeypatch.setattr(dv, "cert_self_issued", lambda path: False)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    tool._print_status(profiles)
    return [line.split("|", 1) for line in printed if "|" in line and "SFTP key exchange" in line]


@pytest.mark.parametrize("value", [None, "default", "Default", " default "])
def test_status_says_the_default_agrees_the_hybrid_exchange_in_the_clients_order(monkeypatch, tmp_path, value):
    """An absent value is the default."""
    env = {"RUN_SFTP": "1"} if value is None else {"RUN_SFTP": "1", "SFTP_KEX_POLICY": value}
    assert _status(monkeypatch, tmp_path, env) == [["grey", DEFAULT]]


def test_status_says_a_client_without_the_hybrid_exchange_cannot_connect_under_pq_required(monkeypatch, tmp_path):
    assert _status(monkeypatch, tmp_path, {"RUN_SFTP": "true", "SFTP_KEX_POLICY": "pq-required"}) == [
        ["yellow", REQUIRED]]


def test_the_split_layout_runs_sftp_without_run_sftp(monkeypatch, tmp_path):
    assert _status(monkeypatch, tmp_path, {"SFTP_KEX_POLICY": "pq-required"}, profiles="split") == [
        ["yellow", REQUIRED]]


@pytest.mark.parametrize("env", [{}, {"SFTP_KEX_POLICY": "pq-required"}, {"RUN_SFTP": "0", "SFTP_KEX_POLICY": "default"},
                                 {"RUN_SFTP": "", "SFTP_KEX_POLICY": "Default"}])
def test_a_web_only_deployment_with_a_valid_value_gets_no_line(monkeypatch, tmp_path, env):
    assert _status(monkeypatch, tmp_path, env) == []


@pytest.mark.parametrize("value", ["pq-requried", "", "  ", "hybrid", "pq_required", "pq-preferred"])
@pytest.mark.parametrize("run_sftp", ["1", "0"])
def test_a_value_the_vault_refuses_to_start_with_is_said_in_red_wherever_sftp_runs(monkeypatch, tmp_path, value,
                                                                                    run_sftp):
    """The settings refuse it when any part of the vault starts, the web side among them."""
    lines = _status(monkeypatch, tmp_path, {"RUN_SFTP": run_sftp, "SFTP_KEX_POLICY": value})
    assert lines == [["red", LABEL + "SFTP_KEX_POLICY=%s in .env is not default or pq-required: the "
                                     "vault refuses to start with it." % value.strip()]], lines


def test_the_values_status_takes_are_the_ones_the_vault_starts_with():
    from app.core.config import Settings
    from app.sftp import kex_policy
    assert set(kex_policy.POLICIES) == {"default", "pq-required"} == set(dv.SFTP_KEX_STATUS_WORDS)
    assert set(dv.SFTP_KEX_POLICIES) == set(kex_policy.POLICIES)
    for value in ("pq-requried", "", "hybrid", "pq-preferred"):
        with pytest.raises(Exception):
            Settings(sftp_kex_policy=value)
    for value in ("Default", "PQ-REQUIRED"):
        assert Settings(sftp_kex_policy=value).sftp_kex_policy == value.lower()
