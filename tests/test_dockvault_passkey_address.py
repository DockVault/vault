"""The host tool says when passkeys stay hidden: browsers make no passkey for an address reached by IP, so on an
install whose address (the first ALLOWED_HOSTS entry that is not a wildcard) is an IP, setup and status say so.
Offline."""
import importlib.util
import io
import types
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
set_bare_api_env()
_spec = importlib.util.spec_from_file_location("dockvault_passkey_address", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


@pytest.mark.parametrize("name", ["203.0.113.9", "127.0.0.1", "10.0.0.5", "2001:db8::1", "[2001:db8::1]"])
def test_an_address_reached_by_ip_hides_passkeys(name):
    note = dv.passkey_address_note(name)
    assert note and "reached by IP" in note and "host name" in note and "ALLOWED_HOSTS" in note


@pytest.mark.parametrize("name", ["vault.example.com", "localhost", "vault", "", None, "not an address"])
def test_a_host_name_or_nothing_gets_no_note(name):
    assert dv.passkey_address_note(name) is None


@pytest.mark.parametrize("cfg, hidden", [
    ({"server_name": "203.0.113.9", "web_host_port": 443}, True),
    ({"server_name": "203.0.113.9", "web_host_port": 8443}, True),              # written as https://203.0.113.9:8443
    ({"server_name": "vault.example.com", "web_host_port": 8443}, False),
    # Behind a proxy or port forwarding the address people open comes first, and it is the one judged.
    ({"server_name": "203.0.113.9", "web_public_address": "files.example.com", "web_host_port": 443}, False),
    ({"server_name": "vault.example.com", "web_public_address": "https://203.0.113.9:8443", "web_host_port": 443},
     True),
])
def test_the_note_judges_the_address_as_setup_writes_it(cfg, hidden):
    written = dv.allowed_hosts_value(cfg)
    assert bool(dv.sign_in_address_note(written)) is hidden, written


# What the vault says of an address (app/core/public_url.readiness), for what the tool says of it.
AS_THE_VAULT_SAYS = {None: "ok", "none": "no_public_host", "http": "address_not_usable", "script": "address_not_usable",
                     "dot": "address_not_usable", "unusable": "address_not_usable", "ip": "ip_address"}


@pytest.mark.parametrize("written, reason", [
    ("vault.example.com", None), ("vault.example.com:8443", None), ("https://vault.example.com:8443", None),
    ("*.example.com,vault.example.com", None), ("http://localhost:8443", None),
    ("http://vault.lan:8080", "http"), ("http://10.0.0.5:8080", "http"), ("http://vault.lan:8080,vault.example.com", "http"),
    ("203.0.113.9", "ip"), ("https://203.0.113.9:8443", "ip"), ("http://127.0.0.1:8080", "ip"),
    ("http://[::1]:8080", "ip"), ("https://[2001:db8::1]:8443", "ip"),
    ("", "none"), ("*.example.com", "none"), (None, "none"),
    ("https://b\u00fccher.example", "script"), ("stra\u00dfe.example", "script"),
    # An address with two faults is refused for one of them, the same one on both sides: another script before
    # the dot, the dot before plain http and before an address reached by IP.
    ("http://vault.lan.", "dot"), ("https://b\u00fccher.example.", "script"), ("http://b\u00fccher.example", "script"),
    ("https://203.0.113.9.", "dot"), ("http://203.0.113.9.:8080", "dot"),
    # What else the vault will not build sign-in on: the tool said nothing of these, and of the last it said that
    # single sign-on works.
    ("https://user@vault.example.com", "unusable"), ("https://user:secret@vault.example.com", "unusable"),
    ("https://vault_x.example.com", "unusable"), ("vault_x.example.com", "unusable"),
    ("https://-bad-.example", "unusable"), ("https://vault.example.com:99999", "unusable"),
    ("vault.example.com:99999", "unusable"), ("https://vault.example.com:0", "unusable"),
    ("2001:db8::1", "unusable"), ("https://vault.example.com:notaport", "unusable"),
    # And what it does: a path after an origin is dropped by the vault, a trailing dot is a name.
    ("https://vault.example.com/some/page", None), ("vault.example.com/x", None), ("vault.example.com.", None),
    ("xn--bcher-kva.example", None),
])
def test_the_tool_and_the_vault_judge_an_address_alike(written, reason, monkeypatch):
    """Setup and status speak before the vault runs, so the tool has the rule in its own words; this holds the two
    to one answer for every kind of address: none, plain http, a name in another script, an IP, and one that works."""
    from app.core import allowed_hosts, public_url
    assert dv.sign_in_address_reason(written) == reason
    monkeypatch.setattr(public_url, "link_base", lambda: allowed_hosts.link_base(written or ""))
    ready = public_url.readiness()
    assert ready["reason"] == AS_THE_VAULT_SAYS[reason], (written, ready)
    assert ready["usable"] is (reason is None)
    note = dv.sign_in_address_note(written)
    assert (note is None) is (reason is None)
    if reason == "dot":
        assert "written with a dot at its end" in note and "ALLOWED_HOSTS" in note     # its own words, held below
    elif note:
        assert note.startswith("passkeys") and "waits meanwhile, and locks nobody out" in note
        # What it turns off: passkeys alone at an address reached by IP, single sign-on too everywhere else.
        if reason == "ip":
            assert "single sign-on and the emailed links work either way" in note
        else:
            assert note.startswith("passkeys and single sign-on stay off"), note
        assert "ALLOWED_HOSTS" in note
    # Where the vault refuses the address in words, they are the words for the tool's reason and no other: the
    # operator who mends what one of the two says does not meet the other's different answer next.
    said = {"script": "another script", "dot": "a dot at its end", "http": "must use https"}
    if reason in said:
        why = public_url.problem(allowed_hosts.link_base(written or ""))
        assert why and said[reason] in why, (written, why)
        assert not [other for other in said.values() if other != said[reason] and other in why], (written, why)


def test_each_reason_says_what_to_change():
    assert "both need https" in dv.sign_in_address_note("http://vault.lan:8080")
    assert "single sign-on and the emailed links work either way" not in dv.sign_in_address_note("http://10.0.0.5:8080")
    assert "xn-- form" in dv.sign_in_address_note("https://b\u00fccher.example")
    assert "has no address" in dv.sign_in_address_note("")
    assert "reached by IP" in dv.sign_in_address_note("https://203.0.113.9:8443")


def test_the_rule_the_vault_checks_is_the_tools_too():
    from app.core.public_url import is_ip_address
    for host in ("203.0.113.9", "2001:db8::1", "127.0.0.1"):
        assert is_ip_address(host) and dv.passkey_address_note(host)
    assert not is_ip_address("vault.example.com") and dv.passkey_address_note("vault.example.com") is None


def test_status_says_passkeys_are_hidden_at_an_ip(monkeypatch, tmp_path):
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    Tool = next(c for c in vars(dv).values() if isinstance(c, type) and hasattr(c, "_print_status"))
    tool = Tool.__new__(Tool)
    tool.pal = types.SimpleNamespace(paint=lambda text, colour=None: text)
    monkeypatch.setattr(tool, "_is_locked", lambda: False)
    monkeypatch.setattr(tool, "_env_lock_path", lambda: str(tmp_path / "none.lock"))
    monkeypatch.setattr(tool, "_env_archives", lambda: [])
    monkeypatch.setattr(tool, "_env_path", lambda: str(tmp_path / ".env"))
    (tmp_path / ".env").write_text("ALLOWED_HOSTS='https://203.0.113.9:8443'\n", encoding="utf-8")
    monkeypatch.setattr(tool, "_load_env", lambda: {"ALLOWED_HOSTS": "https://203.0.113.9:8443"})
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    tool._print_status("combined")
    assert any("Passkeys: hidden" in line and "reached by IP" in line for line in printed), printed
    for written, said in (("http://vault.lan:8080", "both need https"), ("", "has no address")):
        printed.clear()
        monkeypatch.setattr(tool, "_load_env", lambda env={"ALLOWED_HOSTS": written, "SERVER_NAME": "vault"}: env)
        tool._print_status("combined")
        assert any("Passkeys: hidden" in line and said in line and "waits meanwhile" in line for line in printed), printed
    for named in ({"ALLOWED_HOSTS": "vault.example.com"}, {"ALLOWED_HOSTS": "*.example.com,vault.example.com"}, {}):
        printed.clear()
        monkeypatch.setattr(tool, "_load_env", lambda env=named: env)
        tool._print_status("combined")
        assert not any("Passkeys" in line for line in printed), (named, printed)


def test_setup_says_it_once_the_address_is_known():
    source = io.open(ROOT / "dockvault.py", encoding="utf-8").read()
    setup = source[source.index("def _collect_setup_config"):source.index("def _resolve_cert_cfg")]
    # The address as it will be written, made once and judged twice: whether passkeys can be made there, and
    # which of the passkeys that exist were made somewhere else.
    assert setup.count("address = allowed_hosts_value(") == 1
    assert "sign_in_address_note(address)" in setup and "passkey_host(address)" in setup
    assert (setup.index("web_public = public_web_address(") < setup.index("address = allowed_hosts_value(")
            < setup.index("sign_in_address_note(address)") < setup.index("passkey_host(address)"))


def test_the_example_environment_says_it_beside_the_address():
    text = io.open(ROOT / ".env.example", encoding="utf-8").read()
    before, _, _after = text.partition("\nALLOWED_HOSTS=")
    tail = before[-2500:]
    assert "Passkeys need https and a HOST NAME" in tail and "reached by IP" in tail and "plain http" in tail
    assert "xn-- form" in tail and "waits meanwhile" in tail and "dockvault.py setup and status say so" in tail


def test_the_note_about_passkeys_made_at_another_address_counts_those_and_no_others():
    """Setup and status say how many passkeys in use were made at another address than the vault gives out now, of
    how many accounts, where, and what follows. Nothing is said when every key was made here, when there is none,
    or when the deployment could not be asked."""
    here = "vault.example.com"
    answer = {"ok": True, "here": here, "made_at": [
        {"address": here, "passkeys": 3, "accounts": 2},
        {"address": "old.example.com", "passkeys": 2, "accounts": 1},
        {"address": "older.example.com", "passkeys": 1, "accounts": 1},
        {"address": "empty.example.com", "passkeys": 0, "accounts": 0},
        {"address": "broken.example.com", "passkeys": "many", "accounts": 1}, "not an entry"]}
    note = dv.passkeys_elsewhere_note(answer, here)
    assert note.startswith("3 passkeys (of 2 accounts) were made at old.example.com, older.example.com and cannot "
                           "be used at vault.example.com."), note
    # This answer does not say which accounts hold another factor (no "holders"): no number is claimed.
    assert ("An account among them that has no other second factor to use there sets one up again at its next "
            "sign-in: with the account's password, or through its organisation's sign-in where it has none.") in note
    assert "Each of those accounts" not in note and "of those accounts" not in note
    assert note.endswith("The passkeys work again if the vault goes back to that address.")
    assert "empty.example.com" not in note and "broken.example.com" not in note
    one = dv.passkeys_elsewhere_note({"made_at": [{"address": "old.example.com", "passkeys": 1, "accounts": 1}]}, here)
    assert one.startswith("1 passkey (of 1 account) was made at old.example.com and cannot be used at "), one
    # Every key made here (a host name is one name however it is written), no key, no answer: nothing to say.
    for made_here in (here, "VAULT.Example.COM"):
        assert dv.passkeys_elsewhere_note({"made_at": [{"address": made_here, "passkeys": 3, "accounts": 2}]}, here) is None
    assert dv.passkeys_elsewhere_note({"made_at": [{"address": here, "passkeys": 3, "accounts": 2}]}, "Vault.Example.com") is None
    for nothing in (None, {}, {"made_at": "text"}, {"made_at": []}, "text", []):
        assert dv.passkeys_elsewhere_note(nothing, here) is None, nothing
    # An address no passkey can be made at: every key in use was made somewhere else.
    stranded = dv.passkeys_elsewhere_note({"made_at": [{"address": here, "passkeys": 2, "accounts": 2}]}, "")
    assert "cannot be used at the address the vault has now (no passkey can be made there)" in stranded, stranded
    # A key with no address on record is reported by the deployment under its own address; one that still comes
    # with none is named for what it is.
    unnamed = dv.passkeys_elsewhere_note({"made_at": [{"address": "", "passkeys": 1, "accounts": 1}]}, here)
    assert "made at an address that was not recorded" in unnamed, unnamed


def test_the_host_passkeys_are_made_for_is_the_one_the_vault_gives_out():
    assert dv.passkey_host("https://vault.example.com") == "vault.example.com"
    assert dv.passkey_host("https://vault.example.com:8443") == "vault.example.com"
    # As the vault records it on a key (app/core/public_url.py): lower case.
    for written in ("https://VAULT.Example.COM", "Vault.Example.Com"):
        assert dv.passkey_host(written) == "vault.example.com", written
    # A name written with a dot at its end is no address a passkey is made at, for the tool as for the vault.
    for written in ("vault.example.com.", "https://vault.example.com.:8443", "Vault.Example.Com.", "https://vault.example.com./"):
        assert dv.sign_in_address_reason(written) == "dot" and dv.passkey_host(written) == "", written
        assert "without that dot" in dv.sign_in_address_note(written), written
    from app.core import allowed_hosts, public_url
    for written in ("vault.example.com.", "https://vault.example.com./"):
        try:
            public_url.link_base, kept = (lambda w=written: allowed_hosts.link_base(w)), public_url.link_base
            assert public_url.rp_id() == "" == dv.passkey_host(written), written
        finally:
            public_url.link_base = kept
    for written in ("vault.example.com", "https://VAULT.Example.COM:8443",
                    "*.example.com,vault.example.com", "https://xn--bcher-kva.example"):
        try:
            public_url.link_base, kept = (lambda w=written: allowed_hosts.link_base(w)), public_url.link_base
            assert dv.passkey_host(written) == public_url.rp_id() != "", written
        finally:
            public_url.link_base = kept
    for none_can_be_made in ("https://203.0.113.9:8443", "http://vault.lan:8080", "", None):
        assert dv.passkey_host(none_can_be_made) == "", none_can_be_made


def test_status_says_which_passkeys_were_made_at_another_address(monkeypatch, tmp_path):
    printed = []
    monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(str(x) for x in a)))
    Tool = next(c for c in vars(dv).values() if isinstance(c, type) and hasattr(c, "_print_status"))
    tool = Tool.__new__(Tool)
    tool.pal = types.SimpleNamespace(paint=lambda text, colour=None: text)
    monkeypatch.setattr(tool, "_is_locked", lambda: False)
    monkeypatch.setattr(tool, "_env_lock_path", lambda: str(tmp_path / "none.lock"))
    monkeypatch.setattr(tool, "_env_archives", lambda: [])
    monkeypatch.setattr(tool, "_env_path", lambda: str(tmp_path / ".env"))
    (tmp_path / ".env").write_text("ALLOWED_HOSTS='https://vault.example.com'\n", encoding="utf-8")
    monkeypatch.setattr(tool, "_load_env", lambda: {"ALLOWED_HOSTS": "https://vault.example.com"})
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    asked = []
    answers = [{"ok": True, "here": "vault.example.com", "made_at": [
        {"address": "vault.example.com", "passkeys": 4, "accounts": 3},
        {"address": "old.example.com", "passkeys": 2, "accounts": 1}]}]
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: (asked.append(1), answers[0])[1])
    tool._print_status("combined")
    lines = [line for line in printed if "Passkeys:" in line]
    assert len(lines) == 1 and "2 passkeys (of 1 account) were made at old.example.com" in lines[0], printed
    assert "cannot be used at vault.example.com" in lines[0] and asked == [1]
    # Every key made here, or a deployment that could not be asked: no line.
    for quiet in ({"ok": True, "made_at": [{"address": "vault.example.com", "passkeys": 4, "accounts": 3}]}, None):
        printed.clear()
        answers[0] = quiet
        tool._print_status("combined")
        assert not any("Passkeys:" in line for line in printed), (quiet, printed)


def test_the_deployment_that_cannot_be_asked_about_its_passkeys_answers_nothing(monkeypatch):
    Tool = next(c for c in vars(dv).values() if isinstance(c, type) and hasattr(c, "_passkey_addresses"))
    tool = Tool.__new__(Tool)
    monkeypatch.setattr(dv, "docker_available", lambda: (False, "no docker"))
    assert tool._passkey_addresses() is None
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))

    def gone(*a, **k):
        raise OSError("no such command")
    monkeypatch.setattr(tool, "_run_dc", gone)
    assert tool._passkey_addresses() is None
    # An answer that says it failed is no answer; one that is whole is handed on.
    said = ['{"ok": false, "error": "x"}']
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: types.SimpleNamespace(stdout=said[0], returncode=0))
    assert tool._passkey_addresses() is None
    said[0] = '{"ok": true, "here": "vault.example.com", "made_at": []}'
    assert tool._passkey_addresses() == {"ok": True, "here": "vault.example.com", "made_at": []}


def test_the_example_file_says_every_part_of_the_rule_for_the_sign_in_address():
    """An operator who writes ALLOWED_HOSTS by hand reads the rule there: https, a host name, its xn-- form for
    another script, and no dot at its end. Without the last, only status and the pages said so afterwards."""
    from pathlib import Path
    example = (Path(dv.__file__).resolve().parent / ".env.example").read_text(encoding="utf-8")
    said = " ".join(line.lstrip("#").strip() for line in example.splitlines())
    assert ("first entry is an https host name (in its xn-- form when it is written in another script, and without "
            "a dot at its end)") in said


def _holders(*groups):
    return [{"made_at": list(made), "usable_at": list(usable), "other_factor": other, "accounts": accounts}
            for made, usable, other, accounts in groups]


def test_the_note_names_only_the_accounts_left_with_no_factor_and_counts_each_account_once():
    """An account with keys at two other addresses was counted twice, and every account was said to set a second
    factor up again, also the one that signs in with its authenticator app or with a key made here. The
    deployment says which accounts are alike; the note counts each once and names the ones left with none."""
    here, old, older = "vault.example.com", "old.example.com", "older.example.com"
    made_at = [{"address": old, "passkeys": 3, "accounts": 3}, {"address": older, "passkeys": 1, "accounts": 1},
               {"address": here, "passkeys": 1, "accounts": 1}]
    tail = " The passkeys work again if the vault goes back to that address."
    start = ("4 passkeys (of 3 accounts) were made at old.example.com, older.example.com and cannot be used at "
             "vault.example.com. ")
    how = "with the account's password, or through its organisation's sign-in where it has none"

    def said(holders, host=here, **more):
        return dv.passkeys_elsewhere_note({"made_at": made_at, "holders": holders, **more}, host)

    # One account holds keys at both other addresses: three accounts, not four. One of the three is left with
    # none; one has an authenticator app; one has a key it can use here.
    mixed = _holders(((old, older), (old, older), False, 1), ((old,), (old,), True, 1),
                     ((here, old), (here, old), False, 1))
    assert said(mixed) == (start + "1 of those accounts has no other second factor to use there and sets one up "
                           "again at its next sign-in: " + how + ". The others sign in with another one (an "
                           "authenticator app, or a passkey made there)." + tail)
    two = _holders(((old, older), (old, older), False, 2), ((old,), (old,), True, 1))
    assert said(two) == (start + "2 of those accounts have no other second factor to use there and set one up "
                         "again at their next sign-in: " + how + ". The other signs in with another one (an "
                         "authenticator app, or a passkey made there)." + tail)
    # Every one of them is left with none; one account alone; none of them.
    everyone = _holders(((old, older), (old, older), False, 1), ((old,), (old,), False, 2))
    assert said(everyone) == (start + "Each of those accounts has no other second factor to use there and sets "
                              "one up again at its next sign-in: " + how + "." + tail)
    alone = dv.passkeys_elsewhere_note({"made_at": [{"address": old, "passkeys": 2, "accounts": 1}],
                                        "holders": _holders(((old,), (old,), False, 1))}, here)
    assert alone == ("2 passkeys (of 1 account) were made at old.example.com and cannot be used at "
                     "vault.example.com. That account has no other second factor to use there and sets one up "
                     "again at its next sign-in: " + how + "." + tail)
    nobody = _holders(((old, older), (old, older), True, 1), ((here, old), (here,), False, 2))
    assert said(nobody) == (start + "None of those accounts has to set a second factor up again: each holds "
                            "another one to use there (an authenticator app, or a passkey made there)." + tail)
    # A key made here that is no factor (it never verified the person, or its algorithm is accepted no longer)
    # leaves its account with none: the address in "made_at" is not enough, it has to be in "usable_at".
    unusable_here = _holders(((here, old), (old,), False, 1), ((old, older), (old, older), True, 2))
    assert "1 of those accounts has no other second factor" in said(unusable_here)
    # An account whose keys were all made here is none of "those accounts", whatever it holds.
    with_one_here = mixed + _holders(((here,), (), False, 5), (("VAULT.Example.COM",), (), False, 7))
    assert said(with_one_here) == said(mixed)
    # The host name is one name however it is written, in the answer as in the tool.
    shouted = _holders(((old.upper(), "VAULT.Example.COM"), ("Vault.Example.Com",), False, 3))
    assert "None of those accounts has to set a second factor up again" in said(shouted)
    # At an address no passkey can be made at, no key is a factor: only the authenticator app keeps an account.
    nowhere = dv.passkeys_elsewhere_note({"made_at": made_at, "holders": mixed}, "")
    assert nowhere.startswith("5 passkeys (of 3 accounts) were made at old.example.com, older.example.com, "
                              "vault.example.com and cannot be used at the address the vault has now (no passkey "
                              "can be made there). 2 of those accounts have no other second factor"), nowhere
    # A key the deployment reports with no address (it has none itself) is no factor there either, and its
    # account is one of those.
    unrecorded = dv.passkeys_elsewhere_note(
        {"made_at": [{"address": "", "passkeys": 2, "accounts": 2}],
         "holders": _holders((("",), ("",), False, 1), (("",), ("",), True, 1))}, "")
    assert unrecorded.startswith("2 passkeys (of 2 accounts) were made at an address that was not recorded and "
                                 "cannot be used at the address the vault has now (no passkey can be made there). "
                                 "1 of those accounts has no other second factor"), unrecorded
    # While passkeys are turned off no passkey is used at any address: the note says that, and names no set-up.
    off = said(mixed, on=False)
    assert off == (start + "Passkeys are turned off in this vault, so this changes nothing for those accounts now; "
                   "it will once passkeys are turned on again." + tail)
    assert said(mixed, on=True) == said(mixed) and said(mixed, on=None) == said(mixed)
    # Groups that are none (an older build's answer, or one mangled on the way): the sum, and no number claimed.
    for broken in (None, "text", [{"made_at": [old]}], [{"made_at": [old], "usable_at": [], "accounts": "many"}],
                   [{"made_at": [old], "usable_at": [], "accounts": -1}], ["text"], [],
                   mixed + [{"made_at": [old], "usable_at": [], "accounts": -1}], mixed + ["text"],
                   _holders(((here,), (here,), False, 4))):
        note = said(broken)
        assert note.startswith("4 passkeys (of 4 accounts) were made at old.example.com, older.example.com and "
                               "cannot be used at vault.example.com. An account among them that has no other "
                               "second factor to use there sets one up again at its next sign-in: "), (broken, note)


def test_the_looked_up_account_says_which_of_its_passkeys_it_can_sign_in_with(capsys):
    """Beside the number of passkeys an account holds, `account` says how many it can sign in with when that is
    not all of them. An answer that does not say (an older image), or says something that is no number, adds
    nothing: the line reads as it did."""
    note = dv.passkeys_usable_note
    assert note({"passkeys": 2, "passkeys_usable": 2}) == "" and note({"passkeys": 0, "passkeys_usable": 0}) == ""
    assert note({"passkeys": 2, "passkeys_usable": 0}) == " (it can sign in with none of them now)"
    assert note({"passkeys": 1, "passkeys_usable": 0}) == " (it cannot sign in with it now)"
    assert note({"passkeys": 3, "passkeys_usable": 1}) == " (it can sign in with 1 of them now)"
    assert note({"passkeys": 20, "passkeys_usable": 19}) == " (it can sign in with 19 of them now)"
    for unsaid in ({"passkeys": 2}, {"passkeys": 2, "passkeys_usable": None}, {"passkeys": 2, "passkeys_usable": "0"},
                   {"passkeys": 2, "passkeys_usable": True}, {"passkeys": "2", "passkeys_usable": 0},
                   {"passkeys": 2, "passkeys_usable": 3}, {"passkeys": 2, "passkeys_usable": -1},
                   {"passkeys": True, "passkeys_usable": False}, {"passkeys": True, "passkeys_usable": 0},
                   {"passkeys_usable": 0}, {}):
        assert note(unsaid) == "", unsaid
    Tool = next(c for c in vars(dv).values() if isinstance(c, type) and hasattr(c, "_show_account"))
    plain = types.SimpleNamespace(pal=types.SimpleNamespace(paint=lambda text, colour: text))
    account = {"username": "ann", "email": None, "role": "user", "active": True, "last_login": None,
               "second_factor": False, "passkeys": 2, "passkeys_usable": 0}
    Tool._show_account(plain, account)
    assert "  passkeys:      2 (it can sign in with none of them now)\n" in capsys.readouterr().out
    Tool._show_account(plain, {**account, "passkeys_usable": 1, "passkey_requirement_cleared_at": "2026-11-20T10:00:00Z"})
    assert ("  passkeys:      2 (it can sign in with 1 of them now)  (the role's requirement lifted by the host "
            "operator: 2026-11-20T10:00:00Z)\n") in capsys.readouterr().out
    Tool._show_account(plain, {k: v for k, v in account.items() if k != "passkeys_usable"})
    assert "  passkeys:      2\n" in capsys.readouterr().out
