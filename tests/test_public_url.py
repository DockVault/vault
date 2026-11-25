"""The vault's public address as the sign-in features need it (app/core/public_url.py): it is the one configured
address, the base of the emailed links (the first ALLOWED_HOSTS entry that is not a wildcard), never a request's
host and never a second setting; what makes it usable for sign-in, how it is written as a browser writes an origin,
and what passkeys can do with it. Offline."""
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _pu():
    set_bare_api_env()
    from app.core import public_url
    return public_url


def _with_settings(monkeypatch, allowed_hosts=""):
    pu = _pu()
    import app.core.config as config
    monkeypatch.setattr(config.settings, "allowed_hosts", allowed_hosts, raising=False)
    return pu


@pytest.mark.parametrize("value", [
    "", "  ", "https://vault.example.com", "https://vault.example.com/", "https://vault.example.com:8443",
    "HTTPS://Vault.Example.COM:443", "http://localhost", "http://localhost:8200", "http://127.0.0.1:8200",
    "http://[::1]:8200", "https://10.0.0.5", "https://[2001:db8::1]:8443",
])
def test_an_address_of_scheme_host_and_optional_port_can_serve_sign_in(value):
    assert _pu().problem(value) is None


@pytest.mark.parametrize("value,words", [
    ("vault.example.com", "https://"),
    ("ftp://vault.example.com", "https://"),
    ("http://vault.example.com", "only for localhost"),
    ("http://vault.localhost", "only for localhost"),
    ("https://", "no host"),
    ("https:///vault", "no host"),
    ("https://user@vault.example.com", "user name or password"),
    ("https://user:pw@vault.example.com", "user name or password"),
    ("https://vault.example.com/vault", "no path"),
    ("https://vault.example.com/?x=1", "no path"),
    ("https://vault.example.com#frag", "no path"),
    ("https://vault.example.com:0", "port"),
    ("https://vault.example.com:70000", "port"),
    ("https://vault.example.com:abc", "port"),
])
def test_anything_else_cannot_with_a_plain_reason(value, words):
    why = _pu().problem(value)
    assert why and words in why, (value, why)
    assert why.startswith("The vault's address (the first ALLOWED_HOSTS entry) ")


@pytest.mark.parametrize("value", [
    "https://exam ple.com", "https://*.example.com", "https://it's.example.com", "https://-bad.example.com",
    "https://bad-.example.com", "https://ex_ample.com", "https://[2001:db8::1%25eth0]", "https://[foo.internal]",
    "https://" + "a" * 64 + ".example.com",
])
def test_a_host_no_browser_has_cannot(value):
    why = _pu().problem(value)
    assert why and ("host" in why or "address" in why), (value, why)
    # The reason never repeats the value.
    assert "example" not in why and "foo" not in why


def test_a_name_in_another_script_is_taken_only_as_the_browser_writes_it():
    """The browser writes such a name in its xn-- form and signs passkeys and follows redirects at that name. The
    conversion at hand is the older one: it turns a sharp s into ss and a final sigma into a plain one, which are
    other names, owned by whoever registered them. So the other spelling is refused in words, never converted."""
    pu = _pu()
    for written in ("https://bücher.example", "https://Bücher.example:8443", "https://straße.example",
                    "https://ὀδός.example", "https://a\u200db.example"):
        why = pu.problem(written)
        assert why and "xn-- form" in why and "example" not in why, (written, why)
        assert pu.normalize(written) == "", written
    assert pu.problem("https://xn--bcher-kva.example") is None
    assert pu.normalize("https://XN--Bcher-KVA.example:8443") == "https://xn--bcher-kva.example:8443"
    assert pu.normalize("https://xn--strae-oqa.example") == "https://xn--strae-oqa.example"      # never strasse


@pytest.mark.parametrize("written, said", [
    ("http://vault.lan.", "a dot at its end"),                  # the dot, before "must use https"
    ("http://vault.lan", "must use https"),
    ("https://b\u00fccher.example.", "another script"),           # another script, before the dot
    ("https://b\u00fccher.example", "another script"),
    ("https://203.0.113.9.", "a dot at its end"),
    ("https://vault.example.com.:0", "a dot at its end"),       # the dot, before the port
    ("https://vault.example.com./path", "a dot at its end"),    # the dot, before the path
    ("https://exam ple.com.", "a dot at its end"),              # the dot, before "no browser accepts"
])
def test_the_reasons_an_address_is_refused_for_come_in_one_order(written, said):
    """An address with two faults is refused for one of them, always the same one: the setup tool judges in the
    same order (its own table of addresses holds it to that), so the operator who mends what one of them says does
    not meet the other one's different answer next."""
    why = _pu().problem(written)
    assert why and said in why, (written, why)
    for other in ("a dot at its end", "another script", "must use https", "no browser accepts", "not a number",
                  "with no path"):
        assert (other in why) is (other == said), (written, why)


def test_a_host_name_written_with_a_dot_at_its_end_is_no_address_sign_in_is_built_on(monkeypatch):
    """One host, two spellings, and the parts of a sign-in do not agree on one (the host check admits what was
    written, a browser there signs an origin with the dot, a provider is sent back without it). The address is
    refused in words that never repeat it, so no passkey is made or counted there, a requirement waits, and
    single sign-on says why."""
    pu = _pu()
    for written in ("https://vault.example.com.", "https://Vault.Example.COM.:8443", "https://xn--bcher-kva.example./",
                    "http://localhost.", "https://203.0.113.9."):
        why = pu.problem(written)
        assert why and "a dot at its end" in why and "example" not in why and "203" not in why, (written, why)
        assert pu.normalize(written) == "", written
    assert pu.problem("https://vault.example.com") is None
    monkeypatch.setattr(pu, "link_base", lambda: "https://vault.example.com.")
    assert pu.readiness() == {"usable": False, "rp_id": "", "origin": "", "reason": pu.ADDRESS_NOT_USABLE}
    assert pu.public_base_url() == "" and pu.expected_origin() == "" and pu.rp_id() == ""
    assert "a dot at its end" in pu.why_not_usable() and "ALLOWED_HOSTS" in pu.why_not_usable()
    assert "a dot at its end" in pu.why_no_passkeys()
    monkeypatch.setattr(pu, "link_base", lambda: "https://vault.example.com")
    assert pu.readiness()["usable"] is True and pu.rp_id() == "vault.example.com"


def test_normalization_writes_the_address_as_a_browser_writes_an_origin():
    pu = _pu()
    assert pu.normalize("HTTPS://Vault.Example.COM:443/") == "https://vault.example.com"
    assert pu.normalize("https://vault.example.com:8443") == "https://vault.example.com:8443"
    assert pu.normalize("http://localhost:80") == "http://localhost"
    assert pu.normalize("http://localhost:8200/") == "http://localhost:8200"
    assert pu.normalize("https://[2001:DB8::1]:8443") == "https://[2001:db8::1]:8443"
    assert pu.normalize("") == "" and pu.normalize("http://vault.example.com") == ""


# --------------------------------------------------------------------------- the one configured address

@pytest.mark.parametrize("allowed_hosts, address, rp_id", [
    ("vault.example.com", "https://vault.example.com", "vault.example.com"),                 # a bare name: https
    ("vault.example.com:8443", "https://vault.example.com:8443", "vault.example.com"),       # a bare name and a port
    ("https://vault.example.com:8443", "https://vault.example.com:8443", "vault.example.com"),   # a full address
    ("HTTPS://Vault.Example.com:443/", "https://vault.example.com", "vault.example.com"),
    ("http://localhost:8200,vault-api", "http://localhost:8200", "localhost"),               # as the tests run it
    # A wildcard is never the address, bare or written as an address: the first entry that is not one is.
    (" *, 0.0.0.0, .example.com, vault.example.com, two.example.com", "https://vault.example.com",
     "vault.example.com"),
    ("*.example.com, https://*.example.com, https://files.example.com:8443, vault.example.com",
     "https://files.example.com:8443", "files.example.com"),
])
def test_the_address_is_the_first_entry_that_is_not_a_wildcard(monkeypatch, allowed_hosts, address, rp_id):
    pu = _with_settings(monkeypatch, allowed_hosts)
    assert pu.link_base() and pu.public_base_url() == address and pu.expected_origin() == address
    assert pu.rp_id() == rp_id
    assert pu.readiness() == {"usable": True, "rp_id": rp_id, "origin": address, "reason": "ok"}
    assert pu.why_not_usable() == "" and pu.why_no_passkeys() == ""
    # The emailed links are built on the same address.
    from app.core import email_actions
    assert pu.normalize(email_actions.vault_url()) == address


@pytest.mark.parametrize("allowed_hosts", ["", "  ", "*", "*, .example.com, 0.0.0.0", "https://*.example.com"])
def test_with_no_address_configured_sign_in_has_none(monkeypatch, allowed_hosts):
    pu = _with_settings(monkeypatch, allowed_hosts)
    assert pu.link_base() == "" and pu.public_base_url() == "" and pu.rp_id() == "" and pu.expected_origin() == ""
    assert pu.readiness() == {"usable": False, "rp_id": "", "origin": "", "reason": "no_public_host"}
    why = pu.why_not_usable()
    assert "no public address" in why and "ALLOWED_HOSTS" in why and "dockvault.py setup" in why
    assert pu.why_no_passkeys() == why


@pytest.mark.parametrize("allowed_hosts, words", [
    ("http://vault.lan:8200", "https://"),                   # plain http on a name that is not this computer
    ("http://vault.example.com, https://vault.example.com", "https://"),      # no looking for another entry
    ("bad host, vault.example.com", "no browser accepts"),
])
def test_an_address_the_links_use_and_sign_in_cannot_is_not_replaced_by_another_entry(monkeypatch, allowed_hosts,
                                                                                    words):
    """The emailed links keep the address as configured. Sign-in cannot be built on it, and is not built on the
    next entry instead: one address, or none."""
    pu = _with_settings(monkeypatch, allowed_hosts)
    from app.core import email_actions
    assert pu.link_base() == email_actions.vault_url() != ""
    assert pu.public_base_url() == "" and pu.rp_id() == "" and pu.expected_origin() == ""
    assert pu.readiness() == {"usable": False, "rp_id": "", "origin": "", "reason": "address_not_usable"}
    why = pu.why_not_usable()
    assert words in why and "ALLOWED_HOSTS" in why and why.endswith("then restart.")
    # The reason never repeats the address.
    assert "vault.lan" not in why and "example" not in why and "bad host" not in why
    assert pu.why_no_passkeys() == why


def test_an_address_reached_by_ip_is_no_relying_party(monkeypatch):
    pu = _with_settings(monkeypatch, "https://10.0.0.5:8443")
    assert pu.readiness() == {"usable": False, "rp_id": "10.0.0.5", "origin": "https://10.0.0.5:8443",
                              "reason": "ip_address"}
    assert pu.public_base_url() == "https://10.0.0.5:8443"       # single sign-on can still be built on it
    assert pu.why_not_usable() == ""
    why = pu.why_no_passkeys()
    assert "reached by IP" in why and "host name first in ALLOWED_HOSTS" in why and "10.0.0.5" not in why
    pu = _with_settings(monkeypatch, "192.168.1.20")
    assert pu.readiness()["reason"] == "ip_address"
    pu = _with_settings(monkeypatch, "http://localhost:8200")
    assert pu.readiness() == {"usable": True, "rp_id": "localhost", "origin": "http://localhost:8200", "reason": "ok"}


def test_there_is_no_second_setting_for_the_address():
    """One address, set in one place. A setting of its own for sign-in would be a second answer to "where is the
    vault", and the two could disagree."""
    set_bare_api_env()
    from app.core.config import Settings
    assert "public_url" not in Settings.model_fields
    for name in (".env.example", "dockvault.py", "app/core/config.py"):
        assert "PUBLIC_URL" not in (ROOT / name).read_text(encoding="utf-8"), name
    source = (ROOT / "app" / "core" / "public_url.py").read_text(encoding="utf-8")
    # And nothing in it is handed a request, or reads one.
    assert "PUBLIC_URL" not in source and "request." not in source and "request)" not in source
