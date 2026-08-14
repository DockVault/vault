"""The log pull must not look broken when it is merely uncollected.

Every gate on GET /logs answers 404 or 403, so the admin panel could reason about all of them. One
failure mode answers **200 with an empty list**: nothing is writing that component's lines. Only
the combined launcher writes them, and even it writes `[sftp]` only when SFTP runs in the same
container — which the shipped default does not.

`sink_available` is that missing signal, per serveable component.

These assert something in BOTH shapes rather than skipping in one. A test that quietly skips when
the sink is absent is how the gap survived: the strongest existing ON-path assertion was
`isinstance(body["lines"], list)`, which an empty list satisfies.
"""
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def logs_state(admin):
    """Restore the component flags and disable anything minted, like the sibling module does.

    Without this a run permanently switches an exposure surface on and leaves usable tokens behind
    on the instance under test.
    """
    r = admin.get("/settings/logs")
    if r.status_code == 404:
        pytest.skip("log-pull endpoint absent on this build")
    before = r.json()
    minted = []
    yield before, minted
    for tid in minted:
        try:
            admin.post(f"/settings/logs/{tid}/disable")
        except Exception:
            pass
    try:
        admin.put("/settings/logs", json={"flags": before.get("flags", {})})
    except Exception:
        pass


def _settings(admin):
    return admin.get("/settings/logs").json()


def _mint(admin, minted, scope):
    body = admin.post("/settings/logs",
                      json={"name": "sink-availability-probe", "scope": scope}).json()
    minted.append(body["id"])
    return body["token"]


def test_settings_reports_availability_per_serveable_component(admin, logs_state):
    before, _ = logs_state
    data = _settings(admin)
    assert "sink_available" in data, f"the panel cannot gate without this: {sorted(data)}"
    avail = data["sink_available"]
    assert isinstance(avail, dict), f"must be per component, not a single flag: {avail!r}"
    # Per component precisely because the two can differ: the launcher always writes `web`, and
    # writes `sftp` only when SFTP runs alongside it.
    assert set(avail) == set(data["serveable"]), (avail, data["serveable"])
    assert all(isinstance(v, bool) for v in avail.values()), avail


def test_the_pull_matches_what_availability_promises(admin, logs_state):
    """The assertion the original coverage was missing.

    Where a component IS collected, a scoped pull must return actual lines — not merely a list.
    """
    before, minted = logs_state
    data = _settings(admin)
    if not data.get("ceiling"):
        pytest.skip("log ceiling is off on this build; run against a PLAN_LOG_PULL instance")

    admin.put("/settings/logs", json={"flags": {"web": True}})
    token = _mint(admin, minted, ["web"])
    anon = admin.clone_anonymous()
    r = anon.get("/logs", params={"service": "web"},
                 headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (r.status_code, r.text)
    lines = r.json()["lines"]

    if data["sink_available"]["web"]:
        # An empty list here means the feature is silently broken — exactly the reported state,
        # and exactly what `isinstance(lines, list)` failed to catch.
        assert lines, "web reported as collected but the pull returned nothing"
        assert any(isinstance(ln, str) and ln.startswith("[web] ") for ln in lines), lines[:3]
    else:
        # Deliberately NOT asserting the list is empty. Every profile mounts the same logs volume,
        # so a deployment switched from combined to split still has the previous configuration's
        # lines on disk and will serve them. "Nothing is being collected" is the claim; "nothing
        # can be returned" is not, and asserting it would fail on a real, correct deployment.
        assert isinstance(lines, list)


def test_sftp_is_not_advertised_as_collected_when_sftp_does_not_run(admin, logs_state):
    """The default production shape is web-only, and that is where this used to go wrong.

    `RUN_SFTP` ships empty, so the launcher never spawns the SFTP child and no `[sftp]` line is
    ever written — while a single global "sink active" flag would have claimed otherwise.
    """
    before, minted = logs_state
    data = _settings(admin)
    if not data.get("ceiling"):
        pytest.skip("log ceiling is off on this build")

    admin.put("/settings/logs", json={"flags": {"sftp": True}})
    token = _mint(admin, minted, ["sftp"])
    anon = admin.clone_anonymous()
    r = anon.get("/logs", params={"service": "sftp"},
                 headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, (r.status_code, r.text)
    sftp_lines = [ln for ln in r.json()["lines"] if isinstance(ln, str) and ln.startswith("[sftp] ")]

    if not data["sink_available"]["sftp"]:
        assert not sftp_lines, (
            "sftp reported as uncollected but its lines are being written: "
            f"{sftp_lines[:3]}"
        )
    else:
        assert sftp_lines, "sftp reported as collected but no sftp line came back"


def test_availability_is_not_exposed_to_a_non_admin(admin, logs_state):
    u = admin.create_user(role="user")
    try:
        c = admin.clone_anonymous()
        c.login(u["_username"], u["_password"])
        r = c.get("/settings/logs")
        assert r.status_code in (401, 403, 404), (r.status_code, r.text[:120])
    finally:
        admin.delete_user(u["id"])
