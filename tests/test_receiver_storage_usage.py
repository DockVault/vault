"""A drop vault's storage ring must show what the vault holds, not what is in flight.

The ring and the Info dialog both read `reserved_bytes`. That field is not usage: it counts bytes
reserved by an anonymous upload session that is still OPEN, and it is refunded the moment the upload
finalizes, aborts or expires. Its own model comment says so. So it sat at zero whenever anyone
actually looked at a card, and the ring appeared frozen no matter how much had been uploaded through
the link — which is exactly the report, and it was never a refresh problem.

What a person means by "used" is what the drop vault holds, which lives on the vault row as
`total_size_bytes`. The receiver payload now carries it as `stored_bytes`, fetched for the whole page
in one query rather than per row, and both readers use it.

`reserved_bytes` stays in the payload: it is part of the cap arithmetic
(stored + reserved <= max_total_bytes) and removing it would be a separate change. It is simply not
the number to draw.

Lanes:
  * unit        — the payload carries stored_bytes, the list route supplies it from the vault without
                  an N+1, and neither UI reader still draws reserved_bytes. No server.
  * integration — upload through a real link and watch the number move. This is the only lane that
                  proves the ring tracks reality; it needs a deployment running THIS code.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- unit lane

@pytest.mark.unit
def test_the_receiver_payload_reports_what_the_vault_holds():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index("def _receiver_public_dict(")
    body = src[start:src.index("\ndef ", start + 1)]

    assert "stored_bytes" in body, "the payload must carry what the drop vault holds"
    assert re.search(r'"stored_bytes": int\(stored_bytes\) if stored_bytes is not None else None',
                     body), (
        "stored_bytes must distinguish 'nothing stored' from 'not known' — an absent figure "
        "silently drawn as 0 is how a full vault reads as empty")
    # reserved_bytes stays (cap arithmetic) but must no longer be described as usage.
    assert '"reserved_bytes"' in body, "reserved_bytes is still part of the cap arithmetic"


@pytest.mark.unit
def test_the_list_route_supplies_stored_bytes_in_one_query():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index("async def list_receivers(")
    body = src[start:src.index("\n@app.", start + 1)]

    assert "Vault.total_size_bytes" in body, (
        "the list route must read the figure off the vault; the receiver row does not hold it")
    assert ".filter(Vault.id.in_(" in body, (
        "the sizes must be fetched for the whole page at once — a per-receiver lookup here is an "
        "N+1 on a list route")
    # The query must actually run when there are receivers. Disabling it leaves every card reading
    # zero while all the text above still matches, so the condition is pinned explicitly — this is
    # the one mutation the earlier version of this test slept through.
    assert re.search(r"\)\s*if vault_ids else \{\}", body), (
        "the batched lookup must be guarded on vault_ids, not switched off")
    assert re.search(r"_receiver_public_dict\(r, tags\.get\(r\.tag_id\), stored\.get\(r\.vault_id\)",
                     body), "each receiver must be given its own vault's size"


@pytest.mark.unit
def test_neither_the_ring_nor_the_info_dialog_draws_in_flight_bytes():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    start = app.index("function renderReceiverVaults(")
    card = app[start:app.index("\nfunction ", start + 1)]

    assert "r.stored_bytes" in card, "the ring must read stored_bytes"
    assert "r.reserved_bytes" not in card, (
        "the ring is still reading reserved_bytes, which is refunded on finalize and therefore "
        "zero whenever anyone looks at it")

    start = app.index("function openReceiverInfoModal(")
    info = app[start:app.index("\nfunction ", start + 1)]
    assert "r.stored_bytes" in info, "the Info dialog's Storage row must read stored_bytes"
    assert "r.reserved_bytes" not in info, (
        "the Info dialog still shows in-flight bytes as storage — the same defect as the ring, and "
        "fixing only the card would leave the dialog contradicting it")


# --------------------------------------------------------------------------- integration lane

@pytest.mark.integration
def test_uploading_through_a_link_moves_the_stored_figure(admin):
    """The only check that proves the ring tracks reality. Needs a deployment of THIS code.

    Deliberately asserts BOTH halves: stored rises, and reserved returns to zero. Asserting only
    that stored rose would still pass if the two fields were swapped somewhere upstream.
    """
    tags = admin.get("/receiver-tags").json()
    tag = (tags.get("tags") or tags)[0]
    created = admin.post("/receivers", json={"tag_id": tag["id"], "label": "usage-check",
                                             "max_total_bytes": 10 * 1024 * 1024})
    assert created.status_code in (200, 201), created.text
    rec = created.json()
    token_url = rec.get("url_path") or f"/u/{rec['token']}"

    def card():
        rows = admin.get("/receivers").json()["receivers"]
        return next(r for r in rows if r["id"] == rec["id"])

    before = card()
    assert before["stored_bytes"] == 0, before

    body = b"x" * 4096
    up = admin.post(f"{token_url}/upload",
                    files=[("file", ("blob.bin", body, "application/octet-stream"))])
    assert up.status_code in (200, 201), up.text

    after = card()
    assert after["stored_bytes"] >= len(body), (
        f"the drop vault holds a file but reports {after['stored_bytes']} bytes stored")
    assert after["reserved_bytes"] == 0, (
        f"the upload finished, so nothing should still be reserved: {after['reserved_bytes']}")
