"""Static check (no running instance needed): the grid file-tile action clusters are laid out IN
FLOW in BOTH skins, not absolutely positioned over the icon. Complements the runtime grid test in
test_ui_grid_card_interaction.py, which exercises only the default (Console) skin."""
from pathlib import Path

import pytest

CSS_DIR = Path(__file__).resolve().parent.parent / "static" / "css"


@pytest.mark.parametrize("skin", ["ui-v2.css", "redesign.css"])
def test_grid_action_row_is_in_flow(skin):
    text = (CSS_DIR / skin).read_text(encoding="utf-8")
    # the new in-flow action row exists
    assert ".file-tile .tile-actions" in text, f"{skin}: missing the .tile-actions in-flow row"
    # the tile control clusters are no longer absolutely pinned to the tile's top corners
    # (the old rules were `.file-tile .tile-tl/.file-actions { position: absolute; top: .35rem; ... }`)
    assert "position: absolute; top: .35rem" not in text, \
        f"{skin}: a file-tile action cluster is still absolute-positioned over the icon"
