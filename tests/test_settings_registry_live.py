"""The settings registry's table on a running stack (app/core/settings_registry.py).

managed_settings exists with the columns the registry reads and writes, and the web app still saves an
ordinary key through PUT /settings. test_settings_registry.py covers resolving, the copy each process keeps,
the refusals and the startup contract offline.
"""
from _account_change_helpers import psql


def test_the_table_is_there_with_its_columns():
    rows = psql("SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = 'managed_settings' ORDER BY column_name")
    found = {name: (data_type, nullable) for name, data_type, nullable in (r.split("|") for r in rows.splitlines())}
    assert found == {
        "key": ("character varying", "NO"),
        "value": ("json", "YES"),
        "version": ("bigint", "NO"),
        "updated_by": ("uuid", "YES"),
        "updated_by_name": ("character varying", "YES"),
        "updated_at": ("timestamp without time zone", "NO"),
    }
    fk = psql("SELECT confdeltype FROM pg_constraint WHERE conrelid = 'managed_settings'::regclass "
              "AND contype = 'f'")
    assert fk == "n"          # ON DELETE SET NULL: deleting the account keeps the row and its name


def test_an_ordinary_setting_is_still_saved_through_put_settings(admin):
    before = admin.get("/settings").json()
    r = admin.put("/settings", json={"sharing_enabled": bool(before.get("sharing_enabled"))})
    assert r.status_code == 200, r.text
