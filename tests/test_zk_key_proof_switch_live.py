"""The settings page cannot change the switch that postpones the key proof: only the environment can."""


def test_a_settings_save_cannot_postpone_the_key_proof(admin):
    for key in ("zk_key_proof_enforce", "ZK_KEY_PROOF_ENFORCE"):
        r = admin.put("/settings", json={key: False})
        assert r.status_code == 400, r.text
        assert "managed by the deployment environment" in r.json()["detail"]
    stored = admin.get("/settings").json()
    assert not any(k.lower() == "zk_key_proof_enforce" for k in stored), "the refused key was stored anyway"
