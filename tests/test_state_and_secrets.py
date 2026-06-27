from __future__ import annotations

import json

from shroud import state as state_mod
from shroud import paths
from shroud.log import Logger, register_secret


def test_state_roundtrip_and_perms(sandbox):
    st = state_mod.State(role="exit")
    st.set_ref("panel_user", "adm_dead")
    st.record_step("firewall.nftables", True, "sha256:abc")
    state_mod.save(st)

    p = paths.state_file()
    assert p.exists()
    assert oct(p.stat().st_mode)[-3:] == "600"
    loaded = state_mod.load()
    assert loaded.role == "exit"
    assert loaded.get_ref("panel_user") == "adm_dead"
    assert loaded.step_converged("firewall.nftables", "sha256:abc")
    assert not loaded.step_converged("firewall.nftables", "sha256:different")


def test_state_holds_no_raw_secrets(sandbox):
    st = state_mod.State()
    st.set_ref("reality_pbk", "PUBLIC")  # public key is a reference, fine
    state_mod.save(st)
    raw = paths.state_file().read_text("utf-8")
    # generated_refs must not contain a field literally named *_private*.
    data = json.loads(raw)
    assert all("private" not in k for k in data["generated_refs"])


def test_corrupt_state_does_not_brick(sandbox):
    p = paths.state_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{ this is not json", "utf-8")
    st = state_mod.load()  # must not raise
    assert isinstance(st, state_mod.State)
    assert p.with_suffix(".json.corrupt").exists()


def test_log_redacts_registered_secret(tmp_path):
    secret = "super-secret-token-1234"
    register_secret(secret)
    log = Logger(tmp_path / "x.log", verbose=False)
    log.info("test.event", note=f"value is {secret} ok")
    log.close()
    contents = (tmp_path / "x.log").read_text("utf-8")
    assert secret not in contents
    assert "REDACTED" in contents


def test_log_redacts_sensitive_keys(tmp_path):
    log = Logger(tmp_path / "y.log", verbose=False)
    log.info("creds", password="hunter2plaintext", note="ok")
    log.close()
    contents = (tmp_path / "y.log").read_text("utf-8")
    assert "hunter2plaintext" not in contents
