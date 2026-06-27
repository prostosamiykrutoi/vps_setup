from __future__ import annotations

from shroud.phases import p7_output
from shroud import paths


def _seed(ctx):
    ctx.dry_run = False
    ctx.runner.dry_run = False
    ctx.credentials["panel_user"] = "adm_abcd"
    ctx.credentials["panel_pass"] = "PANELPASS123"
    ctx.links = [("VLESS-Reality-XHTTP", "vless://uuid@ip:443?type=xhttp")]
    ctx.summary["subscription"] = "http://203.0.113.7:2096/sub/abcd1234"
    ctx.summary["panel_cert"] = "self-signed (10y)"


def test_summary_text_has_key_sections(ctx):
    _seed(ctx)
    text = p7_output.build_summary_text(ctx)
    assert "ROLE: standalone" in text
    assert "ssh -L 2053:127.0.0.1:2053" in text
    assert "VLESS-Reality-XHTTP" in text
    assert "SUBSCRIPTION:" in text


def test_credentials_file_written_0600_with_secrets(ctx):
    _seed(ctx)
    p7_output.run(ctx)
    creds = paths.credentials_file()
    assert creds.exists()
    assert oct(creds.stat().st_mode)[-3:] == "600"
    body = creds.read_text("utf-8")
    # The credentials file is the ONE place secrets are allowed.
    assert "PANELPASS123" in body


def test_log_file_has_no_secret(ctx, tmp_path):
    _seed(ctx)
    p7_output.run(ctx)
    ctx.log.close()
    # The structured log must never contain the panel password.
    log_text = (tmp_path / "shroud.log").read_text("utf-8")
    assert "PANELPASS123" not in log_text


def test_exit_role_shows_connect_info(ctx):
    _seed(ctx)
    ctx.role = "exit"
    ctx.summary["connect_info_token"] = "shroud-exit://abc"
    ctx.summary["connect_info_file"] = "/root/shroud-connect-info.json"
    text = p7_output.build_summary_text(ctx)
    assert "CONNECT-INFO for entry node" in text
    assert "shroud-exit://abc" in text
