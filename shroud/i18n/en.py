STRINGS = {
    # generic
    "must_be_root": "shroud must be run as root.",
    "lang_prompt": "Select language / Выберите язык: [1] English  [2] Русский: ",
    "mode_quick": "Quick mode: applying defaults without prompts.",
    "mode_interactive": "Interactive mode: confirm each step (Enter accepts default).",
    "prompt_default": "%s [%s]: ",

    # phases
    "phase.start": "=== Phase %s: %s ===",
    "phase.preflight": "Preflight checks",
    "phase.hardening": "Host hardening",
    "phase.firewall": "Firewall",
    "phase.certs": "Panel certificate",
    "phase.stack": "Proxy stack",
    "phase.cascade": "Cascade wiring",
    "phase.verify": "Verification / self-test",
    "phase.output": "Summary",

    # step lifecycle
    "step.ok_already": "[ok] %s — already converged",
    "step.applied": "[changed] %s — applied",
    "step.verify_fail": "[fail] %s — verify() failed after apply()",
    "step.skip_dry": "[dry-run] %s — would apply",
    "step.critical_abort": "Critical step '%s' failed. Aborting safely; state preserved.",
    "step.noncritical_warn": "Non-critical step '%s' failed; continuing with partial result.",

    # preflight
    "preflight.os_unsupported": "Unsupported OS: %s. shroud supports Ubuntu 22.04/24.04.",
    "preflight.no_network": "No network reachability to %s.",
    "preflight.ip_detected": "Public IP: %s (ASN: %s, %s)",
    "preflight.asn_throttle": (
        "WARNING: provider '%s' (ASN %s) is known to throttle/RST censorship-"
        "circumvention traffic (the '~16 KB then reset' behaviour). The node will "
        "still install, but a less-flagged region/provider is recommended."),
    "preflight.strict_abort": "Aborting due to --strict on a flagged ASN.",

    # ssh
    "ssh.warn_session": "WARNING: keep this SSH session open until you have verified the new port works.",
    "ssh.port_kept": "SSH port unchanged (%s).",
    "ssh.port_changed": "SSH port changed to %s (old port still open until verified).",
    "ssh.selftest_ok": "New SSH port %s verified reachable; old port can be closed.",
    "ssh.selftest_fail": "New SSH port %s NOT reachable — rolling back to %s.",

    # reality / sni
    "sni.scanning": "Scanning server subnet for a same-ASN Reality donor SNI...",
    "sni.found": "Selected Reality donor SNI: %s",
    "sni.fallback": "SNI scan unproductive; using same-ASN fallback donor: %s",

    # output
    "output.saved": "Credentials written to %s (mode 0600).",
    "summary.title": "SHROUD — INSTALLATION SUMMARY",

    # verify
    "verify.pass": "[pass] %s",
    "verify.fail": "[fail] %s",
    "verify.note": "Verification is informational; failures are flagged, not fatal.",
}
