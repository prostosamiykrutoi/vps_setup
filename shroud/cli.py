"""shroud CLI — command/flag parsing, mode/language selection, dispatch."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, profile as profile_mod, state as state_mod
from .context import Context
from .i18n import Translator, available_langs


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shroud", description="anti-censorship node orchestrator")
    p.add_argument("--version", action="version", version=f"shroud {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--role", choices=["standalone", "exit", "entry"],
                        default="standalone")
        sp.add_argument("--mode", choices=["quick", "interactive"], default="quick")
        sp.add_argument("--lang", choices=available_langs(), default=None)
        sp.add_argument("--profile", default=None, help="path or URL to a profile")
        sp.add_argument("--ssh-port", type=int, default=None)
        sp.add_argument("--panel-port", type=int, default=None)
        sp.add_argument("--exit", dest="exit_bundle", default=None,
                        help="connect-info file/URL/token (role=entry)")
        sp.add_argument("--strict", action="store_true",
                        help="abort on a known-throttling ASN")
        sp.add_argument("--yes", dest="assume_yes", action="store_true")
        sp.add_argument("--verbose", action="store_true")

    for name in ("install", "dry-run", "update", "verify", "status",
                 "show-sub", "uninstall"):
        common(sub.add_parser(name))

    au = sub.add_parser("add-user")
    common(au)
    au.add_argument("user_name", help="label for the new client")
    return p


def _select_lang(args) -> str:
    if args.lang:
        return args.lang
    env = os.environ.get("SHROUD_LANG")
    if env in available_langs():
        return env
    # First-run prompt (quick+non-tty falls back to en).
    if getattr(args, "mode", "quick") == "interactive" and sys.stdin.isatty():
        t = Translator("en")
        try:
            choice = input(t("lang_prompt")).strip()
        except EOFError:
            choice = ""
        return "ru" if choice == "2" else "en"
    return "en"


def _make_context(args) -> Context:
    lang = _select_lang(args)
    prof = profile_mod.load(args.profile)
    ctx = Context(
        role=getattr(args, "role", "standalone"),
        mode=getattr(args, "mode", "quick"),
        lang=lang,
        assume_yes=getattr(args, "assume_yes", False),
        verbose=getattr(args, "verbose", False),
        strict=getattr(args, "strict", False),
        exit_bundle=getattr(args, "exit_bundle", None),
        profile=prof,
        state=state_mod.load(),
    )
    if args.ssh_port:
        ctx.ssh_port = args.ssh_port
    if args.panel_port:
        ctx.panel_port = args.panel_port
        prof.panel["port"] = args.panel_port
    if ctx.mode == "interactive":
        ctx.log.info("mode", msg=ctx.t("mode_interactive"))
        ctx.ssh_port = int(ctx.prompt("SSH port", str(ctx.ssh_port)))
    else:
        ctx.log.info("mode", msg=ctx.t("mode_quick"))
    return ctx


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if os.geteuid() != 0 and args.command not in ("show-sub", "status", "dry-run"):
        print(Translator(_select_lang(args))("must_be_root"), file=sys.stderr)
        return 1

    from . import orchestrator
    ctx = _make_context(args)

    try:
        if args.command == "install":
            orchestrator.install(ctx)
        elif args.command == "dry-run":
            orchestrator.dry_run(ctx)
        elif args.command == "update":
            orchestrator.update(ctx)
        elif args.command == "verify":
            orchestrator.verify_only(ctx)
        elif args.command == "status":
            orchestrator.status(ctx)
        elif args.command == "show-sub":
            orchestrator.show_sub(ctx)
        elif args.command == "add-user":
            orchestrator.add_user(ctx, args.user_name)
        elif args.command == "uninstall":
            orchestrator.uninstall(ctx)
        else:
            print(f"unknown command {args.command}", file=sys.stderr)
            return 2
    except profile_mod.ProfileError as exc:
        print(f"profile error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # fail safe: never leave a half-state silently
        ctx.log.error("fatal", error=str(exc))
        print(f"shroud: fatal: {exc}", file=sys.stderr)
        return 1
    finally:
        ctx.log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
