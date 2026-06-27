"""Jinja2 rendering of component configs from the volatile profile.

Templates live next to this module. Compose itself is built as a Python dict and
dumped to YAML (see :mod:`shroud.components.stack`) — only per-component config
files that have their own native syntax (TOML/YAML/nginx) are templated here.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

_TEMPLATE_DIR = Path(__file__).resolve().parent

_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    autoescape=False,
)


def render(template_name: str, **context) -> str:
    return _env.get_template(template_name).render(**context)
