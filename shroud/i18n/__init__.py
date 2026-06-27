"""Tiny i18n layer: two flat dicts + a translator with %-formatting.

Missing keys fall back: ru -> en -> the key itself, so partial translations
degrade gracefully rather than crashing.
"""
from __future__ import annotations

from .en import STRINGS as _EN
from .ru import STRINGS as _RU

_TABLES = {"en": _EN, "ru": _RU}


class Translator:
    def __init__(self, lang: str = "en"):
        self.lang = lang if lang in _TABLES else "en"

    def __call__(self, key: str, *args: object) -> str:
        template = _TABLES[self.lang].get(key) or _EN.get(key) or key
        if args:
            try:
                return template % args
            except (TypeError, ValueError):
                return template
        return template


def available_langs() -> list[str]:
    return list(_TABLES)
