"""
CamShield attribute/policy to Charm identifier mapping.

Charm SecretUtil parses ATTR_idx as attribute ATTR and index idx. Tokens such
as ROLE_OWNER that contain underscores are passed to BSW07 without underscores.
"""
from __future__ import annotations

import re


def to_charm_attr(attr: str) -> str:
    return attr.replace("_", "").upper()


def to_charm_attrs(attrs: list[str]) -> list[str]:
    return [to_charm_attr(a) for a in attrs]


def to_charm_policy(policy: str) -> str:
    """Replace ROLE_OWNER-style tokens with ROLEOWNER for Charm."""

    def repl(m: re.Match) -> str:
        return to_charm_attr(m.group(0))

    return re.sub(
        r"\b[A-Z][A-Z0-9_]*\b",
        repl,
        policy,
    )
