from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from morepath import Request


def refresh_nonce_handler(request: Request, userid: str) -> str:
    return "__" + userid + "__"
