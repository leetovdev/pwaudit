from __future__ import annotations

import hashlib
import urllib.request

from . import __version__

API = "https://api.pwnedpasswords.com/range/"


def sha1(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()


def parse_range(body: str) -> dict[str, int]:
    pairs = (line.strip().partition(":") for line in body.splitlines())
    return {suffix: int(count) for suffix, _, count in pairs if count}


class BreachChecker:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._ranges: dict[str, dict[str, int]] = {}

    def _range(self, prefix: str) -> dict[str, int]:
        if prefix not in self._ranges:
            request = urllib.request.Request(
                API + prefix,
                headers={"User-Agent": f"pwaudit/{__version__}", "Add-Padding": "true"},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                self._ranges[prefix] = parse_range(resp.read().decode("utf-8"))
        return self._ranges[prefix]

    def count(self, password: str) -> int:
        digest = sha1(password)
        return self._range(digest[:5]).get(digest[5:], 0)
