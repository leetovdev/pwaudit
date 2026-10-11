from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass, field

COMMON = frozenset("""
123456 123456789 12345678 12345 1234567 1234567890 1234 111111 000000 123123 654321 666666 121212
112233 159753 987654321 123321 7777777 888888 password password1 passw0rd qwerty qwerty123
qwertyuiop qwe123 1q2w3e 1q2w3e4r 1qaz2wsx zaq12wsx qazwsx asdfghjkl azerty abc123 iloveyou
dragon sunshine princess letmein monkey superman batman trustno1 football baseball welcome admin
admin123 administrator root toor master shadow michael jennifer killer starwars login hello
freedom whatever ninja solo loveme flower test test123 guest changeme default secret pass
matrix minecraft pokemon naruto samsung iphone google
пароль йцукен любовь привет
""".split())

ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
TRAILING = re.compile(r"[\d\W_]+$")
YEAR = re.compile(r"(?<!\d)(?:19[5-9]\d|20[0-4]\d)(?!\d)")
REPEAT = re.compile(r"(.)\1{2,}")
LABELS = ("very weak", "weak", "fair", "strong", "very strong")
THRESHOLDS = (28, 36, 60, 80)
SYMBOLS = "!#$%&*+-=?@^_"


@dataclass
class Strength:
    length: int
    entropy: float
    score: int
    warnings: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return LABELS[self.score]


def charset_size(password: str) -> int:
    classes = (
        (26, lambda c: c.isascii() and c.islower()),
        (26, lambda c: c.isascii() and c.isupper()),
        (10, str.isdigit),
        (33, lambda c: c in string.punctuation or c == " "),
        (66, lambda c: not c.isascii()),
    )
    return sum(size for size, test in classes if any(test(c) for c in password))


def _is_run(chunk: str) -> bool:
    steps = {ord(b) - ord(a) for a, b in zip(chunk, chunk[1:])}
    return steps in ({1}, {-1})


def has_sequence(text: str) -> bool:
    for i in range(len(text) - 2):
        three = text[i:i + 3]
        if _is_run(three) and (three.isdigit() or len(text) - i >= 4 and _is_run(text[i:i + 4])):
            return True
    return False


def has_keyboard_walk(text: str, size: int = 4) -> bool:
    lowered = text.lower()
    return any(
        line[i:i + size] in lowered
        for row in ROWS
        for line in (row, row[::-1])
        for i in range(len(line) - size + 1)
    )


def is_common(password: str) -> bool:
    lowered = password.lower()
    return lowered in COMMON or TRAILING.sub("", lowered).translate(LEET) in COMMON


def evaluate(password: str) -> Strength:
    size = charset_size(password)
    entropy = len(password) * math.log2(size) if size else 0.0

    if is_common(password):
        return Strength(len(password), round(entropy, 1), 0, ["one of the most common passwords"])

    checks = (
        (len(password) < 8, "shorter than 8 characters", 0),
        (password.isdigit(), "digits only", 10),
        (bool(REPEAT.search(password)), "repeated characters like aaa", 10),
        (has_sequence(password.lower()), "sequence like abcd or 123", 12),
        (has_keyboard_walk(password), "keyboard pattern like qwer", 12),
        (bool(YEAR.search(password)), "contains a year", 8),
    )
    warnings = [text for hit, text, _ in checks if hit]
    effective = max(0.0, entropy - sum(cost for hit, _, cost in checks if hit))
    score = sum(effective >= t for t in THRESHOLDS)
    if len(password) < 8:
        score = min(score, 1)
    return Strength(len(password), round(effective, 1), score, warnings)


def generate(length: int = 20) -> str:
    if length < 8:
        raise ValueError("length must be at least 8")
    alphabet = string.ascii_letters + string.digits + SYMBOLS
    required = (str.islower, str.isupper, str.isdigit, lambda c: c in SYMBOLS)
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(test(c) for c in candidate) for test in required):
            return candidate
