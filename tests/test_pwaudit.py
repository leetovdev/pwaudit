import string
import unittest
from unittest import mock

from pwaudit.breach import BreachChecker, parse_range, sha1
from pwaudit.strength import evaluate, generate, has_keyboard_walk, has_sequence, is_common


class CommonTest(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(is_common("123456"))

    def test_leet_and_suffix(self):
        for password in ("P@ssw0rd", "Password1!", "qwerty2024", "Dragon_77"):
            with self.subTest(password=password):
                self.assertTrue(is_common(password))
                self.assertEqual(evaluate(password).score, 0)

    def test_cyrillic(self):
        self.assertTrue(is_common("Пароль123"))


class PatternTest(unittest.TestCase):
    def test_digit_sequence(self):
        self.assertTrue(has_sequence("anna123x"))
        self.assertTrue(has_sequence("x987"))

    def test_letter_sequence_needs_four(self):
        self.assertFalse(has_sequence("define"))
        self.assertTrue(has_sequence("xabcdx"))

    def test_keyboard_walk(self):
        self.assertTrue(has_keyboard_walk("Zxcv!Dog"))
        self.assertTrue(has_keyboard_walk("ытрЙЦУКа"))
        self.assertFalse(has_keyboard_walk("Kitten42"))


class StrengthTest(unittest.TestCase):
    def test_short_password_is_capped(self):
        self.assertLessEqual(evaluate("K#9x!q").score, 1)

    def test_digits_only(self):
        strength = evaluate("50287163")
        self.assertIn("digits only", strength.warnings)
        self.assertLessEqual(strength.score, 1)

    def test_passphrase_is_very_strong(self):
        self.assertEqual(evaluate("correct horse battery staple").score, 4)

    def test_random_is_strong(self):
        self.assertGreaterEqual(evaluate("vH7#qL2!mZ9x").score, 3)

    def test_patterns_reduce_score(self):
        self.assertLess(evaluate("Asdfgh1990!").score, evaluate("Mvwktz8417!").score)

    def test_label(self):
        self.assertEqual(evaluate("123456").label, "very weak")


class GeneratorTest(unittest.TestCase):
    def test_classes_and_length(self):
        for _ in range(50):
            password = generate(16)
            self.assertEqual(len(password), 16)
            self.assertTrue(any(c in string.ascii_lowercase for c in password))
            self.assertTrue(any(c in string.ascii_uppercase for c in password))
            self.assertTrue(any(c in string.digits for c in password))

    def test_too_short(self):
        with self.assertRaises(ValueError):
            generate(6)

    def test_default_is_very_strong(self):
        self.assertEqual(evaluate(generate()).score, 4)


class BreachTest(unittest.TestCase):
    def test_sha1(self):
        self.assertEqual(sha1("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

    def test_parse_range_skips_garbage(self):
        self.assertEqual(parse_range("AAA:3\r\nBBB:0\n\nbroken\n"), {"AAA": 3, "BBB": 0})

    def test_only_prefix_is_sent(self):
        digest = sha1("password")
        body = f"{digest[5:]}:52256179\n0000000000000000000000000000000000A:0\n".encode()
        with mock.patch("pwaudit.breach.urllib.request.urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = body
            checker = BreachChecker()
            self.assertEqual(checker.count("password"), 52256179)
            self.assertEqual(checker.count("password"), 52256179)
        request = urlopen.call_args.args[0]
        self.assertTrue(request.full_url.endswith("/" + digest[:5]))
        self.assertNotIn(digest[5:], request.full_url)
        self.assertEqual(urlopen.call_count, 1)


if __name__ == "__main__":
    unittest.main()
