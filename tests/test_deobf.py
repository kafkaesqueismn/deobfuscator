"""Tests for deobf. Run from the project root:  python3 -m unittest -v"""

import base64
import codecs
import contextlib
import io
import os
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import deobf  # noqa: E402

FLAG = b"flag{peel_the_onion_one_layer_at_a_time}"
SENTENCE = b"Attack at dawn, the password is hunter2"


def xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode(), "rot13").encode()


class TestDecoders(unittest.TestCase):
    def test_base64_standard_padded(self):
        self.assertEqual(deobf.decode_base64(base64.b64encode(SENTENCE)), SENTENCE)

    def test_base64_urlsafe_unpadded_and_wrapped(self):
        enc = base64.urlsafe_b64encode(b"\xfb\xff\xfe" + SENTENCE).rstrip(b"=")
        wrapped = enc[:20] + b"\n" + enc[20:]
        self.assertEqual(deobf.decode_base64(wrapped), b"\xfb\xff\xfe" + SENTENCE)

    def test_base64_rejects_non_base64(self):
        for bad in (b"hello world", b"abc", b"abcde", b"%%%%", b"\xff\xfe\xfd\xfc"):
            self.assertIsNone(deobf.decode_base64(bad), bad)

    def test_base32(self):
        self.assertEqual(deobf.decode_base32(base64.b32encode(SENTENCE)), SENTENCE)
        self.assertEqual(deobf.decode_base32(base64.b32encode(SENTENCE).rstrip(b"=")), SENTENCE)
        self.assertIsNone(deobf.decode_base32(b"lowercase"))
        self.assertIsNone(deobf.decode_base32(b"ABC1"))  # 1 is not in the alphabet

    def test_hex_formats(self):
        for enc in (b"48656c6c6f", b"48 65 6c 6c 6f", b"48:65:6C:6C:6F", b"0x48,0x65,0x6c,0x6c,0x6f", rb"\x48\x65\x6c\x6c\x6f"):
            self.assertEqual(deobf.decode_hex(enc), b"Hello", enc)

    def test_hex_rejects(self):
        for bad in (b"abc", b"xyz123", b"g0"):
            self.assertIsNone(deobf.decode_hex(bad), bad)

    def test_url(self):
        self.assertEqual(deobf.decode_url(b"a%20b%3Cc%3E"), b"a b<c>")
        self.assertIsNone(deobf.decode_url(b"no escapes here"))

    def test_rot13(self):
        self.assertEqual(deobf.decode_rot13(b"Uryyb, Jbeyq!"), b"Hello, World!")
        self.assertIsNone(deobf.decode_rot13(b"12345"))

    def test_xor_bruteforce_finds_key(self):
        results = deobf.xor_bruteforce(xor(SENTENCE, 0x42))
        self.assertTrue(results)
        key, plain, _ = results[0]
        self.assertEqual((key, plain), (0x42, SENTENCE))

    def test_xor_cryptopals_challenge_3(self):
        ct = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        key, plain, _ = deobf.xor_bruteforce(ct)[0]
        self.assertEqual(key, ord("X"))
        self.assertEqual(plain, b"Cooking MC's like a pound of bacon")

    def test_xor_on_random_bytes_finds_nothing(self):
        self.assertEqual(deobf.xor_bruteforce(os.urandom(256)), [])


class TestScoring(unittest.TestCase):
    def test_english_beats_encodings(self):
        s = deobf.english_score
        self.assertGreater(s(SENTENCE), s(rot13(SENTENCE)))
        self.assertGreater(s(SENTENCE), 0.8)
        for enc in (base64.b64encode(SENTENCE), base64.b32encode(SENTENCE), SENTENCE.hex().encode()):
            self.assertLess(s(enc), 0.5, enc)

    def test_flag_scores_max(self):
        self.assertEqual(deobf.english_score(b"picoCTF{s0m3_l33t_fl4g}"), 1.0)
        self.assertEqual(deobf.english_score(FLAG), 1.0)

    def test_binary_scores_zero(self):
        self.assertEqual(deobf.english_score(bytes(range(256))), 0.0)
        self.assertEqual(deobf.english_score(b""), 0.0)


class TestDecodeOnce(unittest.TestCase):
    def labels(self, data):
        return {c.label: c.data for c, _ in deobf.decode_once(data)}

    def test_detects_each_encoding(self):
        cases = {
            "base64": base64.b64encode(SENTENCE),
            "base32": base64.b32encode(SENTENCE),
            "hex": SENTENCE.hex().encode(),
            "url": urllib.parse.quote(SENTENCE).encode(),
            "rot13": rot13(SENTENCE),
            "xor(key=0x5a)": xor(SENTENCE, 0x5A),
        }
        for label, enc in cases.items():
            with self.subTest(label):
                self.assertEqual(self.labels(enc).get(label), SENTENCE)

    def test_no_xor_noise_on_structured_input(self):
        # XORing the characters of a hex string is meaningless.
        found = self.labels(SENTENCE.hex().encode())
        self.assertFalse(any(k.startswith("xor") for k in found))

    def test_plain_text_gives_no_xor_or_rot13(self):
        self.assertEqual(self.labels(b"just an ordinary sentence in english"), {})


class TestChain(unittest.TestCase):
    def best(self, data, **kw):
        results = deobf.chain_decode(data, **kw)
        self.assertTrue(results, "chain found nothing")
        return results[0]

    def test_base64_of_hex(self):
        r = self.best(base64.b64encode(FLAG.hex().encode()))
        self.assertEqual((r.path, r.data), (("base64", "hex"), FLAG))

    def test_hex_then_xor(self):
        r = self.best(xor(SENTENCE, 0x37).hex().encode())
        self.assertEqual((r.path, r.data), (("hex", "xor(key=0x37)"), SENTENCE))

    def test_four_layers(self):
        enc = urllib.parse.quote(base64.b64encode(rot13(base64.b32encode(FLAG)))).encode()
        r = self.best(enc)
        self.assertEqual(r.path, ("url", "base64", "rot13", "base32"))
        self.assertEqual(r.data, FLAG)

    def test_xor_that_yields_printable_intermediate(self):
        # base64 -> xor -> base64: the XORed layer is printable junk, not binary.
        cmd = b"powershell -nop -w hidden -c IEX(New-Object Net.WebClient)"
        r = self.best(base64.b64encode(xor(base64.b64encode(cmd), 0x13)))
        self.assertEqual(r.data, cmd)
        self.assertEqual(r.path, ("base64", "xor(key=0x13)", "base64"))

    def test_rot13_echo_not_reported(self):
        results = deobf.chain_decode(base64.b64encode(FLAG.hex().encode()))
        self.assertNotIn(rot13(FLAG), [r.data for r in results])

    def test_depth_limit(self):
        enc = FLAG
        for _ in range(4):
            enc = base64.b64encode(enc)
        self.assertEqual(self.best(enc).data, FLAG)
        self.assertFalse(any(r.data == FLAG for r in deobf.chain_decode(enc, max_depth=3)))

    def test_plain_text_and_random_find_nothing(self):
        self.assertEqual(deobf.chain_decode(b"nothing encoded here at all"), [])
        self.assertEqual(deobf.chain_decode(os.urandom(512)), [])


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = deobf.main(list(argv))
        return code, out.getvalue()

    def test_string_argument(self):
        code, out = self.run_cli(base64.b64encode(SENTENCE).decode())
        self.assertEqual(code, 0)
        self.assertIn("[base64]", out)
        self.assertIn(SENTENCE.decode(), out)

    def test_file_with_chain(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as fh:
            fh.write(base64.b64encode(FLAG.hex().encode()) + b"\n")  # trailing newline
        try:
            code, out = self.run_cli("-f", fh.name, "--chain")
        finally:
            os.unlink(fh.name)
        self.assertEqual(code, 0)
        self.assertIn("base64 -> hex", out)
        self.assertIn(FLAG.decode(), out)

    def test_binary_file_xor(self):
        with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as fh:
            fh.write(xor(SENTENCE, 0xAB))
        try:
            code, out = self.run_cli("-f", fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual(code, 0)
        self.assertIn("xor(key=0xab)", out)

    def test_nothing_found_exit_code(self):
        code, out = self.run_cli("--chain", "plain words only")
        self.assertEqual(code, 1)

    def test_render_binary_and_truncation(self):
        self.assertTrue(deobf.render(bytes(range(200))).startswith("<binary, 200 bytes>"))
        self.assertIn("truncated", deobf.render(b"a" * 5000))
        self.assertNotIn("truncated", deobf.render(b"a" * 5000, limit=None))


if __name__ == "__main__":
    unittest.main()
