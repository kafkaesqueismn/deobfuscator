#!/usr/bin/env python3
"""deobf - a multi-decoder / deobfuscator for CTFs and malware triage.

Standard library only. Detects and decodes Base64, Base32, hex, URL-encoding,
ROT13 and single-byte XOR, and can recursively unwrap layered encodings
("chain" mode).

    python3 deobf.py 'SGVsbG8sIHdvcmxkIQ=='
    python3 deobf.py -f payload.txt --chain
    echo '4a6f...' | python3 deobf.py --chain
"""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import re
import sys
import urllib.parse
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterator

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """One decoding attempt that succeeded structurally."""

    label: str  # e.g. "base64" or "xor(key=0x2a)"
    data: bytes


@dataclass(frozen=True)
class ChainResult:
    path: tuple[str, ...]  # e.g. ("base64", "hex", "rot13")
    data: bytes
    score: float


# ---------------------------------------------------------------------------
# Scoring: "does this look like readable English (or a CTF flag)?"
# ---------------------------------------------------------------------------

# Relative frequency of letters in English text (sums to ~1.0).
_LETTER_FREQ = {
    "a": 0.0817, "b": 0.0149, "c": 0.0278, "d": 0.0425, "e": 0.1270,
    "f": 0.0223, "g": 0.0202, "h": 0.0609, "i": 0.0697, "j": 0.0015,
    "k": 0.0077, "l": 0.0403, "m": 0.0241, "n": 0.0675, "o": 0.0751,
    "p": 0.0193, "q": 0.0010, "r": 0.0599, "s": 0.0633, "t": 0.0906,
    "u": 0.0276, "v": 0.0098, "w": 0.0236, "x": 0.0015, "y": 0.0197,
    "z": 0.0007,
}
# Per-character frequency in running text: ~18% of characters are spaces.
# '_' counts as a space because CTF flags use it as a word separator.
_SPACE_FREQ = 0.18
CHAR_FREQ = {c: f * (1 - _SPACE_FREQ) for c, f in _LETTER_FREQ.items()}
CHAR_FREQ[" "] = CHAR_FREQ["_"] = _SPACE_FREQ
# The mean CHAR_FREQ of genuine English text is sum(f^2); normalise against it
# so typical English scores ~1.0 and random letters score ~0.4.
_EXPECTED = sum(f * f for c, f in CHAR_FREQ.items() if c != "_")

_PRINTABLE = frozenset(range(32, 127)) | {9, 10, 13}
FLAG_RE = re.compile(r"(?i)\b(?:flag|[a-z0-9]{0,12}ctf|htb|thm)\{[^{}\n]{1,200}\}")

_SCORE_SAMPLE = 4096  # score only a prefix of large inputs (speed)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def is_mostly_printable(data: bytes, cutoff: float = 0.95) -> bool:
    return printable_ratio(data[:_SCORE_SAMPLE]) >= cutoff


def english_score(data: bytes) -> float:
    """Return 0.0-1.0: how much `data` looks like English text or a flag."""
    data = data[:_SCORE_SAMPLE]
    if not data:
        return 0.0
    p_ratio = printable_ratio(data)
    if p_ratio < 0.85:  # binary garbage
        return 0.0
    text = data.decode("latin-1")
    if FLAG_RE.search(text):
        return 1.0
    mean_freq = sum(CHAR_FREQ.get(c.lower(), 0.0) for c in text) / len(text)
    fit = min(1.0, mean_freq / _EXPECTED)
    # English is mostly lower case; XOR keys that differ by 0x20 produce
    # case-flipped "sHOUTING" variants, so mildly penalise mostly-upper text.
    letters = [c for c in text if c.isascii() and c.isalpha()]
    upper = sum(c.isupper() for c in letters)
    case_factor = 0.8 if letters and upper / len(letters) > 0.6 else 1.0
    # English is ~75% letters; wrong XOR keys tend to give punctuation soup.
    alpha_factor = min(1.0, len(letters) / len(text) / 0.6)
    # ...and ~18% spaces; far more than that is not prose.
    space_ratio = (text.count(" ") + text.count("_")) / len(text)
    space_factor = max(0.0, 1.0 - max(0.0, space_ratio - 0.3) * 3)
    return round(p_ratio**3 * fit * case_factor * alpha_factor * space_factor, 3)


# ---------------------------------------------------------------------------
# Decoders. Each takes bytes and returns bytes, or None when the input is not
# plausibly in that encoding. Being strict here keeps chain mode from exploding.
# ---------------------------------------------------------------------------


def _ascii(data: bytes) -> str | None:
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return None


_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7]+=*$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HEX_NOISE_RE = re.compile(r"0x|\\x|[\s:,]", re.IGNORECASE)


def decode_base64(data: bytes) -> bytes | None:
    s = _ascii(data)
    if s is None:
        return None
    s = re.sub(r"[\r\n\t]", "", s.strip())  # undo line-wrapping
    if len(s) < 4 or not _B64_RE.match(s) or len(s.rstrip("=")) % 4 == 1:
        return None
    # Accept URL-safe alphabet and missing padding; both are common in the wild.
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_base32(data: bytes) -> bytes | None:
    s = _ascii(data)
    if s is None:
        return None
    s = re.sub(r"\s", "", s)
    core = s.rstrip("=")
    if len(core) < 2 or not _B32_RE.match(s) or len(core) % 8 not in (0, 2, 4, 5, 7):
        return None
    try:
        return base64.b32decode(core + "=" * (-len(core) % 8))
    except (binascii.Error, ValueError):
        return None


def decode_hex(data: bytes) -> bytes | None:
    s = _ascii(data)
    if s is None:
        return None
    s = _HEX_NOISE_RE.sub("", s)  # tolerate "de ad", "de:ad", "0xde,0xad", "\xde\xad"
    if len(s) < 2 or len(s) % 2 or not _HEX_RE.match(s):
        return None
    return bytes.fromhex(s)


def decode_url(data: bytes) -> bytes | None:
    s = _ascii(data)
    if s is None or not re.search(r"%[0-9A-Fa-f]{2}", s):
        return None
    return urllib.parse.unquote_to_bytes(s)


def decode_rot13(data: bytes) -> bytes | None:
    s = _ascii(data)
    if s is None or not re.search(r"[A-Za-z]", s):
        return None
    return codecs.encode(s, "rot13").encode("ascii")


TEXT_DECODERS: list[tuple[str, Callable[[bytes], bytes | None]]] = [
    ("hex", decode_hex),
    ("base64", decode_base64),
    ("base32", decode_base32),
    ("url", decode_url),
    ("rot13", decode_rot13),
]
# Decoders that require a specific, structured alphabet (unlike ROT13).
STRUCTURAL = ("hex", "base64", "base32", "url")

# One translation table per key turns XOR into a fast C-level bytes.translate.
_XOR_TABLES = [bytes(b ^ k for b in range(256)) for k in range(256)]


def xor_bruteforce(data: bytes, top: int = 3, min_score: float = 0.5) -> list[tuple[int, bytes, float]]:
    """Try all single-byte XOR keys; return the best (key, plaintext, score)."""
    sample = data[:_SCORE_SAMPLE]
    scored = []
    for key in range(1, 256):  # key 0 is the identity
        s = english_score(sample.translate(_XOR_TABLES[key]))
        if s >= min_score:
            scored.append((s, key))
    scored.sort(reverse=True)
    return [(k, data.translate(_XOR_TABLES[k]), s) for s, k in scored[:top]]


# ---------------------------------------------------------------------------
# Single-layer mode
# ---------------------------------------------------------------------------


def decode_once(data: bytes, threshold: float = 0.5, xor_top: int = 3) -> list[tuple[Candidate, float]]:
    """Apply every decoder once to `data`."""
    results = []
    base = english_score(data)
    for name, fn in TEXT_DECODERS:
        out = fn(data)
        if out is None or out == data:
            continue
        score = english_score(out)
        # ROT13 "works" on any text with letters; only report it if it beats
        # the input AND is readable (or a clear win when nothing else matched).
        # (rot13 is last in TEXT_DECODERS, so `results` holds the others.)
        if name == "rot13" and (
            score <= base or (score < threshold and (results or score < base + 0.2))
        ):
            continue
        results.append((Candidate(name, out), score))
    # If the input is already valid hex/base64/etc, XORing its *characters* is
    # meaningless - decode that layer first (--chain does it automatically).
    structural = any(c.label in STRUCTURAL for c, _ in results)
    if not structural:
        # Only report XOR results that are *more* readable than the input,
        # otherwise plain text yields case-flipped "decodes".
        for key, out, s in xor_bruteforce(data, top=xor_top, min_score=threshold):
            if s > base + 0.05:
                results.append((Candidate(f"xor(key=0x{key:02x})", out), s))
    return results


# ---------------------------------------------------------------------------
# Chain mode: breadth-first search over the tree of possible decodings.
# ---------------------------------------------------------------------------


def _looks_encoded(data: bytes) -> bool:
    return len(data) >= 8 and any(
        fn(data) is not None for name, fn in TEXT_DECODERS if name in ("hex", "base64", "base32")
    )


def _is_terminal(data: bytes) -> bool:
    """Printable, and no structural decoder applies: nothing left to peel."""
    return is_mostly_printable(data) and not any(
        fn(data) is not None for name, fn in TEXT_DECODERS if name in STRUCTURAL
    )


def _expand(data: bytes, path: tuple[str, ...], score: float, threshold: float) -> Iterator[Candidate]:
    if is_mostly_printable(data):
        # Text: try the text encodings.
        for name, fn in TEXT_DECODERS:
            if name == "rot13" and path and path[-1] == "rot13":
                continue  # rot13 twice is the identity
            out = fn(data)
            if out is not None and out != data:
                yield Candidate(name, out)
    # XOR binary data - and printable junk that is neither readable nor another
    # encoding (XOR can map text to text). Never XOR right after ROT13: ROT13
    # of junk is still junk, and it doubles the search for nothing.
    after_rot13 = bool(path) and path[-1] == "rot13"
    if not after_rot13 and (not is_mostly_printable(data) or (score < 0.4 and _is_terminal(data))):
        # Keep keys that give readable text, or text that is itself another
        # encoding layer.
        for key in range(1, 256):
            out = data.translate(_XOR_TABLES[key])
            if is_mostly_printable(out) and (english_score(out) >= threshold or _looks_encoded(out)):
                yield Candidate(f"xor(key=0x{key:02x})", out)


def chain_decode(
    data: bytes, max_depth: int = 6, threshold: float = 0.5, max_nodes: int = 5000
) -> list[ChainResult]:
    """Recursively decode; return readable results, best first.

    A node is reported if it scores >= threshold, or if it is a terminal
    (nothing left to decode) that is more readable than its parent - this
    catches decoded code/commands that are not English prose.
    """
    root_score = english_score(data)
    queue: deque[tuple[bytes, tuple[str, ...], float]] = deque([(data, (), root_score)])
    seen = {data}  # never revisit the same bytes (prevents cycles)
    found: list[ChainResult] = []
    expanded = 0
    while queue and expanded < max_nodes:
        cur, path, cur_score = queue.popleft()
        expanded += 1
        if len(path) >= max_depth:
            continue
        for cand in _expand(cur, path, cur_score, threshold):
            if cand.data in seen:
                continue
            seen.add(cand.data)
            new_path = path + (cand.label,)
            score = english_score(cand.data)
            if cand.label == "rot13":
                # Don't report "synt{...}" next to "flag{...}".
                report = score >= threshold and score > cur_score
            else:
                improved_leaf = (
                    score > max(cur_score, root_score) + 0.1 and _is_terminal(cand.data)
                )
                report = score >= threshold or improved_leaf
            if report:
                found.append(ChainResult(new_path, cand.data, score))
            queue.append((cand.data, new_path, score))
    # Best score first; among equals prefer the simplest explanation.
    found.sort(key=lambda r: (-r.score, len(r.path)))
    return found


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def render(data: bytes, limit: int | None = 2000) -> str:
    """Human-readable view of decoded bytes."""
    if not is_mostly_printable(data, 0.85):
        preview = data[:48].hex(" ")
        more = " ..." if len(data) > 48 else ""
        return f"<binary, {len(data)} bytes> {preview}{more}"
    text = "".join(
        c if 32 <= ord(c) < 127 or c in "\n\t" else f"\\x{ord(c):02x}" for c in data.decode("latin-1")
    )
    if limit and len(text) > limit:
        text = text[:limit] + f"... [truncated, {len(text)} chars total; use --full]"
    return text


def _indent(text: str) -> str:
    return "\n".join("    " + line for line in text.splitlines() or [""])


def read_input(args: argparse.Namespace) -> bytes:
    if args.file:
        with open(args.file, "rb") as fh:
            data = fh.read()
    elif args.data is not None:
        data = args.data.encode("utf-8", "surrogateescape")
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        raise SystemExit("error: give a string, -f FILE, or pipe data on stdin (see --help)")
    # Drop the trailing newline that text files / echo add.
    if is_mostly_printable(data):
        data = data.rstrip(b"\r\n")
    return data


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="deobf",
        description="Detect and decode Base64, Base32, hex, URL, ROT13 and single-byte XOR.",
    )
    p.add_argument("data", nargs="?", help="string to decode (or use -f / stdin)")
    p.add_argument("-f", "--file", help="read input from a file (binary-safe)")
    p.add_argument("-c", "--chain", action="store_true", help="recursively decode layered encodings")
    p.add_argument("-d", "--depth", type=int, default=6, help="max layers in chain mode (default 6)")
    p.add_argument("-n", "--top", type=int, default=5, help="results to show in chain mode (default 5)")
    p.add_argument(
        "-t", "--threshold", type=float, default=0.5,
        help="min readability score 0-1 for XOR/chain results (default 0.5)",
    )
    p.add_argument("--full", action="store_true", help="do not truncate long output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    data = read_input(args)
    limit = None if args.full else 2000
    kind = "text" if is_mostly_printable(data) else "binary"
    print(f"Input: {len(data)} bytes ({kind}), readability score {english_score(data):.2f}\n")

    if args.chain:
        results = chain_decode(data, max_depth=args.depth, threshold=args.threshold)
        if not results:
            print("No readable result found. Try a lower --threshold or higher --depth.")
            return 1
        print(f"Chain results ({len(results)} readable, showing top {min(args.top, len(results))}):\n")
        for i, r in enumerate(results[: args.top], 1):
            print(f"#{i}  {' -> '.join(r.path)}   (score {r.score:.2f})")
            print(_indent(render(r.data, limit)) + "\n")
        return 0

    results = decode_once(data, threshold=args.threshold)
    if not results:
        print("No decoder matched.")
        return 1
    for cand, score in results:
        print(f"[{cand.label}]  (score {score:.2f})")
        print(_indent(render(cand.data, limit)) + "\n")
    if any(_looks_encoded(c.data) or not is_mostly_printable(c.data) for c, _ in results):
        print("Hint: some output looks encoded or binary - try --chain to peel further layers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
