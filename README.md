# deobf — multi-decoder / deobfuscator

[![tests](https://github.com/kafkaesqueismn/deobfuscator/actions/workflows/tests.yml/badge.svg)](https://github.com/kafkaesqueismn/deobfuscator/actions/workflows/tests.yml)

A small command-line tool for CTFs and malware triage that detects and decodes
**Base64, Base32, hex, URL-encoding, ROT13 and single-byte XOR**, and can
recursively peel **layered** encodings ("chain" mode). It's a single file and
uses only the Python standard library (Python 3.9+).

```console
$ python3 deobf.py -f samples/chain_deep.txt --chain
Input: 92 bytes (text), readability score 0.27

Chain results (1 readable, showing top 1):

#1  url -> base64 -> rot13 -> base32   (score 1.00)
    flag{peel_the_onion_one_layer_at_a_time}
```

## Usage

```
python3 deobf.py STRING              # decode a string (one layer, every decoder)
python3 deobf.py -f FILE             # read a file (binary-safe)
cat blob | python3 deobf.py          # read stdin
python3 deobf.py -c STRING           # chain mode: recursively unwrap layers

options:
  -c, --chain          recursively decode layered encodings
  -d, --depth N        max layers in chain mode (default 6)
  -n, --top N          number of chain results to show (default 5)
  -t, --threshold T    min readability score 0-1 for XOR/chain hits (default 0.5)
  --full               don't truncate long output
```

The exit code is `0` if anything was decoded and `1` otherwise, so you can use
it in scripts.

**Single mode** runs every decoder once and prints each one that succeeds,
with a readability score. Binary output is shown as a hex preview. When an
output still looks encoded or is binary, the tool suggests `--chain`.

**Chain mode** does a breadth-first search: decode, then try every decoder
again on each result, up to `--depth` layers. It reports the results that read
like English or contain a flag, best first. Ties go to the shorter path.

## How it decides what's "readable"

Every candidate gets a score from 0 to 1 (`english_score`):

- **Printable ratio.** Binary garbage scores 0.
- **Character frequency.** The average English frequency of each character
  (`e`, `t`, `a`, space…), normalised so real English is about 1.0 and
  random letters are about 0.4. `_` counts as a space because flags use it
  that way.
- **Penalties.** Too few letters (punctuation soup from a wrong XOR key), too
  many spaces, and mostly-uppercase text (the case-flipped twin that key
  `k ^ 0x20` produces).
- **Flag shortcut.** Anything matching `flag{…}`, `*CTF{…}`, `HTB{…}` or
  `THM{…}` scores 1.0.

Chain mode also reports a decoded result that isn't English prose, such as a
PowerShell one-liner or a `<script>` tag, as long as nothing is left to decode
and it reads clearly better than its input.

## The encodings, and why they show up in CTFs and malware

| Encoding | Looks like | Why you see it |
|---|---|---|
| **Base64** | `SGVsbG8=` — `A–Z a–z 0–9 + /`, `=` padding, length a multiple of 4 | Turns arbitrary bytes into safe text for email, JSON, HTTP and the command line. Malware uses it constantly: `powershell -EncodedCommand`, payloads embedded in scripts, C2 traffic. In CTFs it's the "hello world" of encodings and the most common outer layer. The URL-safe variant (`-` `_`, often unpadded) shows up in JWTs and URLs. |
| **Base32** | `JBSWY3DP` — only `A–Z 2–7`, `=` padding to multiples of 8 | Case-insensitive and avoids look-alike characters, so it suits DNS names, TOTP secrets and human-typed keys. DNS-tunnelling malware uses it because hostnames are case-insensitive. A CTF tell: all caps with lots of `=`. |
| **Hex** | `48656c6c6f`, `48 65 6c`, `\x48\x65`, `0x48,0x65` | The default way to write raw bytes: shellcode, memory dumps, packet captures, hashes. Crypto challenges usually give ciphertext as hex. Only `0–9 a–f` and an even length. |
| **URL / percent** | `%3Cscript%3E` | Needed for reserved characters in URLs. Shows up in web-exploit payloads (XSS, SQLi), in logs from phishing and exploitation attempts, and double-encoded to slip past WAFs. |
| **ROT13** | `synt{...}`, `Uryyb` | Shifts each letter 13 places, and applying it twice gives back the original. It isn't encryption, just a way to hide spoilers. CTFs use it as a warm-up layer, and a `synt{` prefix gives it away. Some malware ROT13s strings, and Windows stores `UserAssist` registry keys in ROT13. |
| **Single-byte XOR** | Unreadable bytes, often handed over as hex/base64 | The cheapest way to hide strings from `strings` and signature scanners. It's very common in malware string tables, configs and shellcode stagers. With only 255 keys it falls to brute force: try them all and keep the most English-looking result (Cryptopals set 1, challenge 3). |

**Why layers?** Every layer is free to add and stops the simplest grep. CTF
authors stack them to make you recognise each one. Malware stacks them
(e.g. Base64 → XOR → Base64 → PowerShell) to get past string signatures.
Chain mode automates the "decode, look at it, decode again" loop.

## Sample inputs

The `samples/` directory holds ready-made test inputs:

| File | Encoding | Command |
|---|---|---|
| `base64.txt` | Base64 | `python3 deobf.py -f samples/base64.txt` |
| `base32.txt` | Base32 | `python3 deobf.py -f samples/base32.txt` |
| `hex.txt` | hex | `python3 deobf.py -f samples/hex.txt` |
| `url.txt` | URL-encoded XSS payload | `python3 deobf.py -f samples/url.txt` |
| `rot13.txt` | ROT13 | `python3 deobf.py -f samples/rot13.txt` |
| `xor_raw.bin` | raw XOR, key `0x5a` | `python3 deobf.py -f samples/xor_raw.bin` |
| `chain_b64_hex.txt` | Base64 of hex | `python3 deobf.py -f samples/chain_b64_hex.txt -c` |
| `chain_hex_xor.txt` | hex of XOR (key `0x37`) | `python3 deobf.py -f samples/chain_hex_xor.txt -c` |
| `chain_b64_xor_b64.txt` | Base64 → XOR `0x13` → Base64 → PowerShell | `python3 deobf.py -f samples/chain_b64_xor_b64.txt -c` |
| `chain_deep.txt` | URL → Base64 → ROT13 → Base32 → flag | `python3 deobf.py -f samples/chain_deep.txt -c` |

Quick ones to paste:

```sh
python3 deobf.py 'SGVsbG8sIHdvcmxkIQ=='                       # base64 -> Hello, world!
python3 deobf.py 'JBSWY3DPEBLW64TMMQQQ===='                   # base32 -> Hello World!
python3 deobf.py '48 65 6c 6c 6f'                             # hex    -> Hello
python3 deobf.py 'synt{ebg13_vf_abg_rapelcgvba}'              # rot13  -> flag{rot13_is_not_encryption}
# Cryptopals 1-3: hex-encoded single-byte XOR (key 'X')
python3 deobf.py -c 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
```

## Tests

```sh
python3 -m unittest -v
```

The tests cover each decoder, including rejecting inputs that aren't in its
format, the scorer's ordering, XOR key recovery (including Cryptopals 1-3),
chain mode on 2-, 3- and 4-layer stacks, false-positive checks against plain
English and random bytes, and the CLI with string, file and binary-file
input.

## Limitations

- XOR is **single-byte** only. Repeating-key XOR needs key-length analysis
  (Hamming distance), which this tool doesn't do.
- The scorer is tuned for English. Decoded output in other languages, or
  short or symbol-heavy output, can score low. Lower `--threshold` if you
  suspect a miss.
- Short strings are ambiguous: `cafe` is valid hex *and* valid Base64. Single
  mode shows every interpretation and leaves the call to you.
- `+` in URL-encoded input is kept as `+`, not turned into a space (form
  encoding), so Base64 inside URLs survives intact.
- Base32 must be uppercase. Allowing lowercase would make most English words
  "valid" Base32.

## License

MIT. See [LICENSE](LICENSE).
