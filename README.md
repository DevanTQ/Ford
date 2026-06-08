# FORD — Forensic Decoder

> **Rapid triage, multi-layer decoding, and IOC extraction — built for CTF and DFIR.**

FORD is a zero-dependency CLI that automatically detects and decodes common encodings (Base64, Hex, Binary, ROT, XOR, URL, and more), chains them recursively, and surfaces Indicators of Compromise (flags, IPs, emails, URLs) in a clean terminal output.

---

## Terminal Output

```
▶ FORD DECODER v3.7 ─── Triage & Multi-Layer Cryptanalysis CLI
────────────────────────────────────────────────────────────────────────────────
  Input Payload : aGVsbG8gd29ybGQ=
  Payload Metrics: 16 chars | Shannon Entropy: 3.75
────────────────────────────────────────────────────────────────────────────────

  ANALYSIS COMPLETE: 1 matching output pipeline(s) found
──────────────────────────────────────────────────────────────────────────────
▶ [BASE64]  Standard Base64 encoding
  Entropy:  3.56 (>6.5 suggests heavy encryption or random bytes)
  Result:   hello world

────────────────────────────────────────────────────────────────────────────────
  FORD Framework v3.7 | Streamlined Cryptanalysis & Threat Intel Triage
```

---

## Install

### From Git (recommended — installs the `ford` command globally)

```bash
git clone https://github.com/DevanTQ/ford.git
cd ford
pip install -e .
```

After that, `ford` is available system-wide — no alias needed:

```bash
ford "aGVsbG8gd29ybGQ="
```

### With Base58 support (optional)

```bash
pip install -e ".[full]"
```

---

## Usage

```
ford "[encoded_text]"
ford "[encoded_text]" --depth 3
ford "[hex_string]"   --xor 0x42
ford "[encoded_text]" --output results.txt
echo "aGVsbG8=" | ford
```

### Options

| Flag | Description |
|------|-------------|
| `--depth N` | Recursive decode depth, 1–5 (default: 1) |
| `--xor 0xKEY` | Apply static single-byte XOR with given key |
| `--output FILE` | Save results to a plain-text file |
| `--all` | Force-show weak heuristic results |
| `--no-banner` | Suppress the header line |
| `-v / --version` | Print version and exit |

---

## Features

- **Auto-detect** — Base64, Base32, Base64-URL, Base85, Base58 (optional), Hex (continuous & spaced), Binary (8-bit spaced & continuous), ROT13, ROT47, all 25 Caesar shifts, URL/percent-encode, HTML entities
- **XOR** — static single-byte with `--xor` key, or bruteforce 0x01–0xFF when no key is given
- **Multi-layer chaining** — `--depth` recursively feeds each decoded output back through all decoders
- **IOC extraction** — auto-highlights CTF flags `WORD{...}`, IPv4 addresses, emails, and URLs
- **Hash identification** — recognizes MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 by digest length
- **Magic byte detection** — identifies PNG, JPEG, ZIP, RAR, ELF, PE, PDF, MP3 in decoded binary output
- **Shannon entropy** — printed per-result to gauge encryption strength
- **File output** — `--output` saves a clean, ANSI-stripped report
- **Stdin pipe support** — `echo "..." | ford`
- **Windows compatible** — VT100/ANSI auto-enabled, graceful fallback on legacy CMD

---

## Examples

```bash
# Simple Base64
ford "aGVsbG8gd29ybGQ="

# Nested encoding (Base64 inside Hex)
ford "6147567362473867643239796247513d" --depth 2

# XOR-encrypted hex with known key
ford "2a3b1c4d" --xor 0x42

# XOR bruteforce (no key specified)
ford "08040b0b0e" --xor

# Pipe from stdin
echo "68656c6c6f" | ford

# Save results to file
ford "dGVzdA==" --output report.txt

# Show all results including weak matches
ford "aGVsbG8=" --all
```

---

## Requirements

- Python 3.8+
- No mandatory third-party packages
- Optional: `base58` for Base58 decoding, `colorama` for legacy Windows CMD color support

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Project Structure

```
ford/
├── ford.py            # Main tool
├── pyproject.toml     # Build config + entrypoint (pip install -e .)
├── requirements.txt   # Optional dependencies
├── LICENSE            # MIT
├── README.md
└── tests/
    └── test_ford.py   # 35 unit tests
```

---

## License

MIT — see [LICENSE](LICENSE)
