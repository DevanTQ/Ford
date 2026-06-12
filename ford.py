#!/usr/bin/env python3
"""
FORD - Forensic Decoder CLI Tool
Author: Jarvis
Version: 3.8

Usage:
    ford "[encoded_text]"
    ford "[encoded_text]" --xor 0x42
    ford "[encoded_text]" --depth 3
    echo "text" | ford
"""

import sys
import base64
import codecs
import urllib.parse
import re
import string
import argparse
import math
import os

_ANSI_SUPPORTED = True

if os.name == 'nt':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        try:
            import colorama
            colorama.init(autoreset=False)
        except ImportError:
            _ANSI_SUPPORTED = False

if os.name == 'nt':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def _ansi(code):
    return code if _ANSI_SUPPORTED else ''

class C:
    GREEN   = _ansi('\033[92m')
    CYAN    = _ansi('\033[96m')
    RED     = _ansi('\033[91m')
    YELLOW  = _ansi('\033[93m')
    BLUE    = _ansi('\033[94m')
    MAGENTA = _ansi('\033[95m')
    BOLD    = _ansi('\033[1m')
    DIM     = _ansi('\033[2m')
    RESET   = _ansi('\033[0m')

def _supports_unicode():
    try:
        '▶★─'.encode(sys.stdout.encoding or 'utf-8')
        return True
    except (UnicodeEncodeError, LookupError):
        return False

_UNI = _supports_unicode()

ICON_ARROW  = '▶' if _UNI else '>'
ICON_STAR   = '★' if _UNI else '*'
ICON_LINE   = '─' if _UNI else '-'

# ---------------------------------------------------------------------------
# Confidence scoring (replaces wordlist gate)
# HIGH  = almost certainly meaningful output
# MED   = plausibly meaningful, worth showing
# LOW   = weak match, shown only with --all
# ---------------------------------------------------------------------------

_COMMON_WORDS = {
    'the','and','for','are','but','not','you','all','can','had','her','was','one','our',
    'out','day','get','has','him','his','how','man','new','now','old','see','two','way',
    'who','boy','did','its','let','put','say','she','too','use','that','with','have',
    'this','from','they','know','want','been','good','much','some','time','very','when',
    'hello','world','test','data','text','file','name','code','work','home','help',
    'system','program','computer','network','server','client','access','login','admin',
    'flag','ctf','hack','key','pass','secret','root','user','encode','decode','cipher'
}

CONF_HIGH = "HIGH"
CONF_MED  = "MED"
CONF_LOW  = "LOW"

CONF_COLOR = {
    CONF_HIGH: C.GREEN,
    CONF_MED:  C.YELLOW,
    CONF_LOW:  C.DIM,
}

def confidence_score(decoded: str, raw_data: bytes, enc_name: str) -> str:
    """
    Returns CONF_HIGH / CONF_MED / CONF_LOW without relying on a wordlist gate.

    HIGH criteria (any one is enough):
      - Contains a CTF-style flag pattern  WORD{...}
      - Contains an IP, email, or URL
      - Contains 2+ common English words
      - Entropy < 3.5  AND  all-printable  AND  len >= 4
      - Is a known hash (enc_name starts with HASH)

    MED criteria:
      - All printable AND entropy < 5.5
      - OR printable ratio > 0.85

    LOW:
      - Everything else that is at least minimally printable
    """
    if enc_name.startswith("HASH"):
        return CONF_HIGH

    insights = find_insights(decoded)
    if insights:
        return CONF_HIGH

    words = re.findall(r'[a-zA-Z]{3,}', decoded.lower())
    common_hits = sum(1 for w in words if w in _COMMON_WORDS)
    if common_hits >= 2:
        return CONF_HIGH

    ent = shannon_entropy(raw_data)
    printable_ratio = sum(1 for c in decoded if c in _SAFE_PRINTABLE) / max(len(decoded), 1)

    if printable_ratio == 1.0 and ent < 3.5 and len(decoded) >= 4:
        return CONF_HIGH

    if printable_ratio == 1.0 and ent < 5.5:
        return CONF_MED

    if printable_ratio > 0.85:
        return CONF_MED

    return CONF_LOW


MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': "PNG Image File",
    b'\xff\xd8\xff': "JPEG Image File",
    b'PK\x03\x04': "ZIP Archive",
    b'Rar!\x1a\x07\x00': "RAR Archive",
    b'\x7fELF': "ELF Executable (Linux)",
    b'MZ': "PE Executable (Windows EXE)",
    b'%PDF-': "PDF Document",
    b'ID3': "MP3 Audio File",
}

_SAFE_PRINTABLE = set(string.printable) - set('\t\n\r\x0b\x0c')

def printable(s):
    return all(c in _SAFE_PRINTABLE for c in s) and len(s) > 0

def shannon_entropy(data):
    if not data: return 0
    if isinstance(data, str): data = data.encode('utf-8', errors='ignore')
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def check_magic_bytes(byte_data):
    for sig, file_type in MAGIC_BYTES.items():
        if byte_data.startswith(sig):
            return file_type
    return None

def find_insights(s):
    insights = []
    if not isinstance(s, str):
        return insights

    flags = re.findall(r'\b[a-zA-Z0-9_\-]{2,15}\{.*?\}', s)
    for f in flags: insights.append(f"Flag Detected: {f}")

    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s)
    if ips: insights.append(f"IPv4 Found: {', '.join(ips[:3])}{'...' if len(ips)>3 else ''}")

    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', s)
    if emails: insights.append(f"Email Found: {', '.join(emails[:3])}")

    urls = re.findall(r'https?://[^\s]+', s)
    if urls: insights.append(f"URL Found: {', '.join(urls[:2])}")

    return insights

def has_words(s):
    """Kept for compatibility but no longer used as a filter gate."""
    if find_insights(s):
        return True
    words = re.findall(r'[a-zA-Z]{3,}', s.lower())
    if not words: return False
    hits = sum(1 for w in words if w in _COMMON_WORDS)
    return hits >= 1

def looks_like_encoding(text):
    clean = text.strip().upper().replace(' ', '')
    if re.match(r'^[AB]+$', clean): return True
    if re.match(r'^[01]+$', clean): return True
    if re.match(r'^[A-Za-z0-9+/]+=*$', text.strip()) and len(text) % 4 == 0 and len(text) >= 8: return True
    if re.match(r'^[0-9a-fA-F]+$', text.strip()) and len(text.strip()) % 2 == 0: return True
    return False

def is_hex_input(text):
    clean = text.strip().replace(' ', '').replace('0x', '').replace(',', '')
    return bool(re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0 and len(clean) >= 4)

def add_result(results, enc_name, raw_data, desc):
    """
    Adds a result unconditionally if printable or a known binary file.
    Confidence is computed later at display time.
    """
    if isinstance(raw_data, bytes):
        file_type = check_magic_bytes(raw_data)
        if file_type:
            results.append((enc_name, f"<Binary File: {file_type}>", desc, raw_data, CONF_HIGH))
            return
        decoded = raw_data.decode('utf-8', errors='replace')
    else:
        decoded = raw_data
        raw_data = decoded.encode('utf-8', errors='replace')

    printable_ratio = sum(1 for c in decoded if c in _SAFE_PRINTABLE) / max(len(decoded), 1)

    # Accept anything with > 70% printable chars (was previously hard-filtered by has_words)
    if printable_ratio > 0.70 and len(decoded) > 0:
        conf = confidence_score(decoded, raw_data, enc_name)
        results.append((enc_name, decoded, desc, raw_data, conf))

def banner():
    sep = ICON_LINE * 80
    print(f"{C.GREEN}{C.BOLD}{ICON_ARROW} FORD DECODER v3.8{C.RESET} {ICON_LINE * 3} {C.DIM}Triage & Multi-Layer Cryptanalysis CLI{C.RESET}")
    print(f"{C.DIM}{sep}{C.RESET}")

# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def try_base64(text):
    results = []
    clean = text.strip().replace('\n', '').replace(' ', '')

    try:
        if re.match(r'^[A-Za-z0-9+/]+=*$', clean) and len(clean) % 4 == 0 and len(clean) >= 4:
            raw = base64.b64decode(clean)
            add_result(results, "BASE64", raw, "Standard Base64 encoding")
    except Exception:
        pass

    try:
        url_safe = clean.replace('-', '+').replace('_', '/')
        while len(url_safe) % 4: url_safe += '='
        raw = base64.b64decode(url_safe)
        if '-' in clean or '_' in clean:
            add_result(results, "BASE64-URL", raw, "URL-safe Base64 encoding")
    except Exception:
        pass

    try:
        if re.match(r'^[A-Z2-7]+=*$', clean.upper()) and len(clean) >= 8:
            raw = base64.b32decode(clean.upper())
            add_result(results, "BASE32", raw, "Standard Base32 encoding")
    except Exception:
        pass

    try:
        raw = base64.b85decode(clean)
        add_result(results, "BASE85", raw, "Ascii85 / Base85 encoding")
    except Exception:
        pass

    try:
        import base58
        raw = base58.b58decode(clean)
        add_result(results, "BASE58", raw, "Base58 encoding (Bitcoin style)")
    except Exception:
        pass

    # Base16 (uppercase hex alias)
    try:
        if re.match(r'^[0-9A-F]+$', clean) and len(clean) % 2 == 0 and len(clean) >= 4:
            raw = bytes.fromhex(clean)
            add_result(results, "BASE16", raw, "Base16 / uppercase hex encoding")
    except Exception:
        pass

    # Base62 (alphanumeric only, no padding)
    _B62_CHARS = string.digits + string.ascii_uppercase + string.ascii_lowercase
    try:
        if re.match(r'^[0-9A-Za-z]+$', clean) and len(clean) >= 4:
            n = 0
            for ch in clean:
                n = n * 62 + _B62_CHARS.index(ch)
            raw = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n > 0 else b'\x00'
            add_result(results, "BASE62", raw, "Base62 alphanumeric encoding")
    except Exception:
        pass

    return results


def try_hex(text):
    results = []
    spaced = re.findall(r'[0-9a-fA-F]{2}', text.strip())
    if len(spaced) > 1:
        try:
            raw = bytes(int(h, 16) for h in spaced)
            add_result(results, "HEX (SPACED)", raw, "Space-separated hexadecimal values")
        except Exception:
            pass

    clean_0x = re.sub(r'0x', '', text.strip(), flags=re.IGNORECASE).replace(',', '').replace(' ', '')
    if re.match(r'^[0-9a-fA-F]+$', clean_0x) and len(clean_0x) % 2 == 0:
        try:
            raw = bytes.fromhex(clean_0x)
            add_result(results, "HEX (CONTINUOUS)", raw, "Continuous hexadecimal string")
        except Exception:
            pass

    return results


def try_rot(text, show_all=False):
    results = []
    input_is_hex = is_hex_input(text)

    if input_is_hex and not show_all:
        return results

    try:
        decoded = codecs.decode(text, 'rot_13')
        # ROT13 on non-alphabetic input (morse, hex, etc.) is meaningless — skip
        if decoded != text and re.search(r'[a-zA-Z]', text):
            add_result(results, "ROT13", decoded, "Substitution cipher shifted by 13")
    except Exception:
        pass

    try:
        decoded = ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)
        # ROT47 on morse/binary is noise — require some alpha chars in input
        if decoded != text and re.search(r'[a-zA-Z0-9]', text) and len(text) >= 4:
            add_result(results, "ROT47", decoded, "Rotates all printable ASCII characters")
    except Exception:
        pass

    for n in range(1, 26):
        if n == 13: continue
        try:
            decoded = text.translate(str.maketrans(
                string.ascii_uppercase + string.ascii_lowercase,
                string.ascii_uppercase[n:] + string.ascii_uppercase[:n] +
                string.ascii_lowercase[n:] + string.ascii_lowercase[:n]
            ))
            # Only emit Caesar results that contain actual words — otherwise every
            # printable input produces 24 noise entries
            if decoded != text and has_words(decoded):
                add_result(results, f"CAESAR (ROT{n})", decoded, f"Caesar rotation cipher shift {n}")
        except Exception:
            pass

    return results


def try_binary(text):
    results = []
    parts = text.strip().split()
    if parts and all(re.match(r'^[01]{8}$', p) for p in parts):
        try:
            raw = bytes(int(p, 2) for p in parts)
            add_result(results, "BINARY (SPACED)", raw, "8-bit space-separated binary chunks")
        except Exception:
            pass

    clean = text.strip().replace(' ', '')
    if re.match(r'^[01]+$', clean) and len(clean) % 8 == 0 and len(clean) >= 8:
        try:
            raw = bytes(int(clean[i:i+8], 2) for i in range(0, len(clean), 8))
            add_result(results, "BINARY (CONTINUOUS)", raw, "Continuous binary bitstream")
        except Exception:
            pass

    return results


def try_url(text):
    results = []
    try:
        decoded = urllib.parse.unquote(text)
        if decoded != text: add_result(results, "URL DECODE", decoded, "URL Percent-encoding")
    except Exception:
        pass

    try:
        import html
        decoded = html.unescape(text)
        if decoded != text: add_result(results, "HTML ENTITIES", decoded, "HTML entity parsing")
    except Exception:
        pass
    return results


def try_xor(text, key):
    results = []
    clean = text.strip().replace(' ', '')

    if key is not None:
        try:
            data = bytes.fromhex(clean)
            raw = bytes([b ^ key for b in data])
            add_result(results, f"XOR (0x{key:02x})", raw, f"Static single-byte XOR using key 0x{key:02x}")
        except Exception:
            pass

    if key is None and re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0:
        try:
            data = bytes.fromhex(clean)
            for k in range(1, 256):
                raw = bytes([b ^ k for b in data])
                decoded = raw.decode('utf-8', errors='replace')
                if printable(decoded) and has_words(decoded):
                    add_result(results, f"XOR BRUTEFORCE (0x{k:02x})", raw, "Bruteforced single-byte XOR")
        except Exception:
            pass

    return results


def try_hash_identify(text):
    results = []
    clean = text.strip()
    if not re.match(r'^[0-9a-fA-F]+$', clean): return results
    length = len(clean)
    hash_map = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
    if length in hash_map:
        add_result(results, f"HASH IDENTIFIED: {hash_map[length]}", clean, f"String length matches {hash_map[length]} structural hash")
    return results


# ---------------------------------------------------------------------------
# NEW DECODERS
# ---------------------------------------------------------------------------

# Morse code
_MORSE_TO_CHAR = {
    '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E', '..-.':'F',
    '--.':'G', '....':'H', '..':'I', '.---':'J', '-.-':'K', '.-..':'L',
    '--':'M', '-.':'N', '---':'O', '.--.':'P', '--.-':'Q', '.-.':'R',
    '...':'S', '-':'T', '..-':'U', '...-':'V', '.--':'W', '-..-':'X',
    '-.--':'Y', '--..':'Z',
    '-----':'0', '.----':'1', '..---':'2', '...--':'3', '....-':'4',
    '.....':'5', '-....':'6', '--...':'7', '---..':'8', '----.':'9',
    '.-.-.-':'.', '--..--':',', '..--..':'?', '.----.': "'",
    '-.-.--':'!', '-..-.':'/', '-.--.':'(', '-.--.-':')',
    '.-...':'&', '---...':':', '-.-.-.':';', '-...-':'=',
    '.-.-.':'+', '-....-':'-', '..--.-':'_', '.-..-.':'"',
    '...-..-':'$', '.--.-.':'@', '...---...':'SOS',
}

def try_morse(text):
    results = []
    clean = text.strip()
    # Accept dots, dashes, spaces, slashes (word separator)
    if not re.match(r'^[.\- /]+$', clean):
        return results
    # Word separator: '/' or '  ' (double space)
    words = re.split(r'\s*/\s*|\s{2,}', clean)
    decoded_words = []
    for word in words:
        chars = word.strip().split()
        decoded_chars = []
        for ch in chars:
            if ch in _MORSE_TO_CHAR:
                decoded_chars.append(_MORSE_TO_CHAR[ch])
            else:
                decoded_chars.append('?')
        decoded_words.append(''.join(decoded_chars))
    result = ' '.join(decoded_words)
    if '?' not in result or len(result) > 3:
        add_result(results, "MORSE CODE", result, "International Morse code")
    return results


# Atbash cipher (reverse alphabet)
def try_atbash(text):
    results = []
    if not re.search(r'[a-zA-Z]', text):
        return results
    table = str.maketrans(
        string.ascii_uppercase + string.ascii_lowercase,
        string.ascii_uppercase[::-1] + string.ascii_lowercase[::-1]
    )
    decoded = text.translate(table)
    if decoded != text:
        add_result(results, "ATBASH", decoded, "Atbash reverse-alphabet substitution cipher")
    return results


# Decimal / Octal byte strings  e.g. "72 101 108 108 111" or "110 145 154 154 157"
def try_decimal_octal(text):
    results = []
    parts = text.strip().split()

    # Decimal bytes
    if len(parts) >= 2 and all(re.match(r'^\d+$', p) for p in parts):
        try:
            vals = [int(p) for p in parts]
            if all(0 <= v <= 255 for v in vals):
                raw = bytes(vals)
                add_result(results, "DECIMAL BYTES", raw, "Space-separated decimal byte values")
        except Exception:
            pass

    # Octal bytes e.g. "110 145 154"
    if len(parts) >= 2 and all(re.match(r'^[0-7]+$', p) for p in parts):
        try:
            vals = [int(p, 8) for p in parts]
            if all(0 <= v <= 255 for v in vals):
                raw = bytes(vals)
                add_result(results, "OCTAL BYTES", raw, "Space-separated octal byte values")
        except Exception:
            pass

    return results


# UUencode
def try_uuencode(text):
    results = []
    lines = text.strip().splitlines()
    # UUencoded data starts with 'begin NNN filename'
    if lines and lines[0].lower().startswith('begin'):
        try:
            import uu, io
            in_buf = io.BytesIO(text.encode())
            out_buf = io.BytesIO()
            uu.decode(in_buf, out_buf, quiet=True)
            raw = out_buf.getvalue()
            add_result(results, "UUENCODE", raw, "UUencoded binary-to-text format")
        except Exception:
            pass
    # Also try raw uuencode lines (without begin/end header)
    elif lines and all(re.match(r'^[!-~\s]+$', l) for l in lines if l.strip()):
        try:
            raw = b''
            for line in lines:
                line = line.rstrip()
                if not line: continue
                length = (ord(line[0]) - 32) & 0x3f
                if length == 0: break
                data = line[1:]
                while len(data) % 4: data += '`'
                chunk = b''
                for i in range(0, len(data), 4):
                    a,b,c,d = [(ord(x)-32)&0x3f for x in data[i:i+4]]
                    chunk += bytes([(a<<2)|(b>>4), ((b&0xf)<<4)|(c>>2), ((c&3)<<6)|d])
                raw += chunk[:length]
            if raw:
                add_result(results, "UUENCODE (RAW)", raw, "Raw UU-encoded data (no header)")
        except Exception:
            pass
    return results


# JWT parser — decodes header + payload, doesn't verify signature
def try_jwt(text):
    results = []
    clean = text.strip()
    parts = clean.split('.')
    if len(parts) != 3:
        return results
    if not all(re.match(r'^[A-Za-z0-9_\-]+$', p) for p in parts):
        return results

    import json as _json
    decoded_parts = []
    for i, part in enumerate(parts[:2]):  # header + payload only
        padded = part + '=' * (4 - len(part) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
            parsed = _json.loads(raw.decode('utf-8', errors='replace'))
            decoded_parts.append(f"{'Header' if i==0 else 'Payload'}: {_json.dumps(parsed, indent=2)}")
        except Exception:
            return results  # not valid JSON = not a JWT

    if decoded_parts:
        full = '\n'.join(decoded_parts) + f"\nSignature: {parts[2]} (not verified)"
        add_result(results, "JWT (BASE64URL)", full, "JSON Web Token — header and payload decoded")
    return results


# ---------------------------------------------------------------------------
# Multi-layer decoder
# ---------------------------------------------------------------------------

def try_multi_decode(text, depth=3, show_all=False):
    results = []
    def attempt(t, layer, history):
        if layer > depth: return
        all_attempts = []
        all_attempts.extend(try_base64(t))
        all_attempts.extend(try_hex(t))
        all_attempts.extend(try_rot(t, show_all=show_all))
        all_attempts.extend(try_url(t))
        all_attempts.extend(try_morse(t))
        all_attempts.extend(try_atbash(t))

        for enc_name, decoded, desc, raw_data, conf in all_attempts:
            chain = history + [enc_name]
            if len(chain) > 1 and printable(decoded):
                results.append((" → ".join(chain), decoded, f"Multi-layer pipeline ({layer} layers)", raw_data, conf))
            if decoded != t and layer < depth and not decoded.startswith("<Binary"):
                attempt(decoded, layer + 1, chain)

    attempt(text, 1, [])
    return results


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_result(enc_name, decoded, desc, raw_data, conf, idx):
    colors = [C.GREEN, C.CYAN, C.YELLOW, C.MAGENTA, C.BLUE]
    color = colors[idx % len(colors)]

    entropy = shannon_entropy(raw_data)
    insights = find_insights(decoded) if decoded and not decoded.startswith("<Binary") else []

    conf_color = CONF_COLOR.get(conf, C.DIM)
    conf_badge = f"{conf_color}[{conf}]{C.RESET}"

    sep = ICON_LINE * 70
    print(f"{C.DIM}{sep}{C.RESET}")
    print(f"{color}{C.BOLD}{ICON_ARROW} [{enc_name}]{C.RESET}  {C.DIM}{desc}{C.RESET}  {conf_badge}")
    print(f"  {C.BOLD}Entropy:{C.RESET}  {entropy:.2f} {C.DIM}(>6.5 suggests heavy encryption or random bytes){C.RESET}")

    if insights:
        for ins in insights:
            print(f"  {C.RED}{C.BOLD}{ICON_STAR} {ins}{C.RESET}")

    print(f"  {C.BOLD}Result:{C.RESET}   {decoded}")

def print_no_result():
    print(f"  {C.RED}[-] No obvious encoding signature found{C.RESET}")
    print(f"  {C.DIM}    Try passing options: ford \"[text]\" --depth 3{C.RESET}")
    print(f"  {C.DIM}    Try bruteforcing   : ford \"[hex]\" --xor 0x42{C.RESET}")
    print()

def valid_depth(value):
    ivalue = int(value)
    if ivalue < 1 or ivalue > 5:
        raise argparse.ArgumentTypeError(f"depth must be between 1 and 5, got {ivalue}")
    return ivalue


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog='ford',
        description='FORD (Forensic Decoder) — Rapid triage, decoding, and IOC extraction tool.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('text', nargs='?', help='Encoded text string wrapped in quotes')
    parser.add_argument('--xor',   type=lambda x: int(x, 0), default=None, help='XOR key to apply (e.g., 0x42)')
    parser.add_argument('--depth', type=valid_depth, default=1, help='Recursive multi-layer depth limit (1-5, default: 1)')
    parser.add_argument('--version', '-v', action='version', version='FORD Framework v3.8')
    parser.add_argument('--no-banner', action='store_true', help='Suppress the horizontal header line')
    parser.add_argument('--all',   action='store_true', dest='show_all', help='Force display of LOW-confidence results too')
    parser.add_argument('--output', '-o', metavar='FILE', default=None, help='Save decoded results to a file (strips ANSI colors)')

    args = parser.parse_args()

    if args.text is None:
        if not sys.stdin.isatty():
            args.text = sys.stdin.read().strip()
        else:
            parser.print_help()
            sys.exit(1)

    if not args.no_banner:
        banner()

    text = args.text
    input_entropy = shannon_entropy(text)

    print(f"{C.DIM}  Input Payload : {text[:75]}{'...' if len(text) > 75 else ''}{C.RESET}")
    print(f"{C.DIM}  Payload Metrics: {len(text)} chars | Shannon Entropy: {input_entropy:.2f}{C.RESET}")
    print(f"{C.DIM}{ICON_LINE * 80}{C.RESET}\n")

    all_results = []
    all_results.extend(try_base64(text))
    all_results.extend(try_hex(text))
    all_results.extend(try_binary(text))
    all_results.extend(try_url(text))
    all_results.extend(try_rot(text, show_all=args.show_all))
    all_results.extend(try_xor(text, args.xor))
    all_results.extend(try_hash_identify(text))
    all_results.extend(try_morse(text))
    all_results.extend(try_atbash(text))
    all_results.extend(try_decimal_octal(text))
    all_results.extend(try_uuencode(text))
    all_results.extend(try_jwt(text))

    if args.depth > 1:
        all_results.extend(try_multi_decode(text, args.depth, show_all=args.show_all))

    # Dedup by decoded value
    seen = set()
    unique = []
    for r in all_results:
        if r[1] not in seen:
            seen.add(r[1])
            unique.append(r)

    # Filter LOW confidence unless --all
    if not args.show_all:
        visible = [r for r in unique if r[4] != CONF_LOW]
        hidden_count = len(unique) - len(visible)
    else:
        visible = unique
        hidden_count = 0

    if not visible:
        print_no_result()
        if hidden_count:
            print(f"  {C.DIM}  ({hidden_count} low-confidence result(s) hidden — use --all to show){C.RESET}")
    else:
        high = sum(1 for r in visible if r[4] == CONF_HIGH)
        med  = sum(1 for r in visible if r[4] == CONF_MED)
        print(f"  {C.GREEN}{C.BOLD}ANALYSIS COMPLETE: {len(visible)} result(s) found  "
              f"[{C.GREEN}{high} HIGH{C.RESET}{C.BOLD}  {C.YELLOW}{med} MED{C.RESET}{C.BOLD}]{C.RESET}")
        if hidden_count:
            print(f"  {C.DIM}  ({hidden_count} low-confidence result(s) hidden — use --all to show){C.RESET}")
        for i, (enc, decoded, desc, raw_data, conf) in enumerate(visible):
            print_result(enc, decoded, desc, raw_data, conf, i)

    print(f"\n{C.DIM}{ICON_LINE * 80}{C.RESET}")
    print(f"{C.DIM}  FORD Framework v3.8 | Streamlined Cryptanalysis & Threat Intel Triage{C.RESET}\n")

    if args.output:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        lines = []
        lines.append(f"FORD DECODER v3.8 — Analysis Report")
        lines.append("=" * 60)
        lines.append(f"Input  : {text}")
        lines.append(f"Entropy: {input_entropy:.2f}")
        lines.append("")
        if not visible:
            lines.append("[-] No obvious encoding signature found.")
        else:
            lines.append(f"[+] {len(visible)} result(s) found\n")
            for enc, decoded, desc, raw_data, conf in visible:
                entropy = shannon_entropy(raw_data)
                insights = find_insights(decoded) if not decoded.startswith("<Binary") else []
                lines.append(f"  Encoding   : {enc}")
                lines.append(f"  Confidence : {conf}")
                lines.append(f"  Desc       : {desc}")
                lines.append(f"  Entropy    : {entropy:.2f}")
                for ins in insights:
                    lines.append(f"  [!] {ins}")
                lines.append(f"  Result     : {decoded}")
                lines.append("")
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            print(f"{C.GREEN}[+] Output saved to: {args.output}{C.RESET}")
        except OSError as e:
            print(f"{C.RED}[-] Failed to write output file: {e}{C.RESET}", file=sys.stderr)

if __name__ == '__main__':
    main()
