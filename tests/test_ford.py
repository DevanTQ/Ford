"""
Unit tests for FORD Decoder v3.8
Run: python -m pytest tests/ -v
"""

import sys
import os
import base64
import binascii

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ford


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decoded_values(results):
    """Return the decoded strings from a results list."""
    return [r[1] for r in results]

def encoder_names(results):
    """Return the encoder name strings from a results list."""
    return [r[0] for r in results]

def confidences(results):
    """Return the confidence strings from a results list."""
    return [r[4] for r in results]


# ---------------------------------------------------------------------------
# Core utilities
# ---------------------------------------------------------------------------

class TestPrintable:
    def test_plain_ascii(self):
        assert ford.printable("hello world") is True

    def test_control_chars_rejected(self):
        assert ford.printable("hello\x00world") is False
        assert ford.printable("tab\there") is False
        assert ford.printable("new\nline") is False

    def test_empty_string(self):
        assert ford.printable("") is False


class TestShannonEntropy:
    def test_uniform_string_low(self):
        assert ford.shannon_entropy("aaaaaaa") < 0.1

    def test_random_bytes_high(self):
        data = bytes(range(256))
        assert ford.shannon_entropy(data) > 5.0

    def test_empty_returns_zero(self):
        assert ford.shannon_entropy("") == 0
        assert ford.shannon_entropy(b"") == 0


class TestHasWords:
    def test_detects_common_word(self):
        assert ford.has_words("hello world") is True

    def test_detects_flag_pattern(self):
        assert ford.has_words("CTF{s0me_fl4g_here}") is True

    def test_random_garbage(self):
        assert ford.has_words("qzxjwvk") is False


class TestFindInsights:
    def test_flag_detection(self):
        insights = ford.find_insights("CTF{this_is_a_flag}")
        assert any("Flag" in i for i in insights)

    def test_ip_detection(self):
        insights = ford.find_insights("Server at 192.168.1.1 responded")
        assert any("IPv4" in i for i in insights)

    def test_email_detection(self):
        insights = ford.find_insights("contact: admin@example.com")
        assert any("Email" in i for i in insights)

    def test_url_detection(self):
        insights = ford.find_insights("visit https://example.com/path")
        assert any("URL" in i for i in insights)

    def test_no_insights_empty(self):
        assert ford.find_insights("") == []


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

class TestConfidenceScore:
    def test_flag_pattern_is_high(self):
        raw = b"CTF{test_flag}"
        assert ford.confidence_score("CTF{test_flag}", raw, "BASE64") == ford.CONF_HIGH

    def test_common_words_high(self):
        raw = b"hello world test"
        assert ford.confidence_score("hello world test", raw, "HEX") == ford.CONF_HIGH

    def test_hash_always_high(self):
        raw = b"d41d8cd98f00b204e9800998ecf8427e"
        assert ford.confidence_score("d41d8cd98f00b204e9800998ecf8427e", raw, "HASH IDENTIFIED: MD5") == ford.CONF_HIGH

    def test_low_entropy_printable_high(self):
        s = "aaabbbccc"
        assert ford.confidence_score(s, s.encode(), "ROT13") == ford.CONF_HIGH

    def test_medium_entropy_printable_med(self):
        # High enough entropy to not be HIGH, all printable
        s = "xK9mP2qR"
        conf = ford.confidence_score(s, s.encode(), "CAESAR")
        assert conf in (ford.CONF_HIGH, ford.CONF_MED)

    def test_ip_in_decoded_is_high(self):
        s = "host 10.0.0.1 ok"
        assert ford.confidence_score(s, s.encode(), "BASE64") == ford.CONF_HIGH


# ---------------------------------------------------------------------------
# Base decoders
# ---------------------------------------------------------------------------

class TestTryBase64:
    def test_standard_base64(self):
        encoded = base64.b64encode(b"hello world").decode()
        results = ford.try_base64(encoded)
        assert any("BASE64" in n for n in encoder_names(results))
        assert any("hello world" in v for v in decoded_values(results))

    def test_base32(self):
        encoded = base64.b32encode(b"test").decode()
        results = ford.try_base64(encoded)
        assert any("BASE32" in n for n in encoder_names(results))

    def test_base16(self):
        encoded = b"hello".hex().upper()
        results = ford.try_base64(encoded)
        assert any("BASE16" in n for n in encoder_names(results))
        assert any("hello" in v for v in decoded_values(results))

    def test_invalid_input_no_crash(self):
        results = ford.try_base64("not_b64!!@@##")
        assert isinstance(results, list)


class TestTryHex:
    def test_continuous_hex(self):
        results = ford.try_hex("68656c6c6f")
        assert any("hello" in v for v in decoded_values(results))

    def test_spaced_hex(self):
        results = ford.try_hex("68 65 6c 6c 6f")
        assert any("hello" in v for v in decoded_values(results))

    def test_invalid_hex_no_crash(self):
        results = ford.try_hex("zzzz")
        assert isinstance(results, list)


class TestTryBinary:
    def test_spaced_binary(self):
        encoded = "01101000 01100101 01101100 01101100 01101111"
        results = ford.try_binary(encoded)
        assert any("hello" in v for v in decoded_values(results))

    def test_continuous_binary(self):
        encoded = "0110100001100101011011000110110001101111"
        results = ford.try_binary(encoded)
        assert any("hello" in v for v in decoded_values(results))

    def test_invalid_binary_no_crash(self):
        results = ford.try_binary("12345")
        assert isinstance(results, list)


class TestTryRot:
    def test_rot13(self):
        results = ford.try_rot("uryyb jbeyq", show_all=True)
        assert any("ROT13" in n for n in encoder_names(results))
        assert any("hello world" in v for v in decoded_values(results))

    def test_caesar(self):
        results = ford.try_rot("khoor", show_all=True)
        assert any("hello" in v for v in decoded_values(results))

    def test_hex_input_skipped_by_default(self):
        results = ford.try_rot("48656c6c6f", show_all=False)
        assert all("ROT" not in n and "CAESAR" not in n for n in encoder_names(results))

    def test_rot47(self):
        # ROT47 of "Hello World!" is "w6==@ (@C=5P"
        encoded = ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in "Hello World!")
        results = ford.try_rot(encoded, show_all=True)
        assert any("ROT47" in n for n in encoder_names(results))


class TestTryUrl:
    def test_url_percent_decode(self):
        results = ford.try_url("hello%20world%21")
        assert any("hello world!" in v for v in decoded_values(results))

    def test_html_entities(self):
        results = ford.try_url("hello &amp; world")
        assert any("hello & world" in v for v in decoded_values(results))

    def test_no_encoding_no_result(self):
        results = ford.try_url("plaintext")
        assert results == []


class TestTryXor:
    def test_xor_with_known_key(self):
        data = binascii.hexlify(bytes([b ^ 0x20 for b in b"hi"])).decode()
        results = ford.try_xor(data, key=0x20)
        assert any("hi" in v.lower() for v in decoded_values(results))

    def test_xor_bruteforce_no_key(self):
        payload = bytes([b ^ 0x01 for b in b"hello world test"])
        results = ford.try_xor(payload.hex(), key=None)
        assert any("hello" in v.lower() for v in decoded_values(results))


class TestHashIdentify:
    def test_md5_length(self):
        results = ford.try_hash_identify("d41d8cd98f00b204e9800998ecf8427e")
        assert any("MD5" in n for n in encoder_names(results))

    def test_sha256_length(self):
        results = ford.try_hash_identify(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert any("SHA-256" in n for n in encoder_names(results))

    def test_non_hex_no_result(self):
        results = ford.try_hash_identify("notahash!!")
        assert results == []

    def test_hash_confidence_is_high(self):
        results = ford.try_hash_identify("d41d8cd98f00b204e9800998ecf8427e")
        assert any(c == ford.CONF_HIGH for c in confidences(results))


# ---------------------------------------------------------------------------
# New decoders (v3.8)
# ---------------------------------------------------------------------------

class TestTryMorse:
    def test_basic_hello_world(self):
        morse = ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
        results = ford.try_morse(morse)
        assert any("MORSE" in n for n in encoder_names(results))
        assert any("HELLO WORLD" in v for v in decoded_values(results))

    def test_sos(self):
        results = ford.try_morse("... --- ...")
        assert len(results) > 0

    def test_non_morse_input_no_crash(self):
        results = ford.try_morse("hello world")
        assert isinstance(results, list)
        assert results == []

    def test_slash_word_separator(self):
        # 'HI' in morse with slash separator
        results = ford.try_morse(".... ..")
        assert any("HI" in v for v in decoded_values(results))

    def test_morse_confidence_high(self):
        morse = ".... . .-.. .-.. ---"
        results = ford.try_morse(morse)
        assert any(c == ford.CONF_HIGH for c in confidences(results))


class TestTryAtbash:
    def test_hello_world(self):
        # atbash of "hello world" = "svool dliow"
        results = ford.try_atbash("svool dliow")
        assert any("ATBASH" in n for n in encoder_names(results))
        assert any("hello world" in v for v in decoded_values(results))

    def test_uppercase(self):
        results = ford.try_atbash("SVOOL DLIOW")
        assert any("hello world" in v.lower() for v in decoded_values(results))

    def test_non_alpha_input_no_result(self):
        results = ford.try_atbash("12345")
        assert results == []

    def test_idempotent(self):
        # atbash is its own inverse: atbash(atbash(x)) == x
        original = "hello"
        r1 = ford.try_atbash(original)
        if r1:
            r2 = ford.try_atbash(r1[0][1])
            assert any(original in v for v in decoded_values(r2))


class TestTryDecimalOctal:
    def test_decimal_bytes_hello(self):
        # "hello" as decimal bytes
        results = ford.try_decimal_octal("104 101 108 108 111")
        assert any("DECIMAL" in n for n in encoder_names(results))
        assert any("hello" in v for v in decoded_values(results))

    def test_octal_bytes_hello(self):
        # "hello" as octal: 150 145 154 154 157
        results = ford.try_decimal_octal("150 145 154 154 157")
        assert any("OCTAL" in n for n in encoder_names(results))
        assert any("hello" in v for v in decoded_values(results))

    def test_single_value_no_result(self):
        # Single token is ambiguous — should not emit a result
        results = ford.try_decimal_octal("65")
        assert results == []

    def test_out_of_range_no_crash(self):
        results = ford.try_decimal_octal("999 888 777")
        assert isinstance(results, list)


class TestTryJwt:
    _SAMPLE_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_detects_jwt(self):
        results = ford.try_jwt(self._SAMPLE_JWT)
        assert any("JWT" in n for n in encoder_names(results))

    def test_header_decoded(self):
        results = ford.try_jwt(self._SAMPLE_JWT)
        assert any("alg" in v for v in decoded_values(results))

    def test_payload_decoded(self):
        results = ford.try_jwt(self._SAMPLE_JWT)
        assert any("sub" in v for v in decoded_values(results))

    def test_signature_not_verified_label(self):
        results = ford.try_jwt(self._SAMPLE_JWT)
        assert any("not verified" in v for v in decoded_values(results))

    def test_non_jwt_string_no_result(self):
        results = ford.try_jwt("this.is.notajwt!!")
        assert results == []

    def test_two_part_string_no_result(self):
        results = ford.try_jwt("aGVsbG8=.d29ybGQ=")
        assert results == []

    def test_jwt_confidence_high(self):
        results = ford.try_jwt(self._SAMPLE_JWT)
        assert any(c == ford.CONF_HIGH for c in confidences(results))


# ---------------------------------------------------------------------------
# Multi-layer decode
# ---------------------------------------------------------------------------

class TestMultiDecode:
    def test_double_base64(self):
        inner = base64.b64encode(b"hello").decode()
        outer = base64.b64encode(inner.encode()).decode()
        results = ford.try_multi_decode(outer, depth=3)
        assert any("hello" in v for v in decoded_values(results))

    def test_hex_then_base64(self):
        b64 = base64.b64encode(b"hello world").decode()
        hex_wrapped = b64.encode().hex()
        results = ford.try_multi_decode(hex_wrapped, depth=2)
        assert any("hello world" in v for v in decoded_values(results))

    def test_depth_1_no_chain(self):
        # depth=1 means no multi-layer — try_multi_decode at depth=1 returns empty
        inner = base64.b64encode(b"hi").decode()
        outer = base64.b64encode(inner.encode()).decode()
        results = ford.try_multi_decode(outer, depth=1)
        # depth=1 starts at layer=1, recurse only if layer < depth — so no chain
        assert all(len(r[0].split(" → ")) <= 2 for r in results)
