"""
Unit tests for FORD Decoder
Run: python -m pytest tests/ -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ford

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

class TestTryBase64:
    def test_standard_base64(self):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        results = ford.try_base64(encoded)
        assert any("BASE64" in r[0] for r in results)
        assert any("hello world" in r[1] for r in results)

    def test_base32(self):
        import base64
        encoded = base64.b32encode(b"test").decode()
        results = ford.try_base64(encoded)
        assert any("BASE32" in r[0] for r in results)

    def test_invalid_input_no_crash(self):
        results = ford.try_base64("not_b64!!@@##")
        assert isinstance(results, list)


class TestTryHex:
    def test_continuous_hex(self):
        encoded = "68656c6c6f"
        results = ford.try_hex(encoded)
        assert any("hello" in r[1] for r in results)

    def test_spaced_hex(self):
        encoded = "68 65 6c 6c 6f"
        results = ford.try_hex(encoded)
        assert any("hello" in r[1] for r in results)

    def test_invalid_hex_no_crash(self):
        results = ford.try_hex("zzzz")
        assert isinstance(results, list)


class TestTryBinary:
    def test_spaced_binary(self):
        encoded = "01101000 01100101 01101100 01101100 01101111"
        results = ford.try_binary(encoded)
        assert any("hello" in r[1] for r in results)

    def test_continuous_binary(self):
        encoded = "0110100001100101011011000110110001101111"
        results = ford.try_binary(encoded)
        assert any("hello" in r[1] for r in results)

    def test_invalid_binary_no_crash(self):
        results = ford.try_binary("12345")
        assert isinstance(results, list)


class TestTryRot:
    def test_rot13(self):
        encoded = "uryyb jbeyq"
        results = ford.try_rot(encoded, show_all=True)
        assert any("ROT13" in r[0] for r in results)
        assert any("hello world" in r[1] for r in results)

    def test_caesar(self):
        encoded = "khoor"
        results = ford.try_rot(encoded, show_all=True)
        assert any("hello" in r[1] for r in results)

    def test_hex_input_skipped_by_default(self):
        results = ford.try_rot("48656c6c6f", show_all=False)
        assert all("ROT" not in r[0] and "CAESAR" not in r[0] for r in results)


class TestTryUrl:
    def test_url_percent_decode(self):
        encoded = "hello%20world%21"
        results = ford.try_url(encoded)
        assert any("hello world!" in r[1] for r in results)

    def test_html_entities(self):
        encoded = "hello &amp; world"
        results = ford.try_url(encoded)
        assert any("hello & world" in r[1] for r in results)

    def test_no_encoding_no_result(self):
        results = ford.try_url("plaintext")
        assert results == []


class TestTryXor:
    def test_xor_with_known_key(self):
        import binascii
        data = binascii.hexlify(bytes([b ^ 0x20 for b in b"hi"])).decode()
        results = ford.try_xor(data, key=0x20)
        assert any("hi" in r[1].lower() for r in results)

    def test_xor_bruteforce_no_key(self):
        payload = bytes([b ^ 0x01 for b in b"hello world test"])
        hex_payload = payload.hex()
        results = ford.try_xor(hex_payload, key=None)
        assert any("hello" in r[1].lower() for r in results)


class TestHashIdentify:
    def test_md5_length(self):
        results = ford.try_hash_identify("d41d8cd98f00b204e9800998ecf8427e")
        assert any("MD5" in r[0] for r in results)

    def test_sha256_length(self):
        results = ford.try_hash_identify(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert any("SHA-256" in r[0] for r in results)

    def test_non_hex_no_result(self):
        results = ford.try_hash_identify("notahash!!")
        assert results == []


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

class TestMultiDecode:
    def test_double_base64(self):
        import base64
        inner = base64.b64encode(b"hello").decode()
        outer = base64.b64encode(inner.encode()).decode()
        results = ford.try_multi_decode(outer, depth=3)
        assert any("hello" in r[1] for r in results)
