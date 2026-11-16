import unittest
import time

from aegis_soar.security import SignatureError, sign_request, verify_request


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"test-only-secret-material-at-least-32-bytes"

    def test_valid_signature_is_accepted(self):
        body = b'{"id":"event-1"}'
        timestamp = str(int(time.time()))
        signature = sign_request(body, timestamp, self.secret)
        verify_request(body, timestamp, signature, self.secret)

    def test_tampered_body_is_rejected(self):
        timestamp = str(int(time.time()))
        signature = sign_request(b'{"id":"event-1"}', timestamp, self.secret)
        with self.assertRaises(SignatureError):
            verify_request(b'{"id":"event-2"}', timestamp, signature, self.secret)

    def test_stale_timestamp_is_rejected(self):
        timestamp = "100"
        signature = sign_request(b"{}", timestamp, self.secret)
        with self.assertRaises(SignatureError):
            verify_request(b"{}", timestamp, signature, self.secret, now=1000)

    def test_missing_headers_are_rejected(self):
        with self.assertRaises(SignatureError):
            verify_request(b"{}", None, None, self.secret)

    def test_non_hex_signature_is_rejected(self):
        with self.assertRaises(SignatureError):
            verify_request(b"{}", str(int(time.time())), "not-a-signature", self.secret)

    def test_non_ascii_timestamp_is_rejected(self):
        with self.assertRaises(SignatureError):
            verify_request(b"{}", "١٢٣", "0" * 64, self.secret)


if __name__ == "__main__":
    unittest.main()
