import unittest
import time

from aegis_soar.security import SignatureError, sign_request, verify_request


class SignatureTests(unittest.TestCase):
    def test_valid_signature_is_accepted(self):
        body = b'{"id":"event-1"}'
        secret = b"test-only-secret"
        timestamp = str(int(time.time()))
        signature = sign_request(body, timestamp, secret)
        verify_request(body, timestamp, signature, secret)

    def test_tampered_body_is_rejected(self):
        secret = b"test-only-secret"
        timestamp = str(int(time.time()))
        signature = sign_request(b'{"id":"event-1"}', timestamp, secret)
        with self.assertRaises(SignatureError):
            verify_request(b'{"id":"event-2"}', timestamp, signature, secret)

    def test_stale_timestamp_is_rejected(self):
        secret = b"test-only-secret"
        timestamp = "100"
        signature = sign_request(b"{}", timestamp, secret)
        with self.assertRaises(SignatureError):
            verify_request(b"{}", timestamp, signature, secret, now=1000)


if __name__ == "__main__":
    unittest.main()
