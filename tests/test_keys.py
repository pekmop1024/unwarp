import base64
import shutil
import subprocess
import unittest
from unittest.mock import patch

from unwarp.keys import derive_public_key, generate_private_key

from tests.fixtures import KEY_SEED, PRIVATE, PUBLIC


class WireGuardKeysTest(unittest.TestCase):
    def test_x25519_public_keys_from_rfc_7748_section_6_1(self):
        bob_private = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        bob_public = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
        self.assertEqual(derive_public_key(base64.b64encode(KEY_SEED).decode()), PUBLIC)
        self.assertEqual(derive_public_key(PRIVATE + '\n'), PUBLIC)
        actual = derive_public_key(base64.b64encode(bob_private).decode())
        self.assertEqual(base64.b64decode(actual, validate=True), bob_public)

    def test_private_key_clamping_and_fresh_entropy(self):
        with patch('unwarp.keys.token_bytes', side_effect=[KEY_SEED, b'\xff' * 32]) as entropy:
            self.assertEqual(generate_private_key(), PRIVATE)
            raw = base64.b64decode(generate_private_key(), validate=True)
        self.assertEqual(raw, b'\xf8' + b'\xff' * 30 + b'\x7f')
        self.assertEqual(entropy.call_count, 2)
        entropy.assert_called_with(32)

    def test_rejects_invalid_private_keys_without_echoing_them(self):
        for private in ('not-a-key', ' ' + PRIVATE, base64.b64encode(bytes(31)).decode(),
                        base64.b64encode(bytes(33)).decode(), 'A' * 42 + 'B='):
            with self.assertRaises(ValueError) as error:
                derive_public_key(private)
            self.assertEqual(str(error.exception), 'invalid WireGuard private key')

    @unittest.skipUnless(shutil.which('wg'), 'wireguard-tools is optional for interoperability testing')
    def test_interoperability_with_wg(self):
        wg_key = subprocess.check_output(['wg', 'genkey'], text=True).strip()
        for private in (wg_key, generate_private_key()):
            expected = subprocess.check_output(['wg', 'pubkey'], input=private + '\n', text=True).strip()
            self.assertEqual(derive_public_key(private), expected)
