"""Synthetic device registration and API responses for offline tests."""

import base64
import io
import json
import time


ACCOUNT = '0123456789abcdef0123456789abcdef'
DEVICE = 't.12345678-1234-4234-8234-123456789abc'
TEAM = 'example-team'
HOST = TEAM + '.cloudflareaccess.com'
# Alice's example from RFC 7748 §6.1. WireGuard stores the clamped private scalar.
KEY_SEED = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
PRIVATE = base64.b64encode(bytes.fromhex(
    '70076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a')).decode()
PUBLIC = base64.b64encode(bytes.fromhex(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')).decode()
DEVICE_TOKEN = 'test-device-credential'
POLICY = {'include': [{'address': '192.0.2.0/24'}, {'host': '*.corp.example'}],
          'tunnel_protocol': 'wireguard'}
LIVE = {'id': DEVICE, 'key': PUBLIC, 'policy': POLICY, 'config': {
    'interface': {'addresses': {'v4': '192.0.2.1', 'v6': '2001:db8::1'}},
    'peers': [{'public_key': PUBLIC, 'endpoint': {'v4': '198.51.100.1:0', 'ports': [2408]}}]}}


def callback(**overrides):
    claims = dict(account_id=ACCOUNT, iss='https://' + HOST, warp=True, exp=int(time.time()) + 90)
    payload = base64.urlsafe_b64encode(json.dumps({**claims, **overrides}).encode()).decode().rstrip('=')
    return f'com.cloudflare.warp://{HOST}/auth?token=e30.{payload}.signature'


def reply(document, status=200):
    response = io.BytesIO(json.dumps(document).encode())
    response.status = status
    return response
