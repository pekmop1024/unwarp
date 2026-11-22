"""Registration, device policy and WireGuard settings from the Cloudflare device API and WARP cache."""

import base64
import http.client
import ipaddress
import json
import re
import uuid
from contextlib import closing

from ..model import RoutePolicy, WireGuardTunnel


DEVICE_HOST = 'api.devices.cloudflare.com'
REGISTRATION_FILE = '/var/lib/cloudflare-warp/reg.json'
WARP_CONFIG_FILE = '/var/lib/cloudflare-warp/conf.json'


def split_registration_id(value):
    if not isinstance(value, str):
        raise ValueError('expected a registration UUID')
    if value.startswith('t.'):
        return 't.', uuid.UUID(value[2:])
    return '', uuid.UUID(value)


class EnrollmentRejected(ValueError):
    """The device API explicitly rejected the registration."""


def register_device(team, interface, public_key, assertion):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
               'User-Agent': 'unwarp', 'Cf-Access-Jwt-Assertion': assertion}
    body = json.dumps({'type': 'linux', 'name': interface, 'key': public_key})
    with closing(http.client.HTTPSConnection(DEVICE_HOST, timeout=20)) as conn:
        conn.request('POST', '/v0/reg', body=body, headers=headers)
        with conn.getresponse() as response:
            if 400 <= response.status < 500:
                raise EnrollmentRejected(f'Cloudflare rejected enrollment (HTTP {response.status}); '
                                         'check the sign-in session and device enrollment policy')
            if response.status != 200:
                raise ValueError(f'Cloudflare registration returned HTTP {response.status}')
            raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError('Cloudflare registration response is too large')
    doc = json.loads(raw)
    if isinstance(doc, dict) and (doc.get('success') is False or doc.get('errors')):
        raise EnrollmentRejected('Cloudflare rejected the device enrollment')
    try:
        device = doc['result']
        if (device['key'] != public_key
                or device['account']['organization'].lower() != team
                or not re.fullmatch(r'[!-~]+', device['token'])):
            raise ValueError
        split_registration_id(device['id'])
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError('invalid registration response or mismatched organization or WireGuard public key') from None
    return device['id'], device['token']


def fetch_device(registration):
    """Read and validate the live device snapshot."""
    if not isinstance(registration, dict):
        raise ValueError('expected an object in the WARP registration file')
    stored_id = registration.get('registration_id')
    if isinstance(stored_id, list) and stored_id:
        stored_id = stored_id[0]
    try:
        prefix, expected_uuid = split_registration_id(stored_id)
    except ValueError:
        raise ValueError('reg.json is missing a valid registration_id') from None
    device_id = f'{prefix}{expected_uuid}'
    token = registration.get('api_token')
    if not isinstance(token, str) or not re.fullmatch(r'[!-~]+', token):
        raise ValueError('reg.json is missing a valid api_token')

    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json',
               'Cache-Control': 'no-cache', 'User-Agent': 'unwarp'}
    account = registration.get('account_id')
    if account is not None:
        try:
            account_id = uuid.UUID(str(account)).hex
        except ValueError:
            raise ValueError('reg.json contains an invalid account_id') from None
        host = DEVICE_HOST
        path = f'/v1/accounts/{account_id}/reg/{device_id}'
    else:
        # GetSourceDevice in wgcf v2.3.1 for registrations without an account tag.
        host = 'api.cloudflareclient.com'
        path = f'/v0a5641/reg/{device_id}'
        headers['CF-Client-Version'] = 'a-6.38.9-5641'

    # HTTPSConnection verifies TLS and does not follow redirects with the token.
    with closing(http.client.HTTPSConnection(host, timeout=15)) as connection:
        connection.request('GET', path, headers=headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError(f'{host} returned HTTP {response.status} for this registration')
            limit = 8 * 1024 * 1024
            body = response.read(limit + 1)
            if len(body) > limit:
                raise ValueError('WARP device response exceeds 8 MiB')
    try:
        document = json.loads(body)
    except ValueError:
        raise ValueError('WARP device API returned invalid JSON') from None
    if not isinstance(document, dict) or document.get('success', True) is not True or document.get('errors'):
        raise ValueError('WARP device API returned an unsuccessful response')
    device = document.get('result', document)
    if not isinstance(device, dict) or not isinstance(device.get('policy'), dict):
        raise ValueError('the registration response contains no split-tunnel policy')
    if device.get('enabled') is False:
        raise ValueError('Cloudflare reports this registration is disabled')
    if 'id' in device:
        try:
            _, returned_uuid = split_registration_id(device['id'])
        except ValueError:
            raise ValueError('unrecognized registration ID format in the device API response '
                             '(expected UUID or t.<UUID>)') from None
        if returned_uuid != expected_uuid:
            raise ValueError('the registration UUID in the device API response differs from reg.json')
    return device


def parse_policy(policy) -> RoutePolicy:
    """Validate the complete snapshot before publishing any of its routes."""
    if not isinstance(policy, dict):
        raise ValueError('expected a split-tunnel policy object')
    rules = {}
    for key in ('include', 'exclude', 'always_include', 'always_exclude'):
        entries = policy.get(key)
        if entries is not None and not isinstance(entries, list):
            raise ValueError(f'expected a list in policy.{key}')
        rules[key] = entries
    modes = [key for key in ('include', 'exclude') if rules[key]]
    if not modes:
        modes = [key for key in ('include', 'exclude') if rules[key] is not None]
    if len(modes) != 1:
        raise ValueError('split-tunnel mode is missing or ambiguous')
    mode = modes[0]
    domains = set()
    networks = {}
    for key in (mode, 'always_include', 'always_exclude'):
        subnets = set()
        field = 'address' if key == mode else 'ip'
        for entry in rules[key] or []:
            if not isinstance(entry, dict):
                raise ValueError(f'invalid route in policy.{key}')
            if key == mode and entry.get('host') not in (None, ''):
                host = entry['host']
                if not isinstance(host, str) or not host.strip():
                    raise ValueError(f'invalid domain in policy.{key}')
                domains.add(host)
                if entry.get(field) in (None, ''):
                    continue
            address = entry.get(field)
            try:
                if not isinstance(address, str):
                    raise ValueError
                subnets.add(ipaddress.ip_network(address, strict=False))
            except ValueError:
                raise ValueError(f'invalid {field} in policy.{key}') from None
        networks[key] = sorted(subnets, key=lambda net: (net.version, net))
    return RoutePolicy(mode, tuple(networks[mode]), tuple(networks['always_include']),
                       tuple(networks['always_exclude']), tuple(sorted(domains)))


def fetch_policy(registration) -> RoutePolicy:
    return parse_policy(fetch_device(registration)['policy'])


def _tunnel(private_key, peer_key, endpoint, addresses, ipv4_only, raw_policy):
    if not all(isinstance(value, str) and value for value in (private_key, peer_key, endpoint)):
        raise ValueError('missing WireGuard key or peer endpoint')
    return WireGuardTunnel(
        private_key=private_key, peer_public_key=peer_key, endpoint=endpoint,
        address4=f'{ipaddress.IPv4Address(addresses["v4"])}/32',
        address6=None if ipv4_only else f'{ipaddress.IPv6Address(addresses["v6"])}/128',
        policy=None if raw_policy is None else parse_policy(raw_policy),
    )


def cached_tunnel(config, registration, ipv4_only) -> WireGuardTunnel:
    """Read the legacy conf.json and reg.json representations without contacting Cloudflare."""
    return _tunnel(registration['secret_key'], config['public_key'], config['endpoints'][0]['v4'],
                   config['interface'], ipv4_only, config.get('policy'))


def fetch_tunnel(registration, ipv4_only) -> WireGuardTunnel:
    device = fetch_device(registration)
    if 'key' in device and device['key'] != registration.get('public_key'):
        raise ValueError('the registered WireGuard public key has changed')
    policy = device['policy']
    if str(policy.get('tunnel_protocol', 'wireguard')).lower() != 'wireguard':
        raise ValueError('the Cloudflare device policy does not select WireGuard')
    try:
        config = device['config']
        addresses = config['interface']['addresses']
        peer = config['peers'][0]
        public = peer['public_key']
        if len(base64.b64decode(public, validate=True)) != 32:
            raise ValueError('invalid peer public key')
        endpoint = peer['endpoint']
        address, _, raw_port = endpoint['v4'].partition(':')
        address = ipaddress.IPv4Address(address)
        port = int(raw_port or 0)
        if port == 0:
            port = next((p for p in endpoint.get('ports', [])
                         if type(p) is int and 1 <= p <= 65535), 0)
        if not 1 <= port <= 65535:
            raise ValueError('no usable WireGuard endpoint port in the registration')
        return _tunnel(registration['secret_key'], public, f'{address}:{port}', addresses, ipv4_only, policy)
    except (KeyError, IndexError, AttributeError, TypeError):
        raise ValueError('the device response is missing WireGuard tunnel settings') from None
