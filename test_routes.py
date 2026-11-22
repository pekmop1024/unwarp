import contextlib
import fcntl
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from configparser import ConfigParser
from pathlib import Path
from unittest.mock import patch

import unwarp


DEVICE = '23acecdf-bddc-4451-b1bf-978461d105e9'
ACCOUNT = '0123456789abcdef0123456789abcdef'
PROFILE = 'dd996575-e5d2-46da-815b-d55ebc750184'
REGISTRATION = {'registration_id': [DEVICE, None], 'account_id': ACCOUNT, 'api_token': 'test-credential'}
POLICY = {
    'include': [{'address': '192.0.2.5/24'}, {'address': '192.0.2.0/24'},
                {'address': '2001:db8::/48'}, {'host': '*.example.test'}],
    'exclude': None,
    'always_include': [{'ip': '198.51.100.1'}, {'ip': '2001:db8:1::1'}],
    'always_exclude': [{'ip': '192.0.2.0/25'}, {'ip': '2001:db8:2::/64'}],
}


class RoutesTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.registration = Path(directory.name, 'reg.json')
        self.registration.write_text(json.dumps(REGISTRATION))

    def run_command(self, response, *args, status=200):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        with patch('unwarp.http.client.HTTPSConnection') as self.https:
            body = response if isinstance(response, bytes) else json.dumps(response).encode()
            message = io.BytesIO(body)
            message.status = status
            self.session = self.https.return_value
            self.session.getresponse.return_value = message
            with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
                return unwarp.main(['routes', '-w', str(self.registration), *args])

    def test_managed_device_preview(self):
        response = {'success': True, 'result': {'id': DEVICE, 'policy': POLICY, 'override_codes': 'private'}}
        with patch('unwarp.nmcli') as nmcli:
            self.assertEqual(self.run_command(response), 0)
            nmcli.assert_not_called()
        self.https.assert_called_once_with('api.devices.cloudflare.com', timeout=15)
        method, path = self.session.request.call_args.args
        self.assertEqual((method, path), ('GET', f'/v1/accounts/{ACCOUNT}/reg/{DEVICE}'))
        self.assertEqual(self.session.request.call_args.kwargs['headers']['Authorization'], 'Bearer test-credential')
        self.assertEqual(json.loads(self.stdout.getvalue()), {
            'mode': 'include', 'include': ['192.0.2.0/24'], 'domains': ['*.example.test'],
            'always_include': ['198.51.100.1/32'], 'always_exclude': ['192.0.2.0/25'],
        })
        request = self.session.request.call_args
        self.assertEqual(self.run_command(response, '--dual-stack'), 0)
        self.assertEqual(self.session.request.call_args, request)
        self.assertEqual(json.loads(self.stdout.getvalue()), {
            'mode': 'include', 'include': ['192.0.2.0/24', '2001:db8::/48'], 'domains': ['*.example.test'],
            'always_include': ['198.51.100.1/32', '2001:db8:1::1/128'],
            'always_exclude': ['192.0.2.0/25', '2001:db8:2::/64'],
        })

    def test_legacy_registration_and_raw_device(self):
        self.registration.write_text(json.dumps({'registration_id': DEVICE, 'api_token': 'test-credential'}))
        self.assertEqual(self.run_command({'id': DEVICE, 'policy': POLICY}, '-4'), 0)
        self.https.assert_called_once_with('api.cloudflareclient.com', timeout=15)
        self.assertEqual(self.session.request.call_args.args, ('GET', f'/v0a5641/reg/{DEVICE}'))
        self.assertEqual(json.loads(self.stdout.getvalue())['include'], ['192.0.2.0/24'])

    def test_registration_id_wire_formats(self):
        compact = DEVICE.replace('-', '').upper()
        for local, returned, requested in (
            ([DEVICE, None], 't.' + DEVICE, DEVICE),
            (DEVICE, compact, DEVICE),
            ('t.' + compact, DEVICE, 't.' + DEVICE),
        ):
            with self.subTest(local=local, returned=returned):
                self.registration.write_text(json.dumps({**REGISTRATION, 'registration_id': local}))
                response = {'result': {'id': returned, 'policy': POLICY}}
                self.assertEqual(self.run_command(response), 0, self.stderr.getvalue())
                self.assertEqual(json.loads(self.stdout.getvalue())['mode'], 'include')
                self.assertEqual(self.session.request.call_args.args, ('GET', f'/v1/accounts/{ACCOUNT}/reg/{requested}'))

    def test_unexpected_id_blocks_apply_without_disclosing_it(self):
        for returned, reason in (('t.' + PROFILE, 'differs'), ('other.' + DEVICE, 'format'), (None, 'format')):
            with self.subTest(returned=returned), patch('unwarp.nmcli') as nmcli:
                response = {'result': {'id': returned, 'policy': POLICY}}
                self.assertEqual(self.run_command(response, '--apply', 'test'), 1)
                nmcli.assert_not_called()
                self.assertEqual(self.stdout.getvalue(), '')
                self.assertIn(reason, self.stderr.getvalue())
                self.assertNotIn(DEVICE, self.stderr.getvalue())
                self.assertNotIn(PROFILE, self.stderr.getvalue())

    def test_fetch_failures_never_modify_a_profile_or_print_secrets(self):
        cases = [
            (302, b'test-credential'), (401, b'test-credential'), (403, b'test-credential'),
            (200, b'<html>test-credential</html>'), (200, {'success': False, 'result': {'policy': POLICY}}),
            (200, {'result': {}}), (200, {'id': PROFILE, 'policy': POLICY}),
            (200, {'policy': {'include': [{'address': 'not a CIDR'}]}}),
            (200, {'policy': {'include': [], 'exclude': []}}),
            (200, {'policy': {'include': [], 'always_exclude': {}}}),
            (200, {'policy': {'include': POLICY['include'], 'exclude': [{'host': 'example.test'}]}}),
        ]
        for status, response in cases:
            with self.subTest(status=status, response=response), patch('unwarp.nmcli') as nmcli:
                self.assertEqual(self.run_command(response, '--apply', 'test', status=status), 1)
                nmcli.assert_not_called()
                self.session.request.assert_called_once()
                self.assertEqual(self.stdout.getvalue(), '')
                self.assertNotIn('test-credential', self.stderr.getvalue())

    def test_invalid_registration_fails_before_network(self):
        for changes in ({'account_id': 'bad'}, {'registration_id': []}, {'api_token': 'x\ny'}):
            with self.subTest(changes=changes):
                self.registration.write_text(json.dumps({**REGISTRATION, **changes}))
                self.assertEqual(self.run_command({}), 1)
                self.https.assert_not_called()

    def test_simultaneous_apply_skips_fetch(self):
        with self.registration.open() as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_command({'policy': POLICY}, '--apply', 'test'), 1)
            self.https.assert_not_called()

    def test_exclude_can_be_inspected(self):
        data = {'policy': {'include': [], 'exclude': [{'address': '198.51.100.2'}, {'address': '2001:db8::/64'}]}}
        self.assertEqual(self.run_command(data), 0)
        self.assertEqual(json.loads(self.stdout.getvalue())['exclude'], ['198.51.100.2/32'])
        with patch('unwarp.nmcli') as nmcli:
            self.assertEqual(self.run_command(data, '--apply', 'test'), 1)
            nmcli.assert_not_called()

    @unittest.skipUnless(shutil.which('nmcli'), 'NetworkManager CLI is unavailable')
    def test_initial_profile_route_families(self):
        key = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
        config = {'policy': POLICY, 'public_key': key, 'endpoints': [{'v4': '192.0.2.254:2408'}],
                  'interface': {'v4': '192.0.2.1', 'v6': '2001:db8::1'}}
        for flags, ipv4_only in (([], True), (['--ipv4only'], True), (['--dual-stack'], False)):
            with self.subTest(flags=flags):
                args = unwarp.parse_args(['-i', 'wg-test', '-n', 'test', *flags])
                profile = unwarp.create_nm_config(config, {'secret_key': key}, args.interface,
                                                  args.nmconnectionname, args.ipv4only, None)
                rendered = io.StringIO()
                profile.write(rendered)
                saved = subprocess.check_output(['nmcli', '--offline', 'connection', 'modify', 'connection.id', 'test'],
                                                input=rendered.getvalue(), text=True)
                self.assertIn('192.0.2.128/25', saved)
                if ipv4_only:
                    self.assertIn('method=disabled', saved)
                    self.assertNotIn('::/0', saved)
                    self.assertNotIn('2001:db8::/48', saved)
                else:
                    self.assertIn('allowed-ips=0.0.0.0/0;::/0;', saved)
                    self.assertIn('2001:db8::/48', saved)

    @unittest.skipUnless(shutil.which('nmcli'), 'NetworkManager CLI is unavailable')
    def test_apply_replaces_routes_in_a_real_offline_nm_profile(self):
        nm = ['nmcli', '--offline', 'connection']
        initial = subprocess.check_output([*nm, 'add', 'type', 'wireguard', 'ifname', 'wg-test',
                                           'con-name', 'test', 'wireguard.peer-routes', 'no',
                                           'ipv4.method', 'manual', 'ipv4.addresses', '192.0.2.1/32',
                                           'ipv4.routes', '203.0.113.0/24', 'ipv4.dns-search', 'example.test',
                                           'ipv6.method', 'manual', 'ipv6.addresses', '2001:db8::1/128'])
        profile = initial
        active = False
        reapplied = []
        writes = []

        def nmcli(*args):
            nonlocal profile
            if args[0] == '--get-values':
                parsed = ConfigParser()
                parsed.read_string(profile.decode())
                def static_routes(family):
                    return ', '.join(value for key, value in parsed[family].items() if key.startswith('route'))
                return [PROFILE, 'wireguard', 'no', 'manual', static_routes('ipv4'), 'manual', static_routes('ipv6')]
            if args[:4] == ('connection', 'modify', 'uuid', PROFILE):
                writes.append(args[4:])
                profile = subprocess.check_output([*nm, 'modify', *args[4:]], input=profile)
                return []
            if args[-1] == '--active':
                return [DEVICE + ':unrelated', PROFILE + ':wg-test'] if active else []
            if args[:2] == ('device', 'reapply'):
                reapplied.append(args[2])
                if len(reapplied) == 1:
                    raise ValueError('simulated reapply failure')
                return []
            self.fail(args)

        with patch('unwarp.nmcli', side_effect=nmcli):
            data = {'policy': POLICY}
            self.assertEqual(self.run_command(data, '--dual-stack', '--apply', 'test'), 0)
            self.assertIn(b'192.0.2.128/25', profile)
            self.assertIn(b'198.51.100.1/32', profile)
            self.assertIn(b'2001:db8::/48', profile)
            self.assertNotIn(b'203.0.113.0/24', profile)
            self.assertIn(b'dns-search=example.test;', profile)
            self.assertEqual(reapplied, [])
            active = True
            first = profile
            self.assertEqual(self.run_command(data, '--apply', 'test'), 1)
            self.assertIn('reapply failure', self.stderr.getvalue())
            self.assertEqual(self.run_command(data, '--apply', 'test'), 0)
            self.assertEqual(profile, first)
            self.assertEqual(len(writes), 1)
            self.assertEqual(reapplied, ['wg-test', 'wg-test'])
            empty = {'policy': {'include': []}}
            self.assertEqual(self.run_command(empty, '--apply', 'test'), 0)
            self.assertNotIn(b'192.0.2.128/25', profile)
            self.assertIn(b'1.1.1.1/32', profile)
            self.assertIn(b'2001:db8::/48', profile)
            self.assertNotIn('ipv6.routes', writes[-1])


if __name__ == '__main__':
    unittest.main()
