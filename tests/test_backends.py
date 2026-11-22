import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch

import unwarp
from unwarp.backends import BACKENDS, DEFAULT_BACKEND, ConfigBackend, get_backend
from unwarp.model import ProfileTarget, RouteOptions, RoutePolicy, WireGuardTunnel

from tests.fixtures import ACCOUNT, DEVICE, DEVICE_TOKEN, LIVE, POLICY, PRIVATE, PUBLIC, TEAM


class BackendTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = self.root / 'config'
        self.config.mkdir(mode=0o700)
        self.plugin = ModuleType('test_unwarp_output')
        self.plugin.reserved_interfaces = Mock(return_value={'unwarp0'})
        self.plugin.write_profile = Mock()
        self.plugin.apply_routes = Mock()
        for context in (patch.dict(BACKENDS, {'test-output': self.plugin.__name__}),
                        patch.dict(sys.modules, {self.plugin.__name__: self.plugin}),
                        patch('unwarp.profiles.SYSTEM_INTERFACES', self.root)):
            context.start()
            self.addCleanup(context.stop)
        device = patch('unwarp.cloudflare.client.fetch_device', return_value=LIVE)
        self.device = device.start()
        self.addCleanup(device.stop)
        self.record = {'state': 'registered', 'interface': 'office', 'connection_name': 'Office / VPN',
                       'connection_uuid': '12345678-1234-4234-8234-123456789abc', 'public_key': PUBLIC,
                       'secret_key': PRIVATE, 'account_id': ACCOUNT, 'registration_id': DEVICE,
                       'api_token': DEVICE_TOKEN}
        self.saved = self.config / 'office.json'
        self.saved.write_text(json.dumps(self.record))

    def cli(self, *args):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        with (contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr),
              patch('unwarp.cli.configure_logging')):
            return unwarp.main(['--config-dir', str(self.config), *args])

    def test_cached_import_reserves_live_and_output_directory_interfaces(self):
        directory = self.root / 'keyfiles'
        directory.mkdir()
        (directory / 'Office.nmconnection').write_text('[connection]\nid=Office\ninterface-name=unwarp1\n')
        cached = self.root / 'conf.json'
        cached.write_text(json.dumps({'public_key': PUBLIC, 'interface': {'v4': '192.0.2.1'},
                                      'endpoints': [{'v4': '198.51.100.1:2408'}]}))
        with patch('unwarp.backends.networkmanager.nmcli', side_effect=[[self.record['connection_uuid']], ['unwarp0']]):
            self.assertEqual(self.cli('-z', str(cached), '-w', str(self.saved), '-c', str(directory),
                                      '--mtu', '1200'), 0, self.stderr.getvalue())
        keyfile = (directory / 'unwarp2.nmconnection').read_text()
        self.assertIn('interface-name = unwarp2', keyfile)
        self.assertIn('mtu = 1200\n', keyfile)
        self.device.assert_not_called()

    def test_enrollment_and_both_sources_dispatch_to_same_plugin(self):
        with (patch('unwarp.profiles.sign_in', return_value=('assertion', ACCOUNT)),
              patch('unwarp.profiles.generate_private_key', return_value=PRIVATE),
              patch('unwarp.profiles.register_device', return_value=(DEVICE, DEVICE_TOKEN))):
            self.assertEqual(self.cli('--backend', 'test-output', 'enroll', TEAM, '-n', 'Office / VPN'), 0)
        self.plugin.reserved_interfaces.assert_called_once_with(None)
        data = json.loads((self.config / 'unwarp1.json').read_text())
        self.assertEqual(data['backend'], 'test-output')
        self.plugin.write_profile.assert_not_called()
        cached = self.root / 'conf.json'
        cached.write_text(json.dumps({'policy': POLICY, 'public_key': PUBLIC,
                                      'endpoints': [{'v4': '198.51.100.1:2408'}],
                                      'interface': {'v4': '192.0.2.1', 'v6': '2001:db8::1'}}))
        flags = ['--dual-stack', '--mtu', '1400', '-s', 'local.example', '-D', '-c', str(self.root)]
        self.assertEqual(self.cli('-z', str(cached), '-w', str(self.saved), '-i', 'office',
                                  '--backend', 'test-output', *flags), 0, self.stderr.getvalue())
        self.device.assert_not_called()
        cached_target, cached_tunnel, options, output = self.plugin.write_profile.call_args.args
        self.assertEqual(cached_target, ProfileTarget('office', 'office'))
        self.assertTrue(output.dry_run)
        self.assertEqual(output.directory, self.root)
        self.assertEqual(options, RouteOptions(False, ('local.example',), False))
        self.assertEqual(self.cli('profile', '-i', 'unwarp1', *flags), 0, self.stderr.getvalue())
        self.device.assert_called_once()
        target, live_tunnel, live_options, live_output = self.plugin.write_profile.call_args.args
        self.assertEqual(target, ProfileTarget('unwarp1', 'Office / VPN', data['connection_uuid']))
        self.assertEqual((live_tunnel, live_options, live_output), (cached_tunnel, options, output))
        self.assertIsInstance(live_tunnel, WireGuardTunnel)
        self.assertEqual(live_tunnel.mtu, 1400)
        self.assertEqual(live_tunnel.private_key, PRIVATE)
        self.assertEqual(live_tunnel.address6, '2001:db8::1/128')
        self.assertNotIn('api_token', vars(live_tunnel))
        self.assertNotIn(DEVICE_TOKEN, repr(self.plugin.write_profile.call_args))
        self.assertNotIn(PRIVATE, repr(live_tunnel))

        self.device.return_value = {'policy': {'exclude': [{'address': '192.0.2.0/24'}]}}
        self.assertEqual(self.cli('routes', '-i', 'unwarp1', '--apply'), 0)
        applied_target, policy, route_options = self.plugin.apply_routes.call_args.args
        self.assertEqual(applied_target, target)
        self.assertIsInstance(policy, RoutePolicy)
        self.assertEqual(policy.mode, 'exclude')
        self.assertEqual(route_options, RouteOptions())
        self.assertEqual(self.cli('routes', '-w', str(self.saved), '--apply', 'explicit profile',
                                  '--backend', 'test-output'), 0)
        self.assertEqual(self.plugin.apply_routes.call_args.args[0], 'explicit profile')

    def test_old_config_defaults_and_one_off_override(self):
        self.assertIsInstance(get_backend(DEFAULT_BACKEND), ConfigBackend)
        original = self.saved.read_bytes()
        self.assertEqual(self.cli('profile', '-i', 'office', '--nmconnectionpath', str(self.root)), 0)
        keyfile = (self.root / 'office.nmconnection').read_text()
        self.assertIn(self.record['connection_uuid'], keyfile)
        self.assertIn('mtu = 1280\n', keyfile)
        self.plugin.write_profile.assert_not_called()
        self.assertEqual(self.cli('profile', '-i', 'office', '--backend', 'test-output'), 0)
        self.plugin.write_profile.assert_called_once()
        self.assertEqual(self.saved.read_bytes(), original)

    def test_invalid_mtu_fails_before_fetching_or_writing(self):
        for flags in (['--mtu', 'auto'], ['--mtu', '67'], ['--mtu', '65536'], ['--dual-stack', '--mtu', '1279']):
            with self.subTest(flags=flags):
                with self.assertRaises(SystemExit) as error:
                    self.cli('profile', '-i', 'office', '-c', str(self.root), *flags)
                self.assertEqual(error.exception.code, 2)
                self.assertIn('--mtu', self.stderr.getvalue())
        self.device.assert_not_called()
        self.assertFalse((self.root / 'office.nmconnection').exists())

    def test_in_memory_cached_api(self):
        cached = {'interface': {'v4': '192.0.2.1'}, 'endpoints': [{'v4': '198.51.100.1:2408'}],
                  'public_key': PUBLIC, 'policy': POLICY}
        self.assertEqual(unwarp.get_routes(cached), (['1.1.1.1/32', '192.0.2.0/24'], []))
        profile = unwarp.create_nm_config(cached, {'secret_key': PRIVATE}, 'office', 'Office', True, 'local.test')
        self.assertEqual(profile['ipv4']['dns-search'], 'local.test;corp.example;')
        self.assertEqual(profile['wireguard']['private-key'], PRIVATE)
        self.device.assert_not_called()

    def test_policy_preview_is_independent_of_backend_availability(self):
        self.saved.write_text(json.dumps({**self.record, 'backend': 'missing'}))
        with patch('unwarp.cli.get_backend', side_effect=AssertionError('preview loaded a backend')):
            self.assertEqual(self.cli('routes', '-i', 'office'), 0)
        self.assertEqual(json.loads(self.stdout.getvalue())['dns_search'], ['corp.example'])
        self.device.reset_mock()
        for cmd in (('profile', '-i', 'office'), ('routes', '-i', 'office', '--apply')):
            self.assertEqual(self.cli(*cmd), 1)
            self.assertIn('unknown configuration backend', self.stderr.getvalue())
        self.device.assert_not_called()
        with self.assertRaises(SystemExit) as error:
            self.cli('routes', '--backend', 'unknown', '-i', 'office')
        self.assertEqual(error.exception.code, 2)
        self.device.assert_not_called()


if __name__ == '__main__':
    unittest.main()
