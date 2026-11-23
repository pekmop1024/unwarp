import base64
import contextlib
import http.client
import io
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import unwarp
from unwarp import cli, profiles
from unwarp.backends import networkmanager
from unwarp.cloudflare import client as cloudflare, login

from tests.fixtures import (ACCOUNT, DEVICE, DEVICE_TOKEN, HOST, KEY_SEED, LIVE, POLICY, PRIVATE, PUBLIC,
                            TEAM, callback, reply)


class ConfigDirectoryTest(unittest.TestCase):
    def test_checkout_uses_its_own_config_even_with_xdg(self):
        checkout = Path(__file__).resolve().parents[1]
        with patch.dict(os.environ, XDG_CONFIG_HOME='/xdg'):
            args = unwarp.parse_args(['routes', '-i', 'unwarp0'])
            self.assertEqual(args.config_dir, checkout / 'config')

    def test_installed_config_uses_xdg_or_home_and_allows_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / 'home'
            xdg = root / 'xdg'
            module = root / 'site-packages' / 'unwarp' / 'profiles.py'
            with patch.object(profiles, '__file__', str(module)), patch.dict(os.environ, HOME=str(home)):
                for value in (None, '', 'relative', str(xdg)):
                    with self.subTest(xdg=value):
                        os.environ.pop('XDG_CONFIG_HOME', None)
                        if value is not None:
                            os.environ['XDG_CONFIG_HOME'] = value
                        expected = xdg if value == str(xdg) else home / '.config'
                        self.assertEqual(unwarp.parse_args(['routes']).config_dir, expected / 'unwarp')
                override = root / 'profiles'
                for argv in (['--config-dir', str(override), 'routes'], ['enroll', TEAM, '--config-dir', str(override)]):
                    self.assertEqual(unwarp.parse_args(argv).config_dir, override)


class EnrollmentTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.directory = self.root / 'config'
        self.sysnet = self.root / 'net'
        self.sysnet.mkdir()
        self.keyfiles = self.root / 'system-connections'
        self.keyfiles.mkdir()
        keyfiles = patch.object(networkmanager, 'DEFAULT_DIRECTORY', self.keyfiles)
        keyfiles.start()
        self.addCleanup(keyfiles.stop)
        devices = patch('unwarp.profiles.SYSTEM_INTERFACES', self.sysnet)
        devices.start()
        self.addCleanup(devices.stop)
        manager = patch('unwarp.backends.networkmanager.nmcli', return_value=[])
        self.manager = manager.start()
        self.addCleanup(manager.stop)
        self.output = io.StringIO()
        self.errors = io.StringIO()
        https = patch('http.client.HTTPSConnection')
        self.https = https.start()
        self.addCleanup(https.stop)
        self.connection = self.https.return_value
        entropy = patch('unwarp.keys.token_bytes', return_value=KEY_SEED)
        self.entropy = entropy.start()
        self.addCleanup(entropy.stop)
        self.connection.getresponse.return_value = self.success()

    def success(self):
        return reply({'success': True, 'result': {'id': DEVICE, 'token': DEVICE_TOKEN,
                      'key': PUBLIC, 'account': {'organization': TEAM}}})

    def cli(self, command, *args, browser_callback=None):
        with (contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.errors),
              patch('unwarp.cli.configure_logging'), patch('sys.stdin', io.StringIO(browser_callback or callback()))):
            return unwarp.main([command, '--config-dir', str(self.directory), *args])

    def enroll(self, *args, **kwargs):
        return self.cli('enroll', TEAM, '--manual', *args, **kwargs)

    def test_enroll_profile_and_scheduled_routes(self):
        name = ' Отдел / VPN 100% \\HQ\nEU '
        with patch.dict(os.environ, PATH=str(self.root)), patch('socket.gethostname', return_value='office-laptop'):
            self.assertEqual(self.enroll('-n', name), 0, self.errors.getvalue())
        path = self.directory / 'unwarp0.json'
        data = json.loads(path.read_text())
        self.assertEqual(data['state'], 'registered')
        self.assertEqual(data['connection_name'], name)
        self.assertEqual(data['device_name'], 'office-laptop')
        self.assertEqual(data['client_version'], cloudflare.DEFAULT_CLIENT_VERSION)
        self.assertEqual(data['account_id'], ACCOUNT)
        self.assertEqual(data['api_token'], DEVICE_TOKEN)
        self.assertEqual(data['secret_key'], PRIVATE)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertNotIn('signature', path.read_text())
        self.https.assert_called_once_with('api.devices.cloudflare.com', timeout=20)
        request = self.connection.request.call_args
        self.assertEqual(request.args, ('POST', '/v0/reg'))
        self.assertEqual(json.loads(request.kwargs['body']), {'type': 'linux', 'key': PUBLIC, 'name': 'office-laptop'})
        self.assertEqual(request.kwargs['headers']['CF-Client-Version'], 'l-' + cloudflare.DEFAULT_CLIENT_VERSION)
        self.assertTrue(request.kwargs['headers']['Cf-Access-Jwt-Assertion'].endswith('.signature'))

        self.connection.getresponse.return_value = reply({'result': LIVE})
        self.assertEqual(self.cli('profile', '-i', 'unwarp0', '-c', str(self.root)), 0, self.errors.getvalue())
        target = self.root / 'unwarp0.nmconnection'
        keyfile = target.read_text()
        self.assertIn('id = ' + networkmanager.keyfile_string(name), keyfile)
        self.assertIn(data['connection_uuid'], keyfile)
        self.assertIn('198.51.100.1:2408', keyfile)
        self.assertIn('dns-search = corp.example;', keyfile)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        if shutil.which('nmcli'):
            subprocess.run(['nmcli', '--offline', 'connection', 'modify', 'wireguard.peer-routes', 'no'],
                           input=keyfile, text=True, capture_output=True, check=True)

        self.connection.getresponse.return_value = reply({'result': LIVE})
        self.manager.reset_mock()
        self.manager.side_effect = [[data['connection_uuid'], 'wireguard', 'no', 'manual', '', '',
                                     'disabled', '', ''], [], []]
        self.assertEqual(self.cli('routes', '-i', 'unwarp0', '--apply'), 0, self.errors.getvalue())
        self.assertEqual(self.manager.call_args_list[0].args[-2:], ('uuid', data['connection_uuid']))
        self.assertEqual(self.connection.request.call_args.args, ('GET', f'/v1/accounts/{ACCOUNT}/reg/{DEVICE}'))
        self.assertEqual(self.connection.request.call_args.kwargs['headers']['Authorization'], 'Bearer ' + DEVICE_TOKEN)
        self.assertEqual(self.enroll('-i', 'unwarp0'), 0)
        self.assertEqual(self.connection.request.call_count, 3)
        for secret in (DEVICE_TOKEN, PRIVATE, '.signature'):
            self.assertNotIn(secret, self.output.getvalue() + self.errors.getvalue())

    def test_custom_enrollment_metadata_survives_an_interrupted_login(self):
        options = ('-i', 'vpn', '-n', 'Work VPN',
                   '--device-name', 'Ноутбук QA', '--client-version', '2026.8-lab')
        with patch('socket.gethostname', side_effect=AssertionError('unexpected hostname lookup')):
            self.assertEqual(self.enroll(*options, browser_callback=callback(exp=0)), 1)
            self.https.assert_not_called()
            self.assertEqual(self.enroll('-i', 'vpn'), 0, self.errors.getvalue())
            self.assertEqual(self.enroll(*options), 0, self.errors.getvalue())
            for flag in ('--device-name', '--client-version'):
                self.assertEqual(self.enroll('-i', 'vpn', flag, 'different'), 1)
                self.assertIn('vpn is already registered', self.errors.getvalue())
        self.assertEqual(self.connection.request.call_count, 1)
        request = self.connection.request.call_args.kwargs
        self.assertEqual(json.loads(request['body'])['name'], 'Ноутбук QA')
        self.assertEqual(request['headers']['CF-Client-Version'], 'l-2026.8-lab')
        config = json.loads((self.directory / 'vpn.json').read_text())
        self.assertEqual((config['interface'], config['connection_name']), ('vpn', 'Work VPN'))
        self.assertEqual((config['device_name'], config['client_version']), ('Ноутбук QA', '2026.8-lab'))

    def test_legacy_enrollments_and_independent_metadata_overrides(self):
        path = self.directory / 'vpn.json'
        self.assertEqual(self.enroll('-i', 'vpn', browser_callback=callback(exp=0)), 1)
        data = json.loads(path.read_text())
        del data['device_name'], data['client_version']
        path.write_text(json.dumps(data))
        with patch('socket.gethostname', return_value='lab-host'):
            status = self.enroll('-i', 'vpn', '--client-version', 'lab.1', browser_callback=callback(exp=0))
            self.assertEqual(status, 1)
        pending = json.loads(path.read_text())
        self.assertEqual((pending['device_name'], pending['client_version']), ('lab-host', 'lab.1'))
        self.https.assert_not_called()
        self.assertEqual(self.enroll('-i', 'vpn', '--device-name', 'QA laptop'), 0, self.errors.getvalue())
        request = self.connection.request.call_args.kwargs
        self.assertEqual(json.loads(request['body'])['name'], 'QA laptop')
        self.assertEqual(request['headers']['CF-Client-Version'], 'l-lab.1')
        registered = json.loads(path.read_text())
        del registered['device_name'], registered['client_version']
        path.write_text(json.dumps(registered))
        self.assertEqual(self.enroll('-i', 'vpn'), 0, self.errors.getvalue())
        self.assertEqual(json.loads(path.read_text()), registered)
        self.assertEqual(self.connection.request.call_count, 1)

    def test_invalid_metadata_is_rejected_before_login(self):
        with patch('unwarp.profiles.sign_in') as sign_in:
            for flag, value in (('--device-name', ' '), ('--device-name', 'я' * 51),
                                ('--client-version', ''), ('--client-version', '1\r\nX-Header: value')):
                with self.subTest(flag=flag, value=value):
                    self.assertEqual(self.enroll('-i', 'vpn', flag, value), 1)
                    self.assertIn(flag, self.errors.getvalue())
        sign_in.assert_not_called()
        self.https.assert_not_called()
        self.assertFalse((self.directory / 'vpn.json').exists())

    def test_enrollment_prints_reusable_system_profile_command(self):
        self.directory = self.root / "user's registrations"
        self.assertEqual(self.enroll('-i', 'office'), 0, self.errors.getvalue())
        self.assertEqual(self.enroll('-i', 'office'), 0, self.errors.getvalue())
        commands = [shlex.split(line) for line in self.output.getvalue().splitlines() if line.startswith('  ')]
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], commands[1])
        command = commands[0]
        if os.geteuid() != 0:
            self.assertEqual(command[0], 'sudo')
        if command[0] == 'sudo':
            command.pop(0)
        launcher = [sys.executable, str(Path(__file__).resolve().parents[1] / 'unwarp.py')]
        self.assertEqual(command[:2], launcher)
        args = unwarp.parse_args(command[2:])
        self.assertEqual((args.command, args.config_dir, args.interface, args.reload),
                         ('profile', self.directory, 'office', True))
        self.assertEqual(self.connection.request.call_count, 1)
        self.connection.getresponse.return_value = reply({'result': LIVE})
        with contextlib.redirect_stdout(self.output), patch('unwarp.cli.configure_logging'):
            self.assertEqual(unwarp.main(command[2:]), 0)
        self.assertTrue((self.keyfiles / 'office.nmconnection').is_file())

    def test_interactive_sudo_enrolls_as_the_invoking_desktop_user(self):
        stdin = MagicMock()
        stdin.isatty.return_value = True
        args = ['enroll', TEAM, '-i', 'office']
        with (patch('os.geteuid', return_value=0),
              patch.dict(os.environ, SUDO_UID='1234', HOME='/root', DISPLAY=':test', ADMIN_ONLY='secret'),
              patch('sys.stdin', stdin), contextlib.redirect_stderr(self.errors),
              patch('unwarp.cli.checkout_root', return_value=None),
              patch('unwarp.cli.default_config_dir', return_value=self.directory),
              patch('unwarp.cli.pwd.getpwuid') as account, patch('os.getgrouplist', return_value=[345, 456]),
              patch('unwarp.cli.subprocess.run') as child):
            account.return_value = MagicMock(pw_dir='/home/desktop', pw_name='desktop', pw_gid=345)
            child.return_value.returncode = 23
            self.assertEqual(unwarp.main(args), 23)
        account.assert_called_once_with(1234)
        argv, = child.call_args.args
        self.assertEqual(argv, [sys.executable, '-I', '-m', 'unwarp', *args])
        opts = child.call_args.kwargs
        self.assertEqual((opts['user'], opts['group'], opts['extra_groups']), (1234, 345, [345, 456]))
        self.assertEqual((opts['env']['HOME'], opts['env']['USER'], opts['env']['DISPLAY']),
                         ('/home/desktop', 'desktop', ':test'))
        self.assertNotIn('SUDO_UID', opts['env'])
        self.assertNotIn('ADMIN_ONLY', opts['env'])
        self.assertFalse(self.directory.exists())
        self.https.assert_not_called()

    def test_sudo_keeps_root_owned_state_and_delegates_only_browser_sign_in(self):
        stdin = MagicMock()
        stdin.isatty.return_value = True
        args = ['enroll', TEAM, '--config-dir', '/', '-i', 'office']
        with (patch('os.geteuid', return_value=0), patch.dict(os.environ, SUDO_UID='1234'),
              patch('sys.stdin', stdin), patch('unwarp.cli.desktop_process_options') as desktop,
              patch('unwarp.cli.enroll', return_value=('office', 'networkmanager')) as register,
              patch('unwarp.cli.subprocess.run') as child,
              contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.errors)):
            self.assertEqual(unwarp.main(args), 0)
            self.assertIs(register.call_args.kwargs['browser_options'], desktop.return_value)
            self.assertEqual(unwarp.main([*args, '--manual']), 0)
            self.assertIsNone(register.call_args.kwargs['browser_options'])
        self.assertIn('  sudo ', self.output.getvalue())
        child.assert_not_called()
        self.https.assert_not_called()

    def test_sudo_recovers_an_unambiguous_local_wayland_display(self):
        with (patch.dict(os.environ, {'XDG_RUNTIME_DIR': str(self.root)}, clear=True),
              socket.socket(socket.AF_UNIX) as first, socket.socket(socket.AF_UNIX) as second):
            first.bind(str(self.root / 'wayland-1'))
            (self.root / 'wayland-1.lock').touch()
            self.assertEqual(cli.desktop_process_options(os.geteuid())['env']['WAYLAND_DISPLAY'], 'wayland-1')
            second.bind(str(self.root / 'wayland-2'))
            self.assertNotIn('WAYLAND_DISPLAY', cli.desktop_process_options(os.geteuid())['env'])

    def test_system_permission_error_preserves_profile_options_and_registration(self):
        self.assertEqual(self.enroll('-i', 'office'), 0, self.errors.getvalue())
        flags = ['profile', '--interface=office', '--backend', 'networkmanager', '--mtu', '1400',
                 '--dual-stack', '--overwrite', '--reload', '-s', 'manual.example other.example']
        with (patch('unwarp.backends.networkmanager.deploy_nm_config', side_effect=PermissionError),
              patch('os.geteuid', return_value=1000), patch('unwarp.cli.checkout_root', return_value=None)):
            self.connection.getresponse.return_value = reply({'result': LIVE})
            self.assertEqual(self.cli(*flags), 1)
            command = shlex.split(self.errors.getvalue().splitlines()[-1])
            self.assertEqual(command, ['sudo', sys.executable, '-I', '-m', 'unwarp', '--config-dir',
                                       str(self.directory), *flags])
            self.errors.seek(0)
            self.errors.truncate()
            self.connection.getresponse.return_value = reply({'result': LIVE})
            self.assertEqual(self.cli(*flags, '-c', str(self.root)), 1)
            self.assertNotIn('sudo', self.errors.getvalue())
        self.assertEqual(self.connection.request.call_count, 3)

    def test_interface_allocation_and_explicit_names(self):
        self.directory.mkdir(mode=0o700)
        (self.directory / 'unwarp1.json').touch()
        (self.sysnet / 'unwarp0').touch()
        self.manager.side_effect = [['12345678-1234-4234-8234-123456789abc'], ['unwarp2']]
        self.assertEqual(self.enroll(), 0)
        config = json.loads((self.directory / 'unwarp3.json').read_text())
        self.assertEqual(config['connection_name'], 'unwarp3')
        self.connection.getresponse.return_value = self.success()
        self.assertEqual(self.enroll('-i', 'wg-office'), 0)
        self.assertEqual(json.loads((self.directory / 'wg-office.json').read_text())['connection_name'], 'wg-office')
        before = self.connection.request.call_count
        self.assertEqual(self.enroll('-i', 'wg-office', '-n', 'different'), 1)
        for invalid in ('../escape', '.', '', 'this-name-is-far-too-long', 'bad:name'):
            self.assertEqual(self.enroll('-i', invalid), 1)
        self.assertEqual(self.connection.request.call_count, before)

    def test_offline_enrollment_skips_interfaces_named_inside_keyfiles(self):
        self.manager.side_effect = FileNotFoundError('nmcli')
        (self.keyfiles / 'Office.nmconnection').write_text(
            '[connection]\nid=Office VPN\ntype=wireguard\ninterface-name=unwarp0\n')
        # The filename is also reserved so a future profile will not overwrite it.
        (self.keyfiles / 'unwarp1.nmconnection').write_text('[connection]\ninterface-name=office1\n')
        (self.keyfiles / 'unwarp2.nmconnection').write_text('malformed keyfile\n')
        (self.keyfiles / 'Other.nmconnection').write_text(
            '[DEFAULT]\ninterface-name=unwarp3\n[connection]\nid=Other\n[vpn]\ninterface-name=unwarp3\n')
        self.assertEqual(self.enroll(), 0, self.errors.getvalue())
        self.assertEqual(json.loads((self.directory / 'unwarp3.json').read_text())['interface'], 'unwarp3')

    def test_bad_login_never_submits_and_can_resume(self):
        for wrong in (callback(exp=0), callback(warp=False), callback(iss='https://other.example'),
                      callback().replace(HOST, 'other.cloudflareaccess.com'), callback() + '&token=other'):
            self.assertEqual(self.enroll('-i', 'vpn', browser_callback=wrong), 1)
            self.assertNotIn(wrong, self.errors.getvalue())
        self.https.assert_not_called()
        self.assertEqual(self.enroll('-i', 'vpn', '--login-url', 'https://attacker.invalid/warp'), 1)
        self.assertEqual(self.enroll('-i', 'vpn', '--login-url', f'https://{HOST}/warp?session=example'), 0)
        self.assertEqual(self.connection.request.call_count, 1)
        self.entropy.assert_called_once_with(32)
        self.assertEqual(json.loads((self.directory / 'vpn.json').read_text())['public_key'], PUBLIC)

    def test_invalid_saved_key_stops_enrollment_before_sign_in(self):
        self.assertEqual(self.enroll('-i', 'vpn', browser_callback=callback(exp=0)), 1)
        path = self.directory / 'vpn.json'
        data = json.loads(path.read_text())
        data['secret_key'] = 'malformed-private-key'
        path.write_text(json.dumps(data))
        with patch('unwarp.profiles.sign_in') as sign_in:
            self.assertEqual(self.enroll('-i', 'vpn'), 1)
        sign_in.assert_not_called()
        self.https.assert_not_called()
        self.entropy.assert_called_once_with(32)
        self.assertEqual(json.loads(path.read_text()), data)
        self.assertIn('invalid WireGuard private key', self.errors.getvalue())
        self.assertNotIn(data['secret_key'], self.output.getvalue() + self.errors.getvalue())

    def test_uncertain_submissions_are_not_repeated_and_rejections_are_retryable(self):
        self.connection.getresponse.side_effect = OSError('connection lost')
        self.assertEqual(self.enroll('-i', 'vpn'), 1)
        path = self.directory / 'vpn.json'
        self.assertEqual(json.loads(path.read_text())['state'], 'submitting')
        self.assertEqual(self.enroll('-i', 'vpn'), 1)
        self.assertEqual(self.connection.request.call_count, 1)
        self.connection.getresponse.side_effect = [reply({}, 403), self.success()]
        self.assertEqual(self.enroll('-i', 'vpn', '--retry-uncertain'), 1)
        self.assertEqual(json.loads(path.read_text())['state'], 'pending')
        self.assertEqual(self.enroll('-i', 'vpn'), 0)
        self.assertEqual(self.connection.request.call_count, 3)

    def test_incompatible_registration_and_profile_fail_closed(self):
        self.connection.getresponse.return_value = reply({'result': {'id': DEVICE, 'token': DEVICE_TOKEN,
            'key': PUBLIC, 'account': {'organization': 'other'}}})
        self.assertEqual(self.enroll('-i', 'vpn'), 1)
        self.assertNotIn(DEVICE_TOKEN, (self.directory / 'vpn.json').read_text())
        self.connection.getresponse.return_value = self.success()
        self.assertEqual(self.enroll('-i', 'vpn', '--retry-uncertain'), 0)
        target = self.root / 'vpn.nmconnection'
        target.write_text('[connection]\nid=existing\nuuid=unrelated\n')
        self.connection.getresponse.return_value = reply({'result': LIVE})
        self.assertEqual(self.cli('profile', '-i', 'vpn', '-f', '-c', str(self.root)), 1)
        self.assertIn('uuid=unrelated', target.read_text())
        data = json.loads((self.directory / 'vpn.json').read_text())
        self.connection.getresponse.return_value = reply({'result': {**LIVE, 'key': 'changed-device-key'}})
        with self.assertRaisesRegex(ValueError, 'registered WireGuard public key has changed'):
            cloudflare.fetch_tunnel(data, True)
        self.connection.getresponse.return_value = reply({'result': LIVE})
        with self.assertRaisesRegex(ValueError, 'WireGuard private key'):
            cloudflare.fetch_tunnel({**data, 'secret_key': 'invalid-test-key'}, True)
        self.connection.getresponse.return_value = reply({'result': LIVE})
        self.assertEqual(cloudflare.fetch_tunnel(data, False).address6, '2001:db8::1/128')

    def test_profile_uses_issued_wireguard_peer_regardless_of_warp_protocol(self):
        self.assertEqual(self.enroll('-i', 'vpn'), 0)
        target = self.root / 'vpn.nmconnection'
        peer_key = base64.b64encode(b'P' * 32).decode('ascii')
        peer = {**LIVE['config']['peers'][0], 'public_key': peer_key}
        config = {**LIVE['config'], 'peers': [peer]}
        for protocol in ({}, {'tunnel_protocol': ''}, {'tunnel_protocol': None}, {'tunnel_protocol': 'masque'}):
            with self.subTest(protocol=protocol):
                policy = {'include': POLICY['include'], **protocol}
                self.connection.getresponse.return_value = reply({'result': {**LIVE, 'policy': policy, 'config': config}})
                self.assertEqual(self.cli('profile', '-i', 'vpn', '-c', str(self.root)), 0, self.errors.getvalue())
                profile = target.read_text()
                self.assertIn(f'[wireguard-peer.{peer_key}]', profile)
                self.assertIn('endpoint = 198.51.100.1:2408', profile)
                self.assertIn('192.0.2.0/24', profile)
                target.unlink()

    def test_profile_requires_usable_wireguard_settings_from_cloudflare(self):
        self.assertEqual(self.enroll('-i', 'vpn'), 0)
        peer = LIVE['config']['peers'][0]
        policy = {**POLICY, 'tunnel_protocol': 'masque'}
        for peers, error in (
                ([], 'WireGuard tunnel settings'),
                ([{**peer, 'public_key': base64.b64encode(b'P' * 65).decode('ascii')}], 'WireGuard peer public key'),
                ([{**peer, 'public_key': 'malformed-test-key'}], 'WireGuard peer public key'),
                ([{**peer, 'endpoint': {'v4': '198.51.100.1:0', 'ports': []}}], 'WireGuard endpoint port')):
            with self.subTest(error=error):
                device = {**LIVE, 'policy': policy, 'config': {**LIVE['config'], 'peers': peers}}
                self.connection.getresponse.return_value = reply({'result': device})
                self.errors = io.StringIO()
                self.assertEqual(self.cli('profile', '-i', 'vpn', '-c', str(self.root)), 1)
                self.assertIn(error, self.errors.getvalue())
                self.assertFalse((self.root / 'vpn.nmconnection').exists())
                for secret in (PRIVATE, DEVICE_TOKEN, 'malformed-test-key'):
                    self.assertNotIn(secret, self.errors.getvalue())

    def test_concurrent_enrollment(self):
        with profiles.enrollment_directory(self.directory):
            self.assertEqual(self.enroll(), 1)
        self.https.assert_not_called()


class BrowserLoginTest(unittest.TestCase):
    def test_desktop_child_returns_only_the_assertion_over_its_private_socket(self):
        with (tempfile.TemporaryFile(mode='w+') as terminal, tempfile.TemporaryFile(mode='w+') as output):
            terminal.write(callback() + '\n')
            terminal.seek(0)
            process = dict(env={'PATH': ''}, stdin=terminal, stdout=output, stderr=output)
            token, account = login.sign_in(TEAM, f'https://{HOST}/warp', False, browser_options=process)
            self.assertEqual(account, ACCOUNT)
            self.assertTrue(token.endswith('.signature'))
            output.seek(0)
            console = output.read()
            self.assertIn(f'https://{HOST}/warp', console)
            self.assertNotIn(token, console)
            terminal.seek(0)
            terminal.truncate()
            with self.assertRaisesRegex(ValueError, 'desktop sign-in'):
                login.sign_in(TEAM, f'https://{HOST}/warp', False, browser_options=process)

    def test_scoped_firefox_handoff_over_loopback(self):
        results = []
        worker = None
        profile = None
        server_class = login.LoginServer

        def open_start_link(team):
            server = server_class(team)
            def follow_link():
                with contextlib.closing(http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)) as conn:
                    conn.request('GET', server.start_path)
                    with conn.getresponse() as response:
                        results.append(response.status)
                        response.read()
            thread = threading.Thread(target=follow_link)
            thread.start()
            self.addCleanup(thread.join, 3)
            return server

        def browser_started(argv, **kwargs):
            nonlocal profile, worker
            profile = Path(argv[argv.index('--profile') + 1])
            settings = json.loads((profile / 'handlers.json').read_text())
            self.assertIn('defaultHandlersVersion', settings)
            handler = settings['schemes']['com.cloudflare.warp']
            self.assertTrue(handler['ask'])
            uri = urlsplit(handler['handlers'][0]['uriTemplate'])
            self.assertEqual((uri.hostname, uri.fragment), ('127.0.0.1', '%s'))
            origin = 'http://' + uri.netloc

            def request(method, path, host, source):
                with contextlib.closing(http.client.HTTPConnection(uri.hostname, uri.port, timeout=3)) as conn:
                    conn.request(method, path, body=callback() if method == 'POST' else None,
                                 headers={'Host': host, 'Origin': source})
                    with conn.getresponse() as response:
                        results.append(response.status)
                        response.read()

            def authorize():
                request('GET', uri.path, uri.netloc, origin)
                request('POST', uri.path, 'other.test', origin)
                request('POST', uri.path, uri.netloc, 'https://other.test')
                request('POST', '/wrong-session', uri.netloc, origin)
                request('POST', uri.path, uri.netloc, origin)
            worker = threading.Thread(target=authorize)
            worker.start()
            return browser

        browser = MagicMock()
        browser.__enter__.return_value = browser
        browser.poll.return_value = None
        with (patch('unwarp.cloudflare.login.LoginServer', side_effect=open_start_link),
              patch('unwarp.cloudflare.login.subprocess.Popen', side_effect=browser_started),
              patch('shutil.which', return_value='/test/firefox'), patch('os.geteuid', return_value=1000),
              patch.dict(os.environ, DISPLAY=':test'), contextlib.redirect_stdout(io.StringIO()),
              contextlib.redirect_stderr(io.StringIO())):
            token, account = login.sign_in(TEAM, f'https://{HOST}/warp', False)
        worker.join(3)
        self.assertEqual(results, [200, 200, 403, 403, 403, 200])
        self.assertTrue(token.endswith('.signature'))
        self.assertEqual(account, ACCOUNT)
        self.assertFalse(profile.exists())
        browser.terminate.assert_called_once()


if __name__ == '__main__':
    unittest.main()
