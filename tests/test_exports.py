import contextlib
import importlib.util
import io
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.fixtures import DEVICE_TOKEN, LIVE, PRIVATE, PUBLIC
from unwarp.backends import get_backend
from unwarp.backends._ini import Section
from unwarp.cli import main


HAS_SEGNO = importlib.util.find_spec('segno') is not None
POLICY = {
    'include': [{'address': '10.0.2.0/25'}, {'address': '10.0.2.128/25'},
                {'address': '10.0.3.0/24'}, {'address': '2001:db8:42::/48'}, {'host': '*.Corp.example'}],
    'always_include': [{'ip': '192.0.2.7/32'}],
    'always_exclude': [{'ip': '10.0.3.128/25'}],
}


class FileExportsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.config = self.root / 'config'
        self.config.mkdir()
        self.record = {'interface': 'office', 'connection_name': 'Office / VPN', 'state': 'registered',
                       'connection_uuid': '12345678-1234-4234-8234-123456789abc',
                       'secret_key': PRIVATE, 'public_key': PUBLIC, 'api_token': DEVICE_TOKEN}
        self.registration = self.config / 'office.json'
        self.registration.write_text(json.dumps(self.record))
        self.cache = self.root / 'conf.json'
        self.cache.write_text(json.dumps({'public_key': PUBLIC, 'endpoints': [{'v4': '198.51.100.1:2408'}],
                                         'interface': {'v4': '192.0.2.1', 'v6': '2001:db8::1'}, 'policy': POLICY}))
        mock = patch('unwarp.cloudflare.client.fetch_device', return_value={**LIVE, 'policy': POLICY})
        self.device = mock.start()
        self.addCleanup(mock.stop)

    def cli(self, *args):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return main(['--config-dir', str(self.config), *args])

    def generate(self, backend, *args):
        return self.cli('profile', '-i', 'office', '--backend', backend, '-c', str(self.root), *args)

    def refresh(self, backend, *args):
        return self.cli('routes', '--backend', backend, '-i', 'office', '--apply', '-c', str(self.root), *args)

    def test_wireguard_profile_from_both_sources_and_wg_quick(self):
        cached = ['-i', 'office', '-n', 'Office / VPN', '-z', str(self.cache), '-w', str(self.registration),
                  '-c', str(self.root), '--backend', 'wireguard']
        self.assertEqual(self.cli(*cached), 0, self.stderr.getvalue())
        self.device.assert_not_called()
        path = self.root / 'office.conf'
        text = path.read_text()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Section(text, 'Interface').values('MTU'), ['1280'])
        self.assertNotIn('2001:db8:', text)
        self.assertNotIn(DEVICE_TOKEN, text)
        self.assertEqual(Section(text, 'Peer').values('AllowedIPs'),
                         ['1.1.1.1/32,10.0.2.0/24,10.0.3.0/25,192.0.2.7/32'])
        self.assertEqual(self.generate('wireguard', '-f', '--dual-stack', '--mtu', '1380'), 0, self.stderr.getvalue())
        text = path.read_text()
        self.assertEqual(Section(text, 'Interface').values('PrivateKey'), [PRIVATE])
        self.assertEqual(Section(text, 'Interface').values('Address'), ['192.0.2.1/32, 2001:db8::1/128'])
        self.assertEqual(Section(text, 'Interface').values('MTU'), ['1380'])
        self.assertIn('corp.example', Section(text, 'Interface').values('DNS')[0])
        self.assertIn('2001:db8:42::/48', text)
        # Linux wg-quick invokes sudo even for its read-only strip command.
        if os.geteuid() == 0 and shutil.which('wg-quick'):
            stripped = subprocess.run(['wg-quick', 'strip', str(path)], capture_output=True, text=True, check=True)
            self.assertIn('AllowedIPs=', stripped.stdout)
            self.assertNotIn('Address=', stripped.stdout)

    def test_networkd_pair_routing_table_permissions_and_name_reservation(self):
        self.assertEqual(self.generate('systemd-networkd', '--dual-stack', '-s', '~internal.example', '--mtu', '1432'),
                         0, self.stderr.getvalue())
        dev = self.root / '50-office.netdev'
        net = self.root / '50-office.network'
        self.assertEqual(dev.stat().st_mode & 0o777, 0o600)
        self.assertEqual(net.stat().st_mode & 0o777, 0o644)
        device, network = dev.read_text(), net.read_text()
        self.assertEqual(Section(device, 'NetDev').values('MTUBytes'), ['1432'])
        self.assertEqual(Section(device, 'WireGuard').values('PrivateKey'), [PRIVATE])
        self.assertEqual(Section(device, 'WireGuard').values('RouteTable'), ['main'])
        self.assertEqual(Section(device, 'WireGuardPeer').values('AllowedIPs'),
                         ['1.1.1.1/32,10.0.2.0/24,10.0.3.0/25,192.0.2.7/32,2001:db8:42::/48'])
        self.assertEqual(Section(network, 'Match').values('Name'), ['office'])
        self.assertEqual(Section(network, 'Network').values('Address'), ['192.0.2.1/32', '2001:db8::1/128'])
        self.assertEqual(Section(network, 'Network').values('Domains'), ['~internal.example corp.example'])
        self.assertNotIn(PRIVATE, network)
        (self.root / '05-existing.netdev').write_text('[NetDev]\nName=unwarp0\nKind=wireguard\n')
        self.assertTrue({'office', 'unwarp0'} <= get_backend('systemd-networkd').reserved_interfaces(self.root))
        with patch('unwarp.backends.networkd.subprocess.run') as run:
            self.assertEqual(self.generate('systemd-networkd', '--reload'), 1)
            run.assert_not_called()

    def test_native_wireguard_file_import(self):
        try:
            import gi
            gi.require_version('NM', '1.0')
            from gi.repository import NM
        except (ImportError, ValueError):
            self.skipTest('libnm WireGuard importer is unavailable')
        self.assertEqual(self.generate('wireguard', '--dual-stack', '--mtu', '1380'), 0)
        connection = NM.conn_wireguard_import(str(self.root / 'office.conf'))
        self.assertTrue(connection.verify())
        wireguard = connection.get_setting(NM.SettingWireGuard)
        self.assertEqual(wireguard.get_mtu(), 1380)
        self.assertEqual(wireguard.get_peers_len(), 1)
        peer = wireguard.get_peer(0)
        networks = {peer.get_allowed_ip(i) for i in range(peer.get_allowed_ips_len())}
        self.assertEqual(networks, {'1.1.1.1/32', '10.0.2.0/24', '10.0.3.0/25', '192.0.2.7/32', '2001:db8:42::/48'})
        self.assertEqual(connection.get_setting_ip4_config().get_dns_search(0), 'corp.example')

    def test_networkd_deploy_and_retry_reload(self):
        backend = get_backend('systemd-networkd')
        (self.root / 'office').touch()
        with (patch.object(backend, 'directory', self.root),
              patch('unwarp.backends.networkd.LINKS', self.root),
              patch('unwarp.backends.networkd.grp.getgrnam', return_value=SimpleNamespace(gr_gid=os.getgid())),
              patch('unwarp.backends.networkd.subprocess.run') as run):
            run.return_value = subprocess.CompletedProcess([], 1, stderr='service unavailable')
            self.assertEqual(self.generate('systemd-networkd', '--reload'), 1)
            self.assertIn('profile saved', self.stderr.getvalue())
            dev = self.root / '50-office.netdev'
            self.assertEqual(dev.stat().st_mode & 0o777, 0o640)
            dev.chmod(0o600)
            run.return_value = subprocess.CompletedProcess([], 0, stderr='')
            self.assertEqual(self.refresh('systemd-networkd', '--reload'), 0)
            self.assertEqual(dev.stat().st_mode & 0o777, 0o640)
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                ['networkctl', 'reload'], ['networkctl', 'reload'], ['networkctl', 'reconfigure', '--', 'office']])

    def test_existing_profile_identity_and_single_peer_are_checked_before_writing(self):
        self.assertEqual(self.generate('wireguard'), 0)
        path = self.root / 'office.conf'
        before = path.read_bytes()
        self.registration.write_text(json.dumps({**self.record, 'connection_uuid': '00000000-0000-4000-8000-000000000001'}))
        self.assertEqual(self.generate('wireguard', '-f'), 1)
        self.assertEqual(before, path.read_bytes())
        self.registration.write_text(json.dumps(self.record))
        self.assertEqual(self.generate('wireguard', '--mtu', '575', '-f'), 1)
        self.assertEqual(before, path.read_bytes())
        with path.open('a') as stream:
            stream.write('\n[peer]\nPublicKey=' + PUBLIC + '\nAllowedIPs=0.0.0.0/0\n')
        two_peers = path.read_bytes()
        self.assertEqual(self.refresh('wireguard'), 1)
        self.assertEqual(two_peers, path.read_bytes())

    def test_scheduled_updates_preserve_peer_mtu_unselected_family_and_local_domains(self):
        for backend, peer_file, link_file, peer_section in (
            ('wireguard', 'office.conf', 'office.conf', 'Peer'),
            ('systemd-networkd', '50-office.netdev', '50-office.network', 'WireGuardPeer'),
        ):
            with self.subTest(backend=backend):
                self.device.return_value = {**LIVE, 'policy': POLICY}
                self.registration.write_text(json.dumps({**self.record, 'backend': backend}))
                self.assertEqual(self.cli('profile', '-i', 'office', '-c', str(self.root), '--dual-stack',
                                          '--mtu', '1360', '-s', 'manual.test'), 0, self.stderr.getvalue())
                self.device.return_value = {'policy': {'include': [{'address': '10.20.0.0/16'}, {'host': '*.new.test'}]}}
                self.assertEqual(self.refresh(backend), 0, self.stderr.getvalue())
                peer = (self.root / peer_file).read_text()
                networks = Section(peer, peer_section).values('AllowedIPs')[0].split(',')
                self.assertEqual(networks, ['1.1.1.1/32', '10.20.0.0/16', '2001:db8:42::/48'])
                self.assertIn(PRIVATE, peer)
                self.assertIn('1360', peer)
                self.assertIn('manual.test', (self.root / link_file).read_text())
                self.assertEqual(self.refresh(backend, '--sync-domains'), 0, self.stderr.getvalue())
                self.assertIn('Removed', self.stderr.getvalue())
                self.assertIn('manual.test', self.stderr.getvalue())
                self.assertNotIn('manual.test', (self.root / link_file).read_text())
                before = (self.root / peer_file).stat().st_mtime_ns
                self.assertEqual(self.refresh(backend), 0)
                self.assertEqual(before, (self.root / peer_file).stat().st_mtime_ns)

    def test_failed_or_dry_run_updates_preserve_files(self):
        for backend, names in (('wireguard', ('office.conf',)),
                               ('systemd-networkd', ('50-office.network', '50-office.netdev'))):
            with self.subTest(backend=backend):
                self.device.return_value = {**LIVE, 'policy': POLICY}
                self.assertEqual(self.generate(backend, '-D'), 0, self.stderr.getvalue())
                self.assertFalse(any((self.root / n).exists() for n in names))
                self.assertEqual(self.generate(backend), 0, self.stderr.getvalue())
                before = [(self.root / n).read_bytes() for n in names]
                self.device.return_value = {'policy': {'exclude': []}}
                self.assertEqual(self.refresh(backend), 1)
                self.assertEqual(before, [(self.root / n).read_bytes() for n in names])
                self.assertNotIn(PRIVATE, self.stderr.getvalue())
        self.device.return_value = {**LIVE, 'policy': POLICY}
        self.assertEqual(self.generate('wireguard', '-f', '-s', '~internal.test'), 1)
        self.assertIn('routing-only', self.stderr.getvalue())
        self.assertEqual(self.generate('wireguard', '-f', '-s', '203.0.113.9'), 1)
        self.assertIn('resolver', self.stderr.getvalue())
        self.assertEqual(self.generate('systemd-networkd', '--qr'), 1)
        self.assertFalse((self.root / 'office.conf.png').exists())

    def test_networkd_restores_pair_if_second_replace_fails(self):
        self.assertEqual(self.generate('systemd-networkd'), 0)
        paths = [self.root / '50-office.network', self.root / '50-office.netdev']
        before = [p.read_bytes() for p in paths]
        real_replace = os.replace

        def fail_netdev(new, destination):
            if destination == paths[1]:
                raise OSError('simulated second-file failure')
            return real_replace(new, destination)

        self.device.return_value = {'policy': {'include': [{'host': 'new.test'}]}}
        with patch('unwarp.backends._files.os.replace', side_effect=fail_netdev):
            self.assertEqual(self.refresh('systemd-networkd', '--sync-domains'), 1)
        self.assertEqual(before, [p.read_bytes() for p in paths])
        self.assertEqual(self.refresh('systemd-networkd', '--sync-domains'), 0)

    def test_qr_is_optional_and_missing_extra_preserves_the_config(self):
        with patch.dict(sys.modules, {'segno': None}):
            self.assertEqual(self.generate('wireguard'), 0, self.stderr.getvalue())
            before = (self.root / 'office.conf').read_bytes()
            self.assertEqual(self.generate('wireguard', '--qr', 'png'), 1)
            self.assertIn('.[qr]', self.stderr.getvalue())
            self.assertEqual((self.root / 'office.conf').read_bytes(), before)
            self.assertEqual(self.generate('wireguard', '--qr', '-D'), 0)
            self.assertFalse((self.root / 'office.conf.png').exists())

    @unittest.skipUnless(HAS_SEGNO, 'install the qr extra for the QR round trip')
    def test_qr_encodes_saved_bytes_and_oversize_profile_keeps_every_route(self):
        self.assertEqual(self.generate('wireguard', '--qr', 'png'), 0, self.stderr.getvalue())
        png, conf = self.root / 'office.conf.png', self.root / 'office.conf'
        self.assertTrue(png.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(png.stat().st_mode & 0o777, 0o600)
        before = conf.read_bytes()
        self.device.return_value = {**LIVE, 'policy': {'include': []}}
        self.assertEqual(self.generate('wireguard', '--qr'), 0)
        self.assertTrue(self.stdout.getvalue().strip())
        self.assertEqual(conf.read_bytes(), before)
        if shutil.which('ZXingReader'):
            decoded = subprocess.check_output(['ZXingReader', '-bytes', str(png)])
            self.assertTrue(decoded == before, 'decoded QR differs from the saved WireGuard file')
        start = int(ipaddress.IPv4Address('10.0.0.1'))
        expected = {f'{ipaddress.IPv4Address(start + 256 * i)}/32' for i in range(450)}
        self.device.return_value = {**LIVE, 'policy': {'include': [{'address': item} for item in expected]}}
        self.assertEqual(self.generate('wireguard', '--qr', 'png', '-f'), 0, self.stderr.getvalue())
        self.assertIn('too large for one QR', self.stderr.getvalue())
        self.assertIn('office.conf', self.stderr.getvalue())
        self.assertFalse(png.exists())
        self.assertEqual(set(Section(conf.read_text(), 'Peer').values('AllowedIPs')[0].split(',')),
                         expected | {'1.1.1.1/32'})
        start = int(ipaddress.IPv4Address('10.40.0.0'))
        neighbors = [{'address': str(ipaddress.IPv4Address(start + i))} for i in range(512)]
        self.device.return_value = {**LIVE, 'policy': {'include': neighbors}}
        self.assertEqual(self.generate('wireguard', '--qr', 'png', '-f'), 0, self.stderr.getvalue())
        self.assertEqual(Section(conf.read_text(), 'Peer').values('AllowedIPs'), ['1.1.1.1/32,10.40.0.0/23'])
        self.assertTrue(png.is_file())


if __name__ == '__main__':
    unittest.main()
