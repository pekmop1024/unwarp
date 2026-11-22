"""systemd-networkd .netdev and .network profiles."""

import grp
import re
import shlex
import subprocess
from pathlib import Path

from ..model import DNS4, DNS6
from ._export import FileBackend, allowed_networks, check_address_family, words
from ._files import Artifact
from ._ini import Section


LINKS = Path('/sys/class/net')


class NetworkdBackend(FileBackend):
    directory = Path('/etc/systemd/network')
    prefix = '50-'
    extensions = ('network', 'netdev')
    domain_file = 'network'
    routing_domains = True

    def validate_name(self, name):
        super().validate_name(name)
        if not re.fullmatch(r'[\w.+=@-]+', name):
            raise ValueError('expected a literal interface name for the networkd Name match')

    def reserved_interfaces(self, directory):
        names = super().reserved_interfaces(directory)
        for ext, section in (('netdev', 'NetDev'), ('network', 'Match')):
            for path in (directory or self.directory).glob(f'*.{ext}'):
                try:
                    if path.is_file():
                        for value in Section(path.read_text(encoding='utf-8'), section).values('Name'):
                            names.update(shlex.split(value))
                except (OSError, ValueError):
                    continue
        return names

    def render(self, name, tunnel, routes):
        device = (f'[NetDev]\nName={name}\nKind=wireguard\nMTUBytes={tunnel.mtu}\n\n'
                  f'[WireGuard]\nPrivateKey={tunnel.private_key}\nRouteTable=main\n\n'
                  f'[WireGuardPeer]\nPublicKey={tunnel.peer_public_key}\nEndpoint={tunnel.endpoint}\n'
                  f'PersistentKeepalive={tunnel.keepalive}\n')
        network = (f'[Match]\nName={name}\n\n[Network]\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nDNSDefaultRoute=no\n'
                   f'Address={tunnel.address4}\nDNS={DNS4}\n')
        if not routes.ipv4_only:
            network += f'Address={tunnel.address6}\nDNS={DNS6}\n'
        return {'network': network, 'netdev': device}

    def domains(self, text):
        return words(Section(text, 'Network').values('Domains', reset_empty=True))

    def set_policy(self, files, policy, options, domains):
        network = Section(files['network'], 'Network')
        check_address_family(network.values('Address', reset_empty=True), options)
        peer = Section(files['netdev'], 'WireGuardPeer')
        networks = allowed_networks(policy, options, words(peer.values('AllowedIPs', reset_empty=True)))
        return {'network': network.set('Domains', ' '.join(domains)),
                'netdev': peer.set('AllowedIPs', ','.join(networks))}

    def artifact(self, ext, text, directory):
        if ext == 'network':
            return Artifact(text.encode('utf-8'), 0o644)
        if directory.resolve() == self.directory:
            try:
                group = grp.getgrnam('systemd-network').gr_gid
            except KeyError:
                raise ValueError('could not find the systemd-network group for the .netdev private key') from None
            return Artifact(text.encode('utf-8'), 0o640, group)
        return Artifact(text.encode('utf-8'))

    def check_output(self, output, directory):
        if output.reload and directory.resolve() != self.directory:
            raise ValueError('--reload requires deployment to /etc/systemd/network')

    def reload(self, interface):
        self._networkctl('reload')
        # AllowedIPs can change in the .netdev while the matching .network stays identical.
        if (LINKS / interface).exists():
            self._networkctl('reconfigure', '--', interface)

    @staticmethod
    def _networkctl(*args):
        try:
            result = subprocess.run(['networkctl', *args], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f'profile saved, but networkctl {args[0]} failed: {exc}') from exc
        if result.returncode:
            raise ValueError(f'profile saved, but networkctl {args[0]} failed: {result.stderr.strip()}')


backend = NetworkdBackend()
