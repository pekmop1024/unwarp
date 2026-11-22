"""Portable wg-quick profiles for the official desktop and mobile clients."""

import ipaddress
import re
from pathlib import Path

from ..model import DNS4, DNS6
from ._export import FileBackend, allowed_networks, check_address_family, words
from ._ini import Section


def is_dns_server(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def dns_settings(interface):
    servers, domains = [], []
    for value in words(interface.values('DNS')):
        if is_dns_server(value):
            servers.append(value)
        else:
            domains.append(value)
    return servers, domains


class WireGuardBackend(FileBackend):
    directory = Path('.')
    extensions = ('conf',)
    domain_file = 'conf'
    supports_qr = True

    def validate_name(self, name):
        super().validate_name(name)
        if not re.fullmatch(r'[a-zA-Z0-9_=+.-]{1,15}', name):
            raise ValueError('wg-quick interface filenames accept only ASCII letters, digits and _=+.-')
        if (name.startswith('.') or name.endswith('.') or
                re.fullmatch(r'CON|PRN|AUX|NUL|(?:COM|LPT)[1-9]', name.partition('.')[0], re.I)):
            raise ValueError('choose a portable tunnel name accepted by the Windows WireGuard client')

    def render(self, name, tunnel, routes):
        if tunnel.mtu < 576:
            raise ValueError('the portable WireGuard profile requires an MTU of at least 576 bytes')
        addresses = [tunnel.address4] if routes.ipv4_only else [tunnel.address4, tunnel.address6]
        servers = [DNS4] if routes.ipv4_only else [DNS4, DNS6]
        text = (f'[Interface]\nPrivateKey={tunnel.private_key}\nAddress={", ".join(addresses)}\n'
                f'MTU={tunnel.mtu}\nDNS={", ".join(servers)}\n\n'
                f'[Peer]\nPublicKey={tunnel.peer_public_key}\nEndpoint={tunnel.endpoint}\n'
                f'PersistentKeepalive={tunnel.keepalive}\n')
        return {'conf': text}

    def domains(self, text):
        return dns_settings(Section(text, 'Interface', case_sensitive=False))[1]

    def set_policy(self, files, policy, options, domains):
        text = files['conf']
        interface = Section(text, 'Interface', case_sensitive=False)
        check_address_family(words(interface.values('Address')), options)
        if any(is_dns_server(d) for d in domains):
            raise ValueError('an IP literal in the portable DNS field selects a resolver; expected a search domain')
        servers, _ = dns_settings(interface)
        peer = Section(interface.set('DNS', ', '.join([*servers, *domains])), 'Peer', case_sensitive=False)
        networks = allowed_networks(policy, options, words(peer.values('AllowedIPs')))
        return {'conf': peer.set('AllowedIPs', ','.join(networks))}

    def sidecars(self, paths):
        return (paths['conf'].with_suffix('.conf.png'),)

    def finish_export(self, paths, files, output):
        if output.qr:
            from ..qr import export_qr

            export_qr(files['conf'].encode('utf-8'), paths['conf'], output.qr, output.overwrite)


backend = WireGuardBackend()
