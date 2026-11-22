"""WireGuard and routing data shared by sources and configuration backends."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Union


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
DNS4 = '1.1.1.1'
DNS6 = '2606:4700:4700::1111'
DEFAULT_MTU = 1280


def interface_name(value):
    if (not value or len(os.fsencode(value)) > 15 or value in ('.', '..')
            or any(char.isspace() or char in '/:\0' for char in value)):
        raise ValueError('invalid Linux interface name (maximum 15 bytes, no whitespace, slash or colon)')
    return value


def connection_name(value):
    if not isinstance(value, str) or not value or '\0' in value:
        raise ValueError('the profile name must be a nonempty UTF-8 string')
    value.encode('utf-8')
    return value


def dns_suffix(host):
    """Translate an exact host or one leading wildcard label to a DNS suffix."""
    name = host.strip()
    if name.startswith('*.'):
        name = name[2:]
    if name.endswith('.'):
        name = name[:-1]
    try:
        name = name.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('invalid DNS name') from None
    if len(name) > 253 or not all(re.fullmatch(r'[a-z0-9_-]{1,63}', label) for label in name.split('.')):
        raise ValueError('expected a DNS name or *.domain')
    return name


def policy_search_domains(hosts):
    return sorted({dns_suffix(host) for host in hosts})


@dataclass(frozen=True)
class RoutePolicy:
    mode: str
    networks: tuple[Network, ...] = ()
    always_include: tuple[Network, ...] = ()
    always_exclude: tuple[Network, ...] = ()
    domains: tuple[str, ...] = ()

    def included_routes(self, version):
        """Compute static Include routes, including the DNS route and mandatory bypasses."""
        if self.mode != 'include':
            raise ValueError('static routes require an Include-mode policy')
        routes = {net for net in self.networks + self.always_include if net.version == version}
        if version == 4:
            routes.add(ipaddress.ip_network(DNS4 + '/32'))
        for excluded in self.always_exclude:
            if excluded.version != version:
                continue
            remaining = set()
            for route in routes:
                if not route.overlaps(excluded):
                    remaining.add(route)
                elif excluded.subnet_of(route):
                    remaining.update(route.address_exclude(excluded))
            routes = remaining
        return sorted(routes)

    def preview(self, ipv4_only):
        result = {'mode': self.mode, 'domains': list(self.domains), 'dns_search': None}
        if self.mode == 'include':
            try:
                result['dns_search'] = policy_search_domains(self.domains)
            except ValueError:
                pass  # Keep unrepresentable rules visible in the original domain list.
        for key, routes in ((self.mode, self.networks), ('always_include', self.always_include),
                            ('always_exclude', self.always_exclude)):
            result[key] = [str(net) for net in routes if not ipv4_only or net.version == 4]
        return result


@dataclass(frozen=True)
class WireGuardTunnel:
    private_key: str = field(repr=False)
    peer_public_key: str
    endpoint: str
    address4: str  # Interface address with prefix length.
    address6: str | None
    policy: RoutePolicy | None  # Older cached configurations may omit the policy.
    mtu: int = DEFAULT_MTU
    keepalive: int = 25


@dataclass(frozen=True)
class ProfileTarget:
    interface: str
    name: str
    uuid: str | None = None

    def __post_init__(self):
        interface_name(self.interface)
        connection_name(self.name)


@dataclass(frozen=True)
class RouteOptions:
    ipv4_only: bool = True
    extra_domains: tuple[str, ...] = ()
    sync_domains: bool = False
    directory: Path | None = None  # Destination for a file-backed routes --apply.
    reload: bool = False


@dataclass(frozen=True)
class WriteOptions:
    directory: Path | None = None
    overwrite: bool = False
    reload: bool = False
    dry_run: bool = False
    qr: str | None = None
