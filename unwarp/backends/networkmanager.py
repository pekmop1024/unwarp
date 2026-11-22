"""NetworkManager keyfile output and live route updates."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from configparser import ConfigParser, Error as ConfigError
from pathlib import Path

from ..domains import plan_dns_domains, reconcile_domains, report_domains
from ..model import (DNS4, DNS6, ProfileTarget, RouteOptions, RoutePolicy, WireGuardTunnel,
                     WriteOptions, policy_search_domains)


LOG = logging.getLogger(__name__)
DEFAULT_DIRECTORY = Path('/etc/NetworkManager/system-connections')


def nmcli(*arguments):
    result = subprocess.run(['nmcli', '--wait', '15', '--escape', 'no', *arguments],
                            capture_output=True, text=True, timeout=20,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError(result.stderr.strip() or f'nmcli exited with status {result.returncode}')
    return result.stdout.splitlines()


def _keyfile_interface_name(path: Path) -> str:
    # GLib keys are case-sensitive and its groups do not inherit a DEFAULT section.
    keyfile = ConfigParser(interpolation=None, delimiters=('=',), strict=False, default_section='')
    keyfile.optionxform = str
    with path.open(encoding='utf-8') as source:
        keyfile.read_file(source)
    interface = keyfile.get('connection', 'interface-name', fallback='')
    # Backslash is the only keyfile-escaped character allowed in a Linux interface name.
    return interface.replace('\\\\', '\\')


def reserved_interfaces(directory: Path | None) -> set[str]:
    names = set()
    try:
        uuids = nmcli('--get-values', 'UUID', 'connection', 'show')
        if uuids:
            selectors = [arg for value in uuids for arg in ('uuid', value)]
            names.update(nmcli('--get-values', 'connection.interface-name', 'connection', 'show', *selectors))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass  # The daemon may be offline during enrollment or a cached import.
    try:
        for path in (directory or DEFAULT_DIRECTORY).glob('*.nmconnection'):
            names.add(path.stem)
            try:
                if not path.is_file():
                    continue
                interface = _keyfile_interface_name(path)
            except (OSError, ConfigError, UnicodeError):
                continue  # Keep the filename reserved even when its settings cannot be read.
            if interface:
                names.add(interface)
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        pass
    return names


def apply_routes(target: ProfileTarget | str, policy: RoutePolicy, routes: RouteOptions) -> None:
    if routes.directory is not None or routes.reload:
        raise ValueError('NetworkManager applies routes directly to a loaded profile; omit --output-dir and --reload')
    if policy.mode != 'include':
        raise ValueError('applying static routes requires an Include-mode policy')
    search_domains = [*routes.extra_domains, *policy_search_domains(policy.domains)]
    profile = (target.uuid or target.name) if isinstance(target, ProfileTarget) else target
    uuid_pattern = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    selector = 'uuid' if re.fullmatch(uuid_pattern, profile, re.IGNORECASE) else 'id'
    fields = ('connection.uuid,connection.type,wireguard.peer-routes,'
              'ipv4.method,ipv4.routes,ipv4.dns-search,ipv6.method,ipv6.routes,ipv6.dns-search')
    properties = nmcli('--get-values', fields, 'connection', 'show', selector, profile)
    if len(properties) != 9:
        raise ValueError('expected one NetworkManager connection; use its UUID if the name is ambiguous')
    profile_uuid, kind, peer_routes, method4, current4, dns4, method6, current6, dns6 = properties
    if kind != 'wireguard' or peer_routes != 'no':
        raise ValueError('the target must be a WireGuard profile with wireguard.peer-routes disabled')
    if method4 in ('disabled', 'ignore') and (routes.ipv4_only or method6 in ('disabled', 'ignore')):
        raise ValueError('the selected profile has no enabled address family to update')
    changes = []
    domain_reports = []
    for version, method, current, dns in ((4, method4, current4, dns4), (6, method6, current6, dns6)):
        if method in ('disabled', 'ignore') or (version == 6 and routes.ipv4_only):
            continue
        desired_routes = list(map(str, policy.included_routes(version)))
        installed = {route.strip() for route in current.split(',') if route.strip()}
        if installed != set(desired_routes):
            changes.extend([f'ipv{version}.routes', ','.join(desired_routes)])
        installed_domains = [domain.strip() for domain in dns.split(',') if domain.strip()]
        wanted, outside, rewrites = plan_dns_domains(installed_domains, search_domains, routes.sync_domains)
        if (routes.sync_domains or rewrites) and installed_domains != wanted:
            # A legacy wildcard is replaced in place, preserving DNS search order.
            changes.extend([f'ipv{version}.dns-search', ','.join(wanted)])
        elif not routes.sync_domains:
            installed_names = set(installed_domains)
            additions = [domain for domain in wanted if domain not in installed_names]
            if additions:
                changes.extend([f'+ipv{version}.dns-search', ','.join(additions)])
        domain_reports.append((f'ipv{version}', outside, rewrites))
    if changes:
        nmcli('connection', 'modify', 'uuid', profile_uuid, *changes)
    for family, outside, rewrites in domain_reports:
        report_domains(f'{family}.dns-search', outside, routes.sync_domains, rewrites=rewrites)
    # Check even on identical snapshots so a failed live reapply can be retried.
    try:
        active = nmcli('--terse', '--fields', 'UUID,DEVICE', 'connection', 'show', '--active')
        for row in active:
            active_uuid, _, interface = row.partition(':')
            if active_uuid == profile_uuid and interface:
                nmcli('device', 'reapply', interface)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f'profile routes are saved, but live update failed ({exc})') from exc


def keyfile_string(value):
    """Escape a scalar according to GLib's key file format."""
    escaped = value.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    start = len(escaped) - len(escaped.lstrip(' '))
    tail = escaped[start:]
    return '\\s' * start + tail.rstrip(' ') + '\\s' * (len(tail) - len(tail.rstrip(' ')))


def render_profile(target: ProfileTarget, tunnel: WireGuardTunnel, routes: RouteOptions) -> ConfigParser:
    policy = tunnel.policy
    if policy is None:
        if routes.sync_domains:
            raise ValueError('--sync-domains requires a split-tunnel policy')
        policy = RoutePolicy('include')
    if policy.mode != 'include':
        raise ValueError('generating static routes requires an Include-mode policy')
    if not routes.ipv4_only and tunnel.address6 is None:
        raise ValueError('dual-stack output requires an IPv6 tunnel address')
    wanted = [*routes.extra_domains, *policy_search_domains(policy.domains)]
    search_domains, _ = reconcile_domains([], wanted, False)
    search = {'dns-search': ';'.join(search_domains) + ';'} if search_domains else {}
    ipv4 = {'address1': tunnel.address4, 'dns': DNS4, 'method': 'manual', **search}
    if routes.ipv4_only:
        ipv6 = {'addr-gen-mode': 'stable-privacy', 'method': 'disabled'}
    else:
        ipv6 = {'addr-gen-mode': 'eui64', 'address1': tunnel.address6, 'dns': DNS6, **search, 'method': 'manual'}
    nmconfig = ConfigParser(interpolation=None)
    nmconfig.read_dict({
        'connection': {'id': keyfile_string(target.name), 'type': 'wireguard', 'autoconnect': 'false',
                       'interface-name': keyfile_string(target.interface)},
        'wireguard': {'mtu': str(tunnel.mtu), 'peer-routes': 'false', 'private-key': tunnel.private_key},
        f'wireguard-peer.{tunnel.peer_public_key}': {
            'endpoint': tunnel.endpoint, 'persistent-keepalive': str(tunnel.keepalive),
            'allowed-ips': '0.0.0.0/0' if routes.ipv4_only else '0.0.0.0/0;::/0;'},
        'ipv6': ipv6, 'ipv4': ipv4, 'proxy': {},
    })
    if target.uuid is not None:
        nmconfig['connection']['uuid'] = target.uuid
    LOG.info('%s ipv6 in networkmanager wireguard connection configuration', 'disabling' if routes.ipv4_only else 'enabling')
    for version in ((4,) if routes.ipv4_only else (4, 6)):
        if search_domains:
            LOG.info('adding following domains search in ipv%d section: %s', version, ' '.join(search_domains))
        for number, network in enumerate(policy.included_routes(version), start=1):
            nmconfig[f'ipv{version}'][f'route{number}'] = str(network)
    return nmconfig


def reconcile_keyfile_domains(nmconfig, filename, sync_domains):
    previous = ConfigParser(interpolation=None, delimiters=('=',), strict=False)
    try:
        with open(filename, encoding='utf-8') as source:
            previous.read_file(source)
    except (ConfigError, UnicodeError):
        raise ValueError('could not read DNS search domains from the existing NetworkManager profile') from None
    reports = []
    for family in ('ipv4', 'ipv6'):
        current = previous.get(family, 'dns-search', fallback='').split(';')
        current = [item.strip() for item in current if item.strip()]
        if not current:
            continue
        if nmconfig[family]['method'] == 'disabled' and not sync_domains:
            raise ValueError(f'regenerating this profile would disable {family} and drop {family}.dns-search '
                             f'({", ".join(current)}). Use --dual-stack to keep it or --sync-domains to remove it')
        desired = nmconfig[family].get('dns-search', '').split(';')
        wanted, outside, rewrites = plan_dns_domains(current, [item for item in desired if item], sync_domains)
        if wanted:
            nmconfig[family]['dns-search'] = ';'.join(wanted) + ';'
        reports.append((family, outside, rewrites))
    return reports


def deploy_nm_config(nmconfig, file_stem, nmpath, overwrite, nmreload, dry_run, sync_domains=False):
    config_file = os.path.join(nmpath, f'{file_stem}.nmconnection')
    exists = os.path.isfile(config_file)
    if exists and nmconfig.has_option('connection', 'uuid'):
        previous = ConfigParser(interpolation=None, delimiters=('=',), strict=False)
        with open(config_file, encoding='utf-8') as file:
            previous.read_file(file)
        if previous.get('connection', 'uuid', fallback=None) != nmconfig['connection']['uuid']:
            raise ValueError(f'a different NetworkManager profile already uses {config_file}')
    if exists and not overwrite:
        LOG.info('file exists, skipping write: %s', config_file)
        if nmreload and not dry_run:
            nmcli('connection', 'reload')
        return
    reports = reconcile_keyfile_domains(nmconfig, config_file, sync_domains) if exists else []
    if dry_run:
        LOG.info('would write file: %s', config_file)
    else:
        output = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=nmpath, prefix='.unwarp-', delete=False)
        try:
            with output:
                nmconfig.write(output)
                os.fchmod(output.fileno(), 0o600)
            if overwrite:
                os.replace(output.name, config_file)
            else:
                os.link(output.name, config_file)
        finally:
            try:
                os.unlink(output.name)
            except FileNotFoundError:
                pass
        LOG.info('saved profile with permissions 600: %s', config_file)
    for family, outside, rewrites in reports:
        report_domains(f'{family}.dns-search', outside, sync_domains, dry_run, rewrites)
    if nmreload and not dry_run:
        LOG.info('reloading networkmanager configuration')
        nmcli('connection', 'reload')


def write_profile(target: ProfileTarget, tunnel: WireGuardTunnel, routes: RouteOptions, output: WriteOptions) -> None:
    profile = render_profile(target, tunnel, routes)
    if target.uuid is not None:
        # NetworkManager ignores dotfiles. Escape the marker as well to keep stems unique.
        stem = '=' + target.interface if target.interface.startswith(('.', '=')) else target.interface
    else:
        # Cached imports historically use their display name when it is a usable filename.
        name = target.name
        safe_filename = (os.path.basename(name) == name and not name.startswith('.')
                         and not any(ord(char) < 32 for char in name)
                         and len(os.fsencode(name + '.nmconnection')) <= 255)
        stem = name if safe_filename else target.interface
    try:
        deploy_nm_config(profile, stem, output.directory or DEFAULT_DIRECTORY, output.overwrite,
                         output.reload, output.dry_run, routes.sync_domains)
    except ConfigError:
        raise ValueError('could not read the existing NetworkManager keyfile') from None
