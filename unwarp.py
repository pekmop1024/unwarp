#!/usr/bin/env python

'''
parse cloudflare warp configuration and create .nmconnection basing on it
'''

import os
import re
import sys
import json
import logging
import argparse
import fcntl
import http.client
import ipaddress
import subprocess
import uuid
from contextlib import closing
from subprocess import Popen, PIPE
from configparser import ConfigParser

LOG = logging.getLogger(__name__)
REGISTRATION_FILE = '/var/lib/cloudflare-warp/reg.json'


def add_address_family_options(parser):
    family = parser.add_mutually_exclusive_group()
    family.add_argument('-4', '--ipv4only', action='store_true', default=True,
                        help='use only IPv4 routes (default)')
    family.add_argument('--dual-stack', dest='ipv4only', action='store_false',
                        help='use both IPv4 and IPv6 routes')


def parse_args(argv=None):
    '''
    parse all the command line arguments
    '''
    help_desc = 'get and set routes from cloudflare warp for usage with vanilla wireguard'
    arguments = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
                                        description=help_desc,
                                        epilog='Fetch live routes with: unwarp.py routes --help')
    arguments.add_argument('-d',
                           '--debug',
                           action='store_true',
                           help='enable debug output')
    arguments.add_argument('-D',
                           '--dry-run',
                           action='store_true',
                           help='dry run')
    arguments.add_argument('-z',
                           '--warpconfig',
                           help='path to warp configuration file',
                           default='/var/lib/cloudflare-warp/conf.json')
    arguments.add_argument('-w',
                           '--wgconfig',
                           help='path to warp registration file (default location needs root for reading)',
                           default=REGISTRATION_FILE)
    arguments.add_argument('-i',
                           '--interface',
                           help='wireguard interface name',
                           required=True)
    arguments.add_argument('-n',
                           '--nmconnectionname',
                           help='networkmanager connection name',
                           required=True)
    arguments.add_argument('-s',
                           '--domainsearch',
                           help='domains search for connection (space-separated list of domain names)',
                           default=None)
    arguments.add_argument('-c',
                           '--nmconnectionpath',
                           help='networkmanager connections path (default location needs root for writing)',
                           default='/etc/NetworkManager/system-connections')
    add_address_family_options(arguments)
    arguments.add_argument('-f',
                           '--overwrite',
                           action='store_true',
                           help='overwrite networkmanager connection configuration file')
    arguments.add_argument('-r',
                           '--nmreload',
                           action='store_true',
                           help='reload networkmanager configuration')

    args, _ = arguments.parse_known_args(argv)
    return args


def split_registration_id(value):
    """Return the wire prefix and UUID of a WARP registration ID."""
    if not isinstance(value, str):
        raise ValueError('registration ID must be a string')
    if value.startswith('t.'):
        return 't.', uuid.UUID(value[2:])
    return '', uuid.UUID(value)


def fetch_device_policy(registration):
    """Read the split-tunnel policy for this registration from Cloudflare."""
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
        host = 'api.devices.cloudflare.com'
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
    return device['policy']


def parse_split_policy(policy):
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
    return mode, networks, sorted(domains)


def profile_routes(networks, version):
    """Build Include-mode IP routes, subtracting mandatory bypass prefixes."""
    routes = {net for net in networks['include'] + networks['always_include'] if net.version == version}
    if version == 4:
        routes.add(ipaddress.ip_network('1.1.1.1/32'))  # DNS route in unwarp profiles
    for excluded in networks['always_exclude']:
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


def nmcli(*arguments):
    result = subprocess.run(['nmcli', '--wait', '15', '--escape', 'no', *arguments],
                            capture_output=True, text=True, timeout=20,
                            env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise ValueError(result.stderr.strip() or f'nmcli exited with status {result.returncode}')
    return result.stdout.splitlines()


def apply_routes(profile, networks, ipv4_only):
    uuid_pattern = r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'
    selector = 'uuid' if re.fullmatch(uuid_pattern, profile, re.IGNORECASE) else 'id'
    fields = 'connection.uuid,connection.type,wireguard.peer-routes,ipv4.method,ipv4.routes,ipv6.method,ipv6.routes'
    properties = nmcli('--get-values', fields, 'connection', 'show', selector, profile)
    if len(properties) != 7:
        raise ValueError('expected one NetworkManager connection; use its UUID if the name is ambiguous')
    profile_uuid, kind, peer_routes, method4, current4, method6, current6 = properties
    if kind != 'wireguard' or peer_routes != 'no':
        raise ValueError('the target must be a WireGuard profile with wireguard.peer-routes disabled')
    if method4 in ('disabled', 'ignore') and (ipv4_only or method6 in ('disabled', 'ignore')):
        raise ValueError('the selected profile has no enabled address family to update')
    changes = []
    for version, method, current in ((4, method4, current4), (6, method6, current6)):
        if method in ('disabled', 'ignore') or (version == 6 and ipv4_only):
            continue
        routes = list(map(str, profile_routes(networks, version)))
        installed = {route.strip() for route in current.split(',') if route.strip()}
        if installed != set(routes):
            changes.extend([f'ipv{version}.routes', ','.join(routes)])
    if changes:
        nmcli('connection', 'modify', 'uuid', profile_uuid, *changes)
    # Check even on identical snapshots so a failed live reapply can be retried.
    try:
        active = nmcli('--terse', '--fields', 'UUID,DEVICE', 'connection', 'show', '--active')
        for row in active:
            active_uuid, _, interface = row.partition(':')
            if active_uuid == profile_uuid and interface:
                nmcli('device', 'reapply', interface)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f'profile routes are saved, but live update failed ({exc})') from exc


def routes_command(argv):
    parser = argparse.ArgumentParser(prog='unwarp.py routes',
                                     description='Fetch the registered device split-tunnel routes as JSON.')
    parser.add_argument('-w', '--wgconfig', default=REGISTRATION_FILE, help='WARP registration file')
    add_address_family_options(parser)
    parser.add_argument('--apply', metavar='PROFILE',
                        help='replace static routes on a dedicated NetworkManager WireGuard profile (name or UUID)')
    args = parser.parse_args(argv)
    try:
        with open(args.wgconfig, encoding='utf-8') as registration:
            if args.apply:
                # Serialize overlapping scheduled runs for the same registration.
                try:
                    fcntl.flock(registration, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError('another route sync is in progress for this registration') from None
            policy = fetch_device_policy(json.load(registration))
            mode, networks, domains = parse_split_policy(policy)
            if args.apply:
                if mode != 'include':
                    raise ValueError('applying static routes requires an Include-mode policy')
                if domains:
                    print(f'Policy has {len(domains)} domain rules. Only IP routes will be applied.', file=sys.stderr)
                apply_routes(args.apply, networks, args.ipv4only)
            else:
                result = {'mode': mode, 'domains': domains}
                for key, routes in networks.items():
                    result[key] = [str(net) for net in routes if not args.ipv4only or net.version == 4]
                print(json.dumps(result))
    except (OSError, ValueError, http.client.HTTPException, subprocess.TimeoutExpired) as exc:
        print(f'Route sync failed: {exc}', file=sys.stderr)
        return 1
    return 0

def configure_logging(debug, dry_run):
    '''
    set up logging
    '''
    if debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logger = logging.getLogger()
    logger.setLevel(log_level)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(log_level)
    if dry_run:
        formatter = logging.Formatter('%(levelname)-8s- DRY RUN: %(message)s')
    else:
        formatter = logging.Formatter('%(levelname)-8s- %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)

def shell_command(cmdline):
    '''
    execute shell command and return dict with exit code, stdout and stderr
    '''
    exitcode = 1
    stdout = b''
    stderr = b''
    LOG.debug('shell command: %s',
              cmdline)
    with Popen(cmdline, shell=True, stdout=PIPE, stderr=PIPE) as cmd:
        exitcode = cmd.wait()
        stdout, stderr = cmd.communicate()
    LOG.debug('shell command exit code: %s',
              exitcode)
    LOG.debug('shell command stdout: %s',
              stdout)
    LOG.debug('shell command stderr: %s',
              stderr)
    return {'exitcode': exitcode, 'stdout': stdout, 'stderr': stderr}

def read_json(config_file):
    '''
    read config file
    '''
    if os.path.isfile(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as json_config:
                config = json.load(json_config)
        except PermissionError:
            LOG.info('can not read file, insufficient permissions: %s',
                     config_file)
            raise IOError from PermissionError
    else:
        LOG.debug('failed to read file: %s',
                  config_file)
        LOG.info('please supply correct path to file, exiting')
        raise IOError
    LOG.info('reading file: %s',
             config_file)
    return config

def get_routes(warpconfig):
    """Use the same routes for initial profile generation and subsequent syncs."""
    if warpconfig.get('policy') is None:
        return ['1.1.1.1/32'], []
    mode, networks, _ = parse_split_policy(warpconfig['policy'])
    if mode != 'include':
        raise ValueError('generating static routes requires an Include-mode policy')
    routes4 = [str(net) for net in profile_routes(networks, 4)]
    routes6 = [str(net) for net in profile_routes(networks, 6)]
    return routes4, routes6

def create_nm_config(warpconfig, wgconfig, ifname, nmname, ipv4only, dnssearch):
    '''
    create networkmanager wireguard connection from cloudflare warp config
    '''
    nmconfig = ConfigParser()
    routes4, routes6 = get_routes(warpconfig)
    nmconfig.add_section('connection')
    nmconfig.add_section('wireguard')
    nmconfig.add_section(f'wireguard-peer.{warpconfig["public_key"]}')
    nmconfig.add_section('ipv6')
    nmconfig.add_section('ipv4')
    nmconfig.add_section('proxy')
    nmconfig.set('connection', 'id', nmname)
    nmconfig.set('connection', 'type', 'wireguard')
    nmconfig.set('connection', 'autoconnect', 'false')
    nmconfig.set('connection', 'interface-name', ifname)
    nmconfig.set('wireguard', 'mtu', '1280')
    nmconfig.set('wireguard', 'peer-routes', 'false')
    nmconfig.set('wireguard', 'private-key', wgconfig["secret_key"])
    nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'endpoint', warpconfig["endpoints"][0]["v4"])
    nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'persistent-keepalive', '25')
    if ipv4only:
        nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'allowed-ips', '0.0.0.0/0')
    else:
        nmconfig.set(f'wireguard-peer.{warpconfig["public_key"]}', 'allowed-ips', '0.0.0.0/0;::/0;')
    nmconfig.set('ipv4', 'address1', f'{warpconfig["interface"]["v4"]}/32')
    nmconfig.set('ipv4', 'dns', '1.1.1.1')
    nmconfig.set('ipv4', 'method', 'manual')
    if dnssearch:
        LOG.info('adding following domains search in ipv4 section: %s',
                 dnssearch)
        nmconfig.set('ipv4', 'dns-search', ';'.join(dnssearch.split()) + ';')
    for number in range(0, len(routes4)):
        nmconfig.set('ipv4', f'route{number+1}', routes4[number])
    if ipv4only:
        LOG.info('disabling ipv6 in networkmanager wireguard connection configuration')
        nmconfig.set('ipv6', 'addr-gen-mode', 'stable-privacy')
        nmconfig.set('ipv6', 'method', 'disabled')
    else:
        LOG.info('enabling ipv6 in networkmanager wireguard connection configuration')
        nmconfig.set('ipv6', 'addr-gen-mode', 'eui64')
        nmconfig.set('ipv6', 'address1', f'{warpconfig["interface"]["v6"]}/128')
        nmconfig.set('ipv6', 'dns', '2606:4700:4700::1111')
        if dnssearch:
            LOG.info('adding following domains search in ipv6 section: %s',
                     dnssearch)
            nmconfig.set('ipv6', 'dns-search', ';'.join(dnssearch.split()) + ';')
        nmconfig.set('ipv6', 'method', 'manual')
        for number in range(0, len(routes6)):
            nmconfig.set('ipv6', f'route{number+1}', routes6[number])
    return nmconfig

def deploy_nm_config(nmconfig, nmname, nmpath, overwrite, nmreload, dry_run):
    '''
    deploy networkmanager configuration
    '''
    msg = 'unknown status'
    write = False
    if nmpath.endswith('/'):
        nmpath = nmpath[:-1]
    config_file = f'{nmpath}/{nmname}.nmconnection'
    if os.path.isfile(config_file) and not overwrite:
        msg = 'file exists, skipping write'
    elif os.path.isfile(config_file) and overwrite:
        msg = 'file exists, overwriting'
        write = True
    elif not os.path.isfile(config_file):
        msg = 'file does not exists, creating'
        write = True
    LOG.info('%s: %s',
             msg, config_file)
    if write and dry_run:
        LOG.info('would have create/overwrite file: %s',
                 config_file)
    elif not write and dry_run:
        LOG.info('would have skip creating/overwriting file: %s',
                 config_file)
    elif write and not dry_run:
        try:
            with open(config_file, 'w', encoding='utf8') as nmconnfile:
                nmconfig.write(nmconnfile)
        except PermissionError as perms_ex:
            LOG.info('can not write file, insufficient permissions: %s',
                     config_file)
            LOG.debug('exception message: %s',
                      perms_ex)
            raise IOError from perms_ex
        LOG.info('setting permissions to 600: %s',
                 config_file)
        os.chmod(config_file, 0o600)
        if nmreload:
            LOG.info('reloading networkmanager configuration')
            shell_command('nmcli c reload')


def main(argv=None):
    '''
    do all the things
    '''
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == 'routes':
        return routes_command(argv[1:])
    args = parse_args(argv)
    configure_logging(args.debug, args.dry_run)
    try:
        warpconfig = read_json(args.warpconfig)
        wgconfig = read_json(args.wgconfig)
    except IOError:
        return 1
    try:
        nmconfig = create_nm_config(warpconfig, wgconfig, args.interface, args.nmconnectionname, args.ipv4only, args.domainsearch)
    except KeyError as warpconf_ex:
        LOG.error('missing parts in cloudflare warp configuration: %s',
                  warpconf_ex)
        return 1
    except ValueError as policy_error:
        LOG.error('%s', policy_error)
        return 1
    try:
        deploy_nm_config(nmconfig, args.nmconnectionname, args.nmconnectionpath, args.overwrite, args.nmreload, args.dry_run)
    except IOError:
        return 1
    return 0

if __name__ == '__main__':
    exit(main())
