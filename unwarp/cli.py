"""Enroll a WireGuard device, generate profiles and refresh their routing policy."""

import argparse
import fcntl
import http.client
import json
import logging
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from .backends import BACKENDS, DEFAULT_BACKEND, get_backend
from .cloudflare import client as cloudflare
from .model import DEFAULT_MTU, ProfileTarget, RouteOptions, WriteOptions
from .profiles import choose_interface, config_path, default_config_dir, enroll, load_config, saved_target


def add_address_family_options(parser):
    family = parser.add_mutually_exclusive_group()
    family.add_argument('-4', '--ipv4only', action='store_true', default=True,
                        help='use only IPv4 routes (default)')
    family.add_argument('--dual-stack', dest='ipv4only', action='store_false',
                        help='use both IPv4 and IPv6 routes')


def add_domain_options(parser):
    domains = parser.add_mutually_exclusive_group()
    domains.add_argument('-s', '--domainsearch', metavar='DOMAINS',
                         help='merge extra space-separated DNS search domains with the policy')
    domains.add_argument('--sync-domains', action='store_true',
                         help='mirror policy DNS suffixes exactly and report removed local entries (default: merge)')


def add_config_directory(parser):
    parser.add_argument('--config-dir', type=Path, default=default_config_dir(), metavar='DIR',
                        help='directory for unwarp interface configurations (default: %(default)s)')


def add_naming_options(parser):
    parser.add_argument('-i', '--interface', help='WireGuard interface name (default: first available unwarpN)')
    parser.add_argument('-n', '--profile-name', '--nmconnectionname', metavar='NAME',
                        help='connection profile name (default: interface name)')


def add_write_options(parser):
    parser.add_argument('-c', '--output-dir', '--nmconnectionpath', type=Path, metavar='DIR',
                        help='profile output directory (default: chosen by the backend)')
    parser.add_argument('--mtu', type=int, default=DEFAULT_MTU, metavar='BYTES',
                        help='WireGuard interface MTU in bytes (default: %(default)s)')
    parser.add_argument('--qr', nargs='?', const='terminal', choices=('terminal', 'png'),
                        help='encode the portable WireGuard profile in the terminal (default) or in a PNG')
    parser.add_argument('-f', '--overwrite', action='store_true', help='regenerate an existing profile')
    parser.add_argument('-r', '--reload', '--nmreload', action='store_true', help='reload profiles after saving')
    parser.add_argument('-D', '--dry-run', action='store_true', help='preview without writing a profile')
    add_address_family_options(parser)
    add_domain_options(parser)


def parse_args(argv=None):
    # These two options apply to every command and may appear before or after its name.
    shared = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    shared.add_argument('--backend', choices=sorted(BACKENDS),
                        help=f'configuration backend (default for new profiles: {DEFAULT_BACKEND})')
    add_config_directory(shared)
    options, remaining = shared.parse_known_args(argv)
    descriptions = {'enroll': 'Enroll an interface using your team sign-in.',
                    'profile': 'Write the profile for an enrolled interface.',
                    'routes': 'Preview the device policy or update a profile.'}
    command = remaining.pop(0) if remaining and remaining[0] in descriptions else None
    prog = 'unwarp.py' if Path(sys.argv[0]).name == 'unwarp.py' else 'unwarp'
    parser = argparse.ArgumentParser(prog=prog + (' ' + command if command else ''), parents=[shared],
                                     description=descriptions.get(command, __doc__),
                                     epilog=None if command else 'Commands: enroll, profile, routes. '
                                                                 'With no command, import local WARP files.')
    if command == 'enroll':
        parser.add_argument('team', help='Cloudflare Zero Trust team name')
        add_naming_options(parser)
        parser.add_argument('--manual', action='store_true', help='print the login link and read the callback in the terminal')
        parser.add_argument('--login-url', help='use an active HTTPS enrollment link issued for the same team')
        parser.add_argument('--retry-uncertain', action='store_true',
                            help='retry an interrupted submission after checking the device list in Zero Trust')
    elif command == 'profile':
        parser.add_argument('-i', '--interface', required=True)
        add_write_options(parser)
    elif command == 'routes':
        source = parser.add_mutually_exclusive_group()
        source.add_argument('-w', '--wgconfig', default=cloudflare.REGISTRATION_FILE, help='WARP registration file')
        source.add_argument('-i', '--interface', help='read the unwarp configuration for this interface')
        parser.add_argument('--apply', nargs='?', const='', metavar='PROFILE',
                            help='update the given profile (default with -i: saved profile)')
        parser.add_argument('-c', '--output-dir', type=Path, metavar='DIR', help='directory of the files to update')
        parser.add_argument('-r', '--reload', action='store_true', help='reload systemd-networkd after applying')
        add_address_family_options(parser)
        add_domain_options(parser)
    else:
        parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
        parser.add_argument('-z', '--warpconfig', default=cloudflare.WARP_CONFIG_FILE, help='cached WARP configuration')
        parser.add_argument('-w', '--wgconfig', default=cloudflare.REGISTRATION_FILE, help='WARP registration file')
        add_naming_options(parser)
        add_write_options(parser)

    args = parser.parse_args(remaining, namespace=options)
    args.command = command
    if command in (None, 'profile'):
        min_mtu = 68 if args.ipv4only else 1280
        if not min_mtu <= args.mtu <= 65535:
            parser.error(f'--mtu must be between {min_mtu} and 65535 bytes for the selected address family')
    if command == 'routes':
        if args.apply == '' and args.interface is None:
            parser.error('--apply requires a profile or --interface')
        if args.apply is None and (args.domainsearch is not None or args.sync_domains):
            parser.error('DNS profile options require --apply PROFILE')
        if args.apply is None and (args.output_dir is not None or args.reload):
            parser.error('--output-dir and --reload require --apply')
    if command == 'enroll' and args.retry_uncertain and args.interface is None:
        parser.error('--retry-uncertain requires an explicit interface')
    return args


def route_options(args):
    return RouteOptions(args.ipv4only, tuple((args.domainsearch or '').split()), args.sync_domains)


def profile_backend(name, args):
    backend = get_backend(name)
    if args.qr and not getattr(backend, 'supports_qr', False):
        raise ValueError('--qr requires the wireguard backend')
    return backend


def write_profile(backend, target, tunnel, args):
    output = WriteOptions(args.output_dir, args.overwrite, args.reload, args.dry_run, args.qr)
    backend.write_profile(target, replace(tunnel, mtu=args.mtu), route_options(args), output)


def lock_profile_update(registration):
    try:
        fcntl.flock(registration, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError('another profile update is in progress for this registration') from None


def routes_command(args):
    managed = args.interface is not None
    path = config_path(args.config_dir, args.interface) if managed else args.wgconfig
    with open(path, encoding='utf-8') as file:
        if args.apply is not None:
            lock_profile_update(file)
        data = load_config(file, args.interface) if managed else json.load(file)
        if args.apply is None:
            print(json.dumps(cloudflare.fetch_policy(data).preview(args.ipv4only)))
            return
        default = data.get('backend', DEFAULT_BACKEND) if managed else DEFAULT_BACKEND
        backend = get_backend(args.backend or default)
        target = args.apply or saved_target(data)
        routes = replace(route_options(args), directory=args.output_dir, reload=args.reload)
        backend.apply_routes(target, cloudflare.fetch_policy(data), routes)


def profile_command(args):
    with config_path(args.config_dir, args.interface).open(encoding='utf-8') as file:
        lock_profile_update(file)
        data = load_config(file, args.interface)
        backend = profile_backend(args.backend or data.get('backend', DEFAULT_BACKEND), args)
        tunnel = cloudflare.fetch_tunnel(data, args.ipv4only)
        write_profile(backend, saved_target(data), tunnel, args)


def import_command(args):
    backend_name = args.backend or DEFAULT_BACKEND
    backend = profile_backend(backend_name, args)
    with open(args.warpconfig, encoding='utf-8') as warp, open(args.wgconfig, encoding='utf-8') as registration:
        tunnel = cloudflare.cached_tunnel(json.load(warp), json.load(registration), args.ipv4only)
    interface = choose_interface(args.interface, args.config_dir, backend_name, args.output_dir)
    name = interface if args.profile_name is None else args.profile_name
    write_profile(backend, ProfileTarget(interface, name), tunnel, args)


def configure_logging(debug, dry_run):
    level = logging.DEBUG if debug else logging.INFO
    prefix = 'DRY RUN: ' if dry_run else ''
    logging.basicConfig(level=level, stream=sys.stdout, format='%(levelname)-8s- ' + prefix + '%(message)s')


def main(argv=None):
    args = parse_args(argv)
    if args.command in (None, 'profile'):
        configure_logging(getattr(args, 'debug', False), args.dry_run)
    try:
        if args.command == 'routes':
            routes_command(args)
        elif args.command == 'enroll':
            enroll(args)
        elif args.command == 'profile':
            profile_command(args)
        else:
            import_command(args)
    except (OSError, ValueError, KeyError, EOFError, http.client.HTTPException, subprocess.TimeoutExpired) as exc:
        operation = {'enroll': 'Enrollment', 'routes': 'Route sync'}.get(args.command, 'Profile generation')
        print(f'{operation} failed: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        if args.command != 'enroll':
            raise
        print('Enrollment interrupted.', file=sys.stderr)
        return 130
    return 0
