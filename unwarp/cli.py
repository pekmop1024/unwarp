"""Enroll a WireGuard device, generate profiles and refresh their routing policy."""

import argparse
import fcntl
import http.client
import json
import logging
import os
import pwd
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from .backends import BACKENDS, DEFAULT_BACKEND, get_backend
from .cloudflare import client as cloudflare
from .model import DEFAULT_MTU, ProfileTarget, RouteOptions, WriteOptions
from .profiles import (checkout_root, choose_interface, config_path, default_config_dir, enroll,
                       load_config, saved_target)


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
    descriptions = {'enroll': 'Sign in from your desktop session and save the interface registration.',
                    'profile': 'Write the profile using the saved registration for an interface.',
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
        parser.add_argument('--device-name', metavar='NAME',
                            help='device name sent to Cloudflare (default: system hostname)')
        parser.add_argument('--client-version', metavar='VERSION',
                            help=f'WARP version sent to Cloudflare (default: {cloudflare.DEFAULT_CLIENT_VERSION})')
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


def launcher():
    checkout = checkout_root()
    if checkout is not None:
        return [sys.executable, str(checkout / 'unwarp.py')]
    return [sys.executable, '-I', '-m', 'unwarp']


def nm_install_command(directory, arguments):
    # sudo may change HOME, XDG_CONFIG_HOME and PATH. Pin the registration and the launcher.
    config_option = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    config_option.add_argument('--config-dir')
    _, arguments = config_option.parse_known_args(arguments)
    prefix = ['sudo'] if os.geteuid() != 0 or sudo_uid() is not None else []
    return shlex.join([*prefix, *launcher(), '--config-dir', str(directory.absolute()), *arguments])


def sudo_uid():
    value = os.environ.get('SUDO_UID', '')
    return (int(value) or None) if os.geteuid() == 0 and value.isdecimal() else None


def desktop_process_options(uid):
    user = pwd.getpwuid(uid)
    session = {'DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
               'XDG_CONFIG_HOME', 'XDG_SESSION_TYPE', 'PATH', 'TERM', 'LANG', 'LANGUAGE'}
    env = {key: value for key, value in os.environ.items() if key in session or key.startswith('LC_')}
    env.update(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name)
    runtime = Path('/run/user') / str(uid)
    if runtime.is_dir() and env.get('XDG_RUNTIME_DIR') in (None, '', '/run/user/0'):
        env['XDG_RUNTIME_DIR'] = str(runtime)
    if (not (env.get('DISPLAY') or env.get('WAYLAND_DISPLAY') or os.environ.get('SSH_CONNECTION'))
            and env.get('XDG_RUNTIME_DIR')):
        runtime = Path(env['XDG_RUNTIME_DIR'])
        if runtime.is_absolute() and runtime.is_dir() and runtime.stat().st_uid == uid:
            displays = [path.name for path in runtime.glob('wayland-*') if path.is_socket()]
            if len(displays) == 1:
                env['WAYLAND_DISPLAY'] = displays[0]
    return dict(user=uid, group=user.pw_gid, extra_groups=os.getgrouplist(user.pw_name, user.pw_gid), env=env)


def root_registration_directory(directory, arguments):
    try:
        return directory.stat().st_uid == 0
    except FileNotFoundError:
        explicit = any(arg.partition('=')[0] == '--config-dir' for arg in arguments)
        if not explicit and checkout_root() is None and directory == default_config_dir():
            return False  # Resolve a fresh default again in the enrolling user's environment.
    for parent in directory.absolute().parents:
        try:
            info = parent.stat()
        except FileNotFoundError:
            continue
        return info.st_uid == 0 and not info.st_mode & 0o022
    return False


def enroll_command(args, arguments):
    uid = sudo_uid()
    browser_options = None
    if uid is not None and not args.manual and sys.stdin.isatty():
        desktop = desktop_process_options(uid)
        print('Running browser sign-in as your desktop user.', file=sys.stderr, flush=True)
        if not root_registration_directory(args.config_dir, arguments):
            return subprocess.run([*launcher(), *arguments], **desktop).returncode
        # An earlier sudo run may already own the registration and its private key.
        browser_options = desktop
    interface, backend = enroll(args, browser_options=browser_options)
    if backend == 'networkmanager':
        command = nm_install_command(args.config_dir, ['profile', f'--interface={interface}', '--reload'])
        print(f'Install the NetworkManager system connection using this registration:\n  {command}')
    return 0


def profile_command(args, arguments):
    with config_path(args.config_dir, args.interface).open(encoding='utf-8') as file:
        lock_profile_update(file)
        data = load_config(file, args.interface)
        name = args.backend or data.get('backend', DEFAULT_BACKEND)
        backend = profile_backend(name, args)
        tunnel = cloudflare.fetch_tunnel(data, args.ipv4only)
        try:
            write_profile(backend, saved_target(data), tunnel, args)
        except PermissionError:
            if (name != 'networkmanager' or os.geteuid() == 0
                    or (args.output_dir or backend.DEFAULT_DIRECTORY).absolute() != backend.DEFAULT_DIRECTORY):
                raise
            command = nm_install_command(args.config_dir, arguments)
            raise ValueError(f'Access to {backend.DEFAULT_DIRECTORY} requires administrator privileges. '
                             f'Use this registration and the same profile options:\n  {command}') from None


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
    arguments = sys.argv[1:] if argv is None else list(argv)
    args = parse_args(arguments)
    if args.command in (None, 'profile'):
        configure_logging(getattr(args, 'debug', False), args.dry_run)
    try:
        if args.command == 'routes':
            routes_command(args)
        elif args.command == 'enroll':
            return enroll_command(args, arguments)
        elif args.command == 'profile':
            profile_command(args, arguments)
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
