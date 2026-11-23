"""Per-interface state, name allocation and enrollment orchestration."""

import fcntl
import http.client
import json
import os
import socket
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

from .backends import DEFAULT_BACKEND, get_backend
from .cloudflare.client import DEFAULT_CLIENT_VERSION, EnrollmentRejected, register_device
from .cloudflare.login import enrollment_url, sign_in
from .keys import derive_public_key, generate_private_key
from .model import ProfileTarget, connection_name, interface_name


SYSTEM_INTERFACES = Path('/sys/class/net')


def checkout_root() -> Path | None:
    root = Path(__file__).resolve().parents[1]
    if (root / 'unwarp.py').is_file() and (root / 'pyproject.toml').is_file():
        return root
    return None


def default_config_dir() -> Path:
    """Keep source checkouts portable and installed credentials per user."""
    root = checkout_root()
    if root is not None:
        return root / 'config'
    xdg_config = Path(os.environ.get('XDG_CONFIG_HOME', ''))
    if xdg_config.is_absolute():
        return xdg_config / 'unwarp'
    return Path.home() / '.config' / 'unwarp'


def choose_interface(requested, directory, backend_name, output_directory=None):
    if requested is not None:
        name = interface_name(requested)
        validate = getattr(get_backend(backend_name), 'validate_name', None)
        if validate is not None:
            validate(name)
        return name
    bound = get_backend(backend_name).reserved_interfaces(output_directory)
    number = 0
    while True:
        name = interface_name(f'unwarp{number}')
        if (name not in bound and not (SYSTEM_INTERFACES / name).exists()
                and not os.path.lexists(directory / (name + '.json'))):
            return name
        number += 1


def config_path(directory, interface):
    return Path(directory, interface_name(interface) + '.json')


def saved_target(data):
    return ProfileTarget(data['interface'], data['connection_name'], data['connection_uuid'])


def load_config(file, interface, *, ready=True):
    data = json.load(file)
    if not isinstance(data, dict) or data.get('interface') != interface:
        raise ValueError('unwarp configuration does not match the requested interface')
    if data.get('state') not in ('registered', 'pending', 'submitting'):
        raise ValueError('unknown enrollment state')
    if ready and data.get('state') != 'registered':
        raise ValueError('enrollment is incomplete for this interface')
    connection_name(data.get('connection_name'))
    try:
        uuid.UUID(data['connection_uuid'])
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError('missing or invalid profile UUID') from None
    return data


@contextmanager
def enrollment_directory(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(fd)
        if stat.st_uid != os.geteuid() or stat.st_mode & 0o022:
            raise ValueError('the config directory must belong to the enrolling user and be writable only by that user')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another enrollment is running in this config directory') from None
        yield fd
    finally:
        os.close(fd)


def save_config(path, data, directory_fd):
    with tempfile.NamedTemporaryFile('w', dir=path.parent, prefix='.unwarp-', delete=False,
                                     encoding='utf-8') as output:
        try:
            json.dump(data, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
            os.replace(output.name, path)
            os.fsync(directory_fd)
        finally:
            Path(output.name).unlink(missing_ok=True)


def enrollment_metadata(args, data):
    device_name = args.device_name if args.device_name is not None else data.get('device_name')
    if device_name is None:
        device_name = socket.gethostname()
    if not isinstance(device_name, str) or not device_name.strip() or len(device_name.encode('utf-8')) > 100:
        raise ValueError('--device-name must be nonempty and at most 100 UTF-8 bytes')

    client_version = args.client_version
    if client_version is None:
        client_version = data.get('client_version', DEFAULT_CLIENT_VERSION)
    if not (isinstance(client_version, str) and client_version.isascii()
            and client_version.isprintable() and client_version.strip()):
        raise ValueError('--client-version must be a nonempty printable ASCII string')
    return device_name, client_version


def enroll(args, *, browser_options=None):
    team = args.team.lower()
    url = enrollment_url(team, args.login_url)
    directory = Path(args.config_dir)
    backend_name = args.backend or DEFAULT_BACKEND
    with enrollment_directory(directory) as fd:
        interface = choose_interface(args.interface, directory, backend_name)
        path = config_path(directory, interface)
        if path.is_symlink():
            raise ValueError('the interface config must be a regular file')
        if path.exists():
            with path.open(encoding='utf-8') as saved:
                data = load_config(saved, interface, ready=False)
            if data.get('team') != team or (args.profile_name is not None
                                            and data['connection_name'] != args.profile_name):
                raise ValueError('the interface already belongs to a different team or profile')
            if args.backend is not None and data.get('backend', DEFAULT_BACKEND) != backend_name:
                raise ValueError('the interface already has a different default backend; '
                                 'select the output backend with profile --backend')
            if not isinstance(data.get('secret_key'), str) or not data['secret_key']:
                raise ValueError('the saved interface config is missing the WireGuard private key')
            if data['state'] == 'registered':
                if not data.get('api_token') or not data.get('registration_id'):
                    raise ValueError('the saved interface config is missing the Cloudflare registration')
                if ((args.device_name is not None and args.device_name != data.get('device_name', interface))
                        or (args.client_version is not None and args.client_version != data.get('client_version'))):
                    raise ValueError(f'{interface} is already registered. The device name and client version '
                                     'can only be set during enrollment')
                print(f'{interface} is already registered. Config: {path}')
                return interface, data.get('backend', DEFAULT_BACKEND)
            if data['state'] == 'submitting' and not args.retry_uncertain:
                raise ValueError('the previous request may have registered this device; check Zero Trust '
                                 'before using --retry-uncertain with this interface')
        else:
            name = connection_name(interface if args.profile_name is None else args.profile_name)
            data = {'interface': interface, 'connection_name': name, 'connection_uuid': str(uuid.uuid4()),
                    'backend': backend_name, 'team': team, 'state': 'pending', 'secret_key': generate_private_key()}
        device_name, client_version = enrollment_metadata(args, data)
        public_key = derive_public_key(data['secret_key'])
        data.update(device_name=device_name, client_version=client_version)
        save_config(path, data, fd)
        print(f'Enrolling interface {interface}. Config: {path}', flush=True)
        assertion, account = sign_in(team, url, args.manual, browser_options=browser_options)
        data['state'] = 'submitting'
        save_config(path, data, fd)
        try:
            device_id, token = register_device(team, device_name, public_key, assertion, client_version=client_version)
        except EnrollmentRejected:
            data['state'] = 'pending'
            save_config(path, data, fd)
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ValueError(f'{exc}; the submission outcome is uncertain for {interface}. '
                             'Check the device list in Zero Trust before retrying') from None
        data.update(state='registered', registration_id=device_id, api_token=token, account_id=account,
                    public_key=public_key)
        save_config(path, data, fd)
    print(f'Registered {interface}. Profile: {data["connection_name"]}')
    return interface, data.get('backend', DEFAULT_BACKEND)
