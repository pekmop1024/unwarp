"""Configuration backend contract and registry."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..model import ProfileTarget, RouteOptions, RoutePolicy, WireGuardTunnel, WriteOptions


@runtime_checkable
class ConfigBackend(Protocol):
    def reserved_interfaces(self, directory: Path | None) -> set[str]:
        """Return interface names already used by this backend."""
        ...

    def write_profile(self, target: ProfileTarget, tunnel: WireGuardTunnel,
                      routes: RouteOptions, output: WriteOptions) -> None:
        """Generate and deploy a profile from a normalized tunnel."""
        ...

    def apply_routes(self, target: ProfileTarget | str, policy: RoutePolicy, routes: RouteOptions) -> None:
        """Update an existing profile from a fresh policy snapshot."""
        ...


DEFAULT_BACKEND = 'networkmanager'
BACKENDS = {
    'networkmanager': 'unwarp.backends.networkmanager',
    'wireguard': 'unwarp.backends.wireguard:backend',
    'systemd-networkd': 'unwarp.backends.networkd:backend',
}


def get_backend(name: str) -> ConfigBackend:
    if not isinstance(name, str) or name not in BACKENDS:
        raise ValueError(f'unknown configuration backend. Available backends: {", ".join(sorted(BACKENDS))}')
    try:
        module, _, attribute = BACKENDS[name].partition(':')
        backend = import_module(module)
        if attribute:
            backend = getattr(backend, attribute)
    except (ImportError, AttributeError) as exc:
        raise ValueError(f'could not load configuration backend {name!r}: {exc}') from exc
    if not isinstance(backend, ConfigBackend):
        raise ValueError(f'configuration backend {name!r} does not implement ConfigBackend')
    return backend
