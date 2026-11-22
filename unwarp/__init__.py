"""Read WARP policies and generate WireGuard profiles."""

from .cli import main, parse_args
from .cloudflare.client import cached_tunnel, parse_policy
from .model import ProfileTarget, RouteOptions, RoutePolicy

__all__ = ['create_nm_config', 'get_routes', 'get_routes_and_domains', 'main', 'parse_args']


def get_routes_and_domains(warpconfig):
    """Read the original cached-config route lists for callers using unwarp as a module."""
    raw = warpconfig.get('policy')
    policy = RoutePolicy('include') if raw is None else parse_policy(raw)
    return (list(map(str, policy.included_routes(4))), list(map(str, policy.included_routes(6))),
            list(policy.domains))


def get_routes(warpconfig):
    return get_routes_and_domains(warpconfig)[:2]


def create_nm_config(warpconfig, wgconfig, ifname, nmname, ipv4only, dnssearch):
    """Keep the in-memory keyfile API for existing callers."""
    from .backends.networkmanager import render_profile

    tunnel = cached_tunnel(warpconfig, wgconfig, ipv4only)
    routes = RouteOptions(ipv4only, tuple((dnssearch or '').split()))
    return render_profile(ProfileTarget(ifname, nmname), tunnel, routes)
