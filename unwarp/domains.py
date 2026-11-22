"""Merge policy DNS search domains with locally maintained entries."""

import sys

from .model import dns_suffix


def search_domain(domain):
    """Keep local suffix spelling and routing-only semantics when converting a wildcard."""
    if '*' not in domain:
        return domain
    if domain.startswith('~'):
        return '~' + dns_suffix(domain[1:])
    return dns_suffix(domain)


def plan_dns_domains(current, wanted, sync):
    desired = {}
    for raw in wanted:
        domain = search_domain(raw)
        desired.setdefault(domain.lower().rstrip('.'), domain)

    existing, outside, rewrites = {}, [], []
    for raw in current:
        try:
            domain = search_domain(raw)
        except ValueError:
            # A legacy pattern with no suffix equivalent stays local until exact sync removes it.
            domain = raw
        name = domain.lower().rstrip('.')
        existing.setdefault(name, domain)
        if name not in desired:
            outside.append(raw if sync else existing[name])
        if domain != raw and (not sync or name in desired):
            rewrites.append((raw, desired[name] if sync else existing[name]))

    if not sync:
        for name, domain in desired.items():
            existing.setdefault(name, domain)
    result = desired if sync else existing
    return list(result.values()), list(dict.fromkeys(outside)), rewrites


def reconcile_domains(current, wanted, sync):
    """Return the search list and the local suffixes outside the desired list."""
    return plan_dns_domains(current, wanted, sync)[:2]


def report_domains(setting, outside, sync, dry_run=False, rewrites=()):
    if rewrites:
        action = 'Would normalize' if dry_run else 'Normalized'
        changes = ', '.join(f'{raw} -> {suffix}' for raw, suffix in rewrites)
        print(f'{action} {setting}: {changes}', file=sys.stderr)
    if outside:
        if sync:
            action = 'Would remove' if dry_run else 'Removed'
            print(f'{action} from {setting}: {", ".join(outside)}', file=sys.stderr)
        else:
            print(f'Keeping local {setting} entries outside the policy: {", ".join(outside)}',
                  file=sys.stderr)
