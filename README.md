# Unwarp.py

Generate a NetworkManager WireGuard profile from a Cloudflare WARP configuration and refresh its IP routes and DNS search domains from the registered device's split-tunnel policy.

## Fetch current routes

From the repository directory, run

```sh
sudo python3 ./unwarp.py routes
```

This makes one HTTPS GET using `registration_id` and `api_token` from `/var/lib/cloudflare-warp/reg.json`. Cloudflare returns the full device policy. Unwarp selects IPv4 prefixes locally by default. Pass `--dual-stack` to include IPv6, or `-4` / `--ipv4only` to select IPv4 explicitly.

The printed JSON includes the split-tunnel mode, the corresponding `include` or `exclude` CIDRs, `always_include` and `always_exclude`. The `domains` field shows the original Cloudflare rules. The `dns_search` field shows the NetworkManager suffixes contributed by the Include policy, before merging local entries. It is `null` for Exclude mode or an Include rule that cannot be converted to a suffix. To compare the two lists, run

```sh
sudo python3 ./unwarp.py routes | jq '{domains, dns_search}'
```

The query reads directly from Cloudflare and works with `warp-svc` stopped. Use `-w PATH` to select a different registration file.

Registrations with an `account_id` use the Zero Trust device API. Registrations without it use wgcf v2.3.1's `GetSourceDevice` endpoint. Both paths use the device's existing credential. A successful preview confirms that this registration can read this policy. [Zero Trust registration API](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md) · [wgcf API implementation](https://github.com/ViRb3/wgcf/blob/v2.3.1/cloudflare/api.go)

## Update a WireGuard profile

To update IP routes and merge DNS search domains into a dedicated unwarp profile, run

```sh
sudo python3 ./unwarp.py routes --apply cloudflare.ztn
```

The profile must already exist in NetworkManager. `--apply` accepts its name or UUID. By default it replaces the profile's static IPv4 routes, including routes added by hand, and updates `ipv4.dns-search`. Add `--dual-stack` to update both settings for IPv6 on an IPv6-enabled profile. Unwarp includes the DNS route `1.1.1.1/32`, adds mandatory includes and subtracts mandatory exclusions. Exclude-mode policies can be previewed.

In the default merge mode, existing DNS search domains keep their order and missing policy suffixes are appended. The Include rule `*.corp.example` contributes `corp.example`. A rule for `vpn.corp.example` contributes that full name. The same wildcard conversion applies to `-s` and to legacy profile entries during an update. For example, `~*.corp.example` becomes the routing-only suffix `~corp.example`. Unwarp reports these profile corrections on stderr. Case and a trailing dot are ignored when matching domains.

NetworkManager's DNS parser interprets a leading `~` for routing-only domains. The 1.52.1 CLI accepts and stores a literal `*.corp.example`. With systemd-resolved, the suffix `corp.example` selects a DNS server for the domain itself and its subdomains. As an ordinary search suffix it also helps resolve short names. Traffic to the resulting addresses follows the IP routing table. [NetworkManager DNS search domains](https://networkmanager.dev/docs/api/latest/settings-ipv4.html) · [NetworkManager 1.52.1 DNS parser](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-core-utils.c#L4142-L4154) · [systemd-resolved query routing](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html)

To make the selected family's DNS search list match the current policy exactly, run

```sh
sudo python3 ./unwarp.py routes --apply cloudflare.ztn --sync-domains
```

Merge mode names local suffixes outside the current policy on stderr and keeps them. Exact sync reports each removed suffix and its address family on stderr after NetworkManager saves the profile. An explicit Include policy with no domain rules clears that family's search list only in exact sync. Use `-s "build.example dev.example"` in merge mode to add extra suffixes.

NetworkManager saves routes and DNS changes together. An active profile is reapplied in place. An inactive profile receives the new settings on its next activation. A fetch error, missing policy or unsupported mode exits nonzero before changing the profile. If NetworkManager saves the profile but fails to reapply it, the command exits nonzero and the next run retries.

For example, a root crontab can refresh a profile every 15 minutes. Substitute the absolute path to your checkout.

```cron
*/15 * * * * /usr/bin/python3 /opt/unwarp/unwarp.py routes --apply cloudflare.ztn
```

## Generate the initial profile from local files

New profiles use IPv4 and inherit the Include policy's DNS suffixes by default. Add `--dual-stack` when generating a profile to enable both IPv4 and IPv6.

```sh
sudo python3 ./unwarp.py -r -f -i ztn0 -n cloudflare.ztn
```

With `-f`, regeneration also merges search domains already in the keyfile. Add `--sync-domains` to mirror the cached policy or `-D` with these flags to preview the removals. If the existing keyfile has IPv6 search domains, use `--dual-stack` to preserve them when regenerating or `--sync-domains` to explicitly drop them when disabling IPv6.

**NOTE**: Script needs root privileges to successfully read Cloudflare WARP configuration and write NetworkManager system connection.

If you don't like the idea running it with root privileges, you can allow your user to read/write these locations, or copy these files to temporary location, run script to generate .nmconnection and place it to /etc/NetworkManager/system-connections/ manually (or by own script).
