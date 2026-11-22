# Unwarp

Unwarp enrolls a WireGuard device with Cloudflare Zero Trust and uses its device token to fetch the current split-tunnel policy. It exports NetworkManager, portable WireGuard and systemd-networkd profiles and can refresh their routes and DNS search domains from cron. Android and iOS can also import a portable profile by QR. All three backends can read an existing WARP client's cached configuration.

## Install and run

Unwarp runs on Linux with Python 3.10 or newer. Registration, WireGuard key generation, policy retrieval and keyfile generation use the Python standard library. A local WARP client installation is optional. Unwarp uses `wg` only in an optional key compatibility test.

Automatic browser sign-in uses Firefox or Firefox ESR. With `--manual` you can complete sign-in in another browser. The NetworkManager backend uses `nmcli` for live profile updates, reloads and, when available, automatic interface-name discovery.

From a checkout, run `python3 ./unwarp.py` or `python3 -m unwarp` with the arguments shown below. To install the `unwarp` command in a virtual environment, run

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/unwarp --help
```

For QR export, run `.venv/bin/python -m pip install '.[qr]'` from the checkout. Debian's system Python can also use the `python3-segno` package. Only QR generation uses Segno. After activating the environment, you can use `unwarp` from any directory. The examples below use the checkout launcher. [Segno](https://segno.readthedocs.io/en/stable/)

| Command | What it does |
| --- | --- |
| `unwarp enroll TEAM` | Sign in with your organization and save a registration for one interface. |
| `unwarp profile -i IFACE` | Fetch the enrolled device's current peer and policy and write its WireGuard profile. |
| `unwarp routes -i IFACE` | Print the current policy as JSON. Add `--apply` to update the selected backend's profile. |
| `unwarp routes -w REG_FILE` | Fetch policy using an existing WARP registration. Add `--apply PROFILE` with a NetworkManager name or UUID, or a file backend's interface name. |
| `unwarp` with no subcommand | Generate a profile from local WARP files. Use `-z` for the cached configuration and `-w` for the registration. |

## Enroll an interface with your team

Run enrollment as your desktop user. Replace `my-team` with your Cloudflare team name.

```sh
python3 ./unwarp.py enroll my-team
```

Open the one-time `127.0.0.1` link printed by unwarp on the same computer. It opens your team's Cloudflare sign-in page in a temporary Firefox profile. Complete your organization's usual login and select **Finish this unwarp sign-in** when Firefox asks where to open the return link. Firefox delivers the answer to the local unwarp process and the temporary profile closes. Unwarp submits the WireGuard public key to Cloudflare and receives the device token and registration ID. [Cloudflare browser enrollment](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/manual-deployment/) · [Device registration API](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md#register-a-client-device-with-a-service-token)

Unwarp generates the private key from the operating system's secure random source. It derives the public key locally with X25519, reusing the saved private key if enrollment resumes. Python's integer arithmetic has no constant-time guarantee. [X25519 in RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748#section-5)

Without `-i`, enrollment and cached import choose the first available name starting at `unwarp0`. Unwarp checks kernel interfaces, its own `<interface>.json` files and names reserved by the selected backend.

The NetworkManager backend asks the daemon for bound interfaces and scans `*.nmconnection` files in `/etc/NetworkManager/system-connections/` or the directory selected with `-c` for a cached import. Each filename reserves its stem, even if the file cannot be read. A readable profile also reserves the `interface-name` in its `[connection]` section. For example, an inactive `Office.nmconnection` with `interface-name=unwarp0` reserves `unwarp0` even when NetworkManager is stopped.

Use `-i` to select an exact interface name. The NetworkManager display name defaults to the interface name and can be set independently with `-n`.

```sh
python3 ./unwarp.py enroll my-team -i wg-office -n 'Office / VPN 100%'
```

Unwarp saves the device credentials and profile UUID in `<interface>.json`. A source checkout uses its own `config/` directory, including when called by absolute path from cron. Git and the distribution archives exclude this directory. An installed copy uses `$XDG_CONFIG_HOME/unwarp/` when `XDG_CONFIG_HOME` is an absolute path, and `~/.config/unwarp/` otherwise. Unwarp creates its directory with mode `0700` and each interface file with mode `0600`.

Pass `--config-dir DIR` to select the same directory for `enroll`, `profile` and `routes`. When switching from a checkout to the installed command, point it at the checkout's existing `config/` to reuse an enrollment. For installed commands run through sudo or cron, pass the absolute path used by the enrolling user.

Use `--manual` for SSH or another browser. Unwarp also uses this mode when Firefox or a desktop session is unavailable, or when run as root. Follow the printed Cloudflare link and paste the completed `com.cloudflare.warp://…/auth?token=…` link into the waiting terminal. Cloudflare documents how to copy it from the success page. If your team requires an active enrollment URL, pass its HTTPS link with `--login-url`. An invalid enrollment session requires a fresh sign-in. [Cloudflare manual enrollment](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/manual-deployment/)

To continue an interrupted sign-in, repeat `enroll` with the printed interface name, for example `-i unwarp0`. A completed configuration is reused. If the registration request was interrupted after submission, check the device list in Zero Trust before repeating it. Use `--retry-uncertain` with that interface only after confirming a new submission is appropriate.

## Use an enrolled interface

Generate and reload the NetworkManager profile, then preview or apply the latest policy.

```sh
sudo python3 ./unwarp.py profile -i unwarp0 -r
python3 ./unwarp.py routes -i unwarp0
sudo python3 ./unwarp.py routes -i unwarp0 --apply
```

`profile` reads current peer settings and the Include policy from Cloudflare. In this example it writes `/etc/NetworkManager/system-connections/unwarp0.nmconnection`. The assigned device policy must allow WireGuard. The saved UUID identifies the profile even if its display name contains spaces, slashes or a percent sign. Use `-c DIR` to write to an existing directory, `-f` to regenerate an existing profile, or `-D` to preview the write. New keyfiles have mode `0600`.

`-r` asks NetworkManager to reload profiles. New profiles have autoconnect disabled. To bring up the example tunnel when ready, run `nmcli connection up id unwarp0` with NetworkManager permissions. If you chose a display name with `-n`, use that name or activate the profile by UUID. Profiles and route updates default to IPv4. Pass `--dual-stack` to both `profile` and `routes` to include IPv6.

Both `profile` and cached imports generate profiles with an MTU of **1280 bytes** by default. Use `--mtu BYTES` each time you generate a profile that needs a different value. For example, to regenerate an existing profile with an MTU of 1400 and reload it in NetworkManager, run

```sh
sudo python3 ./unwarp.py profile -i unwarp0 --mtu 1400 -f -r
```

For IPv4, NetworkManager and networkd accept 68–65535 bytes. Portable WireGuard profiles accept 576–65535 bytes to support the Windows importer. With `--dual-stack` the minimum is 1280 bytes for all backends. Scheduled `routes --apply` updates preserve the profile's MTU. [Windows WireGuard parser](https://git.zx2c4.com/wireguard-windows/tree/conf/parser.go) · [IPv6 minimum link MTU](https://www.rfc-editor.org/rfc/rfc8200.html#section-5)

## Fetch current routes

For an interface enrolled by unwarp, use `routes -i unwarp0`. To use the registration created by an existing WARP client, run

```sh
sudo python3 ./unwarp.py routes
```

This makes one HTTPS GET using `registration_id` and `api_token` from `/var/lib/cloudflare-warp/reg.json`. Cloudflare returns the full device policy. Unwarp selects IPv4 prefixes locally by default. Pass `--dual-stack` to include IPv6, or `-4` / `--ipv4only` to select IPv4 explicitly.

The printed JSON includes the split-tunnel mode, the corresponding `include` or `exclude` CIDRs, `always_include` and `always_exclude`. The `domains` field shows the original Cloudflare host rules. The `dns_search` field shows the suffixes contributed by the Include policy, before merging local entries. It is `null` for Exclude mode or an Include rule that cannot be converted to a suffix. To compare the two lists for an enrolled interface with `jq`, run

```sh
python3 ./unwarp.py routes -i unwarp0 | jq '{domains, dns_search}'
```

Both forms read directly from Cloudflare and work with `warp-svc` and NetworkManager stopped. Use `-w PATH` to select a different WARP registration file.

Registrations with an `account_id` use the Zero Trust device API. Registrations without it use wgcf v2.3.1's `GetSourceDevice` endpoint. Both paths use the device's existing credential. A successful preview confirms that this registration can read this policy. [Zero Trust registration API](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md) · [wgcf API implementation](https://github.com/ViRb3/wgcf/blob/v2.3.1/cloudflare/api.go)

## Update a NetworkManager profile

For an enrolled interface, `routes -i unwarp0 --apply` uses its saved credentials and profile UUID. To update a profile named `cloudflare.ztn` using the WARP client's registration instead, run

```sh
sudo python3 ./unwarp.py routes --apply cloudflare.ztn
```

`--apply` accepts the name or UUID of a WireGuard profile loaded in NetworkManager. It requires `wireguard.peer-routes` to be disabled, as it is in generated keyfiles. By default the update replaces the profile's static IPv4 routes, including routes added by hand, and updates `ipv4.dns-search`. Add `--dual-stack` to update both settings for IPv6 on an IPv6-enabled profile. Unwarp adds the DNS route `1.1.1.1/32` and mandatory includes, then subtracts mandatory exclusions. Applying routes requires Include mode. Exclude-mode policies can be previewed.

In the default merge mode, existing DNS search domains keep their order and missing policy suffixes are appended. The Include rule `*.corp.example` contributes `corp.example`. A rule for `vpn.corp.example` contributes that full name. The same wildcard conversion applies to `-s` and to legacy profile entries during an update. For example, `~*.corp.example` becomes the routing-only suffix `~corp.example`. Unwarp reports these profile corrections on stderr. Case and a trailing dot are ignored when matching domains.

NetworkManager's DNS parser interprets a leading `~` for routing-only domains. The 1.52.1 CLI accepts and stores a literal `*.corp.example`. With systemd-resolved, the suffix `corp.example` selects a DNS server for the domain itself and its subdomains. As an ordinary search suffix it also helps resolve short names. Traffic to the resulting addresses follows the IP routing table. [NetworkManager DNS search domains](https://networkmanager.dev/docs/api/latest/settings-ipv4.html) · [NetworkManager 1.52.1 DNS parser](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-core-utils.c#L4142-L4154) · [systemd-resolved query routing](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.service.html)

To make the selected family's DNS search list match the current policy exactly, run

```sh
sudo python3 ./unwarp.py routes -i unwarp0 --apply --sync-domains
```

Merge mode names local suffixes outside the current policy on stderr and keeps them. Exact sync reports each removed suffix and its address family on stderr after NetworkManager saves the profile. An explicit Include policy with no domain rules clears that family's search list only in exact sync. To inspect the domains saved in the default profile and add manual suffixes in merge mode, run

```sh
nmcli --get-values ipv4.dns-search connection show id unwarp0
sudo python3 ./unwarp.py routes -i unwarp0 --apply -s 'build.example dev.example'
```

NetworkManager saves routes and DNS changes together. An active profile is reapplied in place. An inactive profile receives the new settings on its next activation. A fetch error, missing policy or unsupported mode exits nonzero before changing the profile. If NetworkManager saves the profile but fails to reapply it, the command exits nonzero and the next run retries.

For example, a root crontab can refresh an enrolled interface every 15 minutes. Substitute the absolute path to the checkout where you enrolled.

```cron
*/15 * * * * /usr/bin/python3 /opt/unwarp/unwarp.py routes -i unwarp0 --apply
```

For an installed copy, use the absolute path to the installed command and the enrolling user's configuration directory. For example, a job for an interface enrolled by `alice` could run `/opt/unwarp-venv/bin/unwarp --config-dir /home/alice/.config/unwarp routes -i unwarp0 --apply`.

## Generate the initial profile from local files

With no subcommand, unwarp reads `/var/lib/cloudflare-warp/conf.json` and `/var/lib/cloudflare-warp/reg.json`. It writes a NetworkManager keyfile by default. Use `--backend` to select another format. New profiles use IPv4 and inherit the Include policy's DNS suffixes. Add `--dual-stack` to generate a profile with both IPv4 and IPv6.

```sh
sudo python3 ./unwarp.py -r -i ztn0 -n cloudflare.ztn
```

With `-f`, regeneration also merges search domains already in the keyfile. Add `--sync-domains` to mirror the cached policy or `-D` with these flags to preview the removals. If the existing keyfile has IPv6 search domains, use `--dual-stack` to preserve them when regenerating or `--sync-domains` to explicitly drop them when disabling IPv6.

Import needs read access to the two input files and write access to the output directory. The system locations typically require elevated privileges. To generate a local keyfile as your own user from readable copies, run

```sh
python3 ./unwarp.py -z ./conf.json -w ./reg.json -c . -i ztn0 -n cloudflare.ztn
```

This writes `./cloudflare.ztn.nmconnection` for interface `ztn0`. In cached imports a display name suitable for a filename is used as the keyfile stem, with the interface name as fallback.

## Configuration backends

| Backend | Generated files | Default destination |
| --- | --- | --- |
| `networkmanager` (default) | NetworkManager `.nmconnection` keyfile | `/etc/NetworkManager/system-connections/` |
| `wireguard` | `<interface>.conf` for wg-quick and the official Windows, macOS, Android and iOS apps | Current directory |
| `systemd-networkd` | `50-<interface>.netdev` and `50-<interface>.network` | `/etc/systemd/network/` |

`enroll TEAM --backend NAME` saves the default in the interface config. `profile` and `routes --apply` accept a backend override on each run. A plain `routes` always prints the Cloudflare policy as JSON. Existing interface registrations default to NetworkManager. The original flags `--nmconnectionname`, `--nmconnectionpath` and `--nmreload` remain aliases for profile generation.

### Portable WireGuard and QR

Generate the file for an enrolled interface, then refresh that file whenever the policy changes. Use the same directory for both commands. For cron, supply an absolute output directory.

```sh
python3 ./unwarp.py profile -i unwarp0 --backend wireguard -c .
python3 ./unwarp.py routes -i unwarp0 --backend wireguard --apply -c .
```

The portable and networkd backends write the effective Include CIDRs into the peer's `AllowedIPs`. After subtracting mandatory exclusions, they combine adjacent prefixes that cover exactly the same addresses. Use `--dual-stack` on both generation and refresh to manage IPv6 too. An IPv4 refresh of a dual-stack export keeps its IPv6 routes. Both backends merge local DNS search suffixes and support `--sync-domains` with removal reporting. Portable `DNS` carries ordinary search suffixes. Use the networkd or NetworkManager backend for routing-only suffixes such as `~corp.example`. [wg-quick profile format](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8)

With the QR extra installed, display the saved profile in the terminal or write `unwarp0.conf.png` next to it. Both commands also work on the initial export.

```sh
python3 ./unwarp.py profile -i unwarp0 --backend wireguard --qr
python3 ./unwarp.py profile -i unwarp0 --backend wireguard --qr png
```

The QR contains the exact saved file, including its WireGuard private key. The Cloudflare token stays in unwarp's registration file. Both the `.conf` and PNG are written with mode `0600`. If the complete profile exceeds the capacity of one QR code, unwarp saves all routes and prints the path to import in the app. When an update changes the file, unwarp removes its outdated companion PNG. Run the PNG command again for a fresh image. A profile already imported into an app needs a new import after an update. For an active wg-quick tunnel, bring it up again with the updated config when ready.

### systemd-networkd

The networkd files target systemd **250 or newer**. The `.netdev` defines the key, peer, MTU and `RouteTable=main`, which installs routes for the peer's `AllowedIPs`. The `.network` assigns addresses and configures per-link DNS for the specified search or routing-only domains. With systemd-resolved, `DNSDefaultRoute=no` keeps unrelated DNS queries on their usual links. To generate both files in the current directory, or deploy and refresh them on the host, run

```sh
python3 ./unwarp.py profile -i unwarp0 --backend systemd-networkd -c .
sudo python3 ./unwarp.py profile -i unwarp0 --backend systemd-networkd --reload
sudo python3 ./unwarp.py routes -i unwarp0 --backend systemd-networkd --apply --reload
```

File updates can run offline with respect to networkd. In `/etc/systemd/network/`, `--reload` runs `networkctl reload` after saving and requests reconfiguration of the named interface if it already exists. When exported elsewhere, the private `.netdev` has mode `0600`. When deploying it manually, install it as `root:systemd-network` with mode `0640` so the service can read the key. Unwarp sets that group and mode when writing directly to the system directory as root. [systemd.netdev](https://www.freedesktop.org/software/systemd/man/latest/systemd.netdev.html) · [systemd.network](https://www.freedesktop.org/software/systemd/man/latest/systemd.network.html) · [networkctl reload](https://www.freedesktop.org/software/systemd/man/latest/networkctl.html)

### Adding a backend

The Cloudflare adapter converts live device data and cached WARP files into the same `WireGuardTunnel` and `RoutePolicy` types. Implement the three operations below and register a module path or `module:object` in `BACKENDS`. The CLI loads the selected backend on demand. File backends share route compaction, DNS reconciliation and staged writes. [Backend contract and registry](unwarp/backends/__init__.py) · [Shared data types](unwarp/model.py)

| Function | Responsibility |
| --- | --- |
| `reserved_interfaces(directory)` | Return interface names already in use by this backend for automatic name allocation. |
| `write_profile(target, tunnel, routes, output)` | Generate and deploy the profile using the normalized peer, WireGuard private key, policy and requested output options. Use `tunnel.mtu` for the interface MTU in bytes. |
| `apply_routes(target, policy, routes)` | Update an existing profile from the new policy. The target is either the saved profile identity or the explicit selector passed to `--apply`. |

## Acknowledgements

Thanks to the teams whose documentation and code guided unwarp's device enrollment and policy updates.

- The **Cloudflare One** team explains how browser sign-in returns a `com.cloudflare.warp://` link to the client and how to copy that link for manual enrollment. [Cloudflare One CLI enrollment guide](https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/manual-deployment/#enroll-using-the-cli)
- **AnimMouse and the wgcf-mesh contributors** documented how to register a WireGuard public key with a Cloudflare Access JWT, then use the issued device token to read the Zero Trust device record and its policy. [Device registration](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md#register-a-client-device-with-a-service-token) · [Reading a registration](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md#get-a-registration)
- **ViRb3 and the wgcf contributors** provided the `GetSourceDevice` reference implementation. Unwarp follows that request when a registration has no `account_id`. [wgcf v2.3.1 source](https://github.com/ViRb3/wgcf/blob/v2.3.1/cloudflare/api.go)

The **OpenAI Codex CLI** inspired the sign-in prompt that lets the user open a link and return to the terminal after signing in. [Codex browser login](https://github.com/openai/codex/blob/main/codex-rs/login/src/server.rs)

Unwarp uses **Mozilla Firefox** protocol handlers to return the browser callback to the local process. Thanks to the **wireguard-tools** contributors for the reference implementation we use to check key compatibility. [Firefox protocol handlers](https://firefox-admin-docs.mozilla.org/reference/policies/handlers/) · [WireGuard key generation](https://www.wireguard.com/quickstart/#key-generation)
