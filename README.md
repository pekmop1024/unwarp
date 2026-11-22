# Unwarp.py

Generate a NetworkManager WireGuard profile from a Cloudflare WARP configuration and refresh its IP routes from the registered device's split-tunnel policy.

## Fetch current routes

From the repository directory, run

```sh
sudo python3 ./unwarp.py routes
```

This makes one HTTPS GET using `registration_id` and `api_token` from `/var/lib/cloudflare-warp/reg.json`. Cloudflare returns the full device policy. Unwarp selects IPv4 prefixes locally by default. Pass `--dual-stack` to include IPv6, or `-4` / `--ipv4only` to select IPv4 explicitly.

The printed JSON contains the split-tunnel mode, the corresponding `include` or `exclude` CIDRs, `domains`, `always_include` and `always_exclude`. It reads directly from Cloudflare and works with `warp-svc` stopped. Use `-w PATH` to select a different registration file.

Registrations with an `account_id` use the Zero Trust device API. Registrations without it use wgcf v2.3.1's `GetSourceDevice` endpoint. Both paths use the device's existing credential. A successful preview confirms that this registration can read this policy. [Zero Trust registration API](https://github.com/AnimMouse/wgcf-mesh/blob/main/API.md) · [wgcf API implementation](https://github.com/ViRb3/wgcf/blob/v2.3.1/cloudflare/api.go)

## Update a WireGuard profile

To fetch and apply the current IP routes to a dedicated unwarp profile, run

```sh
sudo python3 ./unwarp.py routes --apply cloudflare.ztn
```

The profile must already exist in NetworkManager. `--apply` accepts its name or UUID. By default it replaces only the profile's static IPv4 routes, including routes added by hand. Add `--dual-stack` to also sync IPv6 routes on an IPv6-enabled profile. Unwarp includes the profile generator's DNS route `1.1.1.1/32`, adds mandatory includes and subtracts mandatory exclusions. Domain rules appear in the preview and require DNS-based routing beyond this IP sync. Exclude-mode policies can be previewed.

NetworkManager saves the selected route changes together. An active profile is reapplied in place. An inactive profile receives the new routes on its next activation. A fetch error, missing policy or unsupported mode exits nonzero before changing the profile. If NetworkManager saves the profile but fails to reapply it, the command exits nonzero and the next run retries.

For example, a root crontab can refresh a profile every 15 minutes. Substitute the absolute path to your checkout.

```cron
*/15 * * * * /usr/bin/python3 /opt/unwarp/unwarp.py routes --apply cloudflare.ztn
```

## Generate the initial profile from local files

New profiles use IPv4 by default. Add `--dual-stack` when generating a profile to enable both IPv4 and IPv6.

```
# unwarp.py -r -f -i ztn0 -n cloudflare.ztn -s "cloudflare.com google.com microsoft.com"
INFO    - reading file: /var/lib/cloudflare-warp/conf.json
INFO    - reading file: /var/lib/cloudflare-warp/reg.json
INFO    - adding following domains search in ipv4 section: cloudflare.com google.com microsoft.com
INFO    - disabling ipv6 in networkmanager wireguard connection configuration
INFO    - file exists, overwriting: /etc/NetworkManager/system-connections/cloudflare.ztn.nmconnection
INFO    - setting permissions to 600: /etc/NetworkManager/system-connections/cloudflare.ztn.nmconnection
INFO    - reloading networkmanager configuration
```

**NOTE**: Script needs root privileges to successfully read Cloudflare WARP configuration and write NetworkManager system connection.

If you don't like the idea running it with root privileges, you can allow your user to read/write these locations, or copy these files to temporary location, run script to generate .nmconnection and place it to /etc/NetworkManager/system-connections/ manually (or by own script).
