# Unwarp.py
Parse CloudFlare WARP configuration and create NetworkManager .nmconnection basing on it

# Usage example:
```
# unwarp.py -r -f -4 -i ztn0 -n cloudflare.ztn -s "cloudflare.com google.com microsoft.com"
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
