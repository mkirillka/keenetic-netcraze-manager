# Symptoms and what to check

Always start with these two commands:

```sh
python3 scripts/kn.py routers     # what is configured
python3 scripts/kn.py doctor      # port, login, version
```

## Connection and login

| Symptom | Cause | Fix |
|---|---|---|
| `Connection refused` / `cannot reach` | wrong port, or this machine is on another network | check the port (`nc -z IP 80/443/777`), check you are on the router's LAN |
| `GET /auth returned HTTP 404` | hit another device or another service | open the address in a browser — you should see a Keenetic/Netcraze panel |
| `login failed (HTTP 401)` | wrong password, wrong login, or the password of another router | `security add-generic-password -U -s keenetic-<name> -a admin -w '…'` |
| `no password available` | no keyring entry and no environment variable | `kn.py init`, or `export KEENETIC_PASSWORD=…` |
| `router requires NDSSO sign-in` | cloud sign-in enabled | create a local user with a password and use it |
| `cannot read profile` | broken JSON in `routers.json` | fix the file, or re-run `kn.py init` |
| Password longer than 32 characters rejected | firmware limit | choose a shorter password |
| Works in the browser but not from the script | panel session limit or a captive portal in front | log out of the panel, check you are not behind a guest portal |

The classic mistake: sending `GET /auth` with credentials in the query string. That returns
401 **always**, even with the right password. It must be `POST` with the hash
(see `rci-protocol.md`).

## Reading and parsing

| Symptom | Cause | Fix |
|---|---|---|
| `argument parse error` | several lines sent in one `parse` | send one command per call; `kn.py apply` already does |
| Empty output for a working command | the response has no `message` (`show ip route` returns `route`) | use `--json` |
| Config contains `"\xd0\x9f\xd0\xbe…"` | the router escapes non-ASCII | `kn.py` decodes it; external scripts must do the same |
| `show/object-group` is empty | data lives only in `show running-config` | use `kn.py groups` |
| `HTTP 404` on `show/wireguard`, `show/startup-config` | the path does not exist in that firmware | read `show/interface` and the config |
| Command error not visible | it is inside the `status` array, not a string | `kn.py` iterates the array and prints the router's text |

## Split tunneling by domain does not work

Check in order:

1. `kn.py groups` — does the group have a route (`dns-proxy route object-group ...`)?
   A list without a route has no effect at all.
2. `kn.py show show/interface` — does the tunnel interface show `link: up`? While it is `down`,
   routes into the tunnel are not installed and edits have no visible effect.
3. Where does the client's DNS go? If the device is configured with a third-party DNS server
   (corporate, public), the router never sees answers and cannot tag addresses.
   Check: `scutil --dns` (macOS), `resolvectl status` (Linux), Wi-Fi settings on mobile.
   Fix: set DNS to the router address, or hand out DNS via DHCP from the router.
4. Is the domain actually in the list? `kn.py domains <group> | grep <domain>`.
   Subdomains must be listed separately.
5. Client DNS cache: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder` (macOS),
   `resolvectl flush-caches` (Linux).
6. Browser or OS may cache the resolved address: restart the browser, or check with
   `dig example.com` whether the answer differs from what the router sees.

## Changes did not survive a reboot

`system configuration save` was not run. Use `kn.py apply ... --save` or `kn.py save --yes`.
Verify it went through: run `kn.py config` again and compare `Md5 checksum`.

## Backups take space

```sh
python3 scripts/kn.py backups              # list with sizes
python3 scripts/kn.py backups --keep 10    # preview pruning
python3 scripts/kn.py backups --keep 10 --yes
```

One config dump is tens of kilobytes; growth is slow but frequent `apply` runs add up.
The files contain router secrets.

## Router behaves strangely

- `kn.py version` — small uptime means the router rebooted on its own (power, firmware crash).
- `kn.py show show/system` — `cpuload`, memory (`memory`), connection count.
- `kn.py show "show ip hotspot host"` — who is on the network.
- Logs live in the panel ("Diagnostics" → "Log"); there is no reliable RCI path to them.

## The script reports "someone else changed the config"

`apply` compares nothing, so this is a manual observation: the `Last change` stamp moved
between your own snapshots. Another administrator or an app (mobile client, cloud service)
can modify the router concurrently. The backup taken before your `apply` shows the state at
that moment; diff it against an older dump to see the foreign change.
