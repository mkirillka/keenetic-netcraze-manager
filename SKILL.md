---
name: keenetic-netcraze-manager
description: Manage Keenetic and Netcraze routers (KN-series, KeeneticOS 4.x/5.x) over RCI, the HTTP-JSON API behind the web panel. Reads KeeneticOS version, running config, interfaces, routes and device lists; shows object-group fqdn domain lists with their dns-proxy routes; edits domain lists and access policies; applies CLI commands with an automatic config backup. Use when a task mentions Keenetic, Netcraze, «кинетик», KeeneticOS, NDMS, ndmc, RCI, KN-1010, KN-1012, KN-1810, KN-1811, KN-2710, KN-3810, Hopper, Giga, Skipper, Speedster, Hero, Peak, Extra, Air, Start, 4G/5G router, home router, or asks to read router settings, list domain groups, add a domain to a domain list, set up split tunneling by domains, dns-proxy route object-group, object-group fqdn, ip policy, access policies, «what is on the router», «which domains are in the list», «router panel does not open», or any read/change of Keenetic router configuration over RCI.
license: MIT
metadata:
  version: 2.0.1
  updated: 2026-11-14
  type: oneshot
---

# Keenetic / Netcraze routers over RCI

An RCI client for any Keenetic or Netcraze router with the HTTP web panel enabled.
Addresses, ports and logins come from a local profile on this machine; passwords come
from the OS keyring. The skill contains no address, login or password of its own, so it
works the same for everyone.

Tested on KeeneticOS 5.1.8 and 4.x. References: `references/`.

## First steps

```sh
cd ~/.agents/skills/keenetic-netcraze-manager    # or wherever the skill is installed
python3 scripts/kn.py routers                    # what is already configured
python3 scripts/kn.py doctor                     # reachability, login, version
```

With no profile yet, run `python3 scripts/kn.py init`: it asks for name, address, port and
password, stores the password in the keychain (macOS) and the profile in
`~/.config/keenetic-skill/routers.json`.

**If `~/.config/keenetic-skill/local-notes.md` exists, read it first.** It holds
machine-local knowledge: which groups mean what, known breakage, what not to touch.
That file is never part of the repository.

## Main rule

**Do not hand-build RCI requests — call the script.**

Hand-rolled requests break at login: `GET /auth` with credentials in the query string
always returns 401. It must be `POST` with `SHA256(challenge + MD5(login:realm:password))`,
and the session cookie has to survive several requests. All of that lives in `scripts/kn.py`.

## Commands

| Command | What it does |
|---|---|
| `init` | setup wizard: profile + password in the keyring |
| `routers` | configured routers, which one is default |
| `doctor` | diagnostics: profile permissions, port, login, version |
| `version` | model, KeeneticOS, uptime, CPU/RAM |
| `config [--out F]` | `show running-config` → file with mode 600 (default under `~/.config/keenetic-skill/backups/`) |
| `show <path>` | GET `/rci/<path>`, e.g. `show/ip/route`, or CLI form `"show ip route"` |
| `groups` | table of `object-group`: type, entry count, `dns-proxy` route, description, plus `ip policy` |
| `domains <group>` | domains of one group; `--out` writes them to a file |
| `cli "<command>"` | one CLI command; modifying commands need `--yes` |
| `apply <file>` | plan only; with `--yes` — backup, apply, `--save` |
| `save --yes` | `system configuration save` |
| `notes` / `note "text"` | read / append local notes |
| `backups [--keep N]` | list backups; `--keep N --yes` prunes old ones |

Pick a router with `-r <name>` (default comes from the profile). For a one-off run without
a profile: `--host 192.168.1.1 --port 80` (plus `--scheme`, `--login`, `--keychain`).
`--json`, `--debug`, `--timeout` and `--ask-password` work with any command and may be
placed before or after the subcommand.

## Safe change procedure

1. `kn.py groups` — see the current state: group names, entry counts, where routes point.
2. `kn.py config` — take a backup. `apply` takes its own, but manual edits deserve a separate one.
3. Build a command file, one command per line. `#` and `!` are comments.
4. `kn.py apply file` — **dry run**, nothing changes on the router.
5. `kn.py apply file --yes --save` — apply and persist.
6. Verify: `kn.py groups`, `kn.py domains <group>`, `kn.py show "show ip route"`.

Domain lists are built one line per command:

```
object-group fqdn domain-list11
include example.com
```

`apply` blocks dangerous lines (`no object-group`, `firewall`, `wireguard`, `ipsec`,
`no interface`, `reboot`, `erase`, `user`, `ip nat`, `ip http/ssh/telnet`) and requires
`--allow-dangerous`. That is a speed bump, not a safety guarantee.

## Traps that save an evening

- **A multi-line command in one `parse` call** → `argument parse error`. Send one line at a time.
- **CLI context lives in the cookie session.** `object-group fqdn X` → `include a.com` → `exit`
  in separate requests behave like one session.
- **Errors arrive as an array** `status: [{status: "error", message: …}]`, not as a string.
  Comparing `status == "error"` will not catch them.
- **`show ip route` returns `route` without `message`** — that is not an empty response.
- **Non-ASCII text in `show running-config`** arrives as `\xd0\x9f\xd0\xbe…` escapes; the script decodes it.
- **Entering a group context updates `Last change`** but not `Md5 checksum`.
  Verify "nothing broke" with the md5, not the timestamp.
- **`show/object-group` returns nothing** — lists are readable only from `show running-config`.
- **Split tunneling depends on DNS.** If a client uses another DNS server and bypasses the
  router, domains are never tagged: the list exists but has no effect.
- **While an interface shows `link: down`**, tunnel routes are not installed — list edits are
  safe but have no visible effect.
- **The panel port varies**: 80 by default, 777 on some models/firmware, 443 for HTTPS.

## Do not do without an explicit request

Do not touch tunnels or the firewall; do not save the config "just in case"; do not print the
whole config into chat or a ticket (it contains the ISP password, tunnel keys, Wi-Fi PSK);
do not delete existing groups or domains.

## Local data and privacy

Everything personal lives in `~/.config/keenetic-skill/` (override: `KEENETIC_HOME`), outside git:

| File | Mode | Contents |
|---|---|---|
| `routers.json` | 600 | addresses, ports, logins, keyring entry names |
| `local-notes.md` | 600 | quirks of these routers, "do not touch" list |
| `backups/` | 700 | config dumps — **contain router secrets** |

Record new knowledge about a specific router locally: `kn.py note "…"`. Do not add it to
the skill or to git.

## References

- `references/rci-protocol.md` — how RCI works: login, cookie session, parse, errors, encoding.
- `references/cli-cheatsheet.md` — common commands: reading, lists, dns-proxy, policies, save.
- `references/setup.md` — install, profile, passwords, ports per model, permissions.
- `references/troubleshooting.md` — symptom table for connection, login and split-tunnel issues.
