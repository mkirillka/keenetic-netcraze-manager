# Keenetic / Netcraze Manager — an agent skill for routers

[![tests](https://github.com/mkirillka/keenetic-netcraze-manager/actions/workflows/tests.yml/badge.svg)](https://github.com/mkirillka/keenetic-netcraze-manager/actions/workflows/tests.yml)

Talk to a **Keenetic** or **Netcraze** router from the command line or from an AI coding
agent. Read what is configured, manage `object-group fqdn` domain lists, wire them into
DNS-based split tunneling, inspect access policies, and apply CLI commands with an automatic
config backup — all over **RCI**, the HTTP-JSON API behind the router web panel.

No address, login or password is baked into the code. Everything site-specific stays in a
local profile on your machine.

Works with KeeneticOS 4.x and 5.x, on macOS and Linux, standard-library Python only.

```
$ python3 scripts/kn.py version
Router:      home (living room)
Address:     http://192.168.1.1:80
Model:       Giga (KN-1012)
KeeneticOS:  5.1.8  [5.01.C.8.0-2, stable]
Arch:        aarch64
Uptime:      12d 4h
CPU / RAM:   3% / 118544/262144 KB

$ python3 scripts/kn.py groups
Router home (living room), http://192.168.1.1:80
object-groups: 12, entries total: 1076

  #  group            type     entries  route                            description
-------------------------------------------------------------------------------------
  1  domain-list0     fqdn         175  Wireguard0 auto                  youtube
  2  domain-list1     fqdn          72  Wireguard0 auto                  instagram
  3  domain-list2     fqdn         191  Wireguard0 auto                  google
 ...
```

## Why this exists

Keenetic routers expose a capable API, but the first request fails in a way that is easy to
misread: `GET /auth` with a login and password in the query string returns **401 every time**,
even with the correct password. The panel actually uses a challenge:

```
GET  /auth                     → 401 + X-NDM-Realm, X-NDM-Challenge, session cookie
sha  = SHA256(challenge + MD5("login:realm:password"))
POST /auth {"login":…, "password":sha}  → 200 + session cookie
POST /rci/ {"parse": "<one CLI command>"}
GET  /rci/<path>               → JSON
```

On top of that, a few behaviours bite anyone who automates this: multi-line commands are
rejected, CLI context is carried by the cookie session, errors arrive as an array rather than
a string, and non-ASCII text comes back as `\xNN` escapes. This skill handles all of it.

## What it can do

| Command | What it does |
|---|---|
| `init` | setup wizard: address, port, login, password → local profile + OS keyring |
| `routers` | list configured routers, show the default |
| `doctor` | diagnose: profile permissions, port reachability, login, firmware version |
| `version` | model, KeeneticOS, architecture, uptime, CPU and memory |
| `config` | full `show running-config` into a file with mode 600 |
| `show <path>` | any RCI path — `show/ip/route`, `show/interface` — or CLI form `"show ip route"` |
| `groups` | table of `object-group`: type, entry count, `dns-proxy` route, description; plus `ip policy` |
| `domains <group>` | domains of one list, optionally to a file |
| `cli "<command>"` | one CLI command; modifying ones need `--yes` |
| `apply <file>` | plan first, then with `--yes`: backup, apply, optional save |
| `save` | `system configuration save` |
| `notes` / `note` | read or append local notes |
| `backups` | list backups, prune old ones with `--keep N` |

Safe by default: `apply` shows the plan and changes nothing until you pass `--yes`. Before
the first modifying command it takes a config backup, and it refuses to proceed if that
backup fails. Commands that can cut your access (`firewall`, `wireguard`, `no object-group`,
`reboot`, `erase`, `user`, `ip nat`, `ip http/ssh/telnet`) are blocked unless you pass
`--allow-dangerous`.

## Install

```sh
mkdir -p ~/.agents/skills
git clone https://github.com/mkirillka/keenetic-netcraze-manager.git \
  ~/.agents/skills/keenetic-netcraze-manager
```

The repository root is the skill directory, so the clone lands where agent runtimes look for
skills (`~/.agents/skills`, `~/.config/opencode/skills`, project-level `.agents/skills`).

Prefer a symlink so `git pull` keeps it fresh:

```sh
./install.sh                      # links into ~/.config/opencode/skills
./install.sh --dry-run            # show what would happen
./install.sh --dest ~/.agents/skills
```

Requirements: Python 3.8+. Nothing else — no `curl`, no pip packages.

## Setup

```sh
cd ~/.agents/skills/keenetic-netcraze-manager
python3 scripts/kn.py init
```

The wizard asks for a router name, address (`192.168.1.1` by default), panel port
(80 usually, 777 on some models, 443 for HTTPS), login (`admin`) and password. The password
goes into the OS keyring — macOS Keychain or Linux `secret-tool` — and the profile into
`~/.config/keenetic-skill/routers.json` with mode 600.

Password lookup order at runtime: `KEENETIC_PASSWORD` → `KEENETIC_PASSWORD_FILE` → OS keyring
→ `--ask-password`.

The wizard can only *write* to the keyring on macOS (`security`). On Linux the wizard stores the
profile and tells you how to add the password yourself — read access works through `secret-tool`:

```sh
secret-tool store --label="keenetic-home" service keenetic-home
export KEENETIC_PASSWORD=…        # or a 600 file via KEENETIC_PASSWORD_FILE
```

On Windows use `KEENETIC_PASSWORD` or `KEENETIC_PASSWORD_FILE`.

Check it end to end:

```sh
python3 scripts/kn.py routers
python3 scripts/kn.py doctor
```

## Common workflows

**Inspect a domain list and where it routes**

```sh
python3 scripts/kn.py groups
python3 scripts/kn.py domains domain-list0
```

**Add a domain to an existing list**

```sh
cat > add.cli <<'EOF'
object-group fqdn domain-list11
include example.com
EOF

python3 scripts/kn.py apply add.cli                # dry run
python3 scripts/kn.py apply add.cli --yes --save   # apply and persist
```

**Wire a list into a tunnel (split tunneling by domain)**

```
object-group fqdn domain-list11
include github.com

dns-proxy route object-group domain-list11 Wireguard0 auto
```

Split tunneling works only for addresses the router itself saw in DNS answers. If a client
uses a third-party DNS server, the router cannot tag anything — see
`references/troubleshooting.md`.

**One-off against a router you have not configured**

```sh
KEENETIC_PASSWORD='…' python3 scripts/kn.py version --host 192.168.1.1 --port 777
```

## Limitations and caveats

Honest list of what this skill does not do, or does with caveats.

**RCI and firmware**

- No NDSSO support (Keenetic cloud sign-in). You need a local user with a password.
- `{"parse": "…"}` accepts **one line only**; a multi-line block is rejected with
  `argument parse error`. Lists are therefore built command by command.
- The structured RCI style (`{"object-group": {"fqdn": {...}}}`) does not work for `include`;
  only step-by-step `parse` does. This skill uses `parse`.
- Available `show/*` paths vary by firmware: `show/wireguard`, `show/startup-config`,
  `show/ip/name` return 404 on some versions. Use `show/interface` for tunnels.
- `show/object-group` returns nothing — lists come only from `show running-config`.
- There is no RCI path to the system log; use the web panel.
- Errors and successes both arrive as `status` arrays; naive implementations miss them.
- Non-ASCII text in `show running-config` is double-escaped (`\xd0\x9f…`). The script
  decodes it, but raw `--json` output still needs decoding in your own tooling.

**Ports and models**

- The panel port varies: 80 by default, 777 on some models/firmware, 443 with HTTPS.
  `Connection refused` almost always means the wrong port.
- Default address and login are identical across devices (`192.168.1.1`, `admin`), so
  profile entries are distinguished only by name — easy to confuse two routers.

**Safety**

- The dangerous-command filter is a speed bump, not a guarantee. `--allow-dangerous`
  bypasses it.
- The password stays in process memory; it is never printed, logged or written to disk. But
  `KEENETIC_PASSWORD` is visible to other processes of the same user — prefer the keyring.
- Config dumps contain secrets (ISP password, tunnel private keys, Wi-Fi PSK). `apply` takes
  a backup automatically and aborts if it cannot.
- The script does not lock out other administrators: a concurrent change by someone else or by
  the mobile app shows up only as a diff against your own backup.

**Split tunneling by domain** — a common goal, not magic

- A list without `dns-proxy route object-group <group> <interface> auto` does nothing.
- Tagging relies on DNS answers the router sees. Clients with a third-party DNS server bypass it.
- While a tunnel interface shows `link: down`, routes are not installed: edits are safe but
  have no visible effect.
- Client-side DNS caches must be flushed separately.

**Small stuff**

- `apply` stops at the first error; `--keep-going` continues and reports at the end.
- `system configuration save` is never automatic: without `--save`, changes last until reboot.
- Backups are not pruned automatically: `backups --keep N --yes`.
- To prove "nothing broke", compare the `Md5 checksum` in the config header. The
  `Last change` stamp is updated even by entering a group context without changes.
- IPv6-specific commands are not modelled; use the free-form `cli`.
- Verified on macOS (Keychain) and partially on Linux (`secret-tool`). On Windows, use
  `KEENETIC_PASSWORD` or `KEENETIC_PASSWORD_FILE`.

## Privacy

Everything site-specific lives in `~/.config/keenetic-skill/` (override with `KEENETIC_HOME`),
outside the repository:

| File | Mode | Contents |
|---|---|---|
| `routers.json` | 600 | addresses, ports, logins, keyring entry names |
| `local-notes.md` | 600 | your own notes about these routers |
| `backups/` | 700 | config dumps — contain router secrets |

Publish nothing from there. The repository `.gitignore` also excludes these names, in case
someone copies them into the skill folder by mistake.

## Tests

```sh
python3 tests/test_kn.py        # 47 offline checks, no network, no router
```

Covered: `show running-config` parsing (groups, routes, policies), non-ASCII decoding, secret
redaction, the dangerous-command filter, profile resolution, password source priority, the `init`
wizard with and without a working keyring, file permissions, version sync between `kn.py` and
`SKILL.md`, and a guard that fails if personal data appears in the skill files.

CI runs the same suite on Python 3.8, 3.11 and 3.13 for every push and pull request.

## Layout

```
SKILL.md                        agent instructions
README.md                       this file
LICENSE                         MIT
install.sh                      symlink installer
scripts/kn.py                   RCI client (stdlib only)
references/rci-protocol.md      protocol: login, session, parse, errors, encoding
references/cli-cheatsheet.md    common CLI commands
references/setup.md             install, profile, passwords, ports, permissions
references/troubleshooting.md   symptoms and what to check
tests/test_kn.py                offline tests
```

## License

MIT — see [LICENSE](LICENSE).

Not affiliated with Keenetic Ltd. Keenetic and Netcraze are trademarks of their respective
owners. This is an independent client for the documented HTTP API of the devices.
