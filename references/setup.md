# Install and setup

The skill stores nothing about a particular router. Everything personal lives in a separate
directory on this machine and never enters git.

## 1. Install

```sh
mkdir -p ~/.agents/skills
git clone https://github.com/mkirillka/keenetic-netcraze-manager.git \
  ~/.agents/skills/keenetic-netcraze-manager
```

The repository root **is** the skill directory, so the clone lands exactly where agent
runtimes look for skills. Other supported locations: `~/.config/opencode/skills/` (symlink or
clone there instead), and project-local `.opencode/skills/` or `.agents/skills/`.

Requirements: Python 3.8+, standard library only. No `curl`, no third-party packages.

## 2. Configure the profile

```sh
cd ~/.agents/skills/keenetic-netcraze-manager
python3 scripts/kn.py init
```

The wizard asks:

| Question | Default | Notes |
|---|---|---|
| Router name | `router` | ASCII, used as `-r <name>` |
| Address | `192.168.1.1` | local panel address |
| Panel port | `80` | 777 on some models, 443 for HTTPS |
| Login | `admin` | web panel user |
| Password | — | input is not echoed |

The password goes to the OS keyring: macOS Keychain (`security`), Linux libsecret
(`secret-tool`). If neither exists, the wizard explains how to pass it via an environment
variable.

Result — `~/.config/keenetic-skill/routers.json` (mode 600):

```json
{
  "default": "router",
  "routers": {
    "router": {
      "label": "home",
      "host": "192.168.1.1",
      "port": 80,
      "scheme": "http",
      "login": "admin",
      "keychain": "keenetic-router"
    }
  }
}
```

Several routers are several entries; `default` is the one used without `-r`.

Verify:

```sh
python3 scripts/kn.py routers     # what is configured
python3 scripts/kn.py doctor      # port, login, version
```

## 3. Where the password comes from

First match wins:

1. `KEENETIC_PASSWORD` — environment variable (handy for one-off runs);
2. `KEENETIC_PASSWORD_FILE` — path to a file with the password (mode 600);
3. OS keyring: macOS Keychain by the `keychain` name (`security`), on Linux `secret-tool`;
4. `--ask-password` — prompt in the terminal (needs a TTY).

The password is never printed: messages mention only the keyring entry name. `--debug` prints
method, path and status code — never bodies or cookies. Response bodies pass through a
redacting filter (`password`, `wpa psk`, `pre-shared-key`, `private-key`) before printing.

## 4. Panel ports

| Model / firmware | Usual port | Notes |
|---|---|---|
| most home models (Giga, Extra, Peak, Hero, Skipper, Air, Start …) | 80 | port 80 open by default |
| some models and firmware builds | 777 | port 80 closed, 443 redirects there |
| with HTTPS enabled | 443 | then set `"scheme": "https"` |

If `doctor` reports `Connection refused`, it is almost always the wrong port. Check what is
open:

```sh
for p in 80 443 777; do nc -z -G 2 192.168.1.1 $p && echo "$p open"; done
```

The port is also visible in the panel under "Management" → "General settings", where HTTP/HTTPS
access is configured.

## 5. File permissions

| Path | Mode | Why |
|---|---|---|
| `~/.config/keenetic-skill/` | 700 | contains addresses and notes |
| `routers.json` | 600 | addresses, logins, keyring entry names |
| `local-notes.md` | 600 | network quirks, "do not touch" list |
| `backups/` | 700 | config dumps with router secrets |

`kn.py doctor` checks the profile permissions and warns when they are wider than 600.

## 6. Local notes

Anything specific to your routers goes into local notes:

```sh
python3 scripts/kn.py note "office router: panel on 777, tunnel currently down"
python3 scripts/kn.py notes
```

`~/.config/keenetic-skill/local-notes.md` never enters git. Agents read it at the start of
work when it exists, which replaces knowledge hardcoded into the skill.

## 7. Multiple routers

```sh
python3 scripts/kn.py init --name home  --host 192.168.1.1 --port 80
python3 scripts/kn.py init --name dacha --host 192.168.1.1 --port 777
python3 scripts/kn.py routers
python3 scripts/kn.py version -r dacha
```

Addresses may coincide (both routers can be `192.168.1.1` in their own networks) — the profile
keeps them apart by name. Only one is reachable at a time, so run a given command while
connected to the matching network.

## 8. Uninstall

```sh
rm -rf ~/.agents/skills/keenetic-netcraze-manager   # the skill
rm -rf ~/.config/keenetic-skill                     # profile, notes, backups
security delete-generic-password -s keenetic-router # per the name in the profile
```
