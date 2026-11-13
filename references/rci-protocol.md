# RCI: how the Keenetic / Netcraze API works

RCI (Remote Control Interface) is the HTTP-JSON API of KeeneticOS — the same engine the web
panel talks to. Authentication is therefore not HTTP Basic but the panel's challenge scheme.

Verified on KeeneticOS 4.x and 5.1.8, 2026. The same API is exposed by devices sold under
both the Keenetic and Netcraze brands (identical firmware lineage).

## 1. Login

A plain `GET /auth?login=...&password=...` returns **401 every time** — it is about the
method, not the password. The correct flow:

```
GET /auth
  → 401 + X-NDM-Realm, X-NDM-Challenge headers + Set-Cookie (session cookie, Max-Age=300)

md5  = MD5("login:realm:password")
sha  = SHA256(challenge + md5)

POST /auth   Content-Type: application/json
  {"login":"admin","password":"<sha>"}
  → 200 {"ndsso":false,"method":"x-ndw2-interactive"}
```

Every later request carries that cookie. It lives 5 minutes and is extended by use.

Traps:

- **Port.** Usually 80, on some models/firmware 777 (panel moved off 80), sometimes 443 with
  `https`. A wrong port looks like `Connection refused` or a reply without `X-NDM-*` headers.
- **The password is the web panel password**, not the Wi-Fi or ISP one.
- `X-NDM-Realm` is the router name (for example `Keenetic Hopper`) and is part of the hash.
  It cannot be substituted.
- `"ndsso": true` means cloud (Keenetic account) sign-in; this tool does not support it.
  Use a local user with a password.

## 2. Reading: GET /rci/<path>

`GET /rci/show/version` returns plain JSON. The path is a CLI command with slashes instead
of spaces.

| Path | Returns |
|---|---|
| `show/version` | model, `title` (e.g. 5.1.8), `release`, arch, ndw3/ndw4 components |
| `show/system` | `uptime` (seconds), `cpuload`, `memory`, `hostname` |
| `show/interface` | interfaces: `state`, `link`, addresses, counters |
| `show/ip/route` | routing table |
| `show/ip/hotspot/host` | LAN clients: MAC, IP, name, uptime |
| `show/ip/policy` | access policies, rules and route tables |
| `show/dns-proxy` | DNS proxy settings |
| `show/ndns` | KeenDNS |
| `show/user` | accounts |
| `show/object-group` | **empty** — object lists are exposed only via `show running-config` |

Some paths 404 depending on firmware and installed components (`show/wireguard`,
`show/startup-config`, `show/ip/name` were missing on tested units). Interfaces such as
`Wireguard0` are visible in `show/interface` and in the config.

## 3. Commands: POST /rci/ with parse

```json
{"parse": "show running-config"}
```

Response for commands with text output:

```json
{"parse": {"prompt": "(config)", "message": ["line", "line"]}}
```

Traps:

- **A multi-line command in one `parse` is rejected** with `argument parse error`.
  Send one command per request.
- **CLI context is kept for the cookie session.** Separate requests
  `object-group fqdn X` → `include a.com` → `exit` behave as one session.
  The current context appears in `prompt`: `(config)`, `(config-ogrp-fqdn)`.
- A response without `message` is not an error: `show ip route` returns `route` directly,
  `show ip policy` returns `policy`. The script prints JSON in that case instead of nothing.
- Errors are reported in an array, not in a `status` string:

```json
{"parse": {"status": [{"status": "error", "code": "7405600",
                       "ident": "Command::Base",
                       "message": "no such command: nosuchcommand."}]}}
```

  Comparing the `status` value with `"error"` misses them — you must iterate the array.
  `kn.py` does that and raises an exception with the router's own text.
- Success is also an array: `{"status": [{"status": "message", "message": "done."}]}`.
- The structured style `{"object-group": {"fqdn": {"include": ...}}}` does **not** work for
  `include`. Only step-by-step `parse` does.

## 4. Non-ASCII encoding

The router encodes non-ASCII text inconsistently:

- `show/ip/policy` — proper UTF-8;
- `show running-config` — literal escape sequences `\xd0\x9f\xd0\xbe…` inside the JSON string
  (double escaping).

Without decoding, config descriptions read `"\xd0\x9f\xd0\xbe..."`. `kn.py` unescapes `\xNN`
and falls back to latin-1 → UTF-8 (`fix_text`).

## 5. Save and backup

- `{"parse": "system configuration save"}` — running-config → startup-config. Without it,
  changes last until reboot.
- `show running-config` is the only complete and reliable source of state: lists, routes,
  policies, tunnels, secrets. The dump contains **the ISP password, tunnel private keys and
  PSKs**. Keep it at mode 600, never commit it.
- The config header has two stamps: `! $$$ Last change:` (time; updated even by entering a
  context without changes) and `! $$$ Md5 checksum:` (changes only when content changes).
  Only the md5 is usable to prove "nothing broke".

## 6. Minimal Python client

```python
import hashlib, http.cookiejar, json, urllib.error, urllib.request

base = "http://192.168.1.1"                  # add the port when it is not 80
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

try:
    opener.open(base + "/auth")
except urllib.error.HTTPError as e:          # the expected 401
    realm, challenge = e.headers["X-NDM-Realm"], e.headers["X-NDM-Challenge"]

md5 = hashlib.md5(f"admin:{realm}:{password}".encode()).hexdigest()
sha = hashlib.sha256((challenge + md5).encode()).hexdigest()
req = urllib.request.Request(base + "/auth",
                            data=json.dumps({"login": "admin", "password": sha}).encode(),
                            headers={"Content-Type": "application/json"})
opener.open(req)
```

A complete client lives in `scripts/kn.py`. Do not duplicate it in other scripts — call it
from the CLI or import it as a module.
