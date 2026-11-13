# CLI cheat sheet for Keenetic / Netcraze over RCI

Every command goes on its own line into `POST /rci/ {"parse": "<command>"}`
(see `rci-protocol.md`). Through the script: `python3 scripts/kn.py cli "show ip route"`.

## Reading (safe, changes nothing)

| Command | Shows |
|---|---|
| `show version` | KeeneticOS, model, components |
| `show system` | uptime, CPU, memory, hostname |
| `show interface` | interfaces, `state`/`link`, addresses, counters |
| `show ip route` | routing table |
| `show ip route 8.8.8.8` | which route is chosen for an address |
| `show ip hotspot host` | LAN clients |
| `show ip policy` | access policies and their rules |
| `show dns-proxy` | DNS proxy settings |
| `show running-config` | the whole config, line by line (answer is a `message` array) |
| `show ndns` | KeenDNS |

`kn.py groups` and `kn.py domains <group>` do not dump the whole config: they parse
`show running-config` and print only the lists — cheaper, and it does not expose secrets.

## Domain lists

A list is an `object-group fqdn <name>` holding domains. One group is one list and is routed
as a whole.

```
object-group fqdn domain-list0
    description youtube
    include youtube.com
    include googlevideo.com
exit
```

Rules:

- **One line per `parse` call.** A multi-line block in one request is rejected
  (`argument parse error`).
- CLI context persists across requests in the session: `object-group fqdn X`, then
  `include a.com`, then `include b.com` — all land in `X`. A subsequent
  `object-group fqdn Y` switches to `Y` from that context.
- Domains are exact (`example.com`) — no wildcards, no regexes. Subdomains must be listed
  separately.
- Remove one domain: `no include a.com`. Remove the whole list: `no object-group fqdn X`
  (dangerous; `apply` blocks it without `--allow-dangerous`).
- **Entering a group updates `! $$$ Last change`** in the config even if nothing was changed.
  Content stays the same (`Md5 checksum` unchanged). Verify untouched config by the md5.

## Routing a list through a tunnel

```
dns-proxy route object-group domain-list0 Wireguard0 auto
```

This is the "domains → interface" binding. Without it the list just sits there and has no
effect. To remove: `no dns-proxy route object-group domain-list0 Wireguard0 auto`.

It only works when DNS queries actually go **through the router**. If a client is configured
with a third-party DNS server (corporate, public), the router never sees the answers and
cannot tag the addresses — the classic "the list exists but the site does not open" case.

While an interface shows `link: down`, tunnel routes are not installed: list edits are safe
but produce no effect.

## Access policies (ip policy)

```
ip policy Policy0
    description "full tunnel"
    permit global Wireguard0
    no permit global GigabitEthernet0/Vlan2
exit
```

A policy is a set of `permit` / `no permit` entries over interfaces, assigned to a client or
a profile. Who goes where: `show ip policy` (it also lists per-policy route tables).

## Saving

```
system configuration save
```

Without it, changes last until reboot. `kn.py apply` saves only with `--save`; standalone
command is `kn.py save --yes`.

## Avoid unless explicitly asked

- `no interface ...`, `interface ... shutdown` — cuts connectivity, possibly to the router itself.
- `firewall`, `ip firewall` — filtering; easy to lock yourself out.
- `wireguard`, `ipsec`, `vpn-server` — tunnels; server access may depend on them.
- `user`, `password`, `ip http`, `ip telnet`, `ip ssh`, `ip ndm` — management access.
- `erase`, `reboot` — wipe and reboot.
- `ip nat`, `ip static` — NAT and static routes.

`kn.py apply` blocks these lines and requires `--allow-dangerous`. The block is a speed bump,
not a guarantee: think anyway.

## Verifying a change

```sh
python3 scripts/kn.py groups                     # groups, entry counts, routes
python3 scripts/kn.py domains domain-list0       # what is really in the group
python3 scripts/kn.py show "show ip route"       # routes did not fall apart
python3 scripts/kn.py show show/interface        # link/state of the tunnel interface
```

From outside: `dig example.com`, `curl -sS -o /dev/null -w '%{http_code}' https://example.com`.
