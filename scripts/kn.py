#!/usr/bin/env python3
"""kn.py — Keenetic / Netcraze RCI client: read state, apply CLI commands safely.

Universal: hosts, ports and logins come from a local profile
(``~/.config/keenetic-skill/routers.json``); passwords come from the OS keychain
or environment variables. No address, login or password is hardcoded here.

Quick start:

    python3 kn.py init                 # setup wizard: address, port, password
    python3 kn.py doctor               # check reachability and login
    python3 kn.py version              # KeeneticOS version, model, uptime
    python3 kn.py groups               # object-group lists, routes, policies

Commands: init, routers, doctor, version, config, show, groups, domains, cli, apply,
save, notes, note, backups.
"""

import argparse
import getpass
import hashlib
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

__version__ = "2.0.1"

# ---------------------------------------------------------------- local data

# Everything personal lives outside the repository and outside the skill folder.
DATA_HOME = os.environ.get("KEENETIC_HOME") or os.path.join(
    os.path.expanduser("~"), ".config", "keenetic-skill"
)

CONFIG_FILE = "routers.json"
NOTES_FILE = "local-notes.md"
BACKUP_SUBDIR = "backups"

DEFAULT_PORT = 80
DEFAULT_LOGIN = "admin"

# Commands that change management access or break connectivity.
# They are applied only with an explicit --allow-dangerous.
DANGEROUS = [
    (r"\berase\b", "config/data wipe"),
    (r"\breboot\b", "reboot"),
    (r"\bshutdown\b", "interface shutdown"),
    (r"^\s*no\s+object-group\b", "deleting a domain/object list"),
    (r"\bfirewall\b", "firewall"),
    (r"\bwireguard\b|\bipsec\b|\bvpn-server\b|\bamnezia\b", "tunnels and VPN"),
    (r"\buser\b|\bpassword\b|\bndsso\b", "accounts and access"),
    (r"\bip\s+http\b|\bip\s+telnet\b|\bip\s+ssh\b|\bip\s+ndm\b", "management access"),
    (r"\bip\s+nat\b|\bip\s+static\b", "NAT and static routes"),
    (r"\binterface\b.*\b(no\s+)?(ip\s+address|security-level)\b", "interface addressing"),
]


class RciError(Exception):
    """An error that should be shown to the user as is, without a traceback."""


class ConfigError(RciError):
    """A problem with the local profile or the password."""


# ---------------------------------------------------------------- helpers


def hget(headers, name):
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return None


def redact(text):
    """Strip anything that looks like a secret before printing."""
    if not text:
        return text
    text = re.sub(r'("password"\s*:\s*)"[^"]*"', r'\1"<hidden>"', text)
    text = re.sub(r"(wpa\s+psk\s+\S+\s+)\S+", r"\1<hidden>", text)
    text = re.sub(r"(pre-shared-key\s+)\S+", r"\1<hidden>", text)
    text = re.sub(r"(private-key\s+)\S+", r"\1<hidden>", text)
    return text


def snippet(body, limit=300):
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    text = redact(text).strip().replace("\n", " ")
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def write_private(path, text):
    """Write a file with 600 permissions, creating the directory with 700."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)
    return path


def stamp():
    return time.strftime("%Y%m%d_%H%M%S")


def _json(body):
    if not body:
        return None
    try:
        return fix_text(json.loads(body.decode("utf-8", "replace")))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _unescape_hex(value):
    if "\\x" not in value:
        return value
    buffer = bytearray()
    changed = False
    index = 0
    while index < len(value):
        chunk = value[index + 2:index + 4]
        if value.startswith("\\x", index) and len(chunk) == 2 and all(
            ch in "0123456789abcdefABCDEF" for ch in chunk
        ):
            buffer.append(int(chunk, 16))
            index += 4
            changed = True
            continue
        buffer.extend(value[index].encode("utf-8"))
        index += 1
    if not changed:
        return value
    try:
        return buffer.decode("utf-8")
    except UnicodeDecodeError:
        return value


def fix_text(value):
    """Keenetic sends non-ASCII as \\xNN escapes, not UTF-8 — decode it back."""
    if isinstance(value, str):
        value = _unescape_hex(value)
        if not any(0x80 <= ord(ch) <= 0xFF for ch in value):
            return value
        try:
            return value.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return value
    if isinstance(value, list):
        return [fix_text(item) for item in value]
    if isinstance(value, dict):
        return {key: fix_text(item) for key, item in value.items()}
    return value


# ---------------------------------------------------------------- local profile


def data_home():
    return DATA_HOME


def config_path():
    return os.path.join(data_home(), CONFIG_FILE)


def notes_path():
    return os.path.join(data_home(), NOTES_FILE)


def backups_dir():
    return os.path.join(data_home(), BACKUP_SUBDIR)


def load_profile():
    path = config_path()
    if not os.path.exists(path):
        return {"default": None, "routers": {}}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read profile {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"profile {path} must be a JSON object")
    routers = data.get("routers") or {}
    if not isinstance(routers, dict):
        raise ConfigError(f"field 'routers' in {path} must be an object")
    return {"default": data.get("default"), "routers": routers}


def save_profile(profile):
    path = write_private(config_path(), json.dumps(profile, ensure_ascii=False, indent=2) + "\n")
    return path


def resolve_router(args):
    """Return a dict with host/port/scheme/login/keychain/label/name."""
    profile = load_profile()
    routers = profile["routers"]

    # 1. one-off router from the command line
    host = getattr(args, "host", None) or os.environ.get("KEENETIC_HOST")
    if host:
        return {
            "name": "cli",
            "label": "from command line",
            "host": host,
            "port": int(getattr(args, "port", None) or os.environ.get("KEENETIC_PORT") or DEFAULT_PORT),
            "scheme": getattr(args, "scheme", None) or os.environ.get("KEENETIC_SCHEME") or "http",
            "login": getattr(args, "login", None) or os.environ.get("KEENETIC_LOGIN") or DEFAULT_LOGIN,
            "keychain": getattr(args, "keychain", None) or os.environ.get("KEENETIC_KEYCHAIN") or "",
        }

    # 2. router by name from the profile
    name = getattr(args, "router", None) or os.environ.get("KEENETIC_ROUTER") or profile["default"]
    if not name:
        if not routers:
            raise ConfigError(
                "no routers configured. Run the setup wizard:\n"
                "  python3 kn.py init\n"
                "or pass an address for a single run: kn.py version --host 192.168.1.1 --port 80"
            )
        raise ConfigError(
            "no default router selected. Pass -r <name> or set \"default\" in "
            f"{config_path()}. Available: {', '.join(sorted(routers))}"
        )
    if name not in routers:
        known = ", ".join(sorted(routers)) or "profile is empty"
        raise ConfigError(f"router '{name}' is not in the profile. Available: {known}")

    entry = dict(routers[name])
    entry["name"] = name
    entry.setdefault("label", "")
    entry["port"] = int(entry.get("port") or DEFAULT_PORT)
    entry["scheme"] = entry.get("scheme") or "http"
    entry["login"] = getattr(args, "login", None) or entry.get("login") or DEFAULT_LOGIN
    entry["keychain"] = getattr(args, "keychain", None) or entry.get("keychain") or ""
    if not entry.get("host"):
        raise ConfigError(f"router '{name}' in the profile has no 'host' field")
    return entry


def keychain_lookup(service, account=None):
    """macOS Keychain → password. Returns None if the entry or the tool is missing."""
    if not service or not shutil.which("security"):
        return None
    cmd = ["security", "find-generic-password", "-s", service]
    if account:
        cmd += ["-a", account]
    cmd.append("-w")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    password = proc.stdout.strip()
    return password if proc.returncode == 0 and password else None


def keychain_store(service, account, password):
    if not service or not shutil.which("security"):
        return False
    cmd = ["security", "add-generic-password", "-U", "-s", service, "-a", account, "-w", password]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def secret_tool_lookup(service):
    """Linux: libsecret. Returns None if the tool is missing."""
    if not service or not shutil.which("secret-tool"):
        return None
    try:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", service],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    password = proc.stdout.strip()
    return password if proc.returncode == 0 and password else None


def resolve_password(router, args):
    """Password priority: env → file → OS keyring → interactive prompt."""
    env_password = os.environ.get("KEENETIC_PASSWORD")
    if env_password:
        return env_password

    password_file = os.environ.get("KEENETIC_PASSWORD_FILE")
    if password_file:
        try:
            with open(os.path.expanduser(password_file), encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read KEENETIC_PASSWORD_FILE: {exc}") from None
        if value:
            return value

    service = router.get("keychain") or ""
    password = keychain_lookup(service, router.get("login")) or secret_tool_lookup(service)
    if password:
        return password

    if getattr(args, "ask_password", False) and sys.stdin.isatty():
        return getpass.getpass(f"Password for {router.get('login')}@{router.get('host')}: ")

    service_hint = service or f"keenetic-{router.get('name', 'router')}"
    raise ConfigError(
        "no password available. Pick one of:\n"
        f"  export KEENETIC_PASSWORD='…'                 (current shell only)\n"
        f"  export KEENETIC_PASSWORD_FILE=~/.secret      (file with the password, 600)\n"
        f"  security add-generic-password -s {service_hint} -a {router.get('login')} -w '…'\n"
        f"  python3 kn.py init                           (wizard stores it in the keychain)\n"
        "or run with --ask-password to type it interactively."
    )


# ---------------------------------------------------------------- RCI


class Rci:
    def __init__(self, router, timeout=25, debug=False):
        self.router = router
        self.name = router.get("name", "router")
        self.host = router["host"]
        self.port = int(router.get("port") or DEFAULT_PORT)
        self.login = router.get("login") or DEFAULT_LOGIN
        self.scheme = router.get("scheme") or "http"
        self.timeout = timeout
        self.debug = debug
        self.base = f"{self.scheme}://{self.host}:{self.port}"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self._authed = False

    def _log(self, text):
        if self.debug:
            print(f"[rci] {text}", file=sys.stderr)

    def _req(self, path, data=None, timeout=None):
        headers = {"Accept": "application/json"}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=body, headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with self.opener.open(request, timeout=timeout or self.timeout) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()
        except urllib.error.URLError as exc:
            raise RciError(
                f"cannot reach {self.host}:{self.port} ({self.name}) — {exc.reason}. "
                "Check that this machine is on the same network and the router responds."
            ) from None
        except TimeoutError:
            raise RciError(f"timeout talking to {self.host}:{self.port} ({self.name})") from None

    def auth(self, password=None, args=None):
        """GET /auth → 401 with X-NDM-Realm and X-NDM-Challenge → POST /auth with SHA256."""
        self._log(f"GET {self.base}/auth")
        code, headers, _ = self._req("/auth")
        if code == 200:
            self._authed = True
            self._log("session already active (HTTP 200)")
            return "session already active"

        realm = hget(headers, "X-NDM-Realm")
        challenge = hget(headers, "X-NDM-Challenge")
        if code != 401 or not realm or not challenge:
            raise RciError(
                f"GET /auth returned HTTP {code} without X-NDM-Realm/Challenge headers. "
                "This does not look like a Keenetic/Netcraze device or the port is wrong."
            )

        secret = password or resolve_password(self.router, args or argparse.Namespace())
        md5 = hashlib.md5(f"{self.login}:{realm}:{secret}".encode()).hexdigest()
        sha = hashlib.sha256((challenge + md5).encode()).hexdigest()
        del secret

        code, _, body = self._req("/auth", {"login": self.login, "password": sha})
        del sha
        if code != 200:
            raise RciError(
                f"login failed (HTTP {code}): wrong login '{self.login}' or wrong password. "
                f"Check the keychain entry {self.router.get('keychain') or '(none)'} or KEENETIC_PASSWORD."
            )
        payload = _json(body) or {}
        if payload.get("ndsso"):
            raise RciError("the router requires NDSSO sign-in, which this tool does not support")
        self._authed = True
        self._log(f"logged in, realm '{realm}'")
        return realm

    def call(self, path, data=None):
        if not self._authed:
            self.auth()
        code, _, body = self._req(path, data)
        if code == 401:
            self._authed = False
            self.auth()
            code, _, body = self._req(path, data)
        self._log(f"{'POST' if data is not None else 'GET'} {path} → {code}")
        if code != 200:
            message = f"{path}: HTTP {code}"
            if body:
                message += f" — {snippet(body)}"
            raise RciError(message)
        return _json(body), body

    def get(self, path):
        payload, raw = self.call("/rci/" + path.lstrip("/"))
        if payload is None:
            return raw.decode("utf-8", "replace")
        return payload

    def parse(self, command):
        """Run one CLI command through {"parse": ...}. Multi-line input is not supported."""
        if "\n" in command.strip():
            raise RciError("one parse call cannot carry several lines — send them one by one")
        payload, raw = self.call("/rci/", {"parse": command})
        if payload is None:
            return raw.decode("utf-8", "replace").splitlines()
        node = payload.get("parse")
        if isinstance(node, dict):
            statuses = node.get("status")
            errors = []
            if isinstance(statuses, list):
                errors = [
                    item for item in statuses
                    if isinstance(item, dict) and str(item.get("status", "")).lower() == "error"
                ]
            elif str(statuses or "").lower() == "error":
                errors = [{"message": node.get("message")}]
            if errors:
                details = "; ".join(str(item.get("message") or item) for item in errors)
                raise RciError(f"'{command}': {details}")
            if self.debug and node.get("prompt"):
                self._log(f"CLI context: {node['prompt']}")
            message = node.get("message")
            if isinstance(message, list):
                return [str(item) for item in message]
            if isinstance(message, str):
                return message.splitlines()
            rest = {key: value for key, value in node.items() if key not in ("prompt", "status")}
            if rest:
                return rest
            if isinstance(statuses, list):
                return [
                    str(item.get("message")) for item in statuses
                    if isinstance(item, dict) and item.get("message")
                ]
            return []
        return []

    def running_config(self):
        return self.parse("show running-config")


# ---------------------------------------------------------------- config parsing


def parse_config(lines):
    """object-group blocks, dns-proxy routes and policies from show running-config."""
    groups = {}
    routes = []
    policies = {}
    order = []
    section = None
    current = None

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped == "!":
            current = None
            continue
        indented = line[:1] in (" ", "\t")

        if not indented:
            current = None
            match = re.match(r"object-group\s+(\S+)\s+(\S+)\s*$", stripped)
            if match:
                gtype, name = match.group(1), match.group(2)
                groups[name] = {"type": gtype, "description": "", "items": []}
                order.append(name)
                current = name
                continue
            if stripped == "dns-proxy":
                section = "dns-proxy"
                continue
            match = re.match(r"ip\s+policy\s+(\S+)\s*$", stripped)
            if match:
                section = "policy"
                policies[match.group(1)] = {"description": "", "items": []}
                current = match.group(1)
                continue
            section = None
            continue

        if current and current in groups:
            if stripped.startswith("description "):
                groups[current]["description"] = stripped[len("description "):]
            elif stripped.startswith("include "):
                groups[current]["items"].append(stripped[len("include "):])
            continue

        if section == "dns-proxy":
            match = re.match(r"route\s+object-group\s+(\S+)\s+(\S+)\s*(\S*)", stripped)
            if match:
                routes.append(
                    {"group": match.group(1), "iface": match.group(2), "mode": match.group(3)}
                )
            continue

        if section == "policy" and current:
            if stripped.startswith("description "):
                policies[current]["description"] = stripped[len("description "):]
            elif stripped.startswith(("permit ", "no permit ")):
                policies[current]["items"].append(stripped)

    return {"groups": groups, "order": order, "routes": routes, "policies": policies}


def natural_key(name):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", name)]


def read_commands(path):
    commands = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped == "!":
                continue
            commands.append(stripped)
    return commands


def check_dangerous(commands):
    """Find potentially dangerous commands. Read-only commands are never flagged."""
    hits = []
    for command in commands:
        if command.lower().startswith(("show ", "?", "!")):
            continue
        for pattern, reason in DANGEROUS:
            if re.search(pattern, command, re.IGNORECASE):
                hits.append((command, reason))
                break
    return hits


def human_uptime(seconds):
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    days, rest = divmod(total, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# ---------------------------------------------------------------- output


def out_json(data):
    print(json.dumps(data, ensure_ascii=False, indent=2))


def print_result(result, as_json=False):
    if isinstance(result, dict) or as_json:
        out_json(result)
        return
    print("\n".join(redact(line) for line in result))


# ---------------------------------------------------------------- setup commands


def _ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        answer = ""
    return answer or default


def cmd_init(rci, args):
    """Setup wizard: name, address, port, login, password → profile + keychain."""
    interactive = not getattr(args, "name", None)
    name = getattr(args, "name", None) or _ask("Router name (ASCII)", "router")
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", name)

    host = getattr(args, "host", None) or (
        _ask("Router address", "192.168.1.1") if interactive else "192.168.1.1"
    )
    port = getattr(args, "port", None)
    if port is None:
        port = int(
            _ask("Web panel port (80, 777, or 443 for https)", str(DEFAULT_PORT))
            if interactive else DEFAULT_PORT
        )
    scheme = getattr(args, "scheme", None) or ("https" if port == 443 else "http")
    login = getattr(args, "login", None) or (
        _ask("Login", DEFAULT_LOGIN) if interactive else DEFAULT_LOGIN
    )
    keychain = getattr(args, "keychain", None)
    if keychain is None:
        keychain = f"keenetic-{name}"

    profile = load_profile()
    routers = profile["routers"]

    password = None
    asked = False
    if getattr(args, "password_stdin", False):
        asked = True
        password = sys.stdin.readline().strip()
    elif interactive:
        asked = True
        password = getpass.getpass(f"Password for {login}@{host} (input is hidden): ")

    stored = False
    if password and keychain:
        stored = keychain_store(keychain, login, password)
    del password

    routers[name] = {
        "label": getattr(args, "label", None) or f"{host}:{port}",
        "host": host,
        "port": int(port),
        "scheme": scheme,
        "login": login,
        "keychain": keychain,
    }
    if not profile["default"]:
        profile["default"] = name
    path = save_profile(profile)

    print(f"Profile:  {path} (mode 600)")
    print(f"Router:   {name} → {scheme}://{host}:{port}, login {login}")
    if stored:
        print(f"Password: stored in the keychain as '{keychain}'")
    elif not keychain:
        print("Password: not stored (keychain entry name is empty).")
        print("          Use KEENETIC_PASSWORD or KEENETIC_PASSWORD_FILE.")
    elif asked:
        print("Password: could not store it in the keychain (no security/secret-tool).")
        print("          Use KEENETIC_PASSWORD or KEENETIC_PASSWORD_FILE.")
    else:
        print(f"Password: not set. Add it: security add-generic-password -s {keychain} -a {login} -w '…'")

    if getattr(args, "no_test", False):
        return

    print("\nChecking connectivity…")
    try:
        router = resolve_router(argparse.Namespace(router=name))
        client = Rci(router, timeout=getattr(args, "timeout", 25))
        realm = client.auth()
        data = client.get("show/version")
        title = data.get("title") if isinstance(data, dict) else "?"
        print(f"  ok: realm '{realm}', KeeneticOS {title}")
    except RciError as exc:
        print(f"  failed: {exc}")
        print("  Hints: references/troubleshooting.md, or run kn.py doctor")


def cmd_routers(rci, args):
    profile = load_profile()
    routers = profile["routers"]
    if getattr(args, "json", False):
        out_json({"default": profile["default"], "config": config_path(), "routers": routers})
        return
    print(f"Profile: {config_path()}")
    if not routers:
        print("No routers yet. Run: python3 kn.py init")
        return
    print(f"Default: {profile['default'] or '— (not set)'}\n")
    header = f"{'':2} {'name':<14} {'address':<28} {'login':<10} {'keychain':<22} label"
    print(header)
    print("-" * len(header))
    for name in sorted(routers):
        entry = routers[name]
        mark = "*" if name == profile["default"] else " "
        address = f"{entry.get('scheme') or 'http'}://{entry.get('host')}:{entry.get('port') or DEFAULT_PORT}"
        print(
            f"{mark:2} {name:<14} {address:<28} {entry.get('login', DEFAULT_LOGIN):<10} "
            f"{entry.get('keychain') or '—':<22} {entry.get('label', '')}".rstrip()
        )
    print("\n* — default")


def cmd_doctor(rci, args):
    ok = True
    print(f"Profile: {config_path()}")
    if not os.path.exists(config_path()):
        print("  ! file is missing — run python3 kn.py init")
        return 3
    mode = oct(os.stat(config_path()).st_mode & 0o777)
    if mode != "0o600":
        print(f"  ! mode is {mode}, expected 600 (chmod 600 {config_path()})")
        ok = False
    else:
        print("  ok: mode 600")

    for tool in ("security", "secret-tool"):
        if shutil.which(tool):
            print(f"  ok: {tool} available")

    profile = load_profile()
    selected = getattr(args, "router", None)
    names = [selected] if selected else sorted(profile["routers"])
    if not names:
        print("  ! no routers in the profile")
        return 3

    timeout = getattr(args, "timeout", 25)
    for name in names:
        entry = profile["routers"].get(name)
        if not entry:
            print(f"\n{name}: not in the profile")
            ok = False
            continue
        host = entry.get("host")
        port = int(entry.get("port") or DEFAULT_PORT)
        print(f"\n{name}: {entry.get('scheme') or 'http'}://{host}:{port}")

        try:
            with socket.create_connection((host, port), timeout=timeout):
                print(f"  ok: port {port} is open")
        except OSError as exc:
            print(f"  ! port {port} is not reachable: {exc}")
            ok = False
            continue

        router = dict(entry)
        router["name"] = name
        try:
            client = Rci(router, timeout=timeout, debug=False)
            realm = client.auth()
            data = client.get("show/version")
            system = client.get("show/system")
            title = data.get("title") if isinstance(data, dict) else "?"
            model = data.get("model") if isinstance(data, dict) else "?"
            uptime = human_uptime(system.get("uptime")) if isinstance(system, dict) else "?"
            print(f"  ok: logged in, realm '{realm}'")
            print(f"  ok: {model}, KeeneticOS {title}, uptime {uptime}")
        except RciError as exc:
            print(f"  ! {exc}")
            ok = False

    return 0 if ok else 1


# ---------------------------------------------------------------- read commands


def cmd_version(rci, args):
    data = rci.get("show/version")
    system = rci.get("show/system")
    if args.json:
        out_json({"version": data, "system": system})
        return
    if not isinstance(data, dict):
        print(str(data).strip())
        return
    router = rci.router
    print(f"Router:      {router.get('name')} ({router.get('label') or '—'})")
    print(f"Address:     {rci.base}")
    print(f"Model:       {data.get('model') or data.get('device') or '?'}")
    print(f"KeeneticOS:  {data.get('title') or '?'}  [{data.get('release') or '?'}, {data.get('sandbox', '?')}]")
    if data.get("arch"):
        print(f"Arch:        {data.get('arch')}")
    ndw3 = (data.get("ndw3") or {}).get("version")
    ndw4 = (data.get("ndw4") or {}).get("version")
    if ndw3 or ndw4:
        print(f"Components:  ndw3 {ndw3 or '—'}, ndw4 {ndw4 or '—'}")
    if isinstance(system, dict):
        if system.get("uptime"):
            print(f"Uptime:      {human_uptime(system['uptime'])}")
        if system.get("hostname"):
            print(f"Hostname:    {system['hostname']}.{system.get('domainname', '')}".rstrip("."))
        load = system.get("cpuload")
        if load is not None:
            print(f"CPU / RAM:   {load}% / {system.get('memory', '?')} KB")


def cmd_config(rci, args):
    lines = rci.running_config()
    if not lines:
        raise RciError("the router returned an empty running-config")
    text = "\n".join(lines) + "\n"
    path = args.out or os.path.join(
        backups_dir(), f"{rci.name}-running-config_{stamp()}.txt"
    )
    write_private(path, text)
    if args.print:
        print(redact(text))
    target = sys.stderr if args.print else sys.stdout
    print(f"Config of {rci.name}: {len(lines)} lines, {len(text)} bytes → {path} (mode 600)", file=target)
    print("The file holds router secrets (ISP password, tunnel keys, PSK) — do not publish.", file=sys.stderr)


def cmd_show(rci, args):
    target = args.path.strip()
    if target.startswith("show "):
        print_result(rci.parse(target), args.json)
        return
    data = rci.get(target)
    if isinstance(data, str):
        print(redact(data))
    elif args.json:
        out_json(data)
    else:
        print(redact(json.dumps(data, ensure_ascii=False, indent=2)))


def cmd_groups(rci, args):
    config = parse_config(rci.running_config())
    groups = config["groups"]
    route_map = {route["group"]: route for route in config["routes"]}
    names = sorted(groups, key=natural_key)

    if args.json:
        out_json({
            "router": rci.name,
            "groups": [
                {
                    "name": name,
                    "type": groups[name]["type"],
                    "description": groups[name]["description"],
                    "domains": len(groups[name]["items"]),
                    "route": route_map.get(name),
                }
                for name in names
            ],
        })
        return

    total = sum(len(groups[name]["items"]) for name in names)
    print(f"Router {rci.name} ({rci.router.get('label') or '—'}), {rci.base}")
    print(f"object-groups: {len(names)}, entries total: {total}\n")
    header = f"{'#':>3}  {'group':<18} {'type':<8} {'entries':>7}  {'route':<32} description"
    print(header)
    print("-" * len(header))
    for index, name in enumerate(names, 1):
        info = groups[name]
        route = route_map.get(name)
        route_text = f"{route['iface']} {route['mode']}".strip() if route else "—"
        print(
            f"{index:>3}  {name:<18} {info['type']:<8} {len(info['items']):>7}  "
            f"{route_text:<32} {info['description'] or ''}".rstrip()
        )
    orphans = [route["group"] for route in config["routes"] if route["group"] not in groups]
    if orphans:
        print(f"\n! routes pointing at missing groups: {', '.join(orphans)}")
    if config["policies"]:
        print("\nAccess policies (ip policy):")
        for name, info in config["policies"].items():
            mark = f" — {info['description']}" if info["description"] else ""
            print(f"  {name}: {len(info['items'])} rules{mark}")


def cmd_domains(rci, args):
    config = parse_config(rci.running_config())
    group = args.group
    if group not in config["groups"]:
        known = ", ".join(sorted(config["groups"], key=natural_key)) or "no groups"
        raise RciError(f"there is no group '{group}'. Available: {known}")
    items = config["groups"][group]["items"]
    if args.json:
        out_json({"group": group, "count": len(items), "domains": items})
        return
    if args.out:
        write_private(args.out, "\n".join(items) + "\n")
        print(f"{len(items)} domains → {args.out} (mode 600)")
        return
    print(f"# {group}: {len(items)} domains ({rci.name})")
    print("\n".join(items))


def cmd_cli(rci, args):
    command = args.command.strip()
    read_only = command.lower().startswith(("show ", "?", "!"))
    if not read_only and not args.yes:
        print(f"Modifying command: {command}")
        print("This is a dry run. To execute, add --yes.")
        return
    print_result(rci.parse(command), args.json)


# ---------------------------------------------------------------- write commands


def cmd_apply(rci, args):
    commands = read_commands(args.file)
    if not commands:
        raise RciError(f"no commands found in {args.file}")

    hits = check_dangerous(commands)
    if hits and not args.allow_dangerous:
        print("STOPPED: the file contains potentially dangerous commands.", file=sys.stderr)
        for command, reason in hits[:10]:
            print(f"  {command}   ({reason})", file=sys.stderr)
        raise RciError("review the file; applying this requires --allow-dangerous")

    print(f"File:    {args.file}")
    print(f"Router:  {rci.name} ({rci.router.get('label') or '—'}), {rci.base}")
    print(f"Commands: {len(commands)}")
    preview = commands if args.verbose else commands[:12]
    print("\nPlan:")
    for command in preview:
        print(f"  {command}")
    if len(preview) < len(commands):
        print(f"  … {len(commands) - len(preview)} more (full list: --verbose)")

    if not args.yes:
        print(
            "\nThis is a dry run, nothing was changed on the router. "
            "To apply: add --yes (and --save to persist the config)."
        )
        return

    # the backup has to succeed before the first modifying command
    lines = rci.running_config()
    if not lines:
        raise RciError("cannot take a backup: empty running-config — applying was cancelled")
    backup = os.path.join(
        backups_dir(), f"{rci.name}-running-config_{stamp()}_before-apply.txt"
    )
    write_private(backup, "\n".join(lines) + "\n")
    print(f"\nBackup:  {backup} ({len(lines)} lines, mode 600)")
    applied_log = write_private(
        os.path.join(backups_dir(), f"{rci.name}-applied_{stamp()}.cli"),
        "\n".join(commands) + "\n",
    )
    print(f"Journal: {applied_log}")

    failed = []
    for index, command in enumerate(commands, 1):
        try:
            result = rci.parse(command)
        except RciError as exc:
            failed.append((command, str(exc)))
            print(f"  [{index}/{len(commands)}] {command} → ERROR: {exc}", file=sys.stderr)
            if not args.keep_going:
                print("Stopped on the first error. The backup above can restore the previous config.", file=sys.stderr)
                break
            continue
        note = f" ({result[0]})" if isinstance(result, list) and result else ""
        print(f"  [{index}/{len(commands)}] {command} → ok{note}")

    if args.save and not failed:
        rci.parse("system configuration save")
        print("Config saved on the router (system configuration save).")
    elif args.save and failed:
        print("Save skipped: there were errors.", file=sys.stderr)

    if failed:
        raise RciError(f"commands failed: {len(failed)}")


def cmd_save(rci, args):
    if not args.yes:
        print("system configuration save — dry run. To execute, add --yes.")
        return
    rci.parse("system configuration save")
    print(f"Config of {rci.name} saved on the router.")


# ---------------------------------------------------------------- local notes


def cmd_notes(rci, args):
    path = notes_path()
    if not os.path.exists(path):
        print(f"No local notes yet: {path}")
        print('Add one: python3 kn.py note "what you learned about this router"')
        return
    with open(path, encoding="utf-8") as handle:
        print(handle.read().rstrip())


def cmd_note(rci, args):
    path = notes_path()
    header = "" if os.path.exists(path) else (
        "# Local notes: keenetic skill\n\n"
        "This file is not part of the repository. Keep here whatever applies only to\n"
        "your routers: addresses, ports, group names, network quirks.\n\n"
    )
    existing = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            existing = handle.read()
    text = existing or header
    if not text.endswith("\n"):
        text += "\n"
    entry = f"- {time.strftime('%Y-%m-%d %H:%M')} — {args.text.strip()}\n"
    write_private(path, text + entry)
    print(f"Written to {path}")


# ---------------------------------------------------------------- backups


def cmd_backups(rci, args):
    directory = backups_dir()
    if not os.path.isdir(directory):
        print(f"No backups: {directory}")
        return
    only_selected = bool(getattr(args, "router", None))
    pattern = f"{rci.name}-" if only_selected else ""
    files = sorted(
        (os.path.join(directory, name) for name in os.listdir(directory) if name.startswith(pattern)),
        key=os.path.getmtime,
    )
    if not files:
        print(f"No backups for {rci.name} in {directory}")
        return
    total = sum(os.path.getsize(path) for path in files)
    print(f"{directory}: {len(files)} files, {total / 1024:.0f} KB\n")
    for path in files:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(os.path.getmtime(path)))
        print(f"  {when}  {os.path.getsize(path) / 1024:7.1f} KB  {os.path.basename(path)}")

    if args.keep:
        keep = max(1, args.keep)
        victims = files[:-keep]
        if not victims:
            print(f"\nNothing to remove: {keep} or fewer files.")
            return
        print(f"\nRemoving {len(victims)} oldest (keeping {keep}):")
        for path in victims:
            if args.yes:
                os.remove(path)
                print(f"  removed {os.path.basename(path)}")
            else:
                print(f"  would remove {os.path.basename(path)}")
        if not args.yes:
            print("This is a dry run. To delete, repeat with --yes.")


# ---------------------------------------------------------------- main


def build_parser():
    # Shared flags. default=SUPPRESS so that a subparser does not overwrite a value
    # given before the subcommand: `kn.py -r home version` works like `kn.py version -r home`.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-r", "--router", help="router name from the profile")
    common.add_argument("--host", help="one-off address, without a profile")
    common.add_argument("--port", type=int, help="one-off port")
    common.add_argument("--scheme", choices=["http", "https"], help="one-off scheme")
    common.add_argument("--login", help="one-off login")
    common.add_argument("--keychain", help="one-off keychain entry name")
    common.add_argument("--ask-password", action="store_true", help="prompt for the password")
    common.add_argument("--json", action="store_true", help="machine-readable JSON output")
    common.add_argument("--debug", action="store_true", help="show HTTP exchange (no bodies, no cookies)")
    common.add_argument("--timeout", type=int, help="request timeout, seconds (default 25)")
    for action in common._actions:
        if action.dest != "help":
            action.default = argparse.SUPPRESS

    parser = argparse.ArgumentParser(
        prog="kn.py",
        description="Keenetic/Netcraze RCI client: read state and apply CLI commands safely.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Local profile: ~/.config/keenetic-skill/routers.json (override: KEENETIC_HOME).\n"
            "Password: KEENETIC_PASSWORD → KEENETIC_PASSWORD_FILE → keychain/secret-tool → --ask-password.\n"
            "Shared flags work before or after the subcommand."
        ),
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"kn.py {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", parents=[common], help="setup wizard for the profile and password")
    p.add_argument("--name", help="router name (ASCII); without it the wizard asks")
    p.add_argument("--label", help="human label, e.g. 'living room'")
    p.add_argument("--password-stdin", action="store_true", help="password is read from stdin")
    p.add_argument("--no-test", action="store_true", help="skip the login check after saving")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("routers", parents=[common], help="list configured routers")
    p.set_defaults(func=cmd_routers)

    p = sub.add_parser("doctor", parents=[common], help="diagnose: port, login, version")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("version", parents=[common], help="KeeneticOS version and model")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("config", parents=[common], help="dump running-config to a 600 file")
    p.add_argument("--out", help="where to save (default: ~/.config/keenetic-skill/backups)")
    p.add_argument("--print", action="store_true", help="print the config too (secrets are hidden)")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("show", parents=[common], help="GET /rci/<path> or a CLI 'show …'")
    p.add_argument("path", help="e.g. show/ip/route, show/interface, or \"show version\"")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("groups", parents=[common], help="object-group lists and routes")
    p.set_defaults(func=cmd_groups)

    p = sub.add_parser("domains", parents=[common], help="domains of one group")
    p.add_argument("group", help="group name, e.g. domain-list0")
    p.add_argument("--out", help="save the list to a file")
    p.set_defaults(func=cmd_domains)

    p = sub.add_parser("apply", parents=[common], help="apply a file of CLI commands (with backup)")
    p.add_argument("file", help="one command per line; # and ! are comments")
    p.add_argument("--yes", action="store_true", help="actually apply")
    p.add_argument("--save", action="store_true", help="run system configuration save at the end")
    p.add_argument("--keep-going", action="store_true", help="continue after an error")
    p.add_argument("--allow-dangerous", action="store_true", help="permit dangerous commands")
    p.add_argument("--verbose", action="store_true", help="print the whole plan, not the first 12")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("cli", parents=[common], help="one CLI command")
    p.add_argument("command", help="e.g. \"show ip route\"")
    p.add_argument("--yes", action="store_true", help="allow a modifying command")
    p.set_defaults(func=cmd_cli)

    p = sub.add_parser("save", parents=[common], help="system configuration save")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_save)

    p = sub.add_parser("notes", parents=[common], help="show local notes")
    p.set_defaults(func=cmd_notes)

    p = sub.add_parser("note", parents=[common], help="append a line to the local notes")
    p.add_argument("text", help="what to remember")
    p.set_defaults(func=cmd_note)

    p = sub.add_parser("backups", parents=[common], help="list backups; --keep N prunes old ones")
    p.add_argument("--keep", type=int, help="keep the N newest")
    p.add_argument("--yes", action="store_true", help="actually delete")
    p.set_defaults(func=cmd_backups)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    for name, default in (("json", False), ("debug", False), ("timeout", 25), ("ask_password", False)):
        if not hasattr(args, name):
            setattr(args, name, default)

    try:
        # commands that do not need a router: profile, setup, notes, diagnostics
        if args.command in ("routers", "init", "notes", "note", "doctor"):
            return args.func(None, args) or 0

        router = resolve_router(args)
        rci = Rci(router, timeout=args.timeout, debug=args.debug)
        if args.command == "backups":
            return args.func(rci, args) or 0
        args.func(rci, args)
    except RciError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
