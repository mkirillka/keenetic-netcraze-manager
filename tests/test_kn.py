#!/usr/bin/env python3
"""Offline tests for kn.py: no network, no router, no passwords.

Run:
    python3 tests/test_kn.py
"""

import argparse
import io
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import kn  # noqa: E402

SAMPLE_CONFIG = """! $$$ Agent: http/rci
! $$$ Last change: Thu, 01 Jan 2026 10:00:00 GMT
! $$$ Md5 checksum: deadbeef
ip host local
    ...
!
object-group fqdn domain-list0
    description youtube
    include youtube.com
    include googlevideo.com
!
object-group fqdn domain-list11
    description github
    include github.com
    include api.github.com
!
dns-proxy
    rebind-protect auto
    route object-group domain-list0 Wireguard0 auto
    route object-group domain-list11 Wireguard0 auto
    route object-group ghost-list Wireguard0 auto
!
ip policy Policy0
    description "full tunnel"
    permit global Wireguard0
    no permit global GigabitEthernet0/Vlan2
!
mws wlan wlan0
    wpa psk ns3 u78E6S1B/+Cnf/Q32tvg4IxABb+DG53w7nys/hHk0z6cKtqc
!
"""


class TempHomeMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._old_home = kn.DATA_HOME
        kn.DATA_HOME = self.tmp.name

    def tearDown(self):
        kn.DATA_HOME = self._old_home
        self.tmp.cleanup()

    def write_profile(self, data):
        with open(os.path.join(self.tmp.name, "routers.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh)


class TestText(unittest.TestCase):
    def test_fix_text_unescapes_cyrillic(self):
        raw = "\\xd0\\x9f\\xd0\\xbe\\xd0\\xbb\\xd0\\xbd\\xd1\\x8b\\xd0\\xb9 \\xd0\\xb1\\xd1\\x83\\xd0\\xbd\\xd1\\x82"
        self.assertEqual(kn.fix_text(raw), "Полный бунт")

    def test_fix_text_keeps_ascii(self):
        self.assertEqual(kn.fix_text("plain text 123"), "plain text 123")

    def test_fix_text_handles_nested(self):
        data = {"a": ["\\xd0\\x9d\\xd0\\xbe\\xd1\\x87\\xd1\\x8c"], "b": 5}
        self.assertEqual(kn.fix_text(data), {"a": ["Ночь"], "b": 5})

    def test_fix_text_survives_broken_escape(self):
        self.assertEqual(kn.fix_text("\\xZZ"), "\\xZZ")

    def test_redact_hides_password(self):
        self.assertEqual(
            kn.redact('{"login":"admin","password":"secret"}'),
            '{"login":"admin","password":"<hidden>"}',
        )

    def test_redact_hides_wifi_psk(self):
        self.assertNotIn("u78E6S1B", kn.redact("    wpa psk ns3 u78E6S1B/+Cnf"))

    def test_redact_hides_wireguard_keys(self):
        self.assertNotIn("abc=", kn.redact("    private-key abc="))
        self.assertNotIn("xyz=", kn.redact("    pre-shared-key xyz="))

    def test_snippet_truncates_and_redacts(self):
        text = kn.snippet(b'{"password":"secret"}' + b"0" * 500, limit=40)
        self.assertNotIn("secret", text)
        self.assertTrue(text.endswith("…"))


class TestConfigParsing(unittest.TestCase):
    def setUp(self):
        self.parsed = kn.parse_config(SAMPLE_CONFIG.splitlines())

    def test_groups_found(self):
        self.assertEqual(sorted(self.parsed["groups"]), ["domain-list0", "domain-list11"])

    def test_group_items_and_description(self):
        group = self.parsed["groups"]["domain-list0"]
        self.assertEqual(group["description"], "youtube")
        self.assertEqual(group["items"], ["youtube.com", "googlevideo.com"])
        self.assertEqual(group["type"], "fqdn")

    def test_routes_found(self):
        routes = {r["group"]: r for r in self.parsed["routes"]}
        self.assertEqual(routes["domain-list0"]["iface"], "Wireguard0")
        self.assertEqual(routes["domain-list0"]["mode"], "auto")
        self.assertIn("ghost-list", routes)

    def test_policies_found(self):
        policy = self.parsed["policies"]["Policy0"]
        self.assertEqual(policy["description"], '"full tunnel"')
        self.assertEqual(len(policy["items"]), 2)

    def test_wifi_block_is_not_a_group(self):
        self.assertNotIn("mws", self.parsed["groups"])

    def test_empty_config(self):
        empty = kn.parse_config([])
        self.assertEqual(empty["groups"], {})
        self.assertEqual(empty["routes"], [])

    def test_natural_sort(self):
        names = ["domain-list10", "domain-list2", "domain-list1"]
        self.assertEqual(
            sorted(names, key=kn.natural_key),
            ["domain-list1", "domain-list2", "domain-list10"],
        )


class TestDangerous(unittest.TestCase):
    def test_safe_commands_pass(self):
        self.assertEqual(kn.check_dangerous(["show version", "include example.com"]), [])

    def test_flags_no_object_group(self):
        hits = kn.check_dangerous(["no object-group fqdn domain-list0"])
        self.assertEqual(hits[0][1], "deleting a domain/object list")

    def test_flags_firewall_wireguard_reboot(self):
        for command in ("firewall disable", "wireguard 0", "reboot", "erase startup-config"):
            self.assertTrue(kn.check_dangerous([command]), command)

    def test_flags_access_commands(self):
        self.assertTrue(kn.check_dangerous(["ip http port 8080"]))
        self.assertTrue(kn.check_dangerous(["user admin"]))

    def test_read_only_commands_never_flagged(self):
        for command in (
            "show ip nat translations",
            "show user",
            "show wireguard",
            "show running-config",
        ):
            self.assertEqual(kn.check_dangerous([command]), [], command)


class TestCommandFiles(unittest.TestCase):
    def test_read_commands_skips_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".cli", delete=False, encoding="utf-8") as fh:
            fh.write("# comment\n\nobject-group fqdn x\n  include a.com\n!\n")
            path = fh.name
        try:
            self.assertEqual(
                kn.read_commands(path),
                ["object-group fqdn x", "include a.com"],
            )
        finally:
            os.unlink(path)


class TestProfile(TempHomeMixin, unittest.TestCase):
    def test_empty_profile_raises_with_hint(self):
        with self.assertRaises(kn.ConfigError) as ctx:
            kn.resolve_router(argparse.Namespace(router=None))
        self.assertIn("init", str(ctx.exception))

    def test_resolves_default(self):
        self.write_profile({
            "default": "home",
            "routers": {"home": {"host": "10.0.0.1", "port": 777, "login": "admin"}},
        })
        router = kn.resolve_router(argparse.Namespace(router=None))
        self.assertEqual(router["host"], "10.0.0.1")
        self.assertEqual(router["port"], 777)
        self.assertEqual(router["name"], "home")

    def test_resolves_by_name(self):
        self.write_profile({
            "default": "home",
            "routers": {
                "home": {"host": "10.0.0.1"},
                "office": {"host": "10.0.0.2", "port": 80},
            },
        })
        router = kn.resolve_router(argparse.Namespace(router="office"))
        self.assertEqual(router["host"], "10.0.0.2")

    def test_unknown_name_lists_known(self):
        self.write_profile({"default": "home", "routers": {"home": {"host": "10.0.0.1"}}})
        with self.assertRaises(kn.ConfigError) as ctx:
            kn.resolve_router(argparse.Namespace(router="nope"))
        self.assertIn("home", str(ctx.exception))

    def test_adhoc_host_wins(self):
        self.write_profile({"default": "home", "routers": {"home": {"host": "10.0.0.1"}}})
        router = kn.resolve_router(argparse.Namespace(router="home", host="192.168.1.1", port=443))
        self.assertEqual(router["name"], "cli")
        self.assertEqual(router["host"], "192.168.1.1")
        self.assertEqual(router["port"], 443)

    def test_port_defaults_to_80(self):
        self.write_profile({"default": "home", "routers": {"home": {"host": "10.0.0.1"}}})
        self.assertEqual(kn.resolve_router(argparse.Namespace(router=None))["port"], 80)

    def test_broken_json_reports_path(self):
        with open(os.path.join(self.tmp.name, "routers.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(kn.ConfigError) as ctx:
            kn.load_profile()
        self.assertIn("routers.json", str(ctx.exception))

    def test_save_profile_is_private(self):
        path = kn.save_profile({"default": None, "routers": {}})
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class TestPassword(TempHomeMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.router = {"host": "10.0.0.1", "login": "admin", "keychain": "keenetic-test-xyz"}
        self._env = {k: os.environ.get(k) for k in ("KEENETIC_PASSWORD", "KEENETIC_PASSWORD_FILE")}
        for key in self._env:
            os.environ.pop(key, None)

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        super().tearDown()

    def test_env_password_wins(self):
        os.environ["KEENETIC_PASSWORD"] = "from-env"
        self.assertEqual(kn.resolve_password(self.router, argparse.Namespace()), "from-env")

    def test_password_file(self):
        path = os.path.join(self.tmp.name, "pw")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("from-file\n")
        os.environ["KEENETIC_PASSWORD_FILE"] = path
        self.assertEqual(kn.resolve_password(self.router, argparse.Namespace()), "from-file")

    def test_missing_password_explains_options(self):
        with self.assertRaises(kn.ConfigError) as ctx:
            kn.resolve_password(self.router, argparse.Namespace())
        message = str(ctx.exception)
        self.assertIn("KEENETIC_PASSWORD", message)
        self.assertIn("security add-generic-password", message)

    def test_error_does_not_leak_secret(self):
        os.environ["KEENETIC_PASSWORD"] = "topsecret"
        try:
            kn.resolve_password({"host": "h", "login": "admin", "keychain": ""}, argparse.Namespace())
        except kn.ConfigError as exc:
            self.assertNotIn("topsecret", str(exc))


class TestInit(TempHomeMixin, unittest.TestCase):
    """The wizard must work without a TTY and without any preset flags."""

    def setUp(self):
        super().setUp()
        # never touch a real keyring from tests
        self._real_store = kn.keychain_store
        kn.keychain_store = lambda service, account, password: True

    def tearDown(self):
        kn.keychain_store = self._real_store
        super().tearDown()

    def _run_init(self, argv, stdin_text=""):
        old_stdin, old_stdout = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = io.StringIO(stdin_text), io.StringIO()
        try:
            code = kn.main(["init", "--no-test"] + argv)
            self.last_output = sys.stdout.getvalue()
            return code
        finally:
            sys.stdin, sys.stdout = old_stdin, old_stdout

    def test_init_with_all_flags(self):
        code = self._run_init(
            ["--name", "test", "--host", "10.0.0.1", "--port", "777",
             "--login", "admin", "--keychain", "", "--password-stdin"],
            "secret\n",
        )
        self.assertEqual(code, 0)
        profile = kn.load_profile()
        self.assertEqual(profile["default"], "test")
        self.assertEqual(profile["routers"]["test"]["host"], "10.0.0.1")
        self.assertEqual(profile["routers"]["test"]["port"], 777)

    def test_init_without_flags_uses_defaults(self):
        """Regression: SUPPRESS flags are absent when not given — must not crash."""
        code = self._run_init(["--name", "x", "--password-stdin"], "secret\n")
        self.assertEqual(code, 0)
        entry = kn.load_profile()["routers"]["x"]
        self.assertEqual(entry["port"], 80)
        self.assertEqual(entry["scheme"], "http")
        self.assertEqual(entry["login"], "admin")
        self.assertEqual(entry["keychain"], "keenetic-x")

    def test_init_https_when_port_443(self):
        self._run_init(["--name", "s", "--port", "443", "--password-stdin"], "secret\n")
        self.assertEqual(kn.load_profile()["routers"]["s"]["scheme"], "https")

    def test_init_sanitizes_name(self):
        self._run_init(["--name", "my router/1", "--password-stdin"], "secret\n")
        self.assertIn("my-router-1", kn.load_profile()["routers"])

    def test_init_keeps_existing_default(self):
        kn.save_profile({"default": "first", "routers": {"first": {"host": "10.0.0.9"}}})
        self._run_init(["--name", "second", "--password-stdin"], "secret\n")
        self.assertEqual(kn.load_profile()["default"], "first")

    def test_init_survives_failed_keyring_store(self):
        """Regression: a missing keyring used to raise UnboundLocalError after `del password`."""
        kn.keychain_store = lambda service, account, password: False
        code = self._run_init(["--name", "nokey", "--password-stdin"], "secret\n")
        self.assertEqual(code, 0)
        self.assertIn("could not store it in the keychain", self.last_output)
        self.assertEqual(kn.load_profile()["routers"]["nokey"]["host"], "192.168.1.1")

    def test_init_without_password_at_all(self):
        """Non-interactive init with no --password-stdin must not crash either."""
        code = self._run_init(["--name", "nopw"])
        self.assertEqual(code, 0)
        self.assertIn("nopw", kn.load_profile()["routers"])


class TestMisc(unittest.TestCase):
    def test_json_of_garbage_is_none(self):
        self.assertIsNone(kn._json(b"<html>nope</html>"))

    def test_json_is_fixed(self):
        # the router sends non-ASCII as a double escape: \\xd0\\x9d inside the JSON string
        self.assertEqual(kn._json(b'{"a":"\\\\xd0\\\\x9d"}')["a"], "Н")

    def test_human_uptime(self):
        self.assertEqual(kn.human_uptime(90), "1m")
        self.assertEqual(kn.human_uptime(3700), "1h 1m")
        self.assertEqual(kn.human_uptime(90000), "1d 1h")

    def test_write_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = kn.write_private(os.path.join(tmp, "sub", "file.txt"), "data")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_parse_rejects_multiline(self):
        client = kn.Rci({"host": "127.0.0.1", "port": 1, "name": "t"})
        with self.assertRaises(kn.RciError):
            client.parse("line1\nline2")

    def test_version_matches_skill_frontmatter(self):
        """The version lives in kn.__version__ and in SKILL.md — they must not drift."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        with open(os.path.join(root, "SKILL.md"), encoding="utf-8") as fh:
            front = fh.read()
        match = re.search(r"^\s*version:\s*(\S+)\s*$", front, re.MULTILINE)
        self.assertIsNotNone(match, "SKILL.md has no metadata.version")
        self.assertEqual(match.group(1), kn.__version__)

    def test_no_personal_data_in_skill_files(self):
        """Personal hosts and keyring names must stay out of the published skill."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        # needles assembled from pieces so the test does not match itself
        needles = [
            "find-generic-password -s keenetic-" + "hopper",
            "find-generic-password -s keenetic-" + "giga",
            "5.61." + "39.252",
            "hopper" + "515",
        ]
        for base, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ("tests", "__pycache__", ".git")]
            for name in files:
                if not name.endswith((".py", ".md", ".json", ".sh", ".txt")):
                    continue
                path = os.path.join(base, name)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                for needle in needles:
                    self.assertNotIn(needle, text, f"{path} contains '{needle}'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
