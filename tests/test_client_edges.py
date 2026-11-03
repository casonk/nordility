"""Routing-rule safety, token redaction, login flow and watcher edges of client.py.

A small in-memory ``ip``/``wg`` simulator stands in for the system: nothing here
runs a real command, touches a real vault, or sees a real token.
"""

from __future__ import annotations

import logging
import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from nordility import client
from nordility.client import (
    CommandExecutionError,
    CommandResult,
    ConfigurationError,
    NordVPNClient,
)

MARK = client.DEFAULT_WIREGUARD_FWMARK
PRIORITY = client.DEFAULT_WIREGUARD_IP_RULE_PRIORITY
PROTO = client.DEFAULT_WIREGUARD_IP_RULE_PROTOCOL
OWNED_LINE = f"{PRIORITY}:\tfrom all fwmark {hex(MARK)} lookup main proto {PROTO}"
CANARY = "CANARYtokenValue0123456789"


def cp(returncode=0, stdout="", stderr=""):
    return CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class Scripted:
    """Runner answering from a mapping of command prefixes; records every call."""

    def __init__(self, answers=None, default=None):
        self.answers = answers or {}
        self.default = default
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command, **_kwargs):
        command = tuple(command)
        self.calls.append(command)
        for prefix, answer in self.answers.items():
            if command[: len(prefix)] == prefix:
                if isinstance(answer, list):
                    value = answer.pop(0) if len(answer) > 1 else answer[0]
                else:
                    value = answer
                if isinstance(value, BaseException):
                    raise value
                return value
        if self.default is not None:
            if isinstance(self.default, BaseException):
                raise self.default
            return self.default
        raise AssertionError(f"unexpected command: {command}")

    def ran(self, *prefix):
        return [c for c in self.calls if c[: len(prefix)] == prefix]


class Sim:
    """Tiny model of ip rules and WireGuard marks."""

    def __init__(self, marks=None, rules=None):
        self.marks: dict[str, str] = dict(marks if marks is not None else {"wg0": "off"})
        self.rules: list[str] = list(rules or [])
        self.calls: list[tuple[str, ...]] = []
        self.fail_add = False
        self.fail_set = False
        self.fail_sudo_too = True
        self.fail_inventory = False
        self.fail_rule_show = False
        self.add_raises: BaseException | None = None
        self.after_add = None
        self.after_inventory_count = None
        self.inventory_reads = 0
        self.fail_delete = False

    def __call__(self, command, **_kwargs):
        command = tuple(command)
        self.calls.append(command)
        sudo = command[:2] == ("sudo", "-n")
        if sudo:
            command = command[2:]
        if command == ("wg", "show", "all", "fwmark"):
            self.inventory_reads += 1
            if self.fail_inventory:
                return cp(1)
            if self.after_inventory_count and self.inventory_reads >= self.after_inventory_count:
                self.marks["other"] = hex(MARK)
            return cp(0, "".join(f"{i}\t{m}\n" for i, m in self.marks.items()))
        if command == ("ip", "rule", "show"):
            if self.fail_rule_show:
                return cp(1)
            return cp(0, "\n".join(self.rules) + "\n")
        if command[:3] == ("ip", "rule", "add"):
            if self.add_raises:
                raise self.add_raises
            if self.fail_add and (self.fail_sudo_too or sudo):
                return cp(1)
            if self.fail_add:
                return cp(1)
            self.rules.append(OWNED_LINE)
            if self.after_add:
                self.after_add(self)
            return cp(0)
        if command[:3] == ("ip", "rule", "del"):
            if self.fail_delete:
                return cp(1)
            self.rules = [r for r in self.rules if r != OWNED_LINE]
            return cp(0)
        if command[:2] == ("wg", "set"):
            if self.fail_set and (self.fail_sudo_too or not sudo):
                return cp(1)
            self.marks[command[2]] = hex(MARK)
            return cp(0)
        raise AssertionError(f"unexpected command: {command}")

    def ran(self, *prefix):
        return [c for c in self.calls if c[: len(prefix)] == prefix]


class RedactionTests(unittest.TestCase):
    def test_token_argument_values_are_removed_from_display_and_collected(self) -> None:
        shown, secrets = client._redact_command(("nordvpn", "login", "--token", CANARY))
        self.assertEqual(shown, ("nordvpn", "login", "--token", "<redacted>"))
        self.assertEqual(secrets, (CANARY,))

        shown, secrets = client._redact_command(("nordvpn", f"--token={CANARY}", "x"))
        self.assertEqual(shown, ("nordvpn", "--token=<redacted>", "x"))
        self.assertEqual(secrets, (CANARY,))

    def test_edge_shapes(self) -> None:
        self.assertEqual(client._redact_command(("n", "--token="))[1], ())
        self.assertEqual(client._redact_command(("n", "--token")), (("n", "--token"), ()))
        shown, secrets = client._redact_command(("n", "--token", "a", "--token", "b"))
        self.assertEqual(secrets, ("a", "b"))
        self.assertEqual(shown.count("<redacted>"), 2)
        self.assertEqual(client._redact_command(()), ((), ()))
        # Only the value after the flag is a secret, not a later argument.
        self.assertEqual(client._redact_command(("n", "--token", "a", "keep"))[0][-1], "keep")

    def test_text_redaction_replaces_every_occurrence_of_every_secret(self) -> None:
        text = f"bad {CANARY} and {CANARY} and other"
        self.assertEqual(
            client._redact_text(text, (CANARY, "other")),
            "bad <redacted> and <redacted> and <redacted>",
        )
        self.assertEqual(client._redact_text("plain", ()), "plain")

    def test_not_logged_in_detection_is_case_insensitive(self) -> None:
        self.assertTrue(client._is_not_logged_in("Error: You Are NOT Logged In"))
        self.assertTrue(client._is_not_logged_in("please log in first"))
        self.assertFalse(client._is_not_logged_in("connection refused"))


class KeepassResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        class KeepassCommandError(Exception):
            pass

        self.error_cls = KeepassCommandError
        self.loaded: list[tuple] = []
        self.resolve = mock.Mock()
        envfile = types.ModuleType("auto_pass.envfile")
        envfile.load_config_environment = lambda path, profile=None: self.loaded.append(
            (path, profile)
        )
        keepass = types.ModuleType("auto_pass.keepassxc")
        keepass.KeepassCommandError = KeepassCommandError
        keepass.resolve_keepassxc_entry = self.resolve
        package = types.ModuleType("auto_pass")
        patcher = mock.patch.dict(
            sys.modules,
            {
                "auto_pass": package,
                "auto_pass.envfile": envfile,
                "auto_pass.keepassxc": keepass,
            },
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root_patch = mock.patch.object(client, "_AUTO_PASS_ROOT", Path(self.tmp.name))
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def test_candidate_entries(self) -> None:
        self.assertEqual(client._candidate_keepass_entries("  "), ())
        self.assertEqual(client._candidate_keepass_entries("a/b"), ("a/b",))
        self.assertEqual(client._candidate_keepass_entries(" tok "), ("tok", "nordvpn/tok"))

    def test_first_hit_is_returned_without_trying_alternatives(self) -> None:
        self.resolve.return_value = {"token": CANARY}
        self.assertEqual(client._resolve_keepass_token("tok"), CANARY)
        self.resolve.assert_called_once_with("tok", attrs_map={"token": "password"})

    def test_missing_token_key_yields_empty_string(self) -> None:
        self.resolve.return_value = {}
        self.assertEqual(client._resolve_keepass_token("tok"), "")

    def test_not_found_falls_through_to_the_namespaced_entry(self) -> None:
        self.resolve.side_effect = [self.error_cls("Entry NOT FOUND"), {"token": CANARY}]
        self.assertEqual(client._resolve_keepass_token("tok"), CANARY)
        self.assertEqual([c.args[0] for c in self.resolve.call_args_list], ["tok", "nordvpn/tok"])

    def test_other_vault_errors_are_not_masked_by_trying_more_entries(self) -> None:
        self.resolve.side_effect = self.error_cls("vault locked")
        with self.assertRaisesRegex(self.error_cls, "vault locked"):
            client._resolve_keepass_token("tok")
        self.resolve.assert_called_once()

    def test_all_candidates_missing_raises_the_last_error(self) -> None:
        self.resolve.side_effect = [
            self.error_cls("no entry a"),
            self.error_cls("could not find b"),
        ]
        with self.assertRaisesRegex(self.error_cls, "could not find b"):
            client._resolve_keepass_token("tok")

    def test_blank_entry_resolves_to_nothing_without_touching_the_vault(self) -> None:
        self.assertEqual(client._resolve_keepass_token("  "), "")
        self.resolve.assert_not_called()

    def test_local_env_file_is_loaded_with_the_profile_when_present(self) -> None:
        self.resolve.return_value = {"token": "x"}
        client._resolve_keepass_token("tok", "prof")
        self.assertEqual(self.loaded, [])
        env = Path(self.tmp.name) / "config"
        env.mkdir()
        (env / "auto-pass.env.local").write_text("")
        client._resolve_keepass_token("tok", "prof")
        self.assertEqual(self.loaded, [(env / "auto-pass.env.local", "prof")])


class WireGuardDiscoveryTests(unittest.TestCase):
    def test_discover_interfaces(self) -> None:
        run = Scripted({("wg", "show", "interfaces"): cp(0, " wg0  nordlynx \n")})
        self.assertEqual(client._discover_wireguard_interfaces(run), ["wg0", "nordlynx"])
        for answer in (cp(1, "wg0"), cp(0, "  \n"), OSError("x"), FileNotFoundError()):
            run = Scripted({("wg", "show", "interfaces"): answer})
            self.assertEqual(client._discover_wireguard_interfaces(run), [])

    def test_peer_endpoints_parse_and_skip_unknown_endpoints(self) -> None:
        out = "KEY1\t1.2.3.4:51820\nKEY2\t(none)\nmalformed-line\n\nKEY3\t[::1]:1\n"
        run = Scripted({("wg", "show", "wg0", "endpoints"): cp(0, out)})
        self.assertEqual(
            client._get_wireguard_peer_endpoints(run, "wg0"),
            {"KEY1": "1.2.3.4:51820", "KEY3": "[::1]:1"},
        )
        self.assertEqual(len(run.calls), 1)

    def test_peer_endpoints_retry_with_sudo_only_when_needed(self) -> None:
        run = Scripted(
            {
                ("wg", "show"): cp(1),
                ("sudo", "-n", "wg", "show"): cp(0, "K\t1.1.1.1:1\n"),
            }
        )
        self.assertEqual(client._get_wireguard_peer_endpoints(run, "wg0"), {"K": "1.1.1.1:1"})
        run = Scripted({("wg", "show"): cp(1), ("sudo", "-n", "wg", "show"): cp(1)})
        self.assertEqual(client._get_wireguard_peer_endpoints(run, "wg0"), {})
        self.assertEqual(
            client._get_wireguard_peer_endpoints(Scripted(default=OSError("x")), "wg0"), {}
        )

    def test_fwmark_inventory_parsing(self) -> None:
        def parse(stdout, rc=0, sudo_rc=None):
            answers = {("wg", "show", "all", "fwmark"): cp(rc, stdout)}
            if sudo_rc is not None:
                answers[("sudo", "-n", "wg")] = cp(sudo_rc, stdout)
            return client._wireguard_fwmark_assignments(Scripted(answers))

        self.assertEqual(parse(""), {})
        self.assertEqual(
            parse("wg0\t0xca6c\nwg1\toff\nwg2\t51820\n"), {"wg0": 0xCA6C, "wg1": None, "wg2": 51820}
        )
        self.assertEqual(parse("wg0\tOFF\n"), {"wg0": None})
        self.assertEqual(parse("wg0\t0\n"), {"wg0": 0})
        self.assertEqual(parse("wg0\t0xFFFFFFFF\n"), {"wg0": 0xFFFFFFFF})
        for bad in (
            "wg0\n",
            "wg0 1 2\n",
            "wg0\tzz\n",
            "wg0\t-1\n",
            "wg0\t0x100000000\n",
            "wg0\t1\nwg0\t2\n",
        ):
            with self.subTest(bad=bad):
                self.assertIsNone(parse(bad))
        self.assertIsNone(parse("wg0\t1\n", rc=1, sudo_rc=1))
        self.assertEqual(parse("wg0\t1\n", rc=1, sudo_rc=0), {"wg0": 1})
        self.assertIsNone(client._wireguard_fwmark_assignments(Scripted(default=OSError("x"))))

    def test_interface_mark_check(self) -> None:
        for value, expected in (
            (hex(MARK), True),
            (str(MARK), True),
            (hex(MARK).upper().replace("X", "x"), True),
            ("off", False),
            ("0x1", False),
            ("", False),
        ):
            with self.subTest(value=value):
                run = Scripted({("wg", "show", "wg0", "fwmark"): cp(0, value + "\n")})
                self.assertIs(client._wireguard_interface_has_fwmark(run, "wg0"), expected)
        run = Scripted({("wg",): cp(1), ("sudo", "-n", "wg"): cp(0, hex(MARK))})
        self.assertTrue(client._wireguard_interface_has_fwmark(run, "wg0"))
        run = Scripted({("wg",): cp(1), ("sudo", "-n", "wg"): cp(1)})
        self.assertFalse(client._wireguard_interface_has_fwmark(run, "wg0"))
        self.assertFalse(client._wireguard_interface_has_fwmark(Scripted(default=OSError()), "wg0"))


class IpRuleMatchTests(unittest.TestCase):
    def match(self, line, fwmark=MARK, priority=PRIORITY):
        return client._ip_rule_line_matches(line, fwmark, priority)

    def test_exact_rule_in_each_accepted_spelling(self) -> None:
        self.assertTrue(self.match(OWNED_LINE))
        self.assertTrue(self.match(f"{PRIORITY} from all fwmark {MARK} lookup main proto {PROTO}"))
        self.assertTrue(
            self.match(f"{PRIORITY}: from all fwmark {hex(MARK)} table main proto {PROTO}")
        )
        self.assertTrue(
            self.match(
                f"{PRIORITY}: from all fwmark {hex(MARK)}/0xffffffff lookup main proto {PROTO}"
            )
        )
        self.assertTrue(
            self.match(
                f"{PRIORITY}: from all fwmark {hex(MARK)}/4294967295 lookup main proto {PROTO}"
            )
        )

    def test_anything_narrower_wider_or_different_is_not_ours(self) -> None:
        base = f"{PRIORITY}: from all fwmark {hex(MARK)} lookup main proto {PROTO}"
        variants = {
            "empty": "",
            "wrong priority": base.replace(str(PRIORITY), str(PRIORITY + 1), 1),
            "non-numeric priority": base.replace(str(PRIORITY), "abc", 1),
            "partial mask": base.replace(hex(MARK), hex(MARK) + "/0xff"),
            "bad mask": base.replace(hex(MARK), hex(MARK) + "/zz"),
            "other mark": base.replace(hex(MARK), "0x1"),
            "other table": base.replace("lookup main", "lookup 200"),
            "other proto": base.replace(f"proto {PROTO}", "proto 3"),
            "no proto": f"{PRIORITY}: from all fwmark {hex(MARK)} lookup main",
            "source selector": base.replace("from all", "from 10.0.0.0/8"),
            "inverse": base.replace("from all", "not from all"),
            "extra selector": base + " iif eth0",
            "bad mark text": base.replace(hex(MARK), "xyz"),
            "selector in the mark slot": base.replace("fwmark", "uidrange"),
            "non-lookup action": base.replace("lookup main", "nat main"),
        }
        for name, line in variants.items():
            with self.subTest(name):
                self.assertFalse(self.match(line))

    def test_priority_state(self) -> None:
        def state(rules="", rc=0, error=None):
            run = Scripted({("ip", "rule", "show"): error or cp(rc, rules)})
            return client._ip_rule_priority_state(run)

        self.assertEqual(state(error=OSError("x")), "unavailable")
        self.assertEqual(state(rc=1), "unavailable")
        self.assertEqual(state(""), "absent")
        self.assertEqual(
            state("0:\tfrom all lookup local\n32766:\tfrom all lookup main\n"), "absent"
        )
        self.assertEqual(state(f"\n{OWNED_LINE}\n"), "owned")
        self.assertEqual(state(f"{PRIORITY}:\tfrom all lookup 99\n"), "conflict")
        self.assertEqual(state(f"{OWNED_LINE}\n{OWNED_LINE}\n"), "conflict")
        self.assertEqual(state(f"{OWNED_LINE}\n{PRIORITY}:\tfrom all lookup 5\n"), "conflict")
        self.assertEqual(state(f"{PRIORITY}x:\tfrom all\n"), "absent")

    def test_has_fwmark_is_true_only_for_owned(self) -> None:
        run = Scripted({("ip", "rule", "show"): cp(0, OWNED_LINE)})
        self.assertTrue(client._ip_rule_has_fwmark(run))
        run = Scripted({("ip", "rule", "show"): cp(0, "")})
        self.assertFalse(client._ip_rule_has_fwmark(run))

    def test_owned_rule_count(self) -> None:
        run = Scripted({("ip", "rule", "show"): cp(0, f"{OWNED_LINE}\n{OWNED_LINE}\nother\n")})
        self.assertEqual(client._ip_rule_owned_rule_count(run), 2)
        self.assertIsNone(client._ip_rule_owned_rule_count(Scripted({("ip",): cp(1)})))
        self.assertIsNone(client._ip_rule_owned_rule_count(Scripted(default=OSError())))


class DeleteOwnedRuleTests(unittest.TestCase):
    def test_deletes_only_the_protocol_tagged_rule_and_verifies(self) -> None:
        run = Scripted({("ip", "rule", "del"): cp(0), ("ip", "rule", "show"): cp(0, "other\n")})
        with self.assertNoLogs("nordility", level="ERROR"):
            self.assertTrue(client._delete_owned_ip_rule(run))
        command = run.ran("ip", "rule", "del")[0]
        self.assertEqual(
            command,
            (
                "ip",
                "rule",
                "del",
                "fwmark",
                str(MARK),
                "lookup",
                "main",
                "priority",
                str(PRIORITY),
                "protocol",
                str(PROTO),
            ),
        )

    def test_sudo_retry_then_failure_is_reported(self) -> None:
        run = Scripted(
            {
                ("ip", "rule", "del"): cp(1),
                ("sudo", "-n", "ip", "rule", "del"): cp(0),
                ("ip", "rule", "show"): cp(0, ""),
            }
        )
        self.assertTrue(client._delete_owned_ip_rule(run))
        run = Scripted({("ip", "rule", "del"): cp(1), ("sudo", "-n"): cp(1)})
        with self.assertLogs("nordility", level="ERROR"):
            self.assertFalse(client._delete_owned_ip_rule(run))
        with self.assertLogs("nordility", level="ERROR"):
            self.assertFalse(client._delete_owned_ip_rule(Scripted(default=OSError())))

    def test_a_rule_that_remains_or_cannot_be_checked_is_a_failure(self) -> None:
        for show in (cp(0, OWNED_LINE), cp(1)):
            with self.subTest(show=show.returncode):
                run = Scripted({("ip", "rule", "del"): cp(0), ("ip", "rule", "show"): show})
                with self.assertLogs("nordility", level="ERROR"):
                    self.assertFalse(client._delete_owned_ip_rule(run))


class RestoreRoutingTests(unittest.TestCase):
    def restore(self, sim, interfaces=("wg0",)):
        return client._restore_wireguard_routing(sim, list(interfaces))

    def test_nothing_requested_runs_nothing(self) -> None:
        sim = Sim()
        self.assertEqual(self.restore(sim, ()), [])
        self.assertEqual(sim.calls, [])

    def test_adds_the_exclusive_rule_then_marks_the_interface(self) -> None:
        sim = Sim()
        self.assertEqual(self.restore(sim), ["wg0"])
        self.assertEqual(sim.rules, [OWNED_LINE])
        self.assertEqual(sim.marks["wg0"], hex(MARK))
        add = sim.ran("ip", "rule", "add")[0]
        self.assertEqual(
            add,
            (
                "ip",
                "rule",
                "add",
                "fwmark",
                str(MARK),
                "lookup",
                "main",
                "priority",
                str(PRIORITY),
                "protocol",
                str(PROTO),
            ),
        )
        # The rule is in place before any interface is touched.
        self.assertLess(
            sim.calls.index(add), sim.calls.index(("wg", "set", "wg0", "fwmark", str(MARK)))
        )

    def test_existing_owned_rule_is_reused_not_duplicated(self) -> None:
        sim = Sim(rules=[OWNED_LINE])
        self.assertEqual(self.restore(sim), ["wg0"])
        self.assertEqual(sim.ran("ip", "rule", "add"), [])
        self.assertEqual(sim.ran("ip", "rule", "del"), [])

    def test_duplicate_interface_names_are_set_once(self) -> None:
        sim = Sim()
        self.assertEqual(self.restore(sim, ("wg0", "wg0")), ["wg0"])
        self.assertEqual(len(sim.ran("wg", "set")), 1)

    def test_unknown_inventory_refuses_any_mutation(self) -> None:
        sim = Sim()
        sim.fail_inventory = True
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(sim.ran("ip", "rule", "add"), [])
        self.assertEqual(sim.ran("wg", "set"), [])

    def test_interface_missing_from_inventory_refuses(self) -> None:
        sim = Sim(marks={"wg1": "off"})
        with self.assertLogs("nordility", level="WARNING") as logs:
            self.assertEqual(self.restore(sim), [])
        self.assertIn("wg0", "\n".join(logs.output))
        self.assertEqual(sim.ran("ip", "rule", "add"), [])

    def test_another_tunnel_already_using_the_mark_refuses(self) -> None:
        sim = Sim(marks={"wg0": "off", "other": hex(MARK)})
        with self.assertLogs("nordility", level="WARNING") as logs:
            self.assertEqual(self.restore(sim), [])
        self.assertIn("other", "\n".join(logs.output))
        self.assertEqual(sim.ran("ip", "rule", "add"), [])

    def test_a_requested_interface_sharing_the_mark_is_not_a_collision(self) -> None:
        sim = Sim(marks={"wg0": hex(MARK)})
        self.assertEqual(self.restore(sim), ["wg0"])

    def test_foreign_rule_at_our_priority_refuses(self) -> None:
        sim = Sim(rules=[f"{PRIORITY}:\tfrom all lookup 77"])
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(sim.ran("ip", "rule", "add"), [])

    def test_ip_unavailable_refuses(self) -> None:
        sim = Sim()
        sim.fail_rule_show = True
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(sim.ran("ip", "rule", "add"), [])

    def test_failed_add_returns_nothing_and_never_touches_interfaces(self) -> None:
        sim = Sim()
        sim.fail_add = True
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(sim.ran("wg", "set"), [])
        self.assertEqual(len(sim.ran("ip", "rule", "add")), 1)
        self.assertEqual(len(sim.ran("sudo", "-n", "ip", "rule", "add")), 1)
        # Nothing was created, so there is nothing to roll back.
        self.assertEqual(sim.ran("ip", "rule", "del"), [])
        self.assertEqual(sim.ran("sudo", "-n", "ip", "rule", "del"), [])

    def test_ip_command_missing_during_add(self) -> None:
        sim = Sim()
        sim.add_raises = FileNotFoundError("ip")
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(sim.ran("wg", "set"), [])

    def test_rule_that_cannot_be_verified_as_exclusive_is_rolled_back(self) -> None:
        sim = Sim()
        sim.after_add = lambda s: s.rules.append(f"{PRIORITY}:\tfrom all lookup 77")
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(self.restore(sim), [])
        self.assertEqual(len(sim.ran("ip", "rule", "del")), 1)
        self.assertEqual(sim.ran("wg", "set"), [])

    def test_collision_that_appears_after_the_add_rolls_the_rule_back(self) -> None:
        sim = Sim()
        sim.after_inventory_count = 2
        with self.assertLogs("nordility", level="WARNING") as logs:
            self.assertEqual(self.restore(sim), [])
        self.assertIn("collision appeared", "\n".join(logs.output))
        self.assertEqual(sim.rules, [])
        self.assertEqual(sim.ran("wg", "set"), [])

    def test_inventory_lost_after_the_add_rolls_back_only_a_rule_we_created(self) -> None:
        for existing, expected_deletes in ((False, 1), (True, 0)):
            with self.subTest(existing=existing):
                sim = Sim(rules=[OWNED_LINE] if existing else [])
                original = sim.__call__
                state = {"reads": 0}

                def call(command, _original=original, _state=state, _sim=sim, **kw):
                    plain = tuple(command)
                    if plain[:2] == ("sudo", "-n"):
                        plain = plain[2:]
                    if plain == ("wg", "show", "all", "fwmark"):
                        if tuple(command) == plain:
                            _state["reads"] += 1
                        if _state["reads"] >= 2:
                            return cp(1)
                    return _original(command, **kw)

                with self.assertLogs("nordility", level="WARNING"):
                    self.assertEqual(client._restore_wireguard_routing(call, ["wg0"]), [])
                self.assertEqual(len(sim.ran("ip", "rule", "del")), expected_deletes)

    def test_sudo_retry_marks_the_interface(self) -> None:
        sim = Sim()
        sim.fail_set = True
        sim.fail_sudo_too = False
        self.assertEqual(self.restore(sim), ["wg0"])
        self.assertEqual(len(sim.ran("wg", "set")), 1)
        self.assertEqual(len(sim.ran("sudo", "-n", "wg", "set")), 1)

    def test_marking_failure_rolls_back_a_new_rule_but_keeps_an_existing_one(self) -> None:
        for existing, deletes in ((False, 1), (True, 0)):
            with self.subTest(existing=existing):
                sim = Sim(rules=[OWNED_LINE] if existing else [])
                sim.fail_set = True
                with self.assertLogs("nordility", level="WARNING"):
                    self.assertEqual(self.restore(sim), [])
                self.assertEqual(len(sim.ran("ip", "rule", "del")), deletes)

    def test_partial_marking_keeps_the_rule(self) -> None:
        sim = Sim(marks={"wg0": "off", "wg1": "off"})
        original = sim.__call__

        def call(command, **kw):
            if tuple(command)[:3] == ("wg", "set", "wg1") or tuple(command)[2:5] == (
                "wg",
                "set",
                "wg1",
            ):
                return cp(1)
            return original(command, **kw)

        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(client._restore_wireguard_routing(call, ["wg0", "wg1"]), ["wg0"])
        self.assertEqual(sim.ran("ip", "rule", "del"), [])

    def test_wg_missing_is_logged_per_interface(self) -> None:
        sim = Sim()
        original = sim.__call__

        def call(command, **kw):
            if tuple(command)[:2] == ("wg", "set"):
                raise FileNotFoundError("wg")
            return original(command, **kw)

        with self.assertLogs("nordility", level="WARNING") as logs:
            self.assertEqual(client._restore_wireguard_routing(call, ["wg0"]), [])
        self.assertIn("wg not available", "\n".join(logs.output))
        self.assertEqual(len(sim.ran("ip", "rule", "del")), 1)


class RoutingRestoredCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)
        (self.config / "wg0.conf").write_text("")

    def check(self, sim, interfaces=("wg0",)):
        return client._wireguard_routing_is_restored(
            sim, interfaces=list(interfaces), wireguard_config_dir=self.config
        )

    def test_no_managed_interface_means_nothing_to_restore(self) -> None:
        sim = Sim()
        self.assertTrue(self.check(sim, ("unmanaged",)))
        self.assertTrue(self.check(sim, ("nordlynx",)))
        self.assertEqual(sim.calls, [])

    def test_interface_list_is_discovered_when_not_given(self) -> None:
        run = Scripted({("wg", "show", "interfaces"): cp(0, "")})
        self.assertTrue(
            client._wireguard_routing_is_restored(run, wireguard_config_dir=self.config)
        )

    def test_restored_only_with_rule_and_mark(self) -> None:
        self.assertTrue(self.check(Sim(marks={"wg0": hex(MARK)}, rules=[OWNED_LINE])))
        self.assertFalse(self.check(Sim(marks={"wg0": hex(MARK)}, rules=[])))
        self.assertFalse(self.check(Sim(marks={"wg0": "off"}, rules=[OWNED_LINE])))
        self.assertFalse(self.check(Sim(marks={"wg0": "0x1"}, rules=[OWNED_LINE])))

    def test_unknown_inventory_is_not_restored(self) -> None:
        sim = Sim(marks={"wg0": hex(MARK)}, rules=[OWNED_LINE])
        sim.fail_inventory = True
        self.assertFalse(self.check(sim))

    def test_foreign_tunnel_with_our_mark_is_not_restored(self) -> None:
        sim = Sim(marks={"wg0": hex(MARK), "other": hex(MARK)}, rules=[OWNED_LINE])
        self.assertFalse(self.check(sim))

    def test_only_allowed_interfaces_count(self) -> None:
        (self.config / "wg9.conf").write_text("")
        sim = Sim(marks={"wg0": hex(MARK), "wg9": "off"}, rules=[OWNED_LINE])
        self.assertTrue(self.check(sim, ("wg0", "wg9")))
        run_all = client._wireguard_routing_is_restored(
            sim,
            interfaces=["wg0", "wg9"],
            wireguard_config_dir=self.config,
            allowed_interfaces=("wg0", "wg9"),
        )
        self.assertFalse(run_all)


class SignatureTests(unittest.TestCase):
    def test_status_signature_ignores_counters(self) -> None:
        one = "Status: Connected\nHostname: a\nTransfer: 1 MiB\nUptime: 3 seconds\n"
        two = "Status: Connected\nHostname: a\nTransfer: 9 GiB\nUptime: 9 hours\n"
        self.assertEqual(client._stable_nordvpn_status(one), client._stable_nordvpn_status(two))
        self.assertEqual(client._stable_nordvpn_status(one), "Status: Connected\nHostname: a")
        self.assertEqual(client._stable_nordvpn_status("odd\n\nlines"), "odd\nlines")
        self.assertEqual(client._stable_nordvpn_status("Transfer: 1\n"), "")
        # Unrecognised lines are only a fallback when no stable field exists.
        self.assertEqual(client._stable_nordvpn_status("Status: Up\nodd line"), "Status: Up")

    def test_run_for_signature_reports_errors_and_stderr(self) -> None:
        text = client._run_for_signature(Scripted(default=OSError("gone")), ["wg", "show"])
        self.assertIn("error=OSError:gone", text)
        run = Scripted({("wg",): cp(2, "out", "bad")})
        text = client._run_for_signature(run, ["wg", "show"])
        self.assertEqual(text, "wg show\nreturncode=2\nout\nstderr=bad")
        run = Scripted({("nordvpn",): cp(0, "Status: Up\nUptime: 4\n", "")})
        self.assertEqual(
            client._run_for_signature(run, ["nordvpn", "status"]),
            "nordvpn status\nreturncode=0\nStatus: Up",
        )

    def test_connection_signature_combines_status_endpoints_and_marks(self) -> None:
        run = Scripted(default=cp(0, "x"))
        signature = client._nordvpn_connection_signature(run, executable="/bin/nordvpn")
        self.assertEqual(signature.count("\n---\n"), 2)
        self.assertEqual(
            [c for c in run.calls],
            [
                ("/bin/nordvpn", "status"),
                ("wg", "show", "nordlynx", "endpoints"),
                ("wg", "show", "nordlynx", "fwmark"),
            ],
        )


class InterfaceStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)

    def test_starts_only_configured_inactive_allowlisted_interfaces(self) -> None:
        (self.config / "wg0.conf").write_text("")
        (self.config / "wg1.conf").write_text("")
        (self.config / "nordlynx.conf").write_text("")
        (self.config / "NordLynx.conf").write_text("")
        run = Scripted(
            {
                ("wg", "show", "interfaces"): cp(0, "wg1\n"),
                ("systemctl", "start"): cp(0),
            }
        )
        started = client._ensure_wireguard_interfaces(
            run, ("wg0", "wg1", "nordlynx", "NordLynx", "wg2"), config_dir=self.config
        )
        self.assertEqual(started, ["wg0"])
        self.assertEqual(run.ran("systemctl"), [("systemctl", "start", "wg-quick@wg0.service")])

    def test_no_interfaces_means_no_commands(self) -> None:
        run = Scripted()
        self.assertEqual(client._ensure_wireguard_interfaces(run, ()), [])
        self.assertEqual(run.calls, [])

    def test_start_failures_are_reported_not_raised(self) -> None:
        (self.config / "wg0.conf").write_text("")
        run = Scripted(
            {("wg", "show", "interfaces"): cp(0, ""), ("systemctl",): cp(1), ("sudo", "-n"): cp(1)}
        )
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(client._ensure_wireguard_interfaces(run, ("wg0",), self.config), [])
        run = Scripted({("wg", "show", "interfaces"): cp(0, ""), ("systemctl",): OSError("x")})
        with self.assertLogs("nordility", level="WARNING"):
            self.assertEqual(client._ensure_wireguard_interfaces(run, ("wg0",), self.config), [])

    def test_start_uses_the_unit_not_a_raw_wg_quick(self) -> None:
        run = Scripted({("systemctl",): cp(1), ("sudo", "-n", "systemctl"): cp(0)})
        self.assertTrue(client._start_wireguard_interface(run, "wg0"))
        self.assertEqual(
            run.calls,
            [
                ("systemctl", "start", "wg-quick@wg0.service"),
                ("sudo", "-n", "systemctl", "start", "wg-quick@wg0.service"),
            ],
        )
        self.assertFalse(any(part == "wg-quick" for call in run.calls for part in call))


class PeerRefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = Path(self.tmp.name)
        (self.config / "wg0.conf").write_text("")

    def test_refresh_resets_each_peer_endpoint_on_managed_interfaces_only(self) -> None:
        run = Scripted(
            {
                ("wg", "show", "wg0", "endpoints"): cp(0, "K1\t1.1.1.1:1\nK2\t2.2.2.2:2\n"),
                ("wg", "set"): cp(0),
            }
        )
        refreshed = client._refresh_wireguard_peers(
            run, ["wg0", "nordlynx", "unmanaged"], config_dir=self.config
        )
        self.assertEqual(refreshed, ["wg0"])
        self.assertEqual(
            run.ran("wg", "set"),
            [
                ("wg", "set", "wg0", "peer", "K1", "endpoint", "1.1.1.1:1"),
                ("wg", "set", "wg0", "peer", "K2", "endpoint", "2.2.2.2:2"),
            ],
        )

    def test_without_config_requirement_only_daemon_interfaces_are_skipped(self) -> None:
        run = Scripted({("wg", "show"): cp(0, "K\t1.1.1.1:1\n"), ("wg", "set"): cp(0)})
        out = client._refresh_wireguard_peers(
            run, ["anything", "nordlynx"], config_dir=self.config, require_config=False
        )
        self.assertEqual(out, ["anything"])

    def test_failed_and_missing_set_commands_do_not_count(self) -> None:
        run = Scripted(
            {
                ("wg", "show", "wg0", "endpoints"): cp(0, "K\t1.1.1.1:1\n"),
                ("wg", "set"): cp(1),
                ("sudo", "-n", "wg", "set"): cp(1),
            }
        )
        self.assertEqual(client._refresh_wireguard_peers(run, ["wg0"], self.config), [])
        run = Scripted(
            {("wg", "show", "wg0", "endpoints"): cp(0, "K\t1.1.1.1:1\n"), ("wg", "set"): OSError()}
        )
        self.assertEqual(client._refresh_wireguard_peers(run, ["wg0"], self.config), [])

    def test_sudo_fallback_counts(self) -> None:
        run = Scripted(
            {
                ("wg", "show", "wg0", "endpoints"): cp(0, "K\t1.1.1.1:1\n"),
                ("wg", "set"): cp(1),
                ("sudo", "-n", "wg", "set"): cp(0),
            }
        )
        self.assertEqual(client._refresh_wireguard_peers(run, ["wg0"], self.config), ["wg0"])

    def test_interface_without_peers_is_skipped(self) -> None:
        run = Scripted({("wg", "show", "wg0", "endpoints"): cp(0, "")})
        self.assertEqual(client._refresh_wireguard_peers(run, ["wg0"], self.config), [])
        self.assertEqual(run.ran("wg", "set"), [])


class RestoreAfterNordvpnTests(unittest.TestCase):
    def test_no_active_interfaces_reports_only_what_was_started(self) -> None:
        with (
            mock.patch.object(client, "_ensure_wireguard_interfaces", return_value=["wg0"]),
            mock.patch.object(client, "_discover_wireguard_interfaces", return_value=[]),
        ):
            summary = client.restore_wireguard_after_nordvpn(Scripted())
        self.assertEqual(summary, client.WireGuardRestoreSummary(started=("wg0",)))

    def test_cli_backend_refreshes_and_restores_only_authorised_managed_interfaces(self) -> None:
        with (
            mock.patch.object(client, "_ensure_wireguard_interfaces", return_value=[]),
            mock.patch.object(
                client, "_discover_wireguard_interfaces", return_value=["wg0", "wg9", "nordlynx"]
            ),
            mock.patch.object(
                client, "_user_managed_wireguard_interfaces", return_value=["wg0"]
            ) as managed,
            mock.patch.object(client, "_refresh_wireguard_peers", return_value=["wg0"]) as refresh,
            mock.patch.object(
                client, "_restore_wireguard_routing", return_value=["wg0"]
            ) as restore,
        ):
            summary = client.restore_wireguard_after_nordvpn(
                Scripted(), ensure_interfaces=("wg0", "nordlynx"), fwmark=7, ip_rule_priority=8
            )
        managed.assert_called_once()
        self.assertEqual(managed.call_args.args[0], ["wg0", "nordlynx"])
        self.assertTrue(refresh.call_args.kwargs["require_config"])
        self.assertEqual(restore.call_args.kwargs, {"fwmark": 7, "ip_rule_priority": 8})
        self.assertEqual(summary.interfaces, ("wg0", "wg9", "nordlynx"))
        self.assertEqual(summary.routing_candidates, ("wg0",))
        self.assertEqual(summary.routing_restored, ("wg0",))
        self.assertEqual(summary.refreshed, ("wg0",))

    def test_windows_backend_never_changes_routing_and_skips_the_config_requirement(self) -> None:
        with (
            mock.patch.object(client, "_ensure_wireguard_interfaces", return_value=[]),
            mock.patch.object(
                client, "_discover_wireguard_interfaces", return_value=["wg0", "nordlynx"]
            ),
            mock.patch.object(client, "_user_managed_wireguard_interfaces", return_value=["wg0"]),
            mock.patch.object(client, "_refresh_wireguard_peers", return_value=["wg0"]) as refresh,
            mock.patch.object(client, "_restore_wireguard_routing") as restore,
        ):
            summary = client.restore_wireguard_after_nordvpn(Scripted(), backend="windows")
        self.assertEqual(refresh.call_args.args[1], ["wg0"])
        self.assertFalse(refresh.call_args.kwargs["require_config"])
        restore.assert_not_called()
        self.assertEqual(summary.routing_candidates, ())

    def test_nothing_managed_means_no_refresh_and_no_routing_change(self) -> None:
        with (
            mock.patch.object(client, "_ensure_wireguard_interfaces", return_value=[]),
            mock.patch.object(client, "_discover_wireguard_interfaces", return_value=["wg0"]),
            mock.patch.object(client, "_user_managed_wireguard_interfaces", return_value=[]),
            mock.patch.object(client, "_refresh_wireguard_peers") as refresh,
            mock.patch.object(client, "_restore_wireguard_routing") as restore,
        ):
            summary = client.restore_wireguard_after_nordvpn(Scripted())
        refresh.assert_not_called()
        restore.assert_not_called()
        self.assertEqual(summary.refreshed, ())

    def test_summary_text(self) -> None:
        empty = client.WireGuardRestoreSummary()
        self.assertEqual(empty.describe(), "no active WireGuard interfaces found")
        self.assertEqual(empty.message_suffix(), "")
        full = client.WireGuardRestoreSummary(
            interfaces=("wg0",),
            started=("wg0",),
            refreshed=("wg0",),
            routing_candidates=("wg0",),
            routing_restored=("wg0",),
        )
        self.assertEqual(
            full.describe(),
            "interfaces: wg0; started: wg0; refreshed: wg0; routing restored: wg0",
        )
        self.assertEqual(
            full.message_suffix(),
            "; WireGuard started on wg0; WireGuard refreshed on wg0; routing restored on wg0",
        )
        checked = client.WireGuardRestoreSummary(interfaces=("wg0",), routing_candidates=("wg0",))
        self.assertEqual(checked.describe(), "interfaces: wg0; routing candidates checked: wg0")
        self.assertEqual(
            client.WireGuardRestoreSummary(started=("wg0",)).describe(), "started: wg0"
        )


class WatcherTests(unittest.TestCase):
    def watch(self, **kwargs):
        sleeps: list[float] = []
        kwargs.setdefault("runner", Scripted())
        kwargs.setdefault("wireguard_config_dir", Path("/nonexistent-nordility-test"))
        events = client.watch_nordvpn_wireguard(sleeper=sleeps.append, **kwargs)
        return events, sleeps

    def test_argument_validation(self) -> None:
        for kwargs, fragment in (
            ({"backend": "windows"}, "cli backend"),
            ({"interval_seconds": 0}, "greater than 0"),
            ({"interval_seconds": -1}, "greater than 0"),
            ({"stabilize_seconds": -1}, "greater than or equal to 0"),
            ({"ensure_interfaces": ("wg0", "NordLynx")}, "NordLynx"),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ConfigurationError, fragment):
                self.watch(**kwargs)

    def test_zero_stabilize_wait_is_allowed(self) -> None:
        with mock.patch.object(client, "restore_wireguard_after_nordvpn"):
            self.watch(stabilize_seconds=0, once=True)

    def test_once_repairs_at_startup_and_returns(self) -> None:
        summary = client.WireGuardRestoreSummary(started=("wg0",))
        with mock.patch.object(
            client, "restore_wireguard_after_nordvpn", return_value=summary
        ) as fix:
            events, sleeps = self.watch(
                once=True, fwmark=9, ip_rule_priority=8, ensure_interfaces=("wg0",)
            )
        self.assertEqual(events, [summary])
        self.assertEqual(sleeps, [])
        self.assertEqual(fix.call_args.kwargs["fwmark"], 9)
        self.assertEqual(fix.call_args.kwargs["ip_rule_priority"], 8)
        self.assertEqual(fix.call_args.kwargs["ensure_interfaces"], ("wg0",))

    def run_loop(self, signatures, interfaces, restored, config_exists=False, **kwargs):
        sig = iter(signatures)
        with (
            mock.patch.object(client, "restore_wireguard_after_nordvpn") as fix,
            mock.patch.object(
                client, "_nordvpn_connection_signature", side_effect=lambda *a, **k: next(sig)
            ),
            mock.patch.object(client, "_discover_wireguard_interfaces", return_value=interfaces),
            mock.patch.object(client, "_wireguard_config_exists", return_value=config_exists),
            mock.patch.object(
                client, "_wireguard_routing_is_restored", return_value=restored
            ) as check,
        ):
            fix.return_value = client.WireGuardRestoreSummary()
            events, sleeps = self.watch(max_iterations=1, **kwargs)
        return fix, check, events, sleeps

    def test_stable_healthy_state_triggers_no_repair(self) -> None:
        fix, check, events, sleeps = self.run_loop(["a", "a"], ["wg0"], True)
        self.assertEqual(fix.call_count, 1)  # startup only
        self.assertEqual(len(events), 1)
        self.assertEqual(sleeps, [5])
        check.assert_called_once()

    def test_connection_change_waits_then_repairs_and_skips_other_checks(self) -> None:
        fix, check, events, sleeps = self.run_loop(
            ["a", "b", "b"], ["wg0"], True, stabilize_seconds=3
        )
        self.assertEqual(fix.call_count, 2)
        self.assertEqual(sleeps, [5, 3])
        check.assert_not_called()

    def test_no_stabilize_sleep_when_zero(self) -> None:
        fix, _, _, sleeps = self.run_loop(["a", "b", "b"], ["wg0"], True, stabilize_seconds=0)
        self.assertEqual(sleeps, [5])
        self.assertEqual(fix.call_count, 2)

    def test_configured_interface_that_is_down_triggers_repair(self) -> None:
        fix, check, _, _ = self.run_loop(
            ["a", "a"], [], True, config_exists=True, ensure_interfaces=("wg0",)
        )
        self.assertEqual(fix.call_count, 2)
        check.assert_not_called()

    def test_unconfigured_missing_interface_is_not_a_repair_trigger(self) -> None:
        fix, check, _, _ = self.run_loop(["a", "a"], [], True, config_exists=False)
        self.assertEqual(fix.call_count, 1)
        check.assert_called_once()

    def test_routing_drift_triggers_repair(self) -> None:
        fix, _, events, _ = self.run_loop(["a", "a"], ["wg0"], False)
        self.assertEqual(fix.call_count, 2)
        self.assertEqual(len(events), 2)

    def test_runs_until_max_iterations_sleeping_each_time(self) -> None:
        sig = iter(["a"] * 20)
        with (
            mock.patch.object(client, "restore_wireguard_after_nordvpn"),
            mock.patch.object(
                client, "_nordvpn_connection_signature", side_effect=lambda *a, **k: next(sig)
            ),
            mock.patch.object(client, "_discover_wireguard_interfaces", return_value=["wg0"]),
            mock.patch.object(client, "_wireguard_routing_is_restored", return_value=True),
        ):
            _, sleeps = self.watch(max_iterations=3, interval_seconds=2)
        self.assertEqual(sleeps, [2, 2, 2])


class ClientFlowTests(unittest.TestCase):
    def make(self, runner=None, backend="cli", **kwargs):
        sleeps: list[float] = []
        instance = NordVPNClient(
            executable="/usr/bin/nordvpn" if backend == "cli" else "nordvpn.exe",
            backend=backend,
            runner=runner or Scripted(default=cp(0)),
            launcher=kwargs.pop("launcher", mock.Mock()),
            sleeper=sleeps.append,
            rng=mock.Mock(choice=lambda groups: groups[0]),
            **kwargs,
        )
        instance.sleeps = sleeps  # type: ignore[attr-defined]
        return instance

    def test_command_builders_per_backend(self) -> None:
        cli = self.make()
        self.assertEqual(cli._build_connect_command(), ("/usr/bin/nordvpn", "connect"))
        self.assertEqual(
            cli._build_connect_command("United_States"),
            ("/usr/bin/nordvpn", "connect", "United States"),
        )
        self.assertEqual(cli._build_disconnect_command(), ("/usr/bin/nordvpn", "disconnect"))
        win = self.make(backend="windows")
        self.assertEqual(win._build_connect_command(), ("nordvpn.exe", "-c"))
        self.assertEqual(
            win._build_connect_command("United_States"),
            ("nordvpn.exe", "-c", "-g", "United_States"),
        )
        self.assertEqual(win._build_disconnect_command(), ("nordvpn.exe", "-d"))

    def test_login_command_runs_the_helper_module_with_the_resolved_executable(self) -> None:
        with mock.patch.object(client.shutil, "which", return_value="/opt/bin/nordvpn"):
            command = self.make()._build_login_command()
        self.assertEqual(
            command, (sys.executable, "-m", "nordility.token_login", "/opt/bin/nordvpn")
        )
        with mock.patch.object(client.shutil, "which", return_value=None):
            self.assertEqual(self.make()._build_login_command()[-1], "/usr/bin/nordvpn")

    def test_speed_validation_and_group_selection(self) -> None:
        instance = self.make()
        self.assertEqual(instance.list_groups("FAST"), client.FAST_GROUPS)
        self.assertEqual(instance.list_groups("full"), client.FULL_GROUPS)
        self.assertEqual(instance.pick_group("fast"), client.FAST_GROUPS[0])
        with self.assertRaisesRegex(ConfigurationError, "Unsupported speed: warp"):
            instance.list_groups("warp")

    def test_login_requires_a_token_and_prefers_an_explicit_one(self) -> None:
        instance = self.make()
        with self.assertRaisesRegex(ConfigurationError, "requires a token"):
            instance.login()
        with mock.patch.object(client, "_resolve_keepass_token", return_value="") as resolve:
            with self.assertRaises(ConfigurationError):
                instance.login(keepass_entry="e")
        resolve.assert_called_once_with("e", client.DEFAULT_KEEPASS_PROFILE)
        with (
            mock.patch.object(client, "_resolve_keepass_token") as resolve,
            mock.patch.object(
                instance,
                "_execute_token_login",
                return_value=CommandResult(("x",), "m", returncode=0),
            ) as run,
        ):
            result = instance.login(token="explicit", keepass_entry="e")
        resolve.assert_not_called()
        run.assert_called_once_with("explicit")
        self.assertEqual(result.message, "NordVPN Logged In")

    def test_token_login_is_cli_only(self) -> None:
        win = self.make(backend="windows")
        with self.assertRaisesRegex(ConfigurationError, "hardened Linux CLI helper"):
            win._execute_token_login(CANARY)

    def test_token_travels_on_stdin_never_in_the_command_line(self) -> None:
        runner = mock.Mock(return_value=cp(0, f"ok {CANARY}", f"warn {CANARY}"))
        instance = self.make(runner=runner)
        result = instance._execute_token_login(CANARY)
        args, kwargs = runner.call_args
        self.assertNotIn(CANARY, " ".join(args[0]))
        self.assertEqual(kwargs["input"], f"{CANARY}\n")
        self.assertNotIn(CANARY, result.stdout + result.stderr + " ".join(result.command))
        self.assertEqual(result.stdout, "ok <redacted>")

    def test_token_login_failures_never_echo_the_token(self) -> None:
        instance = self.make(runner=mock.Mock(side_effect=OSError(f"cannot run {CANARY}")))
        with self.assertRaises(CommandExecutionError) as ctx:
            instance._execute_token_login(CANARY)
        self.assertNotIn(CANARY, str(ctx.exception))

        instance = self.make(runner=mock.Mock(return_value=cp(3, "", f" bad {CANARY} \n")))
        with self.assertRaises(CommandExecutionError) as ctx:
            instance._execute_token_login(CANARY)
        self.assertEqual(str(ctx.exception), "bad <redacted>")

        instance = self.make(runner=mock.Mock(return_value=cp(3, "", "  ")))
        with self.assertRaisesRegex(CommandExecutionError, "exit code 3"):
            instance._execute_token_login(CANARY)

    def test_execute_cli_failure_and_success(self) -> None:
        instance = self.make(runner=Scripted(default=cp(2, "", " boom \n")))
        with self.assertRaisesRegex(CommandExecutionError, "^boom$"):
            instance._execute(("nordvpn", "connect"), 5)
        self.assertEqual(instance.sleeps, [])
        instance = self.make(runner=Scripted(default=cp(2)))
        with self.assertRaisesRegex(CommandExecutionError, "exit code 2"):
            instance._execute(("nordvpn", "connect"), 5)

        instance = self.make(runner=Scripted(default=cp(0, "out", "err")))
        result = instance._execute(("nordvpn", "connect"), 5)
        self.assertEqual(
            (result.message, result.stdout, result.stderr, result.returncode),
            ("Command completed", "out", "err", 0),
        )
        self.assertEqual(instance.sleeps, [5])
        instance = self.make(runner=Scripted(default=cp(0)))
        instance._execute(("nordvpn", "connect"), 0)
        self.assertEqual(instance.sleeps, [])

    def test_execute_redacts_secret_arguments_everywhere(self) -> None:
        instance = self.make(runner=Scripted(default=cp(0, f"echo {CANARY}", f"w {CANARY}")))
        result = instance._execute(("nordvpn", "login", "--token", CANARY), 0)
        self.assertEqual(result.command[-1], "<redacted>")
        self.assertNotIn(CANARY, result.stdout + result.stderr)
        instance = self.make(runner=Scripted(default=cp(1, "", f"bad {CANARY}")))
        with self.assertRaises(CommandExecutionError) as ctx:
            instance._execute(("nordvpn", "login", f"--token={CANARY}"), 0)
        self.assertNotIn(CANARY, str(ctx.exception))

    def test_windows_launcher(self) -> None:
        launcher = mock.Mock()
        win = self.make(backend="windows", launcher=launcher)
        result = win._execute(("nordvpn.exe", "-c"), 4)
        launcher.assert_called_once_with(("nordvpn.exe", "-c"))
        self.assertEqual(result.message, "Command launched")
        self.assertEqual(win.sleeps, [4])
        win = self.make(backend="windows", launcher=mock.Mock())
        win._execute(("nordvpn.exe", "-c"), 0)
        self.assertEqual(win.sleeps, [])
        failing = self.make(
            backend="windows", launcher=mock.Mock(side_effect=OSError(f"no {CANARY}"))
        )
        with self.assertRaises(CommandExecutionError) as ctx:
            failing._execute(("nordvpn.exe", "x", "--token", CANARY), 0)
        self.assertNotIn(CANARY, str(ctx.exception))

    def test_connect_messages(self) -> None:
        instance = self.make()
        self.assertEqual(instance.connect().message, "VPN Connected")
        result = instance.connect(group="Japan")
        self.assertEqual((result.message, result.group), ("VPN Connected to Japan", "Japan"))
        self.assertEqual(instance.disconnect().message, "VPN Disconnected")

    def test_connect_logs_in_once_and_retries_only_for_a_missing_login(self) -> None:
        runner = Scripted(
            {("/usr/bin/nordvpn", "connect"): [cp(1, "", "You are not logged in."), cp(0)]}
        )
        instance = self.make(runner=runner)
        with mock.patch.object(instance, "login") as login:
            result = instance.connect(auto_login=True, keepass_entry="e", keepass_profile="p")
        login.assert_called_once_with(keepass_entry="e", keepass_profile="p")
        self.assertEqual(result.message, "VPN Connected")
        self.assertEqual(len(runner.ran("/usr/bin/nordvpn", "connect")), 2)

    def test_connect_does_not_log_in_without_permission_or_for_other_errors(self) -> None:
        for auto_login, stderr in ((False, "not logged in"), (True, "network unreachable")):
            with self.subTest(auto_login=auto_login):
                instance = self.make(runner=Scripted(default=cp(1, "", stderr)))
                with (
                    mock.patch.object(instance, "login") as login,
                    self.assertRaises(CommandExecutionError),
                ):
                    instance.connect(auto_login=auto_login)
                login.assert_not_called()

    def test_change_defaults_waits_and_group(self) -> None:
        instance = self.make()
        result = instance.change()
        self.assertEqual(instance.sleeps, [10])
        self.assertEqual(result.group, client.FAST_GROUPS[0])
        self.assertEqual(
            result.message, f"VPN Connection Successfully Redirected to {client.FAST_GROUPS[0]}"
        )
        self.assertEqual(
            result.command, ("/usr/bin/nordvpn", "connect", client.FAST_GROUPS[0].replace("_", " "))
        )
        instance = self.make()
        instance.change(speed="full")
        self.assertEqual(instance.sleeps, [30])
        instance = self.make()
        result = instance.change(group="Japan", wait_seconds=1)
        self.assertEqual(instance.sleeps, [1])
        self.assertEqual((result.group, result.command[-1]), ("Japan", "Japan"))
        with self.assertRaises(ConfigurationError):
            self.make().change(speed="warp")

    def test_change_auto_login_retries_once(self) -> None:
        runner = Scripted({("/usr/bin/nordvpn", "connect"): [cp(1, "", "Please log in"), cp(0)]})
        instance = self.make(runner=runner)
        with mock.patch.object(instance, "login") as login:
            instance.change(auto_login=True, keepass_entry="e", keepass_profile="p")
        login.assert_called_once_with(keepass_entry="e", keepass_profile="p")
        runner = Scripted(default=cp(1, "", "Please log in"))
        instance = self.make(runner=runner)
        with (
            mock.patch.object(instance, "login") as login,
            self.assertRaises(CommandExecutionError),
        ):
            instance.change(auto_login=False)
        login.assert_not_called()
        instance = self.make(runner=Scripted(default=cp(1, "", "disk full")))
        with (
            mock.patch.object(instance, "login") as login,
            self.assertRaises(CommandExecutionError),
        ):
            instance.change(auto_login=True)
        login.assert_not_called()

    def test_change_can_repair_wireguard_afterwards(self) -> None:
        instance = self.make()
        summary = client.WireGuardRestoreSummary(started=("wg0",))
        with mock.patch.object(
            client, "restore_wireguard_after_nordvpn", return_value=summary
        ) as fix:
            result = instance.change(restore_wireguard=True, wireguard_fwmark=77)
        self.assertTrue(result.message.endswith("; WireGuard started on wg0"))
        self.assertEqual(fix.call_args.kwargs["fwmark"], 77)
        self.assertEqual(fix.call_args.kwargs["backend"], "cli")
        with mock.patch.object(client, "restore_wireguard_after_nordvpn") as fix:
            self.make().change()
        fix.assert_not_called()

    def test_environment_resolution(self) -> None:
        with mock.patch.dict(
            "os.environ", {"NORDILITY_EXECUTABLE": "/a", "NORDVPN_EXECUTABLE": "/b"}
        ):
            self.assertEqual(client.resolve_executable(None), "/a")
            self.assertEqual(client.resolve_executable("/explicit"), "/explicit")
        with mock.patch.dict("os.environ", {"NORDVPN_EXECUTABLE": "/b"}, clear=True):
            self.assertEqual(client.resolve_executable(None), "/b")
        with (
            mock.patch.dict("os.environ", {}, clear=True),
            mock.patch.object(client.shutil, "which", return_value=None),
        ):
            self.assertEqual(client.resolve_executable(None), client.DEFAULT_WINDOWS_EXECUTABLE)
        with mock.patch.dict("os.environ", {"NORDILITY_BACKEND": "windows"}):
            self.assertEqual(client.resolve_backend("/x", "cli"), "windows")
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertEqual(client.resolve_backend("a.EXE", "auto"), "windows")
            self.assertEqual(client.resolve_backend("a", "auto"), "cli")
            with self.assertRaisesRegex(ConfigurationError, "Unsupported backend: ssh"):
                client.resolve_backend("a", "ssh")


class ModuleWrapperTests(unittest.TestCase):
    def patched(self, **methods):
        instance = mock.Mock()
        for name, value in methods.items():
            getattr(instance, name).side_effect = (
                value if isinstance(value, BaseException) else None
            )
            if not isinstance(value, BaseException):
                getattr(instance, name).return_value = value
        return mock.patch.object(client, "NordVPNClient", return_value=instance), instance

    def test_each_wrapper_returns_message_or_result_on_success(self) -> None:
        result = CommandResult(("x",), "the message")
        for func, method, kwargs in (
            (client.login_vpn_server, "login", {"token": "t"}),
            (client.connect_vpn_server, "connect", {}),
            (client.disconnect_vpn_server, "disconnect", {}),
            (client.change_vpn_server, "change", {}),
        ):
            with self.subTest(func.__name__):
                patch, _ = self.patched(**{method: result})
                with patch:
                    self.assertEqual(func(**kwargs), "the message")
                patch, _ = self.patched(**{method: result})
                with patch:
                    self.assertIs(func(status=False, **kwargs), result)

    def test_failures_become_messages_or_are_reraised(self) -> None:
        expectations = (
            (client.login_vpn_server, "login", "NordVPN Login Failed"),
            (client.connect_vpn_server, "connect", "VPN Failed to Connect"),
            (client.disconnect_vpn_server, "disconnect", "VPN Failed to Disconnect"),
            (
                client.change_vpn_server,
                "change",
                "VPN Connection Failed to Redirect to selected group",
            ),
        )
        for func, method, message in expectations:
            with self.subTest(func.__name__):
                error = CommandExecutionError(f"boom {method}")
                patch, _ = self.patched(**{method: error})
                with patch, self.assertLogs("nordility", level="ERROR") as logs:
                    self.assertEqual(func(), message)
                self.assertIn(f"boom {method}", "\n".join(logs.output))
                patch, _ = self.patched(**{method: error})
                with patch, self.assertLogs("nordility", level="ERROR"):
                    with self.assertRaises(CommandExecutionError):
                        func(status=False)

    def test_unexpected_errors_are_not_swallowed(self) -> None:
        patch, _ = self.patched(connect=RuntimeError("bug"))
        with patch, self.assertRaises(RuntimeError):
            client.connect_vpn_server()

    def test_change_wrapper_chooses_the_reset_and_names_the_failed_group(self) -> None:
        result = CommandResult(("x",), "m")
        patch, instance = self.patched(change=result)
        with patch:
            client.change_vpn_server(
                speed="fast",
                fast_reset=1,
                default_reset=2,
                restore_wireguard=True,
                wireguard_fwmark=5,
            )
            client.change_vpn_server(speed="full", fast_reset=1, default_reset=2)
        first, second = instance.change.call_args_list
        self.assertEqual(first.kwargs["wait_seconds"], 1)
        self.assertEqual(second.kwargs["wait_seconds"], 2)
        self.assertTrue(first.kwargs["restore_wireguard"])
        self.assertEqual(first.kwargs["wireguard_fwmark"], 5)
        patch, _ = self.patched(change=CommandExecutionError("x"))
        with patch, self.assertLogs("nordility", level="ERROR"):
            self.assertEqual(
                client.change_vpn_server(group="Japan"),
                "VPN Connection Failed to Redirect to Japan",
            )

    def test_connect_wrapper_passes_group_and_wait(self) -> None:
        patch, instance = self.patched(connect=CommandResult(("x",), "m"))
        with patch:
            client.connect_vpn_server(group="Japan", wait_seconds=3, executable="/x", backend="cli")
        instance.connect.assert_called_once_with(group="Japan", wait_seconds=3)


if __name__ == "__main__":
    logging.disable(logging.NOTSET)
    unittest.main()
