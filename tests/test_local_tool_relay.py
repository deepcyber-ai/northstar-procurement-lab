"""Offline contract tests: mock Docker completely; never mutate the daemon."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "local_tool_relay", Path(__file__).resolve().parents[1] / "scripts/local-tool-relay.py")
relay_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay_module)
GATEWAY, TOOL, OTHER = "a" * 64, "b" * 64, "c" * 64
IMAGE = "sha256:" + "d" * 64


def info(container_id, service="", run=""):
    return {"id": container_id, "name": "/fixture", "running": True,
            "service": service, "project": "test", "image": IMAGE,
            "run": run, "mode": "bridge", "ports": {}, "labels": {}}


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.relay = relay_module.Relay(GATEWAY, TOOL, "strix", "new-run")
        self.gateway = info(GATEWAY, "gateway")
        self.gateway["ports"] = {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
        self.tool = info(TOOL, run="new-run")
        self.helper = info(OTHER)
        self.helper.update(labels=self.relay.labels, mode="container:" + TOOL)
        self.prints = contextlib.redirect_stdout(io.StringIO())
        self.prints.__enter__()
        self.addCleanup(self.prints.__exit__, None, None, None)

    def network(self, members=None, internal=True, labels=None):
        return [internal, "bridge", members if members is not None else {GATEWAY: {}, TOOL: {}},
                *(labels or self.relay.labels).values()]

    def test_full_ids_and_unique_targets_required(self):
        for args in (("a", TOOL, "artex"), (GATEWAY, GATEWAY, "artex"),
                     (GATEWAY + "\n", TOOL, "artex"), (GATEWAY, TOOL, "strix")):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                relay_module.Relay(*args)

    def test_artex_rejects_run_id(self):
        with self.assertRaises(RuntimeError):
            relay_module.Relay(GATEWAY, TOOL, "artex", "unexpected")

    def test_selected_fields_use_valid_parenthesized_go_template(self):
        with patch.object(relay_module, "docker", return_value='["gateway"]') as docker:
            relay_module.selected("container", GATEWAY, ('index .Config.Labels "service"',))
            self.assertIn('{{json (index .Config.Labels "service")}}', docker.call_args.args[3])

    def test_inspection_does_not_request_environment(self):
        with patch.object(relay_module, "docker", side_effect=['[]', '[]']) as docker:
            relay_module.container(TOOL)
            self.assertNotIn(".Env", str(docker.call_args_list))
            self.assertNotIn("{{json .}}", str(docker.call_args_list))

    def test_existing_resource_refused_without_mutation(self):
        with patch.object(self.relay, "existing", return_value=(True, False)), \
                patch.object(relay_module, "docker") as docker, self.assertRaises(RuntimeError):
            self.relay.setup()
        docker.assert_not_called()

    def test_wrong_run_refused(self):
        self.tool["run"] = "old-run"
        with patch.object(relay_module, "container", side_effect=[self.gateway, self.tool]), \
                patch.object(relay_module, "docker") as docker, self.assertRaises(RuntimeError):
            self.relay.verify_targets()
        docker.assert_not_called()

    def test_gateway_must_be_loopback_only(self):
        self.gateway["ports"]["8080/tcp"][0]["HostIp"] = "0.0.0.0"
        with patch.object(relay_module, "container", side_effect=[self.gateway, self.tool]), \
                self.assertRaises(RuntimeError):
            self.relay.verify_targets()

    def test_running_identity_required(self):
        self.tool["running"] = False
        with patch.object(relay_module, "container", side_effect=[self.gateway, self.tool]), \
                self.assertRaises(RuntimeError):
            self.relay.verify_targets()

    def test_artex_service_required(self):
        artex = relay_module.Relay(GATEWAY, TOOL, "artex")
        with patch.object(relay_module, "container", side_effect=[self.gateway, self.tool]), \
                self.assertRaises(RuntimeError):
            artex.verify_targets()

    def test_occupied_port_refuses_before_network_creation(self):
        with patch.object(self.relay, "existing", return_value=(False, False)), \
                patch.object(self.relay, "verify_targets", return_value=IMAGE), \
                patch.object(relay_module, "docker", side_effect=RuntimeError("occupied")) as docker, \
                self.assertRaises(RuntimeError):
            self.relay.setup()
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(docker.call_args.args[:4], ("exec", TOOL, "python3", "-c"))

    def test_port_check_rejects_ipv4_listener(self):
        table = "header\n0: 0100007F:1F90 00000000:0000 0A\n"
        with patch.object(Path, "read_text", return_value=table), self.assertRaises(SystemExit):
            exec(relay_module.PORT_CHECK, {})

    def test_port_check_rejects_ipv6_listener(self):
        table = "header\n0: 00000000000000000000000000000000:1F90 0:0000 0A\n"
        with patch.object(Path, "read_text", side_effect=["header\n", table]), \
                self.assertRaises(SystemExit):
            exec(relay_module.PORT_CHECK, {})

    def test_port_check_allows_other_listeners(self):
        table = "header\n0: 0100007F:BBd0 00000000:0000 0A\n"
        with patch.object(Path, "read_text", return_value=table):
            exec(relay_module.PORT_CHECK, {})

    def test_port_check_fails_closed_when_unavailable(self):
        with patch.object(Path, "read_text", side_effect=OSError("unavailable")), \
                self.assertRaises(OSError):
            exec(relay_module.PORT_CHECK, {})

    def test_setup_only_connects_explicit_targets_and_mounts_config(self):
        with patch.object(self.relay, "existing", return_value=(False, False)), \
                patch.object(self.relay, "verify_targets", return_value=IMAGE), \
                patch.object(self.relay, "status"), patch.object(relay_module, "docker") as docker:
            self.relay.setup()
        commands = [c.args for c in docker.call_args_list]
        connects = [c for c in commands if c[:2] == ("network", "connect")]
        self.assertEqual({c[-1] for c in connects}, {GATEWAY, TOOL})
        self.assertIn("--internal", commands[1])
        run = next(c for c in commands if c[0] == "run")
        self.assertEqual(run.count("--mount"), 1)
        self.assertNotIn("--publish", run)
        self.assertNotIn("-p", run)
        self.assertIn("container:" + TOOL, run)
        self.assertIn("--read-only", run)
        self.assertIn("never", run)
        self.assertIn(IMAGE, run)

    def test_extra_network_member_refuses_all_cleanup(self):
        with patch.object(self.relay, "existing", return_value=(True, True)), \
                patch.object(relay_module, "selected", return_value=self.network({OTHER: {}})), \
                patch.object(relay_module, "docker") as docker, self.assertRaises(RuntimeError):
            self.relay.remove()
        docker.assert_not_called()

    def test_unowned_labels_refuse_cleanup(self):
        labels = dict(self.relay.labels, gateway=OTHER)
        with patch.object(relay_module, "selected", return_value=self.network(labels=labels)), \
                self.assertRaises(RuntimeError):
            self.relay.verify_owned(True, False)

    def test_noninternal_network_refused(self):
        with patch.object(relay_module, "selected", return_value=self.network(internal=False)), \
                self.assertRaises(RuntimeError):
            self.relay.verify_owned(True, False)

    def test_wrong_relay_namespace_refused(self):
        self.helper["mode"] = "host"
        with patch.object(relay_module, "container", return_value=self.helper), \
                self.assertRaises(RuntimeError):
            self.relay.verify_owned(False, True)

    def test_cleanup_exact_helper_only(self):
        with patch.object(self.relay, "existing", return_value=(True, True)), \
                patch.object(relay_module, "selected", return_value=self.network()), \
                patch.object(relay_module, "container", return_value=self.helper), \
                patch.object(relay_module, "docker") as docker:
            self.relay.remove()
        self.assertEqual([c.args for c in docker.call_args_list], [
            ("container", "rm", "--force", self.relay.relay),
            ("network", "disconnect", self.relay.network, GATEWAY),
            ("network", "disconnect", self.relay.network, TOOL),
            ("network", "rm", self.relay.network)])

    def test_partial_setup_can_be_removed_without_scanner(self):
        with patch.object(self.relay, "existing", return_value=(True, False)), \
                patch.object(relay_module, "selected", return_value=self.network({GATEWAY: {}})), \
                patch.object(relay_module, "docker") as docker:
            self.relay.remove()
        self.assertEqual(docker.call_count, 2)
        self.assertNotIn("container", str(docker.call_args_list))

    def test_status_is_nonmutating(self):
        with patch.object(self.relay, "existing", return_value=(True, True)), \
                patch.object(self.relay, "verify_owned", return_value={GATEWAY: {}, TOOL: {}}), \
                patch.object(self.relay, "verify_targets"), \
                patch.object(relay_module, "container", return_value=self.helper), \
                patch.object(relay_module, "docker") as docker:
            self.relay.status()
        docker.assert_not_called()

    def test_docker_failure_does_not_leak_diagnostics(self):
        failure = subprocess.CompletedProcess([], 1, "secret", "secret")
        with patch.object(relay_module.subprocess, "run", return_value=failure), \
                self.assertRaisesRegex(RuntimeError, "^Docker command failed: network ls$"):
            relay_module.docker("network", "ls")


if __name__ == "__main__":
    unittest.main()
