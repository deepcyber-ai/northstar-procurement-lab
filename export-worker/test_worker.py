import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import worker


def request(export_format="csv", vulnerable=True):
    return {"version": 1, "action": "export", "format": export_format,
            "vulnerable": vulnerable, "order": {"id": "ORD-A-100"}}


class ExportWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        worker.enable_subreaper()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="northstar-export-test-")
        self.scratch_patch = patch.object(worker, "SCRATCH", Path(self.temp.name) / "scratch")
        self.scratch_patch.start()

    def tearDown(self):
        self.scratch_patch.stop()
        self.temp.cleanup()

    def test_harmless_marker_executes_only_when_vulnerable(self):
        payload = "csv; printf CMD01_PROOF"
        vulnerable = worker.handle(request(payload))
        self.assertIn("CMD01_PROOF", vulnerable["output"])
        self.assertEqual(0, vulnerable["exitCode"])
        fixed = worker.handle(request(payload, False))
        self.assertEqual("INVALID_EXPORT_FORMAT", fixed["error"])
        self.assertEqual("", fixed["output"])

    def test_fixed_formats_do_not_create_a_subprocess(self):
        with patch.object(worker.subprocess, "Popen") as launch:
            self.assertEqual(worker.CSV, worker.handle(request("csv", False))["output"])
            self.assertEqual(worker.FIXTURE, json.loads(worker.handle(request("json", False))["output"]))
            self.assertEqual("INVALID_EXPORT_FORMAT", worker.handle(request("XML", False))["error"])
        launch.assert_not_called()

    def test_order_id_is_never_shell_interpreted(self):
        body = request()
        body["order"]["id"] = "anything; printf UNEXPECTED_ORDER_INJECTION"
        self.assertNotIn("UNEXPECTED_ORDER_INJECTION", worker.handle(body)["output"])

    def test_timeout_terminates_command(self):
        before = time.monotonic()
        reply = worker.vulnerable_export("csv; sleep 10", timeout=0.1)
        self.assertTrue(reply["timedOut"])
        self.assertEqual(124, reply["exitCode"])
        self.assertLess(time.monotonic() - before, 1.5)

    def test_infinite_output_is_bounded(self):
        before = time.monotonic()
        reply = worker.handle(request("csv; yes X"))
        self.assertEqual(worker.MAX_OUTPUT, len(reply["output"].encode()))
        self.assertEqual("OUTPUT_LIMIT", reply["error"])
        self.assertEqual(125, reply["exitCode"])
        self.assertLess(time.monotonic() - before, 1.5)

    @unittest.skipUnless(os.path.isdir("/proc/self"), "Linux descendant cleanup")
    def test_background_and_detached_children_are_cleaned_up(self):
        before = worker.descendant_pids()
        worker.handle(request("csv; sleep 20 >/dev/null 2>&1 &"))
        worker.handle(request("csv; setsid sh -c 'sleep 20' >/dev/null 2>&1 &"))
        self.assertEqual(before, worker.descendant_pids())

    def test_bad_payloads_are_rejected(self):
        bad = [None, [], {}, {"version": True, "action": "reset"}, {"version": 1.0, "action": "reset"},
               {"version": 1, "action": "anything"}, {**request(), "extra": "value"},
               {**request(), "vulnerable": "true"}, {**request(), "order": {"item": "unsafe"}}]
        bad += [request(value) for value in (None, 1, "", "x" * 129, "csv\n", "csv\x00", "csv\x7f")]
        for body in bad:
            with self.subTest(body=body):
                self.assertEqual("INVALID_REQUEST", worker.handle(body)["error"])

    def test_reset_only_removes_named_scratch_files(self):
        worker.SCRATCH.mkdir()
        for name in worker.KNOWN_SCRATCH:
            (worker.SCRATCH / name).write_text("marker")
        (worker.SCRATCH / "untouched.txt").write_text("keep")
        reply = worker.handle({"version": 1, "action": "reset"})
        self.assertEqual(0, reply["exitCode"])
        self.assertTrue((worker.SCRATCH / "untouched.txt").exists())
        self.assertTrue(all(not (worker.SCRATCH / name).exists() for name in worker.KNOWN_SCRATCH))
        self.assertEqual("INVALID_REQUEST", worker.handle({"version": 1, "action": "reset", "path": "/"})["error"])

    def test_reset_does_not_follow_scratch_directory_symlink(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "proof.txt").write_text("keep")
        worker.SCRATCH.symlink_to(outside)
        self.assertEqual("RESET_FAILED", worker.handle({"version": 1, "action": "reset"})["error"])
        self.assertEqual("keep", (outside / "proof.txt").read_text())

    def test_reset_unlinks_file_symlink_not_target(self):
        worker.SCRATCH.mkdir()
        outside = Path(self.temp.name) / "outside"
        outside.write_text("keep")
        (worker.SCRATCH / "proof.txt").symlink_to(outside)
        self.assertEqual(0, worker.handle({"version": 1, "action": "reset"})["exitCode"])
        self.assertEqual("keep", outside.read_text())

    def test_protocol_limits_and_duplicate_keys(self):
        frames = [b'{"version":1,"version":1}\n', b'{}\n{}\n', b'x' * (worker.MAX_FRAME + 1), b'{}']
        for frame in frames:
            with self.subTest(size=len(frame)):
                client, server = socket.socketpair()
                def send():
                    try:
                        client.sendall(frame)
                        client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                sender = threading.Thread(target=send)
                sender.start()
                with client, server:
                    with self.assertRaises(ValueError):
                        worker.read_frame(server)
                sender.join(timeout=1)

    def test_valid_frame(self):
        client, server = socket.socketpair()
        with client, server:
            client.sendall(json.dumps(request()).encode() + b"\n")
            self.assertEqual(request(), worker.read_frame(server))

    def test_protocol_read_deadline(self):
        client, server = socket.socketpair()
        before = time.monotonic()
        with client, server:
            with self.assertRaises((TimeoutError, socket.timeout)):
                worker.read_frame(server)
        self.assertLess(time.monotonic() - before, 1)


if __name__ == "__main__":
    unittest.main()
