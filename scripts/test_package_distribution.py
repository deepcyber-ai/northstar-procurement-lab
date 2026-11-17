#!/usr/bin/env python3
"""Offline release checks: synthetic temp trees only; no Docker or network calls."""
import ast
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "package_distribution.sh"
PROJECT = "northstar-procurement-0.1.0-rc.3"
SOURCE = SCRIPT.read_text(encoding="utf-8")
# Read only literal allowlists, never execute the embedded packager in-process.
PYTHON_SOURCE = SOURCE.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
LISTS = {
    node.targets[0].id: ast.literal_eval(node.value)
    for node in ast.parse(PYTHON_SOURCE).body
    if isinstance(node, ast.Assign) and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id in {
        "ROOT_FILES", "DOC_FILES", "SOURCE_DIRS", "EXTRA_FILES", "REQUIRED_SOURCE_FILES"
    }
}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="northstar-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        for directory in LISTS["SOURCE_DIRS"]:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        required = set(LISTS["ROOT_FILES"] + LISTS["EXTRA_FILES"] + LISTS["REQUIRED_SOURCE_FILES"])
        required.update("docs/" + name for name in LISTS["DOC_FILES"])
        for relative in required:
            self.put(relative, "Synthetic release fixture.\n")
        shutil.copy2(SCRIPT, self.root / "package_distribution.sh")
        shutil.copy2(Path(__file__), self.root / "scripts/test_package_distribution.py")
        self.put("VERSION", "0.1.0-rc.3\n")
        self.put(".env.example", "LAB_CALLBACK_TOKEN=\n")

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_packager(self, *arguments):
        return subprocess.run(
            ["bash", str(self.root / "package_distribution.sh"), *arguments],
            cwd=self.root, text=True, capture_output=True, timeout=20, check=False,
        )

    def require_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def require_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "dist" / PROJECT).exists())
        if (self.root / "dist").exists():
            self.assertFalse(list((self.root / "dist").glob(".northstar-release-*")))

    def archive(self):
        return self.root / "dist" / PROJECT / (PROJECT + ".zip")

    def test_curated_runtime_tests_and_docs_are_included(self):
        self.put("backend/src/test/java/FixtureTest.java", "// Source test fixture\n")
        self.put("frontend/src/uncommitted.ts", "// Working-tree source is included\n")
        self.put("owner-control/test_control.py", "# Offline source test\n")
        self.put("export-worker/test_worker.py", "# Offline source test\n")
        self.put("infra/main.tf", "private deployment fixture\n")
        self.put("infra-aws-native/main.tf", "private deployment fixture\n")
        self.put("infra-aws-native/functions/owner-control.py", "private handler fixture\n")
        self.put("docs/AWS_DEPLOYMENT.md", "private runbook fixture\n")
        self.put("docs/ANSWER_KEY.md", "unselected legacy document\n")
        self.require_success(self.run_packager())
        with zipfile.ZipFile(self.archive()) as archive:
            names = {entry.filename for entry in archive.infolist()}
            for relative in (
                ".dockerignore", ".env.example", "VERSION", "LICENSE", "NOTICE", "owner-control/Dockerfile",
                "export-worker/Dockerfile", "scripts/local-tool-relay.py",
                "scripts/test_package_distribution.py", "tests/test_local_tool_relay.py",
                "backend/src/test/java/FixtureTest.java", "frontend/src/uncommitted.ts",
                "owner-control/test_control.py", "export-worker/test_worker.py",
                "infra-aws-native/functions/owner-demo.html", "docs/LAB_OPERATIONS.md",
                "docs/LOCAL_TESTING_SETUP.md", "docs/RELEASE_NOTES.md",
                "docs/screenshots/artex-test-account-fields.png",
                "docs/screenshots/artex-budget-exhausted.png",
                "docs/screenshots/northstar-home.jpg",
                "docs/screenshots/northstar-login.jpg",
                "docs/screenshots/northstar-order-summary.jpg",
            ):
                self.assertIn(PROJECT + "/" + relative, names)
            self.assertEqual(
                [name for name in names if "/infra" in name],
                [PROJECT + "/infra-aws-native/functions/owner-demo.html"],
            )
            self.assertNotIn(PROJECT + "/docs/AWS_DEPLOYMENT.md", names)
            self.assertNotIn(PROJECT + "/docs/ANSWER_KEY.md", names)
            self.assertIsNone(archive.testzip())
            self.assertEqual(len(names), len(archive.infolist()))
            self.assertTrue(all(stat.S_ISREG(entry.external_attr >> 16) for entry in archive.infolist()))
        checksum = self.archive().with_suffix(".zip.sha256").read_text().split()[0]
        self.assertEqual(checksum, hashlib.sha256(self.archive().read_bytes()).hexdigest())

    def test_runtime_secrets_state_caches_and_archives_are_excluded(self):
        excluded = (
            ".env", "owner-control/.env", "backend/.env.example", "backend/identity/opaque.json",
            "backend/keys/opaque.json", "backend/data/opaque.json", "backend/runtime/opaque.json",
            "backend/state/opaque.json", "backend/northstar.db", "backend/identity.db-wal",
            "backend/identity.db-shm", "backend/backup.DB.2026", "backend/users.sqlite3",
            "backend/signing.jwk", "backend/key.JWKS", "backend/private_key.json",
            "backend/key.pem", "backend/key.key", "backend/credentials.json", "backend/.netrc",
            "backend/key.p12", "backend/key.pfx", "backend/key.jks", "backend/id_ed25519",
            "backend/terraform.tfvars", "backend/state.tfstate.backup", "backend/state.tfplan",
            "backend/.terraform/cache", "backend/.build/cache", "backend/.aws/config",
            "frontend/node_modules/package/file.js", "frontend/.angular/cache/file",
            "backend/target/file", "backend/.cache/file", "export-worker/__pycache__/worker.pyc",
            "owner-control/.pytest_cache/file", "backend/results/evidence.json",
            "backend/strix_runs/evidence.json", "backend/dist/old.txt", "backend/run.log",
            "backend/old.zip", "backend/old.tgz", "backend/old.tar.gz", "backend/.DS_Store",
        )
        marker = "RUNTIME_" + "EXCLUSION_FIXTURE"
        for relative in excluded:
            self.put(relative, marker + "\n")
        self.require_success(self.run_packager())
        with zipfile.ZipFile(self.archive()) as archive:
            self.assertFalse(any(marker.encode() in archive.read(name) for name in archive.namelist()))
            for relative in excluded:
                self.assertNotIn(PROJECT + "/" + relative, archive.namelist())

    def test_populated_example_credentials_are_rejected_without_echo(self):
        secret = "sk-" + "fixture" * 6
        self.put(".env.example", "OPENAI_API_KEY=" + secret + "\n")
        result = self.run_packager()
        self.require_failure(result)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_private_key_in_ordinary_source_is_rejected(self):
        self.put("backend/notes.txt", "-----BEGIN " + "PRIVATE KEY-----\nfixture\n")
        result = self.run_packager()
        self.require_failure(result)
        self.assertNotIn("fixture", result.stdout + result.stderr)

    def test_source_symlink_is_rejected(self):
        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("outside fixture")
        (self.root / "backend/linked.txt").symlink_to(outside)
        self.require_failure(self.run_packager())

    def test_explicit_allowlist_parent_symlink_is_rejected(self):
        original = self.root / "infra-aws-native/functions"
        external = Path(self.temporary.name) / "external-functions"
        original.rename(external)
        original.symlink_to(external, target_is_directory=True)
        self.require_failure(self.run_packager())

    def test_unsafe_filename_is_rejected_without_echo(self):
        for filename in ("bad\nname.txt", "bad\\name.txt", "bad\x85name.txt", "bad:name.txt"):
            with self.subTest(filename=repr(filename)):
                path = self.put("backend/" + filename, "fixture")
                result = self.run_packager()
                self.require_failure(result)
                self.assertNotIn(filename, result.stdout + result.stderr)
                path.unlink()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_special_file_is_rejected_without_reading(self):
        os.mkfifo(self.root / "backend/fixture.fifo")
        self.require_failure(self.run_packager())

    def test_oversized_source_is_rejected(self):
        with (self.root / "backend/large.bin").open("wb") as stream:
            stream.truncate(25 * 1024 * 1024 + 1)
        self.require_failure(self.run_packager())

    def test_failure_preserves_older_deliverable(self):
        old = self.put("dist/older-candidate/old.zip", "previous valid bundle fixture")
        before = old.read_bytes()
        (self.root / "owner-control/Dockerfile").unlink()
        self.require_failure(self.run_packager())
        self.assertEqual(old.read_bytes(), before)

    def test_completed_candidate_cannot_be_overwritten(self):
        self.require_success(self.run_packager())
        before = self.archive().read_bytes()
        self.put("README.md", "changed fixture")
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.archive().read_bytes(), before)

    def test_mid_build_rejection_preserves_older_deliverable(self):
        old = self.put("dist/older-candidate/old.zip", "previous valid bundle fixture")
        before = old.read_bytes()
        self.put("backend/notes.txt", "-----BEGIN " + "PRIVATE KEY-----\nfixture\n")
        self.require_failure(self.run_packager())
        self.assertEqual(old.read_bytes(), before)

    def test_check_is_offline_and_writes_no_deliverable(self):
        self.require_success(self.run_packager("--check"))
        self.assertFalse((self.root / "dist").exists())

    def test_distribution_directory_symlink_is_rejected(self):
        external = Path(self.temporary.name) / "external-dist"
        external.mkdir()
        (self.root / "dist").symlink_to(external, target_is_directory=True)
        self.assertNotEqual(self.run_packager().returncode, 0)
        self.assertEqual(list(external.iterdir()), [])

    def test_licence_and_notice_are_required(self):
        for relative in ("LICENSE", "NOTICE"):
            with self.subTest(relative=relative):
                (self.root / relative).unlink()
                self.require_failure(self.run_packager())
                self.put(relative, "Owner-selected licence fixture\n")

    def test_version_cannot_escape_distribution_directory(self):
        self.put("VERSION", "../../outside\n")
        self.require_failure(self.run_packager())


if __name__ == "__main__":
    unittest.main(verbosity=2)
