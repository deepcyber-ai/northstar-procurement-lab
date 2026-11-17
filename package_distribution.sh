#!/usr/bin/env bash
# Build an audited, Docker-only source preview. Requires Python 3, no packages.
set -Eeuo pipefail
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 - "$SCRIPT_DIR" "$@" <<'PY'
import fnmatch
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile

ROOT = Path(sys.argv[1])
CHECK_ONLY = sys.argv[2:] == ["--check"]
if sys.argv[2:] not in ([], ["--check"]):
    sys.exit("Usage: bash package_distribution.sh [--check]")

ROOT_FILES = (
    ".env.example", ".gitignore", ".dockerignore", "README.md", "VERSION", "LICENSE", "NOTICE",
    "docker-compose.yml", "package_distribution.sh",
    "scripts/test_package_distribution.py", "scripts/local-tool-relay.py",
    "tests/test_local_tool_relay.py",
)
DOC_FILES = (
    "USER_GUIDE.md", "KNOWN_VULNERABILITIES.md", "LAB_OPERATIONS.md",
    "ARTEX_TO_STRIX_RETEST_TUTORIAL.md", "LOCAL_TESTING_SETUP.md",
    "screenshots/artex-test-account-fields.png",
    "screenshots/artex-budget-exhausted.png",
    "screenshots/northstar-home.jpg",
    "screenshots/northstar-login.jpg",
    "screenshots/northstar-order-summary.jpg",
    "artex-local/localhost-proxy.conf",
    "blog/ai-assisted-pentesting-discovery-to-retest.md", "RELEASE_NOTES.md",
)
SOURCE_DIRS = (
    "backend", "frontend", "gateway", "owner-control", "export-worker",
    "openapi", "docs/retest-pack-template",
)
# The local Docker owner-control image shares this static page with AWS.
# No Terraform, AWS handlers, deployment scripts or private runbooks are shipped.
EXTRA_FILES = ("infra-aws-native/functions/owner-demo.html",)
REQUIRED_SOURCE_FILES = (
    "backend/Dockerfile", "backend/.dockerignore", "backend/pom.xml",
    "backend/src/main/java/com/deepcyber/training/TrainingLabApplication.java",
    "backend/src/main/resources/application.yml",
    "backend/src/test/java/com/deepcyber/training/TrainingLabApiTests.java",
    "frontend/Dockerfile", "frontend/.dockerignore", "frontend/package.json",
    "frontend/package-lock.json", "frontend/angular.json", "frontend/src/main.ts",
    "gateway/Dockerfile", "gateway/.dockerignore", "gateway/default.conf",
    "gateway/training-proxy-headers.conf",
    "owner-control/Dockerfile", "owner-control/control.py",
    "owner-control/local_server.py", "owner-control/configure_owner.py",
    "owner-control/test_control.py", "export-worker/Dockerfile",
    "export-worker/.dockerignore", "export-worker/worker.py", "export-worker/test_worker.py",
    "openapi/lab-api.yaml", "docs/retest-pack-template/START_HERE.md",
)
EXCLUDED_NAMES = {
    ".git", ".terraform", ".terraform-data", ".build", "node_modules",
    "target", "dist", "results", "strix_runs", ".aws", ".ssh", ".kube",
    ".docker", ".cache", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".angular", ".next", ".venv", "venv", "coverage",
    "htmlcov", "logs", "runtime", "state", "data", "identity", "keys",
    "lab-data", "lab-config", "identity-data", "identity-keys", "export-socket",
    ".npmrc", ".pypirc", ".netrc", ".terraformrc", "terraform.rc", ".ds_store",
}
EXCLUDED_PATTERNS = (
    ".env", ".env.*", "*.db*", "*.sqlite*", "*.jwk*", "*.pem", "*.key",
    "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa*", "id_ed25519*",
    "credentials*", "*private-key*", "*private_key*", "*signing-key*",
    "*signing_key*", "terraform.tfvars*", "*.auto.tfvars*", "*.tfstate*",
    "*.tfplan", "*.log", "*.pyc", "*.pyo", ".coverage*", "*.zip", "*.tgz",
    "*.tar", "*.tar.*", "*.gz", "*.bz2", "*.xz", "*.7z", "*.rar", "*.sock",
)
MAX_BYTES = 25 * 1024 * 1024
# Heuristic detection, not a claim that all secrets are found. Every packaged
# file is scanned, including this script and its fixture tests.
SECRET_PATTERN = re.compile(
    rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|"
    rb"(?:AKIA|ASIA)[0-9A-Z]{16}|sk-(?:ant-)?[A-Za-z0-9_-]{16,}|"
    rb"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    rb"xox[baprs]-[A-Za-z0-9-]{16,}|AIza[0-9A-Za-z_-]{30,}|"
    rb"(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|LLM_API_KEY|"
    rb"LAB_RESET_TOKEN|LAB_CALLBACK_TOKEN|NORTHSTAR_OWNER_DIGEST|NORTHSTAR_OWNER_SALT)"
    rb"[ \t]*[:=][ \t]*[\"']?[A-Za-z0-9_./+=-]{12,}"
)


def fail(message):
    raise ValueError(message)


def safe_path(relative):
    if (not relative or PurePosixPath(relative).is_absolute() or "\\" in relative or ":" in relative
            or any(unicodedata.category(char) in ("Cc", "Cf") for char in relative)
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        fail("Unsafe source/archive path; no path or contents printed.")


def excluded(relative):
    if relative == ".env.example":
        return False
    return any(part.lower() in EXCLUDED_NAMES
               or any(fnmatch.fnmatchcase(part.lower(), pattern) for pattern in EXCLUDED_PATTERNS)
               for part in PurePosixPath(relative).parts)


def file_bytes(relative):
    safe_path(relative)
    path = ROOT / relative
    for parent in [path, *path.parents]:
        if parent == ROOT:
            break
        if parent.is_symlink():
            fail("Refusing a symbolic link in an allowlisted source path.")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        fail("Refusing a non-regular source file.")
    with path.open("rb") as stream:
        content = stream.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        fail("Refusing a source file larger than 25 MiB.")
    if SECRET_PATTERN.search(content):
        fail("Refusing content resembling a private key or populated credential; contents withheld.")
    return content, metadata.st_mode


def collect_files():
    required = set(ROOT_FILES + EXTRA_FILES + REQUIRED_SOURCE_FILES)
    required.update("docs/" + name for name in DOC_FILES)
    files = set(required)
    for directory in SOURCE_DIRS:
        source = ROOT / directory
        if not source.is_dir() or source.is_symlink():
            fail("Missing or unsafe required source directory: " + directory)
        def walk_error(_error):
            fail("Unable to inspect an allowlisted source directory.")
        for current, directories, names in os.walk(source, followlinks=False, onerror=walk_error):
            for name in directories[:] + names:
                path = Path(current) / name
                relative = path.relative_to(ROOT).as_posix()
                safe_path(relative)
                if path.is_symlink():
                    fail("Refusing a symbolic link in a source directory.")
                if excluded(relative):
                    if name in directories:
                        directories.remove(name)
                    continue
                if name not in directories:
                    files.add(relative)
    for relative in files:
        if excluded(relative):
            fail("A required file matches the release exclusion policy.")
        if not (ROOT / relative).is_file():
            fail("Missing required distribution file: " + relative)
    return sorted(files)


def build_archive(destination, project, files):
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for relative in files:
            content, mode = file_bytes(relative)
            info = zipfile.ZipInfo(project + "/" + relative, (2026, 11, 16, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | (0o755 if mode & 0o111 else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    # Independently audit ZIP metadata and content after writing.
    expected = {project + "/" + relative for relative in files}
    with zipfile.ZipFile(destination) as archive:
        entries = archive.infolist()
        if len(entries) != len(expected) or {entry.filename for entry in entries} != expected:
            fail("Refusing missing, unexpected or duplicate archive entries.")
        for entry in entries:
            safe_path(entry.filename)
            relative = entry.filename[len(project) + 1:]
            if (not entry.filename.startswith(project + "/") or excluded(relative)
                    or not stat.S_ISREG(entry.external_attr >> 16)
                    or entry.file_size > MAX_BYTES or entry.flag_bits & 1):
                fail("Refusing unsafe ZIP metadata.")
            if SECRET_PATTERN.search(archive.read(entry)):
                fail("Refusing credential-like archive content; contents withheld.")
        if archive.testzip() is not None:
            fail("ZIP integrity check failed.")


def main():
    version = file_bytes("VERSION")[0].decode("ascii").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+", version):
        fail("VERSION must name a release candidate, for example 0.1.0-rc.1.")
    project = "northstar-procurement-" + version
    files = collect_files()
    if CHECK_ONLY:
        with tempfile.TemporaryDirectory(prefix="northstar-release-check-") as temporary:
            build_archive(Path(temporary) / "preview.zip", project, files)
        print("Release source and ZIP audit passed (" + str(len(files)) + " files); no deliverable written.")
        return
    output_parent = ROOT / "dist"
    if output_parent.is_symlink():
        fail("Refusing a symbolic-link distribution directory.")
    output_parent.mkdir(mode=0o700, exist_ok=True)
    output = output_parent / project
    if output.exists() or output.is_symlink():
        fail("Release destination already exists; preserve it and use a new candidate version.")
    # ZIP and digest move into place together. Existing dist artifacts are untouched.
    with tempfile.TemporaryDirectory(prefix=".northstar-release-", dir=output_parent) as temporary:
        staging = Path(temporary)
        archive = staging / (project + ".zip")
        build_archive(archive, project, files)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (staging / (archive.name + ".sha256")).write_text(digest + "  " + archive.name + "\n", encoding="ascii")
        if output.exists() or output.is_symlink():
            fail("Release destination appeared during packaging; refusing replacement.")
        staging.rename(output)
    print("Created " + str(output / archive.name))
    print("SHA-256 " + digest)
    print("Audited " + str(len(files)) + " files. Docker-only review candidate; no deployment or publication performed.")


try:
    main()
except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as error:
    # OS exceptions can contain unsafe/sensitive filenames. Never echo them.
    message = str(error) if isinstance(error, ValueError) else "Unable to read or create release files; no contents printed."
    sys.exit("Packaging failed: " + message)
PY
