"""Deliberately vulnerable export exercise. Run ONLY in the documented isolated container.

The fixed path never launches a subprocess. CMD-01 affects only the `format` field;
order data, paths and executable names are never accepted as shell input.
"""
import ctypes
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import stat
import subprocess
import time

SOCKET_PATH = "/run/northstar-export/export.sock"
SCRATCH = Path("/tmp/northstar-export")
KNOWN_SCRATCH = ("export.csv", "export.json", "proof.txt")
MAX_FRAME = 65536
MAX_OUTPUT = 8192
COMMAND_SECONDS = 2.0
FIXTURE = {"id": "SYNTHETIC-001", "item": "Demo stationery", "quantity": 2}
CSV = "id,item,quantity\nSYNTHETIC-001,Demo stationery,2\n"


def result(output="", exit_code=0, timed_out=False, error=None):
    response = {"output": output, "exitCode": exit_code, "timedOut": timed_out}
    if error:
        response["error"] = error
    return response


def enable_subreaper():
    """Adopt daemonised descendants so cleanup also catches setsid/double forks on Linux."""
    if os.path.isdir("/proc/self"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError(ctypes.get_errno(), "Cannot establish export subprocess cleanup")


def child_limits():
    # Defense in depth; Docker's memory/PID/CPU limits are the outer resource boundary.
    for key, limit in ((resource.RLIMIT_CPU, 2), (resource.RLIMIT_FSIZE, 1048576),
                       (resource.RLIMIT_NOFILE, 32), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(key, (limit, limit))
    if hasattr(resource, "RLIMIT_AS") and os.path.isdir("/proc/self"):
        resource.setrlimit(resource.RLIMIT_AS, (48 * 1024 * 1024, 48 * 1024 * 1024))


def descendant_pids():
    """Only this worker's descendants; never kill unrelated host processes in unit tests."""
    parents = {}
    for entry in Path("/proc").glob("[0-9]*/stat"):
        try:
            # comm may contain spaces or ')'; PPID is the second field after the final ')'.
            tail = entry.read_text().rsplit(")", 1)[1].split()
            parents[int(entry.parent.name)] = int(tail[1])
        except (OSError, ValueError, IndexError):
            continue
    descendants = {os.getpid()}
    changed = True
    while changed:
        added = {pid for pid, ppid in parents.items() if ppid in descendants} - descendants
        changed = bool(added)
        descendants.update(added)
    descendants.discard(os.getpid())
    return descendants


def cleanup(process):
    # Run on success too: `printf marker &` must not leave background children behind.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.1)
    except subprocess.TimeoutExpired:
        pass
    end = time.monotonic() + 0.25
    while True:
        descendants = descendant_pids() if os.path.isdir("/proc/self") else set()
        for pid in descendants:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            while os.waitpid(-1, os.WNOHANG)[0] != 0:
                pass
        except ChildProcessError:
            pass
        if not descendants or time.monotonic() >= end:
            break
        time.sleep(0.005)


def vulnerable_export(export_format, timeout=COMMAND_SECONDS):
    SCRATCH.mkdir(mode=0o700, exist_ok=True)
    if not stat.S_ISDIR(SCRATCH.lstat().st_mode):
        return result(exit_code=2, error="INVALID_SCRATCH_DIRECTORY")
    # INTENTIONAL CMD-01: this is the one shell-interpreted, user-controlled value.
    # Neither the order ID nor item/notes/other business fields appear in this command.
    command = "printf '%s\\n' 'id,item,quantity' 'SYNTHETIC-001,Demo stationery,2'; printf 'format=%s\\n' " + export_format
    process = subprocess.Popen(["/bin/sh", "-c", command], cwd=SCRATCH,
                               env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C"},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True,
                               close_fds=True, preexec_fn=child_limits)
    output = bytearray()
    timed_out = False
    too_large = False
    selector = selectors.DefaultSelector()
    os.set_blocking(process.stdout.fileno(), False)
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    exit_code = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(remaining, 0.05))
            if events:
                chunk = os.read(process.stdout.fileno(), min(4096, MAX_OUTPUT + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    too_large = True
                    break
            elif process.poll() is not None:
                # A background child may still own stdout. Cleanup must not wait for it.
                break
        exit_code = process.poll()
        if exit_code is None and not timed_out and not too_large:
            try:
                exit_code = process.wait(timeout=0.025)
            except subprocess.TimeoutExpired:
                pass
    finally:
        selector.close()
        cleanup(process)
        process.stdout.close()
    if timed_out:
        return result(bytes(output[:MAX_OUTPUT]).decode("utf-8", "replace"), 124, True)
    if too_large:
        return result(bytes(output[:MAX_OUTPUT]).decode("utf-8", "replace"), 125, False, "OUTPUT_LIMIT")
    return result(bytes(output).decode("utf-8", "replace"), exit_code if exit_code is not None else process.returncode or 0)


def handle(payload):
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != 1:
        return result(exit_code=2, error="INVALID_REQUEST")
    if payload.get("action") == "reset":
        if set(payload) != {"version", "action"}:
            return result(exit_code=2, error="INVALID_REQUEST")
        # Never accept a path, recurse, follow symlinks, or remove arbitrary shell-created files.
        try:
            directory = os.open(SCRATCH, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            directory = None
        except OSError:
            return result(exit_code=2, error="RESET_FAILED")
        if directory is not None:
            try:
                for name in KNOWN_SCRATCH:
                    try:
                        os.unlink(name, dir_fd=directory)
                    except FileNotFoundError:
                        pass
            except OSError:
                return result(exit_code=2, error="RESET_FAILED")
            finally:
                os.close(directory)
        return result("Known export scratch files reset. Restart the worker for a complete lab reset.\n")
    if payload.get("action") != "export" or set(payload) != {"version", "action", "format", "vulnerable", "order"}:
        return result(exit_code=2, error="INVALID_REQUEST")
    export_format = payload["format"]
    order = payload["order"]
    if (not isinstance(export_format, str) or not 1 <= len(export_format) <= 128
            or any(ord(char) < 32 or ord(char) == 127 for char in export_format)
            or type(payload["vulnerable"]) is not bool or not isinstance(order, dict)
            or set(order) != {"id"} or not isinstance(order["id"], str) or len(order["id"]) > 128):
        return result(exit_code=2, error="INVALID_REQUEST")
    if not payload["vulnerable"]:
        if export_format == "csv":
            return result(CSV)
        if export_format == "json":
            return result(json.dumps(FIXTURE, separators=(",", ":")) + "\n")
        return result(exit_code=2, error="INVALID_EXPORT_FORMAT")
    return vulnerable_export(export_format)


def read_frame(connection):
    data = bytearray()
    deadline = time.monotonic() + 0.5
    while True:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        chunk = connection.recv(min(4096, MAX_FRAME + 1 - len(data)))
        if not chunk:
            raise ValueError("Truncated frame")
        data.extend(chunk)
        if len(data) > MAX_FRAME:
            raise ValueError("Frame too large")
        if b"\n" in data:
            frame, trailing = bytes(data).split(b"\n", 1)
            if trailing:
                raise ValueError("One request per connection")
            return json.loads(frame, object_pairs_hook=unique_object)
        if time.monotonic() >= deadline:
            raise TimeoutError("Read deadline exceeded")


def unique_object(pairs):
    value = {}
    for key, entry in pairs:
        if key in value:
            raise ValueError("Duplicate field")
        value[key] = entry
    return value


def serve(path=SOCKET_PATH):
    if os.geteuid() == 0:
        raise RuntimeError("The export worker must not run as root")
    enable_subreaper()
    # Runtime path is fixed; mounts are configured by the trusted deployer, not API callers.
    socket_path = Path(path)
    if socket_path.exists():
        if not stat.S_ISSOCK(socket_path.lstat().st_mode):
            raise RuntimeError("Refusing to replace a non-socket")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        # The dedicated volume is mounted ONLY in Spring and this worker. The Spring UID
        # need not match; it receives a read-only mount, never the worker's /tmp.
        socket_path.chmod(0o666)
        server.listen(1)
        while True:  # Exactly one request/command at a time; no thread or subprocess pool.
            connection, _ = server.accept()
            with connection:
                try:
                    reply = handle(read_frame(connection))
                except (ValueError, UnicodeError, OSError, TimeoutError, subprocess.SubprocessError):
                    reply = result(exit_code=2, error="INVALID_REQUEST")
                try:
                    connection.settimeout(0.5)
                    connection.sendall(json.dumps(reply, ensure_ascii=True, separators=(",", ":")).encode() + b"\n")
                except OSError:
                    pass


if __name__ == "__main__":
    serve()
