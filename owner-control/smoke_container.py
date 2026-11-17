"""Actual loopback HTTP smoke test with disposable credentials/network/volume.

Build first: docker build -f owner-control/Dockerfile -t northstar-owner-control:check .
Then: python3 -B owner-control/smoke_container.py
"""
import base64
import hashlib
import json
import re
import secrets
import socket
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


suffix = secrets.token_hex(6)
name, volume, network = ("northstar-owner-check-" + suffix + tail for tail in ("", "-config", "-net"))
with socket.socket() as reserved:
    reserved.bind(("127.0.0.1", 0))
    port = reserved.getsockname()[1]
origin = f"http://localhost:{port}"
password = secrets.token_urlsafe(32)
authorization = "Basic " + base64.b64encode(("owner:" + password).encode()).decode()
salt = secrets.token_hex(32)
digest = hashlib.sha256((salt + ":" + authorization).encode()).hexdigest()
opener = build_opener(NoRedirect())


def request(path, form=None, authenticated=True, request_origin=origin):
    headers = {"Authorization": authorization} if authenticated else {}
    data = None
    if form is not None:
        data = urlencode(form, doseq=True).encode()
        headers.update({"Content-Type": "application/x-www-form-urlencoded", "Origin": request_origin})
    try:
        result = opener.open(Request(origin + path, data=data, headers=headers), timeout=2)
    except HTTPError as error:
        result = error
    return result.status, result.headers, result.read().decode()


try:
    docker("network", "create", network)
    docker("run", "-d", "--name", name, "--network", network, "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--pids-limit", "16", "--memory", "64m",
           "--stop-timeout", "1", "-p", f"127.0.0.1:{port}:8081", "-v", volume + ":/config",
           "-e", "NORTHSTAR_OWNER_ORIGIN=" + origin, "-e", "NORTHSTAR_OWNER_SALT=" + salt,
           "-e", "NORTHSTAR_OWNER_DIGEST=" + digest, "northstar-owner-control:check")
    for _ in range(100):
        try:
            if request("/demo", authenticated=False)[0] == 401:
                break
        except (URLError, ConnectionError):
            time.sleep(0.2)
    assert request("/controls", authenticated=False)[0] == 401
    assert request("/demo")[0] == 200
    status, headers, page = request("/controls")
    assert status == 200 and page.count('type="checkbox"') == 17
    assert "no-store" in headers["Cache-Control"] and not headers.get("Access-Control-Allow-Origin")
    form = {key: re.search(f'name="{key}" value="([^"]+)"', page)[1] for key in ("csrf", "revision")}
    form["action"] = "fixed"
    assert request("/controls/save", form, request_origin="http://localhost:8080")[0] == 403
    assert request("/controls/save", form)[0] == 303
    assert request("/controls/save", form)[0] == 409
    state = json.loads(docker("exec", name, "python", "-c",
                             "from pathlib import Path; print(Path('/config/vulnerabilities.json').read_text())"))
    assert not any(state["enabled"].values())
    assert request("/api/orders")[0] == 404
    print("PASS: owner-only loopback HTTP, all 17 controls, cross-origin denial, Fixed save, stale-form rejection, no app proxy")
except Exception:
    print("Owner container state:", docker("inspect", "--format", "{{.State.Status}} exit={{.State.ExitCode}}", name))
    print(docker("logs", "--tail", "20", name))
    raise
finally:
    for command in (("rm", "-f", name), ("volume", "rm", volume), ("network", "rm", network)):
        subprocess.run(["docker", *command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Removed only this test's disposable owner container, profile volume and network.")
