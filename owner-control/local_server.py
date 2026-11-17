"""Loopback-published owner control plane. Never proxy Basic credentials to Spring."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
from control import FileStore, MAX_BODY, handle, response


def main():
    salt = os.environ.get("NORTHSTAR_OWNER_SALT", "")
    digest = os.environ.get("NORTHSTAR_OWNER_DIGEST", "")
    if not all(re.fullmatch(r"[a-f0-9]{64}", value) for value in (salt, digest)):
        raise SystemExit("Configure owner credentials first: python3 owner-control/configure_owner.py")
    origin = os.environ.get("NORTHSTAR_OWNER_ORIGIN", "http://localhost:8081")
    parsed = urlsplit(origin)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1") or parsed.path or parsed.query or parsed.fragment:
        raise SystemExit("Local owner origin must be loopback HTTP; use the isolated HTTPS owner deployment for AWS")
    store = FileStore(os.environ.get("NORTHSTAR_CONFIG_PATH", "/config/vulnerabilities.json"))
    store.initialize()
    csrf_key = hmac.new(digest.encode(), (salt + ":owner-csrf").encode(), hashlib.sha256).hexdigest()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not record URLs/credentials/forms. State changes have their own minimal audit.

        def do_GET(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

        def dispatch(self):
            self.connection.settimeout(5)
            if self.headers.get("Host") != parsed.netloc:
                self.send_result(response(403, "Invalid owner host.")); return
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or len(auth[0]) > 1024 or not hmac.compare_digest(
                    hashlib.sha256((salt + ":" + auth[0]).encode()).hexdigest(), digest):
                self.send_result(response(401, "Owner authentication required.",
                                          **{"www-authenticate": 'Basic realm="Northstar Owner Demo", charset="UTF-8"'})); return
            if len(self.headers.get_all("Content-Length", [])) > 1 or self.headers.get("Transfer-Encoding"):
                self.send_result(response(400, "Invalid framing.")); return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= MAX_BODY:
                    raise ValueError()
            except ValueError:
                self.send_result(response(413, "Invalid body size.")); return
            path = urlsplit(self.path).path
            if self.command == "GET" and path in ("/", "/demo"):
                if path == "/":
                    self.send_result(response(302, "", location="/demo")); return
                self.send_result(response(200, Path("/app/owner-demo.html").read_text())); return
            body = self.rfile.read(length)
            self.send_result(handle(self.command, path, {k.lower(): v for k, v in self.headers.items()},
                                    body, store, csrf_key, origin))

        def send_result(self, result):
            raw = result["body"].encode()
            self.send_response(result["statusCode"])
            for name, value in result["headers"].items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    HTTPServer(("0.0.0.0", 8081), Handler).serve_forever()


if __name__ == "__main__":
    main()
