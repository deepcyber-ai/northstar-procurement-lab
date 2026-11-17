"""Owner-only lab configuration. No dependency on, or credentials for, the target app.

The same controller runs behind a loopback-only Basic-auth server locally and
behind the authenticated, isolated CloudFront owner distribution on AWS.
"""
import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import parse_qs

EXERCISES = {
    "API-01": "Order object-level authorization",
    "API-02": "Order mass assignment",
    "GW-01": "Trust in client-supplied administrator role",
    "GW-02": "Exact-path gateway policy (local Nginx)",
    "GW-03": "Reflected credentialed API CORS",
    "API-03": "SSRF simulation (never performs network access)",
    "WF-01": "Workflow start authorization / action validation",
    "WF-02": "Missing workflow idempotency",
    "WF-03": "Workflow object-level authorization",
    "WF-04": "Callback authentication / validation / replay",
    "DB-01": "Exposed synthetic database configuration",
    "SQL-01": "Read-query SQL injection",
    "SQL-02": "Data-modifying SQL injection",
    "AUTH-01": "Missing PKCE verifier bypass",
    "XSS-01": "Stored notes: Angular sanitizer bypass",
    "SC-01": "Lab-owned supplier widget publishing / missing integrity",
    "CMD-01": "Isolated export-worker shell injection",
}
MAX_BODY = 8192


def profile(enabled=False):
    return {"version": 1, "revision": secrets.token_hex(16),
            "enabled": {code: enabled for code in EXERCISES}}


def validate(value):
    if not isinstance(value, dict) or set(value) != {"version", "revision", "enabled"}:
        raise ValueError("Invalid configuration")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Invalid version")
    if not isinstance(value["revision"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value["revision"]):
        raise ValueError("Invalid revision")
    flags = value["enabled"]
    if not isinstance(flags, dict) or set(flags) != set(EXERCISES) or any(type(v) is not bool for v in flags.values()):
        raise ValueError("All 17 boolean switches are required")
    return value


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration key")
            result[key] = value
        return result
    if len(raw) > MAX_BODY:
        raise ValueError("Oversized configuration")
    return validate(json.loads(raw, object_pairs_hook=unique))


class Conflict(Exception):
    pass


class FileStore:
    def __init__(self, path):
        self.path = Path(path)

    def initialize(self):
        """Explicit first installation only; restart never resets an existing profile."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        marker = self.path.with_name("." + self.path.name + ".initialized")
        if marker.exists() or marker.is_symlink():
            return
        # Record initialization BEFORE writing the default. A crash or a deleted
        # config must fail fixed on restart, not silently re-enable every flaw.
        # Recreating the entire lab-config volume is an explicit fresh installation.
        with marker.open("x") as stream:
            stream.write("Northstar configuration initialized; missing configuration requires operator recovery.\n")
            stream.flush()
            os.fsync(stream.fileno())
        if self.path.exists() or self.path.is_symlink():
            return
        value = profile(True)  # User-selected default: deliberately vulnerable lab.
        with self.path.open("x") as stream:
            json.dump(value, stream)
        self.path.chmod(0o644)  # Flags contain no secrets; target receives read-only mount.

    def read(self):
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("Configuration must be a regular non-symlink file")
        with self.path.open("rb") as stream:
            raw = stream.read(MAX_BODY + 1)
        return decode(raw), hashlib.sha256(raw).hexdigest()

    def write(self, value, expected):
        _, current = self.read()
        if current != expected:
            raise Conflict()
        # Local server is deliberately single-threaded; all writes are serialized.
        temporary = self.path.with_name(".vulnerabilities-" + secrets.token_hex(8))
        try:
            with temporary.open("x") as stream:
                json.dump(validate(value), stream)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o644)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)


class S3Store:
    def __init__(self, client, bucket, key):
        self.client, self.bucket, self.key = client, bucket, key

    def read(self):
        obj = self.client.get_object(Bucket=self.bucket, Key=self.key)
        return decode(obj["Body"].read(MAX_BODY + 1)), obj["ETag"]

    def write(self, value, expected):
        try:
            self.client.put_object(Bucket=self.bucket, Key=self.key,
                                   Body=json.dumps(validate(value)).encode(), ContentType="application/json",
                                   IfMatch=expected, ServerSideEncryption="AES256")
        except Exception as error:
            if getattr(error, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode") in (409, 412):
                raise Conflict() from error
            raise


def csrf(key, origin, revision, expiry):
    message = f"{origin}|{revision}|{expiry}".encode()
    return str(expiry) + "." + hmac.new(key.encode(), message, hashlib.sha256).hexdigest()


def valid_csrf(token, key, origin, revision):
    try:
        expiry = int(token.split(".", 1)[0])
        return time.time() <= expiry <= time.time() + 1800 and hmac.compare_digest(token, csrf(key, origin, revision, expiry))
    except (ValueError, IndexError):
        return False


def response(status, body, **extra):
    headers = {
        "content-type": "text/html; charset=utf-8", "cache-control": "no-store, private, max-age=0",
        "pragma": "no-cache", "x-content-type-options": "nosniff", "x-frame-options": "DENY",
        "referrer-policy": "no-referrer", "cross-origin-resource-policy": "same-origin",
        "cross-origin-opener-policy": "same-origin", "x-robots-tag": "noindex, nofollow, noarchive",
        "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    }
    headers.update(extra)
    return {"statusCode": status, "headers": headers, "body": body}


def page(state, token):
    count = sum(state["enabled"].values())
    mode = "Vulnerable" if count == len(EXERCISES) else "Fixed" if count == 0 else "Custom"
    rows = "".join(f'<label><input type="checkbox" name="enabled" value="{code}" '
                   f'{"checked" if state["enabled"][code] else ""}> <strong>{code}</strong> {html.escape(label)}</label>'
                   for code, label in EXERCISES.items())
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar | Owner controls</title><style>
body{{background:#091426;color:#edf5ff;font:17px/1.6 system-ui;margin:0}}main{{max-width:920px;margin:4vh auto;padding:28px}}
a{{color:#64ded1}}label{{display:block;padding:12px;border-bottom:1px solid #33435a}}input{{margin-right:10px}}
button{{padding:12px 18px;margin:8px 8px 8px 0;border-radius:6px;border:1px solid #64ded1;background:#123648;color:white;font:inherit}}
.notice{{padding:18px;background:#10263a;border-left:3px solid #64ded1}}code{{overflow-wrap:anywhere}}</style></head><body><main>
<p><a href="/demo">Owner demo guide</a></p><h1>Vulnerability controls</h1>
<p>Desired profile: <strong>{mode}</strong> · {count} / {len(EXERCISES)} exercises enabled</p>
<p class="notice">These switches affect every tester. Coordinate before changing an active assessment.
Fixed disables the seeded flaws; it is not a production-security certification. Network restrictions and worker containment cannot be switched off.</p>
<form method="post" action="/controls/save">
<input type="hidden" name="revision" value="{html.escape(state["revision"], quote=True)}">
<input type="hidden" name="csrf" value="{token}">
<p><button name="action" value="all">Enable all — Vulnerable</button>
<button name="action" value="fixed">Disable all — Fixed</button></p>
{rows}<p><button name="action" value="save">Save individual switches</button></p></form>
<p>Changes apply on the next request locally, or after the AWS host's next configuration sync (normally within 30 seconds).
This page shows desired configuration, not proof that every running component has applied it.</p>
<p>Switching modes does not reset orders, notes, the vendor widget, or existing tokens.
Close and reopen test browser contexts after unsafe script execution; switching off a flaw cannot undo code already run.</p>
<p>GW-02 reproduces the local Nginx exact-path policy. It does not create an API Gateway defect on AWS.</p>
<p>Revision: <code>{html.escape(state["revision"])}</code></p></main></body></html>'''


def handle(method, path, headers, body, store, key, origin):
    if path not in ("/controls", "/controls/save"):
        return response(404, "Not found.")
    if method == "GET" and path == "/controls":
        try:
            state, _ = store.read()
        except Exception:
            return response(503, "Configuration unavailable. The target fails closed to Fixed; repair the configuration before changing it.")
        return response(200, page(state, csrf(key, origin, state["revision"], int(time.time()) + 900)))
    if method != "POST" or path != "/controls/save":
        return response(405, "Method not allowed.", allow="GET, POST")
    # Basic credentials can be ambient. Both a same-origin POST and an unguessable
    # revision-bound token are required; cross-origin app XSS cannot read this page.
    if headers.get("origin") != origin or headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
        return response(403, "Same-origin owner action required.")
    if len(body) > MAX_BODY or headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
        return response(400, "Invalid form.")
    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=25)
        if set(form) - {"action", "revision", "csrf", "enabled"}:
            raise ValueError()
        if any(len(form.get(field, [])) != 1 for field in ("action", "revision", "csrf")):
            raise ValueError()
        state, etag = store.read()
        revision = form["revision"][0]
        if revision != state["revision"]:
            return response(409, 'Another owner action changed the profile. <a href="/controls">Reload controls</a>.')
        if not valid_csrf(form["csrf"][0], key, origin, revision):
            return response(403, "Invalid or expired owner form. Reload controls.")
        action, selected = form["action"][0], form.get("enabled", [])
        if action not in ("save", "all", "fixed") or len(selected) != len(set(selected)) or set(selected) - set(EXERCISES):
            raise ValueError()
        updated = profile(action == "all")
        if action == "save":
            updated["enabled"] = {code: code in selected for code in EXERCISES}
        store.write(updated, etag)
        # Log codes and revision only: never Basic credentials, CSRF tokens or forms.
        print(json.dumps({"event": "owner_profile_changed", "revision": updated["revision"],
                          "enabled": [code for code, on in updated["enabled"].items() if on]}))
        return response(303, "", location="/controls")
    except Conflict:
        return response(409, "Concurrent update. Reload controls.")
    except (ValueError, UnicodeError):
        return response(400, "Invalid form or configuration.")
    except Exception:
        return response(503, "Configuration update failed. Reload controls before retrying.")


def handler(event, context):
    """Lambda entry: custom origin secret is known only to the OWNER distribution."""
    headers = {k.lower(): v for k, v in event.get("headers", {}).items()}
    expected = os.environ.get("CONTROL_ORIGIN_SECRET", "")
    if len(expected) < 32 or not hmac.compare_digest(headers.get("x-northstar-control-origin", ""), expected):
        return response(403, "Forbidden.")
    host = headers.get("x-northstar-owner-host", "")
    if headers.get("x-northstar-owner-authenticated") != "true" or not re.fullmatch(r"[a-z0-9.-]+\.cloudfront\.net", host):
        return response(403, "Forbidden.")
    import boto3  # Provided by Lambda, not a local dependency.
    store = S3Store(boto3.client("s3"), os.environ["CONFIG_BUCKET"], os.environ["CONFIG_KEY"])
    try:
        body = event.get("body", "") or ""
        if len(body) > MAX_BODY * 2:
            return response(413, "Body too large.")
        raw = base64.b64decode(body, validate=True) if event.get("isBase64Encoded") else body.encode()
    except (ValueError, UnicodeError):
        return response(400, "Invalid request.")
    http = event.get("requestContext", {}).get("http", {})
    return handle(http.get("method", ""), event.get("rawPath", ""), headers, raw,
                  store, expected, "https://" + host)
