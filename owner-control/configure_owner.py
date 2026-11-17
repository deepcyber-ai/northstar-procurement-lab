"""Interactive local setup; plaintext passwords are neither printed nor stored."""
import base64
from getpass import getpass
import hashlib
import os
from pathlib import Path
import secrets

password = getpass("Owner password (at least 16 characters): ")
if len(password) < 16 or password != getpass("Confirm owner password: "):
    raise SystemExit("Passwords must match and contain at least 16 characters.")
salt = secrets.token_hex(32)
authorization = "Basic " + base64.b64encode(("owner:" + password).encode()).decode()
digest = hashlib.sha256((salt + ":" + authorization).encode()).hexdigest()
path = Path(__file__).resolve().parent / ".env"
if path.exists():
    raise SystemExit("owner-control/.env already exists; preserve or move it before rotating credentials.")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(f"NORTHSTAR_OWNER_SALT={salt}\nNORTHSTAR_OWNER_DIGEST={digest}\n")
print("Created owner-control/.env (private digest only). Use username owner at http://localhost:8081/demo.")
