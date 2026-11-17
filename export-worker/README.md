# Isolated order-export exercise (CMD-01)

This is **real OS command injection inside a deliberately restricted lab container**, not a simulated success message. It must not run in the Spring/identity container, on the host, or with network access. The fixed implementation does not start a shell.

The lab's intended default is **Vulnerable**; **Fixed** applies the exercise's correction. Neither mode makes Northstar production-ready, and changing modes never weakens or disables the worker containment requirements below.

## API and switching

- `POST /api/orders/{id}/export` with JSON `{"format":"csv"}` selects the vulnerable or fixed implementation using the owner-controlled `CMD-01` feature flag.
- `POST /api/secure/orders/{id}/export` always uses the fixed implementation.
- Both routes require a valid app access token **and** real tenant/owner access to the order, regardless of the `API-01` switch.
- The result is `{"output":"...","exitCode":0,"timedOut":false}`. It is untrusted text: render with Angular interpolation, never `innerHTML` or a sanitizer bypass.
- A missing, stalled or malformed worker response returns HTTP 503. Spring has no shell fallback and contains no command execution code.

For the harmless proof, use `{"format":"csv; printf CMD01_PROOF"}` against an order the test persona can read. In vulnerable mode, the marker appears in output. In fixed mode it returns HTTP 400. Do not probe outside this disposable worker.

The exported document is a fixed synthetic fixture (`SYNTHETIC-001`, demo stationery). Only the order ID is passed as contextual JSON; it is not interpolated or exported. Tokens, item/notes text, tenant data, prices, database paths and identity material are never sent to the worker.

## Mandatory deployment boundary

The Dockerfile intentionally does not grant any containment by itself. Deployment must enforce **all** of these settings:

| Setting | Required value |
|---|---|
| User | `10001:10001`, non-root |
| Networking | `network_mode: none`; no published ports or shared host networking |
| Root filesystem | Read-only |
| Linux capabilities | Drop `ALL`; `no-new-privileges:true`; retain Docker's default seccomp profile |
| Resources | PID limit 32; memory 64 MiB with no extra swap; CPU limit 0.25 |
| Scratch | `/tmp` tmpfs, 16 MiB, `noexec,nosuid,nodev` |
| Socket | Dedicated **1 MiB tmpfs-backed** volume at `/run/northstar-export`; worker RW, Spring **RO**; `noexec,nosuid,nodev` |
| All other mounts | None: especially no app DB, identity DB/keys, credentials, host paths, or Docker socket |
| Environment | No cloud credentials, tokens, application secrets or inherited host environment |

The image initializes the socket directory owned by UID 10001. Its socket is mode 0666 so Spring's different non-root UID can connect; the dedicated volume must never be mounted into other containers. Use Docker's local volume driver with `type=tmpfs`, `device=tmpfs`, and `o=size=1m,uid=10001,gid=10001,mode=0755,nosuid,nodev,noexec`. A normal disk-backed named volume is **not acceptable**: an injected command could fill host storage or persist files there. The worker has no HTTP server. Its only IPC surface is the Unix socket, configured in Spring as `lab.export-socket` (default `/run/northstar-export/export.sock`).

The network namespace has no network interface other than loopback, so neither the internet, application services nor EC2 metadata is reachable. IMDSv2 alone is **not** this boundary. Containers share the host kernel; this design limits an intentionally exploitable process but is not equivalent to a separate VM. Keep the entire lab IP-restricted and do not introduce real data or privileged workloads on its host.

Each request runs at most one command, with a two-second wall deadline, 8 KiB aggregate stdout/stderr limit, an empty/allowlisted subprocess environment and additional CPU/file/descriptor limits. Linux subreaping and process-group cleanup terminate background and detached descendants after every command. A malicious command can still disrupt its own worker; restarting/recreating that worker is the recovery path. Docker limits are the outer resource boundary, not the Python timeout alone.

## Unix-socket contract

One UTF-8 JSON object plus LF per connection, maximum 64 KiB. No HTTP and no persistent session.

```json
{"version":1,"action":"export","format":"csv","vulnerable":true,"order":{"id":"ORD-A-100"}}
```

`format` is 1–128 printable characters. The fixed path accepts exactly `csv` and `json`. Only the deliberately vulnerable path passes `format` to `/bin/sh -c`; executable, fixture, working directory and all other fields are fixed by the worker. The worker does not read the global policy itself: the authenticated Spring bridge chooses `vulnerable` after checking ownership. The transport deadline in Spring is four seconds across connect, write and read, using nonblocking Unix sockets without background executor threads.

Trusted management code can call `ExportWorkerService.reset()`, which sends `{"version":1,"action":"reset"}`. This unlinks only `export.csv`, `export.json` and `proof.txt` inside the fixed scratch directory; it accepts no paths and does not traverse symlinks. It does not claim to undo arbitrary command execution. **Recreate the worker and its socket volume** for a complete clean filesystem/process state: stop/recreate the backend as well to release its read-only socket mount, discard only the export socket volume, then start the two services with a fresh bounded volume. Do not delete the app, identity, signing-key or policy volumes. The worker's `/tmp` is also disposable. A worker restart alone does not clear files in a still-mounted shared socket volume. Ordinary app users receive no reset endpoint through this controller.

## Tests

No Python packages are needed. Local portable tests:

```bash
cd export-worker
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_worker.py
```

Run the suite inside Linux as well to exercise subreaper/background-process cleanup. Use a disposable container with the deployment restrictions above and a read-only test-source mount. Test-only source mounts must not be present in the deployed worker.

The reproducible deployment-boundary smoke test builds the actual worker image, starts isolated disposable containers, verifies Docker policy and effective Linux restrictions, checks outbound/metadata denial and the 1 MiB socket-file budget, and exercises the Unix-socket contract in both modes. A different-UID client proves the read-only socket mount still supports IPC. The test also verifies that worker recreation alone leaves shared files while another consumer holds the volume, then confirms the full two-consumer/socket-volume reset clears them:

```bash
docker build -t northstar-export-worker:containment export-worker
python3 export-worker/test_container.py
```

Run these two commands from the repository root. The test removes only its own uniquely named container and socket volume. It never mounts application data or secrets. The image is retained for inspection.

The Java tests exercise socket framing, response bounds, overall deadlines, missing-worker failure, fixed-format validation, server-selected flags, authentication, and cross-tenant denial. Python tests cover harmless marker execution, no subprocess in fixed mode, ignored order data, output limits, timeout, child cleanup, protocol validation and restricted reset behavior.
