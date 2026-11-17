#!/usr/bin/env python3
"""Connect one explicitly selected local scanner to Northstar's public gateway.

Standard library only. Never reads container environments or stops scanner/lab
containers. Docker labels are the recovery record; keep the printed IDs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


PREFIX = "io.northstar.local-relay."
ID = re.compile(r"[0-9a-f]{64}")
CONF = Path(__file__).resolve().parents[1] / "docs/artex-local/localhost-proxy.conf"
PORT_CHECK = """from pathlib import Path
for name in ('tcp', 'tcp6'):
    for row in Path('/proc/net/' + name).read_text().splitlines()[1:]:
        fields = row.split()
        if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == 8080:
            raise SystemExit('Port 8080 already has a listener; nothing changed.')
"""
LABELS = ("version", "gateway", "tool", "kind", "run-id")


def docker(*args):
    result = subprocess.run(["docker", *args], text=True, capture_output=True,
                            timeout=30, check=False)
    if result.returncode:
        # Never reproduce arbitrary Docker diagnostics in a shareable transcript.
        raise RuntimeError("Docker command failed: " + " ".join(args[:2]))
    return result.stdout.strip()


def selected(kind, name, fields):
    template = "[" + ",".join("{{json (" + f + ")}}" for f in fields) + "]"
    return json.loads(docker(kind, "inspect", "--format", template, name))


def container(name):
    keys = ("id", "name", "running", "image", "service", "project", "run",
            "mode", "ports", "labels")
    fields = (".Id", ".Name", ".State.Running", ".Image",
              'index .Config.Labels "com.docker.compose.service"',
              'index .Config.Labels "com.docker.compose.project"',
              'index .Config.Labels "strix-run-id"',
              ".HostConfig.NetworkMode", ".HostConfig.PortBindings")
    values = selected("container", name, fields)
    # Read only known metadata labels, never all labels or Config.Env.
    values.append(dict(zip(LABELS, selected("container", name, tuple(
        f'index .Config.Labels "{PREFIX}{key}"' for key in LABELS)))))
    return dict(zip(keys, values))


class Relay:
    def __init__(self, gateway, tool, kind, run_id=""):
        if not ID.fullmatch(gateway) or not ID.fullmatch(tool) or gateway == tool:
            raise RuntimeError("Supply two different full 64-character container IDs.")
        if kind == "strix" and not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
            raise RuntimeError("Strix requires --run-id from this new session.")
        if kind == "artex" and run_id:
            raise RuntimeError("--run-id is only for Strix.")
        self.gateway, self.tool, self.kind = gateway, tool, kind
        self.network = "northstar-local-" + tool[:16]
        self.relay = "northstar-relay-" + tool[:16]
        self.labels = dict(zip(LABELS, ("1", gateway, tool, kind, run_id)))

    def label_args(self):
        return [item for k, v in self.labels.items()
                for item in ("--label", PREFIX + k + "=" + v)]

    def existing(self):
        networks = docker("network", "ls", "--format", "{{.Name}}").splitlines()
        containers = docker("container", "ls", "--all", "--format", "{{.Names}}").splitlines()
        return self.network in networks, self.relay in containers

    def verify_owned(self, network, relay):
        members = {}
        if network:
            fields = (".Internal", ".Driver", ".Containers") + tuple(
                f'index .Labels "{PREFIX}{key}"' for key in LABELS)
            internal, driver, members, *labels = selected("network", self.network, fields)
            members = members or {}
            if (not internal or driver != "bridge" or
                    dict(zip(LABELS, labels)) != self.labels or
                    not set(members).issubset({self.gateway, self.tool})):
                raise RuntimeError("Network ownership/membership differs; refusing changes.")
        if relay:
            info = container(self.relay)
            if (info["labels"] != self.labels or
                    info["mode"] != "container:" + self.tool or info["ports"]):
                raise RuntimeError("Relay ownership/network mode differs; refusing changes.")
        return members

    def verify_targets(self):
        gateway, tool = container(self.gateway), container(self.tool)
        for expected, info in ((self.gateway, gateway), (self.tool, tool)):
            if info["id"] != expected or not info["running"]:
                raise RuntimeError("The selected container is not running with that exact ID.")
        if (gateway["service"] != "gateway" or not gateway["project"] or
                gateway["ports"] != {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}):
            raise RuntimeError("Expected a Compose gateway published only on 127.0.0.1:8080.")
        if self.kind == "artex" and (tool["service"] != "artex" or not tool["project"]):
            raise RuntimeError("Expected the explicit ARTEX Compose service.")
        if self.kind == "strix" and tool["run"] != self.labels["run-id"]:
            raise RuntimeError("Strix sandbox run label does not match --run-id.")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", gateway["image"]):
            raise RuntimeError("Expected an immutable local gateway image ID.")
        docker("image", "inspect", "--format", "{{.Id}}", gateway["image"])
        docker("exec", self.gateway, "nginx", "-v")
        return gateway["image"]

    def setup(self):
        if any(self.existing()):
            raise RuntimeError("Helper name exists. Use status; never reuse an unidentified resource.")
        image = self.verify_targets()
        if not CONF.is_file() or "," in str(CONF):
            raise RuntimeError("Relay config missing or checkout path contains a comma.")
        docker("exec", self.tool, "python3", "-c", PORT_CHECK)
        print("Creating only:", self.network, self.relay, flush=True)
        print("gateway=" + self.gateway + " tool=" + self.tool, flush=True)
        docker("network", "create", "--driver", "bridge", "--internal",
               *self.label_args(), self.network)
        # Leave a labelled partial setup on failure; never guess a rollback scope.
        docker("network", "connect", "--alias", "northstar-gateway", self.network, self.gateway)
        docker("network", "connect", self.network, self.tool)
        docker("run", "--detach", "--pull", "never", "--name", self.relay,
               *self.label_args(), "--label", PREFIX + "config-sha256=" +
               hashlib.sha256(CONF.read_bytes()).hexdigest(),
               "--network", "container:" + self.tool, "--read-only", "--user", "101:101",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--memory", "32m", "--memory-swap", "32m", "--cpus", "0.1",
               "--pids-limit", "32", "--no-healthcheck",
               "--mount", "type=bind,src=" + str(CONF) +
               ",dst=/etc/nginx/northstar-relay.conf,readonly",
               "--entrypoint", "nginx", image,
               "-c", "/etc/nginx/northstar-relay.conf", "-g", "daemon off;")
        self.status()

    def status(self):
        network, relay = self.existing()
        members = self.verify_owned(network, relay)
        print(json.dumps({"network": self.network, "relay": self.relay,
                          "network_exists": network, "relay_exists": relay,
                          **self.labels}, indent=2))
        if not network or not relay or set(members) != {self.gateway, self.tool}:
            raise RuntimeError("Setup absent/incomplete; no changes made by status.")
        self.verify_targets()
        if not container(self.relay)["running"]:
            raise RuntimeError("Relay is not running; do not start testing.")
        print("Structure ready. Run the documented health/config/browser checks before testing.")

    def remove(self):
        network, relay = self.existing()
        members = self.verify_owned(network, relay)
        if relay:
            docker("container", "rm", "--force", self.relay)
        if network:
            for member in sorted(members):
                docker("network", "disconnect", self.network, member)
            docker("network", "rm", self.network)
        print("Removed only the selected helper relay/network; scanner and lab containers untouched."
              if network or relay else "No matching helper resources remain.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("setup", "status", "remove"))
    parser.add_argument("--gateway", required=True, help="Full gateway container ID")
    parser.add_argument("--tool", required=True, help="Full scanner container ID")
    parser.add_argument("--kind", choices=("artex", "strix"), required=True)
    parser.add_argument("--run-id", default="", help="Required for the selected new Strix session")
    args = parser.parse_args()
    try:
        relay = Relay(args.gateway, args.tool, args.kind, args.run_id)
        getattr(relay, args.action)()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print("STOP:", exc, file=sys.stderr)
        print("No broad cleanup attempted. Retain IDs; inspect with status, then remove only this helper.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
