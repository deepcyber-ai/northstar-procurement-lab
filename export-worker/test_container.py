"""Disposable Docker containment smoke test; no third-party Python packages.

Build the local Dockerfile first as northstar-export-worker:containment, then run
python3 test_container.py. Only containers/volumes created by this invocation are removed.
"""
import json
import subprocess
import uuid


def docker(*arguments):
    return subprocess.check_output(["docker", *arguments], text=True)


def run():
    name = "northstar-export-check-" + uuid.uuid4().hex[:12]
    volume = name + "-socket"
    holder = name + "-client"
    created_container = False
    created_volume = False
    created_holder = False
    def create_volume():
        docker("volume", "create", "--driver", "local", "--opt", "type=tmpfs", "--opt", "device=tmpfs",
               "--opt", "o=size=1m,uid=10001,gid=10001,mode=0755,nosuid,nodev,noexec", volume)
    def start_worker():
        docker("run", "--detach", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--pids-limit", "32", "--memory", "64m",
               "--memory-swap", "64m", "--cpus", "0.25", "--tmpfs",
               "/tmp:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700",
               "--mount", "type=volume,source=" + volume + ",target=/run/northstar-export",
               "northstar-export-worker:containment")
    try:
        create_volume()
        created_volume = True
        start_worker()
        created_container = True
        config = json.loads(docker("inspect", name))[0]
        host = config["HostConfig"]
        assert config["Config"]["User"] == "10001:10001"
        assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"]
        assert "ALL" in host["CapDrop"] and "no-new-privileges:true" in host["SecurityOpt"]
        assert host["PidsLimit"] == 32 and host["Memory"] == 64 * 1024 * 1024
        assert host["MemorySwap"] == host["Memory"] and host["NanoCpus"] == 250000000
        assert not config["NetworkSettings"]["Ports"]
        mounts = config["Mounts"]
        assert len(mounts) == 1 and mounts[0]["Type"] == "volume"
        assert mounts[0]["Name"] == volume and mounts[0]["Destination"] == "/run/northstar-export"
        volume_config = json.loads(docker("volume", "inspect", volume))[0]
        assert volume_config["Options"]["type"] == "tmpfs"
        assert "size=1m" in volume_config["Options"]["o"]
        output = docker("exec", name, "python3", "-I", "-c", PROBE)
        print(output.strip())
        print(docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges:true", "--user", "65534:65534",
                     "--mount", "type=volume,source=" + volume + ",target=/run/northstar-export,readonly",
                     "--entrypoint", "python3", "python:3.12-slim", "-I", "-c", CLIENT_PROBE).strip())
        print("Docker policy: non-root, network-none, read-only, capabilities dropped, no-new-privileges,")
        print("64 MiB RAM/no swap, 32 PIDs, 0.25 CPU, 1 MiB tmpfs socket-only volume: PASS")
        # Model the backend's long-lived RO mount: worker recreation alone must not be
        # advertised as clearing the shared volume while another consumer keeps it mounted.
        docker("run", "--detach", "--name", holder, "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--user", "65534:65534", "--pids-limit", "16",
               "--memory", "32m", "--memory-swap", "32m", "--cpus", "0.25",
               "--mount", "type=volume,source=" + volume + ",target=/run/northstar-export,readonly",
               "--entrypoint", "python3", "python:3.12-slim", "-I", "-c", "import time; time.sleep(60)")
        created_holder = True
        docker("exec", name, "python3", "-I", "-c",
               "from pathlib import Path; Path('/run/northstar-export/reset-proof').write_text('before reset')")
        docker("rm", "--force", name)
        created_container = False
        start_worker()
        created_container = True
        docker("exec", name, "python3", "-I", "-c",
               "from pathlib import Path; assert Path('/run/northstar-export/reset-proof').read_text() == 'before reset'")
        docker("rm", "--force", name)
        created_container = False
        docker("rm", "--force", holder)
        created_holder = False
        docker("volume", "rm", volume)
        created_volume = False
        create_volume()
        created_volume = True
        start_worker()
        created_container = True
        docker("exec", name, "python3", "-I", "-c",
               "from pathlib import Path; assert not Path('/run/northstar-export/reset-proof').exists()")
        print("Complete reset after releasing both mounts and recreating only the socket volume: PASS")
    finally:
        if created_container:
            docker("rm", "--force", name)
        if created_holder:
            docker("rm", "--force", holder)
        if created_volume:
            docker("volume", "rm", volume)
        print("Removed this check's disposable container and socket volume; no application data was mounted.")


PROBE = r'''
import errno, json, os, pathlib, socket, time
assert os.geteuid() == 10001
status = pathlib.Path('/proc/self/status').read_text()
assert 'CapEff:\t0000000000000000' in status and 'NoNewPrivs:\t1' in status
assert set(os.listdir('/sys/class/net')) == {'lo'}
assert not any(k.startswith(('AWS_', 'LAB_', 'NORTHSTAR_', 'DOCKER_')) for k in os.environ)
assert all(not pathlib.Path(p).exists() for p in ['/app/data', '/app/identity', '/app/keys', '/var/run/docker.sock'])
socket_mount = next(line.split() for line in pathlib.Path('/proc/mounts').read_text().splitlines()
                    if line.split()[1] == '/run/northstar-export')
assert socket_mount[2] == 'tmpfs'
assert all(option in socket_mount[3].split(',') for option in ('nosuid', 'nodev', 'noexec', 'size=1024k'))
space = os.statvfs('/run/northstar-export')
assert space.f_blocks * space.f_frsize <= 1024 * 1024
budget_probe = pathlib.Path('/run/northstar-export/socket-budget-proof')
try:
    with budget_probe.open('wb') as stream:
        for _ in range(32):
            stream.write(b'x' * 65536)
    raise AssertionError('Socket volume unexpectedly accepted 2 MiB')
except OSError as error:
    assert error.errno == errno.ENOSPC
finally:
    budget_probe.unlink(missing_ok=True)
try:
    pathlib.Path('/opt/export-worker/containment-marker').write_text('should not be writable')
    raise AssertionError('Root filesystem unexpectedly writable')
except OSError as error:
    assert error.errno in (errno.EROFS, errno.EACCES)
for host in ('169.254.169.254', '1.1.1.1'):
    try:
        connection = socket.create_connection((host, 80), timeout=0.2)
        connection.close()
        raise AssertionError('Outbound network unexpectedly reachable')
    except OSError:
        pass
path = '/run/northstar-export/export.sock'
deadline = time.monotonic() + 5
while not pathlib.Path(path).is_socket():
    assert time.monotonic() < deadline, 'Worker socket did not become ready'
    time.sleep(0.05)
def call(fmt, vulnerable):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(4)
        connection.connect(path)
        payload = {'version':1,'action':'export','format':fmt,'vulnerable':vulnerable,'order':{'id':'ORD-A-100'}}
        connection.sendall(json.dumps(payload).encode() + b'\n')
        data = bytearray()
        while not data.endswith(b'\n'):
            block = connection.recv(4096)
            assert block and len(data) + len(block) <= 65536
            data.extend(block)
        return json.loads(data)
proof = call('csv; printf CMD01_CONTAINER_PROOF', True)
assert 'CMD01_CONTAINER_PROOF' in proof['output'] and proof['exitCode'] == 0
fixed = call('csv; printf CMD01_CONTAINER_PROOF', False)
assert fixed['error'] == 'INVALID_EXPORT_FORMAT' and fixed['output'] == ''
fixture = call('json', False)
assert json.loads(fixture['output'])['id'] == 'SYNTHETIC-001'
print('Runtime boundary, metadata/internet denial, 1 MiB file budget, Unix socket, vulnerable marker and fixed rejection: PASS')
'''

CLIENT_PROBE = r'''
import errno, json, pathlib, socket
try:
    pathlib.Path('/run/northstar-export/forbidden-client-write').write_text('must fail')
    raise AssertionError('Client socket mount unexpectedly writable')
except OSError as error:
    assert error.errno in (errno.EROFS, errno.EACCES)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(4)
    connection.connect('/run/northstar-export/export.sock')
    request = {'version':1,'action':'export','format':'csv','vulnerable':False,'order':{'id':'ORD-A-100'}}
    connection.sendall(json.dumps(request).encode() + b'\n')
    data = bytearray()
    while not data.endswith(b'\n'):
        block = connection.recv(4096)
        assert block and len(data) + len(block) <= 65536
        data.extend(block)
    reply = json.loads(data)
    assert reply['exitCode'] == 0 and 'SYNTHETIC-001' in reply['output']
print('Different-UID client with read-only socket mount connects successfully: PASS')
'''


if __name__ == "__main__":
    run()
