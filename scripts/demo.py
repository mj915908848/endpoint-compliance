#!/usr/bin/env python3
"""Local demo on macOS/Linux: loopback server (SQLite) plus two simulated endpoints.

Builds the UI, server and agent, starts the server at http://127.0.0.1:5080, enrolls one
endpoint with a confirmed violation and one without findings, then keeps running until Ctrl+C.
Simulated endpoints never count as native verification, so the clean one shows UNKNOWN.
State lives in data/demo/ (gitignored); the admin login is written to data/demo/login.txt.
"""
import argparse, http.cookiejar, json, os, pathlib, secrets, shutil, subprocess, sys, time, urllib.request
from datetime import datetime, timezone

root = pathlib.Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--dotnet", default=shutil.which("dotnet") or str(pathlib.Path.home() / ".dotnet/dotnet"))
ap.add_argument("--port", type=int, default=5080)
ap.add_argument("--reset", action="store_true", help="discard data/demo and start fresh")
ap.add_argument("--skip-build", action="store_true")
args = ap.parse_args()

data = root / "data" / "demo"
if args.reset and data.exists():
    shutil.rmtree(data)
data.mkdir(parents=True, exist_ok=True)
base = f"http://127.0.0.1:{args.port}"


def run(cmd, cwd=root):
    print("$", " ".join(map(str, cmd)), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


if not args.skip_build:
    npm = shutil.which("npm") or sys.exit("npm not found")
    if not (root / "ui/node_modules").exists():
        run([npm, "ci", "--no-audit", "--no-fund"], cwd=root / "ui")
    run([npm, "run", "build"], cwd=root / "ui")
    run([args.dotnet, "build", "src/Compliance.Server", "-c", "Release", "-v", "q", "-nologo"])
    run([args.dotnet, "build", "src/Compliance.Agent", "-c", "Release", "-v", "q", "-nologo"])

login_file = data / "login.txt"
if login_file.exists():
    password = json.loads(login_file.read_text())["password"]
else:
    password = secrets.token_urlsafe(18)
    login_file.write_text(json.dumps({"url": base, "username": "demo-admin", "password": password}, indent=2))
    login_file.chmod(0o600)

env = os.environ.copy()
env.update({
    "ASPNETCORE_URLS": base,
    "Compliance__DemoMode": "true",
    "Compliance__Storage": "Sqlite",
    "Compliance__Database": str(data / "server.sqlite"),
    "Compliance__SigningKeyPath": str(data / "signing.pem"),
    "Compliance__BootstrapUsers": json.dumps([
        {"username": "demo-admin", "password": password, "roles": ["Reader", "Operator", "Publisher", "Admin"]},
    ]),
})
log = (data / "server.log").open("a")
server = subprocess.Popen(
    [args.dotnet, str(root / "src/Compliance.Server/bin/Release/net10.0/Compliance.Server.dll")],
    cwd=root / "src/Compliance.Server", env=env, stdout=log, stderr=subprocess.STDOUT,
)

client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def api(path, body=None):
    req = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
    )
    with client.open(req, timeout=15) as r:
        return json.loads(r.read().decode())


try:
    deadline = time.monotonic() + 30
    while True:
        if server.poll() is not None:
            sys.exit(f"Server exited; see {data / 'server.log'}")
        try:
            api("/api/status")
            break
        except Exception:
            if time.monotonic() > deadline:
                sys.exit("Server startup timeout")
            time.sleep(0.2)

    csrf = api("/api/auth/login", {"username": "demo-admin", "password": password})["csrfToken"]

    def inventory(maker, model, serial, cpu, cores, threads, memory_gb, disk, disk_gb, programs):
        gb = 1024 ** 3
        return {
            "collectedAt": datetime.now(timezone.utc).isoformat(),
            "hardware": {"manufacturer": maker, "model": model, "serialNumber": serial, "biosVersion": "1.20.0",
                         "processor": cpu, "cores": cores, "logicalProcessors": threads, "memoryBytes": memory_gb * gb},
            "operatingSystem": {"name": "Windows 11 专业版", "version": "10.0.26100.2314", "displayVersion": "24H2",
                                "architecture": "64 位", "installedAt": "2025-03-18T02:00:00Z",
                                "lastBootAt": datetime.now(timezone.utc).isoformat()},
            "disks": [{"model": disk, "sizeBytes": disk_gb * 1000 ** 3, "mediaType": "SSD", "busType": "NVMe"}],
            "volumes": [{"name": "C:", "label": "", "fileSystem": "NTFS", "sizeBytes": disk_gb * 1000 ** 3 - 10 ** 9,
                         "freeBytes": disk_gb * 1000 ** 3 // 3}],
            "software": [{"name": n, "version": v, "publisher": p, "installedOn": "20250410", "scope": s}
                         for n, v, p, s in programs],
        }

    def endpoint(name, host, evidence, inventory):
        folder = data / "agents" / name
        folder.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        (folder / "inventory.json").write_text(json.dumps(inventory, ensure_ascii=False))
        modules = ["installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli"]
        (folder / "snapshot.json").write_text(json.dumps({
            "deviceId": "fixture", "hostName": host, "platform": "Windows", "simulated": True,
            "collectedAt": now, "policyVersion": 1, "evidence": evidence, "controls": [],
            "modules": [{"module": m, "scope": "machine", "status": "Complete", "collectedAt": now} for m in modules],
            "users": [{"sid": "S-1-5-21-1-2-3-1001", "name": "zhangsan"}],
        }))
        cmd = [args.dotnet, str(root / "src/Compliance.Agent/bin/Release/net10.0-windows/Compliance.Agent.dll"),
               "--fixture", str(folder / "snapshot.json"), "--data-dir", str(folder / "state"),
               "--server", base, "--once"]
        if not (folder / "state").exists():
            cmd += ["--enroll", "--code", api("/api/enrollment-codes", {"expiresMinutes": 15})["code"]]
        with (folder / "agent.log").open("a") as out:
            subprocess.run(cmd, cwd=root, stdout=out, stderr=subprocess.STDOUT, timeout=60, check=True)

    endpoint("violating", "DEMO-PC-01", [
        {"productId": "cursor", "productName": "Cursor", "kind": "Installation", "objectKey": "cursor-install",
         "source": "demo registry", "summary": "Cursor 已安装（模拟数据）", "userSid": "S-1-5-21-1-2-3-1001",
         "confirmed": True},
        {"productId": "cursor", "productName": "Cursor", "kind": "Process", "objectKey": "pid:4242",
         "source": "demo process", "summary": "Cursor.exe 正在运行（模拟数据）", "userSid": "S-1-5-21-1-2-3-1001",
         "confirmed": True},
    ], inventory("LENOVO", "ThinkPad T14 Gen 4", "PF4DEMO1", "Intel(R) Core(TM) i7-1365U", 10, 12, 32,
                 "SAMSUNG MZVL21T0", 1024, [
                     ("Cursor", "1.7.38", "Anysphere", "zhangsan"),
                     ("Google Chrome", "131.0.6778.86", "Google LLC", "machine"),
                     ("微信", "3.9.12.17", "腾讯科技(深圳)有限公司", "zhangsan"),
                     ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "machine"),
                     ("Microsoft 365 企业应用版 - zh-cn", "16.0.18129.20158", "Microsoft Corporation", "machine"),
                 ]))
    endpoint("clean", "DEMO-PC-02", [], inventory(
        "Dell Inc.", "OptiPlex 7010", "8XKDEMO2", "13th Gen Intel(R) Core(TM) i5-13500", 14, 20, 16,
        "KIOXIA KBG50ZNV512G", 512, [
            ("Google Chrome", "130.0.6723.117", "Google LLC", "machine"),
            ("钉钉", "7.6.15", "钉钉(中国)信息技术有限公司", "lisi"),
            ("WPS Office", "12.1.0.18608", "Kingsoft Corp.", "machine"),
            ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "machine"),
        ]))

    print(f"""
Demo running at {base}
  Admin (operate/publish):  demo-admin
  Password:                 see {login_file}
Two simulated endpoints are enrolled. Press Ctrl+C to stop; data stays in {data}
(run with --reset to start over).""", flush=True)
    server.wait()
except KeyboardInterrupt:
    pass
finally:
    if server.poll() is None:
        server.terminate()
        server.wait(timeout=10)
