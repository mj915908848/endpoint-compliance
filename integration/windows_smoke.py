#!/usr/bin/env python3
"""Native Windows smoke test: a loopback server plus the real agent collectors on this machine.

It plants a known listener and a user proxy setting, runs one real scan, and checks that the registry,
PackageManager, socket-table and account lookups produced complete modules and the expected evidence.
Runs on Windows only (CI uses windows-latest); it changes the current user's proxy setting and restores it.
"""
import argparse, http.cookiejar, json, os, pathlib, secrets, socket, subprocess, sys, time, urllib.request
import winreg

root = pathlib.Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--dotnet", default="dotnet")
ap.add_argument("--data", type=pathlib.Path)
args = ap.parse_args()
data = args.data or root / "artifacts" / ("windows-smoke-" + secrets.token_hex(4))
data.mkdir(parents=True, exist_ok=False)

with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
base = f"http://127.0.0.1:{port}"
password = secrets.token_urlsafe(24)
env = os.environ.copy()
env.update({
    "ASPNETCORE_URLS": base,
    "Compliance__DemoMode": "true",
    "Compliance__Storage": "Sqlite",
    "Compliance__Database": str(data / "server.sqlite"),
    "Compliance__SigningKeyPath": str(data / "signing.pem"),
    "Compliance__BootstrapUsers": json.dumps(
        [{"username": "ci-admin", "password": password, "roles": ["Reader", "Operator", "Publisher"]}]
    ),
})
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def request(path, body=None, raw=False):
    encoded = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        base + path, data=encoded, headers={"Content-Type": "application/json", "X-CSRF-Token": csrf}
    )
    with client.open(req, timeout=30) as response:
        content = response.read().decode()
        return content if raw else json.loads(content)


INTERNET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
PROXY_PORT = 7890  # one of the agent's common proxy ports, so the listener is reported as a clue


def read_proxy():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET) as key:
        values = {}
        for name in ("ProxyEnable", "ProxyServer"):
            try:
                values[name] = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                values[name] = None
        return values


def write_proxy(values):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET, 0, winreg.KEY_SET_VALUE) as key:
        for name, value in values.items():
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, value[1], value[0])


server_log = (data / "server.log").open("w")
server = None
saved_proxy = read_proxy()
listener = socket.socket()
try:
    dll = root / "src/Compliance.Server/bin/Release/net10.0/Compliance.Server.dll"
    server = subprocess.Popen(
        [args.dotnet, str(dll)], cwd=root / "src/Compliance.Server", env=env,
        stdout=server_log, stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 60
    while True:
        if server.poll() is not None:
            raise AssertionError("Server exited; inspect server.log")
        try:
            request("/api/status")
            break
        except Exception:
            if time.monotonic() > deadline:
                raise AssertionError("Server startup timeout")
            time.sleep(0.2)
    csrf = request("/api/auth/login", {"username": "ci-admin", "password": password})["csrfToken"]
    code = request("/api/enrollment-codes", {"expiresMinutes": 15})["code"]

    # Known state for the collectors to find: this process listens on a proxy port, and the user's
    # system proxy points at it.
    listener.bind(("127.0.0.1", PROXY_PORT))
    listener.listen()
    write_proxy({
        "ProxyEnable": (1, winreg.REG_DWORD),
        "ProxyServer": (f"127.0.0.1:{PROXY_PORT}", winreg.REG_SZ),
    })

    agent = root / "src/Compliance.Agent/bin/Release/net10.0-windows10.0.19041.0/Compliance.Agent.dll"
    cmd = [args.dotnet, str(agent), "--local-demo", "--once", "--data-dir", str(data / "agent"),
           "--server", base, "--enroll", "--code", code]
    with (data / "agent.log").open("w") as log:
        result = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    print((data / "agent.log").read_text(errors="replace"))
    assert result.returncode == 0, f"Agent exited with {result.returncode}"

    devices = request("/api/devices")
    assert len(devices) == 1, f"expected one device, got {len(devices)}"
    device = devices[0]["id"]
    detail = request(f"/api/devices/{device}")
    snapshot = detail["snapshot"]
    assert snapshot and snapshot["simulated"] is False, "Native scan must not be simulated"
    (data / "snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    md = request(f"/api/devices/{device}/report.md", raw=True)
    (data / "report.md").write_text(md, encoding="utf-8")

    print("Modules:")
    for m in snapshot["modules"]:
        print(f"  {m['module']:<16} {m['scope']:<48} {m['status']:<9} {m.get('error') or ''}")
    by_module = {}
    for m in snapshot["modules"]:
        by_module.setdefault(m["module"], []).append(m)
    # Other accounts on the runner are not logged on, so their per-user scopes legitimately report an
    # unloaded hive or missing profile folder. Anything else that is not Complete is a collector failure.
    expected_gaps = ("注册表未加载", "用户目录不可用")
    failures = []
    for module in ("installed", "services", "processes", "proxy", "ports", "users", "appx", "extensions"):
        results = by_module.get(module, [])
        if not any(m["status"] == "Complete" for m in results):
            failures.append(f"{module}: no complete result")
        for m in results:
            if m["status"] != "Complete" and not any(g in (m.get("error") or "") for g in expected_gaps):
                failures.append(f"{module} ({m['scope']}): {m['status']} {m.get('error') or ''}")
    assert not failures, "Incomplete native modules:\n  " + "\n  ".join(failures)
    print("PASS registry, services, processes, PackageManager, socket table and accounts read completely")

    evidence = snapshot["evidence"]
    port_clue = [e for e in evidence if e["objectKey"] == f"tcp:127.0.0.1:{PROXY_PORT}"]
    assert port_clue and "python" in port_clue[0]["summary"].lower(), \
        f"Socket table did not attribute port {PROXY_PORT} to python: {port_clue}"
    proxy = [e for e in evidence if e["kind"] == "Proxy" and e["objectKey"].startswith("proxy:S-1-")]
    assert proxy, "User proxy from the registry was not reported"
    assert "python" in proxy[0]["summary"].lower(), f"Proxy not attributed to its listener: {proxy[0]['summary']}"
    print("PASS planted listener and user proxy found and attributed to their owning process")

    users = snapshot.get("users") or []
    assert users and all(u["name"] and not u["name"].startswith("S-1-") for u in users), \
        f"Accounts not translated to names: {users}"
    print("PASS user SIDs translated to account names: " + ", ".join(u["name"] for u in users))

    report = request(f"/api/devices/{device}/report")
    assert report["verdict"] == "FAIL", f"An enabled proxy must fail the check, got {report['verdict']}"
    assert sum(line.startswith("## ") for line in md.splitlines()) == 9
    print("PASS native report: FAIL with nine Markdown sections")
    print("Evidence: " + str(data))
finally:
    write_proxy(saved_proxy)
    listener.close()
    if server and server.poll() is None:
        server.terminate()
        server.wait(timeout=10)
    server_log.close()
    if sys.exc_info()[0] is not None and (data / "server.log").exists():
        print((data / "server.log").read_text(errors="replace")[-4000:])
