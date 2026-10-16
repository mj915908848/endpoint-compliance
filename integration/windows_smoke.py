#!/usr/bin/env python3
"""Native Windows smoke test: a loopback server plus the real agent collectors on this machine.

It plants a known listener, a user proxy setting and files whose names contain a sensitive keyword, runs one
real scan, and checks that the registry, PackageManager, socket-table, account lookups and file name scan
produced complete modules and the expected evidence. Runs on Windows only (CI uses windows-latest); it
changes the current user's proxy setting and restores it, and removes the planted files.
"""
import argparse, http.cookiejar, json, os, pathlib, secrets, shutil, socket, subprocess, sys, time, urllib.request
import winreg

# The runner console is cp1252; agent and server logs are UTF-8 Chinese.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

root = pathlib.Path(__file__).resolve().parents[1]
ap = argparse.ArgumentParser()
ap.add_argument("--dotnet", default="dotnet")
ap.add_argument("--data", type=pathlib.Path)
# A staged package (agent-windows-x64 + deploy/windows): installs it as a service from a downloaded
# 登记配置.json, as an administrator would, then uninstalls it.
ap.add_argument("--package", type=pathlib.Path)
# An earlier release's package: installed first, then upgraded in place with --package ("1 仅更新程序").
ap.add_argument("--old-package", type=pathlib.Path)
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



def screenshot(path):
    """Best effort: a hosted runner may have no visible desktop."""
    script = (
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing;"
        "$b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds;"
        "$i=New-Object System.Drawing.Bitmap $b.Width,$b.Height;"
        "$g=[System.Drawing.Graphics]::FromImage($i);"
        "$g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size);"
        f"$i.Save('{path}')"
    )
    result = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Screenshot {path.name} failed: {result.stderr.strip()[:300]}")

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


# A keyword no real file contains, and content that must never leave the machine.
KEYWORD = "冒烟机密" + secrets.token_hex(3)
SECRET_CONTENT = "content-must-not-upload-" + secrets.token_hex(8)
# One hit in the user's profile and one folder hit on the drive holding the checkout (D: on CI runners).
profile_hit = pathlib.Path.home() / f"{KEYWORD}-名单.txt"
drive_hit = data.resolve() / f"{KEYWORD}-资料"
# A portable proxy program unpacked outside any install folder.
TOKEN = secrets.token_hex(4)
program_dir = data.resolve() / f"portable-{TOKEN}"
planted = []

server_log = (data / "server.log").open("w")
server = None
saved_proxy = read_proxy()
listener = socket.socket()
installed = False
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

    # Publish the sensitive file rule before enrolling so the device is assigned it.
    policy = json.loads(request("/api/policies/current")["payload"])
    policy["sensitiveFiles"] = {
        **policy.get("sensitiveFiles", {}),
        "enabled": True,
        "scanUserProfiles": True,
        "scanOtherFixedDrives": True,
        # Package caches on the runner hold many files and no documents.
        "excludePaths": ["AppData", "$Recycle.Bin", "System Volume Information", "node_modules", ".git",
                         ".nuget", ".dotnet", ".cargo", ".rustup", "hostedtoolcache"],
        "rules": [{"id": "smoke", "name": "冒烟测试机密", "keywords": [KEYWORD], "extensions": [],
                   "matchFolders": True, "action": "Alert"}],
    }
    request("/api/policies", policy)
    code = request("/api/enrollment-codes", {"expiresMinutes": 15})["code"]

    profile_hit.write_text(SECRET_CONTENT, encoding="utf-8")
    planted.append(profile_hit)
    drive_hit.mkdir()
    planted.append(drive_hit)
    (drive_hit / f"{KEYWORD}-内部.txt").write_text(SECRET_CONTENT, encoding="utf-8")
    program_dir.mkdir()
    planted.append(program_dir)
    (program_dir / "xray.exe").write_bytes(b"MZ")

    # Known state for the collectors to find: this process listens on a proxy port, and the user's
    # system proxy points at it.
    listener.bind(("127.0.0.1", PROXY_PORT))
    listener.listen()
    write_proxy({
        "ProxyEnable": (1, winreg.REG_DWORD),
        "ProxyServer": (f"127.0.0.1:{PROXY_PORT}", winreg.REG_SZ),
    })

    agent = root / "src/Compliance.Agent/bin/Release/net10.0-windows/Compliance.Agent.dll"
    cmd = [args.dotnet, str(agent), "--local-demo", "--once", "--data-dir", str(data / "agent"),
           "--server", base, "--enroll", "--code", code]
    with (data / "agent.log").open("w") as log:
        result = subprocess.run(cmd, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    print((data / "agent.log").read_text(encoding="utf-8", errors="replace"))
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
    for module in ("installed", "services", "processes", "proxy", "ports", "users", "appx", "extensions", "cli",
                   "programs"):
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

    program = [e for e in evidence if e["productId"] == "program-clue"
               and e["objectKey"].endswith(f"portable-{TOKEN}\\xray.exe".lower())]
    assert program and not program[0]["confirmed"], \
        f"Portable program without version information was not a clue: {program}"
    print("PASS portable program found through the file table reported as a clue")

    users = snapshot.get("users") or []
    assert users and all(u["name"] and not u["name"].startswith("S-1-") for u in users), \
        f"Accounts not translated to names: {users}"
    print("PASS user SIDs translated to account names: " + ", ".join(u["name"] for u in users))

    system_drive = os.environ.get("SystemDrive", "C:").upper()[0]
    sensitive_modules = by_module.get("sensitive-files", [])
    assert sensitive_modules, "Sensitive file scan reported no result"
    for m in sensitive_modules:
        # Folders the scan account cannot open are listed in the error and keep the scope incomplete.
        assert m["status"] == "Complete" or (m["status"] == "Error" and "无法读取" in (m.get("error") or "")), \
            f"Sensitive file scan of {m['scope']} failed: {m['status']} {m.get('error') or ''}"
    hits = {e["objectKey"].lower(): e for e in evidence if e["kind"] == "SensitiveFile"}
    profile_evidence = hits.get(str(profile_hit).lower())
    assert profile_evidence and profile_evidence["source"].startswith("S-1-5-21-"), \
        f"Profile file not reported under its user: {profile_evidence} (hits: {list(hits)})"
    drive_evidence = hits.get(str(drive_hit).lower())
    assert drive_evidence, f"Folder on the checkout drive not reported (hits: {list(hits)})"
    if drive_hit.drive.upper()[0] != system_drive:
        assert drive_evidence["source"] == "drive:" + drive_hit.drive.upper()[0], \
            f"Folder on a data drive reported under {drive_evidence['source']}"
    assert not any(k.endswith("-内部.txt") for k in hits), "File inside a reported folder was listed again"
    assert SECRET_CONTENT not in json.dumps(snapshot, ensure_ascii=False), "File content left the machine"
    print(f"PASS sensitive file names found in the profile and under {drive_evidence['source']}; content not uploaded")
    log_text = (data / "agent.log").read_text(encoding="utf-8", errors="replace")
    assert "通过 NTFS 文件表比对" in log_text, "Sensitive file scan did not use the NTFS file table"
    print("PASS sensitive file scan read the NTFS file table instead of walking folders")

    alerts = request("/api/alerts")
    sensitive_alerts = {a["objectKey"].lower() for a in alerts if a["type"] == "SensitiveFile"}
    assert {str(profile_hit).lower(), str(drive_hit).lower()} <= sensitive_alerts, \
        f"Sensitive file alerts missing: {sensitive_alerts}"
    assert "### 敏感文件" in md and KEYWORD in md, "Markdown report lacks the sensitive file table"
    print("PASS one administrator alert per sensitive path and the report lists them")

    report = request(f"/api/devices/{device}/report")
    assert report["verdict"] == "FAIL", f"An enabled proxy must fail the check, got {report['verdict']}"
    assert sum(line.startswith("## ") for line in md.splitlines()) == 9
    print("PASS native report: FAIL with nine Markdown sections")

    # The tray's windows must start and stay up; screenshots go to the evidence folder for a visual check.
    tray = root / "src/Compliance.Tray/bin/Release/net10.0-windows/Compliance.Tray.exe"
    for argument, shot in (("--log", "tray-log.png"), ("--notices", "tray-notices.png")):
        viewer = subprocess.Popen([str(tray), argument])
        try:
            time.sleep(6)
            assert viewer.poll() is None, f"Tray {argument} exited with {viewer.returncode}"
            if argument == "--log":
                # A second request only brings the open window forward.
                second = subprocess.run([str(tray), argument], timeout=30)
                assert second.returncode == 0 and viewer.poll() is None, "A second log window was opened"
            screenshot(data / shot)
        finally:
            viewer.kill()
            viewer.wait(timeout=10)
    print("PASS tray log window and notification center start")

    if args.package:
        package = args.package.resolve()
        batch = request("/api/enrollment-codes", {"expiresMinutes": 60, "maxUses": 2, "label": "冒烟批次"})

        def run_installer(root_dir, answer, name, succeeds=True):
            (root_dir / "登记配置.json").write_text(
                json.dumps({"serverUrl": base, "code": batch["code"]}), encoding="utf-8"
            )
            install = [
                "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(root_dir / "deploy/windows/Install-TrialService.ps1"), "-PackageRoot", str(root_dir),
            ]
            with (data / name).open("w", encoding="utf-8") as log:
                # Without an answer there is no console input: a prompt the config should have answered fails.
                result = subprocess.run(install, input=answer, stdout=log, stderr=subprocess.STDOUT,
                                        text=True, timeout=300)
            print((data / name).read_text(encoding="utf-8", errors="replace"))
            assert (result.returncode == 0) == succeeds, f"Installer exited with {result.returncode}"

        def wait_reporting(since=""):
            deadline = time.monotonic() + 180
            while True:
                enrolled = [d for d in request("/api/devices") if d["id"] != device]
                if enrolled and (enrolled[0]["lastHeartbeat"] or "") > since and enrolled[0]["lastScan"]:
                    return enrolled
                assert time.monotonic() < deadline, "Installed service did not enroll, heartbeat and report"
                time.sleep(2)

        # A standard user may create the data directory before installation, with an agent.json of their own. The
        # installer must refuse it instead of enrolling with that file; rolling back removes the directory.
        agent_data = pathlib.Path(os.environ["ProgramData"]) / "ComplianceAgent"
        agent_data.mkdir()
        (agent_data / "agent.json").write_text(json.dumps({"serverUrl": "http://10.0.0.1:1"}), encoding="utf-8")
        subprocess.run(["icacls", str(agent_data), "/setowner", "*S-1-5-32-545", "/T"], check=True, capture_output=True)
        installed = True
        run_installer(package, "", "foreign-data.log", succeeds=False)
        assert "not SYSTEM or Administrators" in (data / "foreign-data.log").read_text(encoding="utf-8", errors="replace")
        assert not agent_data.exists(), "Rolling back left the foreign data directory"
        assert subprocess.run(["sc.exe", "query", "ComplianceAgent"], capture_output=True).returncode != 0, \
            "A service was installed next to a foreign data directory"
        print("PASS the installer refuses a data directory someone else created")
        run_installer((args.old_package or args.package).resolve(), "", "install.log")
        enrolled = wait_reporting()
        uses = [c for c in request("/api/enrollment-codes") if c["id"] == batch["id"]][0]["uses"]
        assert uses == 1, f"batch code uses {uses}"
        print("PASS double-click installer enrolls with the downloaded config; the service reports")
        if args.old_package:
            before = enrolled[0]["lastHeartbeat"]
            run_installer(package, "1\n", "upgrade.log")
            upgraded = wait_reporting(before)
            assert [d["id"] for d in upgraded] == [d["id"] for d in enrolled], "Upgrade enrolled a new device"
            assert "更新到" in (data / "upgrade.log").read_text(encoding="utf-8", errors="replace")
            print("PASS upgrading an earlier release in place keeps the device identity and the service reports")
        # The installing administrator's account wrote the configuration and identity key (an earlier release left
        # them so); the service hands everything to Administrators, since an owner can always change permissions.
        owners = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(@(Get-Item -LiteralPath '{agent_data}' -Force) + @(Get-ChildItem -LiteralPath '{agent_data}' -Force)) | "
             "ForEach-Object { $_.Name + ' ' + (Get-Acl -LiteralPath $_.FullName).GetOwner("
             "[Security.Principal.SecurityIdentifier]).Value }"],
            capture_output=True, text=True, timeout=60,
        ).stdout
        assert owners.strip() and all(
            line.split()[-1] in ("S-1-5-18", "S-1-5-32-544") for line in owners.splitlines() if line.strip()
        ), f"Data directory items with other owners: {owners}"
        print("PASS the data directory and its files belong to SYSTEM or Administrators")
        # The log sits in a logs folder every user may read but not change, so the tray opens it without elevation;
        # an earlier release's log next to the key moved there on upgrade.
        logs = agent_data / "logs"
        assert (logs / "agent.log").exists(), "The service did not write logs\\agent.log"
        assert not (agent_data / "agent.log").exists() and not (agent_data / "agent.log.1").exists(), \
            "A log was left next to the identity key"
        rules = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"$acl = Get-Acl -LiteralPath '{logs}'; 'protected ' + $acl.AreAccessRulesProtected; "
             "$acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | "
             "ForEach-Object { $_.IdentityReference.Value + ' ' + $_.AccessControlType + ' ' + $_.FileSystemRights }"],
            capture_output=True, text=True, timeout=60,
        ).stdout
        users = [line for line in rules.splitlines() if line.startswith("S-1-5-32-545 ")]
        assert "protected True" in rules and users and all(
            "Allow" in line and not any(w in line for w in ("Write", "Modify", "FullControl", "Delete", "ChangePermissions"))
            for line in users
        ), f"Users may not read the logs folder, or may change it: {rules}"
        assert all(
            line.split()[0] in ("S-1-5-18", "S-1-5-32-544", "S-1-5-32-545")
            for line in rules.splitlines()[1:] if line.strip()
        ), f"The logs folder grants another account: {rules}"
        print("PASS the log is in a folder users may read but not change, and an earlier release's log moved there")
        # Explorer's "permanently get access" prompt grants the signed-in user access to the data directory.
        # The service must remove that grant on its next start, keep running and tell the administrator.
        before = wait_reporting()[0]["lastHeartbeat"]
        grant = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"icacls '{agent_data}' /grant '*S-1-5-32-545:(OI)(CI)R' /Q | Out-Null; "
             "Restart-Service ComplianceAgent; (Get-Service ComplianceAgent).Status"],
            capture_output=True, text=True, timeout=120,
        )
        assert grant.returncode == 0 and "Running" in grant.stdout, f"Service did not restart: {grant.stdout}{grant.stderr}"
        acl = subprocess.run(["icacls", str(agent_data)], capture_output=True, text=True).stdout
        assert "S-1-5-32-545" not in acl and "BUILTIN\\Users" not in acl, f"Users grant kept: {acl}"
        wait_reporting(before)
        deadline = time.monotonic() + 120
        while not any(a["type"] == "Health" and a["objectKey"] == "agent:data-acl" for a in request("/api/alerts")):
            assert time.monotonic() < deadline, "No health alert for the repaired data directory permissions"
            time.sleep(2)
        print("PASS a user granted access to the data directory is removed at start and reported")
        # The installed tray shares the service's runtime folder; it must load from there.
        installed_tray = pathlib.Path(os.environ["ProgramFiles"]) / "ComplianceAgent" / "Compliance.Tray.exe"
        viewer = subprocess.Popen([str(installed_tray), "--notices"])
        try:
            time.sleep(6)
            assert viewer.poll() is None, f"Installed tray exited with {viewer.returncode}"
        finally:
            viewer.kill()
            viewer.wait(timeout=10)
        print("PASS installed tray starts from the shared runtime folder")
        # Start the installed tray as the installer does, then uninstall: every runtime file must be removed.
        subprocess.Popen(["explorer.exe", str(installed_tray)])
        time.sleep(5)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(package / "deploy/windows/Uninstall-TrialService.ps1"), "-Quiet"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180,
        )
        installed = False
        assert result.returncode == 0 and not installed_tray.parent.exists(), \
            f"Uninstall left {installed_tray.parent}: {result.stdout}{result.stderr}"
        print("PASS uninstall stops the tray and service and removes the install folder")

    print("Evidence: " + str(data))
finally:
    if installed:
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(args.package.resolve() / "deploy/windows/Uninstall-TrialService.ps1"), "-Quiet"],
            stdin=subprocess.DEVNULL, timeout=120,
        )
    write_proxy(saved_proxy)
    for path in planted:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        except OSError as e:
            print(f"Could not remove {path}: {e}")
    listener.close()
    if server and server.poll() is None:
        server.terminate()
        server.wait(timeout=10)
    server_log.close()
    if sys.exc_info()[0] is not None and (data / "server.log").exists():
        print((data / "server.log").read_text(encoding="utf-8", errors="replace")[-4000:])
