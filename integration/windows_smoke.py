#!/usr/bin/env python3
"""Native Windows smoke test: a loopback server plus the real agent collectors on this machine.

It plants a known listener, a user proxy setting and files whose names contain a sensitive keyword, runs one
real scan, and checks that the registry, PackageManager, socket-table, account lookups and file name scan
produced complete modules and the expected evidence. Runs on Windows only (CI uses windows-latest); it
changes the current user's proxy setting and restores it, and removes the planted files.
"""
import argparse, base64, hashlib, http.cookiejar, json, os, pathlib, re, secrets, shutil, socket, subprocess, sys, time, urllib.request
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
# The client MSI: takes over a script install, enrolls silently, and waits for an enrollment when installed without one.
ap.add_argument("--msi", type=pathlib.Path)
args = ap.parse_args()
data = args.data or root / "artifacts" / ("windows-smoke-" + secrets.token_hex(4))
data.mkdir(parents=True, exist_ok=False)

with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
base = f"http://127.0.0.1:{port}"
password = secrets.token_urlsafe(24)
# The policy asks for it when the MSI removes the client (UninstallPassword in src/Compliance.Core/Tamper.cs).
uninstall_password = "smoke-" + secrets.token_hex(6)
salt = secrets.token_bytes(16)
uninstall_hash = "pbkdf2-sha256$100000${}${}".format(
    base64.b64encode(salt).decode(),
    base64.b64encode(hashlib.pbkdf2_hmac("sha256", uninstall_password.encode(), salt, 100000)).decode(),
)
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



def tray_running():
    found = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "if (Get-Process Compliance.Tray -ErrorAction SilentlyContinue) { 'yes' }"],
        capture_output=True, text=True, timeout=60,
    )
    return "yes" in found.stdout


def wait_service_tray():
    """The service starts the tray in signed-in sessions without one once no installation runs, as after an upgrade."""
    deadline = time.monotonic() + 90
    while not tray_running():
        assert time.monotonic() < deadline, "The service did not start the tray in the signed-in session"
        time.sleep(2)


def stop_trays():
    """Ends trays already running in this session; a new one would otherwise hand over to them and exit."""
    subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-Process Compliance.Tray -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep -Seconds 1"],
        capture_output=True, timeout=60,
    )


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
    result = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, errors="replace")
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
msi_installed = False
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
    policy["tamper"] = {"uninstallPassword": uninstall_hash}
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
    assert "通过文件索引比对" in log_text, "Sensitive file scan did not use the NTFS file table"
    # The sensitive file scan and the program file scan share one read of each drive's file table.
    reads = re.findall(r"文件索引：读取 ([A-Za-z]):", log_text)
    assert reads and len(reads) == len(set(r.upper() for r in reads)), \
        f"File tables read more than once per drive: {reads}"
    print(f"PASS both scans used one read of the NTFS file table per drive ({', '.join(reads)}) instead of walking folders")

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
                                        text=True, errors="replace", timeout=300)
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
        run_installer(package, "", "install.log")
        enrolled = wait_reporting()
        uses = [c for c in request("/api/enrollment-codes") if c["id"] == batch["id"]][0]["uses"]
        assert uses == 1, f"batch code uses {uses}"
        print("PASS double-click installer enrolls with the downloaded config; the service reports")
        # The installing administrator's account wrote the configuration and identity key; the service hands
        # everything to Administrators, since an owner can always change permissions.
        owners = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(@(Get-Item -LiteralPath '{agent_data}' -Force) + @(Get-ChildItem -LiteralPath '{agent_data}' -Force)) | "
             "ForEach-Object { $_.Name + ' ' + (Get-Acl -LiteralPath $_.FullName).GetOwner("
             "[Security.Principal.SecurityIdentifier]).Value }"],
            capture_output=True, text=True, errors="replace", timeout=60,
        ).stdout
        assert owners.strip() and all(
            line.split()[-1] in ("S-1-5-18", "S-1-5-32-544") for line in owners.splitlines() if line.strip()
        ), f"Data directory items with other owners: {owners}"
        print("PASS the data directory and its files belong to SYSTEM or Administrators")
        # The log sits in a logs folder every user may read but not change, so the tray opens it without elevation.
        logs = agent_data / "logs"
        assert (logs / "agent.log").exists(), "The service did not write logs\\agent.log"
        assert not (agent_data / "agent.log").exists() and not (agent_data / "agent.log.1").exists(), \
            "A log was left next to the identity key"
        rules = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"$acl = Get-Acl -LiteralPath '{logs}'; 'protected ' + $acl.AreAccessRulesProtected; "
             "$acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | "
             "ForEach-Object { $_.IdentityReference.Value + ' ' + $_.AccessControlType + ' ' + $_.FileSystemRights }"],
            capture_output=True, text=True, errors="replace", timeout=60,
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
        print("PASS the log is in a folder users may read but not change")
        # Explorer's "permanently get access" prompt grants the signed-in user access to the data directory.
        # The service must remove that grant on its next start, keep running and tell the administrator.
        before = wait_reporting()[0]["lastHeartbeat"]
        # With no tray running, the restarted service starts one in this session, as after a silent upgrade.
        stop_trays()
        grant = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"icacls '{agent_data}' /grant '*S-1-5-32-545:(OI)(CI)R' /Q | Out-Null; "
             "Restart-Service ComplianceAgent; (Get-Service ComplianceAgent).Status"],
            capture_output=True, text=True, errors="replace", timeout=120,
        )
        assert grant.returncode == 0 and "Running" in grant.stdout, f"Service did not restart: {grant.stdout}{grant.stderr}"
        acl = subprocess.run(["icacls", str(agent_data)], capture_output=True, text=True, errors="replace").stdout
        assert "S-1-5-32-545" not in acl and "BUILTIN\\Users" not in acl, f"Users grant kept: {acl}"
        wait_reporting(before)
        deadline = time.monotonic() + 120
        while not any(a["type"] == "Health" and a["objectKey"] == "agent:data-acl" for a in request("/api/alerts")):
            assert time.monotonic() < deadline, "No health alert for the repaired data directory permissions"
            time.sleep(2)
        print("PASS a user granted access to the data directory is removed at start and reported")
        wait_service_tray()
        print("PASS the service starts the tray in the signed-in session that has none")
        # The installed tray shares the service's runtime folder; it must load from there. The install script
        # already started one, and only one runs per session, so stop it first.
        installed_tray = pathlib.Path(os.environ["ProgramFiles"]) / "ComplianceAgent" / "Compliance.Tray.exe"
        stop_trays()
        viewer = subprocess.Popen([str(installed_tray), "--notices"])
        try:
            time.sleep(6)
            assert viewer.poll() is None, f"Installed tray exited with {viewer.returncode}"
            # A second start hands over to the running tray and leaves.
            second = subprocess.run([str(installed_tray)], timeout=30)
            assert second.returncode == 0 and viewer.poll() is None, "A second tray kept running"
        finally:
            viewer.kill()
            viewer.wait(timeout=10)
        print("PASS installed tray starts from the shared runtime folder, once per session")
        # Start the installed tray as the installer does, then uninstall: every runtime file must be removed.
        subprocess.Popen(["explorer.exe", str(installed_tray)])
        time.sleep(5)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(package / "deploy/windows/Uninstall-TrialService.ps1"), "-Quiet"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=180,
        )
        installed = False
        assert result.returncode == 0 and not installed_tray.parent.exists(), \
            f"Uninstall left {installed_tray.parent}: {result.stdout}{result.stderr}"
        print("PASS uninstall stops the tray and service and removes the install folder")

    if args.msi:
        msi = args.msi.resolve()
        program = pathlib.Path(os.environ["ProgramFiles"]) / "ComplianceAgent"
        agent_data = pathlib.Path(os.environ["ProgramData"]) / "ComplianceAgent"
        code = request("/api/enrollment-codes", {"expiresMinutes": 60, "maxUses": 5, "label": "MSI"})["code"]

        def msiexec(action, name, *properties, succeeds=True):
            global msi_installed
            log = data / name
            started = time.monotonic()
            if action == "/x" and succeeds:
                properties = (*properties, f"UNINSTALLPASSWORD={uninstall_password}")
            result = subprocess.run(["msiexec", action, str(msi), "/qn", "/l*v", str(log), *properties], timeout=600)
            took = time.monotonic() - started
            raw = log.read_bytes() if log.exists() else b""
            text = raw.decode("utf-16", errors="replace") if raw[:2] == b"\xff\xfe" else raw.decode("mbcs", errors="replace")
            if not succeeds:
                assert result.returncode != 0, f"msiexec {action} should have failed"
                assert uninstall_password not in text, "The MSI log holds the uninstall password"
                return text
            assert result.returncode == 0, f"msiexec {action} exited with {result.returncode}: {text[-3000:]}"
            assert uninstall_password not in text, "The MSI log holds the uninstall password"
            # No system restore point: where System Protection is on, creating one is slow (runners have it off).
            assert re.search(r"Property\(S\): MSIFASTINSTALL = 1\r?$", text, re.M), "The MSI does not skip the restore point"
            print(f"TIME msiexec {action} ({name}) {took:.1f}s; slowest actions: {slowest_actions(text)}", flush=True)
            msi_installed = action == "/i"
            return text

        def slowest_actions(text, count=6):
            """The actions that took longest: from each action's start in the verbose log, immediate ("Doing
            action") or in the installation script ("ActionStart"), to the next one's."""
            marks = []
            for m in re.finditer(r"\[(\d+):(\d+):(\d+):(\d+)\]: (?:Doing action: |Executing op: ActionStart\(Name=)([\w.]+)", text):
                h, mi, se, ms = (int(x) for x in m.groups()[:4])
                marks.append(((h * 3600 + mi * 60 + se) * 1000 + ms, m.group(5)))
            spans = {}
            for (at, name), (after, _) in zip(marks, marks[1:]):
                spans[name] = spans.get(name, 0) + (after - at) % 86400000
            ranked = sorted(spans.items(), key=lambda x: -x[1])[:count]
            return ", ".join(f"{name} {ms / 1000:.1f}s" for name, ms in ranked)

        def wait_device(device_id=None, known=(), since=""):
            """The device with this id, or the first one not in known, once it has a newer heartbeat and a scan."""
            deadline = time.monotonic() + 180
            while True:
                for d in request("/api/devices"):
                    if (d["id"] == device_id if device_id else d["id"] not in known) and \
                            (d["lastHeartbeat"] or "") > since and d["lastScan"]:
                        return d
                assert time.monotonic() < deadline, "The MSI-installed service did not report"
                time.sleep(2)

        # The Start menu shortcut gives the tray's notifications their name and icon through its AppUserModelID.
        shortcut = pathlib.Path(os.environ["ProgramData"]) / r"Microsoft\Windows\Start Menu\Programs\终端合规客户端.lnk"

        def notification_identity():
            assert shortcut.exists(), f"The MSI did not add {shortcut}"
            script = f"$s = (New-Object -ComObject Shell.Application).NameSpace('{shortcut.parent}').ParseName('{shortcut.name}'); $s.ExtendedProperty('System.AppUserModel.ID')"
            aumid = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
            assert aumid == "ComplianceAgent.Tray", f"The Start menu shortcut's AppUserModelID is {aumid!r}"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\AppUserModelId\ComplianceAgent.Tray") as key:
                assert winreg.QueryValueEx(key, "DisplayName")[0] == "终端合规客户端"
            # UAC, Task Manager and services.msc show these; none may fall back to the English assembly names.
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\ComplianceAgent") as key:
                assert winreg.QueryValueEx(key, "DisplayName")[0] == "终端合规客户端"
            folder = pathlib.Path(os.environ["ProgramFiles"]) / "ComplianceAgent"
            for exe, title in (("Compliance.Tray.exe", "终端合规客户端"), ("Compliance.Agent.exe", "终端合规客户端服务")):
                script = f"(Get-Item '{folder / exe}').VersionInfo.FileDescription"
                described = subprocess.run(["powershell", "-NoProfile", "-Command", "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
                assert described == title, f"{exe} describes itself as {described!r}"

        def wait_alert(object_key, device_id, contains=""):
            deadline = time.monotonic() + 180
            while True:
                for a in request("/api/alerts"):
                    if a["type"] == "Tamper" and a["objectKey"] == object_key and a["deviceId"] == device_id \
                            and contains in (a.get("summary") or ""):
                        return a
                assert time.monotonic() < deadline, f"No Tamper alert {object_key} {contains}"
                time.sleep(2)

        def removed():
            assert subprocess.run(["sc.exe", "query", "ComplianceAgent"], capture_output=True).returncode != 0, \
                "Uninstalling the MSI left the service"
            assert not program.exists(), \
                f"Uninstalling the MSI left {program}: {[str(p) for p in program.rglob('*')][:20]}"
            assert not agent_data.exists(), f"Uninstalling the MSI left {agent_data}"
            assert not shortcut.exists(), f"Uninstalling the MSI left {shortcut}"

        def pipe(request_line):
            with open(r"\\.\pipe\ComplianceAgent.Notifications.v1", "r+b", buffering=0) as p:
                p.write(request_line.encode() + b"\n")
                return p.readline().decode()

        # A client the install scripts put there: the MSI takes the service over and keeps the enrollment.
        known = {d["id"] for d in request("/api/devices")}
        (package / "登记配置.json").write_text(json.dumps({"serverUrl": base, "code": code}), encoding="utf-8")
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(package / "deploy/windows/Install-TrialService.ps1"), "-PackageRoot", str(package)],
            input="", stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, text=True, errors="replace", timeout=300,
        )
        installed = True
        assert result.returncode == 0, "Script install before the MSI failed"
        scripted = wait_device(known=known)
        msiexec("/i", "msi-takeover.log")
        installed = False
        taken = wait_device(scripted["id"], since=scripted["lastHeartbeat"])
        config = subprocess.run(["sc.exe", "qc", "ComplianceAgent"], capture_output=True, text=True, errors="replace").stdout
        assert "--config" in config and str(program).lower() in config.lower(), f"Service not the MSI's: {config}"
        failure = subprocess.run(["sc.exe", "qfailure", "ComplianceAgent"], capture_output=True, text=True, errors="replace").stdout
        assert failure.count("RESTART") >= 3, f"Service restarts on failure not configured: {failure}"
        notification_identity()
        print(f"PASS the MSI takes over a script install and keeps its enrollment ({taken['hostName']}); its shortcut names the tray's notifications")
        # Browser rules the client added go with it; someone else's stay. Planted with the service stopped, so
        # only the uninstall can remove them.
        subprocess.run(["sc.exe", "stop", "ComplianceAgent"], capture_output=True)
        deadline = time.monotonic() + 60
        while "STOPPED" not in subprocess.run(["sc.exe", "query", "ComplianceAgent"], capture_output=True, text=True).stdout:
            assert time.monotonic() < deadline, "The service did not stop"
            time.sleep(1)
        wait_alert("tamper:service-stopped", taken["id"])
        print("PASS stopping the service by hand is reported as tampering before it stops")
        edge = r"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist"
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, edge, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "1", 0, winreg.REG_SZ, "external.example.com")
            winreg.SetValueEx(key, "2", 0, winreg.REG_SZ, "owned.example.com")
        (agent_data / "browser-blocklist.json").write_text(json.dumps({"Edge": ["owned.example.com"]}), encoding="utf-8")
        msiexec("/x", "msi-uninstall.log")
        removed()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, edge) as key:
            left = [winreg.QueryValueEx(key, str(i))[0] for i in range(1, winreg.QueryInfoKey(key)[1] + 1)]
        assert left == ["external.example.com"], f"Uninstalling left these Edge rules: {left}"
        winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, edge)
        print("PASS uninstalling the MSI removes the service, the program folder, the data directory and its browser rules")

        # A data directory a standard user created is removed; a silent install enrolls with SERVERURL and CODE.
        agent_data.mkdir()
        (agent_data / "agent.json").write_text(json.dumps({"serverUrl": "http://10.0.0.1:1", "dataDirectory": str(agent_data), "deviceId": "planted"}), encoding="utf-8")
        subprocess.run(["icacls", str(agent_data), "/setowner", "*S-1-5-32-545", "/T"], check=True, capture_output=True)
        known = {d["id"] for d in request("/api/devices")}
        text = msiexec("/i", "msi-silent.log", f"SERVERURL={base}", f"CODE={code}")
        assert code not in text, "The MSI log holds the enrollment code"
        silent = wait_device(known=known)
        assert json.loads((agent_data / "agent.json").read_text(encoding="utf-8"))["serverUrl"] == base
        print("PASS a silent MSI install removes a foreign data directory and enrolls with SERVERURL and CODE")

        # Set to start by hand and its tray taken off sign-in: both come back, and the administrator hears of it.
        subprocess.run(["sc.exe", "config", "ComplianceAgent", "start=", "demand"], check=True, capture_output=True)
        run_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, run_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "ComplianceTray")
        wait_alert("tamper:service-start", silent["id"], "已恢复为自动启动")
        wait_alert("tamper:tray-autostart", silent["id"], "已恢复")
        config = subprocess.run(["sc.exe", "qc", "ComplianceAgent"], capture_output=True, text=True, errors="replace").stdout
        assert "AUTO_START" in config, f"The start type was not restored: {config}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, run_key) as key:
            assert "Compliance.Tray.exe" in winreg.QueryValueEx(key, "ComplianceTray")[0]
        print("PASS a service set to manual start and a removed tray Run value are restored and reported")

        # The policy sets an uninstall password: removing without it fails and is reported; with it, it goes.
        msiexec("/x", "msi-uninstall-refused.log", succeeds=False)
        assert "RUNNING" in subprocess.run(["sc.exe", "query", "ComplianceAgent"], capture_output=True, text=True).stdout, \
            "A refused removal left the service stopped"
        wait_alert("tamper:uninstall-refused", silent["id"], "未提供卸载密码")
        msiexec("/x", "msi-uninstall-wrong.log", "UNINSTALLPASSWORD=wrong-password", succeeds=False)
        assert program.exists() and agent_data.exists(), "A refused removal removed files"
        print("PASS removing the client without the uninstall password fails, keeps it running and is reported")
        msiexec("/x", "msi-uninstall-2.log")
        removed()
        wait_alert("tamper:uninstall", silent["id"], "卸载密码验证通过")
        print("PASS removing it with the password works and tells the server")

        # Installed without an enrollment, the service waits and tells the tray; enrolling as the window does
        # (elevated) starts it reporting without a restart.
        msiexec("/i", "msi-waiting.log")
        deadline = time.monotonic() + 60
        while True:
            try:
                reply = pipe('{"action":"list"}')
                break
            except OSError:
                assert time.monotonic() < deadline, "The waiting service does not answer the tray"
                time.sleep(1)
        assert "not-enrolled" in reply, f"Waiting service replied {reply}"
        setup_dir = data / "setup"
        setup_dir.mkdir()
        (setup_dir / "登记配置.json").write_text(json.dumps({"serverUrl": base, "code": code}), encoding="utf-8")
        # The service starts a tray once the installer is done; end it so the window below is the only one.
        wait_service_tray()
        stop_trays()
        viewer = subprocess.Popen([str(program / "Compliance.Tray.exe"), "--setup", str(setup_dir / "client.msi")])
        try:
            time.sleep(8)
            assert viewer.poll() is None, f"Tray --setup exited with {viewer.returncode}"
            screenshot(data / "tray-setup.png")
        finally:
            viewer.kill()
            viewer.wait(timeout=10)
        known = {d["id"] for d in request("/api/devices")}
        outcome = data / "enroll-result.txt"
        result = subprocess.run(
            [str(program / "Compliance.Agent.exe"), "--config", str(agent_data / "agent.json"), "--server", base,
             "--enroll", "--code", code, "--result", str(outcome)],
            capture_output=True, text=True, errors="replace", timeout=120,
        )
        assert result.returncode == 0, f"Enrollment failed: {outcome.read_text(encoding='utf-8') if outcome.exists() else result.stdout}"
        assert "登记成功" in outcome.read_text(encoding="utf-8")
        wait_device(known=known)
        print("PASS an MSI installed without enrollment waits, tells the tray, and reports once enrolled")
        msiexec("/x", "msi-uninstall-3.log")
        removed()

    print("Evidence: " + str(data))
finally:
    if msi_installed:
        subprocess.run(["msiexec", "/x", str(args.msi.resolve()), "/qn", f"UNINSTALLPASSWORD={uninstall_password}"],
                       timeout=300)
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
