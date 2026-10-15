#!/usr/bin/env python3
"""Build the Windows packages: a client package for production installs and, with --trial, the full trial package.

The version is VERSION plus the number of commits, e.g. 0.1.152, so every build of a commit gets the same number.
Writes artifacts/终端合规-<version>-Windows客户端.zip (and -Windows试用包.zip) and prints the version.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
DOTNET = os.environ.get("DOTNET", shutil.which("dotnet") or str(Path.home() / ".dotnet" / "dotnet"))


def version() -> str:
    count = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=ROOT, text=True).strip()
    return f"{(ROOT / 'VERSION').read_text().strip()}.{count}"


def publish(project: str, output: Path, ver: str, single_file: bool) -> None:
    args = [DOTNET, "publish", f"src/{project}", "-c", "Release", "-r", "win-x64", "--self-contained"]
    args += [f"-p:Version={ver}", "-p:EnableWindowsTargeting=true", "-o", str(output), "--nologo", "-v", "q"]
    if single_file:
        args.append("-p:PublishSingleFile=true")
    subprocess.run(args, cwd=ROOT, check=True)


def copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix == ".bat":
        # cmd.exe needs CRLF line endings.
        target.write_bytes(source.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    else:
        shutil.copy2(source, target)


def make_zip(folder: Path, destination: Path) -> None:
    destination.unlink(missing_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(folder).as_posix())
    print(f"{destination.relative_to(ROOT)}  {destination.stat().st_size / 1048576:.0f} MB")


def stage_client(stage: Path, published: Path) -> None:
    shutil.copytree(published / "agent", stage / "agent-windows-x64")
    shutil.copytree(published / "tray", stage / "agent-windows-x64", dirs_exist_ok=True)
    windows = ROOT / "deploy" / "windows"
    for script in windows.glob("*.ps1"):
        copy(script, stage / "deploy" / "windows" / script.name)
    copy(windows / "README.md", stage / "deploy" / "windows" / "README.md")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trial", action="store_true", help="also build the full trial package with the Windows server")
    args = parser.parse_args()
    ver = version()
    published = ARTIFACTS / "publish"
    shutil.rmtree(published, ignore_errors=True)
    publish("Compliance.Agent", published / "agent", ver, True)
    publish("Compliance.Tray", published / "tray", ver, True)

    stage = ARTIFACTS / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage_client(stage, published)
    for name in ("安装客户端（正式环境）.bat", "卸载常驻客户端.bat"):
        copy(ROOT / "deploy" / "windows" / name, stage / name)
    copy(ROOT / "deploy" / "windows" / "客户端安装说明.md", stage / "安装说明.md")
    make_zip(stage, ARTIFACTS / f"终端合规-{ver}-Windows客户端.zip")

    if args.trial:
        subprocess.run(["npm", "run", "build"], cwd=ROOT / "ui", check=True, stdout=subprocess.DEVNULL)
        publish("Compliance.Server", published / "server", ver, False)
        shutil.rmtree(stage)
        stage_client(stage, published)
        shutil.copytree(published / "server", stage / "server-windows-x64")
        for name in ("README.md", "Start-Demo.ps1"):
            copy(ROOT / "deploy" / "server" / name, stage / "deploy" / "server" / name)
        for bat in (ROOT / "deploy").rglob("*.bat"):
            copy(bat, stage / bat.name)
        for name in ("README.md", "docs/capabilities.md", "docs/server-api.md"):
            copy(ROOT / name, stage / name)
        copy(ROOT / "deploy" / "server" / "试用说明.md", stage / "使用说明.md")
        make_zip(stage, ARTIFACTS / f"终端合规-{ver}-Windows试用包.zip")

    shutil.rmtree(stage)
    print(ver)


if __name__ == "__main__":
    main()
