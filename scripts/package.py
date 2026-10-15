#!/usr/bin/env python3
"""Build the Windows packages: a client package for production installs and, with --trial, the full trial package.

Releases pass --version; without it the build is the next release number with a -dev suffix.
Writes artifacts/compliance-client-<version>-windows.zip (and compliance-trial-<version>-windows.zip).
"""
from __future__ import annotations

import argparse
import filecmp
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
DOTNET = os.environ.get("DOTNET", shutil.which("dotnet") or str(Path.home() / ".dotnet" / "dotnet"))


def next_version() -> str:
    """VERSION plus one more than the highest released patch number: 0.2.0, 0.2.1, ..."""
    base = (ROOT / "VERSION").read_text().strip()
    tags = subprocess.check_output(["git", "tag", "--list", f"v{base}.*"], cwd=ROOT, text=True).split()
    patches = [int(t.rsplit(".", 1)[1]) for t in tags if t.rsplit(".", 1)[1].isdigit()]
    return f"{base}.{max(patches, default=-1) + 1}"


def publish(project: str, output: Path, ver: str, single_file: bool) -> None:
    args = [DOTNET, "publish", f"src/{project}", "-c", "Release", "-r", "win-x64", "--self-contained"]
    args += [f"-p:Version={ver}", "-p:EnableWindowsTargeting=true", "-o", str(output), "--nologo", "-v", "q"]
    # Only Chinese resources for the runtime's own messages; other languages fall back to English.
    args += ["-p:SatelliteResourceLanguages=zh-Hans"]
    if single_file:
        args.append("-p:PublishSingleFile=true")
    subprocess.run(args, cwd=ROOT, check=True)


def file_versions(folder: Path) -> dict[str, tuple]:
    """(assembly version, file version) of each published file, from the apps' deps.json files."""
    def key(v: str | None) -> tuple:
        return tuple(int(x) for x in (v or "0").split("."))

    versions: dict[str, tuple] = {}
    for deps in folder.glob("*.deps.json"):
        for library in json.loads(deps.read_text(encoding="utf-8"))["targets"].values():
            for entry in library.values():
                for group in ("runtime", "native"):
                    for path, info in entry.get(group, {}).items():
                        versions[Path(path).name] = (key(info.get("assemblyVersion")), key(info.get("fileVersion")))
    return versions


def merge(source: Path, target: Path) -> None:
    """Adds an app's files to another self-contained app's folder so both share one .NET runtime. Where the two
    ship different builds of a library (a NuGet package against the runtime's copy, or a facade against the full
    Windows Desktop assembly), the higher version stays; both apps bind to it."""
    ours, theirs = file_versions(target), file_versions(source)
    for file in source.rglob("*"):
        if not file.is_file():
            continue
        destination = target / file.relative_to(source)
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, destination)
        elif not filecmp.cmp(file, destination, shallow=False):
            if file.name not in ours or file.name not in theirs:
                raise ValueError(f"Conflicting file without version information: {destination}")
            if theirs[file.name] > ours[file.name]:
                shutil.copy2(file, destination)


def publish_client(output: Path, ver: str) -> None:
    """The service and the tray in one folder with one copy of the runtime."""
    shutil.rmtree(output, ignore_errors=True)
    publish("Compliance.Tray", output, ver, False)
    publish("Compliance.Agent", output.with_name(output.name + "-agent"), ver, False)
    merge(output.with_name(output.name + "-agent"), output)
    shutil.rmtree(output.with_name(output.name + "-agent"))


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
    shutil.copytree(published / "client", stage / "agent-windows-x64")
    windows = ROOT / "deploy" / "windows"
    for script in windows.glob("*.ps1"):
        copy(script, stage / "deploy" / "windows" / script.name)
    copy(windows / "README.md", stage / "deploy" / "windows" / "README.md")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="release version; defaults to the next one with a -dev suffix")
    parser.add_argument("--trial", action="store_true", help="also build the full trial package with the Windows server")
    parser.add_argument("--stage", type=Path, help="only stage the client package (no zip) into this folder")
    args = parser.parse_args()
    ver = args.version or next_version() + "-dev"
    published = ARTIFACTS / "publish"
    shutil.rmtree(published, ignore_errors=True)
    publish_client(published / "client", ver)
    if args.stage:
        shutil.rmtree(args.stage, ignore_errors=True)
        stage_client(args.stage, published)
        return

    stage = ARTIFACTS / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage_client(stage, published)
    for name in ("安装客户端（正式环境）.bat", "卸载常驻客户端.bat"):
        copy(ROOT / "deploy" / "windows" / name, stage / name)
    copy(ROOT / "deploy" / "windows" / "客户端安装说明.md", stage / "安装说明.md")
    make_zip(stage, ARTIFACTS / f"compliance-client-{ver}-windows.zip")

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
        make_zip(stage, ARTIFACTS / f"compliance-trial-{ver}-windows.zip")

    shutil.rmtree(stage)


if __name__ == "__main__":
    main()
