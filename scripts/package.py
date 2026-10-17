#!/usr/bin/env python3
"""Build the Windows client: the MSI for installs, or a staged folder with the install scripts for tests.

Releases pass --version; without it the build is the next release number with a -dev suffix.
--msi (Windows only) writes artifacts/compliance-client-<version>-windows-x64.msi; --stage copies the client and its
install scripts into a folder.
"""
from __future__ import annotations

import argparse
import filecmp
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
DOTNET = os.environ.get("DOTNET", shutil.which("dotnet") or str(Path.home() / ".dotnet" / "dotnet"))


def next_version() -> str:
    """VERSION plus one more than the highest released patch number: 0.2.0, 0.2.1, ..."""
    base = (ROOT / "VERSION").read_text().strip()
    tags = subprocess.check_output(["git", "tag", "--list", f"v{base}.*"], cwd=ROOT, text=True).split()
    patches = [int(t.rsplit(".", 1)[1]) for t in tags if t.rsplit(".", 1)[1].isdigit()]
    return f"{base}.{max(patches, default=-1) + 1}"


def publish(project: str, output: Path, ver: str) -> None:
    args = [DOTNET, "publish", f"src/{project}", "-c", "Release", "-r", "win-x64", "--self-contained"]
    args += [f"-p:Version={ver}", "-p:EnableWindowsTargeting=true", "-o", str(output), "--nologo", "-v", "q"]
    # Only Chinese resources for the runtime's own messages; other languages fall back to English.
    args += ["-p:SatelliteResourceLanguages=zh-Hans"]
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
    publish("Compliance.Tray", output, ver)
    publish("Compliance.Agent", output.with_name(output.name + "-agent"), ver)
    merge(output.with_name(output.name + "-agent"), output)
    shutil.rmtree(output.with_name(output.name + "-agent"))


def copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def stage_client(stage: Path, published: Path) -> None:
    shutil.copytree(published / "client", stage / "agent-windows-x64")
    windows = ROOT / "deploy" / "windows"
    for script in windows.glob("*.ps1"):
        copy(script, stage / "deploy" / "windows" / script.name)
    copy(windows / "README.md", stage / "deploy" / "windows" / "README.md")


def build_msi(client: Path, ver: str) -> Path:
    """The client as an MSI (deploy/windows/msi). WiX builds on Windows only. MSI versions are numbers only."""
    output = ARTIFACTS / "msi-build"
    shutil.rmtree(output, ignore_errors=True)
    subprocess.run(
        [DOTNET, "build", "deploy/windows/msi/ComplianceClient.wixproj", "-c", "Release", "--nologo", "-v", "q",
         f"-p:ClientDir={client.resolve()}", f"-p:ProductVersion={ver.split('-')[0]}", "-o", str(output)],
        cwd=ROOT, check=True,
    )
    destination = ARTIFACTS / f"compliance-client-{ver}-windows-x64.msi"
    shutil.copy2(output / "compliance-client.msi", destination)
    print(f"{destination.relative_to(ROOT)}  {destination.stat().st_size / 1048576:.0f} MB")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="release version; defaults to the next one with a -dev suffix")
    parser.add_argument("--stage", type=Path, help="stage the client and its install scripts into this folder")
    parser.add_argument("--msi", action="store_true", help="build the client MSI (Windows only)")
    args = parser.parse_args()
    if not (args.stage or args.msi):
        parser.error("choose --msi or --stage")
    ver = args.version or next_version() + "-dev"
    published = ARTIFACTS / "publish"
    shutil.rmtree(published, ignore_errors=True)
    publish_client(published / "client", ver)
    if args.stage:
        shutil.rmtree(args.stage, ignore_errors=True)
        stage_client(args.stage, published)
    if args.msi:
        build_msi(published / "client", ver)


if __name__ == "__main__":
    main()
