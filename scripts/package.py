#!/usr/bin/env python3
"""Package already-published self-contained binaries without local runtime state."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parents[1] / "outputs"
PUBLISHED = ROOT / "artifacts" / "package"
VERSION = "0.1.0"


def add_tree(source: Path, target: Path) -> None:
    if not source.is_dir():
        raise FileNotFoundError(f"Publish first: {source}")
    for file in source.rglob("*"):
        if file.is_file():
            destination = target / file.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and destination.read_bytes() != file.read_bytes():
                raise ValueError(f"Published file collision: {destination}")
            shutil.copy2(file, destination)


def add_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def make_zip(folder: Path, destination: Path) -> None:
    files = sorted(path for path in folder.rglob("*") if path.is_file())
    checksums = []
    for path in files:
        relative = path.relative_to(folder).as_posix()
        checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    (folder / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    files.append(folder / "SHA256SUMS.txt")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".zip.tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=7) as archive:
        for path in files:
            relative = path.relative_to(folder).as_posix()
            info = zipfile.ZipInfo(relative, (2026, 10, 14, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=7)
    os.replace(temporary, destination)
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError(f"Package CRC validation failed: {destination}")
    print(f"{destination}  sha256={hashlib.sha256(destination.read_bytes()).hexdigest()}")


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="compliance-release-", dir=PUBLISHED) as temporary:
        stage = Path(temporary) / "windows"
        add_tree(PUBLISHED / "server-windows-x64", stage / "server-windows-x64")
        add_tree(PUBLISHED / "agent-windows-x64", stage / "agent-windows-x64")
        add_tree(PUBLISHED / "tray-windows-x64", stage / "agent-windows-x64")
        for name in ("install.ps1", "uninstall.ps1", "README.md"):
            add_file(ROOT / "deploy" / "windows" / name, stage / "deploy" / "windows" / name)
        for name in ("Start-Demo.ps1", "README.md"):
            add_file(ROOT / "deploy" / "server" / name, stage / "deploy" / "server" / name)
        for name in ("README.md", "docs/capabilities.md", "docs/server-api.md"):
            add_file(ROOT / name, stage / name)
        add_file(OUTPUT / "客户终端合规管控-0.1.0-试用说明.md", stage / "试用说明.md")
        make_zip(stage, OUTPUT / f"客户终端合规管控-{VERSION}-Windows试用包.zip")

        stage = Path(temporary) / "linux"
        add_tree(PUBLISHED / "server-linux-x64", stage / "server-linux-x64")
        for name in ("README.md", "docs/capabilities.md", "docs/server-api.md", "deploy/server/README.md", "deploy/server/compliance.service.example"):
            add_file(ROOT / name, stage / name)
        make_zip(stage, OUTPUT / f"客户终端合规管控-{VERSION}-Linux服务端.zip")


if __name__ == "__main__":
    main()
