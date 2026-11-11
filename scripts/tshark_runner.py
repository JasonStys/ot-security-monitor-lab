"""Jason Stys: verify and administratively extract a pinned official offline dissector on a disposable Windows runner only."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 49
# variable: URL — line 50
# variable: SIZE — line 51
# variable: SHA256 — line 52
# definition: verified_copy — line 55
# parameter: digest — line 55
# parameter: size — line 55
# parameter: source — line 55
# parameter: target — line 55
# variable: actual — line 57
# variable: length — line 58
# variable: output — line 59
# variable: data — line 60
# variable: length — line 61
# definition: runner_root — line 70
# variable: target — line 79
# variable: entry — line 82
# definition: main — line 88
# variable: temporary — line 90
# variable: stage — line 91
# variable: package — line 92
# variable: response — line 93
# variable: destination — line 110
# variable: candidates — line 124
# variable: executable — line 127
# variable: entry — line 128
# variable: observed — line 131
# variable: path_file — line 140
# variable: info — line 141
# variable: parent — line 144
# variable: stream — line 147
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import BinaryIO

ROOT = Path(__file__).resolve().parents[1]
URL = "https://www.wireshark.org/download/win64/Wireshark-4.6.9-x64.msi"
SIZE = 80_433_152
SHA256 = "1975dfc96581a9b674fda3f41ac1585963b4ba52ea9459f3b6d9cedfac3a7217"


def verified_copy(source: BinaryIO, target: Path, size: int, digest: str) -> None:
    """Create one new bounded file and require exact bytes/digest before any package execution."""
    actual = hashlib.sha256()
    length = 0
    with target.open("xb") as output:
        while data := source.read(1024 * 1024):
            length += len(data)
            if length > size:
                raise ValueError("Official package exceeds the reviewed byte count")
            actual.update(data)
            output.write(data)
    if length != size or actual.hexdigest() != digest:
        raise ValueError("Official package size/digest differs; not executable")


def runner_root() -> Path:
    """Refuse ordinary PCs; only admit the actual disposable Windows AMD64 Actions worker."""
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "Windows"
        or platform.system() != "Windows"
        or platform.machine().upper() not in {"AMD64", "X86_64"}
    ):
        raise ValueError("This dependency setup is hosted-Windows-only")
    target = Path(os.environ["RUNNER_TEMP"])
    if not target.is_absolute() or not target.is_dir():
        raise ValueError("Missing absolute runner temporary directory")
    for entry in (target, *target.parents):
        if entry.is_symlink() or entry.is_junction():
            raise ValueError("Linked runner temporary path refused")
    return target.resolve()


def main() -> None:
    """Verify provider identity, extract only; run no capture/driver installer, then expose the reviewed CLI to the next step."""
    temporary = runner_root()
    stage = Path(tempfile.mkdtemp(prefix="ot-tshark-", dir=temporary))
    package = stage / "Wireshark-4.6.9-x64.msi"
    with urllib.request.urlopen(URL, timeout=60) as response:
        if response.url != URL or response.status != 200:
            raise ValueError("Unexpected package provider redirect/status")
        verified_copy(response, package, SIZE, SHA256)
    subprocess.run(
        [
            "pwsh.exe",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(ROOT / "scripts/check_tshark_signature.ps1"),
            "-Package",
            str(package),
        ],
        check=True,
        timeout=60,
    )
    destination = stage / "administrative-image"
    subprocess.run(
        [
            "msiexec.exe",
            "/a",
            str(package),
            "/qn",
            "TARGETDIR=" + str(destination),
            "/l*v",
            str(stage / "administrative-extraction.log"),
        ],
        check=True,
        timeout=120,
    )
    candidates = list(destination.rglob("tshark.exe"))
    if len(candidates) != 1:
        raise ValueError("Administrative image must contain one TShark")
    executable = candidates[0]
    for entry in (executable, *executable.parents):
        if entry.is_symlink() or entry.is_junction():
            raise ValueError("Linked extracted dependency refused")
    observed = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.splitlines()[0]
    if not observed.startswith("TShark (Wireshark) 4.6.9"):
        raise ValueError("Extracted dissector version differs")
    path_file = Path(os.environ["GITHUB_PATH"])
    info = path_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Runner path command file must be ordinary")
    parent = str(executable.parent)
    if "\r" in parent or "\n" in parent:
        raise ValueError("Unexpected command-file separator")
    with path_file.open("a", encoding="utf-8") as stream:
        stream.write(parent + "\n")
    print(
        json.dumps(
            {
                "version": observed,
                "packageSha256": SHA256,
                "bytes": SIZE,
                "mode": "administrative extraction; offline dissection only",
            }
        )
    )


if __name__ == "__main__":
    main()
