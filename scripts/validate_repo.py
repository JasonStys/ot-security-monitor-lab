"""Jason Stys: tracked-file privacy, passive-runtime imports and zero-artifact/cache workflow guards."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 31
# definition: main — line 34
# variable: names — line 36
# variable: name — line 42
# variable: part — line 45
# variable: path — line 52
# variable: text — line 55
# variable: imports — line 64
# variable: node — line 65
# variable: alias — line 67
# variable: path — line 83
# variable: text — line 84
# variable: action — line 91
# variable: codeql — line 94
# variable: flag — line 95
# END CODE MAP

import ast
import json
import re
import subprocess
from pathlib import Path

if __package__:
    from .publication_text import public_text
else:
    from publication_text import public_text

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Inspect reviewed source only; imported offline runtime must not gain active network/process capabilities."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    for name in names:
        if any(
            part in {"out", ".venv", ".tools", "__pycache__"}
            for part in name.split("/")
        ) or name.lower().endswith(
            (".pcap", ".pcapng", ".sqlite", ".db", ".key", ".pem", ".env")
        ):
            raise ValueError(
                "private capture/database/credential or generated file is tracked"
            )
        path = ROOT / name
        if path.is_symlink() or path.is_junction():
            raise ValueError("tracked links are forbidden")
        text = public_text(path, ROOT)
        if re.search(
            r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            text,
        ):
            raise ValueError("possible credential in tracked source")
        if name.endswith(".json"):
            json.loads(text)
        if name.startswith("otmon/") and name.endswith(".py"):
            imports = []
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imports.append((node.module or "").split(".")[0])
            if set(imports) & {
                "socket",
                "subprocess",
                "urllib",
                "http",
                "requests",
                "ftplib",
                "telnetlib",
                "paramiko",
            }:
                raise ValueError(
                    "passive offline runtime cannot import active network/process modules"
                )
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if (
            "upload-artifact@" in text
            or "actions/cache@" in text
            or re.search(r"^\s+cache:", text, re.M)
        ):
            raise ValueError("Actions artifact/cache use is disabled")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action):
                raise ValueError("remote action must be pinned to a reviewed commit")
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    for flag in ("trap-caching", "dependency-caching", "upload-database"):
        if flag + ": false" not in codeql:
            raise ValueError("CodeQL cache/database opt-out missing")
    print(
        f"Privacy, passive import and workflow storage guards passed: {len(names)} tracked files"
    )


if __name__ == "__main__":
    main()
