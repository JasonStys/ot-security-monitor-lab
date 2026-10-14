"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: BEGIN — line 36
# variable: END — line 36
# variable: SPECIAL — line 37
# definition: purpose — line 52
# parameter: name — line 52
# variable: text — line 56
# variable: lines — line 61
# variable: index — line 62
# variable: line — line 62
# variable: description — line 64
# variable: continuation — line 66
# variable: description — line 72
# definition: main — line 77
# variable: parser — line 79
# variable: args — line 81
# variable: names — line 82
# variable: rows — line 90
# variable: name — line 91
# variable: label — line 92
# variable: path — line 94
# variable: original — line 95
# variable: end — line 96
# variable: start — line 96
# variable: expected — line 97
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    ".gitignore": "Exclude captured traffic, local databases, reports, credentials and tool caches.",
    ".gitattributes": "Consistent LF text checkouts across operating systems.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "requirements-dev.lock": "Universal complete hash-locked test and security-tool graph.",
    "tools.lock.json": "Official Linux scanner versions, URLs and SHA256 digests.",
    "examples/policy.json": "Synthetic water-treatment asset roles, register ranges and scoped maintenance.",
    "docs/reports/ci.json": "Actual immutable accepted-source CI snapshot.",
    "docs/reports/evaluation.json": "Actual independent synthetic scenario detection/capture-integrity outcomes.",
    "docs/reports/native.json": "Actual independent TShark dissection of synthetic segmented Modbus traffic.",
    "docs/reports/example.html": "Generated inert public synthetic analyst report; no real capture data.",
    "docs/reports/benchmark.json": "Measured bounded capture analysis and Python allocation peak.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "Jason Stys:" in line:
            description = line.lstrip("#!/- ")
            if name.endswith((".cpp", ".hpp", ".rs")):
                for continuation in lines[index + 1 :]:
                    if (
                        not continuation.startswith("//")
                        or "BEGIN CODE MAP" in continuation
                    ):
                        break
                    description += " " + continuation.lstrip("/! ")
            return description
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        label = name.replace("_", "\\_")
        rows.append(f"| [{label}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
