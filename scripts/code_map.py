"""Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 50
# definition: mapped — line 53
# parameter: source — line 53
# parameter: suffix — line 53
# variable: prefix — line 55
# variable: begin — line 56
# variable: end — line 56
# variable: source — line 57
# variable: lines — line 63
# variable: records — line 64
# variable: insertion — line 65
# variable: tree — line 67
# variable: insertion — line 70
# variable: node — line 71
# variable: insertion — line 84
# variable: line — line 85
# variable: number — line 85
# variable: name — line 88
# variable: name — line 90
# variable: name — line 92
# variable: item — line 94
# variable: name — line 96
# variable: name — line 100
# variable: name — line 102
# variable: count — line 104
# variable: header — line 105
# variable: kind — line 109
# variable: name — line 109
# variable: number — line 109
# parameter: item — line 110
# definition: main — line 119
# variable: parser — line 121
# variable: args — line 123
# variable: paths — line 124
# variable: stale — line 133
# variable: path — line 134
# variable: source — line 135
# variable: expected — line 136
# END CODE MAP

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mapped(source: str, suffix: str) -> str:
    """Insert physical line maps without executing source; SQL/YAML indexes are lexical, Python is AST-based."""
    prefix = "--" if suffix == ".sql" else "#"
    begin, end = prefix + " BEGIN CODE MAP", prefix + " END CODE MAP"
    source = re.sub(
        r"^" + re.escape(begin) + r"[^\n]*\n.*?^" + re.escape(end) + r"\n",
        "",
        source,
        flags=re.M | re.S,
    )
    lines = source.splitlines(keepends=True)
    records: set[tuple[str, str, int]] = set()
    insertion = 1 if source.startswith("#!") else 0
    if suffix == ".py":
        tree = ast.parse(source)
        if not ast.get_docstring(tree):
            raise ValueError("missing file purpose header")
        insertion = tree.body[0].end_lineno or 0
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not ast.get_docstring(node):
                    raise ValueError("missing function/class description: " + node.name)
                records.add(("definition", node.name, node.lineno))
            elif isinstance(node, ast.arg):
                records.add(("parameter", node.arg, node.lineno))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                records.add(("variable", node.id, node.lineno))
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
                records.add(("attribute", node.attr, node.lineno))
    else:
        while insertion < len(lines) and lines[insertion].startswith(prefix):
            insertion += 1
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith(prefix):
                continue
            for name in re.findall(r"^([a-z_][a-z0-9_]*)\(\)\s*\{", line):
                records.add(("shell function", name, number))
            for name in re.findall(r"\b([a-z_][a-z0-9_]*)=", line):
                records.add(("shell variable", name, number))
            for name in re.findall(r"\bfor\s+(\w+)\s+in|\bread\s+-r\s+(\w+)", line):
                records.add(
                    ("shell loop/input", next(item for item in name if item), number)
                )
            for name in re.findall(
                r"CREATE (?:TABLE|TRIGGER|INDEX) (?:IF NOT EXISTS )?(\w+)", line
            ):
                records.add(("SQL object", name, number))
            for name in re.findall(r"\b(\w+) (?:INTEGER|TEXT|BLOB)\b", line):
                records.add(("column", name, number))
            for name in re.findall(r"^\s*(?:- )?([\w-]+):", line):
                records.add(("parameter", name, number))
    count = len(records) + 2
    header = [
        begin + " (generated; python scripts/code_map.py)",
        *[
            f"{prefix} {kind}: {name} — line {number + count if number > insertion else number}"
            for kind, name, number in sorted(
                records, key=lambda item: (item[2], item[0], item[1])
            )
        ],
        end,
    ]
    lines.insert(insertion, "\n".join(header) + "\n")
    return "".join(lines)


def main() -> int:
    """Generate or check every authored Python, SQL and workflow header; drift or missing descriptions fail CI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    paths = [
        *(ROOT / "otmon").glob("*.py"),
        *(ROOT / "scripts").glob("*.py"),
        *(ROOT / "tests").glob("*.py"),
        *(ROOT / "examples").glob("*.py"),
        *(ROOT / "scripts").glob("*.sh"),
        *(ROOT / "sql").glob("*.sql"),
        *(ROOT / ".github/workflows").glob("*.yml"),
    ]
    stale = []
    for path in paths:
        source = path.read_text(encoding="utf-8")
        expected = mapped(source, path.suffix)
        if source != expected:
            stale.append(str(path.relative_to(ROOT)))
            if not args.check:
                path.write_text(expected, encoding="utf-8", newline="\n")
    print("Code maps current" if not stale else "Code maps: " + ", ".join(stale))
    return int(args.check and bool(stale))


if __name__ == "__main__":
    raise SystemExit(main())
