"""Jason Stys: actual Office ZIP fixtures retain text scanning and reject unknown content.

Functions, parameters and variables: docs/CODE_INDEX.md or docs/SOURCE_MAP.md.
These tests verify documentation input handling, not application-runtime behavior.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: edition — line 42
# parameter: main — line 43
# parameter: name — line 43
# parameter: root — line 43
# parameter: text — line 43
# variable: path — line 46
# variable: package — line 48
# definition: test_named_office_xml_remains_visible — line 65
# parameter: main — line 65
# parameter: name — line 65
# parameter: tmp_path — line 65
# variable: text — line 67
# definition: test_unknown_binary_is_not_an_exclusion — line 71
# parameter: tmp_path — line 71
# variable: path — line 73
# definition: test_missing_document_root_is_rejected — line 78
# parameter: tmp_path — line 78
# definition: test_invalid_zip_is_rejected — line 86
# parameter: tmp_path — line 86
# variable: path — line 88
# definition: test_invalid_utf8_xml_is_rejected — line 95
# parameter: tmp_path — line 95
# definition: test_expansion_budget_is_active — line 104
# parameter: tmp_path — line 104
# variable: path — line 106
# END CODE MAP

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from scripts.publication_text import MAX_MEMBER_BYTES, public_text


def edition(
    root: Path, name: str, main: str, text: bytes = b"<document>public</document>"
) -> Path:
    """Create an isolated actual ZIP containing declared XML and a relationship."""
    path = root / "docs" / "reports" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", b"<Types/>")
        package.writestr(main, text)
        package.writestr(
            "_rels/.rels", b"<Relationship>review-secret-marker</Relationship>"
        )
    return path


@pytest.mark.parametrize(
    "name,main",
    [
        ("project-guide.docx", "word/document.xml"),
        ("validation-review.docx", "word/document.xml"),
        ("validation-evidence.xlsx", "xl/workbook.xml"),
    ],
)
def test_named_office_xml_remains_visible(tmp_path: Path, name: str, main: str) -> None:
    """Every allowed edition exposes main text and relationships to existing scans."""
    text = public_text(edition(tmp_path, name, main), tmp_path)
    assert "public" in text and "review-secret-marker" in text


def test_unknown_binary_is_not_an_exclusion(tmp_path: Path) -> None:
    """A different Office filename still receives strict ordinary UTF-8 handling."""
    path = edition(tmp_path, "unknown.docx", "word/document.xml")
    with pytest.raises(UnicodeDecodeError):
        public_text(path, tmp_path)


def test_missing_document_root_is_rejected(tmp_path: Path) -> None:
    """A workbook renamed as Word cannot pass the declared edition contract."""
    with pytest.raises(ValueError, match="root is missing"):
        public_text(
            edition(tmp_path, "project-guide.docx", "xl/workbook.xml"), tmp_path
        )


def test_invalid_zip_is_rejected(tmp_path: Path) -> None:
    """The exact allowed filename does not make arbitrary bytes acceptable."""
    path = tmp_path / "docs/reports/project-guide.docx"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not an Office ZIP")
    with pytest.raises(ValueError, match="Invalid reviewed"):
        public_text(path, tmp_path)


def test_invalid_utf8_xml_is_rejected(tmp_path: Path) -> None:
    """Text decoding errors cannot be hidden by replacement characters."""
    with pytest.raises(UnicodeDecodeError):
        public_text(
            edition(tmp_path, "project-guide.docx", "word/document.xml", b"\xff"),
            tmp_path,
        )


def test_expansion_budget_is_active(tmp_path: Path) -> None:
    """A genuinely compressed oversized XML member is refused before expansion."""
    path = edition(
        tmp_path,
        "project-guide.docx",
        "word/document.xml",
        b"x" * (MAX_MEMBER_BYTES + 1),
    )
    with pytest.raises(ValueError, match="Unsupported reviewed"):
        public_text(path, tmp_path)
