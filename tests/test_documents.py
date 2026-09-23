"""M4: reading the ST and the test plan -- pages, sections, tables, and quote checks."""
from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

import pytest

from code_analyzer.errors import UserError
from code_analyzer.sesip.documents import (
    Page,
    extract,
    extract_docx,
    locate,
    quote_found,
)

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def make_pdf(path: Path, pages: list[list[str]]) -> Path:
    """A minimal text PDF: one Helvetica text object per page."""
    objects: list[bytes] = []
    kids = []
    for index, lines in enumerate(pages):
        stream = "BT /F1 11 Tf 72 720 Td 14 TL " + " ".join(
            f"({line.replace('(', '[').replace(')', ']')}) Tj T*" for line in lines) + " ET"
        content_id = 4 + index * 2
        page_id = content_id + 1
        objects.append(f"{content_id} 0 obj << /Length {len(stream)} >> stream\n{stream}\nendstream endobj".encode())
        objects.append(f"{page_id} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       f"/Contents {content_id} 0 R /Resources << /Font << /F1 3 0 R >> >> >> endobj".encode())
        kids.append(f"{page_id} 0 R")
    head = [b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
            f"2 0 obj << /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >> endobj".encode(),
            b"3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj"]
    body = b"%PDF-1.4\n"
    offsets = []
    for obj in head + objects:
        offsets.append(len(body))
        body += obj + b"\n"
    xref = len(body)
    body += f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f \n".encode()
    body += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    body += f"trailer << /Size {len(offsets) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    path.write_bytes(body)
    return path


def make_docx(path: Path, blocks: list[tuple[str, str | list[list[str]]]]) -> Path:
    """blocks: ("h", text) heading, ("p", text) paragraph, ("t", rows) table."""
    parts = []
    for kind, value in blocks:
        if kind == "t":
            rows = "".join("<w:tr>" + "".join(f"<w:tc><w:p><w:r><w:t>{c}</w:t></w:r></w:p></w:tc>" for c in row)
                           + "</w:tr>" for row in value)
            parts.append(f"<w:tbl>{rows}</w:tbl>")
        else:
            style = '<w:pPr><w:pStyle w:val="Heading1"/></w:pPr>' if kind == "h" else ""
            parts.append(f"<w:p>{style}<w:r><w:t>{value}</w:t></w:r></w:p>")
    xml = f'<?xml version="1.0"?><w:document xmlns:w="{W_NS}"><w:body>{"".join(parts)}</w:body></w:document>'
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", xml)
        archive.writestr("[Content_Types].xml", "<Types/>")
    return path


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="needs poppler's pdftotext")
def test_pdf_pages_keep_their_numbers(tmp_path: Path) -> None:
    pdf = make_pdf(tmp_path / "tp.pdf", [
        ["NXP i.MX RT700 SESIP Level 3 - AVA Test Plan", "1 Introduction and scope of the evaluation"],
        ["7.4.1 Security Levels", "Error: Requires immediate review because the issue may cause serious runtime failures."],
    ])
    pages = extract(pdf)
    assert [p.n for p in pages] == [1, 2] and pages[1].loc == "p2"
    assert quote_found(pages, "Error:  Requires immediate   review", page=2)
    assert not quote_found(pages, "Requires immediate review", page=1)
    assert locate(pages, "7.4.1 Security Levels").n == 2


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="needs poppler's pdftotext")
def test_a_pdf_without_a_text_layer_is_refused(tmp_path: Path) -> None:
    with pytest.raises(UserError, match="text layer"):
        extract(make_pdf(tmp_path / "scan.pdf", [[""], [""]]))


def test_docx_sections_and_tables(tmp_path: Path) -> None:
    docx = make_docx(tmp_path / "st.docx", [
        ("p", "Security Target for the RT700 platform"),
        ("h", "5 Security Functional Requirements"),
        ("p", "The TOE claims the following SFRs."),
        ("t", [["SFR", "Description"], ["Secure Update of Platform", "Updates are authenticated and anti-rollback."]]),
        ("h", "6 TOE Summary Specification"),
        ("p", "Secure boot verifies the image before execution."),
    ])
    pages = extract_docx(docx)
    assert [p.loc for p in pages] == ["§start", "§5 Security Functional Requirements", "§6 TOE Summary Specification"]
    assert "Secure Update of Platform | Updates are authenticated" in pages[1].text
    assert quote_found(pages, "Updates are authenticated and anti-rollback", page=2)


def test_short_quotes_do_not_count_as_evidence() -> None:
    pages = [Page(1, "p1", "the TOE shall do X")]
    assert not quote_found(pages, "TOE")


def test_unsupported_formats_are_refused(tmp_path: Path) -> None:
    (tmp_path / "st.txt").write_text("x")
    with pytest.raises(UserError):
        extract(tmp_path / "st.txt")
    (tmp_path / "bad.docx").write_bytes(b"PK\x03\x04 not really")
    with pytest.raises(UserError):
        extract(tmp_path / "bad.docx")
