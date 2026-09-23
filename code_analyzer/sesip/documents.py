"""Text out of the Security Target and the test plan, with locations an evaluator can check.

PDF goes through ``pdftotext -layout`` (poppler, on the host; never installed by
us) one page at a time -- form feeds separate pages -- so every extracted item
can cite ``{doc, page, quote}``.  A PDF with almost no text layer is a scan and
is refused plainly: OCR would invent quotes nobody could verify.

DOCX is read with the standard library (it is a zip of XML).  Word has no
pages, so a "page" here is a section: the text from one heading to the next,
cited as ``{doc, loc: "§<heading>", quote}``; tables become ``cell | cell``
lines.

``quote_found`` is the check every extracted item must pass before it is shown
as grounded: the quote, whitespace-normalised, must appear verbatim in the
cited page.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from ..errors import UserError

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
MIN_TEXT_PER_PAGE = 40
PDFTOTEXT_TIMEOUT = 120


@dataclass(frozen=True)
class Page:
    n: int
    loc: str
    text: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract(path: Path) -> list[Page]:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return extract_pdf(path)
    if suffix == ".docx":
        return extract_docx(path)
    raise UserError(f"{path.name}: only PDF and DOCX documents can be read")


def extract_pdf(path: Path) -> list[Page]:
    executable = shutil.which("pdftotext")
    if executable is None:
        raise UserError("pdftotext (poppler-utils) is not installed on this host; upload the document as DOCX "
                        "or fill the profile form by hand")
    try:
        completed = subprocess.run([executable, "-layout", "-enc", "UTF-8", str(path), "-"], capture_output=True,
                                   timeout=PDFTOTEXT_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        raise UserError(f"{path.name}: pdftotext did not finish within {PDFTOTEXT_TIMEOUT}s") from None
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()[:200]
        raise UserError(f"{path.name}: pdftotext failed: {detail}")
    raw_pages = completed.stdout.decode("utf-8", "replace").split("\f")
    if raw_pages and not raw_pages[-1].strip():
        raw_pages.pop()
    pages = [Page(i + 1, f"p{i + 1}", text) for i, text in enumerate(raw_pages)]
    if not pages or sum(len(p.text.strip()) for p in pages) < MIN_TEXT_PER_PAGE * len(pages):
        raise UserError(f"{path.name} has (almost) no text layer -- a scanned PDF cannot be quoted reliably; "
                        "upload a text PDF or DOCX, or fill the profile form by hand")
    return pages


def extract_docx(path: Path) -> list[Page]:
    try:
        with zipfile.ZipFile(path) as archive:
            document = archive.read("word/document.xml")
    except (zipfile.BadZipFile, KeyError) as error:
        raise UserError(f"{path.name} is not a readable .docx: {error}") from None
    root = ElementTree.fromstring(document)
    body = root.find(f"{W}body")
    if body is None:
        raise UserError(f"{path.name} has no document body")
    sections: list[tuple[str, list[str]]] = [("start", [])]
    for element in body:
        if element.tag == f"{W}p":
            text = _paragraph_text(element)
            if not text.strip():
                continue
            if _is_heading(element):
                sections.append((text.strip()[:120], [text]))
            else:
                sections[-1][1].append(text)
        elif element.tag == f"{W}tbl":
            for row in element.iter(f"{W}tr"):
                cells = [" ".join(_paragraph_text(p) for p in cell.iter(f"{W}p")).strip()
                         for cell in row.iter(f"{W}tc")]
                if any(cells):
                    sections[-1][1].append(" | ".join(cells))
    return [Page(i + 1, f"§{heading}", "\n".join(lines))
            for i, (heading, lines) in enumerate(sections) if lines]


def quote_found(pages: list[Page], quote: str, *, page: int | None = None) -> bool:
    """Whether ``quote`` appears verbatim (whitespace-normalised) in the cited page, or anywhere."""
    needle = _normalise(quote)
    if len(needle) < 8:
        return False
    candidates = [p for p in pages if page is None or p.n == page]
    return any(needle in _normalise(p.text) for p in candidates)


def locate(pages: list[Page], quote: str) -> Page | None:
    needle = _normalise(quote)
    return next((p for p in pages if needle and needle in _normalise(p.text)), None)


def _normalise(text: str) -> str:
    return " ".join(text.replace("­", "").replace("‑", "-").split()).lower()


def _paragraph_text(paragraph: ElementTree.Element) -> str:
    parts = []
    for node in paragraph.iter():
        if node.tag == f"{W}t" and node.text:
            parts.append(node.text)
        elif node.tag == f"{W}tab":
            parts.append("\t")
        elif node.tag in (f"{W}br", f"{W}cr"):
            parts.append("\n")
    return "".join(parts)


def _is_heading(paragraph: ElementTree.Element) -> bool:
    style = paragraph.find(f"{W}pPr/{W}pStyle")
    value = style.get(f"{W}val", "") if style is not None else ""
    return bool(re.match(r"(?i)heading\d|titre\d|berschrift\d|title", value))
