"""A minimal, deterministic XLSX writer (SpreadsheetML), standard library only.

Enough for a list: several sheets of strings and numbers, a bold header row,
frozen header, column widths.  Strings are written inline (``inlineStr``) so
there is no shared-string table to keep consistent.  The archive is
byte-stable -- fixed timestamps, fixed member order -- so an export's sha256
changes only when its content does.
"""
from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Sequence
from typing import Any
from xml.sax.saxutils import escape

_FIXED_TIME = (2026, 1, 1, 0, 0, 0)
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
_MAX_CELL = 32767

Sheet = tuple[str, Sequence[str], Sequence[Sequence[Any]]]  # (name, header, rows)


def workbook(sheets: Sequence[Sheet]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        def put(name: str, text: str) -> None:
            info = zipfile.ZipInfo(name, _FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text.encode("utf-8"))

        put("[Content_Types].xml", _content_types(len(sheets)))
        put("_rels/.rels", _ROOT_RELS)
        put("xl/workbook.xml", _workbook(sheets))
        put("xl/_rels/workbook.xml.rels", _workbook_rels(len(sheets)))
        put("xl/styles.xml", _STYLES)
        for index, (_, header, rows) in enumerate(sheets, 1):
            put(f"xl/worksheets/sheet{index}.xml", _sheet(header, rows))
    return buffer.getvalue()


def _cell_text(value: Any) -> str:
    text = _ILLEGAL_XML.sub("\ufffd", str(value))
    return text[:_MAX_CELL]


def _column(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _sheet(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    widths = [max([len(str(h))] + [min(len(str(r[i])) if i < len(r) else 0, 80) for r in rows]) for i, h in
              enumerate(header)]
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
             '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
             'state="frozen"/></sheetView></sheetViews>', "<cols>"]
    parts += [f'<col min="{i + 1}" max="{i + 1}" width="{min(max(w, 8), 80) + 2}" customWidth="1"/>'
              for i, w in enumerate(widths)]
    parts.append("</cols><sheetData>")
    for row_index, row in enumerate([header, *rows], 1):
        style = ' s="1"' if row_index == 1 else ""
        cells = []
        for col_index, value in enumerate(row):
            ref = f"{_column(col_index)}{row_index}"
            if isinstance(value, bool) or value is None:
                value = "" if value is None else str(value).lower()
            if isinstance(value, (int, float)) and row_index > 1:
                cells.append(f'<c r="{ref}"{style}><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"{style}><is><t xml:space="preserve">'
                             f"{escape(_cell_text(value))}</t></is></c>")
        parts.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    parts.append("</sheetData></worksheet>")
    return "".join(parts)


def _workbook(sheets: Sequence[Sheet]) -> str:
    entries = "".join(f'<sheet name="{escape(_sheet_name(name))}" sheetId="{i}" r:id="rId{i}"/>'
                      for i, (name, _, _) in enumerate(sheets, 1))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{entries}</sheets></workbook>")


def _sheet_name(name: str) -> str:
    return re.sub(r"[\[\]:*?/\\]", "-", name)[:31] or "Sheet"


def _workbook_rels(count: int) -> str:
    rels = "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
                   f'relationships/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in range(1, count + 1))
    rels += (f'<Relationship Id="rId{count + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
             'relationships/styles" Target="styles.xml"/>')
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>')


def _content_types(count: int) -> str:
    sheets = "".join(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/'
                     'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' for i in range(1, count + 1))
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            f"{sheets}</Types>")


_ROOT_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
              '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
              'officeDocument" Target="xl/workbook.xml"/></Relationships>')
_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
           '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
           '<fills count="2"><fill><patternFill patternType="none"/></fill>'
           '<fill><patternFill patternType="gray125"/></fill></fills>'
           '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
           '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
           '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
           '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
           '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
           '</styleSheet>')
