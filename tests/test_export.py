"""M3: the list as deliverables -- xlsx structure, ordering, redaction, and the leak check."""
from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest
from test_evaluate import buildctx_file, fake_tools, project

from code_analyzer.evidence.analyze import evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.export import listing
from code_analyzer.export.xlsx import workbook


def test_xlsx_is_a_valid_deterministic_package() -> None:
    data = workbook([("PV List", ("A", "B"), [["x & <y>", 1], ["\x01bell", 2.5]]), ("Coverage", ("k",), [])])
    assert data == workbook([("PV List", ("A", "B"), [["x & <y>", 1], ["\x01bell", 2.5]]), ("Coverage", ("k",), [])])
    with zipfile.ZipFile(io.BytesIO(data)) as book:
        names = book.namelist()
        assert {"[Content_Types].xml", "xl/workbook.xml", "xl/worksheets/sheet2.xml", "xl/styles.xml"} <= set(names)
        sheet = book.read("xl/worksheets/sheet1.xml").decode()
        import xml.dom.minidom
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                xml.dom.minidom.parseString(book.read(name))  # well-formed
    assert "x &amp; &lt;y&gt;" in sheet and "\x01" not in sheet and "<v>2.5</v>" in sheet


def _evaluated(tmp_path: Path) -> Workspace:
    source = project(tmp_path)
    tools = fake_tools(tmp_path, source / "a.c")
    outcome = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                       buildctx=load_buildctx(buildctx_file(tmp_path, tools)), compile_db=False)
    assert outcome.exit_code == 0
    return outcome.workspace


def _sheet_text(workspace: Workspace, export_id: str, sheet: int) -> str:
    data = (workspace.root / "exports" / export_id / "pv-list.xlsx").read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as book:
        return book.read(f"xl/worksheets/sheet{sheet}.xml").decode()


def test_export_writes_english_columns_and_records_it(tmp_path: Path) -> None:
    workspace = _evaluated(tmp_path)
    result = listing.export(workspace, "internal", ["xlsx", "csv", "md"])
    assert result["leak_check"] == "passed" and result["entries"] == 1
    csv_text = (workspace.root / "exports" / result["id"] / "pv-list.csv").read_text()
    assert csv_text.splitlines()[0].startswith("PV ID,Title,Partition,TOE Module,SFR")
    assert "PV-0001" in csv_text and "bufferAccessOutOfBounds" in csv_text  # the lower line of two errors titles it
    md = (workspace.root / "exports" / result["id"] / "pv-list.md").read_text()
    assert md.startswith("# Vulnerability list") and "1 main" in md
    assert workspace.ledger.of("export_written")[-1]["export_id"] == result["id"]


def test_a_path_in_a_message_is_redacted_in_the_shareable_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _evaluated(tmp_path)
    original = listing._line

    def with_path(entry: dict[str, Any], members: list[dict[str, Any]], profile: str, variant: str) -> list[Any]:
        row = original(entry, members, profile, variant)
        row[1] = f"see {workspace.source}/a.c and {Path.home()}/notes"
        return row

    monkeypatch.setattr(listing, "_line", with_path)
    shared = listing.export(workspace, "shareable", ["xlsx"])
    assert shared["leak_check"] == "passed"
    text = _sheet_text(workspace, shared["id"], 1)
    assert "&lt;SOURCE&gt;/a.c" in text and str(workspace.source) not in text
    internal = listing.export(workspace, "internal", ["xlsx"])
    assert internal["leak_check"] == "failed"  # reported, not refused: internal lists may name paths


def test_a_shareable_export_that_still_leaks_is_not_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _evaluated(tmp_path)
    monkeypatch.setattr(listing, "_forbidden", lambda ws: [b"OutOfBounds"])
    with pytest.raises(listing.LeakFound):
        listing.export(workspace, "shareable", ["csv"])
    assert not workspace.ledger.of("export_written")
    assert not any((workspace.root / "exports").iterdir())


def test_dispositioned_entries_move_to_their_own_sheet(tmp_path: Path) -> None:
    from code_analyzer.evidence import overlays
    from code_analyzer.evidence.store import Store

    workspace = _evaluated(tmp_path)
    store = Store(workspace.index_path)
    overlays.set_status(workspace, store, "PV-0001", "not_exploitable", "stack canary + bounds", by="fgt")
    store.close()
    result = listing.export(workspace, "internal", ["xlsx"])
    assert result["entries"] == 0 and result["dispositioned"] == 1
    assert "stack canary + bounds" in _sheet_text(workspace, result["id"], 2)
    assert re.search(r"PV-0001", _sheet_text(workspace, result["id"], 1)) is None
