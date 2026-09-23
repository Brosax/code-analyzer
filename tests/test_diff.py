"""M8: re-evaluation -- the list of one version against another, and a build context carried across."""
from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from test_evaluate import SOURCE, buildctx_file, fake_tools

from code_analyzer.evidence.analyze import carry_buildctx, current_buildctx, evaluate
from code_analyzer.evidence.buildctx_schema import buildctx_text, load_buildctx
from code_analyzer.evidence.overlays import set_status
from code_analyzer.evidence.store import Store
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.sesip.diff import compare


def _evaluation(tmp_path: Path, name: str) -> Workspace:
    source = tmp_path / name
    source.mkdir()
    (source / "a.c").write_text(SOURCE, encoding="utf-8")
    tools_ = fake_tools(tmp_path, source / "a.c")  # each run's fake cppcheck names its own a.c
    return evaluate(source, eval_dir=tmp_path / f"eval-{name}", profile="generic-sesip",
                    buildctx=load_buildctx(buildctx_file(tmp_path, tools_)), compile_db=False).workspace


def test_the_same_code_keeps_every_entry_and_offers_the_old_dispositions(tmp_path: Path) -> None:
    base, head = _evaluation(tmp_path, "v1"), _evaluation(tmp_path, "v2")
    store = Store(base.index_path)
    set_status(base, store, "PV-0001", "false_positive", "bounds checked by caller", by="fgt")
    store.close()
    result = compare(base, head)
    assert result["counts"] == {"kept": 1, "new": 0, "gone": 0, "how": {"fingerprint": 1}, "dispositions_to_reuse": 1}
    [kept] = result["kept"]
    assert (kept["base_status"], kept["base_note"]) == ("false_positive", "bounds checked by caller")


def test_new_and_gone_entries(tmp_path: Path) -> None:
    base, head = _evaluation(tmp_path, "v1"), _evaluation(tmp_path, "v2")
    with sqlite3.connect(base.index_path) as db:        # as if v1 never had it: new in v2
        db.execute("DELETE FROM pvs")
    assert compare(base, head)["counts"]["new"] == 1
    assert compare(head, base)["counts"]["gone"] == 1   # and the other way round: gone


def test_a_build_context_is_carried_to_the_new_tree(tmp_path: Path) -> None:
    base, head = _evaluation(tmp_path, "v1"), _evaluation(tmp_path, "v2")
    context = current_buildctx(base)
    context["build"]["include"] = [str(base.source / "include"), "/usr/include/extra"]
    base.save_version("buildctx", buildctx_text(context))
    base.ledger.append("buildctx_version", version=2, sha256="x", by="test")
    carry_buildctx(base, head)
    carried = current_buildctx(head)["build"]["include"]
    assert carried == [str(head.source.resolve() / "include"), "/usr/include/extra"]
    assert head.ledger.of("buildctx_carried")[-1]["source_evaluation"] == base.root.name
    shutil.rmtree(tmp_path / "v1")  # nothing in head still points at the old tree
    assert str(tmp_path / "v1") not in str(current_buildctx(head))
