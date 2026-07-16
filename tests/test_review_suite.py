"""Regression coverage migrated from the pre-consolidation analyzer runners."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


CORE = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "code-analyzer"
    / "scripts"
    / "code_analyzer_core.py"
)


def load_core():
    spec = importlib.util.spec_from_file_location("legacy_regression_core", CORE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ConsolidatedParserRegressionTests(unittest.TestCase):
    def test_parses_flawfinder_text_without_a_second_scan(self):
        core = load_core()
        findings = core._parse_flawfinder_csv(
            """
/repo/src/main.c:37:  [2] (buffer) memcpy:
  Does not check for buffer overflows when copying to destination (CWE-120).
  Make sure destination can always hold the source data.
/repo/src/rand.c:85:  [3] (random) srand:
  This function is not sufficiently random for security-related functions (CWE-327).
"""
        )
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].rule_id, "buffer:memcpy")
        self.assertEqual(findings[0].cwe, "CWE-120")
        self.assertEqual(findings[1].severity, "medium")

    def test_parses_splint_continuations_unknown_and_wrapped_locations(self):
        core = load_core()
        findings, diagnostics = core._parse_splint(
            """
< Location unknown >: Preprocessing error for file src/main.c
src/main.c:12:
    8: Variable buffer used before definition
      Additional wrapped detail.
src/include/config.h:3: Cannot find include file <missing.h>
src/parser.c:44: Parse Error: Suspect missing semicolon
"""
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].column, "8")
        self.assertIn("Additional wrapped detail", findings[0].message)
        self.assertEqual(len(diagnostics), 3)
        self.assertEqual(diagnostics[0].file, "< Location unknown >")
        self.assertEqual([item.category for item in diagnostics], ["configuration", "include", "parsing"])
        self.assertFalse(diagnostics[0].fatal)
        self.assertTrue(diagnostics[2].fatal)

    def test_parses_consecutive_wrapped_long_splint_paths_separately(self):
        core = load_core()
        findings, diagnostics = core._parse_splint(
            """
testcases/CWE121_Stack_Based_Buffer_Overflow/s03/CWE121_Stack_Based_Buffer_Overf
    low__CWE805_char_alloca_loop_03.c:26:36: Unrecognized identifier: alloca
  Identifier used in code has not been declared.
testcases/CWE121_Stack_Based_Buffer_Overflow/s03/CWE121_Stack_Based_Buffer_Overf
    low__CWE805_char_alloca_loop_03.c:38:24:
    Function memset expects arg 2 to be int gets char: 'C'
"""
        )
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].file.endswith("Overflow__CWE805_char_alloca_loop_03.c"))
        self.assertEqual(findings[0].line, "38")
        self.assertEqual(len(diagnostics), 1)
        self.assertTrue(diagnostics[0].file.endswith("Overflow__CWE805_char_alloca_loop_03.c"))
        self.assertEqual(diagnostics[0].line, "26")
        self.assertFalse(diagnostics[0].fatal)

    def test_include_discovery_prioritizes_explicit_and_skips_reports(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            include = project / "include"
            include.mkdir()
            (include / "project.h").write_text("#pragma once\n", encoding="utf-8")
            report = project / "code-analyzer-report-old"
            report.mkdir()
            (report / "ignored.h").write_text("", encoding="utf-8")
            manifest = core.build_source_manifest(project, [], [], True, report)
            includes = core._include_dirs(manifest, [str(include)])

        self.assertEqual(includes, [str(include)])

    def test_default_tool_registry_keeps_three_static_tools_and_optional_ai(self):
        core = load_core()
        self.assertEqual(core.DEFAULT_TOOL_ORDER, ("cppcheck", "flawfinder", "splint"))
        self.assertEqual(core.TOOL_ORDER, ("cppcheck", "flawfinder", "splint", "ai-review"))
        self.assertEqual(list(core.ADAPTERS), ["cppcheck", "flawfinder", "splint", "ai-review"])
        self.assertEqual([spec.required for spec in core.ANALYZERS.values()], [True, True, False])


if __name__ == "__main__":
    unittest.main()
