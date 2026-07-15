import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock


PLUGIN = Path(__file__).resolve().parents[1]
SKILL = PLUGIN / "skills" / "code-analyzer"
SCRIPT = SKILL / "scripts" / "run_code_analyzer.py"
INSTALLER = SKILL / "scripts" / "install_code_analyzer.py"
CORE = SKILL / "scripts" / "code_analyzer_core.py"
VALIDATOR = PLUGIN / "scripts" / "validate_release.py"


def load_core():
    spec = importlib.util.spec_from_file_location("code_analyzer_core", CORE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_installer():
    spec = importlib.util.spec_from_file_location("install_code_analyzer", INSTALLER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def make_binary(directory: Path, name: str, body: str) -> Path:
    path = directory / name
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(0o755)
    return path


def dashboard_data(rendered: str):
    marker = '<script id="report-data" type="application/json">'
    start = rendered.index(marker) + len(marker)
    end = rendered.index("</script>", start)
    return json.loads(rendered[start:end])


class CodeAnalyzerCoreTests(unittest.TestCase):
    def test_normalizes_paths_fingerprints_and_groups_cross_tool_overlap(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "src" / "main.c"
            source.parent.mkdir()
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            first = core.Finding("cppcheck", "high", "nullPointer", "bad", str(source), "7")
            second = core.Finding(
                "flawfinder", "high", "buffer:null", "bad", "src/main.c", "9", cwe="CWE-476"
            )
            summary = core.aggregate_results(
                project,
                [
                    core.ToolResult("cppcheck", "ok", findings=[first]),
                    core.ToolResult("flawfinder", "ok", findings=[second]),
                ],
                run_id="stable",
            )

        self.assertEqual([f["file"] for f in summary["findings"]], [str(source), "src/main.c"])
        self.assertEqual({f["canonical_path"] for f in summary["findings"]}, {"src/main.c"})
        self.assertTrue(all(len(f["fingerprint"]) == 64 for f in summary["findings"]))
        self.assertEqual(len(summary["overlap_groups"]), 1)
        self.assertEqual(summary["top_files"], [{"file": "src/main.c", "count": 2}])
        self.assertEqual(summary["overlap_groups"][0]["line"], "7-9")
        self.assertEqual(summary["overlap_groups"][0]["category"], "null-dereference")

    def test_overlap_does_not_merge_unrelated_nearby_findings(self):
        core = load_core()
        project = Path("/tmp/overlap-project")
        summary = core.aggregate_results(
            project,
            [
                core.ToolResult("cppcheck", "ok", findings=[
                    core.Finding("cppcheck", "high", "bufferAccessOutOfBounds", "buffer overflow", "main.c", "10")
                ]),
                core.ToolResult("flawfinder", "ok", findings=[
                    core.Finding("flawfinder", "high", "format:printf", "format string", "main.c", "11")
                ]),
            ],
            run_id="unrelated",
        )
        self.assertEqual(summary["overlap_groups"], [])

    def test_source_manifest_applies_shared_default_and_explicit_filters(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            for relative in (
                "src/main.c", "src/skip.c", "src/nested/deep.c", "include/api.hpp", ".tools/tool.c",
                "vendor/vendor.c", "generated/generated.c", "build/build.c",
                "code-analyzer-report-old/copied.c",
            ):
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("int value;\n", encoding="utf-8")
            manifest = core.build_source_manifest(
                project, ["src/*.c", "include/*.hpp"], ["**/skip.c"], True,
                project / "code-analyzer-report",
            )
            unfiltered_vendor = core.build_source_manifest(
                project, ["vendor/*.c"], [], False, project / "reports",
            )
            ancestor_output = core.build_source_manifest(
                project, ["src/main.c"], [], True, project.parent,
            )

        self.assertEqual([manifest.relative(path) for path in manifest.files], ["include/api.hpp", "src/main.c"])
        self.assertEqual([unfiltered_vendor.relative(path) for path in unfiltered_vendor.files], ["vendor/vendor.c"])
        self.assertEqual([ancestor_output.relative(path) for path in ancestor_output.files], ["src/main.c"])
        self.assertGreaterEqual(manifest.excluded_count, 6)
        self.assertEqual(manifest.payload()["excluded_paths"], manifest.excluded_count)

    def test_splint_source_chunking_honors_command_limit(self):
        core = load_core()
        sources = [Path("/project/src/file-%02d.c" % index) for index in range(12)]
        chunks = core._chunk_sources(["splint", "-I/project/include"], sources, 120)
        self.assertGreater(len(chunks), 1)
        self.assertEqual([path for chunk in chunks for path in chunk], sources)
        for chunk in chunks:
            size = sum(len(os.fsencode(value)) + 1 for value in ["splint", "-I/project/include"])
            size += sum(len(os.fsencode(str(path))) + 1 for path in chunk)
            self.assertLessEqual(size, 120)

    def test_executor_records_version_and_times_out_process_group(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = make_binary(
                root,
                "slow-tool",
                """
                import sys, time
                if '--version' in sys.argv:
                    print('slow-tool 1.2.3')
                else:
                    print('started', flush=True)
                    time.sleep(5)
                """,
            )
            request = core.ToolRequest(
                tool="slow",
                command=[str(binary)],
                cwd=root,
                out_dir=root / "out",
                required=True,
                timeout_seconds=1,
            )
            started = time.monotonic()
            result = core.execute_request(request)

        self.assertEqual(result.status, "timed_out")
        self.assertIn("1.2.3", result.version)
        self.assertLess(time.monotonic() - started, 4)

    def test_executor_streams_large_logs_without_retaining_them_in_result(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = make_binary(
                root,
                "large-tool",
                """
                import sys
                if '--version' in sys.argv:
                    print('large-tool 1')
                else:
                    sys.stdout.write('x' * (1024 * 1024))
                """,
            )
            result = core.execute_request(core.ToolRequest(
                "large", [str(binary)], root, root / "out", True, timeout_seconds=5,
            ))
            log_size = (root / "out" / "stdout.txt").stat().st_size

        self.assertEqual(result.status, "ok")
        self.assertEqual(log_size, 1024 * 1024)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_tool_error_gate_counts_failed_and_timed_out_but_not_skipped(self):
        core = load_core()
        self.assertFalse(core.should_fail({"tools": {"x": {"status": "skipped"}}, "findings": []}, "tool-error"))
        self.assertTrue(core.should_fail({"tools": {"x": {"status": "failed"}}, "findings": []}, "tool-error"))
        self.assertTrue(core.should_fail({"tools": {"x": {"status": "timed_out"}}, "findings": []}, "tool-error"))

    def test_all_severity_gates_use_minimum_rank(self):
        core = load_core()
        summary = {
            "tools": {},
            "findings": [{"rank": core.SEVERITY_RANK["high"]}],
        }
        self.assertTrue(core.should_fail(summary, "medium"))
        self.assertTrue(core.should_fail(summary, "high"))
        self.assertFalse(core.should_fail(summary, "critical"))
        self.assertFalse(core.should_fail(summary, "none"))

    def test_publishing_subset_removes_stale_compatibility_symlink(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reports"
            first = out / ".first"
            (first / "cppcheck").mkdir(parents=True)
            (first / "combined").mkdir()
            core.publish_run(first, out, "first", False)
            self.assertTrue((out / "cppcheck").is_symlink())

            second = out / ".second"
            (second / "combined").mkdir(parents=True)
            core.publish_run(second, out, "second", False)
            self.assertFalse((out / "cppcheck").is_symlink())

    def test_publishing_removes_retired_clang_tidy_link_but_preserves_history(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reports"
            historical = out / "runs" / "historical" / "clang-tidy"
            historical.mkdir(parents=True)
            marker = historical / "summary.json"
            marker.write_text("{}\n", encoding="utf-8")
            (out / "clang-tidy").symlink_to(
                "runs/historical/clang-tidy", target_is_directory=True
            )

            staging = out / ".current"
            (staging / "combined").mkdir(parents=True)
            core.publish_run(staging, out, "current", False)

            self.assertFalse((out / "clang-tidy").is_symlink())
            self.assertTrue(marker.exists())

    def test_publishing_migrates_legacy_flat_directories(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reports"
            old_marker = out / "cppcheck" / "old.txt"
            old_marker.parent.mkdir(parents=True)
            old_marker.write_text("old", encoding="utf-8")
            (out / "combined").mkdir()
            staging = out / ".current"
            (staging / "cppcheck").mkdir(parents=True)
            (staging / "combined").mkdir()

            core.publish_run(staging, out, "current", False)
            legacy_runs = list((out / "runs").glob("legacy-*"))

            self.assertEqual(len(legacy_runs), 1)
            self.assertEqual((legacy_runs[0] / "cppcheck" / "old.txt").read_text(), "old")
            self.assertTrue((out / "cppcheck").is_symlink())
            self.assertTrue((out / "combined").is_symlink())

    def test_publish_failure_rolls_back_flat_reports_and_staging(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "reports"
            marker = out / "cppcheck" / "old.txt"
            marker.parent.mkdir(parents=True)
            marker.write_text("old", encoding="utf-8")
            staging = out / ".current"
            (staging / "cppcheck").mkdir(parents=True)
            (staging / "combined").mkdir()
            original = core._reporting._atomic_symlink

            def fail_first_link(target, link):
                raise OSError("simulated link failure")

            core._reporting._atomic_symlink = fail_first_link
            try:
                with self.assertRaises(OSError):
                    core.publish_run(staging, out, "current", False)
            finally:
                core._reporting._atomic_symlink = original

            self.assertEqual(marker.read_text(encoding="utf-8"), "old")
            self.assertTrue(staging.exists())
            self.assertFalse((out / "runs" / "current").exists())
            self.assertEqual(list((out / "runs").glob("legacy-*")), [])

    def test_html_dashboard_embeds_all_findings_and_escapes_script_data(self):
        core = load_core()
        malicious = "bad </script><script>alert(1)</script> & value\u2028next"
        findings = [
            core.Finding("cppcheck", "high", "nullPointer", malicious, "main.c", "2", "CWE-476"),
            core.Finding("cppcheck", "low", "style", "second finding", "other.c", "4"),
        ]
        result = core.ToolResult(
            "cppcheck", "failed", "bad configuration", findings=findings,
            diagnostics=[core.ToolDiagnostic(
                "cppcheck", "error", "configuration", "invalid include path", fatal=True,
            )],
            metadata={
                "stdout_log": "cppcheck.stdout.txt", "stderr_log": "cppcheck.xml", "source_count": 2,
            },
        )
        flawfinder = core.ToolResult("flawfinder", "ok", findings=[
            core.Finding("flawfinder", "high", "pointer:null", "related finding", "main.c", "3", "CWE-476"),
        ])
        summary = core.aggregate_results(Path("/tmp/project"), [result, flawfinder], "html")
        rendered = core.html_report(summary, 1)
        embedded = dashboard_data(rendered)

        self.assertIn('id="severity"', rendered)
        self.assertIn('id="tool"', rendered)
        self.assertIn('id="cwe"', rendered)
        self.assertIn('id="search"', rendered)
        self.assertIn('id="severity-chart"', rendered)
        self.assertIn('id="overlap-body"', rendered)
        self.assertIn("bad configuration", rendered)
        self.assertIn('href="summary.json"', rendered)
        self.assertNotIn("https://", rendered)
        self.assertNotIn("http://", rendered)
        self.assertNotIn("</script><script>alert(1)</script>", rendered)
        self.assertIn("\\u003c/script\\u003e", rendered)
        self.assertEqual(len(embedded["findings"]), 3)
        self.assertEqual(embedded["findings"][0]["message"], malicious)
        self.assertEqual(len(embedded["diagnostics"]), 1)
        self.assertEqual(len(embedded["overlap_groups"]), 1)
        self.assertEqual(embedded["tools"]["cppcheck"]["stdout_log"], "cppcheck.stdout.txt")

    def test_max_findings_limits_markdown_but_not_html_dashboard(self):
        core = load_core()
        findings = [
            core.Finding("cppcheck", "high", "rule-%s" % index, "message-%s" % index, "main.c", str(index))
            for index in range(1, 276)
        ]
        result = core.ToolResult("cppcheck", "ok", findings=findings)
        summary = core.aggregate_results(Path("/tmp/project"), [result], "all-findings")

        markdown = core.markdown_report(summary, 1)
        embedded = dashboard_data(core.html_report(summary, 1))

        self.assertIn("message-1", markdown)
        self.assertNotIn("message-2", markdown)
        self.assertEqual(len(embedded["findings"]), 275)
        self.assertEqual(embedded["findings"][0]["message"], "message-1")
        self.assertEqual(embedded["findings"][-1]["message"], "message-275")


class CodeAnalyzerCliTests(unittest.TestCase):
    def _fake_tools(self, root: Path):
        log = root / "calls.log"
        cppcheck = make_binary(
            root,
            "cppcheck",
            f"""
            import sys
            from pathlib import Path
            if '--version' in sys.argv:
                print('Cppcheck 2.14')
            else:
                Path({str(log)!r}).open('a').write('cppcheck\\n')
                print('<?xml version="1.0"?><results><errors><error id="nullPointer" severity="error" msg="Null"><location file="src/main.c" line="3"/></error></errors></results>', file=sys.stderr)
            """,
        )
        flawfinder = make_binary(
            root,
            "flawfinder",
            f"""
            import sys
            from pathlib import Path
            if '--version' in sys.argv:
                print('flawfinder 2.0.19')
            else:
                Path({str(log)!r}).open('a').write('flawfinder\\n')
                print('File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context,Fingerprint')
                print('src/main.c,3,1,4,buffer,strcpy,Risky call,Use bounded API,,CWE-120,,abc')
            """,
        )
        splint = make_binary(
            root,
            "splint",
            f"""
            import sys
            from pathlib import Path
            if '--version' in sys.argv or '-help' in sys.argv:
                print('Splint 3.1.2')
            else:
                Path({str(log)!r}).open('a').write('splint\\n')
                print('src/main.c:3:1: Variable used before definition', file=sys.stderr)
                raise SystemExit(1)
            """,
        )
        return log, cppcheck, flawfinder, splint

    def test_cli_publishes_history_latest_links_with_three_default_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "src").mkdir()
            (project / "src" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            out = root / "reports"
            log, cppcheck, flawfinder, splint = self._fake_tools(root)
            cmd = [
                sys.executable,
                str(SCRIPT),
                "--project", str(project),
                "--out", str(out),
                "--run-id", "run-one",
                "--max-findings", "1",
                "--cppcheck-bin", str(cppcheck),
                "--flawfinder-bin", str(flawfinder),
                "--splint-bin", str(splint),
            ]
            result = subprocess.run(cmd, text=True, capture_output=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            run = out / "runs" / "run-one"
            summary = json.loads((run / "combined" / "summary.json").read_text(encoding="utf-8"))
            dashboard = (run / "combined" / "index.html").read_text(encoding="utf-8")
            self.assertEqual(summary["schema_version"], "2.1")
            self.assertEqual(list(summary["tools"]), ["cppcheck", "flawfinder", "splint"])
            self.assertEqual(summary["run"]["tool_order"], ["cppcheck", "flawfinder", "splint"])
            self.assertEqual(summary["source_manifest"]["files"], ["src/main.c"])
            self.assertEqual(summary["total_diagnostics"], 0)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["cppcheck", "flawfinder", "splint"])
            self.assertEqual(len(dashboard_data(dashboard)["findings"]), 3)
            self.assertIn("dashboard: %s" % (run / "combined" / "index.html"), result.stdout)
            self.assertIn("Findings (first 1)", (run / "combined" / "summary.md").read_text(encoding="utf-8"))
            self.assertTrue((out / "latest").is_symlink())
            self.assertTrue((out / "combined" / "summary.json").exists())
            self.assertTrue((run / "combined" / "index.html").exists())
            self.assertTrue((run / "combined" / "source-manifest.json").exists())
            self.assertFalse((run / "flawfinder" / "html").exists())
            self.assertFalse((run / "clang-tidy").exists())
            self.assertFalse((out / "clang-tidy").is_symlink())

            duplicate = subprocess.run(cmd, text=True, capture_output=True)
            self.assertNotEqual(duplicate.returncode, 0)
            self.assertIn("already exists", duplicate.stderr)

            overwritten = subprocess.run(cmd + ["--overwrite"], text=True, capture_output=True)
            self.assertEqual(overwritten.returncode, 0, overwritten.stderr)
            self.assertEqual([p.name for p in (out / "runs").iterdir()], ["run-one"])

    def test_required_missing_fails_but_still_writes_combined_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            out = root / "reports"
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                    "--run-id", "missing", "--tools", "cppcheck",
                    "--cppcheck-bin", str(root / "absent"),
                ],
                text=True,
                capture_output=True,
            )
            summary = json.loads((out / "runs" / "missing" / "combined" / "summary.json").read_text())
            dashboard = dashboard_data(
                (out / "runs" / "missing" / "combined" / "index.html").read_text(encoding="utf-8")
            )

        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["tools"]["cppcheck"]["status"], "failed")
        self.assertEqual(dashboard["tools"]["cppcheck"]["status"], "failed")
        self.assertEqual(dashboard["findings"], [])

    def test_doctor_is_json_and_does_not_run_analyzers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "ran"
            tool = make_binary(
                root,
                "tool",
                f"""
                import sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('tool 9')
                else:
                    Path({str(marker)!r}).write_text('ran')
                """,
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--doctor", "--cppcheck-bin", str(tool)],
                text=True,
                capture_output=True,
            )
            payload = json.loads(result.stdout)

        self.assertEqual(result.returncode, 0)
        self.assertEqual(list(payload["tools"]), ["cppcheck", "flawfinder", "splint"])
        self.assertIn("capabilities", payload["tools"]["cppcheck"])
        self.assertFalse(marker.exists())

    def test_flawfinder_extra_arg_is_preserved_and_scan_is_still_single_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            arguments = root / "arguments.json"
            flawfinder = make_binary(
                root,
                "flawfinder",
                f"""
                import json, sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('flawfinder 2')
                else:
                    Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))
                    print('File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context,Fingerprint')
                """,
            )
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT), "--project", str(project), "--out", str(root / "out"),
                    "--run-id", "extra", "--tools", "flawfinder", "--flawfinder-bin", str(flawfinder),
                    "--extra-arg=--neverignore",
                ], text=True, capture_output=True,
            )
            recorded_arguments = json.loads(arguments.read_text(encoding="utf-8")) if arguments.exists() else []

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--neverignore", recorded_arguments)
        self.assertEqual(Path(recorded_arguments[-1]).name, "source-view")

    def test_compile_commands_remains_supported_for_cppcheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "main.c"
            source.write_text("int main(void){return 0;}\n", encoding="utf-8")
            database = project / "compile_commands.json"
            vendor = project / "vendor" / "third-party.c"
            vendor.parent.mkdir()
            vendor.write_text("int third_party;\n", encoding="utf-8")
            database.write_text(json.dumps([
                {"directory": ".", "file": "main.c", "command": "cc -c main.c"},
                {"directory": str(project), "file": "vendor/third-party.c", "command": "cc -c vendor/third-party.c"},
            ]), encoding="utf-8")
            arguments = root / "cppcheck-arguments.json"
            cppcheck = make_binary(
                root,
                "cppcheck",
                f"""
                import json, sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('Cppcheck 2.14')
                else:
                    Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))
                    print('<?xml version="1.0"?><results><errors/></results>', file=sys.stderr)
                """,
            )
            out = root / "out"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "cppcheck-db", "--tools", "cppcheck",
                "--cppcheck-bin", str(cppcheck), "--compile-commands", str(database),
            ], text=True, capture_output=True)
            recorded = json.loads(arguments.read_text(encoding="utf-8"))
            filtered = json.loads(
                (out / "runs/cppcheck-db/cppcheck/compile_commands.filtered.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        project_arguments = [value for value in recorded if value.startswith("--project=")]
        self.assertEqual(len(project_arguments), 1)
        self.assertTrue(project_arguments[0].endswith("/cppcheck/compile_commands.filtered.json"))
        self.assertEqual([entry["file"] for entry in filtered], ["main.c"])

    def test_invalid_empty_tools_missing_compile_database_and_numeric_values_are_cli_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            cases = (
                ["--tools", ","],
                ["--tools", "flawfinder", "--compile-commands", "missing.json"],
                ["--tool-jobs", "0"],
                ["--timeout-seconds", "0"],
                ["--flawfinder-minlevel", "6"],
                ["--splint-command-bytes", "4095"],
                ["--source-exclude", "[z-a]"],
            )
            for index, extra in enumerate(cases):
                with self.subTest(arguments=extra):
                    out = root / ("invalid-%d" % index)
                    result = subprocess.run(
                        [
                            sys.executable, str(SCRIPT), "--project", str(project),
                            "--out", str(out), "--run-id", "invalid-%d" % index,
                        ] + extra,
                        text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse((out / "runs").exists())

    def test_report_path_file_is_a_clean_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            out = root / "report-file"
            out.write_text("occupied\n", encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "invalid-output", "--tools", "cppcheck",
            ], text=True, capture_output=True)

            self.assertEqual(result.returncode, 2)
            self.assertIn("unable to create report directory", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_cppcheck_uses_filtered_shared_source_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            for relative in ("src/main.c", "src/skip.c", "vendor/vendor.c", ".tools/tool.c"):
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("int value;\n", encoding="utf-8")
            recorded = root / "files.json"
            cppcheck = make_binary(
                root, "cppcheck",
                f"""
                import json, sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('Cppcheck 2')
                else:
                    option = next(value for value in sys.argv if value.startswith('--file-list='))
                    files = Path(option.split('=', 1)[1]).read_text().splitlines()
                    Path({str(recorded)!r}).write_text(json.dumps(files))
                    print('<?xml version="1.0"?><results><errors/></results>', file=sys.stderr)
                """,
            )
            out = root / "out"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "manifest", "--tools", "cppcheck", "--cppcheck-bin", str(cppcheck),
                "--source-include", "src/*.c", "--source-exclude", "src/skip.c",
            ], text=True, capture_output=True)
            files = json.loads(recorded.read_text(encoding="utf-8"))
            summary = json.loads((out / "runs/manifest/combined/summary.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(files, [str((project / "src/main.c").resolve())])
        self.assertEqual(summary["source_manifest"]["files"], ["src/main.c"])

    def test_relative_cppcheck_support_files_resolve_from_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            suppressions = project / "suppressions.txt"
            suppressions.write_text("unusedFunction\n", encoding="utf-8")
            recorded = root / "arguments.json"
            cppcheck = make_binary(
                root, "cppcheck",
                f"""
                import json, sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('Cppcheck 2')
                else:
                    Path({str(recorded)!r}).write_text(json.dumps(sys.argv[1:]))
                    print('<?xml version="1.0"?><results><errors/></results>', file=sys.stderr)
                """,
            )
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(root / "out"),
                "--run-id", "support", "--tools", "cppcheck", "--cppcheck-bin", str(cppcheck),
                "--suppressions-list", "suppressions.txt",
            ], cwd=str(root), text=True, capture_output=True)
            arguments = json.loads(recorded.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--suppressions-list=%s" % suppressions.resolve(), arguments)

    def test_splint_fatal_diagnostics_fail_tool_without_security_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            splint = make_binary(
                root, "splint",
                """
                import sys
                if '-help' in sys.argv:
                    print('Splint 3')
                else:
                    print('main.c:1: Parse Error: missing semicolon', file=sys.stderr)
                    raise SystemExit(1)
                """,
            )
            out = root / "out"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "splint-fatal", "--tools", "splint", "--splint-bin", str(splint),
            ], text=True, capture_output=True)
            summary = json.loads((out / "runs/splint-fatal/combined/summary.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(summary["tools"]["splint"]["status"], "failed")
        self.assertEqual(summary["total_findings"], 0)
        self.assertEqual(summary["total_diagnostics"], 1)
        self.assertTrue(summary["diagnostics"][0]["fatal"])

    def test_removed_clang_tidy_tool_and_options_are_cli_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            cases = (
                ["--tools", "clang-tidy"],
                ["--doctor", "--tools", "clang-tidy"],
                ["--clang-tidy-bin", "clang-tidy"],
                ["--clang-tidy-checks", "bugprone-*"],
            )
            for index, removed_arguments in enumerate(cases):
                with self.subTest(arguments=removed_arguments):
                    out = root / ("out-%s" % index)
                    result = subprocess.run(
                        [
                            sys.executable, str(SCRIPT), "--project", str(project),
                            "--out", str(out), "--run-id", "removed-%s" % index,
                        ] + removed_arguments,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn("clang-tidy", result.stderr)
                    self.assertFalse((out / "runs").exists())

    def test_bad_output_fails_one_tool_and_other_tool_still_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            bad = make_binary(
                root, "flawfinder",
                """
                import sys
                print('flawfinder 2' if '--version' in sys.argv else 'not parseable')
                """,
            )
            splint = make_binary(
                root, "splint",
                """
                import sys
                if '--version' in sys.argv:
                    print('Splint 3')
                else:
                    print('main.c:1:1: warning from splint', file=sys.stderr)
                    raise SystemExit(1)
                """,
            )
            out = root / "out"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "partial", "--tools", "flawfinder,splint",
                "--flawfinder-bin", str(bad), "--splint-bin", str(splint),
            ], text=True, capture_output=True)
            summary = json.loads((out / "runs/partial/combined/summary.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["tools"]["flawfinder"]["status"], "failed")
        self.assertEqual(summary["tools"]["splint"]["status"], "ok")
        self.assertEqual(summary["tools"]["splint"]["total_findings"], 1)

    def test_explicit_parallelism_is_concurrent_but_summary_order_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            cppcheck = make_binary(
                root, "cppcheck",
                """
                import sys, time
                if '--version' in sys.argv: print('Cppcheck 2')
                else:
                    time.sleep(1)
                    print('<?xml version="1.0"?><results><errors/></results>', file=sys.stderr)
                """,
            )
            flawfinder = make_binary(
                root, "flawfinder",
                """
                import sys, time
                if '--version' in sys.argv: print('flawfinder 2')
                else:
                    time.sleep(1)
                    print('File,Line,Column,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context,Fingerprint')
                """,
            )
            out = root / "out"
            started = time.monotonic()
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "parallel", "--tools", "cppcheck,flawfinder", "--tool-jobs", "2",
                "--cppcheck-bin", str(cppcheck), "--flawfinder-bin", str(flawfinder),
            ], text=True, capture_output=True)
            elapsed = time.monotonic() - started
            summary = json.loads((out / "runs/parallel/combined/summary.json").read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 1.8)
        self.assertEqual(list(summary["tools"]), ["cppcheck", "flawfinder"])

    def test_cancellation_terminates_analyzer_process_group_without_publishing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
            cppcheck_pid = root / "cppcheck.pid"
            flawfinder_pid = root / "flawfinder.pid"
            cppcheck = make_binary(
                root, "cppcheck",
                f"""
                import os, subprocess, sys, time
                from pathlib import Path
                if '--version' in sys.argv:
                    print('Cppcheck 2')
                else:
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
                    Path({str(cppcheck_pid)!r}).write_text('%s,%s' % (os.getpid(), child.pid))
                    time.sleep(30)
                """,
            )
            flawfinder = make_binary(
                root, "flawfinder",
                f"""
                import os, subprocess, sys, time
                from pathlib import Path
                if '--version' in sys.argv:
                    print('flawfinder 2')
                else:
                    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
                    Path({str(flawfinder_pid)!r}).write_text('%s,%s' % (os.getpid(), child.pid))
                    time.sleep(30)
                """,
            )
            out = root / "out"
            process = subprocess.Popen([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "cancelled", "--tools", "cppcheck,flawfinder", "--tool-jobs", "2",
                "--cppcheck-bin", str(cppcheck), "--flawfinder-bin", str(flawfinder),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not (cppcheck_pid.exists() and flawfinder_pid.exists()) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(cppcheck_pid.exists(), "Cppcheck did not start")
                self.assertTrue(flawfinder_pid.exists(), "Flawfinder did not start")
                child_pids = [
                    int(value)
                    for path in (cppcheck_pid, flawfinder_pid)
                    for value in path.read_text(encoding="utf-8").split(",")
                ]
                process.send_signal(signal.SIGINT)
                _, stderr = process.communicate(timeout=10)

                self.assertEqual(process.returncode, 130, stderr)
                self.assertFalse((out / "runs/cancelled").exists())
                for child_pid in child_pids:
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child_pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()


class DistributionLayoutTests(unittest.TestCase):
    def test_only_code_analyzer_skill_is_discoverable_and_legacy_scripts_forward(self):
        manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["interface"]["displayName"], "Code Analyzer")
        self.assertEqual(manifest["version"], "0.5.0")
        self.assertNotIn("clang-tidy", json.dumps(manifest))
        self.assertTrue((SKILL / "SKILL.md").exists())
        skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        description = skill_text.split("description:", 1)[1].splitlines()[0].strip()
        self.assertTrue(description.startswith("Use when"))
        self.assertIn("## Overview", skill_text)
        self.assertIn("## Quick reference", skill_text)
        self.assertIn("## Common mistakes", skill_text)
        self.assertNotIn("clang-tidy", skill_text)
        openai_metadata = (SKILL / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("three analyzers", openai_metadata)
        self.assertNotIn("clang-tidy", openai_metadata)
        self.assertEqual(list((PLUGIN / "skills").rglob("SKILL.md")), [SKILL / "SKILL.md"])
        self.assertLess(len(CORE.read_text(encoding="utf-8").splitlines()), 50)
        for module in ("runtime", "adapters", "dashboard", "reporting", "cli"):
            self.assertTrue((SKILL / "scripts" / ("code_analyzer_%s.py" % module)).is_file())
        for name in ("c-cpp-review-suite", "cppcheck-analysis", "flawfinder-analysis", "splint-analysis"):
            self.assertFalse((PLUGIN / "skills" / name).exists())
            wrapper = next((PLUGIN / "legacy" / name / "scripts").glob("run_*.py"))
            self.assertLess(len(wrapper.read_text(encoding="utf-8").splitlines()), 40)
        self.assertTrue((PLUGIN / "README.md").is_file())
        self.assertTrue((PLUGIN / "LICENSE").is_file())
        workflow = (PLUGIN / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('python-version: ["3.8", "3.10", "3.12"]', workflow)

    def test_legacy_suite_entry_forwards_to_code_analyzer_help(self):
        legacy = PLUGIN / "legacy" / "c-cpp-review-suite" / "scripts" / "run_review_suite.py"
        result = subprocess.run([sys.executable, str(legacy), "--help"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--compile-commands", result.stdout)
        self.assertNotIn("--clang-tidy", result.stdout)

    def test_release_validator_accepts_distribution(self):
        result = subprocess.run([sys.executable, str(VALIDATOR)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release validation passed", result.stdout)


class InstallerTests(unittest.TestCase):
    def test_installer_rejects_empty_duplicate_hosts_and_non_object_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = {**os.environ, "HOME": str(home)}
            for hosts in ("", "codex,codex"):
                with self.subTest(hosts=hosts):
                    result = subprocess.run(
                        [sys.executable, str(INSTALLER), "--hosts", hosts],
                        env=env, text=True, capture_output=True,
                    )
                    self.assertEqual(result.returncode, 2)
            installed = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "codex", "--copy"],
                env=env, text=True, capture_output=True,
            )
            marker = home / ".agents/skills/code-analyzer/.code-analyzer-source.json"
            marker.write_text("[]\n", encoding="utf-8")
            conflict = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "codex"],
                env=env, text=True, capture_output=True,
            )

            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertEqual(conflict.returncode, 2)
            self.assertIn("refusing to overwrite", conflict.stderr)
            self.assertNotIn("Traceback", conflict.stderr)

    def test_install_check_idempotency_conflict_migration_copy_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = {**os.environ, "HOME": str(home)}
            hosts = "codex,claude,pi,hermes"
            install = [sys.executable, str(INSTALLER), "--hosts", hosts]
            first = subprocess.run(install, env=env, text=True, capture_output=True)
            second = subprocess.run(install, env=env, text=True, capture_output=True)
            check = subprocess.run(install + ["--check"], env=env, text=True, capture_output=True)

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertTrue((home / ".agents/skills/code-analyzer").is_symlink())
            self.assertTrue((home / ".claude/skills/code-analyzer").is_symlink())
            self.assertTrue((home / ".hermes/skills/code-analyzer").is_symlink())

            claude = home / ".claude/skills/code-analyzer"
            claude.unlink()
            claude.mkdir()
            (claude / "foreign.txt").write_text("mine", encoding="utf-8")
            conflict = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "claude"], env=env, text=True, capture_output=True
            )
            self.assertNotEqual(conflict.returncode, 0)

            legacy = home / ".claude/skills/c-cpp-review-suite"
            legacy.mkdir()
            (legacy / "SKILL.md").write_text("legacy", encoding="utf-8")
            migrated = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "claude", "--migrate-legacy"],
                env=env, text=True, capture_output=True,
            )
            self.assertNotEqual(migrated.returncode, 0, "foreign target must remain protected")
            self.assertTrue(legacy.exists(), "migration must be transactional when target conflicts")

            claude.joinpath("foreign.txt").unlink()
            claude.rmdir()
            copied = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "claude", "--copy", "--migrate-legacy"],
                env=env, text=True, capture_output=True,
            )
            self.assertEqual(copied.returncode, 0, copied.stderr)
            self.assertTrue((claude / ".code-analyzer-source.json").exists())
            self.assertFalse(legacy.exists())

            removed = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", hosts, "--uninstall"],
                env=env, text=True, capture_output=True,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse((home / ".agents/skills/code-analyzer").exists())
            self.assertFalse(claude.exists())

    def test_copy_install_check_detects_and_repairs_stale_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = {**os.environ, "HOME": str(home)}
            command = [sys.executable, str(INSTALLER), "--hosts", "codex", "--copy"]
            installed = subprocess.run(command, env=env, text=True, capture_output=True)
            destination = home / ".agents/skills/code-analyzer"
            (destination / "SKILL.md").write_text("corrupt\n", encoding="utf-8")
            stale = subprocess.run(command + ["--check"], env=env, text=True, capture_output=True)
            repaired = subprocess.run(command, env=env, text=True, capture_output=True)
            current = subprocess.run(command + ["--check"], env=env, text=True, capture_output=True)
            marker = json.loads((destination / ".code-analyzer-source.json").read_text(encoding="utf-8"))

            self.assertEqual(installed.returncode, 0, installed.stderr)
            self.assertEqual(stale.returncode, 1, stale.stderr)
            self.assertIn("stale", stale.stdout)
            self.assertEqual(repaired.returncode, 0, repaired.stderr)
            self.assertEqual(current.returncode, 0, current.stderr)
            self.assertEqual((destination / "SKILL.md").read_text(), (SKILL / "SKILL.md").read_text())
            self.assertEqual(len(marker["content_sha256"]), 64)

    def test_multi_host_legacy_preflight_prevents_partial_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env = {**os.environ, "HOME": str(home)}
            legacy = home / ".claude/skills/c-cpp-review-suite"
            legacy.mkdir(parents=True)
            (legacy / "SKILL.md").write_text("legacy", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(INSTALLER), "--hosts", "codex,claude"],
                env=env, text=True, capture_output=True,
            )

            self.assertEqual(result.returncode, 2)
            self.assertTrue(legacy.exists())
            self.assertFalse((home / ".agents/skills/code-analyzer").exists())
            self.assertFalse((home / ".claude/skills/code-analyzer").exists())

    def test_multi_host_install_failure_rolls_back_migrations_and_prior_targets(self):
        installer = load_installer()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            legacies = [
                home / ".agents/skills/c-cpp-review-suite",
                home / ".claude/skills/c-cpp-review-suite",
            ]
            for legacy in legacies:
                legacy.mkdir(parents=True)
                (legacy / "SKILL.md").write_text("legacy", encoding="utf-8")
            real_install_link = installer.install_link
            calls = []

            def fail_second(source, destination):
                calls.append(destination)
                if len(calls) == 2:
                    raise OSError("simulated install failure")
                real_install_link(source, destination)

            with mock.patch.dict(os.environ, {"HOME": str(home)}), \
                    mock.patch.object(installer, "install_link", side_effect=fail_second), \
                    mock.patch("builtins.print"):
                result = installer.main(["--hosts", "codex,claude", "--migrate-legacy"])

            self.assertEqual(result, 2)
            self.assertTrue(all(path.exists() for path in legacies))
            self.assertFalse((home / ".agents/skills/code-analyzer").exists())
            self.assertFalse((home / ".claude/skills/code-analyzer").exists())
            self.assertEqual(list(home.rglob("*.legacy-*")), [])


if __name__ == "__main__":
    unittest.main()
