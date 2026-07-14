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


PLUGIN = Path(__file__).resolve().parents[1]
SKILL = PLUGIN / "skills" / "code-analyzer"
SCRIPT = SKILL / "scripts" / "run_code_analyzer.py"
INSTALLER = SKILL / "scripts" / "install_code_analyzer.py"
CORE = SKILL / "scripts" / "code_analyzer_core.py"


def load_core():
    spec = importlib.util.spec_from_file_location("code_analyzer_core", CORE)
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


class CodeAnalyzerCoreTests(unittest.TestCase):
    def test_normalizes_paths_fingerprints_and_groups_cross_tool_overlap(self):
        core = load_core()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            source = project / "src" / "main.c"
            source.parent.mkdir()
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            first = core.Finding("cppcheck", "high", "null", "bad", str(source), "7")
            second = core.Finding("flawfinder", "high", "CWE-476", "bad", "src/main.c", "7")
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

    def test_cli_publishes_history_latest_links_and_partial_optional_skip(self):
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
                "--cppcheck-bin", str(cppcheck),
                "--flawfinder-bin", str(flawfinder),
                "--splint-bin", str(splint),
                "--clang-tidy-bin", str(root / "missing-clang-tidy"),
            ]
            result = subprocess.run(cmd, text=True, capture_output=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            run = out / "runs" / "run-one"
            summary = json.loads((run / "combined" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["schema_version"], "2.0")
            self.assertEqual(list(summary["tools"]), ["cppcheck", "flawfinder", "splint", "clang-tidy"])
            self.assertEqual(summary["tools"]["clang-tidy"]["status"], "skipped")
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), ["cppcheck", "flawfinder", "splint"])
            self.assertTrue((out / "latest").is_symlink())
            self.assertTrue((out / "combined" / "summary.json").exists())
            self.assertTrue((run / "combined" / "index.html").exists())
            self.assertFalse((run / "flawfinder" / "html").exists())

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

        self.assertEqual(result.returncode, 1)
        self.assertEqual(summary["tools"]["cppcheck"]["status"], "failed")

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
        self.assertIn("tools", payload)
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

    def test_clang_tidy_uses_compile_database_and_default_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            source = project / "main.cpp"
            source.write_text("int main(){return 0;}\n", encoding="utf-8")
            database = project / "compile_commands.json"
            database.write_text(json.dumps([
                {"directory": str(project), "file": "main.cpp", "command": "c++ -c main.cpp"}
            ]), encoding="utf-8")
            arguments = root / "clang-arguments.json"
            clang_tidy = make_binary(
                root,
                "clang-tidy",
                f"""
                import json, sys
                from pathlib import Path
                if '--version' in sys.argv:
                    print('LLVM clang-tidy 19')
                else:
                    Path({str(arguments)!r}).write_text(json.dumps(sys.argv[1:]))
                    print({str(source)!r} + ':1:1: warning: issue [bugprone-test]')
                """,
            )
            out = root / "out"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "clang", "--tools", "clang-tidy", "--clang-tidy-bin", str(clang_tidy),
            ], text=True, capture_output=True)
            summary = json.loads((out / "runs/clang/combined/summary.json").read_text(encoding="utf-8"))
            recorded = json.loads(arguments.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(summary["tools"]["clang-tidy"]["status"], "ok")
        self.assertEqual(summary["findings"][0]["rule_id"], "bugprone-test")
        self.assertIn("-p=%s" % project, recorded)
        self.assertIn("-checks=clang-analyzer-*,bugprone-*,performance-*,portability-*", recorded)

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
            pid_file = root / "child.pid"
            cppcheck = make_binary(
                root, "cppcheck",
                f"""
                import os, sys, time
                from pathlib import Path
                if '--version' in sys.argv:
                    print('Cppcheck 2')
                else:
                    Path({str(pid_file)!r}).write_text(str(os.getpid()))
                    time.sleep(30)
                """,
            )
            out = root / "out"
            process = subprocess.Popen([
                sys.executable, str(SCRIPT), "--project", str(project), "--out", str(out),
                "--run-id", "cancelled", "--tools", "cppcheck", "--cppcheck-bin", str(cppcheck),
            ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while not pid_file.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_file.exists(), "analyzer did not start")
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            process.send_signal(signal.SIGINT)
            _, stderr = process.communicate(timeout=7)

            self.assertEqual(process.returncode, 130, stderr)
            self.assertFalse((out / "runs/cancelled").exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)


class DistributionLayoutTests(unittest.TestCase):
    def test_only_code_analyzer_skill_is_discoverable_and_legacy_scripts_forward(self):
        manifest = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["interface"]["displayName"], "Code Analyzer")
        self.assertTrue((SKILL / "SKILL.md").exists())
        skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        description = skill_text.split("description:", 1)[1].splitlines()[0].strip()
        self.assertTrue(description.startswith("Use when"))
        self.assertIn("## Overview", skill_text)
        self.assertIn("## Quick reference", skill_text)
        self.assertIn("## Common mistakes", skill_text)
        self.assertEqual(list((PLUGIN / "skills").rglob("SKILL.md")), [SKILL / "SKILL.md"])
        for name in ("c-cpp-review-suite", "cppcheck-analysis", "flawfinder-analysis", "splint-analysis"):
            self.assertFalse((PLUGIN / "skills" / name).exists())
            wrapper = next((PLUGIN / "legacy" / name / "scripts").glob("run_*.py"))
            self.assertLess(len(wrapper.read_text(encoding="utf-8").splitlines()), 40)

    def test_legacy_suite_entry_forwards_to_code_analyzer_help(self):
        legacy = PLUGIN / "legacy" / "c-cpp-review-suite" / "scripts" / "run_review_suite.py"
        result = subprocess.run([sys.executable, str(legacy), "--help"], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--clang-tidy-bin", result.stdout)


class InstallerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
