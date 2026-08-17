# TF-M full acceptance run

This is a slow release/manual robustness test, not a normal CI job. Run it with
no compilation database and no project include or define overrides:

```bash
code-analyzer analyze trusted-firmware-m --no-compile-db
```

The entire run must retain `analysis_context: "degraded"`. Acceptance requires
a complete, hashed inventory; exact accounting of every planned, started,
completed, failed, timed-out, and unscheduled unit; all existing native evidence
reachable from `manifest.json` and `index.html`; and a valid shareable ZIP with
no local paths. Broad Splint parse failures and a Cppcheck timeout are acceptable
when they are accurately represented as partial execution. Do not compare the
result with the historical Coverity count of 165.
