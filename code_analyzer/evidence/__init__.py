"""The evidence layer: native findings, their SQLite index, and deterministic triage.

Evidence is never merged, deleted or judged here.  Everything that filters or
groups -- ``view_class``, clusters, TOE membership -- is a *view* stored beside
the rows, recomputable from the native reports at any time.
"""
