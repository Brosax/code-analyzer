"""Packaged dsh scanner skills.

This module exists so the kebab-case skill directories ship as package data
and resolve through ``importlib.resources`` under a zip install as well as an
editable one.  There is no Python code here; ``code_analyzer.llm.skills``
reads the Markdown.
"""
