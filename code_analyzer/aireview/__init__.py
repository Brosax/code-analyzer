"""Targeted AI review (v3 M7): lenses, output contracts, code units and prompts.

The blind scan is gone.  The model looks at one unit of code at a time, chosen
deterministically (sesip/relevance.py): an existing list entry to verify (T1),
or a function the profile ties to an SFR or TSFI that no tool flagged (T2).
What it says is advice -- grounded against the code it was shown, never able
to remove an entry, and only able to add one after a second, verifying look.
"""
