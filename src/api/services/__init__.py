"""Domain services — logic that is not a route and not a table.

A service here owns a rule the rest of the app is not allowed to re-implement.
``finding_groups`` is the first: before it, the question "which findings does
this issue speak for?" was answered independently in eight places in
``routers/findings.py``, and they could disagree.
"""
