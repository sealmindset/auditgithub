"""Keep credentials out of issue bodies sent to external trackers.

For most scanners a ``code_snippet`` is context: the unsafe call, the
vulnerable version string, the misconfigured block. An issue without it is
harder to act on, so it is included.

For a secret scanner the snippet *is* the finding. The line gitleaks or
whispers matched is ``"password": "Sleep1234!"`` or an API key, and copying it
into a tracker publishes a working credential into a second system with its own
audience, its own retention and its own export paths. AuditBoard issues cannot
be deleted and their descriptions cannot be edited after create, so there is no
taking it back.

Measured on this estate: GRC issue I#1716 carries a live Google API key in its
body in plaintext, because this check did not exist when it was filed.

The browser already withholds these snippets when it builds the body
(``isSecretFamilyScanner`` in ``lib/finding-issue.ts``). This module is the
second line: the API accepts the body as text from the caller, so a stale tab,
a replayed request or a script posting straight to the endpoint would otherwise
put the secret through. Enforced server-side because a client-side rule is a
suggestion.

Withheld entirely rather than masked. Masking means guessing which token on the
line is the secret, and a guess that is wrong leaks the whole line while
looking safe.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

#: Scanners whose snippets are credentials. Kept in step with
#: ``SECRET_FAMILY_SCANNERS`` in ``src/web-ui/lib/finding-issue.ts``.
SECRET_FAMILY = re.compile(
    r"gitleaks|trufflehog|whispers|detect.?secret|secret|credential|gitsecrets|shhgit|ggshield",
    re.IGNORECASE,
)

#: What stands in for a withheld snippet, wherever one is removed.
SNIPPET_WITHHELD = (
    "[Snippet withheld by AuditGitHub. This scanner reports the matched secret "
    "itself, and copying it into a tracker would put a working credential in a "
    "second system. Open the finding in AuditGitHub to see the line.]"
)

#: Shortest fragment worth removing. Below this a "snippet" is punctuation or a
#: brace that appears throughout the body, and replacing every occurrence would
#: shred the text without protecting anything.
MIN_FRAGMENT = 8


def is_secret_family(scanner_name: Optional[str]) -> bool:
    """Whether this scanner's snippets must never reach an external tracker."""
    return bool(SECRET_FAMILY.search(scanner_name or ""))


def redact_snippet(description: str, finding) -> Tuple[str, bool]:
    """Strip a secret-scanner snippet out of an issue body.

    Returns the body and whether anything was removed, so the caller can log
    that it happened — a redaction that fires means a client sent something it
    should not have, and that is worth knowing about.

    Only the finding's own snippet is removed, not anything that merely looks
    like a secret. This is not a secret scanner; it is the narrow guarantee
    that the one value this system already knows to be a credential does not
    get forwarded.
    """
    if not description or not is_secret_family(getattr(finding, "scanner_name", None)):
        return description, False

    snippet = (getattr(finding, "code_snippet", None) or "").strip()
    if not snippet:
        return description, False

    redacted = description
    if snippet in redacted:
        redacted = redacted.replace(snippet, SNIPPET_WITHHELD)

    # Line by line as well. A body may carry a clipped or re-wrapped copy of
    # the snippet rather than the whole thing verbatim -- the browser truncates
    # long snippets -- and a partial copy of a credential line is still the
    # credential.
    for line in snippet.splitlines():
        fragment = line.strip()
        if len(fragment) >= MIN_FRAGMENT and fragment in redacted:
            redacted = redacted.replace(fragment, SNIPPET_WITHHELD)

    return redacted, redacted != description
