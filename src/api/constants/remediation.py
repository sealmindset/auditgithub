"""
Remediation taxonomy — the fixed vocabulary for "what kind of work fixes this".

Every finding resolves to exactly one of these categories. The list is closed:
a classifier, human or model, selects from it and may not invent a value. That
is what makes "totals by remediation category" a countable thing rather than a
free-text field nobody can sum.

The two-line text in REMEDIATION_TEXT is the template that renders into a
report. Placeholders are filled from the finding row and, where available, the
knowledge-base entry. An unresolved placeholder renders as
"unknown — {what would resolve it}" and never as a blank or a guess.

Roles are derived from category, not measured. The derivation is stated here so
a reader can disagree with it in one place rather than hunting for it.

See docs/specs/REPORT_GENERATOR_WIZARD_SPEC.md §2.
"""

from enum import Enum


class RemediationCategory(str, Enum):
    """Closed set. Order is report order, not priority."""

    PATCH = "patch"
    UPGRADE_DEPENDENCY = "upgrade_dependency"
    CONFIGURE = "configure"
    CODE_CHANGE = "code_change"
    ROTATE_SECRET = "rotate_secret"
    ACCESS_CONTROL = "access_control"
    INFRA_CONTROL = "infra_control"
    REMOVE_DEPENDENCY = "remove_dependency"
    COMPENSATING_CONTROL = "compensating_control"
    ACCEPT_RISK = "accept_risk"
    FALSE_POSITIVE = "false_positive"


class CategorySource(str, Enum):
    """Who decided the category. Reported separately; never merged into one total."""

    RULE = "rule"      # deterministic, reproducible, confidence 1.00
    AI = "ai"          # model-inferred, confidence is the model's
    HUMAN = "human"    # analyst override, confidence 1.00
    NONE = "none"      # not yet classified


class EffortRole(str, Enum):
    """Who does the work. Derived from category — see ROLE_FOR_CATEGORY."""

    DEVELOPER = "developer"
    DEVOPS = "devops"
    DBA = "dba"
    SECURITY = "security"
    VENDOR = "vendor"
    PRODUCT_OWNER = "product_owner"


class EffortBand(str, Enum):
    """An estimate, always labelled as one. Never converted to hours."""

    S = "S"
    M = "M"
    L = "L"
    XL = "XL"


# Display name and the two-line remediation text, per category.
#
# The text is deliberately two lines: line one is the action, line two is the
# consequence or caveat. A one-line instruction with no caveat is how a breaking
# upgrade gets filed as routine work.
REMEDIATION_TEXT: dict[RemediationCategory, dict[str, str]] = {
    RemediationCategory.PATCH: {
        "display": "Patch",
        "text": (
            "Apply the vendor patch for {reference}.\n"
            "No dependency version change is required."
        ),
    },
    RemediationCategory.UPGRADE_DEPENDENCY: {
        "display": "Upgrade dependency",
        "text": (
            "Upgrade {package} from {current_version} to {fixed_version}.\n"
            "{breaking_note}"
        ),
    },
    RemediationCategory.CONFIGURE: {
        "display": "Configure",
        "text": (
            "Change {setting} in {location}.\n"
            "No application code is modified."
        ),
    },
    RemediationCategory.CODE_CHANGE: {
        "display": "Code change",
        "text": (
            "Modify {location} so that {behaviour}.\n"
            "Requires code review and test coverage before release."
        ),
    },
    RemediationCategory.ROTATE_SECRET: {
        "display": "Rotate secret",
        "text": (
            "Revoke {secret_type} in {system} and issue a replacement.\n"
            "Purge the value from git history; rotation alone leaves it readable in past commits."
        ),
    },
    RemediationCategory.ACCESS_CONTROL: {
        "display": "Access control",
        "text": (
            "Restrict {principal} access to {resource}.\n"
            "Re-grant on least privilege rather than restoring the previous grant."
        ),
    },
    RemediationCategory.INFRA_CONTROL: {
        "display": "Infrastructure control",
        "text": (
            "Place {control} in front of {resource}.\n"
            "This blocks exploitation without changing the application; the defect remains present."
        ),
    },
    RemediationCategory.REMOVE_DEPENDENCY: {
        "display": "Remove or replace dependency",
        "text": (
            "Remove {package} and replace it with {alternative}.\n"
            "No fixed version is published upstream."
        ),
    },
    RemediationCategory.COMPENSATING_CONTROL: {
        "display": "Compensating control",
        "text": (
            "No fix is available. Add detection for {signal} and alert {owner}.\n"
            "This detects exploitation; it does not prevent it."
        ),
    },
    RemediationCategory.ACCEPT_RISK: {
        "display": "Accept risk",
        "text": (
            "Risk accepted by {owner} on {accepted_date}.\n"
            "Re-review on {review_date}; acceptance without a review date is not acceptance."
        ),
    },
    RemediationCategory.FALSE_POSITIVE: {
        "display": "False positive",
        "text": (
            "Not exploitable in this context because {reason}.\n"
            "Suppress {rule} for {scope} so the finding does not return on the next scan."
        ),
    },
}


# Role derivation. A judgement, recorded once, in one place.
#
# Supporting roles are the people whose sign-off or access the primary role
# needs, not everyone who might be consulted.
ROLE_FOR_CATEGORY: dict[RemediationCategory, tuple[EffortRole, tuple[EffortRole, ...]]] = {
    RemediationCategory.PATCH: (EffortRole.DEVOPS, (EffortRole.VENDOR,)),
    RemediationCategory.UPGRADE_DEPENDENCY: (EffortRole.DEVELOPER, ()),
    RemediationCategory.CONFIGURE: (EffortRole.DEVOPS, ()),
    RemediationCategory.CODE_CHANGE: (EffortRole.DEVELOPER, ()),
    RemediationCategory.ROTATE_SECRET: (EffortRole.SECURITY, (EffortRole.DEVOPS,)),
    RemediationCategory.ACCESS_CONTROL: (EffortRole.SECURITY, (EffortRole.DEVOPS,)),
    RemediationCategory.INFRA_CONTROL: (EffortRole.DEVOPS, (EffortRole.SECURITY,)),
    RemediationCategory.REMOVE_DEPENDENCY: (EffortRole.DEVELOPER, (EffortRole.PRODUCT_OWNER,)),
    RemediationCategory.COMPENSATING_CONTROL: (EffortRole.SECURITY, (EffortRole.DEVOPS,)),
    RemediationCategory.ACCEPT_RISK: (EffortRole.PRODUCT_OWNER, (EffortRole.SECURITY,)),
    RemediationCategory.FALSE_POSITIVE: (EffortRole.SECURITY, ()),
}


# Categories whose work does not remove the finding. A report that sums these
# into "findings resolved" is overstating what the work bought.
NON_REMOVING_CATEGORIES: frozenset[RemediationCategory] = frozenset({
    RemediationCategory.INFRA_CONTROL,
    RemediationCategory.COMPENSATING_CONTROL,
    RemediationCategory.ACCEPT_RISK,
})


def remediation_text(category: RemediationCategory, **values: object) -> str:
    """
    Render the two-line remediation text for a category.

    Any placeholder with no supplied value renders as an explicit unknown
    naming what would resolve it, rather than leaving a blank that reads as
    "nothing to do here".
    """
    template = REMEDIATION_TEXT[category]["text"]

    class _Unknown(dict):
        def __missing__(self, key: str) -> str:
            return f"unknown — no {key} recorded on this finding"

    supplied = _Unknown({k: v for k, v in values.items() if v not in (None, "")})
    return template.format_map(supplied)
