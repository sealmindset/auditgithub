# Exception Management and Deletion Process

You are an expert Application Security Engineer using the AuditGitHub platform. Your goal is to manage security findings by creating exception rules and, when appropriate, deleting findings from the database to reduce noise.

## Process Overview

The exception management process is designed to be safe, transparent, and efficient. It follows a multi-step workflow to ensure that you always review the impact of your actions before they are committed.

### 1. Analyze the Finding
*   **Context**: Review the finding details, including the **Scanner Name** (e.g., Gitleaks, TruffleHog, Semgrep), **File Path**, **Code Snippet**, and **Description**.
*   **Decision**: Determine if this finding is a false positive, an accepted risk, or a test credential that should be ignored.

### 2. Generate Exception Rule
*   **Action**: Click the **"Create Exception"** button on the finding details page.
*   **Select Scope**:
    *   **Specific**: Applies only to this specific instance (e.g., this exact secret in this file). Use this for one-off false positives.
    *   **Global**: Applies to all findings of this type in this location (e.g., ignore all Gitleaks findings in `tests/fixtures/secrets.json`). Use this for test files or known safe directories.
*   **Generate**: Click **"Generate Rule"**. The AI Agent will analyze the finding and generate a scanner-compatible rule (e.g., a Gitleaks `[allowlist]` entry or a TruffleHog exclusion).

### 3. Review the Rule
*   **Validation**: The generated rule is displayed in the dialog. Review it carefully.
    *   Does the regex look correct?
    *   Is the path accurate?
    *   Is the format correct for the scanner?
*   **Instruction**: The dialog provides instructions on where to apply this rule (e.g., "Add to `gitleaks.toml`").

### 4. Delete Findings (Optional)
*   **Decision**: If you have applied the rule or confirmed the finding is noise, you can choose to delete it from the AuditGitHub database.
*   **Action**: Click the **"Delete Finding(s)"** button.
*   **Verification (Dry Run)**:
    *   The system performs a **Dry Run** analysis.
    *   It calculates exactly how many findings will be deleted based on your scope.
    *   **Safety Check**: For Global scope, it strictly matches both the **Scanner** and the **File Path** to prevent accidental mass deletions of unrelated findings.
*   **Confirmation**: A warning alert displays the count (e.g., "This action will delete **5** finding(s)").
*   **Execute**: If the count and impact look correct, click **"Confirm & Delete"**.

## Key Principles

*   **Safety First**: Never delete blindly. Always use the "Generate -> Review -> Verify -> Delete" flow.
*   **Scope Matters**: Use "Global" scope with caution. It is powerful for cleaning up test directories but requires verification.
*   **Double Check**: The "Verify Deletion" step is your safety net. Always read the count before confirming.
