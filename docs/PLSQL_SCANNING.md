# PL/SQL Security Scanning

## Overview

PL/SQL security scanning is fully integrated into the AuditGH workflow. The system automatically detects Oracle PL/SQL code and applies specialized security rules to identify vulnerabilities specific to Oracle databases and Oracle E-Business Suite.

## Integration Details

### Automatic Detection

When scanning repositories, the system automatically:

1. **Detects PL/SQL files** by extension: `.sql`, `.pls`, `.pkb`, `.pks`, `.plb`, `.fnc`, `.prc`, `.trg`, `.vw`
2. **Applies PL/SQL security rules** via Semgrep when PL/SQL files are present
3. **Stores findings in PostgreSQL** with `scanner_name='semgrep'` and `finding_type='sast'`
4. **Displays results in the Web UI** under the SAST category for each repository

### Storage & Display

**Database Storage:**
- Table: `findings`
- Scanner: `semgrep`
- Type: `sast`
- Includes: file path, line numbers, severity, code snippets

**Web UI Display:**
- Location: **Repositories → Projects → {project_id} → SAST tab**
- PL/SQL findings appear alongside other SAST findings
- Filterable by: severity, file, scanner, date
- Click on finding for details: code snippet, location, remediation advice

## What Gets Detected

### SQL Injection Vulnerabilities
- ✅ `EXECUTE IMMEDIATE` with dynamic SQL
- ✅ `OPEN CURSOR FOR` with user input
- ✅ `DBMS_SQL.PARSE` / `EXECUTE` misuse
- **Severity:** ERROR (High)
- **CWE:** CWE-89

### Hardcoded Credentials
- ✅ Hardcoded passwords (`PASSWORD := 'secret'`)
- ✅ Connection strings with credentials
- ✅ Oracle EBS APPS schema passwords
- **Severity:** ERROR (High)
- **CWE:** CWE-798

### Command Injection
- ✅ `UTL_FILE` operations with user input
- ✅ `DBMS_SCHEDULER.CREATE_JOB` misuse
- **Severity:** ERROR (High) / WARNING (Medium)
- **CWE:** CWE-78

### Weak Cryptography
- ✅ DES encryption usage
- ✅ MD5 hashing
- **Severity:** ERROR (High) / WARNING (Medium)
- **CWE:** CWE-327, CWE-328

### Information Disclosure
- ✅ Exposing detailed error messages (`SQLERRM`)
- ✅ `DBMS_UTILITY.FORMAT_ERROR_STACK` in user output
- **Severity:** WARNING (Medium)
- **CWE:** CWE-209

### Privilege Escalation
- ✅ Missing `AUTHID CURRENT_USER` in procedures
- ✅ Autonomous transaction abuse
- **Severity:** WARNING (Medium)
- **CWE:** CWE-269

### Oracle EBS Specific
- ✅ `FND_USER.CREATE_USER` misuse
- ✅ Direct APPS schema access
- **Severity:** WARNING (Medium) / ERROR (High)

## Usage

### Option 1: Automatic Scanning (Integrated)

PL/SQL scanning happens automatically during normal scans:

```bash
# Regular scan - PL/SQL rules apply automatically to .sql files
docker-compose run --rm scanner --target example-org

# Scan specific Oracle EBS repository
docker-compose run --rm scanner \
  --target example-org \
  --repo EBS-E-7000-Store-Inventory-REST-API

# Results are automatically ingested into database
# View in Web UI: Repositories → Projects → {id} → SAST
```

**What happens:**
1. Scanner detects `.sql`, `.pls`, `.pkb` files
2. Semgrep runs with both standard rules + PL/SQL security rules
3. Findings stored in database with `scanner_name='semgrep'`, `finding_type='sast'`
4. Auto-ingest loads findings (if enabled)
5. Web UI displays findings under SAST tab

### Option 2: Re-scan Existing Repositories

To update existing repositories with PL/SQL security scans:

```bash
# Preview which repos have PL/SQL code
docker exec auditgh_api python /app/rescan_plsql_repos.py --org example-org --dry-run

# Scan all PL/SQL repos in organization
docker exec auditgh_api python /app/rescan_plsql_repos.py --org example-org

# Scan all PL/SQL repos across all organizations
docker exec auditgh_api python /app/rescan_plsql_repos.py

# Then ingest results
docker exec auditgh_api python /app/ingest_reports.py
```

**Output example:**
```
================================================================================
PL/SQL Repository Security Re-Scan
================================================================================
Target: example-org
Mode: LIVE SCAN
================================================================================

Scanning repository directories for PL/SQL files...
Found 15 repositories with PL/SQL code:

  1. example-org/EBS-E-7000-Store-Inventory-REST-API (47 PL/SQL files)
  2. example-org/oracle-utilities (23 PL/SQL files)
  3. example-org/ebs-custom-reports (156 PL/SQL files)
  ...

================================================================================
[1/15] example-org/EBS-E-7000-Store-Inventory-REST-API
  Found 8 PL/SQL security issues
[2/15] example-org/oracle-utilities
  Found 3 PL/SQL security issues
...

================================================================================
Scan Complete!
================================================================================
Total Repositories: 15
Successfully Scanned: 15
Failed: 0
Total PL/SQL Findings: 42
================================================================================
```

### Option 3: Standalone PL/SQL Scan

For ad-hoc scanning of a specific repository:

```bash
# Scan specific repo with PL/SQL rules
docker exec auditgh_api semgrep scan \
  --config /app/semgrep_plsql_rules.yml \
  --json \
  --output /tmp/plsql_results.json \
  /app/vulnerability_reports/example-org/EBS-E-7000-Store-Inventory-REST-API/

# View results
docker exec auditgh_api cat /tmp/plsql_results.json | jq '.results[] | {severity: .extra.severity, message: .extra.message, file: .path, line: .start.line}'
```

## Viewing Findings

### In Web UI

1. **Navigate to:** http://localhost:3000
2. **Select organization:** example-org
3. **Go to:** Repositories → Projects
4. **Click on repository:** e.g., EBS-E-7000-Store-Inventory-REST-API
5. **View SAST tab:** PL/SQL findings appear here with other SAST results

**Findings include:**
- **Title:** Rule ID (e.g., `plsql-sql-injection-execute-immediate`)
- **Severity:** Critical/High/Medium/Low
- **File:** Path to affected file
- **Line:** Exact line number
- **Code Snippet:** Vulnerable code
- **Description:** What the issue is and how to fix it
- **CWE/OWASP:** Security classification

### Via Database

```bash
# View all PL/SQL findings for a repository
docker exec auditgh_db psql -U postgres -d security_portal -c "
  SELECT
    f.severity,
    f.title,
    f.file_path,
    f.line_start,
    LEFT(f.description, 100) as description
  FROM findings f
  JOIN repositories r ON f.repository_id = r.id
  WHERE r.name = 'EBS-E-7000-Store-Inventory-REST-API'
    AND f.scanner_name = 'semgrep'
    AND f.finding_type = 'sast'
  ORDER BY
    CASE f.severity
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      ELSE 4
    END,
    f.file_path;
"

# Count PL/SQL findings by severity
docker exec auditgh_db psql -U postgres -d security_portal -c "
  SELECT
    o.github_org,
    r.name,
    f.severity,
    COUNT(*) as count
  FROM findings f
  JOIN repositories r ON f.repository_id = r.id
  JOIN organizations o ON r.organization_id = o.id
  WHERE f.scanner_name = 'semgrep'
    AND f.finding_type = 'sast'
    AND o.github_org = 'example-org'
  GROUP BY o.github_org, r.name, f.severity
  ORDER BY
    CASE f.severity
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      ELSE 4
    END,
    COUNT(*) DESC;
"
```

### Via API

```bash
# Get findings for a repository
curl http://localhost:8000/repositories/{repo_id}/findings?scanner=semgrep&type=sast | jq

# Filter by severity
curl http://localhost:8000/repositories/{repo_id}/findings?scanner=semgrep&severity=high | jq
```

## Customizing Rules

The PL/SQL security rules are defined in `semgrep_plsql_rules.yml`. You can customize them:

### Add New Rules

```yaml
# Add to semgrep_plsql_rules.yml
rules:
  - id: custom-plsql-rule
    pattern-regex: 'YOUR_PATTERN_HERE'
    message: |
      Your custom security message
    languages: [generic]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-XXX"
```

### Modify Severity

```yaml
# Change severity of existing rule
- id: plsql-weak-hash-md5
  pattern-regex: 'DBMS_CRYPTO\.HASH.*HASH_MD5'
  severity: ERROR  # Changed from WARNING to ERROR
```

### Disable Rules

Comment out rules you don't want:

```yaml
# Disabled rule
# - id: plsql-exception-information-disclosure
#   pattern-regex: 'SQLERRM|DBMS_UTILITY\.FORMAT_ERROR_STACK'
#   ...
```

## Oracle EBS Specific Considerations

### Recommended for Oracle EBS Environments

1. **Scan custom code** in `XXCUST` schemas and custom packages
2. **Review findings in:**
   - Custom procedures and functions
   - Custom concurrent programs
   - Custom triggers
   - Custom views and materialized views

3. **Common Oracle EBS issues detected:**
   - Hardcoded FND/APPS passwords
   - SQL injection in custom forms
   - Missing security checks in custom APIs
   - Weak encryption in data interfaces

### Example: EBS Store Inventory API

For `EBS-E-7000-Store-Inventory-REST-API`:

```bash
# Scan the repository
docker-compose run --rm scanner \
  --target example-org \
  --repo EBS-E-7000-Store-Inventory-REST-API

# View findings
# Navigate to: Repositories → Projects → EBS-E-7000-Store-Inventory-REST-API → SAST

# Expected findings might include:
# - SQL injection in dynamic queries
# - Hardcoded credentials in API authentication
# - Missing input validation in REST endpoints
# - Weak encryption in data exchange
```

## Best Practices

### For Development Teams

1. **Run scans before deployment:**
   ```bash
   docker-compose run --rm scanner --target example-org --repo YOUR_EBS_REPO
   ```

2. **Review findings in Web UI** under SAST tab

3. **Prioritize fixes by severity:**
   - **Critical/High:** Fix immediately (SQL injection, hardcoded passwords)
   - **Medium:** Fix before production deployment
   - **Low:** Address in regular maintenance cycles

4. **Use bind variables:**
   ```sql
   -- BAD: SQL injection risk
   EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = ' || p_user_id;

   -- GOOD: Use bind variables
   EXECUTE IMMEDIATE 'SELECT * FROM users WHERE id = :1' USING p_user_id;
   ```

5. **Secure credentials:**
   ```sql
   -- BAD: Hardcoded password
   v_password := 'mypassword123';

   -- GOOD: Use Oracle Wallet or secure vault
   v_password := get_password_from_wallet('app_user');
   ```

### For Security Teams

1. **Schedule regular scans:**
   - Daily: For active development repositories
   - Weekly: For all Oracle EBS repositories
   - Monthly: Comprehensive scans with all rules

2. **Track metrics:**
   - Number of PL/SQL vulnerabilities over time
   - Time to remediation
   - Repositories with most findings

3. **Integrate with ticketing:**
   - Export findings via API
   - Create tickets for critical issues
   - Track remediation progress

## Troubleshooting

### No findings appear

```bash
# Check if PL/SQL files were detected
docker exec auditgh_api ls -la /app/vulnerability_reports/example-org/EBS-E-7000-Store-Inventory-REST-API/*.sql

# Check if rules file exists
docker exec auditgh_api cat /app/semgrep_plsql_rules.yml | head -20

# Run manual scan with verbose output
docker exec auditgh_api semgrep scan \
  --config /app/semgrep_plsql_rules.yml \
  --verbose \
  /app/vulnerability_reports/example-org/EBS-E-7000-Store-Inventory-REST-API/
```

### Findings not showing in UI

```bash
# Check if findings are in database
docker exec auditgh_db psql -U postgres -d security_portal -c \
  "SELECT COUNT(*) FROM findings WHERE scanner_name = 'semgrep' AND finding_type = 'sast';"

# Re-run ingestion
docker exec auditgh_api python /app/ingest_reports.py

# Check API endpoint
curl http://localhost:8000/repositories | jq '.[] | select(.name == "EBS-E-7000-Store-Inventory-REST-API")'
```

### Scan errors

```bash
# Check Semgrep version
docker exec auditgh_api semgrep --version

# Validate rules file
docker exec auditgh_api semgrep scan --config /app/semgrep_plsql_rules.yml --validate

# Check logs
docker-compose logs scanner | grep -i "plsql\|semgrep"
```

## Performance

- **Scan speed:** ~100-500 files/second
- **Memory usage:** ~200MB per scan
- **Typical scan time:**
  - Small repo (< 50 files): < 10 seconds
  - Medium repo (50-200 files): 10-30 seconds
  - Large repo (> 200 files): 30-60 seconds

## Future Enhancements

Potential future additions:

1. **Oracle-specific SAST tools:**
   - CodeScan (commercial)
   - SonarQube PL/SQL plugin
   - Checkmarx for Oracle

2. **Dynamic analysis:**
   - SQL injection testing against database
   - Privilege escalation testing
   - Performance profiling

3. **Custom EBS rules:**
   - FND API security checks
   - Concurrent program validation
   - Custom form security

4. **Automated remediation:**
   - AI-powered fix suggestions
   - Auto-generate bind variable conversions
   - Security patch recommendations

## Support

For questions or issues with PL/SQL scanning:

1. Check [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
2. Review [CHEATSHEET.md](docs/CHEATSHEET.md) for command examples
3. File issue on GitHub with:
   - Repository name
   - Scan output
   - Expected vs actual behavior
