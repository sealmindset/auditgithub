Example:

[+] Creating 1/1
 ✔ Container auditgh_db  Running                                                                                                                                                                 0.0s 
[auditgh] Starting scan_repos.py ...
INFO:root:⚡ Override scan enabled - all skip logic disabled, will scan every repository
INFO:src.knowledge_base:Connected to Knowledge Base (PostgreSQL)
INFO:src.knowledge_base:Remediations table uses new schema (managed by API) - disabling knowledge base cache
INFO:root:Temporary directory for cloning: /tmp/repo_scan_0kj9kd67
INFO:root:Reports will be saved to: /app/vulnerability_reports
INFO:root:Single repository mode: -EBS-F-7005-AP-UPD-PYMT-METHOD
INFO:root:Fetching repository: sleepnumberinc/-EBS-F-7005-AP-UPD-PYMT-METHOD
WARNING:root:Repository name '-EBS-F-7005-AP-UPD-PYMT-METHOD' starts with hyphen. This may cause issues with GitHub API.
INFO:root:Processing repository: -EBS-F-7005-AP-UPD-PYMT-METHOD
WARNING:root:⚠️  -EBS-F-7005-AP-UPD-PYMT-METHOD: Repository name starts with hyphen (needs quoting for CLI) - will process with safe argument handling
INFO:root:⚡ Scanning -EBS-F-7005-AP-UPD-PYMT-METHOD: Override scan enabled
...
WARNING:root:Empty response body for SleepNumberInc/-EBS-F-7005-AP-UPD-PYMT-METHOD (status 204). Skipping contributors.
INFO:root:Completed processing repository: -EBS-F-7005-AP-UPD-PYMT-METHOD

Problem:
Despite the DOE/Self-annealing capabilities, the scans are halted indifintely despite indications that the scan was completed.

Create a prompt for Claude Sonnet 4.5 or Gemini 3.0 Pro that will resolve the issues with repos having problematic names (like leading hyphens). Devise a thorough and comprehensive method to hand the repo's name so to allow the scan to still be fully completed, even using AI Agent to do the work and manage the entire process (self-annealing.) Write the prompt into directives/ as 'nameschema.md'
