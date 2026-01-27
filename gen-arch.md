# How to Use
## Quick Start

### Navigate to your project directory
```
cd <path to>/auditgithub
```
### Run for a repository (by name)
```
./gen-arch.sh "EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR" "org"
```

### Or by UUID
```
./gen-arch.sh "d4e5f6g7-8901-2345-6789-012345678901"
```

## What It Does
✅ Finds the repository in your database
✅ Clones and analyzes the repository
✅ Generates architecture report using AI
✅ Generates diagram code (Python)
✅ Executes code to create PNG image
✅ Updates database with all three artifacts
✅ Saves copies to ~/Downloads/ with timestamped filenames:
    - {repo_name}_report_{timestamp}.md
    - {repo_name}_diagram_{timestamp}.py
    - {repo_name}_diagram_{timestamp}.png

## Features
 - Uses all the deterministic fixes we implemented
 - Automatic error recovery with AI-powered diagram fixing
 - Detailed logging of all steps
 - Automatic cleanup of temporary files
 - Works with repository names or UUIDs
 - Multi-tenant support (optional second argument)

## Example Output
```
========================================
Architecture Generation CLI
========================================
Repository: EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR
Tenant: default
========================================
Found repository: EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR (ID: ...)
Cloning repository...
Analyzing repository structure...
Generating architecture report and diagram code...
Executing diagram code to generate image...
Updating database...
Report saved to: /Users/rob.vance@sleepnumber.com/Downloads/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_report_20260127_143022.md
Diagram code saved to: /Users/rob.vance@sleepnumber.com/Downloads/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_diagram_20260127.py
Diagram image saved to: /Users/rob.vance@sleepnumber.com/Downloads/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_diagram_20260127.png
========================================
SUCCESS! Architecture generation completed.
========================================
```