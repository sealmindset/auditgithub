# Architecture Generator CLI

Command-line tool to generate architecture diagrams and reports for repositories.

## Features

- ✅ Generates architecture diagrams and reports using AI
- ✅ Updates database with results (diagram code, report, image)
- ✅ Saves copies to `./generated_architectures/` folder with timestamped filenames
- ✅ **Uploads files to GitHub** - Commits and pushes to `.architecture/` folder in the repository
- ✅ **Batch processing** - Process multiple repositories matching a pattern
- ✅ Uses all the deterministic fixes for consistent results
- ✅ Works with repository names or UUIDs
- ✅ Works with Docker or local Python environment

## Installation

No additional installation needed. The script automatically detects and uses your environment:
- **Docker**: Runs inside the `api` container if Docker Compose is running
- **Local**: Uses your Python virtual environment if available

## Usage

### Single Repository

#### Option 1: Using the Shell Wrapper (Easiest)

```bash
./gen-arch.sh "Repository Name"
```

#### Option 2: Using Python Directly

```bash
python generate_architecture_cli.py "Repository Name"
```

#### Examples

```bash
# By repository name
./gen-arch.sh "EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR"

# By repository UUID
./gen-arch.sh "d4e5f6g7-8901-2345-6789-012345678901"

# With custom tenant (multi-tenant setups)
./gen-arch.sh "My Repo" "tenant-slug"
```

### Batch Processing (Multiple Repositories)

Process multiple repositories matching a pattern:

```bash
./gen-arch-batch.sh "<pattern>" [tenant_slug] [--skip-if-exists] [--delay=SECONDS]
```

#### Batch Examples

```bash
# Process all repositories with "-oic" in the name
./gen-arch-batch.sh "-oic"

# Process all repositories starting with "EBS-R-"
./gen-arch-batch.sh "EBS-R-"

# Process with specific tenant
./gen-arch-batch.sh "-oic" "tenant-slug"

# Skip repositories that already have architecture files
./gen-arch-batch.sh "-oic" --skip-if-exists

# Add 60-second delay between repos (RECOMMENDED for rate limiting)
./gen-arch-batch.sh "-oic" --delay=60

# Combine all options (recommended for large batches)
./gen-arch-batch.sh "-oic" --skip-if-exists --delay=30
```

#### Batch Processing Options

- `--skip-if-exists` - Skip repositories that already have all three architecture files in `.architecture/` folder (report.md, diagram.py, diagram.png)
- `--delay=SECONDS` - Wait specified seconds between processing repositories (recommended: 30-60 seconds)
  - **Important**: Helps avoid rate limits on both Azure AI Foundry API and GitHub API
  - For large batches (50+ repos), use `--delay=60` or higher
  - **Smart Delay**: Skipped repos automatically use 10-second delay instead of full delay (no API calls needed)

#### Batch Processing Features

- **Pattern Matching**: Case-insensitive search anywhere in repository name
- **Interactive Confirmation**: Shows matching repos and asks for confirmation before processing
- **Skip Existing**: Optionally skip repos that already have architecture documentation
- **Smart Rate Limiting**: Full delay for new generations, shorter delay (10s) for skipped repos
- **Progress Tracking**: Shows current progress (e.g., "Processing 3/51")
- **Error Handling**: Continues processing even if some repos fail
- **Summary Report**: Shows success/skipped/failure counts and lists all repos in each category
- **Sequential Processing**: Processes one repo at a time for reliability

## What It Does

1. **Finds the repository** in your database by name or UUID
2. **Clones the repository** to a temporary directory
3. **Analyzes the code structure** and configuration files
4. **Generates architecture report** using AI (Claude)
5. **Generates diagram code** (Python using diagrams library)
6. **Executes diagram code** to create PNG image
7. **Updates database** with all three artifacts
8. **Saves copies locally** to `./generated_architectures/` folder:
   - `{repo_name}_report_{timestamp}.md` - Markdown report
   - `{repo_name}_diagram_{timestamp}.py` - Python diagram code
   - `{repo_name}_diagram_{timestamp}.png` - Diagram image
9. **Commits and pushes to GitHub** - Creates `.architecture/` folder in the repository with:
   - `architecture_report.md` - Latest architecture report
   - `architecture_diagram.py` - Latest diagram code
   - `architecture_diagram.png` - Latest diagram image

## Output

Files are saved to the `./generated_architectures/` folder in your project directory with filenames like:

```
generated_architectures/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_report_20260127_143022.md
generated_architectures/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_diagram_20260127_143022.py
generated_architectures/EBS-R-6186-SC-OIC-Stores-With-a-Close-Date-in-HR_diagram_20260127_143022.png
```

This folder is accessible from both Docker containers and your host machine, and is automatically created if it doesn't exist.

## GitHub Integration

The CLI automatically commits and pushes the generated files to the repository's `.architecture/` folder:

- **Commit Message**: `Add architecture documentation` with timestamp and details
- **Branch**: Pushes to the current default branch (usually `main` or `master`)
- **Files Created**:
  - `.architecture/architecture_report.md` - Always updated with latest version
  - `.architecture/architecture_diagram.py` - Latest diagram code
  - `.architecture/architecture_diagram.png` - Latest diagram image
- **Authentication**: Uses the organization's GitHub token from secrets manager or environment variables
- **Behavior**:
  - If files already exist, they will be overwritten with the new version
  - If no changes are detected (identical content), no commit is created
  - If push fails, files are still saved locally and in the database

This allows team members to view the architecture documentation directly in GitHub without needing database access.

## Requirements

- Python 3.8+
- All project dependencies installed
- Database configured and running
- Repository must exist in the database
- Repository must have a valid Git URL

## Troubleshooting

### "Repository not found"
- Check that the repository exists in your database
- Try using the exact name as shown in the UI
- Or use the UUID from the database

### "Repository has no URL configured"
- The repository needs a valid Git URL in the database
- Update the repository record with a valid URL

### "AI Agent not initialized"
- Check your AI provider configuration in settings
- Ensure API keys are configured correctly

### "Failed to clone repository"
- Check that the Git URL is accessible
- Verify GitHub token is configured for the organization
- Check network connectivity

### "Diagram execution failed"
- The script will attempt an AI-powered fix automatically
- If that fails, the report and code are still saved
- You can manually fix the diagram code and re-run it

## Logs

The script outputs detailed logs showing:
- Repository being processed
- Clone progress
- Analysis steps
- Generation progress
- File save locations
- Any errors encountered

## Deterministic Generation

This script uses all the fixes implemented for deterministic generation:
- ✅ Sorted file system traversal
- ✅ Sorted configuration files
- ✅ Sorted diagrams index
- ✅ Temperature set to 0 for consistent AI output
- ✅ Sorted dictionary and set iterations

Running the script multiple times on the same repository should produce identical results (assuming no code changes in the repository between runs).

## Integration with Docker

If running the application in Docker, you can execute the CLI from outside Docker:

```bash
# The script connects directly to the database
# No need to enter the container
./gen-arch.sh "Repository Name"
```

Or from inside a Docker container:

```bash
docker-compose exec web python generate_architecture_cli.py "Repository Name"
```

## Notes

- The script requires an active database connection
- Temporary repository clones are cleaned up automatically
- All three artifacts (report, code, image) are saved even if one fails
- Database is always updated with the latest successful generation
- Files are timestamped to avoid overwriting previous generations
