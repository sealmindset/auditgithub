<#
.SYNOPSIS
    Claude CLI Setup - Single Script Automation (Windows)

.DESCRIPTION
    This script handles the complete Claude CLI setup in one file:
    - Creates ~/.claude directory if it doesn't exist
    - Creates get-claude-token.ps1 if it doesn't exist
    - Creates/updates settings.json (with backup if exists)
    - Generates token and saves to claudekey.txt
    - Tests the setup

    On failure, a diagnostic log is automatically saved to the user's Desktop
    so they can send it to IT support.

.PARAMETER BaseUrl
    Anthropic Foundry base URL. Default: https://snapistg-scus.azure.sleepnumber.com/anthropic

.PARAMETER SonnetModel
    Sonnet model name. Default: cogdep-aifoundry-dev-eus2-claude-sonnet-4-5

.PARAMETER HaikuModel
    Haiku model name. Default: cogdep-aifoundry-dev-eus2-claude-haiku-4-5

.PARAMETER OpusModel
    Opus model name. Default: cogdep-aifoundry-dev-eus2-claude-opus-4-6

.PARAMETER SkipToken
    Skip token generation (setup configuration only).

.PARAMETER Debug
    Enable debug logging.

.EXAMPLE
    .\setup_claude_single.ps1

.EXAMPLE
    .\setup_claude_single.ps1 -SkipToken

.EXAMPLE
    .\setup_claude_single.ps1 -BaseUrl "https://custom.url.com" -Debug
#>

param(
    [string]$BaseUrl = "https://snapistg-scus.azure.sleepnumber.com/anthropic",
    [string]$SonnetModel = "cogdep-aifoundry-dev-eus2-claude-sonnet-4-5",
    [string]$HaikuModel = "cogdep-aifoundry-dev-eus2-claude-haiku-4-5",
    [string]$OpusModel = "cogdep-aifoundry-dev-eus2-claude-opus-4-6",
    [switch]$SkipToken,
    [switch]$DebugLog
)

# ============================================================================
# Configuration
# ============================================================================

$ClaudeDir      = Join-Path $env:USERPROFILE ".claude"
$TokenScript    = Join-Path $ClaudeDir "get-claude-token.ps1"
$SettingsFile   = Join-Path $ClaudeDir "settings.json"
$TokenFile      = Join-Path $ClaudeDir "claudekey.txt"

# Use env vars as overrides if set
if ($env:ANTHROPIC_FOUNDRY_BASE_URL)       { $BaseUrl      = $env:ANTHROPIC_FOUNDRY_BASE_URL }
if ($env:ANTHROPIC_DEFAULT_SONNET_MODEL)   { $SonnetModel  = $env:ANTHROPIC_DEFAULT_SONNET_MODEL }
if ($env:ANTHROPIC_DEFAULT_HAIKU_MODEL)    { $HaikuModel   = $env:ANTHROPIC_DEFAULT_HAIKU_MODEL }
if ($env:ANTHROPIC_DEFAULT_OPUS_MODEL)     { $OpusModel    = $env:ANTHROPIC_DEFAULT_OPUS_MODEL }

$HasErrors   = $false
$HasWarnings = $false
$StepLog     = [System.Collections.Generic.List[string]]::new()
$DiagLog     = [System.Collections.Generic.List[string]]::new()
$DiagLogFile = ""

# Save original args for diagnostic log
$OriginalArgs = $PSBoundParameters | Out-String

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Ok {
    param([string]$Message)
    Write-Host "  " -NoNewline
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host " $Message"
    $script:StepLog.Add("[OK]      $Message")
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  " -NoNewline
    Write-Host "[!!]" -ForegroundColor Yellow -NoNewline
    Write-Host " $Message"
    $script:StepLog.Add("[WARNING] $Message")
    $script:HasWarnings = $true
}

function Write-Err {
    param([string]$Message)
    Write-Host "  " -NoNewline
    Write-Host "[XX]" -ForegroundColor Red -NoNewline
    Write-Host " $Message"
    $script:StepLog.Add("[ERROR]   $Message")
    $script:HasErrors = $true
}

function Write-Dbg {
    param([string]$Message)
    if ($DebugLog) {
        Write-Host "  " -NoNewline
        Write-Host "[DBG]" -ForegroundColor Cyan -NoNewline
        Write-Host " $Message"
    }
    $script:StepLog.Add("[DEBUG]   $Message")
}

function Write-Step {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor White
}

# ============================================================================
# Diagnostic Log
# ============================================================================

function Collect-Diagnostics {
    $d = $script:DiagLog

    $d.Add("===============================================================================")
    $d.Add("CLAUDE CLI SETUP - DIAGNOSTIC LOG (Windows)")
    $d.Add("===============================================================================")
    $d.Add("")
    $d.Add("Generated:  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')")
    $d.Add("Script:     $($MyInvocation.ScriptName)")
    $d.Add("Arguments:  $OriginalArgs")
    $d.Add("")

    # --- System Info ---
    $d.Add("--- SYSTEM INFO ---")
    $d.Add("Computer:   $env:COMPUTERNAME")
    $d.Add("OS:         $([System.Environment]::OSVersion.VersionString)")
    $d.Add("PS Version: $($PSVersionTable.PSVersion)")
    $d.Add("PS Edition: $($PSVersionTable.PSEdition)")
    $d.Add("User:       $env:USERNAME")
    $d.Add("Home:       $env:USERPROFILE")
    $d.Add("Arch:       $env:PROCESSOR_ARCHITECTURE")
    $d.Add("")

    # --- Azure CLI ---
    $d.Add("--- AZURE CLI ---")
    $azPath = Get-Command az -ErrorAction SilentlyContinue
    if ($azPath) {
        $d.Add("Installed:  YES")
        $d.Add("Location:   $($azPath.Source)")
        try {
            $azVer = az --version 2>&1 | Select-Object -First 5
            $d.Add("Version:")
            foreach ($line in $azVer) { $d.Add("    $line") }
        } catch {
            $d.Add("Version:    (could not retrieve)")
        }
        $d.Add("")
        try {
            $null = az account show 2>$null
            if ($LASTEXITCODE -eq 0) {
                $d.Add("Logged in:  YES")
                $acct = az account show 2>&1
                foreach ($line in $acct) { $d.Add("    $line") }
            } else {
                $d.Add("Logged in:  NO")
            }
        } catch {
            $d.Add("Logged in:  ERROR checking ($($_.Exception.Message))")
        }
    } else {
        $d.Add("Installed:  NO")
    }
    $d.Add("")

    # --- Claude CLI ---
    $d.Add("--- CLAUDE CLI ---")
    $claudePath = Get-Command claude -ErrorAction SilentlyContinue
    if ($claudePath) {
        $d.Add("Installed:  YES")
        $d.Add("Location:   $($claudePath.Source)")
        try {
            $d.Add("Version:    $(claude --version 2>&1)")
        } catch {
            $d.Add("Version:    (could not retrieve)")
        }
    } else {
        $d.Add("Installed:  NO")
    }
    $d.Add("")

    # --- Node/npm ---
    $d.Add("--- NODE/NPM ---")
    $nodePath = Get-Command node -ErrorAction SilentlyContinue
    if ($nodePath) {
        $d.Add("Node:       $(node --version 2>&1)")
    } else {
        $d.Add("Node:       NOT INSTALLED")
    }
    $npmPath = Get-Command npm -ErrorAction SilentlyContinue
    if ($npmPath) {
        $d.Add("npm:        $(npm --version 2>&1)")
    } else {
        $d.Add("npm:        NOT INSTALLED")
    }
    $d.Add("")

    # --- Configuration ---
    $d.Add("--- CONFIGURATION ---")
    $d.Add("Base URL:      $BaseUrl")
    $d.Add("Sonnet Model:  $SonnetModel")
    $d.Add("Haiku Model:   $HaikuModel")
    $d.Add("Opus Model:    $OpusModel")
    $d.Add("Skip Token:    $SkipToken")
    $d.Add("")

    # --- File State ---
    $d.Add("--- FILE STATE ---")
    $d.Add("~/.claude/ exists:          $(Test-Path $ClaudeDir)")
    if (Test-Path $ClaudeDir) {
        $d.Add("~/.claude/ contents:")
        Get-ChildItem $ClaudeDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $d.Add("    $($_.Mode)  $($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $($_.Length.ToString().PadLeft(10))  $($_.Name)")
        }
    }
    $d.Add("")

    $d.Add("settings.json exists:       $(Test-Path $SettingsFile)")
    if (Test-Path $SettingsFile) {
        $d.Add("settings.json content:")
        Get-Content $SettingsFile -ErrorAction SilentlyContinue | ForEach-Object { $d.Add("    $_") }
    }
    $d.Add("")

    $d.Add("get-claude-token.ps1 exists: $(Test-Path $TokenScript)")
    $d.Add("")

    $d.Add("claudekey.txt exists:       $(Test-Path $TokenFile)")
    if (Test-Path $TokenFile) {
        $size = (Get-Item $TokenFile -ErrorAction SilentlyContinue).Length
        $d.Add("claudekey.txt size:         $size bytes")
    }
    $d.Add("")

    # --- Environment Variables ---
    $d.Add("--- ENVIRONMENT VARIABLES ---")
    $d.Add("ANTHROPIC_FOUNDRY_BASE_URL:     $($env:ANTHROPIC_FOUNDRY_BASE_URL ?? '(not set)')")
    $d.Add("ANTHROPIC_DEFAULT_SONNET_MODEL: $($env:ANTHROPIC_DEFAULT_SONNET_MODEL ?? '(not set)')")
    $d.Add("ANTHROPIC_DEFAULT_HAIKU_MODEL:  $($env:ANTHROPIC_DEFAULT_HAIKU_MODEL ?? '(not set)')")
    $d.Add("ANTHROPIC_DEFAULT_OPUS_MODEL:   $($env:ANTHROPIC_DEFAULT_OPUS_MODEL ?? '(not set)')")
    $d.Add("CLAUDE_CODE_USE_FOUNDRY:        $($env:CLAUDE_CODE_USE_FOUNDRY ?? '(not set)')")
    $d.Add("")

    # --- Execution Policy ---
    $d.Add("--- POWERSHELL EXECUTION POLICY ---")
    try {
        $policies = Get-ExecutionPolicy -List 2>&1
        foreach ($line in ($policies | Out-String -Stream)) { $d.Add("    $line") }
    } catch {
        $d.Add("    (could not retrieve)")
    }
    $d.Add("")

    # --- Step Log ---
    $d.Add("--- SETUP STEP LOG ---")
    foreach ($entry in $script:StepLog) { $d.Add("    $entry") }
    $d.Add("")
    $d.Add("===============================================================================")
    $d.Add("END OF DIAGNOSTIC LOG")
    $d.Add("===============================================================================")
}

function Save-DiagnosticLog {
    Collect-Diagnostics

    # Pick a location the user can easily find
    $desktop = [System.Environment]::GetFolderPath("Desktop")
    if (-not $desktop -or -not (Test-Path $desktop)) {
        $desktop = $env:USERPROFILE
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $script:DiagLogFile = Join-Path $desktop "claude-setup-log-$timestamp.txt"

    try {
        $script:DiagLog | Out-File -FilePath $script:DiagLogFile -Encoding UTF8
    } catch {
        # Fallback to temp
        $script:DiagLogFile = Join-Path $env:TEMP "claude-setup-log-$timestamp.txt"
        $script:DiagLog | Out-File -FilePath $script:DiagLogFile -Encoding UTF8
    }
}

# ============================================================================
# Display Functions
# ============================================================================

function Show-Header {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "              CLAUDE CLI SETUP AUTOMATION (Windows)            " -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  Base URL:     $BaseUrl"
    Write-Host "  Sonnet Model: $SonnetModel"
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Success {
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "   SETUP COMPLETE - You're all set!" -ForegroundColor Green
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host "  Directory:    $ClaudeDir"
    Write-Host "  Token Script: get-claude-token.ps1"
    Write-Host "  Settings:     settings.json"
    Write-Host "  Token File:   claudekey.txt"
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host "  Next Steps:"
    Write-Host "  1. Test your setup: claude --version"
    Write-Host "  2. Start coding:    claude"
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Green
    Write-Host ""
}

function Show-Failure {
    Save-DiagnosticLog

    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host ""
    if ($script:HasErrors) {
        Write-Host "   SETUP DID NOT COMPLETE SUCCESSFULLY" -ForegroundColor Red
    } else {
        Write-Host "   SETUP COMPLETED WITH WARNINGS" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "   A diagnostic log has been saved to your Desktop." -ForegroundColor White
    Write-Host ""
    Write-Host "   Please send this file to IT support:" -ForegroundColor White
    Write-Host ""
    Write-Host "     $(Split-Path $script:DiagLogFile -Leaf)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Location:" -ForegroundColor White
    Write-Host "     $($script:DiagLogFile)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "   What to do:" -ForegroundColor White
    Write-Host ""
    Write-Host "   1. Find the file on your Desktop"
    Write-Host "      (or the location shown above)"
    Write-Host ""
    Write-Host "   2. Email it to your IT support team, or attach"
    Write-Host "      it to a support ticket"
    Write-Host ""
    Write-Host "   3. IT will have everything they need to help you"
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Red
    Write-Host ""
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

function Test-AzureCli {
    Write-Step "Pre-flight Checks"

    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if (-not $azCmd) {
        Write-Err "Azure CLI (az) is not installed on this computer."
        return $false
    }

    try {
        $version = (az --version 2>&1 | Select-Object -First 1)
        Write-Ok "Found: $version"
    } catch {
        Write-Ok "Azure CLI found (could not read version)"
    }
    return $true
}

function Test-AzureLogin {
    try {
        $null = az account show 2>$null
        if ($LASTEXITCODE -eq 0) {
            $user = az account show --query user.name -o tsv 2>$null
            Write-Ok "Logged in as: $user"
        } else {
            Write-Warn "Not logged into Azure. You may be prompted to sign in."
        }
    } catch {
        Write-Warn "Could not check Azure login status."
    }
}

function Test-ClaudeCli {
    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($claudeCmd) {
        try {
            $version = claude --version 2>&1
            Write-Ok "Claude CLI found: $version"
        } catch {
            Write-Ok "Claude CLI found (could not read version)"
        }
    } else {
        Write-Warn "Claude CLI is not installed yet."
    }
}

# ============================================================================
# Setup Functions
# ============================================================================

function New-ClaudeDirectory {
    Write-Step "Step 1: Create .claude Directory"

    if (Test-Path $ClaudeDir) {
        Write-Dbg "Directory already exists: $ClaudeDir"
    } else {
        try {
            New-Item -ItemType Directory -Path $ClaudeDir -Force | Out-Null
            Write-Dbg "Created directory: $ClaudeDir"
        } catch {
            Write-Err "Could not create the configuration folder: $ClaudeDir"
            return $false
        }
    }

    Write-Ok "Directory ready: $ClaudeDir"
    return $true
}

function New-TokenScript {
    Write-Step "Step 2: Create Token Script"

    # Backup existing script
    if (Test-Path $TokenScript) {
        Write-Dbg "Token script already exists, will overwrite"
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Copy-Item $TokenScript "${TokenScript}.backup.${timestamp}" -ErrorAction SilentlyContinue
        Write-Dbg "Backed up existing script"
    }

    $tokenScriptContent = @'
# Check if already logged in to Azure CLI
$null = az account get-access-token 2>$null
if ($LASTEXITCODE -ne 0) {
    # Not logged in, so login
    az login | Out-Null
}
# Get access token for Azure Cognitive Services
az account get-access-token --resource "https://cognitiveservices.azure.com" --query accessToken -o tsv
'@

    try {
        Set-Content -Path $TokenScript -Value $tokenScriptContent -Encoding UTF8
        Write-Ok "Token script created: $TokenScript"
    } catch {
        Write-Err "Could not create the token script: $TokenScript"
        return $false
    }

    return $true
}

function New-SettingsJson {
    Write-Step "Step 3: Create Settings File"

    # Backup existing settings
    if (Test-Path $SettingsFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        Copy-Item $SettingsFile "${SettingsFile}.backup.${timestamp}" -ErrorAction SilentlyContinue
        Write-Ok "Backed up existing settings"
    }

    # Build the apiKeyHelper with the actual user path
    $escapedTokenScript = $TokenScript -replace '\\', '\\\\'
    $apiKeyHelper = "powershell -ExecutionPolicy Bypass -File $escapedTokenScript"

    $settings = @{
        apiKeyHelper = $apiKeyHelper
        env = @{
            CLAUDE_CODE_USE_FOUNDRY        = "1"
            ANTHROPIC_FOUNDRY_BASE_URL     = $BaseUrl
            ANTHROPIC_DEFAULT_SONNET_MODEL = $SonnetModel
            ANTHROPIC_DEFAULT_HAIKU_MODEL  = $HaikuModel
            ANTHROPIC_DEFAULT_OPUS_MODEL   = $OpusModel
        }
    }

    try {
        $json = $settings | ConvertTo-Json -Depth 3
        Set-Content -Path $SettingsFile -Value $json -Encoding UTF8
        Write-Ok "Settings file created: $SettingsFile"

        if ($DebugLog) {
            Write-Dbg "Settings content:"
            $json -split "`n" | ForEach-Object { Write-Host "    $_" }
        }
    } catch {
        Write-Err "Could not create the settings file: $SettingsFile"
        return $false
    }

    return $true
}

function New-Token {
    Write-Step "Step 4: Generate Token"

    if ($SkipToken) {
        Write-Ok "Token generation skipped (-SkipToken flag)"
        return
    }

    Write-Dbg "Executing token script..."

    try {
        $tokenOutput = powershell -ExecutionPolicy Bypass -File $TokenScript 2>&1
        $token = ($tokenOutput | Where-Object { $_ -is [string] -or $_ -is [System.Management.Automation.PSObject] }) |
                 Out-String |
                 ForEach-Object { $_.Trim() }

        # Separate actual errors from stdout
        $tokenErrors = $tokenOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }

        if ($LASTEXITCODE -ne 0 -or $tokenErrors) {
            $errMsg = ($tokenErrors | Out-String).Trim()
            Write-Warn "Token generation failed."
            $script:StepLog.Add("[DETAIL]  Token error output: $errMsg")
            Write-Host "    You can generate it manually later with:"
            Write-Host "    powershell -ExecutionPolicy Bypass -File `"$TokenScript`""
            return
        }

        if ([string]::IsNullOrWhiteSpace($token)) {
            Write-Warn "Token generation returned an empty result."
            Write-Host "    You can generate it manually later with:"
            Write-Host "    powershell -ExecutionPolicy Bypass -File `"$TokenScript`""
            return
        }

        # Save token with restricted permissions
        Set-Content -Path $TokenFile -Value $token -Encoding UTF8

        # Restrict permissions — owner only
        try {
            $acl = Get-Acl $TokenFile
            $acl.SetAccessRuleProtection($true, $false)
            $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $owner, "FullControl", "Allow"
            )
            $acl.SetAccessRule($rule)
            Set-Acl -Path $TokenFile -AclObject $acl
        } catch {
            Write-Dbg "Could not restrict token file permissions: $($_.Exception.Message)"
        }

        $tokenLen = $token.Length
        Write-Ok "Token generated and saved to: $TokenFile"
        Write-Dbg "Token length: $tokenLen characters"
        if ($tokenLen -gt 40) {
            Write-Dbg "Token preview: $($token.Substring(0,20))...$($token.Substring($tokenLen - 20))"
        }
    } catch {
        Write-Warn "Token generation failed: $($_.Exception.Message)"
        Write-Host "    You can generate it manually later with:"
        Write-Host "    powershell -ExecutionPolicy Bypass -File `"$TokenScript`""
    }
}

function Test-Setup {
    Write-Step "Step 5: Test Setup"

    $claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
    if ($claudeCmd) {
        try {
            $version = claude --version 2>&1
            Write-Ok "Claude CLI test passed: $version"
        } catch {
            Write-Ok "Claude CLI found (could not read version)"
        }
    } else {
        Write-Dbg "Claude CLI not found (already reported in pre-flight)"
    }
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Show-Header

    # Pre-flight checks — Azure CLI is required, the rest are warnings
    if (-not (Test-AzureCli)) {
        Show-Failure
        exit 1
    }
    Test-AzureLogin
    Test-ClaudeCli

    # Setup steps — directory and file writes are required
    if (-not (New-ClaudeDirectory)) {
        Show-Failure
        exit 1
    }

    if (-not (New-TokenScript)) {
        Show-Failure
        exit 1
    }

    if (-not (New-SettingsJson)) {
        Show-Failure
        exit 1
    }

    New-Token
    Test-Setup

    # Final result
    if ($script:HasErrors -or $script:HasWarnings) {
        Show-Failure
        if ($script:HasErrors) {
            exit 1
        }
    } else {
        Show-Success
    }
}

Main
