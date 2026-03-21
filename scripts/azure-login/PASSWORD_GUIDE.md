# Secure Password Handling Guide

## Overview

The Azure login script now supports secure password handling via the `--auto-password` flag. This provides a more secure and automated approach compared to manual browser entry.

## Usage Options

### Option 1: Manual Password Entry (Default)

```bash
python az_login.py
```

**How it works:**
- Browser opens and displays a password prompt
- You manually type your password in the browser window
- Script waits for you to complete authentication

**Pros:**
- No password touching the terminal
- Familiar browser interface

**Cons:**
- Requires manual interaction
- Slower process

---

### Option 2: Secure Auto-Fill (Recommended)

```bash
python az_login.py --auto-password
```

**How it works:**
1. Script prompts: `Enter password for admin@company.example:`
2. You type your password (characters are hidden - no echo)
3. Script automatically fills the password in the browser
4. Password is cleared from memory after use

**Pros:**
- Faster automation
- Password never stored in files/scripts
- No echo to terminal (secure input)
- Password only in memory during execution

**Cons:**
- Password entered in terminal session (check for shoulder surfers)

---

## Security Features

### What We Do
✅ Use Python's `getpass` module for secure, non-echoing input
✅ Password stays in memory only during script execution
✅ No password storage in files, environment variables, or logs
✅ Password is cleared when script exits

### What We Don't Do
❌ Never store passwords in plaintext files
❌ Never log passwords to console or files
❌ Never pass passwords as command-line arguments (visible in process list)
❌ Never use environment variables for passwords

---

## Example Commands

```bash
# Basic usage with auto-password
python az_login.py --auto-password

# With custom email and subscription
python az_login.py --auto-password \
  --email user@company.com \
  --subscription "my-subscription"

# With debug logging
python az_login.py --auto-password --debug

# Without auto-password (manual entry in browser)
python az_login.py
```

---

## Environment Variables

You can set default values to avoid typing them each time:

```bash
export AZURE_LOGIN_EMAIL="admin@company.example"
export AZURE_SUBSCRIPTION="my-azure-subscription"
export AZURE_MFA_TIMEOUT="300"

# Then simply run:
python az_login.py --auto-password
```

**Note:** Never set `AZURE_PASSWORD` as an environment variable!

---

## Troubleshooting

### "Password cannot be empty"
You pressed Enter without typing a password. Try again and enter your password.

### "Password prompt cancelled"
You pressed Ctrl+C during password entry. This is safe - the script exits cleanly.

### Password auto-fill fails
- Check that the browser fully loaded the password page
- Increase `--slow-mo` value: `python az_login.py --auto-password --slow-mo 1000`
- Check debug logs with `--debug` flag

---

## Best Practices

1. **Use `--auto-password` for automation** - Faster and still secure
2. **Check your surroundings** - Ensure no one can see your screen when entering password
3. **Use MFA** - Always enable multi-factor authentication on your Azure account
4. **Verify the script** - Review the source code to ensure it's trustworthy
5. **Keep the venv secure** - The virtual environment should not be world-readable

---

## Technical Details

### How Password is Handled

```python
# Password prompt (secure, no echo)
password = getpass.getpass("Enter password: ")

# Password used in memory only
page.locator('input[type="password"]').fill(password)

# Password cleared when script exits (Python garbage collection)
# No explicit clearing needed - it goes out of scope
```

### Memory Safety

The password:
- Is stored as a Python string in local scope
- Is passed by reference (not copied unnecessarily)
- Is garbage collected when the function returns
- Is never written to disk or logs

---

## Security Comparison

| Method | Security | Convenience | Automation |
|--------|----------|-------------|------------|
| Manual browser entry | ⭐⭐⭐⭐ | ⭐⭐ | ❌ |
| `--auto-password` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ✅ |
| Stored in file | ❌ NEVER | ⭐⭐⭐⭐⭐ | ✅ |
| Command-line arg | ❌ NEVER | ⭐⭐⭐ | ✅ |
| Environment variable | ⭐ NOT RECOMMENDED | ⭐⭐⭐⭐ | ✅ |

**Recommendation:** Use `--auto-password` for the best balance of security and convenience.
