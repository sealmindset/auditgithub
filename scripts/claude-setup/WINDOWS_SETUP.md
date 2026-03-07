# Claude CLI Setup — Windows Instructions

Follow these steps in order. If you run into any problems, the script will
create a log file on your Desktop — just send that file to IT support.

---

## Before You Start

Make sure you have these installed. If you're not sure, IT can help.

- **Azure CLI** — You should be able to type `az` in a terminal
- **Claude CLI** — You should be able to type `claude` in a terminal
- **The setup script** — You need the file `setup_claude_single.ps1`

---

## Step-by-Step Instructions

### Step 1: Open PowerShell

1. Click the **Start menu** (Windows icon, bottom-left of your screen)
2. Type **PowerShell**
3. Click **Windows PowerShell** from the search results
   - You do **not** need "Run as Administrator"
   - Do **not** use "Command Prompt" — it must be PowerShell

You should see a blue or black window with a blinking cursor.

---

### Step 2: Go to the folder where the script is saved

If you downloaded the script to your **Downloads** folder, type this and press **Enter**:

```
cd ~\Downloads
```

If IT gave you a different location, use that instead. For example:

```
cd C:\path\to\where\the\script\is
```

> **Tip:** You can also type `cd ` (with a space after it), then drag and drop
> the folder from File Explorer into the PowerShell window. It will fill in the
> path for you.

---

### Step 3: Allow the script to run

Windows may block scripts by default. Type this and press **Enter**:

```
Set-ExecutionPolicy -Scope Process Bypass
```

- This only applies to **this PowerShell window**
- It resets automatically when you close the window
- It does **not** change any system settings

If you see a confirmation prompt, type **Y** and press **Enter**.

---

### Step 4: Run the setup script

Type this and press **Enter**:

```
.\setup_claude_single.ps1
```

The script will now:

1. Check that Azure CLI is installed
2. Check if you're signed into Azure
3. Create your configuration files
4. Generate your access token
5. Test the setup

**If you see a browser window pop up**, that's Azure asking you to sign in.
Sign in with your work email and password, then come back to the PowerShell
window. The script will continue automatically.

---

### Step 5: Check the result

**If you see "SETUP COMPLETE — You're all set!" in green:**

You're done! Move on to Step 6.

**If you see errors or warnings in red/yellow:**

The script has saved a diagnostic log file to your **Desktop** called
something like `claude-setup-log-20260307-143022.txt`.

1. Find that file on your Desktop
2. Email it to your IT support team (or attach it to a support ticket)
3. IT will have all the details they need to help you

---

### Step 6: Start using Claude CLI

If you already had Claude CLI open, **close it and reopen it** so it picks up
the new configuration.

Open a new PowerShell window (or your preferred terminal) and type:

```
claude
```

You should be connected and ready to go.

---

## Troubleshooting

### "The term 'az' is not recognized"

Azure CLI is not installed. Ask IT to install it for you, or install it
yourself:

1. Open a browser
2. Go to https://aka.ms/installazurecliwindows
3. Download and run the installer
4. Close and reopen PowerShell
5. Try the setup script again

### "running scripts is disabled on this system"

You skipped Step 3. Go back and run:

```
Set-ExecutionPolicy -Scope Process Bypass
```

Then try the script again.

### "Not logged into Azure"

The script will try to open a browser for you to sign in. If that doesn't
work:

1. In PowerShell, type: `az login`
2. Sign in with your work email and password in the browser
3. Come back to PowerShell and run the setup script again

### The script seems stuck or frozen

- If a browser window opened, switch to it and complete the sign-in
- If no browser opened, press **Ctrl+C** to cancel, then try again
- If it keeps getting stuck, run with the `-SkipToken` flag to skip token
  generation (IT can help with the token later):

```
.\setup_claude_single.ps1 -SkipToken
```

### I need to run the script again

That's fine. The script backs up your old settings before creating new ones.
Just repeat Steps 3 and 4.

---

## Quick Reference

| What you type                                | What it does                       |
|----------------------------------------------|------------------------------------|
| `Set-ExecutionPolicy -Scope Process Bypass`  | Allow scripts in this window       |
| `.\setup_claude_single.ps1`                  | Run the setup                      |
| `.\setup_claude_single.ps1 -SkipToken`       | Run setup without generating token |
| `claude`                                     | Start Claude CLI                   |
| `claude --version`                           | Check Claude CLI is working        |
| `az login`                                   | Sign into Azure manually           |
