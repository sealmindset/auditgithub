# Claude CLI Setup — macOS Instructions

Follow these steps in order. If you run into any problems, the script will
create a log file on your Desktop — just send that file to IT support.

---

## Before You Start

Make sure you have these installed. If you're not sure, IT can help.

- **Azure CLI** — You should be able to type `az` in a terminal
- **Claude CLI** — You should be able to type `claude` in a terminal
- **The setup script** — You need the file `setup_claude_single.sh`

---

## Step-by-Step Instructions

### Step 1: Open Terminal

1. Click the **magnifying glass** icon in the top-right corner of your screen
   (or press **Command + Space**)
2. Type **Terminal**
3. Click **Terminal** from the search results

You should see a window with a blinking cursor.

---

### Step 2: Go to the folder where the script is saved

If you downloaded the script to your **Downloads** folder, type this and press **Return**:

```
cd ~/Downloads
```

If IT gave you a different location, use that instead. For example:

```
cd /path/to/where/the/script/is
```

> **Tip:** You can also type `cd ` (with a space after it), then drag and drop
> the folder from Finder into the Terminal window. It will fill in the path
> for you.

---

### Step 3: Make the script executable

The first time you run the script, you need to give it permission to execute.
Type this and press **Return**:

```
chmod +x setup_claude_single.sh
```

- You only need to do this **once**
- If you've already done it before, running it again is harmless

---

### Step 4: Run the setup script

Type this and press **Return**:

```
./setup_claude_single.sh
```

The script will now:

1. Check that Azure CLI is installed
2. Check if you're signed into Azure
3. Create your configuration files
4. Generate your access token
5. Test the setup

**If you see a browser window pop up**, that's Azure asking you to sign in.
Sign in with your work email and password, then come back to the Terminal
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

Open a new Terminal window and type:

```
claude
```

You should be connected and ready to go.

---

## Troubleshooting

### "Azure CLI (az) is not installed on this computer"

Azure CLI is not installed. Ask IT to install it for you, or install it
yourself:

1. Open Terminal
2. Type: `brew install azure-cli`
3. Press **Return** and wait for it to finish
4. Try the setup script again

If you see "brew: command not found", Homebrew is not installed either.
Ask IT for help, or install Homebrew first by visiting https://brew.sh

### "permission denied: ./setup_claude_single.sh"

You skipped Step 3. Go back and run:

```
chmod +x setup_claude_single.sh
```

Then try the script again.

### "Not logged into Azure"

The script will try to open a browser for you to sign in. If that doesn't
work:

1. In Terminal, type: `az login`
2. Sign in with your work email and password in the browser
3. Come back to Terminal and run the setup script again

### The script seems stuck or frozen

- If a browser window opened, switch to it and complete the sign-in
- If no browser opened, press **Control + C** to cancel, then try again
- If it keeps getting stuck, run with the `--skip-token` flag to skip token
  generation (IT can help with the token later):

```
./setup_claude_single.sh --skip-token
```

### I need to run the script again

That's fine. The script backs up your old settings before creating new ones.
Just repeat Step 4.

---

## Quick Reference

| What you type                              | What it does                       |
|--------------------------------------------|------------------------------------|
| `chmod +x setup_claude_single.sh`         | Allow the script to run (once)     |
| `./setup_claude_single.sh`                | Run the setup                      |
| `./setup_claude_single.sh --skip-token`   | Run setup without generating token |
| `claude`                                   | Start Claude CLI                   |
| `claude --version`                         | Check Claude CLI is working        |
| `az login`                                 | Sign into Azure manually           |
