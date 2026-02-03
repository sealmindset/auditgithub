# Fix Docker CLI Access

If Docker Desktop GUI is running but CLI commands fail, here's how to fix it:

## Most Common Issue: Docker Engine Not Running

**Symptom**: Docker Desktop GUI shows it's running, but `docker ps` says "Cannot connect to Docker daemon"

**Cause**: Docker Desktop GUI started but the engine/daemon didn't start

**Fix**: Run the automatic fix script:
```bash
./fix-docker.sh
```

This will:
1. Completely quit Docker Desktop
2. Clean up stale sockets
3. Restart Docker Desktop
4. Wait for the daemon to be ready
5. Verify it's working

**Or do it manually**:
1. **Quit** Docker Desktop (Cmd+Q or Quit from menu bar)
2. Wait 10 seconds
3. **Start** Docker Desktop again from Applications
4. Wait until you see "Docker Desktop is running" in the menu bar
5. Try: `docker ps`

## Other Common Fixes

### Option 1: Restart Terminal
1. Close your terminal completely
2. Open a new terminal window
3. Try: `docker ps`

Docker Desktop adds itself to PATH when it starts, but existing terminal sessions don't pick up the change.

### Option 2: Link Docker CLI Manually
Run these commands:

```bash
# Create symlinks to Docker CLI tools
sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker /usr/local/bin/docker
sudo ln -sf /Applications/Docker.app/Contents/Resources/bin/docker-compose /usr/local/bin/docker-compose

# Verify it works
docker ps
docker-compose version
```

## If Still Not Working

### Check if Docker CLI is installed
```bash
ls -la /Applications/Docker.app/Contents/Resources/bin/
```

You should see `docker` and `docker-compose` files there.

### Check your PATH
```bash
echo $PATH | grep -i docker
```

Should show: `/Applications/Docker.app/Contents/Resources/bin`

### Add to PATH manually (if needed)
Add this to your `~/.zshrc` or `~/.bashrc`:

```bash
# Docker Desktop
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
```

Then reload:
```bash
source ~/.zshrc  # or source ~/.bashrc
```

### Check Docker Context
```bash
docker context ls
docker context use desktop-linux
```

### Reinstall Docker Desktop (Last Resort)
If nothing works:
1. Quit Docker Desktop
2. Delete: `/Applications/Docker.app`
3. Delete: `~/Library/Group Containers/group.com.docker`
4. Delete: `~/Library/Containers/com.docker.docker`
5. Reinstall from: https://www.docker.com/products/docker-desktop

## Verify Everything Works

```bash
# Test Docker
docker ps

# Test docker-compose
docker-compose version

# Test with auditgithub
cd /path/to/auditgithub
docker-compose ps
```

## Common Issues

**"Cannot connect to Docker daemon"**
- Docker Desktop is not fully started (wait 30 seconds after starting)
- Wrong Docker context: `docker context use desktop-linux`

**"docker: command not found"**
- Docker CLI not in PATH (see "Add to PATH manually" above)

**"docker-compose: command not found"**
- Same as above, or use `docker compose` (no dash) for newer Docker versions

## Alternative: Use Docker Desktop GUI

You can also use Docker Desktop's built-in terminal:
1. Open Docker Desktop
2. Click on "Settings" → "Advanced"
3. Enable "Use integrated terminal"
4. Use Docker Desktop's terminal for commands

## Scripts Updated

The start.sh and restart.sh scripts have been updated to skip Docker checks and just run the commands directly. If there's a CLI issue, you'll see clear error messages from docker-compose itself.
