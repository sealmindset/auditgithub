# AuditGitHub Quick Start Guide

## 🚀 Starting the Application

### Normal Startup
```bash
./start.sh
```
- Uses Docker cache for faster builds
- Automatically starts Docker if needed
- Verifies all services are healthy
- Shows service URLs when ready

### Clean Rebuild
```bash
REBUILD=true ./start.sh
```
- Forces complete rebuild without cache
- Ensures 100% latest code
- Takes longer but guarantees fresh build

### Get Help
```bash
./start.sh --help
```
- Shows all features
- Explains tripwire mechanisms
- Lists expected timings

## 🔧 Docker Issues?

### Docker Not Responding
If you get "Cannot connect to the Docker daemon" errors even though Docker Desktop is running:

```bash
./restart-docker.sh
```

This script will:
1. Gracefully quit Docker Desktop
2. Force kill any stuck processes
3. Wait for complete shutdown
4. Start Docker fresh
5. Verify it's operational
6. Ask if you want to run ./start.sh

**When to use restart-docker.sh:**
- Socket connection errors
- Docker seems frozen
- After Mac sleep/wake
- Commands fail but GUI shows containers running

## 📋 Common Issues & Solutions

### Issue: "Docker daemon not running"
**Solution:**
```bash
./restart-docker.sh
```

### Issue: Build fails with connection errors
**Solution:**
1. Run `./restart-docker.sh`
2. Wait for "Docker is fully operational"
3. Run `./start.sh`

### Issue: Containers won't start
**Solution:**
```bash
docker-compose down
./start.sh
```

### Issue: Port 3000 or 3001 already in use
**Solution:**
The start.sh script automatically kills processes on these ports. If issues persist:
```bash
lsof -ti:3000,3001 | xargs kill -9
```

### Issue: API health check fails
**Solution:**
Check the logs:
```bash
docker-compose logs -f api
```

## 📊 Service URLs

After successful startup, access these URLs:

- **Web UI:** http://localhost:3000
- **API:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **MinIO:** http://localhost:9001
- **Database:** localhost:5432

## 🛠️ Useful Commands

### View All Logs
```bash
docker-compose logs -f
```

### View Specific Service Logs
```bash
docker-compose logs -f api
docker-compose logs -f db
docker-compose logs -f web-ui
```

### Stop All Services
```bash
docker-compose down
```

### Check Container Status
```bash
docker-compose ps
```

### Restart a Single Service
```bash
docker-compose restart api
```

### Rebuild Single Service
```bash
docker-compose build api
docker-compose up -d api
```

## 🔍 Debugging

### Check if Docker is working
```bash
docker info
docker ps
```

### Check if docker-compose can connect
```bash
docker-compose ps
```

### Check socket location
```bash
ls -la /var/run/docker.sock
ls -la ~/.docker/run/docker.sock
```

### Check Docker context
```bash
docker context ls
```

## 🎯 Workflow

### First Time Setup
1. Make sure Docker Desktop is installed
2. Run `./start.sh`
3. Wait for all services to be healthy
4. Access http://localhost:3000

### Daily Development
```bash
./start.sh  # Fast startup using cache
```

### After Changing Dependencies
```bash
REBUILD=true ./start.sh  # Clean rebuild
```

### If Docker Acts Up
```bash
./restart-docker.sh  # Fix Docker issues
./start.sh          # Start services
```

### Shutting Down
```bash
docker-compose down  # Stop all services
```

## ⚡ Performance Tips

1. **Use cache:** Normal `./start.sh` is much faster
2. **Clean rebuild only when needed:** After dependency changes or git pull
3. **Keep Docker Desktop running:** Startup is instant when Docker is already running
4. **Restart Docker periodically:** If it's been running for days and acting sluggish

## 🔐 Security Notes

- Never commit `.env` files with secrets
- Database credentials are in `.env`
- GitHub tokens should be in environment variables
- MinIO credentials are configurable

## 📝 Notes

- The startup script has built-in retry logic
- Each step waits for completion before proceeding (tripwires)
- Health checks ensure services are actually ready, not just started
- All logs are saved to `/tmp/docker-*.log` for debugging

## 🆘 Getting Help

If issues persist:
1. Check `/tmp/docker-build.log` for build errors
2. Check `/tmp/docker-start.log` for startup errors
3. Run `docker-compose logs <service>` for service-specific logs
4. Restart Docker Desktop manually if scripts don't work
5. Check GitHub Issues for similar problems
