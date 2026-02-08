# ArmourMail Deployment Guide

## Railway Deployment

### Quick Start (Recommended)

1. **Login to Railway**: https://railway.app
2. **Create New Project** → "Deploy from GitHub repo"
3. **Connect the ArmourMail repository**
4. Railway auto-detects the Python app and deploys using the included config files

### Files Included for Railway

| File | Purpose |
|------|---------|
| `Procfile` | Defines the web process command |
| `railway.toml` | Railway-specific config (health check, restart policy) |
| `nixpacks.toml` | Build configuration for Nixpacks builder |

---

## Manual Deployment Steps

### Step 1: Create Railway Account & Project

1. Go to https://railway.app and sign up/login
2. Click **New Project** → **Deploy from GitHub repo**
3. Authorize Railway to access your GitHub account
4. Select the `armourmail` repository (or the repo containing it)
5. Select the branch to deploy (usually `main`)

### Step 2: Configure Root Directory (if needed)

If ArmourMail is in a subdirectory:
1. Go to **Settings** → **General**
2. Set **Root Directory** to `armourmail/`

### Step 3: Environment Variables

Railway auto-sets `PORT`. Add these optional variables if needed:

| Variable | Description | Default |
|----------|-------------|---------|
| `ARMOURMAIL_DEBUG` | Enable debug mode | `false` |
| `ARMOURMAIL_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |

To add variables:
1. Go to your service in Railway
2. Click **Variables** tab
3. Add each variable

### Step 4: Deploy

Railway auto-deploys on push. To trigger manually:
1. Go to **Deployments** tab
2. Click **Deploy** → **Latest Commit**

### Step 5: Get Your URL

After deployment succeeds:
1. Go to **Settings** → **Networking**
2. Click **Generate Domain** to get a `*.railway.app` URL
3. Or add a custom domain

---

## Verifying Deployment

### Health Check

```bash
curl https://YOUR-APP.railway.app/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2026-02-01T22:00:00.000Z"
}
```

### API Documentation

- **Swagger UI**: `https://YOUR-APP.railway.app/docs`
- **ReDoc**: `https://YOUR-APP.railway.app/redoc`

---

## Railway CLI Deployment (Alternative)

If you prefer CLI deployment:

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Create project (from armourmail directory)
cd armourmail
railway init

# Link to project
railway link

# Deploy
railway up

# Get URL
railway domain
```

---

## SendGrid Webhook Configuration

Once deployed, configure SendGrid Inbound Parse:

1. Go to SendGrid → **Settings** → **Inbound Parse**
2. Add a new host/URL
3. Set **Destination URL**: `https://YOUR-APP.railway.app/webhook/ingest`
4. Configure your domain's MX record to point to SendGrid

---

## Production Considerations

### Database
Currently uses in-memory storage. For production, add:
- PostgreSQL (Railway offers this as an add-on)
- Update models to use SQLAlchemy or similar ORM

### Scaling
Railway supports horizontal scaling:
1. Go to **Settings** → **Deploy**
2. Configure **Replicas** (requires paid plan)

### Monitoring
- Railway provides built-in logs: **Deployments** → Click any deployment → View logs
- Add error tracking (Sentry, etc.) for production

---

## Costs

Railway offers:
- **Free Tier**: $5/month credit, good for testing
- **Hobby Plan**: $5/month, includes 8GB RAM/month
- **Pro Plan**: For production workloads

---

## Troubleshooting

### Build Fails
- Check logs in Railway dashboard
- Ensure `requirements.txt` has all dependencies
- Verify Python version compatibility

### App Crashes on Start
- Check if PORT environment variable is being used
- Look for import errors in logs

### Health Check Fails
- Ensure `/health` endpoint responds with 200
- Check healthcheckTimeout in railway.toml

---

## URLs

- **GitHub Repo**: https://github.com/neg-0/armourmail
- **Live App**: _[Add after deployment]_
- **Health Endpoint**: _[Add after deployment]/health_
- **API Docs**: _[Add after deployment]/docs_

---

## Deployment History

| Date | Version | Status | Notes |
|------|---------|--------|-------|
| 2026-02-01 | 1.0.0 | Pending | Initial deployment setup |

---

## Next Steps

1. [ ] Deploy to Railway
2. [ ] Test health endpoint
3. [ ] Configure SendGrid webhook
4. [ ] Add PostgreSQL for persistence
5. [ ] Set up custom domain
6. [ ] Configure monitoring/alerting
