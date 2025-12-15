# 🚂 Railway Deployment Guide

## Glooko Risk Assessment Tracker

Deploy the Risk Assessment app to Railway in under 5 minutes.

---

## Prerequisites

- [Railway account](https://railway.app) (free tier works)
- GitHub account (for deployment)
- Your `RISK-0003_09.xlsx` file ready to import

---

## Quick Deploy (3 Steps)

### Step 1: Create Railway Project

```bash
# Option A: Using Railway CLI
npm install -g @railway/cli
railway login
railway init

# Option B: Via Web UI
# Go to https://railway.app/new
# Click "Deploy from GitHub repo"
```

### Step 2: Add PostgreSQL Database

In Railway dashboard:
1. Click **"+ New"** → **"Database"** → **"PostgreSQL"**
2. Railway automatically sets `DATABASE_URL` environment variable

### Step 3: Deploy

```bash
# Push to Railway
railway up

# Or connect GitHub repo for auto-deploy
railway link
git push
```

---

## Environment Variables

Railway auto-configures most variables. Add these in the Railway dashboard under **Variables**:

| Variable | Value | Required |
|----------|-------|----------|
| `DATABASE_URL` | Auto-set by Railway | ✅ Auto |
| `SECRET_KEY` | Generate: `python -c "import secrets; print(secrets.token_hex(32))"` | ✅ Yes |
| `FLASK_DEBUG` | `false` | Optional |

---

## Import Data

After deployment, import your 2025 risk data:

```bash
# SSH into Railway container
railway run bash

# Upload and import Excel file
python import_data.py /path/to/RISK-0003_09.xlsx
```

**Alternative: Use Railway's file upload**
1. Upload Excel to `/app/data/` via Railway shell
2. Run import script

---

## Project Structure for Railway

```
risk-assessment-app/
├── app.py                  # Main Flask app
├── import_data.py          # Data import script
├── requirements.txt        # Python dependencies
├── railway.toml            # Railway config (copy from railway/ folder)
├── templates/              # HTML templates
│   ├── base.html
│   ├── dashboard.html
│   ├── risks.html
│   ├── risk_detail.html
│   ├── assets.html
│   └── controls.html
└── data/                   # Created automatically
```

---

## Railway CLI Commands

```bash
# Deploy
railway up

# View logs
railway logs

# Open app in browser
railway open

# Run command in container
railway run python import_data.py data.xlsx

# Check status
railway status

# View environment variables
railway variables
```

---

## Costs

| Usage | Estimated Cost |
|-------|----------------|
| Free tier | $5/month credit |
| This app (light use) | ~$2-3/month |
| PostgreSQL (small) | Included in usage |

Your 1-month project will likely stay within free tier.

---

## Troubleshooting

### App won't start
```bash
# Check logs
railway logs

# Verify DATABASE_URL is set
railway variables
```

### Database connection error
- Ensure PostgreSQL service is running
- Check `DATABASE_URL` format: `postgresql://...` (not `postgres://`)
- The app auto-converts this, but verify if issues persist

### Import fails
```bash
# Check Python environment
railway run python --version

# Verify pandas is installed
railway run pip list | grep pandas
```

---

## One-Click Template (Optional)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/...)

*Note: Create a Railway template from your repo for team re-use*

---

## Security Notes

- Railway provides SOC 2 Type II compliance
- Data encrypted in transit (TLS) and at rest
- No public access without your Railway URL
- Consider adding basic auth for extra protection

---

## Support

- [Railway Docs](https://docs.railway.app)
- [Railway Discord](https://discord.gg/railway)
- Internal: Contact IT Security for questions about hosting risk data

---

**Estimated Setup Time: 5-10 minutes**
