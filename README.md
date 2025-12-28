# Threat Intelligence Web Platform

Hybrid web application with GitHub Pages frontend + Render.com backend.

## 🏗️ Architecture

```
Frontend (GitHub Pages)               Backend (Render.com)
ugurrates.github.io/threat-intel  →   threat-intel-api.onrender.com
├─ HTML/CSS/JS (static)                ├─ Flask API
├─ Tailwind CSS                        ├─ Rate limiting (5/day/IP)
└─ Dark theme                          ├─ SQLite caching (24h)
                                       └─ 17+ threat intel sources
```

## 📦 Project Structure

```
threat-intel-web/
├── backend/                  # Deploy to Render.com
│   ├── app.py               # Flask API
│   ├── rate_limiter.py      # Rate limiting & caching
│   ├── requirements.txt
│   └── render.yaml          # Render config
│
└── frontend/                # Deploy to GitHub Pages
    ├── index.html          # Main page
    ├── css/
    │   └── style.css       # Dark theme
    └── js/
        └── app.js          # API integration
```

---

## 🚀 DEPLOYMENT GUIDE

### STEP 1: Deploy Backend to Render.com

1. **Create Render Account**
   - Go to: https://render.com
   - Sign up with GitHub

2. **Create New Web Service**
   - Dashboard → New → Web Service
   - Connect your GitHub repository
   - Or use "Deploy from Git URL"

3. **Configuration**
   ```
   Name: threat-intel-api
   Region: Frankfurt (or closest to you)
   Branch: main
   Root Directory: backend
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: gunicorn app:app
   Plan: Free
   ```

4. **Environment Variables** (Optional)
   ```
   PYTHON_VERSION=3.11.0
   PORT=10000
   ```

5. **Deploy!**
   - Click "Create Web Service"
   - Wait ~5 minutes for deployment
   - Note your URL: `https://threat-intel-api.onrender.com`

### STEP 2: Update Frontend API URL

1. **Edit `frontend/js/app.js`**
   ```javascript
   // Line 3: Change API_BASE_URL
   const API_BASE_URL = 'https://threat-intel-api.onrender.com';
   ```

2. **Save the file**

### STEP 3: Deploy Frontend to GitHub Pages

#### Option A: New Repository

1. **Create Repository**
   ```bash
   cd threat-intel-web/frontend
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/ugurrates/threat-intel.git
   git push -u origin main
   ```

2. **Enable GitHub Pages**
   - Repository → Settings → Pages
   - Source: Deploy from branch
   - Branch: `main` / `root`
   - Save

3. **Access**
   - URL: `https://ugurrates.github.io/threat-intel`
   - Wait 1-2 minutes for deployment

#### Option B: Add to Existing Website

1. **Copy Frontend Files**
   ```bash
   cp -r threat-intel-web/frontend/* your-website-repo/threat-intel/
   cd your-website-repo
   git add threat-intel/
   git commit -m "Add threat intelligence platform"
   git push
   ```

2. **Access**
   - URL: `https://ugurrates.github.io/threat-intel/`

---

## ⚙️ Configuration

### Rate Limits (backend/rate_limiter.py)

```python
DAILY_LIMIT_PER_IP = 5        # Per IP: 5 queries/day
GLOBAL_DAILY_LIMIT = 100      # Platform: 100 queries/day
GLOBAL_MONTHLY_LIMIT = 500    # Platform: 500 queries/month
CACHE_TTL_HOURS = 24          # Cache: 24 hours
```

### CORS Origins (backend/app.py)

```python
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://ugurrates.github.io",  # Your GitHub Pages
            "http://localhost:*",            # Local testing
        ]
    }
})
```

---

## 🧪 Local Testing

### Backend (Terminal 1)

```bash
cd threat-intel-web/backend
pip install -r requirements.txt
python app.py
```

Backend runs on: `http://localhost:5000`

### Frontend (Terminal 2)

```bash
cd threat-intel-web/frontend
python3 -m http.server 8000
```

Frontend runs on: `http://localhost:8000`

**NOTE:** Make sure `frontend/js/app.js` has `API_BASE_URL = 'http://localhost:5000'`

---

## 📊 API Endpoints

### POST /api/analyze
Analyze IOC with rate limiting and caching.

**Request:**
```json
{
  "ioc": "192.0.2.1"
}
```

**Response:**
```json
{
  "cached": false,
  "ioc": "192.0.2.1",
  "results": {
    "normalized_score": {
      "final_score": 96,
      "severity": "CRITICAL"
    },
    "detection_rules": {
      "kql_queries": [...],
      "spl_queries": [...],
      "sigma_rules": [...],
      "xql_queries": [...],
      "yara_rules": [...]
    }
  },
  "rate_limit": {
    "remaining": 4,
    "limit": 5
  }
}
```

### GET /api/health
Health check.

### GET /api/stats
Platform and user statistics.

---

## 🔒 Security Features

- **Rate Limiting**: 5 queries/day per IP
- **Caching**: 24-hour cache (repeated queries = free)
- **CORS**: Restricted to GitHub Pages domain
- **No API Keys Exposed**: All keys server-side
- **SQLite**: Local database (auto-created)

---

## 💰 Cost Analysis

### Free Tier Limits

| Service | Free Tier | Usage | Status |
|---------|-----------|-------|--------|
| Render.com | 750 hours/month | ~24/7 uptime | ✅ Free |
| GitHub Pages | Unlimited | Static hosting | ✅ Free |
| VirusTotal | 500 req/day | <100/day | ✅ Free |
| Shodan | 100 req/month | <90/month (cached) | ✅ Free |
| Other APIs | Unlimited/High | N/A | ✅ Free |

**Total Cost: $0/month** 🎉

### Cost Protection

- Rate limit: 5/day/IP → Max 100/day global
- Cache: 70%+ hit rate → 30 actual API calls/day
- Shodan cache: 7 days → ~3 req/month
- Monthly cap: 500 queries → Well within limits

---

## 🐛 Troubleshooting

### "CORS error"
- Check `backend/app.py` CORS origins
- Make sure frontend URL is whitelisted

### "Rate limit exceeded"
- Wait for reset (displayed in banner)
- Cached results don't count!

### "Analysis failed"
- Check Render.com logs
- Verify MCP server files are present
- Test backend health: `https://your-api.onrender.com/api/health`

### Render.com "Service Unavailable"
- Free tier sleeps after 15min inactivity
- First request takes ~30 seconds (cold start)
- Subsequent requests are fast

---

## 📝 Features

- ✅ **17+ Intelligence Sources**
- ✅ **5 Detection Platforms** (KQL, SPL, SIGMA, XQL, YARA)
- ✅ **Real-time Analysis** (~3 seconds)
- ✅ **Rate Limiting** (5/day/IP, cached = free)
- ✅ **Dark Theme** (Glassmorphism)
- ✅ **Mobile Responsive**
- ✅ **Copy-Paste Ready** Detection Rules
- ✅ **VirusTotal Community** Intelligence
- ✅ **USOM Integration** 🇹🇷
- ✅ **Domain Entropy** Analysis
- ✅ **MITRE ATT&CK** Mapping

---

## 🔗 Links

- **GitHub**: https://github.com/ugurrates/MCP-For-SOC
- **Portfolio**: https://ugurcanates.github.io
- **Medium**: https://medium.com/@ugur.can.ates

---

**Built with ❤️ by Ugur Ates**
