# SHADOWTRACE v2.0 — Setup Guide

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with default settings
python app.py
```

## Environment Variables (Recommended for Production)

Set these before running:

```bash
export ADMIN_USER="your_admin_username"
export ADMIN_PASS="YourStr0ng!Password"
export ADMIN_PREFIX="your-secret-panel-path"   # e.g. "mgt-b7x2k" — the URL path to admin
export ADMIN_SECRET_KEY="random-64-char-string-here"
export LOG_DB="/path/to/logs/shadowtrace_logs.db"
export PORT=5000
```

## Admin Panel Access

Access the admin panel at:
  http://localhost:5000/<ADMIN_PREFIX>

Default (change immediately!):
  http://localhost:5000/x7k9m-panel

The admin panel is:
- NOT linked anywhere on the public site
- NOT indexed by search engines (noindex header)
- Protected by login with CSRF token
- Login uses constant-time comparison (brute-force resistant)
- Has a 1.5s throttle on failed login attempts

## What the Admin Panel Shows

- **Scan Log** — every scan with: timestamp, IP, mode (email/phone/domain/username), target, user-agent, result count
- **Rate Blocks** — IPs that hit rate limits
- **IP Summary** — per-IP breakdown of scan types and last seen time
- **CSV Export** — download any table as CSV
- **Clear Logs** — wipe records when needed

## Changing Default Credentials

Edit app.py lines (or use env vars — preferred):
```python
ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'YOUR_USERNAME_HERE')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'YOUR_PASSWORD_HERE')
ADMIN_PREFIX   = os.environ.get('ADMIN_PREFIX', 'your-secret-path')
```

## Production with Gunicorn

```bash
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 app:app
```

## Security Notes

1. **Change ADMIN_PREFIX** — the default `x7k9m-panel` is in this readme, so change it
2. **Change ADMIN_PASS** — use a strong password (20+ chars, mixed)  
3. **Change ADMIN_SECRET_KEY** — used for Flask session signing
4. **Use HTTPS** in production (nginx + certbot)
5. **Restrict DB file permissions**: `chmod 600 shadowtrace_logs.db`
6. The log DB is SQLite — back it up regularly if you need records
