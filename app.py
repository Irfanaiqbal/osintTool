#!/usr/bin/env python3
import subprocess, threading, queue, time, re, socket, ssl, datetime, os, hashlib, hmac
from flask import Flask, request, Response, render_template_string, jsonify, redirect, url_for, session
import requests
import whois
from collections import deque
import uuid
import json
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get('ADMIN_SECRET_KEY', 'change-this-secret-key-in-production-please')

# ============================================================
#  DATABASE — request logging (completely hidden from public)
# ============================================================
DB_PATH = os.environ.get('LOG_DB', 'shadowtrace_logs.db')

def db_init():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS scans (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        TEXT    NOT NULL,
        ip        TEXT    NOT NULL,
        mode      TEXT    NOT NULL,
        target    TEXT    NOT NULL,
        ua        TEXT,
        country   TEXT,
        result_ct INTEGER DEFAULT 0
    )''')
    cur.execute('''CREATE TABLE IF NOT EXISTS rate_blocks (
        id  INTEGER PRIMARY KEY AUTOINCREMENT,
        ts  TEXT NOT NULL,
        ip  TEXT NOT NULL,
        msg TEXT
    )''')
    con.commit()
    con.close()

def db_log_scan(ip, mode, target, ua, result_ct=0):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute(
            'INSERT INTO scans (ts,ip,mode,target,ua,result_ct) VALUES (?,?,?,?,?,?)',
            (datetime.datetime.utcnow().isoformat(), ip, mode, target, ua, result_ct)
        )
        con.commit()
        con.close()
    except Exception:
        pass

def db_log_block(ip, msg):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute('INSERT INTO rate_blocks (ts,ip,msg) VALUES (?,?,?)',
                    (datetime.datetime.utcnow().isoformat(), ip, msg))
        con.commit()
        con.close()
    except Exception:
        pass

db_init()

# ============================================================
#  ADMIN CREDENTIALS — change these or use env vars
# ============================================================
ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'haleema')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASS', 'haleema@321')
# Hidden admin panel URL segment — not linked anywhere on the site
ADMIN_PREFIX    = os.environ.get('ADMIN_PREFIX', 'x7k9m-panel')

# ============================================================
#  RATE LIMITING
# ============================================================
MAX_CONCURRENT_REQUESTS = 500
MAX_REQUESTS_PER_IP     = 10
IP_REQUEST_WINDOW       = 60
active_requests = 0
request_queue   = deque()
request_lock    = threading.Lock()
ip_request_log  = {}
ip_lock         = threading.Lock()

def get_real_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

def check_ip_rate_limit(ip):
    now = time.time()
    with ip_lock:
        timestamps = ip_request_log.get(ip, [])
        timestamps = [t for t in timestamps if now - t < IP_REQUEST_WINDOW]
        if len(timestamps) >= MAX_REQUESTS_PER_IP:
            return False
        timestamps.append(now)
        ip_request_log[ip] = timestamps
    return True

# ============================================================
#  INPUT VALIDATION
# ============================================================
def validate_target(mode, target):
    target = target.strip()
    if not target or len(target) > 256:
        return False, 'Invalid target length'
    if mode == 'email':
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
            return False, 'Invalid email format'
    elif mode == 'domain':
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return False, 'Invalid domain format'
    elif mode == 'phone':
        if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', target):
            return False, 'Invalid phone format'
    elif mode == 'username':
        if not re.match(r'^[a-zA-Z0-9._\-]{1,50}$', target):
            return False, 'Invalid username (alphanumeric, dots, dashes only)'
    return True, target

# ============================================================
#  USERNAME PLATFORMS
# ============================================================
USERNAME_PLATFORMS = {
    "GitHub":         "https://github.com/{u}",
    "GitLab":         "https://gitlab.com/{u}",
    "Bitbucket":      "https://bitbucket.org/{u}",
    "SourceForge":    "https://sourceforge.net/u/{u}",
    "Gitea":          "https://gitea.com/{u}",
    "CodePen":        "https://codepen.io/{u}",
    "Replit":         "https://replit.com/@{u}",
    "Kaggle":         "https://www.kaggle.com/{u}",
    "HackerRank":     "https://www.hackerrank.com/{u}",
    "LeetCode":       "https://leetcode.com/{u}",
    "Twitter / X":    "https://twitter.com/{u}",
    "Instagram":      "https://www.instagram.com/{u}/",
    "Facebook":       "https://www.facebook.com/{u}",
    "Reddit":         "https://www.reddit.com/user/{u}/",
    "TikTok":         "https://www.tiktok.com/@{u}",
    "Threads":        "https://www.threads.net/@{u}",
    "Pinterest":      "https://www.pinterest.com/{u}/",
    "Tumblr":         "https://{u}.tumblr.com",
    "Snapchat":       "https://www.snapchat.com/add/{u}",
    "Telegram":       "https://t.me/{u}",
    "Discord":        "https://discord.com/users/{u}",
    "Matrix":         "https://matrix.to/#/@{u}:matrix.org",
    "YouTube":        "https://www.youtube.com/@{u}",
    "Twitch":         "https://www.twitch.tv/{u}",
    "Vimeo":          "https://vimeo.com/{u}",
    "SoundCloud":     "https://soundcloud.com/{u}",
    "Mixcloud":       "https://www.mixcloud.com/{u}",
    "Bandcamp":       "https://bandcamp.com/{u}",
    "DeviantArt":     "https://www.deviantart.com/{u}",
    "Behance":        "https://www.behance.net/{u}",
    "Dribbble":       "https://dribbble.com/{u}",
    "Medium":         "https://medium.com/@{u}",
    "Substack":       "https://{u}.substack.com",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "Quora":          "https://www.quora.com/profile/{u}",
    "Steam":          "https://steamcommunity.com/id/{u}",
    "Epic Games":     "https://www.epicgames.com/id/{u}",
    "Roblox":         "https://www.roblox.com/user.aspx?username={u}",
    "Fiverr":         "https://www.fiverr.com/{u}",
    "Upwork":         "https://www.upwork.com/freelancers/{u}",
    "LinkedIn":       "https://www.linkedin.com/in/{u}",
    "Pastebin":       "https://pastebin.com/u/{u}",
    "Keybase":        "https://keybase.io/{u}",
    "About.me":       "https://about.me/{u}",
    "ProductHunt":    "https://www.producthunt.com/@{u}",
}

jobs = {}

# ============================================================
#  HELPERS
# ============================================================
def make_card(title, body, body_plain=None, icon='fa-info-circle', tag='', url=''):
    return json.dumps({
        'title': title,
        'body': body,
        'body_plain': body_plain or body,
        'icon': icon,
        'tag': tag,
        'url': url
    })

# ============================================================
#  PUBLIC FRONTEND HTML
# ============================================================
HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SHADOWTRACE · OSINT INTELLIGENCE</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Passive OSINT reconnaissance platform for digital footprint analysis.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&family=Rajdhani:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>
    :root {
      --bg0:     #03030a;
      --bg1:     #070710;
      --bg2:     #0d0d1a;
      --bg3:     #131325;
      --bg4:     #1a1a30;
      --border:  #1e1e38;
      --border2: #282845;
      --fg:      #e2e2f0;
      --fg2:     #8888aa;
      --fg3:     #44445a;
      --c:       #00e5ff;    /* cyan accent */
      --p:       #9b5de5;    /* purple */
      --g:       #00f5a0;    /* green */
      --pk:      #ff4d8f;    /* pink */
      --y:       #ffd166;    /* yellow */
      --o:       #ff9a3c;    /* orange */
      --bl:      #4488ff;    /* blue */
      --gc:  0 0 18px rgba(0,229,255,.3);
      --gp:  0 0 18px rgba(155,93,229,.3);
      --gg:  0 0 14px rgba(0,245,160,.25);
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

    body{
      font-family:'Space Grotesk',sans-serif;
      background:var(--bg0);color:var(--fg);
      min-height:100vh;overflow-x:hidden;
    }

    /* ── GRID + GLOW BACKGROUND ── */
    body::before{
      content:'';position:fixed;inset:0;z-index:0;
      background-image:
        linear-gradient(rgba(0,229,255,.025) 1px,transparent 1px),
        linear-gradient(90deg,rgba(0,229,255,.025) 1px,transparent 1px);
      background-size:48px 48px;pointer-events:none;
    }
    body::after{
      content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
      background:
        radial-gradient(ellipse 70% 50% at 10% 5%,rgba(0,229,255,.07) 0%,transparent 55%),
        radial-gradient(ellipse 55% 45% at 90% 90%,rgba(155,93,229,.08) 0%,transparent 55%),
        radial-gradient(ellipse 40% 35% at 55% 45%,rgba(255,77,143,.04) 0%,transparent 55%);
    }

    .wrap{max-width:1180px;margin:0 auto;padding:0 22px;position:relative;z-index:1}

    /* ── HEADER ── */
    header{
      position:sticky;top:0;z-index:200;
      border-bottom:1px solid var(--border);
      background:rgba(3,3,10,.88);backdrop-filter:blur(20px);
    }
    .hrow{display:flex;align-items:center;justify-content:space-between;padding:13px 0}
    .logo{display:flex;align-items:center;gap:11px;text-decoration:none}
    .logo-mark{
      width:36px;height:36px;border-radius:10px;
      background:linear-gradient(140deg,var(--c),var(--p));
      display:flex;align-items:center;justify-content:center;
      font-size:17px;color:#000;box-shadow:var(--gc);
      position:relative;overflow:hidden;
    }
    .logo-mark::after{
      content:'';position:absolute;inset:0;
      background:linear-gradient(135deg,rgba(255,255,255,.2),transparent);
    }
    .logo-text{
      font-family:'Rajdhani',sans-serif;font-size:21px;font-weight:700;
      letter-spacing:.1em;
      background:linear-gradient(135deg,var(--fg) 0%,var(--c) 60%,var(--p) 100%);
      -webkit-background-clip:text;background-clip:text;color:transparent;
    }
    .logo-badge{
      font-size:10px;font-weight:500;color:var(--fg3);
      background:var(--bg3);border:1px solid var(--border);
      padding:2px 8px;border-radius:20px;letter-spacing:.06em;
    }
    .hnav{display:flex;gap:8px;align-items:center}
    .nbtn{
      display:flex;align-items:center;gap:7px;
      padding:7px 15px;border-radius:8px;font-size:13px;font-weight:500;
      border:1px solid var(--border);background:var(--bg3);color:var(--fg2);
      cursor:pointer;text-decoration:none;transition:all .2s;
      font-family:'Space Grotesk',sans-serif;
    }
    .nbtn:hover{border-color:var(--c);color:var(--fg);box-shadow:var(--gc)}
    .nbtn.donate{border-color:rgba(255,77,143,.35);background:rgba(255,77,143,.07);color:var(--pk)}
    .nbtn.donate:hover{box-shadow:0 0 14px rgba(255,77,143,.3)}
    .hburger{
      display:none;width:40px;height:40px;border-radius:9px;
      background:var(--bg3);border:1px solid var(--border);color:var(--fg2);
      align-items:center;justify-content:center;cursor:pointer;font-size:18px;
      transition:all .2s;
    }
    .hburger:hover{border-color:var(--c);color:var(--c)}

    /* ── MOBILE MENU ── */
    .mob-overlay{position:fixed;inset:0;background:rgba(0,0,0,.9);backdrop-filter:blur(10px);z-index:900;opacity:0;visibility:hidden;transition:all .25s}
    .mob-overlay.open{opacity:1;visibility:visible}
    .mob-panel{position:fixed;top:0;right:-300px;width:280px;height:100vh;background:var(--bg2);border-left:1px solid var(--border);z-index:901;transition:right .3s cubic-bezier(.4,0,.2,1);padding:24px;display:flex;flex-direction:column;gap:10px}
    .mob-panel.open{right:0}
    .mob-hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}
    .mob-hd h3{font-family:'Rajdhani',sans-serif;font-size:18px;font-weight:700;background:linear-gradient(135deg,var(--c),var(--p));-webkit-background-clip:text;background-clip:text;color:transparent}
    .mob-x{background:none;border:none;color:var(--fg3);font-size:22px;cursor:pointer;transition:color .2s;width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:6px}
    .mob-x:hover{color:var(--pk)}
    .mob-item{display:flex;align-items:center;gap:14px;padding:13px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:10px;color:var(--fg2);text-decoration:none;cursor:pointer;transition:all .2s;font-size:15px}
    .mob-item i{color:var(--c);width:20px;text-align:center}
    .mob-item:hover{border-color:var(--c);color:var(--fg);transform:translateX(-4px)}
    .mob-item.donate i{color:var(--pk)}
    .mob-item.donate:hover{border-color:var(--pk)}

    /* ── HERO ── */
    .hero{padding:52px 0 36px;text-align:center}
    .hero-eye{
      font-family:'Space Mono',monospace;font-size:11px;letter-spacing:.22em;
      color:var(--c);text-shadow:var(--gc);margin-bottom:18px;
      display:flex;align-items:center;justify-content:center;gap:10px;
    }
    .hero-eye::before,.hero-eye::after{content:'';flex:1;max-width:72px;height:1px;background:linear-gradient(90deg,transparent,var(--c))}
    .hero-eye::after{background:linear-gradient(90deg,var(--c),transparent)}
    .hero h1{
      font-family:'Rajdhani',sans-serif;
      font-size:clamp(38px,7vw,72px);font-weight:700;
      letter-spacing:.07em;line-height:1;
      background:linear-gradient(140deg,var(--fg) 0%,var(--c) 45%,var(--p) 85%);
      -webkit-background-clip:text;background-clip:text;color:transparent;
      margin-bottom:18px;
    }
    .hero p{color:var(--fg2);font-size:16px;max-width:500px;margin:0 auto;line-height:1.65}
    .hero-chips{display:flex;justify-content:center;flex-wrap:wrap;gap:10px;margin-top:28px}
    .chip{
      display:flex;align-items:center;gap:7px;padding:8px 16px;
      background:var(--bg3);border:1px solid var(--border);border-radius:30px;
      font-size:12px;font-weight:500;color:var(--fg2);letter-spacing:.04em;
    }
    .chip i{font-size:11px}
    .chip.c i{color:var(--c)}.chip.p i{color:var(--p)}.chip.g i{color:var(--g)}.chip.pk i{color:var(--pk)}

    /* ── SCANNER CARD ── */
    .scanner{
      background:var(--bg2);border:1px solid var(--border);
      border-radius:18px;padding:28px;margin-bottom:22px;
      position:relative;overflow:hidden;
    }
    .scanner-bar{
      position:absolute;top:0;left:0;right:0;height:2px;
      background:linear-gradient(90deg,var(--c),var(--p),var(--pk),var(--c));
      background-size:200% 100%;animation:barflow 5s linear infinite;
    }
    @keyframes barflow{to{background-position:200% 0}}

    /* ── TABS ── */
    .tabs{display:flex;gap:6px;margin-bottom:22px;flex-wrap:wrap}
    .tab{
      display:flex;align-items:center;gap:8px;
      padding:10px 20px;border-radius:9px;font-size:14px;font-weight:600;
      background:var(--bg3);border:1px solid var(--border);color:var(--fg2);
      cursor:pointer;transition:all .2s;letter-spacing:.04em;
      font-family:'Rajdhani',sans-serif;font-size:15px;
    }
    .tab:hover{border-color:var(--c);color:var(--fg)}
    .tab.active{
      background:linear-gradient(135deg,rgba(0,229,255,.13),rgba(155,93,229,.13));
      border-color:var(--c);color:var(--c);box-shadow:var(--gc);
    }
    .tab-dot{width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.7}

    /* ── INPUT ── */
    .irow{display:flex;gap:10px}
    .ibox{
      flex:1;display:flex;align-items:center;
      background:var(--bg3);border:1px solid var(--border);border-radius:12px;
      padding:0 18px;gap:12px;transition:all .2s;
    }
    .ibox:focus-within{border-color:var(--c);box-shadow:var(--gc)}
    .ibox i{color:var(--fg3);font-size:15px;flex-shrink:0}
    .ibox input{
      flex:1;background:none;border:none;outline:none;
      color:var(--fg);font-size:15px;padding:15px 0;
      font-family:'Space Mono',monospace;
    }
    .ibox input::placeholder{color:var(--fg3);font-family:'Space Grotesk',sans-serif;font-size:14px}
    .ibtn{
      display:flex;align-items:center;gap:9px;
      padding:15px 26px;border-radius:12px;font-size:14px;font-weight:700;
      background:linear-gradient(135deg,var(--c),var(--p));
      border:none;color:#000;cursor:pointer;transition:all .2s;
      font-family:'Rajdhani',sans-serif;letter-spacing:.06em;white-space:nowrap;
    }
    .ibtn:hover:not(:disabled){transform:translateY(-2px);box-shadow:var(--gc),var(--gp)}
    .ibtn:disabled{opacity:.4;cursor:not-allowed}
    .ibtn .btn-shine{
      position:absolute;inset:0;border-radius:inherit;
      background:linear-gradient(135deg,rgba(255,255,255,.15),transparent);
      pointer-events:none;
    }

    /* ── TOOLBAR ── */
    .toolbar{display:flex;align-items:center;justify-content:space-between;margin-top:14px;flex-wrap:wrap;gap:10px}
    .disc{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--fg3)}
    .disc i{color:var(--y)}
    .tactions{display:flex;gap:8px}
    .tact-btn{
      display:flex;align-items:center;gap:6px;padding:7px 13px;
      border-radius:7px;font-size:12px;font-weight:500;
      background:var(--bg3);border:1px solid var(--border);color:var(--fg2);
      cursor:pointer;transition:all .2s;font-family:'Space Grotesk',sans-serif;
    }
    .tact-btn:hover{border-color:var(--c);color:var(--fg)}
    .tact-btn:disabled{opacity:.35;cursor:not-allowed}

    /* ── MESSAGES ── */
    .msg{margin-top:13px;padding:12px 18px;border-radius:9px;font-size:13px;font-weight:500;display:none;border:1px solid;font-family:'Space Mono',monospace}
    .msg.show{display:block}
    .msg-err{background:rgba(255,77,143,.07);border-color:var(--pk);color:var(--pk)}
    .msg-ok{background:rgba(0,245,160,.07);border-color:var(--g);color:var(--g)}

    /* ── PROGRESS ── */
    .prog-wrap{margin-top:16px;display:none}
    .prog-wrap.show{display:block}
    .prog-row{display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--fg3);margin-bottom:7px;font-family:'Space Mono',monospace}
    .prog-track{height:3px;background:var(--bg4);border-radius:2px;overflow:hidden}
    .prog-fill{height:100%;width:0%;background:linear-gradient(90deg,var(--c),var(--p));border-radius:2px;transition:width .3s;box-shadow:var(--gc)}
    .prog-label{color:var(--c)}

    /* ── QUEUE CARD ── */
    .queue-card{background:var(--bg2);border:1px solid var(--border2);border-radius:18px;padding:52px;text-align:center;margin:16px 0;display:none}
    .queue-card.show{display:block}
    .queue-spinner{width:52px;height:52px;border-radius:50%;margin:0 auto 22px;border:3px solid var(--border);border-top-color:var(--c);border-right-color:var(--p);animation:spin .8s linear infinite;box-shadow:var(--gc)}
    @keyframes spin{to{transform:rotate(360deg)}}
    .queue-card h3{font-family:'Rajdhani',sans-serif;font-size:20px;font-weight:700;color:var(--y);margin-bottom:8px;letter-spacing:.07em}
    .queue-pos{font-family:'Space Mono',monospace;font-size:44px;color:var(--c);text-shadow:var(--gc);margin:14px 0}

    /* ── LOADING ── */
    .loading{padding:52px;text-align:center;display:none}
    .loading.show{display:block}
    .loading p{color:var(--fg2);font-family:'Space Mono',monospace;font-size:14px;margin-top:16px}
    .loading p span{color:var(--c);text-shadow:var(--gc)}

    /* ── RESULTS HEADER ── */
    .res-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;padding-bottom:14px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:10px}
    .res-title{font-family:'Rajdhani',sans-serif;font-size:20px;font-weight:700;letter-spacing:.07em;background:linear-gradient(135deg,var(--c),var(--p));-webkit-background-clip:text;background-clip:text;color:transparent}
    .res-right{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    .res-count{font-family:'Space Mono',monospace;font-size:12px;padding:5px 13px;border-radius:20px;color:var(--fg2);background:var(--bg3);border:1px solid var(--border)}

    /* ── FILTER ── */
    .filter-row{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
    .filter-input{flex:1;min-width:200px;background:var(--bg3);border:1px solid var(--border);border-radius:9px;padding:9px 15px;font-size:13px;color:var(--fg);outline:none;transition:border-color .2s;font-family:'Space Grotesk',sans-serif}
    .filter-input:focus{border-color:var(--c)}
    .filter-input::placeholder{color:var(--fg3)}

    /* ── RESULT GRID ── */
    .res-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px}
    .rcard{
      background:var(--bg2);border:1px solid var(--border);border-radius:13px;
      padding:20px;transition:all .2s;position:relative;overflow:hidden;
      animation:cardin .3s ease both;
    }
    @keyframes cardin{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
    .rcard::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:linear-gradient(180deg,var(--c),var(--p));opacity:0;transition:opacity .2s}
    .rcard:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 10px 28px rgba(0,0,0,.45)}
    .rcard:hover::after{opacity:1}
    .rcard.link{cursor:pointer}
    .rcard-top{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:10px}
    .rcard-title{display:flex;align-items:center;gap:9px;font-family:'Rajdhani',sans-serif;font-size:16px;font-weight:600;letter-spacing:.04em;color:var(--fg)}
    .rcard-title i{color:var(--c);font-size:14px;flex-shrink:0}
    .rcard-copy{background:none;border:1px solid var(--border);border-radius:6px;color:var(--fg3);font-size:11px;padding:3px 9px;cursor:pointer;transition:all .2s;opacity:0;font-family:'Space Grotesk',sans-serif;white-space:nowrap}
    .rcard:hover .rcard-copy{opacity:1}
    .rcard-copy:hover{border-color:var(--c);color:var(--c)}
    .rcard-body{color:var(--fg2);font-size:13px;line-height:1.65;word-break:break-word}
    .rcard-body a{color:var(--g);text-decoration:none}
    .rcard-body a:hover{text-decoration:underline}
    .rcard-tag{display:inline-block;margin-top:13px;font-size:10px;font-weight:700;color:#000;padding:3px 11px;border-radius:20px;letter-spacing:.07em;font-family:'Space Mono',monospace}
    .tag-email{background:linear-gradient(135deg,var(--bl),var(--c))}
    .tag-username{background:linear-gradient(135deg,var(--p),var(--pk))}
    .tag-domain{background:linear-gradient(135deg,var(--g),var(--bl))}
    .tag-phone{background:linear-gradient(135deg,var(--o),var(--pk))}

    /* ── HISTORY ── */
    .hist-panel{background:var(--bg2);border:1px solid var(--border);border-radius:13px;padding:20px;margin-bottom:20px;display:none}
    .hist-panel.show{display:block}
    .hist-title{font-family:'Rajdhani',sans-serif;font-size:15px;font-weight:700;color:var(--fg2);margin-bottom:14px;letter-spacing:.06em}
    .hist-list{display:flex;flex-wrap:wrap;gap:8px}
    .hist-item{display:flex;align-items:center;gap:7px;padding:6px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;font-size:12px;color:var(--fg2);cursor:pointer;transition:all .2s;font-family:'Space Mono',monospace}
    .hist-item:hover{border-color:var(--c);color:var(--c)}
    .hist-clear{font-size:12px;color:var(--fg3);cursor:pointer;padding:4px 8px;border-radius:4px;transition:color .2s;background:none;border:none;font-family:'Space Grotesk',sans-serif}
    .hist-clear:hover{color:var(--pk)}

    /* ── EMPTY STATE ── */
    .empty{text-align:center;padding:80px 20px;display:none}
    .empty.show{display:block}
    .empty-icon{font-size:58px;margin-bottom:22px;background:linear-gradient(135deg,var(--c),var(--p));-webkit-background-clip:text;background-clip:text;color:transparent}
    .empty h3{font-family:'Rajdhani',sans-serif;font-size:22px;font-weight:700;color:var(--fg2);margin-bottom:8px}
    .empty p{color:var(--fg3);font-size:14px}
    .kbd{display:inline-flex;align-items:center;justify-content:center;background:var(--bg3);border:1px solid var(--border2);border-radius:4px;padding:1px 7px;font-family:'Space Mono',monospace;font-size:12px;color:var(--fg2)}

    /* ── FOOTER ── */
    footer{border-top:1px solid var(--border);padding:28px 0;margin-top:60px;position:relative;z-index:1}
    .frow{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px}
    .fcopy{font-size:12px;color:var(--fg3);font-family:'Space Mono',monospace}
    .flinks{display:flex;gap:20px}
    .flinks a{font-size:13px;color:var(--fg3);cursor:pointer;text-decoration:none;transition:color .2s}
    .flinks a:hover{color:var(--c)}

    /* ── MODALS ── */
    .modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.94);backdrop-filter:blur(14px);display:none;justify-content:center;align-items:center;z-index:500;padding:20px}
    .modal-bg.show{display:flex}
    .modal{background:var(--bg2);border:1px solid var(--border);border-radius:18px;width:100%;max-width:560px;max-height:85vh;overflow:hidden;position:relative}
    .modal::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--c),var(--p),var(--pk))}
    .modal-hd{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
    .modal-hd h2{font-family:'Rajdhani',sans-serif;font-size:18px;font-weight:700;letter-spacing:.07em;background:linear-gradient(135deg,var(--c),var(--p));-webkit-background-clip:text;background-clip:text;color:transparent}
    .modal-x{background:none;border:none;color:var(--fg3);font-size:24px;cursor:pointer;transition:all .2s;width:32px;height:32px;display:flex;align-items:center;justify-content:center}
    .modal-x:hover{color:var(--pk)}
    .modal-body{padding:24px;overflow-y:auto;max-height:calc(85vh - 70px)}
    .msec{margin-bottom:22px}
    .msec h3{font-size:14px;font-weight:600;color:var(--c);margin-bottom:8px;letter-spacing:.04em}
    .msec p,.msec li{font-size:14px;color:var(--fg2);line-height:1.7}
    .msec ul{padding-left:18px}
    .msec li{margin-bottom:6px}
    .crypto-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
    .ccard{background:var(--bg3);border:1px solid var(--border);border-radius:13px;padding:20px;text-align:center;transition:all .2s}
    .ccard:hover{border-color:var(--c);box-shadow:var(--gc)}
    .ccard-icon{font-size:32px;margin-bottom:12px}
    .ccard-icon.btc{color:var(--y)}.ccard-icon.eth{color:var(--p)}
    .ccard h3{font-size:15px;font-weight:600;margin-bottom:12px}
    .ccard h3.btc{color:var(--y)}.ccard h3.eth{color:var(--p)}
    .wallet{background:var(--bg0);border:1px solid var(--border);border-radius:7px;padding:10px;font-family:'Space Mono',monospace;font-size:11px;word-break:break-all;color:var(--fg2);margin:10px 0;text-align:left}
    .cbtn{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,var(--c),var(--p));border:none;padding:9px 18px;border-radius:20px;color:#000;font-size:12px;font-weight:700;cursor:pointer;transition:all .2s;font-family:'Rajdhani',sans-serif;letter-spacing:.04em}
    .cbtn:hover{transform:scale(1.05);box-shadow:var(--gc)}
    .copied{font-size:11px;color:var(--g);margin-top:6px;display:none}
    .copied.show{display:block}

    /* ── TOAST ── */
    .toast{position:fixed;bottom:24px;right:24px;z-index:999;background:var(--bg3);border:1px solid var(--border);border-radius:11px;padding:13px 20px;font-size:13px;color:var(--fg);box-shadow:0 10px 28px rgba(0,0,0,.55);display:flex;align-items:center;gap:11px;transform:translateY(80px);opacity:0;transition:all .3s;font-family:'Space Mono',monospace;max-width:300px}
    .toast.show{transform:translateY(0);opacity:1}
    .toast i{color:var(--c)}

    /* ── SHORTCUTS ── */
    .shortcuts{font-size:12px;color:var(--fg3);display:flex;gap:14px;flex-wrap:wrap}
    .shortcuts span{display:flex;align-items:center;gap:5px}

    /* ── SCAN TYPE INDICATOR ── */
    .scan-mode-lbl{font-family:'Space Mono',monospace;font-size:11px;color:var(--fg3);margin-bottom:18px;display:flex;align-items:center;gap:8px}
    .scan-mode-lbl::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--c);box-shadow:var(--gc);animation:pulse 2s ease infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

    /* ── RESPONSIVE ── */
    @media(max-width:768px){
      .hnav{display:none}.hburger{display:flex}
      .irow{flex-direction:column}.ibtn{justify-content:center}
      .res-grid{grid-template-columns:1fr}.crypto-grid{grid-template-columns:1fr}
      .frow{flex-direction:column;text-align:center}
      .hero-chips{gap:8px}.chip{font-size:11px}
      .toolbar{flex-direction:column;align-items:flex-start}
    }
    @media(max-width:480px){
      .tabs{justify-content:center}.tab{flex:1;justify-content:center}.scanner{padding:18px}
    }
    ::-webkit-scrollbar{width:5px}
    ::-webkit-scrollbar-track{background:var(--bg2)}
    ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
    ::-webkit-scrollbar-thumb:hover{background:var(--c)}
    ::selection{background:rgba(155,93,229,.4);color:var(--fg)}
  </style>
</head>
<body>

<header>
  <div class="wrap">
    <div class="hrow">
      <a class="logo" href="/">
        <div class="logo-mark"><i class="fas fa-crosshairs"></i></div>
        <span class="logo-text">SHADOWTRACE</span>
        <span class="logo-badge">v2.0</span>
      </a>
      <nav class="hnav">
        <a href="mailto:shadowtrace5@proton.me" class="nbtn"><i class="fas fa-envelope"></i> Contact</a>
        <button class="nbtn donate" onclick="openM('donate')"><i class="fas fa-heart"></i> Donate</button>
      </nav>
      <button class="hburger" onclick="toggleMob()"><i class="fas fa-bars"></i></button>
    </div>
  </div>
</header>

<div class="mob-overlay" id="mobOverlay" onclick="closeMob()"></div>
<div class="mob-panel" id="mobPanel">
  <div class="mob-hd"><h3>MENU</h3><button class="mob-x" onclick="closeMob()"><i class="fas fa-times"></i></button></div>
  <a href="mailto:shadowtrace5@proton.me" class="mob-item"><i class="fas fa-envelope"></i> Contact</a>
  <button class="mob-item donate" onclick="openM('donate');closeMob()"><i class="fas fa-heart"></i> Donate</button>
  <button class="mob-item" onclick="openM('privacy');closeMob()"><i class="fas fa-shield-alt"></i> Privacy</button>
  <button class="mob-item" onclick="openM('guide');closeMob()"><i class="fas fa-book"></i> Guide</button>
</div>

<main>
  <div class="wrap">

    <div class="hero">
      <div class="hero-eye"><i class="fas fa-satellite-dish"></i> PASSIVE RECONNAISSANCE PLATFORM</div>
      <h1>OSINT INTELLIGENCE</h1>
      <p>Map digital footprints across email, username, domain, and phone data sources — passively, with no account required.</p>
      <div class="hero-chips">
        <div class="chip c"><i class="fas fa-envelope"></i> Email Lookup</div>
        <div class="chip p"><i class="fas fa-user"></i> Username Trace</div>
        <div class="chip g"><i class="fas fa-globe"></i> Domain Intel</div>
        <div class="chip pk"><i class="fas fa-phone"></i> Phone OSINT</div>
      </div>
    </div>

    <div class="hist-panel" id="histPanel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="hist-title"><i class="fas fa-history" style="color:var(--c);margin-right:8px"></i>RECENT SCANS</div>
        <button class="hist-clear" onclick="clearHistory()">Clear all</button>
      </div>
      <div class="hist-list" id="histList"></div>
    </div>

    <div class="scanner">
      <div class="scanner-bar"></div>

      <div class="tabs">
        <div class="tab active" data-mode="email"><div class="tab-dot"></div><i class="fas fa-envelope"></i> Email</div>
        <div class="tab" data-mode="username"><div class="tab-dot"></div><i class="fas fa-user"></i> Username</div>
        <div class="tab" data-mode="domain"><div class="tab-dot"></div><i class="fas fa-globe"></i> Domain</div>
        <div class="tab" data-mode="phone"><div class="tab-dot"></div><i class="fas fa-phone"></i> Phone</div>
      </div>

      <div class="scan-mode-lbl" id="modeLbl">EMAIL SCAN MODE</div>

      <div class="irow">
        <div class="ibox">
          <i class="fas fa-envelope" id="iicon"></i>
          <input id="target" placeholder="e.g., user@example.com" autocomplete="off" spellcheck="false">
        </div>
        <button id="runBtn" class="ibtn" style="position:relative">
          <i class="fas fa-bolt"></i> SCAN
        </button>
      </div>

      <div class="toolbar">
        <div class="disc"><i class="fas fa-shield-alt"></i> Passive recon only · Use responsibly</div>
        <div class="tactions">
          <button class="tact-btn" id="exportBtn" onclick="exportResults()" disabled>
            <i class="fas fa-download"></i> Export JSON
          </button>
          <button class="tact-btn" onclick="openM('guide')">
            <i class="fas fa-question-circle"></i> Guide
          </button>
        </div>
      </div>

      <div class="prog-wrap" id="progWrap">
        <div class="prog-row">
          <span id="progLabel">Initializing...</span>
          <span class="prog-label" id="progPct">0%</span>
        </div>
        <div class="prog-track"><div class="prog-fill" id="progFill"></div></div>
      </div>
      <div class="msg msg-err" id="errMsg"></div>
      <div class="msg msg-ok" id="okMsg"></div>
    </div>

    <div class="queue-card" id="queueCard">
      <div class="queue-spinner"></div>
      <h3>QUEUED</h3>
      <p style="color:var(--fg3);font-size:13px">Your position in queue</p>
      <div class="queue-pos" id="queuePos">1</div>
      <p style="color:var(--fg3);font-size:13px">Waiting for a free processing slot...</p>
    </div>

    <div class="loading" id="loading">
      <div class="queue-spinner"></div>
      <p><span id="loadLabel">SCANNING</span> — collecting intelligence...</p>
    </div>

    <div id="resultsWrap" style="display:none">
      <div class="res-header">
        <div class="res-title">INTELLIGENCE REPORT</div>
        <div class="res-right">
          <div class="res-count" id="resCount">0 items</div>
        </div>
      </div>
      <div class="filter-row">
        <input class="filter-input" id="filterInput" placeholder="Filter results..." oninput="filterResults()">
      </div>
      <div class="res-grid" id="resGrid"></div>
    </div>

    <div class="empty show" id="emptyState">
      <div class="empty-icon"><i class="fas fa-satellite-dish"></i></div>
      <h3>READY TO TRACE</h3>
      <p>Enter a target above and press <span class="kbd">Enter</span> or click SCAN</p>
      <div class="shortcuts" style="justify-content:center;margin-top:18px">
        <span><span class="kbd">Tab</span> Switch mode</span>
        <span><span class="kbd">Ctrl+K</span> Focus input</span>
        <span><span class="kbd">Esc</span> Clear</span>
      </div>
    </div>

  </div>
</main>

<footer>
  <div class="wrap">
    <div class="frow">
      <div class="fcopy">© 2026 SHADOWTRACE · OSINT PLATFORM</div>
      <div class="flinks">
        <a onclick="openM('privacy')">Privacy</a>
        <a onclick="openM('guide')">Guide</a>
        <a onclick="openM('donate')">Support</a>
      </div>
    </div>
  </div>
</footer>

<div class="toast" id="toast"><i class="fas fa-check-circle"></i><span id="toastMsg">Copied!</span></div>

<!-- PRIVACY MODAL -->
<div class="modal-bg" id="modal-privacy">
  <div class="modal">
    <div class="modal-hd"><h2>PRIVACY POLICY</h2><button class="modal-x" onclick="closeM('privacy')">&times;</button></div>
    <div class="modal-body">
      <div class="msec"><h3>Data Handling</h3><p>This platform performs passive reconnaissance using public APIs and open-source data. Scan targets are processed server-side and results are streamed directly to your browser.</p></div>
      <div class="msec"><h3>Third-Party Sources</h3><p>We query public sources including WHOIS registries, DNS servers, social platform endpoints, and phone carrier databases. Your queries are never sold or shared with third parties.</p></div>
      <div class="msec"><h3>Responsible Use</h3><p>This tool is intended for legitimate security research, digital footprint awareness, and OSINT education only. Always obtain proper authorisation before scanning any target you do not own or have explicit permission to scan.</p></div>
    </div>
  </div>
</div>

<!-- GUIDE MODAL -->
<div class="modal-bg" id="modal-guide">
  <div class="modal">
    <div class="modal-hd"><h2>USAGE GUIDE</h2><button class="modal-x" onclick="closeM('guide')">&times;</button></div>
    <div class="modal-body">
      <div class="msec"><h3>Email</h3><p>Uses Holehe to check whether an email is registered on popular services. Returns confirmed registrations only.</p></div>
      <div class="msec"><h3>Username</h3><p>Probes 40+ platforms for username existence via HTTP checks. Click a result card to open the profile directly.</p></div>
      <div class="msec"><h3>Domain</h3><p>Performs WHOIS lookup, DNS enumeration (A, AAAA, MX, NS, TXT, CAA), IP resolution, web server fingerprinting, and TLS certificate inspection.</p></div>
      <div class="msec"><h3>Phone</h3><p>Validates and formats the number, identifies carrier and geographic region, timezone, number type, and provides quick links to WhatsApp, Telegram, and Google.</p></div>
      <div class="msec"><h3>Keyboard Shortcuts</h3>
        <ul>
          <li><strong>Enter</strong> — Start scan</li>
          <li><strong>Tab</strong> — Cycle scan modes</li>
          <li><strong>Ctrl + K</strong> — Focus input</li>
          <li><strong>Escape</strong> — Clear / close</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<!-- DONATE MODAL -->
<div class="modal-bg" id="modal-donate">
  <div class="modal">
    <div class="modal-hd"><h2>SUPPORT THE PROJECT</h2><button class="modal-x" onclick="closeM('donate')">&times;</button></div>
    <div class="modal-body">
      <p style="color:var(--fg2);font-size:14px;margin-bottom:4px">Help keep this service running and free. Every contribution is genuinely appreciated.</p>
      <div class="crypto-grid">
        <div class="ccard">
          <div class="ccard-icon btc"><i class="fab fa-bitcoin"></i></div>
          <h3 class="btc">Bitcoin</h3>
          <div class="wallet" id="btcAddr">bc1qzpsqrjp5kuax6n6q0uuatkmeacc82rp8sfur7l</div>
          <button class="cbtn" onclick="copyWallet('btcAddr','btcOk')"><i class="fas fa-copy"></i> COPY</button>
          <div class="copied" id="btcOk">✓ Copied!</div>
        </div>
        <div class="ccard">
          <div class="ccard-icon eth"><i class="fab fa-ethereum"></i></div>
          <h3 class="eth">Ethereum</h3>
          <div class="wallet" id="ethAddr">0x70e93cab6cc9a7c6c7f68662bfd2ca160d3afa3d</div>
          <button class="cbtn" onclick="copyWallet('ethAddr','ethOk')"><i class="fas fa-copy"></i> COPY</button>
          <div class="copied" id="ethOk">✓ Copied!</div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let mode = 'email';
let currentJobId = null;
let resultCount = 0;
let allResults = [];
let scanHistory = JSON.parse(localStorage.getItem('st_history') || '[]');
let progTimer = null;
let progVal = 0;

const $ = id => document.getElementById(id);
const runBtn   = $('runBtn');
const targetIn = $('target');
const errMsg   = $('errMsg');
const okMsg    = $('okMsg');
const loading  = $('loading');
const queueCard= $('queueCard');
const resWrap  = $('resultsWrap');
const resGrid  = $('resGrid');
const resCount = $('resCount');
const emptyState=$('emptyState');
const progWrap = $('progWrap');
const progFill = $('progFill');
const progLabel= $('progLabel');
const progPct  = $('progPct');
const exportBtn= $('exportBtn');
const filterIn = $('filterInput');

const modeIcons = {email:'fa-envelope',username:'fa-user',domain:'fa-globe',phone:'fa-phone'};
const modePH    = {email:'e.g., user@example.com',username:'e.g., johndoe',domain:'e.g., example.com',phone:'e.g., +1234567890'};
const modeLbls  = {email:'EMAIL SCAN MODE',username:'USERNAME TRACE MODE',domain:'DOMAIN INTELLIGENCE MODE',phone:'PHONE OSINT MODE'};

document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  mode = t.dataset.mode;
  targetIn.placeholder = modePH[mode];
  $('iicon').className = 'fas ' + modeIcons[mode];
  $('modeLbl').textContent = modeLbls[mode];
}));

targetIn.addEventListener('keydown', e => {
  if (e.key === 'Tab' && document.activeElement === targetIn) {
    e.preventDefault();
    const modes = ['email','username','domain','phone'];
    const next = modes[(modes.indexOf(mode)+1)%modes.length];
    document.querySelector(`[data-mode="${next}"]`).click();
  }
  if (e.key === 'Enter') runBtn.click();
  if (e.key === 'Escape') { targetIn.value = ''; clearMessages(); }
});
document.addEventListener('keydown', e => {
  if ((e.ctrlKey||e.metaKey) && e.key === 'k') { e.preventDefault(); targetIn.focus(); }
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-bg.show').forEach(m => m.classList.remove('show'));
    closeMob();
    document.body.style.overflow = '';
  }
});

runBtn.addEventListener('click', async () => {
  const target = targetIn.value.trim();
  if (!target) { showErr('Enter a target to scan'); return; }
  resetUI();
  loading.classList.add('show');
  runBtn.disabled = true;
  startFakeProgress();
  try {
    const res = await fetch('/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({mode, target})
    });
    const data = await res.json();
    if (data.status === 'error') throw new Error(data.message);
    if (data.status === 'queued') {
      loading.classList.remove('show');
      stopFakeProgress();
      queueCard.classList.add('show');
      $('queuePos').textContent = data.queue_position;
      currentJobId = data.job_id;
      pollQueue();
    } else {
      currentJobId = data.job_id;
      saveHistory(mode, target);
      startStream();
    }
  } catch(err) {
    loading.classList.remove('show');
    stopFakeProgress();
    showErr(err.message || 'Server error');
    runBtn.disabled = false;
  }
});

async function pollQueue() {
  if (!currentJobId) return;
  try {
    const r = await fetch(`/queue-status/${currentJobId}`);
    const d = await r.json();
    if (d.status === 'started') {
      queueCard.classList.remove('show');
      loading.classList.add('show');
      startFakeProgress();
      startStream();
    } else if (d.status === 'queued') {
      $('queuePos').textContent = d.queue_position;
      setTimeout(pollQueue, 3000);
    }
  } catch { showErr('Queue check failed'); runBtn.disabled = false; }
}

function startStream() {
  const es = new EventSource(`/stream/${currentJobId}`);
  $('loadLabel').textContent = mode.toUpperCase();
  es.onmessage = e => {
    if (e.data === '__DONE__') {
      es.close();
      loading.classList.remove('show');
      stopFakeProgress();
      progWrap.classList.remove('show');
      if (resultCount === 0) {
        emptyState.classList.add('show');
        emptyState.querySelector('h3').textContent = 'NO RESULTS';
        emptyState.querySelector('p').textContent = 'Nothing found for this target.';
      } else {
        resWrap.style.display = 'block';
        exportBtn.disabled = false;
      }
      runBtn.disabled = false;
      return;
    }
    try { addCard(JSON.parse(e.data)); } catch {}
  };
  es.onerror = () => {
    es.close();
    loading.classList.remove('show');
    stopFakeProgress();
    showErr('Connection lost during scan');
    runBtn.disabled = false;
  };
}

function addCard(obj) {
  resultCount++;
  updateCount();
  allResults.push(obj);
  const card = document.createElement('div');
  card.className = 'rcard' + (obj.url ? ' link' : '');
  card.dataset.search = (obj.title + ' ' + obj.body).toLowerCase();
  if (obj.url) card.addEventListener('click', () => window.open(obj.url, '_blank'));
  const tagClass = {email:'tag-email',username:'tag-username',domain:'tag-domain',phone:'tag-phone'}[obj.tag] || 'tag-domain';
  card.innerHTML = `
    <div class="rcard-top">
      <div class="rcard-title"><i class="fas ${obj.icon||'fa-info-circle'}"></i> ${obj.title}</div>
      <button class="rcard-copy" onclick="event.stopPropagation();copyText('${escJs(obj.body_plain||obj.body)}')"><i class="fas fa-copy"></i> copy</button>
    </div>
    <div class="rcard-body">${obj.body}</div>
    ${obj.tag ? `<div class="rcard-tag ${tagClass}">${obj.tag.toUpperCase()}</div>` : ''}
  `;
  resGrid.appendChild(card);
  if (!resWrap.style.display || resWrap.style.display==='none') resWrap.style.display='block';
}

function escJs(s){return (s||'').replace(/'/g,"\\'").replace(/"/g,"&quot;")}

function filterResults() {
  const q = filterIn.value.toLowerCase();
  document.querySelectorAll('.rcard').forEach(c => {
    c.style.display = c.dataset.search.includes(q) ? '' : 'none';
  });
}

function exportResults() {
  const blob = new Blob([JSON.stringify(allResults, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `shadowtrace_${Date.now()}.json`;
  a.click();
  showToast('Exported as JSON');
}

function saveHistory(m, t) {
  scanHistory = scanHistory.filter(x => !(x.m===m && x.t===t));
  scanHistory.unshift({m, t});
  if (scanHistory.length > 8) scanHistory = scanHistory.slice(0, 8);
  localStorage.setItem('st_history', JSON.stringify(scanHistory));
  renderHistory();
}
function renderHistory() {
  const panel = $('histPanel'); const list = $('histList');
  if (!scanHistory.length) { panel.classList.remove('show'); return; }
  panel.classList.add('show');
  list.innerHTML = scanHistory.map(x =>
    `<div class="hist-item" onclick="loadHistory('${x.m}','${escJs(x.t)}')"><i class="fas ${modeIcons[x.m]}"></i>${escHtml(x.t)}</div>`
  ).join('');
}
function loadHistory(m, t) {
  document.querySelector(`[data-mode="${m}"]`).click();
  targetIn.value = t; targetIn.focus();
}
function clearHistory() {
  scanHistory = []; localStorage.removeItem('st_history');
  $('histPanel').classList.remove('show');
}
function escHtml(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

function startFakeProgress() {
  progVal=0; progWrap.classList.add('show');
  progFill.style.width='0%'; progLabel.textContent='Initializing...'; progPct.textContent='0%';
  progTimer = setInterval(() => {
    if (progVal < 85) {
      progVal += Math.random() * 2.5;
      progFill.style.width = progVal + '%';
      progPct.textContent = Math.round(progVal) + '%';
    }
  }, 300);
}
function stopFakeProgress() {
  clearInterval(progTimer);
  progVal=100; progFill.style.width='100%'; progPct.textContent='100%'; progLabel.textContent='Complete';
}

function resetUI() {
  clearMessages(); emptyState.classList.remove('show');
  emptyState.querySelector('h3').textContent = 'READY TO TRACE';
  resWrap.style.display='none'; queueCard.classList.remove('show');
  loading.classList.remove('show'); resGrid.innerHTML='';
  resultCount=0; allResults=[]; exportBtn.disabled=true; filterIn.value=''; updateCount();
}
function updateCount(){resCount.textContent=`${resultCount} item${resultCount!==1?'s':''}`}
function showErr(t){errMsg.textContent='⚠ '+t;errMsg.classList.add('show')}
function clearMessages(){errMsg.classList.remove('show');okMsg.classList.remove('show')}

function showToast(msg) {
  $('toastMsg').textContent = msg;
  const t = $('toast'); t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
function copyText(text){navigator.clipboard?.writeText(text).then(()=>showToast('Copied to clipboard'))}
function copyWallet(id,okId){
  navigator.clipboard?.writeText($(id).innerText).then(()=>{
    const el=$(okId);el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2000);
  });
}
function openM(id){$('modal-'+id).classList.add('show');document.body.style.overflow='hidden'}
function closeM(id){$('modal-'+id).classList.remove('show');document.body.style.overflow=''}
document.querySelectorAll('.modal-bg').forEach(m=>m.addEventListener('click',e=>{if(e.target===m){m.classList.remove('show');document.body.style.overflow=''}}));
function toggleMob(){$('mobPanel').classList.toggle('open');$('mobOverlay').classList.toggle('open')}
function closeMob(){$('mobPanel').classList.remove('open');$('mobOverlay').classList.remove('open')}
renderHistory();
</script>
</body>
</html>"""

# ============================================================
#  ADMIN PANEL HTML — completely unlisted / hidden
# ============================================================
ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>System Dashboard</title>
  <meta name="robots" content="noindex,nofollow">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
  <style>
    :root{--bg0:#02020a;--bg1:#07070f;--bg2:#0c0c18;--bg3:#111122;--b:#18182e;--b2:#222240;--fg:#ddddf0;--fg2:#8888aa;--fg3:#44445a;--c:#00e5ff;--p:#9b5de5;--g:#00f5a0;--pk:#ff4d8f;--y:#ffd166;--o:#ff9a3c;--r:#ff4455}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Space Grotesk',sans-serif;background:var(--bg0);color:var(--fg);min-height:100vh}
    body::before{content:'';position:fixed;inset:0;z-index:0;background-image:linear-gradient(rgba(0,229,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.02) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
    .wrap{max-width:1300px;margin:0 auto;padding:0 20px;position:relative;z-index:1}

    /* HEADER */
    header{background:rgba(2,2,10,.9);border-bottom:1px solid var(--b);backdrop-filter:blur(20px);position:sticky;top:0;z-index:100}
    .hrow{display:flex;align-items:center;justify-content:space-between;padding:14px 0}
    .logo{display:flex;align-items:center;gap:10px;font-family:'Space Mono',monospace;font-size:15px;font-weight:700;color:var(--c);text-shadow:0 0 12px rgba(0,229,255,.4)}
    .logo i{font-size:18px}
    .hadmin{display:flex;align-items:center;gap:10px}
    .badge{font-size:11px;padding:4px 10px;border-radius:20px;border:1px solid}
    .badge.live{border-color:var(--g);color:var(--g);background:rgba(0,245,160,.08)}
    .badge.warn{border-color:var(--y);color:var(--y);background:rgba(255,209,102,.08)}
    .logout-btn{display:flex;align-items:center;gap:7px;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:500;border:1px solid var(--b2);background:var(--bg2);color:var(--fg2);cursor:pointer;text-decoration:none;transition:all .2s;font-family:'Space Grotesk',sans-serif}
    .logout-btn:hover{border-color:var(--pk);color:var(--pk)}

    /* STATS ROW */
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;padding:28px 0 20px}
    .scard{background:var(--bg2);border:1px solid var(--b);border-radius:14px;padding:20px;position:relative;overflow:hidden}
    .scard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
    .scard.s1::before{background:linear-gradient(90deg,var(--c),var(--p))}
    .scard.s2::before{background:linear-gradient(90deg,var(--g),var(--c))}
    .scard.s3::before{background:linear-gradient(90deg,var(--y),var(--o))}
    .scard.s4::before{background:linear-gradient(90deg,var(--pk),var(--p))}
    .scard.s5::before{background:linear-gradient(90deg,var(--r),var(--pk))}
    .scard-lbl{font-size:11px;font-weight:600;letter-spacing:.12em;color:var(--fg3);margin-bottom:10px;text-transform:uppercase}
    .scard-val{font-family:'Space Mono',monospace;font-size:32px;font-weight:700;color:var(--fg)}
    .scard-sub{font-size:12px;color:var(--fg3);margin-top:6px}

    /* TOOLBAR */
    .toolbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:16px;padding:16px 0 0}
    .ctrl-btn{display:flex;align-items:center;gap:7px;padding:9px 16px;border-radius:8px;font-size:13px;font-weight:500;border:1px solid var(--b2);background:var(--bg2);color:var(--fg2);cursor:pointer;transition:all .2s;font-family:'Space Grotesk',sans-serif}
    .ctrl-btn:hover{border-color:var(--c);color:var(--fg)}
    .ctrl-btn.danger:hover{border-color:var(--r);color:var(--r)}
    .search-box{flex:1;min-width:200px;background:var(--bg2);border:1px solid var(--b);border-radius:8px;padding:9px 14px;font-size:13px;color:var(--fg);outline:none;transition:border-color .2s;font-family:'Space Grotesk',sans-serif}
    .search-box:focus{border-color:var(--c)}
    .search-box::placeholder{color:var(--fg3)}

    /* TABS */
    .sec-tabs{display:flex;gap:6px;margin-bottom:18px}
    .sec-tab{padding:9px 20px;border-radius:8px;font-size:13px;font-weight:600;border:1px solid var(--b);background:var(--bg2);color:var(--fg2);cursor:pointer;transition:all .2s;letter-spacing:.04em}
    .sec-tab:hover{border-color:var(--c);color:var(--fg)}
    .sec-tab.active{background:rgba(0,229,255,.1);border-color:var(--c);color:var(--c)}
    .sec-panel{display:none}.sec-panel.show{display:block}

    /* TABLE */
    .tbl-wrap{background:var(--bg2);border:1px solid var(--b);border-radius:14px;overflow:hidden;margin-bottom:24px}
    table{width:100%;border-collapse:collapse}
    thead tr{background:var(--bg3);border-bottom:1px solid var(--b2)}
    th{padding:12px 16px;font-size:11px;font-weight:700;letter-spacing:.1em;color:var(--fg3);text-align:left;white-space:nowrap}
    td{padding:11px 16px;font-size:13px;color:var(--fg2);border-bottom:1px solid var(--b);vertical-align:middle;max-width:280px;word-break:break-all}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:rgba(255,255,255,.02)}
    .ip-cell{font-family:'Space Mono',monospace;font-size:12px;color:var(--c)}
    .target-cell{font-family:'Space Mono',monospace;font-size:12px;color:var(--fg)}
    .ts-cell{font-family:'Space Mono',monospace;font-size:11px;color:var(--fg3);white-space:nowrap}
    .mode-badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.06em}
    .m-email{background:rgba(68,136,255,.15);border:1px solid rgba(68,136,255,.3);color:#4488ff}
    .m-username{background:rgba(155,93,229,.15);border:1px solid rgba(155,93,229,.3);color:var(--p)}
    .m-domain{background:rgba(0,245,160,.12);border:1px solid rgba(0,245,160,.3);color:var(--g)}
    .m-phone{background:rgba(255,154,60,.12);border:1px solid rgba(255,154,60,.3);color:var(--o)}
    .m-block{background:rgba(255,68,85,.12);border:1px solid rgba(255,68,85,.3);color:var(--r)}

    /* IP DETAILS CARD */
    .ip-detail{background:var(--bg3);border:1px solid var(--b2);border-radius:8px;padding:12px 16px;font-size:12px;color:var(--fg2);margin-top:4px;font-family:'Space Mono',monospace;display:none}
    .ip-detail.show{display:block}
    .ip-expand{cursor:pointer;font-size:11px;color:var(--fg3);background:none;border:none;padding:2px 6px;border-radius:4px;transition:color .2s}
    .ip-expand:hover{color:var(--c)}

    /* PAGINATION */
    .pager{display:flex;justify-content:center;align-items:center;gap:8px;padding:16px 0}
    .pager-btn{padding:7px 14px;border-radius:7px;font-size:13px;font-weight:500;border:1px solid var(--b2);background:var(--bg2);color:var(--fg2);cursor:pointer;transition:all .2s;font-family:'Space Grotesk',sans-serif}
    .pager-btn:hover{border-color:var(--c);color:var(--fg)}
    .pager-btn:disabled{opacity:.35;cursor:not-allowed}
    .pager-info{font-size:12px;color:var(--fg3);font-family:'Space Mono',monospace}

    /* LOGIN */
    .login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}
    .login-box{background:var(--bg2);border:1px solid var(--b);border-radius:18px;padding:40px;width:100%;max-width:400px;position:relative;overflow:hidden}
    .login-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--c),var(--p),var(--pk))}
    .login-title{font-family:'Space Mono',monospace;font-size:13px;font-weight:700;color:var(--c);text-align:center;margin-bottom:28px;letter-spacing:.15em}
    .login-field{margin-bottom:16px}
    .login-field label{display:block;font-size:12px;font-weight:600;color:var(--fg3);letter-spacing:.08em;margin-bottom:7px;text-transform:uppercase}
    .login-field input{width:100%;background:var(--bg3);border:1px solid var(--b);border-radius:9px;padding:12px 16px;font-size:14px;color:var(--fg);outline:none;transition:border-color .2s;font-family:'Space Mono',monospace}
    .login-field input:focus{border-color:var(--c)}
    .login-btn{width:100%;padding:13px;border-radius:10px;font-size:14px;font-weight:700;background:linear-gradient(135deg,var(--c),var(--p));border:none;color:#000;cursor:pointer;transition:all .2s;font-family:'Space Mono',monospace;letter-spacing:.06em;margin-top:8px}
    .login-btn:hover{transform:translateY(-2px);box-shadow:0 0 18px rgba(0,229,255,.3)}
    .login-err{background:rgba(255,68,85,.1);border:1px solid rgba(255,68,85,.3);border-radius:8px;padding:10px 14px;font-size:13px;color:var(--r);margin-top:12px;font-family:'Space Mono',monospace;display:none}
    .login-err.show{display:block}

    /* CHART-LIKE BAR */
    .mini-bar{height:6px;border-radius:3px;background:linear-gradient(90deg,var(--c),var(--p));margin-top:6px}

    /* EMPTY */
    .tbl-empty{text-align:center;padding:48px 20px;color:var(--fg3);font-family:'Space Mono',monospace;font-size:13px}

    .text-right{text-align:right}
    @media(max-width:768px){th:nth-child(5),td:nth-child(5),th:nth-child(4),td:nth-child(4){display:none}}
    ::-webkit-scrollbar{width:5px}
    ::-webkit-scrollbar-track{background:var(--bg2)}
    ::-webkit-scrollbar-thumb{background:var(--b2);border-radius:3px}
    ::-webkit-scrollbar-thumb:hover{background:var(--c)}
  </style>
</head>
<body>
{% if not logged_in %}
<div class="login-wrap">
  <div class="login-box">
    <div class="login-title">⬡ SYSTEM ACCESS</div>
    <form method="POST">
      <div class="login-field">
        <label>Identifier</label>
        <input type="text" name="username" autocomplete="off" required placeholder="enter identifier">
      </div>
      <div class="login-field">
        <label>Access Key</label>
        <input type="password" name="password" required placeholder="••••••••••••">
      </div>
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <button class="login-btn" type="submit">ACCESS SYSTEM</button>
      {% if error %}<div class="login-err show">{{ error }}</div>{% endif %}
    </form>
  </div>
</div>
{% else %}
<header>
  <div class="wrap">
    <div class="hrow">
      <div class="logo"><i class="fas fa-server"></i> SYSTEM MONITOR</div>
      <div class="hadmin">
        <span class="badge live"><i class="fas fa-circle" style="font-size:8px"></i> LIVE</span>
        <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Sign Out</a>
      </div>
    </div>
  </div>
</header>

<div class="wrap">
  <div class="stats">
    <div class="scard s1">
      <div class="scard-lbl">Total Scans</div>
      <div class="scard-val">{{ stats.total }}</div>
      <div class="scard-sub">all time</div>
    </div>
    <div class="scard s2">
      <div class="scard-lbl">Scans Today</div>
      <div class="scard-val">{{ stats.today }}</div>
      <div class="scard-sub">{{ stats.today_date }}</div>
    </div>
    <div class="scard s3">
      <div class="scard-lbl">Unique IPs</div>
      <div class="scard-val">{{ stats.unique_ips }}</div>
      <div class="scard-sub">total visitors</div>
    </div>
    <div class="scard s4">
      <div class="scard-lbl">Rate Blocks</div>
      <div class="scard-val">{{ stats.blocks }}</div>
      <div class="scard-sub">blocked requests</div>
    </div>
    <div class="scard s5">
      <div class="scard-lbl">Email Lookups</div>
      <div class="scard-val">{{ stats.emails }}</div>
      <div class="scard-sub">email scans run</div>
    </div>
  </div>

  <div class="sec-tabs">
    <button class="sec-tab active" onclick="showTab('scans')">
      <i class="fas fa-list" style="margin-right:7px"></i>Scan Log
    </button>
    <button class="sec-tab" onclick="showTab('blocks')">
      <i class="fas fa-ban" style="margin-right:7px"></i>Rate Blocks
    </button>
    <button class="sec-tab" onclick="showTab('ips')">
      <i class="fas fa-network-wired" style="margin-right:7px"></i>IP Summary
    </button>
  </div>

  <!-- SCAN LOG -->
  <div class="sec-panel show" id="tab-scans">
    <div class="toolbar">
      <input class="search-box" type="text" id="scanSearch" placeholder="Search IP, target, mode..." oninput="filterScans()">
      <a href="?export=scans" class="ctrl-btn"><i class="fas fa-download"></i> Export CSV</a>
      <button class="ctrl-btn danger" onclick="confirmClear('scans')"><i class="fas fa-trash"></i> Clear Logs</button>
    </div>
    <div class="tbl-wrap">
      <table id="scanTable">
        <thead>
          <tr>
            <th>#</th>
            <th>TIMESTAMP (UTC)</th>
            <th>IP ADDRESS</th>
            <th>MODE</th>
            <th>TARGET</th>
            <th>USER AGENT</th>
            <th>RESULTS</th>
          </tr>
        </thead>
        <tbody>
          {% for row in scans %}
          <tr>
            <td style="color:var(--fg3);font-family:'Space Mono',monospace;font-size:11px">{{ row[0] }}</td>
            <td class="ts-cell">{{ row[1][:19].replace('T',' ') }}</td>
            <td class="ip-cell">{{ row[2] }}</td>
            <td><span class="mode-badge m-{{ row[3] }}">{{ row[3].upper() }}</span></td>
            <td class="target-cell">{{ row[4][:60] }}{{ '...' if row[4]|length > 60 else '' }}</td>
            <td style="font-size:11px;color:var(--fg3);max-width:180px">{{ (row[5] or '—')[:60] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:12px;color:var(--y)">{{ row[6] or 0 }}</td>
          </tr>
          {% else %}
          <tr><td colspan="7" class="tbl-empty">No scan records yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- RATE BLOCKS -->
  <div class="sec-panel" id="tab-blocks">
    <div class="toolbar">
      <a href="?export=blocks" class="ctrl-btn"><i class="fas fa-download"></i> Export CSV</a>
      <button class="ctrl-btn danger" onclick="confirmClear('blocks')"><i class="fas fa-trash"></i> Clear</button>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>TIMESTAMP</th>
            <th>IP ADDRESS</th>
            <th>REASON</th>
          </tr>
        </thead>
        <tbody>
          {% for row in blocks %}
          <tr>
            <td style="color:var(--fg3);font-family:'Space Mono',monospace;font-size:11px">{{ row[0] }}</td>
            <td class="ts-cell">{{ row[1][:19].replace('T',' ') }}</td>
            <td class="ip-cell">{{ row[2] }}</td>
            <td><span class="mode-badge m-block">{{ row[3] or 'Rate Limit' }}</span></td>
          </tr>
          {% else %}
          <tr><td colspan="4" class="tbl-empty">No blocked requests.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- IP SUMMARY -->
  <div class="sec-panel" id="tab-ips">
    <div class="toolbar">
      <a href="?export=ips" class="ctrl-btn"><i class="fas fa-download"></i> Export CSV</a>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>IP ADDRESS</th>
            <th>TOTAL SCANS</th>
            <th>EMAIL SCANS</th>
            <th>PHONE SCANS</th>
            <th>DOMAIN SCANS</th>
            <th>USERNAME SCANS</th>
            <th>LAST SEEN (UTC)</th>
          </tr>
        </thead>
        <tbody>
          {% for row in ip_summary %}
          <tr>
            <td class="ip-cell">{{ row[0] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:13px;color:var(--c)">{{ row[1] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:12px">{{ row[2] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:12px">{{ row[3] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:12px">{{ row[4] }}</td>
            <td style="font-family:'Space Mono',monospace;font-size:12px">{{ row[5] }}</td>
            <td class="ts-cell">{{ row[6][:19].replace('T',' ') if row[6] else '—' }}</td>
          </tr>
          {% else %}
          <tr><td colspan="7" class="tbl-empty">No data yet.</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

</div><!-- /wrap -->

<script>
function showTab(name) {
  document.querySelectorAll('.sec-panel').forEach(p=>p.classList.remove('show'));
  document.querySelectorAll('.sec-tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('show');
  event.currentTarget.classList.add('active');
}
function filterScans() {
  const q = document.getElementById('scanSearch').value.toLowerCase();
  document.querySelectorAll('#scanTable tbody tr').forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
function confirmClear(tbl) {
  if (confirm('Permanently delete all records from this table?')) {
    window.location.href = '?clear='+tbl;
  }
}
</script>
{% endif %}
</body>
</html>"""

# ============================================================
#  ROUTES — PUBLIC
# ============================================================
@app.after_request
def sec_headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    r.headers['Referrer-Policy'] = 'no-referrer'
    return r

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/start', methods=['POST'])
def start():
    global active_requests
    ip = get_real_ip()
    ua = request.headers.get('User-Agent', '')

    if not check_ip_rate_limit(ip):
        db_log_block(ip, 'Rate limit exceeded')
        return jsonify({'status': 'error', 'message': 'Rate limit exceeded — try again in a minute'})

    data   = request.get_json(force=True)
    mode_v = data.get('mode', '')
    target = data.get('target', '').strip()

    ok, result = validate_target(mode_v, target)
    if not ok:
        return jsonify({'status': 'error', 'message': result})
    target = result

    job_id = str(uuid.uuid4())
    q = queue.Queue()
    jobs[job_id] = q

    with request_lock:
        if active_requests >= MAX_CONCURRENT_REQUESTS:
            pos = len(request_queue) + 1
            request_queue.append(job_id)
            return jsonify({'status': 'queued', 'job_id': job_id, 'queue_position': pos})
        active_requests += 1

    # Capture result count for logging
    result_counter = [0]

    def runner():
        global active_requests
        try:
            if mode_v == 'email':
                try:
                    p = subprocess.Popen(
                        ['holehe', '--only-used', target],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                    )
                    for line in p.stdout:
                        if line.startswith('[+]'):
                            svc = line.split(']', 1)[1].strip()
                            q.put(make_card(svc, 'Email registered on this platform',
                                           icon='fa-check-circle', tag='email'))
                            result_counter[0] += 1
                    p.wait()
                except FileNotFoundError:
                    q.put(make_card('holehe not installed',
                                   'Install with: pip install holehe',
                                   icon='fa-exclamation-triangle', tag='email'))

            elif mode_v == 'username':
                for name, url_tpl in USERNAME_PLATFORMS.items():
                    try:
                        u = url_tpl.format(u=target)
                        r = requests.get(u, timeout=5, allow_redirects=True,
                                         headers={'User-Agent': 'Mozilla/5.0'})
                        if r.status_code == 200 and len(r.content) > 500:
                            q.put(make_card(name,
                                           f'<a href="{u}" target="_blank">{u}</a>',
                                           body_plain=u,
                                           icon='fa-external-link-alt',
                                           tag='username', url=u))
                            result_counter[0] += 1
                    except Exception:
                        pass

            elif mode_v == 'domain':
                # WHOIS
                try:
                    info = whois.whois(target)
                    if info.registrar:
                        q.put(make_card('Registrar', info.registrar, icon='fa-building', tag='domain'))
                        result_counter[0] += 1
                    for field, label, icon in [
                        ('creation_date','Created','fa-calendar-plus'),
                        ('expiration_date','Expires','fa-calendar-times'),
                        ('updated_date','Updated','fa-calendar-check'),
                    ]:
                        val = getattr(info, field, None)
                        if val:
                            if isinstance(val, list): val = val[0]
                            ds = val.strftime('%Y-%m-%d') if hasattr(val,'strftime') else str(val)[:10]
                            q.put(make_card(label, ds, icon=icon, tag='domain'))
                            result_counter[0] += 1
                    if info.name_servers:
                        ns = info.name_servers
                        txt = ', '.join(str(x).lower() for x in (ns[:3] if isinstance(ns,list) else [ns]))
                        q.put(make_card('Name Servers', txt, icon='fa-server', tag='domain'))
                        result_counter[0] += 1
                    if info.status:
                        st = info.status
                        if isinstance(st, list): st = st[0]
                        q.put(make_card('WHOIS Status', str(st)[:80], icon='fa-tag', tag='domain'))
                        result_counter[0] += 1
                    if info.emails:
                        em = info.emails
                        if isinstance(em, list): em = ', '.join(em[:3])
                        q.put(make_card('Registrant Email', str(em), icon='fa-envelope', tag='domain'))
                        result_counter[0] += 1
                    if info.country:
                        q.put(make_card('Country', str(info.country), icon='fa-flag', tag='domain'))
                        result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('WHOIS Error', str(e)[:80], icon='fa-exclamation-triangle'))

                # DNS
                try:
                    import dns.resolver
                    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA']:
                        try:
                            answers = dns.resolver.resolve(target, rtype, lifetime=5)
                            for rec in answers:
                                q.put(make_card(f'DNS {rtype}', str(rec),
                                               icon='fa-network-wired', tag='domain'))
                                result_counter[0] += 1
                        except Exception:
                            pass
                except ImportError:
                    pass

                # IP
                try:
                    ip_addr = socket.gethostbyname(target)
                    q.put(make_card('IP Address', ip_addr, icon='fa-map-marker-alt', tag='domain'))
                    result_counter[0] += 1
                    try:
                        rev = socket.gethostbyaddr(ip_addr)[0]
                        q.put(make_card('Reverse DNS', rev, icon='fa-exchange-alt', tag='domain'))
                        result_counter[0] += 1
                    except Exception:
                        pass
                except Exception:
                    pass

                # HTTP
                for scheme in ('https://', 'http://'):
                    try:
                        r = requests.get(scheme + target, timeout=6,
                                        headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
                        srv  = r.headers.get('Server', '—')
                        powered = r.headers.get('X-Powered-By', '')
                        cf = 'Cloudflare' if 'cloudflare' in r.headers.get('CF-RAY','').lower() or \
                                             'cloudflare' in r.headers.get('Server','').lower() else ''
                        body = f'{scheme}{target} → HTTP {r.status_code}<br>Server: {srv}'
                        if powered: body += f'<br>Powered-By: {powered}'
                        if cf:      body += f'<br><span style="color:var(--o)">⚡ {cf}</span>'
                        q.put(make_card('Web Server', body,
                                       body_plain=f'{scheme}{target} HTTP {r.status_code} {srv}',
                                       icon='fa-globe', tag='domain'))
                        result_counter[0] += 1
                        break
                    except Exception:
                        pass

                # TLS
                try:
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
                        s.settimeout(6)
                        s.connect((target, 443))
                        cert = s.getpeercert()
                    cn = next((item[0][1] for sub in cert.get('subject',[]) for item in sub if item[0][0]=='commonName'), None)
                    issuer = next((item[0][1] for sub in cert.get('issuer',[]) for item in sub if item[0][0]=='organizationName'), None)
                    not_after = cert.get('notAfter','')
                    exp = None
                    for fmt in ('%b %d %H:%M:%S %Y %Z','%b %d %H:%M %Y %Z','%Y%m%d%H%M%SZ'):
                        try: exp = datetime.datetime.strptime(not_after, fmt); break
                        except: pass
                    days = (exp - datetime.datetime.now()).days if exp else None
                    col = 'var(--g)' if days and days>30 else ('var(--y)' if days and days>7 else 'var(--pk)')
                    parts = []
                    if cn:     parts.append(f'CN: {cn}')
                    if issuer: parts.append(f'Issuer: {issuer}')
                    if exp:    parts.append(f'Expires: {exp.strftime("%Y-%m-%d")}')
                    if days is not None: parts.append(f'<span style="color:{col}">{days} days remaining</span>')
                    sans = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
                    if sans: parts.append(f'SANs: {", ".join(sans[:4])}{"..." if len(sans)>4 else ""}')
                    if parts:
                        q.put(make_card('TLS Certificate', '<br>'.join(parts),
                                       body_plain=' | '.join(p for p in parts if '<' not in p),
                                       icon='fa-lock', tag='domain'))
                        result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('TLS', f'No TLS or error: {str(e)[:60]}', icon='fa-lock-open', tag='domain'))

            elif mode_v == 'phone':
                try:
                    import phonenumbers
                    from phonenumbers import geocoder, carrier, timezone as tz_mod
                    pn = phonenumbers.parse(target, None)
                    valid = phonenumbers.is_valid_number(pn)
                    q.put(make_card('Validity', 'Valid ✓' if valid else 'Invalid ✗',
                                   icon='fa-check-circle' if valid else 'fa-times-circle', tag='phone'))
                    result_counter[0] += 1
                    intl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                    e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
                    nat  = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
                    q.put(make_card('International', intl, icon='fa-phone-alt', tag='phone'))
                    q.put(make_card('E.164 Format', e164, icon='fa-hashtag', tag='phone'))
                    q.put(make_card('National', nat, icon='fa-phone', tag='phone'))
                    result_counter[0] += 3
                    region = geocoder.description_for_number(pn, 'en')
                    if region:
                        q.put(make_card('Region', region, icon='fa-map-marker-alt', tag='phone'))
                        result_counter[0] += 1
                    carr = carrier.name_for_number(pn, 'en')
                    if carr:
                        q.put(make_card('Carrier', carr, icon='fa-satellite-dish', tag='phone'))
                        result_counter[0] += 1
                    zones = tz_mod.time_zones_for_number(pn)
                    if zones:
                        q.put(make_card('Timezone', ', '.join(zones), icon='fa-clock', tag='phone'))
                        result_counter[0] += 1
                    ntype = phonenumbers.number_type(pn)
                    type_names = {0:'Fixed Line',1:'Mobile',2:'Fixed/Mobile',3:'Toll Free',4:'Premium',6:'VOIP',7:'Personal'}
                    q.put(make_card('Number Type', type_names.get(ntype,'Unknown'), icon='fa-tag', tag='phone'))
                    result_counter[0] += 1
                except Exception as e:
                    q.put(make_card('Parse Error', str(e)[:100], icon='fa-exclamation-triangle', tag='phone'))

                digits = re.sub(r'\D', '', target)
                if len(digits) >= 7:
                    wa_url = f'https://wa.me/{digits}'
                    tg_url = f'https://t.me/{digits}'
                    g_url  = f'https://www.google.com/search?q={digits}'
                    q.put(make_card('WhatsApp', f'<a href="{wa_url}" target="_blank">Open chat →</a>',
                                   body_plain=wa_url, icon='fab fa-whatsapp', tag='phone', url=wa_url))
                    q.put(make_card('Telegram',  f'<a href="{tg_url}" target="_blank">Check profile →</a>',
                                   body_plain=tg_url, icon='fab fa-telegram', tag='phone', url=tg_url))
                    q.put(make_card('Google',    f'<a href="{g_url}" target="_blank">Search number →</a>',
                                   body_plain=g_url, icon='fab fa-google', tag='phone', url=g_url))
                    result_counter[0] += 3

        except Exception as e:
            q.put(make_card('Unexpected Error', str(e)[:120], icon='fa-exclamation-circle'))
        finally:
            q.put('__DONE__')
            # Log to DB after scan completes
            db_log_scan(ip, mode_v, target, ua, result_counter[0])
            with request_lock:
                active_requests -= 1
                if request_queue:
                    request_queue.popleft()
            threading.Timer(600, lambda: jobs.pop(job_id, None)).start()

    threading.Thread(target=runner, daemon=True).start()
    return jsonify({'status': 'started', 'job_id': job_id})


@app.route('/queue-status/<job_id>')
def queue_status(job_id):
    global active_requests
    with request_lock:
        if job_id in request_queue:
            pos = list(request_queue).index(job_id) + 1
            return jsonify({'status': 'queued', 'queue_position': pos})
        elif job_id in jobs:
            if active_requests < MAX_CONCURRENT_REQUESTS:
                active_requests += 1
                return jsonify({'status': 'started'})
            else:
                if job_id not in request_queue:
                    request_queue.append(job_id)
                pos = list(request_queue).index(job_id) + 1
                return jsonify({'status': 'queued', 'queue_position': pos})
        return jsonify({'status': 'error', 'message': 'Job not found'})


@app.route('/stream/<job_id>')
def stream(job_id):
    def gen():
        q = jobs.get(job_id)
        if not q:
            yield 'data: __DONE__\n\n'
            return
        while True:
            try:
                m = q.get(timeout=60)
                if m == '__DONE__':
                    yield 'data: __DONE__\n\n'
                    break
                yield f'data: {m}\n\n'
            except queue.Empty:
                yield 'data: __DONE__\n\n'
                break
    return Response(gen(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


# ============================================================
#  ROUTES — ADMIN (hidden, unlisted)
# ============================================================
import secrets as _secrets

def _get_csrf():
    if '_csrf' not in session:
        session['_csrf'] = _secrets.token_hex(16)
    return session['_csrf']

def _admin_stats():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')
    stats = {
        'total':      cur.execute('SELECT COUNT(*) FROM scans').fetchone()[0],
        'today':      cur.execute('SELECT COUNT(*) FROM scans WHERE ts LIKE ?', (today+'%',)).fetchone()[0],
        'today_date': today,
        'unique_ips': cur.execute('SELECT COUNT(DISTINCT ip) FROM scans').fetchone()[0],
        'blocks':     cur.execute('SELECT COUNT(*) FROM rate_blocks').fetchone()[0],
        'emails':     cur.execute("SELECT COUNT(*) FROM scans WHERE mode='email'").fetchone()[0],
    }
    con.close()
    return stats

def _admin_scans(limit=500):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('SELECT id,ts,ip,mode,target,ua,result_ct FROM scans ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    con.close()
    return rows

def _admin_blocks(limit=500):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('SELECT id,ts,ip,msg FROM rate_blocks ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    con.close()
    return rows

def _admin_ip_summary():
    con = sqlite3.connect(DB_PATH)
    rows = con.execute('''
        SELECT ip,
               COUNT(*) as total,
               SUM(CASE WHEN mode='email' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='phone' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='domain' THEN 1 ELSE 0 END),
               SUM(CASE WHEN mode='username' THEN 1 ELSE 0 END),
               MAX(ts)
        FROM scans GROUP BY ip ORDER BY total DESC LIMIT 200
    ''').fetchall()
    con.close()
    return rows

def _export_csv(table):
    import csv, io
    con = sqlite3.connect(DB_PATH)
    if table == 'scans':
        rows = con.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
        header = ['id','ts','ip','mode','target','ua','result_ct']
    elif table == 'blocks':
        rows = con.execute('SELECT * FROM rate_blocks ORDER BY id DESC').fetchall()
        header = ['id','ts','ip','msg']
    elif table == 'ips':
        rows = _admin_ip_summary()
        header = ['ip','total','email','phone','domain','username','last_seen']
    else:
        con.close()
        return None, None
    con.close()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    w.writerows(rows)
    return buf.getvalue(), table

@app.route(f'/{ADMIN_PREFIX}', methods=['GET', 'POST'])
@app.route(f'/{ADMIN_PREFIX}/', methods=['GET', 'POST'])
def admin_panel():
    # Handle logout
    if request.args.get('logout'):
        session.clear()
        return redirect(f'/{ADMIN_PREFIX}')

    logged_in = session.get('admin_ok', False)
    error = None
    csrf_token = _get_csrf()

    # Handle login
    if request.method == 'POST' and not logged_in:
        uname = request.form.get('username', '')
        passw = request.form.get('password', '')
        csrf_in = request.form.get('csrf', '')
        # Constant-time compare
        if (hmac.compare_digest(uname, ADMIN_USERNAME) and
            hmac.compare_digest(passw, ADMIN_PASSWORD) and
            hmac.compare_digest(csrf_in, csrf_token)):
            session['admin_ok'] = True
            session.permanent = True
            return redirect(f'/{ADMIN_PREFIX}')
        else:
            error = 'Invalid credentials'
            import time as _t; _t.sleep(1.5)  # Throttle brute force

    if not logged_in:
        return render_template_string(ADMIN_HTML,
            logged_in=False, error=error, csrf_token=csrf_token)

    # Handle clear
    clear = request.args.get('clear')
    if clear in ('scans', 'blocks'):
        con = sqlite3.connect(DB_PATH)
        if clear == 'scans':
            con.execute('DELETE FROM scans')
        else:
            con.execute('DELETE FROM rate_blocks')
        con.commit(); con.close()
        return redirect(f'/{ADMIN_PREFIX}')

    # Handle export
    export = request.args.get('export')
    if export:
        csv_data, fname = _export_csv(export)
        if csv_data:
            return Response(csv_data, mimetype='text/csv',
                headers={'Content-Disposition': f'attachment;filename=shadowtrace_{fname}.csv'})

    return render_template_string(ADMIN_HTML,
        logged_in=True,
        csrf_token=csrf_token,
        stats=_admin_stats(),
        scans=_admin_scans(),
        blocks=_admin_blocks(),
        ip_summary=_admin_ip_summary()
    )

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
