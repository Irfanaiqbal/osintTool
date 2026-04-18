#!/usr/bin/env python3
import subprocess, threading, queue, time, re, socket, ssl, datetime
from flask import Flask, request, Response, render_template_string, jsonify
import requests
import whois
from collections import deque
import uuid
import json

app = Flask(__name__)
jobs = {}

# ---------------- RATE LIMITING SYSTEM ----------------
MAX_CONCURRENT_REQUESTS = 500
MAX_REQUESTS_PER_IP = 10        # per minute
IP_REQUEST_WINDOW = 60          # seconds
active_requests = 0
request_queue = deque()
request_lock = threading.Lock()
ip_request_log = {}             # ip -> list of timestamps
ip_lock = threading.Lock()

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

# ---------------- INPUT VALIDATION ----------------
def validate_target(mode, target):
    target = target.strip()
    if not target or len(target) > 256:
        return False, "Invalid target length"
    if mode == 'email':
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
            return False, "Invalid email format"
    elif mode == 'domain':
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', target):
            return False, "Invalid domain format"
    elif mode == 'phone':
        if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', target):
            return False, "Invalid phone format"
    elif mode == 'username':
        if not re.match(r'^[a-zA-Z0-9._\-]{1,50}$', target):
            return False, "Invalid username (alphanumeric, dots, dashes only)"
    return True, target

# ---------------- USERNAME PLATFORMS ----------------
USERNAME_PLATFORMS = {
    "GitHub":        "https://github.com/{u}",
    "GitLab":        "https://gitlab.com/{u}",
    "Bitbucket":     "https://bitbucket.org/{u}",
    "SourceForge":   "https://sourceforge.net/u/{u}",
    "Gitea":         "https://gitea.com/{u}",
    "CodePen":       "https://codepen.io/{u}",
    "Replit":        "https://replit.com/@{u}",
    "Kaggle":        "https://www.kaggle.com/{u}",
    "HackerRank":    "https://www.hackerrank.com/{u}",
    "LeetCode":      "https://leetcode.com/{u}",
    "Twitter / X":   "https://twitter.com/{u}",
    "Instagram":     "https://www.instagram.com/{u}/",
    "Facebook":      "https://www.facebook.com/{u}",
    "Reddit":        "https://www.reddit.com/user/{u}/",
    "TikTok":        "https://www.tiktok.com/@{u}",
    "Threads":       "https://www.threads.net/@{u}",
    "Pinterest":     "https://www.pinterest.com/{u}/",
    "Tumblr":        "https://{u}.tumblr.com",
    "Snapchat":      "https://www.snapchat.com/add/{u}",
    "Telegram":      "https://t.me/{u}",
    "Discord":       "https://discord.com/users/{u}",
    "Matrix":        "https://matrix.to/#/@{u}:matrix.org",
    "YouTube":       "https://www.youtube.com/@{u}",
    "Twitch":        "https://www.twitch.tv/{u}",
    "Vimeo":         "https://vimeo.com/{u}",
    "SoundCloud":    "https://soundcloud.com/{u}",
    "Mixcloud":      "https://www.mixcloud.com/{u}",
    "Bandcamp":      "https://bandcamp.com/{u}",
    "DeviantArt":    "https://www.deviantart.com/{u}",
    "Behance":       "https://www.behance.net/{u}",
    "Dribbble":      "https://dribbble.com/{u}",
    "Medium":        "https://medium.com/@{u}",
    "Substack":      "https://{u}.substack.com",
    "Stack Overflow":"https://stackoverflow.com/users/{u}",
    "Quora":         "https://www.quora.com/profile/{u}",
    "Steam":         "https://steamcommunity.com/id/{u}",
    "Epic Games":    "https://www.epicgames.com/id/{u}",
    "Roblox":        "https://www.roblox.com/user.aspx?username={u}",
    "Fiverr":        "https://www.fiverr.com/{u}",
    "Upwork":        "https://www.upwork.com/freelancers/{u}",
    "LinkedIn":      "https://www.linkedin.com/in/{u}",
    "Pastebin":      "https://pastebin.com/u/{u}",
    "Keybase":       "https://keybase.io/{u}",
    "About.me":      "https://about.me/{u}",
    "ProductHunt":   "https://www.producthunt.com/@{u}",
}

# ------------------------------------------------------------------ HTML
HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>SHADOWTRACE · OSINT</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg:        #050508;
      --bg2:       #0c0c12;
      --bg3:       #13131c;
      --bg4:       #1a1a26;
      --border:    #252535;
      --border2:   #303048;
      --fg:        #e8e8f0;
      --fg2:       #9090a8;
      --fg3:       #505068;
      --cyan:      #00ffe0;
      --pink:      #ff2d78;
      --purple:    #a855f7;
      --green:     #00ff99;
      --yellow:    #ffe566;
      --blue:      #4499ff;
      --orange:    #ff8c42;
      --gcyan:     0 0 12px rgba(0,255,224,.35);
      --gpink:     0 0 12px rgba(255,45,120,.35);
      --gpurple:   0 0 12px rgba(168,85,247,.35);
      --ggreen:    0 0 12px rgba(0,255,153,.3);
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', sans-serif;
      background: var(--bg);
      color: var(--fg);
      min-height: 100vh;
      overflow-x: hidden;
    }

    /* ── GRID BACKGROUND ── */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background-image:
        linear-gradient(rgba(0,255,224,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,255,224,.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }
    body::after {
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background:
        radial-gradient(ellipse 60% 40% at 15% 10%, rgba(0,255,224,.06) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 80%, rgba(168,85,247,.07) 0%, transparent 60%),
        radial-gradient(ellipse 40% 30% at 50% 50%, rgba(255,45,120,.04) 0%, transparent 60%);
      pointer-events: none;
    }

    .wrap { max-width: 1200px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }

    /* ── HEADER ── */
    header {
      position: sticky; top: 0; z-index: 200;
      border-bottom: 1px solid var(--border);
      background: rgba(5,5,8,.85);
      backdrop-filter: blur(16px);
    }
    .hrow {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 0;
    }
    .logo {
      display: flex; align-items: center; gap: 10px;
      font-family: 'Rajdhani', sans-serif;
      font-size: 22px; font-weight: 700; letter-spacing: .08em;
    }
    .logo-icon {
      width: 34px; height: 34px; border-radius: 8px;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      display: flex; align-items: center; justify-content: center;
      font-size: 16px; color: var(--bg); box-shadow: var(--gcyan);
    }
    .logo-name {
      background: linear-gradient(135deg, var(--cyan) 30%, var(--purple));
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .logo-ver {
      font-size: 11px; font-weight: 500; color: var(--fg3);
      background: var(--bg3); border: 1px solid var(--border);
      padding: 2px 7px; border-radius: 20px; letter-spacing: .04em;
    }
    .hnav { display: flex; gap: 8px; align-items: center; }
    .nbtn {
      display: flex; align-items: center; gap: 6px;
      padding: 7px 14px; border-radius: 6px; font-size: 13px; font-weight: 500;
      border: 1px solid var(--border); background: var(--bg3); color: var(--fg2);
      cursor: pointer; text-decoration: none; transition: all .2s; font-family: 'Inter', sans-serif;
    }
    .nbtn:hover { border-color: var(--cyan); color: var(--fg); box-shadow: var(--gcyan); }
    .nbtn.donate { border-color: rgba(255,45,120,.4); background: rgba(255,45,120,.06); color: var(--pink); }
    .nbtn.donate:hover { box-shadow: var(--gpink); }
    .hburger {
      display: none; width: 40px; height: 40px; border-radius: 8px;
      background: var(--bg3); border: 1px solid var(--border); color: var(--fg2);
      align-items: center; justify-content: center; cursor: pointer; font-size: 18px;
      transition: all .2s;
    }
    .hburger:hover { border-color: var(--cyan); color: var(--cyan); }

    /* ── MOBILE MENU ── */
    .mob-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,.85); backdrop-filter: blur(8px);
      z-index: 900; opacity: 0; visibility: hidden; transition: all .25s;
    }
    .mob-overlay.open { opacity: 1; visibility: visible; }
    .mob-panel {
      position: fixed; top: 0; right: -300px; width: 280px; height: 100vh;
      background: var(--bg2); border-left: 1px solid var(--border);
      z-index: 901; transition: right .3s cubic-bezier(.4,0,.2,1);
      padding: 24px; display: flex; flex-direction: column; gap: 12px;
    }
    .mob-panel.open { right: 0; }
    .mob-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .mob-head h3 {
      font-family: 'Rajdhani', sans-serif; font-size: 18px; font-weight: 700;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .mob-x {
      background: none; border: none; color: var(--fg3); font-size: 22px;
      cursor: pointer; transition: color .2s; width: 32px; height: 32px;
      display: flex; align-items: center; justify-content: center; border-radius: 6px;
    }
    .mob-x:hover { color: var(--pink); }
    .mob-item {
      display: flex; align-items: center; gap: 14px; padding: 14px 16px;
      background: var(--bg3); border: 1px solid var(--border); border-radius: 10px;
      color: var(--fg2); text-decoration: none; cursor: pointer; transition: all .2s;
      font-size: 15px; font-family: 'Inter', sans-serif;
    }
    .mob-item i { color: var(--cyan); width: 20px; text-align: center; }
    .mob-item:hover { border-color: var(--cyan); color: var(--fg); transform: translateX(-4px); }
    .mob-item.donate i { color: var(--pink); }
    .mob-item.donate:hover { border-color: var(--pink); box-shadow: var(--gpink); }

    /* ── HERO ── */
    .hero {
      text-align: center; padding: 60px 0 40px;
    }
    .hero-eyebrow {
      font-family: 'Share Tech Mono', monospace;
      font-size: 12px; letter-spacing: .2em; color: var(--cyan);
      text-shadow: var(--gcyan); margin-bottom: 16px;
      display: flex; align-items: center; justify-content: center; gap: 8px;
    }
    .hero-eyebrow::before, .hero-eyebrow::after {
      content: ''; flex: 1; max-width: 60px; height: 1px;
      background: linear-gradient(90deg, transparent, var(--cyan));
    }
    .hero-eyebrow::after { background: linear-gradient(90deg, var(--cyan), transparent); }
    .hero h1 {
      font-family: 'Rajdhani', sans-serif;
      font-size: clamp(36px, 6vw, 64px); font-weight: 700;
      letter-spacing: .06em; line-height: 1;
      background: linear-gradient(135deg, var(--fg) 0%, var(--cyan) 50%, var(--purple) 100%);
      -webkit-background-clip: text; background-clip: text; color: transparent;
      margin-bottom: 16px;
    }
    .hero p {
      color: var(--fg2); font-size: 16px; max-width: 480px; margin: 0 auto;
      line-height: 1.6;
    }
    .hero-stats {
      display: flex; justify-content: center; gap: 32px; margin-top: 32px;
    }
    .hstat {
      text-align: center;
    }
    .hstat-val {
      font-family: 'Share Tech Mono', monospace; font-size: 22px;
      color: var(--cyan); text-shadow: var(--gcyan);
    }
    .hstat-lbl { font-size: 12px; color: var(--fg3); margin-top: 2px; letter-spacing: .05em; }

    /* ── SCANNER CARD ── */
    .scanner {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 16px; padding: 28px; margin-bottom: 24px;
      position: relative; overflow: hidden;
    }
    .scanner-top-bar {
      position: absolute; top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, var(--cyan), var(--purple), var(--pink), var(--cyan));
      background-size: 200% 100%;
      animation: barflow 4s linear infinite;
    }
    @keyframes barflow { to { background-position: 200% 0; } }

    /* ── TABS ── */
    .tabs { display: flex; gap: 6px; margin-bottom: 20px; flex-wrap: wrap; }
    .tab {
      display: flex; align-items: center; gap: 7px;
      padding: 9px 18px; border-radius: 8px; font-size: 13px; font-weight: 600;
      background: var(--bg3); border: 1px solid var(--border); color: var(--fg2);
      cursor: pointer; transition: all .2s; letter-spacing: .03em;
      font-family: 'Rajdhani', sans-serif; font-size: 14px;
    }
    .tab:hover { border-color: var(--cyan); color: var(--fg); }
    .tab.active {
      background: linear-gradient(135deg, rgba(0,255,224,.15), rgba(168,85,247,.15));
      border-color: var(--cyan); color: var(--cyan); box-shadow: var(--gcyan);
    }

    /* ── INPUT ── */
    .irow { display: flex; gap: 10px; }
    .ibox {
      flex: 1; display: flex; align-items: center;
      background: var(--bg3); border: 1px solid var(--border); border-radius: 10px;
      padding: 0 16px; gap: 10px; transition: border-color .2s;
    }
    .ibox:focus-within { border-color: var(--cyan); box-shadow: var(--gcyan); }
    .ibox i { color: var(--fg3); font-size: 14px; }
    .ibox input {
      flex: 1; background: none; border: none; outline: none;
      color: var(--fg); font-size: 15px; padding: 14px 0;
      font-family: 'Share Tech Mono', monospace;
    }
    .ibox input::placeholder { color: var(--fg3); font-family: 'Inter', sans-serif; font-size: 14px; }
    .ibtn {
      display: flex; align-items: center; gap: 8px;
      padding: 14px 24px; border-radius: 10px; font-size: 14px; font-weight: 700;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      border: none; color: var(--bg); cursor: pointer; transition: all .2s;
      font-family: 'Rajdhani', sans-serif; letter-spacing: .05em; white-space: nowrap;
    }
    .ibtn:hover:not(:disabled) { transform: translateY(-2px); box-shadow: var(--gcyan), var(--gpurple); }
    .ibtn:disabled { opacity: .45; cursor: not-allowed; }

    /* ── TOOLBAR (below input) ── */
    .toolbar {
      display: flex; align-items: center; justify-content: space-between;
      margin-top: 14px; flex-wrap: wrap; gap: 10px;
    }
    .disc {
      display: flex; align-items: center; gap: 8px;
      font-size: 12px; color: var(--fg3);
    }
    .disc i { color: var(--yellow); }
    .tactions { display: flex; gap: 8px; }
    .tact-btn {
      display: flex; align-items: center; gap: 6px; padding: 6px 12px;
      border-radius: 6px; font-size: 12px; font-weight: 500;
      background: var(--bg3); border: 1px solid var(--border); color: var(--fg2);
      cursor: pointer; transition: all .2s; font-family: 'Inter', sans-serif;
    }
    .tact-btn:hover { border-color: var(--cyan); color: var(--fg); }
    .tact-btn:disabled { opacity: .4; cursor: not-allowed; }

    /* ── MESSAGES ── */
    .msg {
      margin-top: 12px; padding: 12px 18px; border-radius: 8px;
      font-size: 13px; font-weight: 500; display: none; border: 1px solid;
      font-family: 'Share Tech Mono', monospace;
    }
    .msg.show { display: block; }
    .msg-err { background: rgba(255,45,120,.08); border-color: var(--pink); color: var(--pink); }
    .msg-ok  { background: rgba(0,255,153,.08); border-color: var(--green); color: var(--green); }

    /* ── PROGRESS BAR ── */
    .prog-wrap {
      margin-top: 14px; display: none;
    }
    .prog-wrap.show { display: block; }
    .prog-row {
      display: flex; justify-content: space-between; align-items: center;
      font-size: 12px; color: var(--fg3); margin-bottom: 6px;
      font-family: 'Share Tech Mono', monospace;
    }
    .prog-track {
      height: 4px; background: var(--bg3); border-radius: 2px; overflow: hidden;
    }
    .prog-fill {
      height: 100%; width: 0%;
      background: linear-gradient(90deg, var(--cyan), var(--purple));
      border-radius: 2px; transition: width .3s;
      box-shadow: var(--gcyan);
    }
    .prog-label { color: var(--cyan); }

    /* ── QUEUE ── */
    .queue-card {
      background: var(--bg2); border: 1px solid var(--border2);
      border-radius: 16px; padding: 48px; text-align: center;
      margin: 16px 0; display: none;
    }
    .queue-card.show { display: block; }
    .queue-spinner {
      width: 48px; height: 48px; border-radius: 50%; margin: 0 auto 20px;
      border: 3px solid var(--border); border-top-color: var(--cyan);
      border-right-color: var(--purple); animation: spin .9s linear infinite;
      box-shadow: var(--gcyan);
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .queue-card h3 {
      font-family: 'Rajdhani', sans-serif; font-size: 20px; font-weight: 700;
      color: var(--yellow); margin-bottom: 8px; letter-spacing: .06em;
    }
    .queue-pos {
      font-family: 'Share Tech Mono', monospace; font-size: 40px;
      color: var(--cyan); text-shadow: var(--gcyan); margin: 12px 0;
    }

    /* ── LOADING ── */
    .loading {
      padding: 48px; text-align: center; display: none;
    }
    .loading.show { display: block; }
    .loading .queue-spinner { margin-bottom: 16px; }
    .loading p { color: var(--fg2); font-family: 'Share Tech Mono', monospace; font-size: 14px; }
    .loading p span { color: var(--cyan); text-shadow: var(--gcyan); }

    /* ── RESULTS HEADER ── */
    .res-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid var(--border);
      flex-wrap: wrap; gap: 10px;
    }
    .res-title {
      font-family: 'Rajdhani', sans-serif; font-size: 20px; font-weight: 700;
      letter-spacing: .06em;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .res-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .res-count {
      font-family: 'Share Tech Mono', monospace; font-size: 13px;
      padding: 5px 12px; border-radius: 20px; color: var(--fg2);
      background: var(--bg3); border: 1px solid var(--border);
    }

    /* ── FILTER ── */
    .filter-row {
      display: flex; gap: 8px; margin-bottom: 18px; flex-wrap: wrap;
    }
    .filter-input {
      flex: 1; min-width: 180px; background: var(--bg3); border: 1px solid var(--border);
      border-radius: 8px; padding: 8px 14px; font-size: 13px; color: var(--fg);
      outline: none; transition: border-color .2s; font-family: 'Inter', sans-serif;
    }
    .filter-input:focus { border-color: var(--cyan); }
    .filter-input::placeholder { color: var(--fg3); }

    /* ── RESULTS GRID ── */
    .res-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 16px;
    }
    .rcard {
      background: var(--bg2); border: 1px solid var(--border); border-radius: 12px;
      padding: 20px; transition: all .2s; position: relative; overflow: hidden;
      animation: cardin .3s ease both;
    }
    @keyframes cardin {
      from { opacity: 0; transform: translateY(10px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    .rcard::before {
      content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 3px;
      background: linear-gradient(180deg, var(--cyan), var(--purple));
      opacity: 0; transition: opacity .2s;
    }
    .rcard:hover { border-color: var(--border2); transform: translateY(-3px); box-shadow: 0 8px 24px rgba(0,0,0,.4); }
    .rcard:hover::before { opacity: 1; }
    .rcard.link { cursor: pointer; }
    .rcard-top {
      display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;
      margin-bottom: 10px;
    }
    .rcard-title {
      display: flex; align-items: center; gap: 8px;
      font-family: 'Rajdhani', sans-serif; font-size: 16px; font-weight: 600;
      letter-spacing: .03em; color: var(--fg);
    }
    .rcard-title i { color: var(--cyan); font-size: 14px; flex-shrink: 0; }
    .rcard-copy {
      background: none; border: 1px solid var(--border); border-radius: 6px;
      color: var(--fg3); font-size: 11px; padding: 3px 8px; cursor: pointer;
      transition: all .2s; opacity: 0; font-family: 'Inter', sans-serif;
      white-space: nowrap;
    }
    .rcard:hover .rcard-copy { opacity: 1; }
    .rcard-copy:hover { border-color: var(--cyan); color: var(--cyan); }
    .rcard-body { color: var(--fg2); font-size: 13px; line-height: 1.6; word-break: break-word; }
    .rcard-body a { color: var(--green); text-decoration: none; }
    .rcard-body a:hover { text-decoration: underline; }
    .rcard-tag {
      display: inline-block; margin-top: 12px; font-size: 10px; font-weight: 700;
      color: var(--bg); padding: 3px 10px; border-radius: 20px; letter-spacing: .06em;
      font-family: 'Share Tech Mono', monospace;
    }
    .tag-email    { background: linear-gradient(135deg, var(--blue), var(--cyan)); }
    .tag-username { background: linear-gradient(135deg, var(--purple), var(--pink)); }
    .tag-domain   { background: linear-gradient(135deg, var(--green), var(--blue)); }
    .tag-phone    { background: linear-gradient(135deg, var(--orange), var(--pink)); }

    /* ── HISTORY PANEL ── */
    .hist-panel {
      background: var(--bg2); border: 1px solid var(--border); border-radius: 12px;
      padding: 20px; margin-bottom: 20px; display: none;
    }
    .hist-panel.show { display: block; }
    .hist-title {
      font-family: 'Rajdhani', sans-serif; font-size: 16px; font-weight: 700;
      color: var(--fg2); margin-bottom: 14px; letter-spacing: .06em;
    }
    .hist-list { display: flex; flex-wrap: wrap; gap: 8px; }
    .hist-item {
      display: flex; align-items: center; gap: 6px; padding: 6px 12px;
      background: var(--bg3); border: 1px solid var(--border); border-radius: 6px;
      font-size: 12px; color: var(--fg2); cursor: pointer; transition: all .2s;
      font-family: 'Share Tech Mono', monospace;
    }
    .hist-item:hover { border-color: var(--cyan); color: var(--cyan); }
    .hist-item i { font-size: 10px; color: var(--fg3); }
    .hist-clear {
      font-size: 12px; color: var(--fg3); cursor: pointer; padding: 4px 8px;
      border-radius: 4px; transition: color .2s; background: none; border: none;
      font-family: 'Inter', sans-serif;
    }
    .hist-clear:hover { color: var(--pink); }

    /* ── EMPTY STATE ── */
    .empty {
      text-align: center; padding: 80px 20px; display: none;
    }
    .empty.show { display: block; }
    .empty-icon {
      font-size: 56px; margin-bottom: 20px;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .empty h3 {
      font-family: 'Rajdhani', sans-serif; font-size: 22px; font-weight: 700;
      color: var(--fg2); margin-bottom: 8px;
    }
    .empty p { color: var(--fg3); font-size: 14px; }
    .kbd {
      display: inline-flex; align-items: center; justify-content: center;
      background: var(--bg3); border: 1px solid var(--border2);
      border-radius: 4px; padding: 1px 6px; font-family: 'Share Tech Mono', monospace;
      font-size: 12px; color: var(--fg2);
    }

    /* ── FOOTER ── */
    footer {
      border-top: 1px solid var(--border); padding: 28px 0; margin-top: 60px;
      position: relative; z-index: 1;
    }
    .frow {
      display: flex; justify-content: space-between; align-items: center;
      flex-wrap: wrap; gap: 16px;
    }
    .fcopy { font-size: 13px; color: var(--fg3); }
    .flinks { display: flex; gap: 20px; }
    .flinks a {
      font-size: 13px; color: var(--fg3); cursor: pointer; text-decoration: none;
      transition: color .2s;
    }
    .flinks a:hover { color: var(--cyan); }

    /* ── MODALS ── */
    .modal-bg {
      position: fixed; inset: 0; background: rgba(0,0,0,.92);
      backdrop-filter: blur(12px); display: none;
      justify-content: center; align-items: center; z-index: 500; padding: 20px;
    }
    .modal-bg.show { display: flex; }
    .modal {
      background: var(--bg2); border: 1px solid var(--border);
      border-radius: 16px; width: 100%; max-width: 560px;
      max-height: 85vh; overflow: hidden; position: relative;
    }
    .modal::before {
      content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
      background: linear-gradient(90deg, var(--cyan), var(--purple), var(--pink));
    }
    .modal-hd {
      padding: 20px 24px; border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }
    .modal-hd h2 {
      font-family: 'Rajdhani', sans-serif; font-size: 18px; font-weight: 700;
      letter-spacing: .06em;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      -webkit-background-clip: text; background-clip: text; color: transparent;
    }
    .modal-x {
      background: none; border: none; color: var(--fg3); font-size: 24px;
      cursor: pointer; transition: all .2s; width: 32px; height: 32px;
      display: flex; align-items: center; justify-content: center;
    }
    .modal-x:hover { color: var(--pink); }
    .modal-body {
      padding: 24px; overflow-y: auto; max-height: calc(85vh - 70px);
    }
    .msec { margin-bottom: 24px; }
    .msec h3 { font-size: 14px; font-weight: 600; color: var(--cyan); margin-bottom: 8px; letter-spacing: .04em; }
    .msec p, .msec li { font-size: 14px; color: var(--fg2); line-height: 1.7; }
    .msec ul { padding-left: 18px; }
    .msec li { margin-bottom: 6px; }

    /* Crypto cards */
    .crypto-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px; }
    .ccard {
      background: var(--bg3); border: 1px solid var(--border); border-radius: 12px;
      padding: 20px; text-align: center; transition: all .2s;
    }
    .ccard:hover { border-color: var(--cyan); box-shadow: var(--gcyan); }
    .ccard-icon { font-size: 32px; margin-bottom: 12px; }
    .ccard-icon.btc { color: var(--yellow); }
    .ccard-icon.eth { color: var(--purple); }
    .ccard h3 { font-size: 15px; font-weight: 600; margin-bottom: 12px; }
    .ccard h3.btc { color: var(--yellow); }
    .ccard h3.eth { color: var(--purple); }
    .wallet {
      background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
      padding: 10px; font-family: 'Share Tech Mono', monospace; font-size: 11px;
      word-break: break-all; color: var(--fg2); margin: 10px 0; text-align: left;
    }
    .cbtn {
      display: inline-flex; align-items: center; gap: 6px;
      background: linear-gradient(135deg, var(--cyan), var(--purple));
      border: none; padding: 8px 16px; border-radius: 20px;
      color: var(--bg); font-size: 12px; font-weight: 700; cursor: pointer;
      transition: all .2s; font-family: 'Rajdhani', sans-serif; letter-spacing: .04em;
    }
    .cbtn:hover { transform: scale(1.05); box-shadow: var(--gcyan); }
    .copied { font-size: 11px; color: var(--green); margin-top: 6px; display: none; }
    .copied.show { display: block; }

    /* ── TOAST ── */
    .toast {
      position: fixed; bottom: 24px; right: 24px; z-index: 999;
      background: var(--bg3); border: 1px solid var(--border);
      border-radius: 10px; padding: 12px 18px; font-size: 13px; color: var(--fg);
      box-shadow: 0 8px 24px rgba(0,0,0,.5); display: flex; align-items: center; gap: 10px;
      transform: translateY(80px); opacity: 0; transition: all .3s;
      font-family: 'Share Tech Mono', monospace; max-width: 280px;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast i { color: var(--cyan); }

    /* ── SHORTCUTS HINT ── */
    .shortcuts {
      font-size: 12px; color: var(--fg3); display: flex; gap: 14px; flex-wrap: wrap;
    }
    .shortcuts span { display: flex; align-items: center; gap: 5px; }

    /* ── RESPONSIVE ── */
    @media (max-width: 768px) {
      .hnav { display: none; }
      .hburger { display: flex; }
      .irow { flex-direction: column; }
      .ibtn { justify-content: center; }
      .res-grid { grid-template-columns: 1fr; }
      .crypto-grid { grid-template-columns: 1fr; }
      .frow { flex-direction: column; text-align: center; }
      .hero-stats { gap: 20px; }
      .toolbar { flex-direction: column; align-items: flex-start; }
    }
    @media (max-width: 480px) {
      .tabs { justify-content: center; }
      .tab { flex: 1; justify-content: center; }
      .scanner { padding: 18px; }
    }

    /* ── SCROLLBAR ── */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg2); }
    ::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--cyan); }
    ::selection { background: rgba(168,85,247,.4); color: var(--fg); }
  </style>
</head>
<body>

<!-- HEADER -->
<header>
  <div class="wrap">
    <div class="hrow">
      <div class="logo">
        <div class="logo-icon"><i class="fas fa-crosshairs"></i></div>
        <span class="logo-name">SHADOWTRACE</span>
        <span class="logo-ver">v3.0</span>
      </div>
      <nav class="hnav">
        <a href="mailto:shadowtrace5@proton.me" class="nbtn"><i class="fas fa-envelope"></i> Contact</a>
        <button class="nbtn donate" onclick="openM('donate')"><i class="fas fa-heart"></i> Donate</button>
      </nav>
      <button class="hburger" onclick="toggleMob()"><i class="fas fa-bars"></i></button>
    </div>
  </div>
</header>

<!-- MOBILE MENU -->
<div class="mob-overlay" id="mobOverlay" onclick="closeMob()"></div>
<div class="mob-panel" id="mobPanel">
  <div class="mob-head">
    <h3>MENU</h3>
    <button class="mob-x" onclick="closeMob()"><i class="fas fa-times"></i></button>
  </div>
  <a href="mailto:support@shadowtrace.com" class="mob-item"><i class="fas fa-envelope"></i> Contact</a>
  <button class="mob-item donate" onclick="openM('donate');closeMob()"><i class="fas fa-heart"></i> Donate</button>
  <button class="mob-item" onclick="openM('privacy');closeMob()"><i class="fas fa-shield-alt"></i> Privacy</button>
  <button class="mob-item" onclick="openM('guide');closeMob()"><i class="fas fa-book"></i> Guide</button>
</div>

<!-- MAIN -->
<main>
  <div class="wrap">

    <!-- HERO -->
    <div class="hero">
      <div class="hero-eyebrow"><i class="fas fa-satellite-dish"></i> PASSIVE RECONNAISSANCE</div>
      <h1>OSINT PLATFORM</h1>
      <p>Trace digital footprints across email, username, domain, and phone intelligence sources.</p>
      <div class="hero-stats">
        <div class="hstat"><div class="hstat-val">40+</div><div class="hstat-lbl">PLATFORMS</div></div>
        <div class="hstat"><div class="hstat-val">4</div><div class="hstat-lbl">SCAN MODES</div></div>
        <div class="hstat"><div class="hstat-val">0</div><div class="hstat-lbl">LOGS KEPT</div></div>
      </div>
    </div>

    <!-- HISTORY -->
    <div class="hist-panel" id="histPanel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <div class="hist-title"><i class="fas fa-history" style="color:var(--cyan);margin-right:8px"></i>RECENT SCANS</div>
        <button class="hist-clear" onclick="clearHistory()">Clear all</button>
      </div>
      <div class="hist-list" id="histList"></div>
    </div>

    <!-- SCANNER -->
    <div class="scanner">
      <div class="scanner-top-bar"></div>

      <div class="tabs">
        <div class="tab active" data-mode="email"><i class="fas fa-envelope"></i> Email</div>
        <div class="tab" data-mode="username"><i class="fas fa-user"></i> Username</div>
        <div class="tab" data-mode="domain"><i class="fas fa-globe"></i> Domain</div>
        <div class="tab" data-mode="phone"><i class="fas fa-phone"></i> Phone</div>
      </div>

      <div class="irow">
        <div class="ibox">
          <i class="fas fa-search" id="iicon"></i>
          <input id="target" placeholder="e.g., user@example.com" autocomplete="off" spellcheck="false">
        </div>
        <button id="runBtn" class="ibtn"><i class="fas fa-bolt"></i> SCAN</button>
      </div>

      <div class="toolbar">
        <div class="disc"><i class="fas fa-shield-alt"></i> Passive recon only — use responsibly</div>
        <div class="tactions">
          <button class="tact-btn" id="exportBtn" onclick="exportResults()" disabled>
            <i class="fas fa-download"></i> Export
          </button>
          <button class="tact-btn" onclick="openM('guide')">
            <i class="fas fa-question-circle"></i> Guide
          </button>
        </div>
      </div>

      <!-- progress -->
      <div class="prog-wrap" id="progWrap">
        <div class="prog-row">
          <span id="progLabel">Initializing...</span>
          <span class="prog-label" id="progPct">0%</span>
        </div>
        <div class="prog-track"><div class="prog-fill" id="progFill"></div></div>
      </div>

      <div class="msg msg-err" id="errMsg"></div>
      <div class="msg msg-ok"  id="okMsg"></div>
    </div>

    <!-- QUEUE -->
    <div class="queue-card" id="queueCard">
      <div class="queue-spinner"></div>
      <h3>QUEUED</h3>
      <p style="color:var(--fg3);font-size:13px">Position in queue</p>
      <div class="queue-pos" id="queuePos">1</div>
      <p style="color:var(--fg3);font-size:13px">Waiting for a free slot...</p>
    </div>

    <!-- LOADING -->
    <div class="loading" id="loading">
      <div class="queue-spinner"></div>
      <p><span id="loadLabel">SCANNING</span> in progress...</p>
    </div>

    <!-- RESULTS -->
    <div id="resultsWrap" style="display:none">
      <div class="res-header">
        <div class="res-title">RESULTS</div>
        <div class="res-right">
          <div class="res-count" id="resCount">0 items</div>
        </div>
      </div>
      <div class="filter-row">
        <input class="filter-input" id="filterInput" placeholder="Filter results..." oninput="filterResults()">
      </div>
      <div class="res-grid" id="resGrid"></div>
    </div>

    <!-- EMPTY -->
    <div class="empty show" id="emptyState">
      <div class="empty-icon"><i class="fas fa-radar"></i></div>
      <h3>READY TO SCAN</h3>
      <p>Enter a target above and press <span class="kbd">Enter</span> or click SCAN</p>
      <div class="shortcuts" style="justify-content:center;margin-top:16px">
        <span><span class="kbd">Tab</span> Switch mode</span>
        <span><span class="kbd">Ctrl+K</span> Focus input</span>
        <span><span class="kbd">Esc</span> Clear</span>
      </div>
    </div>

  </div><!-- /wrap -->
</main>

<!-- FOOTER -->
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

<!-- TOAST -->
<div class="toast" id="toast"><i class="fas fa-check-circle"></i><span id="toastMsg">Copied!</span></div>

<!-- MODALS -->
<!-- Privacy -->
<div class="modal-bg" id="modal-privacy">
  <div class="modal">
    <div class="modal-hd"><h2>PRIVACY POLICY</h2><button class="modal-x" onclick="closeM('privacy')">&times;</button></div>
    <div class="modal-body">
      <div class="msec"><h3>Data Collection</h3><p>No personal data is stored. All scans are processed anonymously and discarded immediately after completion. No tracking, no cookies, no logs retained.</p></div>
      <div class="msec"><h3>Third Parties</h3><p>We query public APIs (WHOIS, DNS, social platforms) server-side. Your queries are never shared or retained.</p></div>
      <div class="msec"><h3>Responsible Use</h3><p>This tool is for legitimate security research and personal digital footprint awareness only. Always obtain proper authorisation before scanning any target you do not own.</p></div>
    </div>
  </div>
</div>

<!-- Guide -->
<div class="modal-bg" id="modal-guide">
  <div class="modal">
    <div class="modal-hd"><h2>USAGE GUIDE</h2><button class="modal-x" onclick="closeM('guide')">&times;</button></div>
    <div class="modal-body">
      <div class="msec"><h3>Email</h3><p>Uses Holehe to check whether an email address is registered on popular platforms. Results show confirmed registrations only.</p></div>
      <div class="msec"><h3>Username</h3><p>Probes 40+ platforms for username existence using HTTP status code checks. Click any result card to open the profile.</p></div>
      <div class="msec"><h3>Domain</h3><p>Performs WHOIS lookup, DNS record enumeration (A, AAAA, MX, NS, TXT), IP resolution, web server fingerprinting, and TLS certificate inspection.</p></div>
      <div class="msec"><h3>Phone</h3><p>Validates and formats the number, identifies carrier and geographic region, timezone, and provides quick-link pivots to WhatsApp, Telegram, and Google.</p></div>
      <div class="msec"><h3>Export</h3><p>After a scan completes, use the Export button to download all results as a JSON file for offline analysis.</p></div>
      <div class="msec"><h3>Keyboard Shortcuts</h3>
        <ul>
          <li><strong>Enter</strong> — Start scan</li>
          <li><strong>Tab</strong> — Cycle through scan modes</li>
          <li><strong>Ctrl + K</strong> — Focus the input</li>
          <li><strong>Escape</strong> — Clear input / close modals</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<!-- Donate -->
<div class="modal-bg" id="modal-donate">
  <div class="modal">
    <div class="modal-hd"><h2>SUPPORT THE PROJECT</h2><button class="modal-x" onclick="closeM('donate')">&times;</button></div>
    <div class="modal-body">
      <p style="color:var(--fg2);font-size:14px;margin-bottom:4px">Help keep this service running and free. Your support is genuinely appreciated.</p>
      <div class="crypto-grid">
        <div class="ccard">
          <div class="ccard-icon btc"><i class="fab fa-bitcoin"></i></div>
          <h3 class="btc">Bitcoin</h3>
          <div class="wallet" id="btcAddr">bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh</div>
          <button class="cbtn" onclick="copyWallet('btcAddr','btcOk')"><i class="fas fa-copy"></i> COPY</button>
          <div class="copied" id="btcOk">✓ Copied!</div>
        </div>
        <div class="ccard">
          <div class="ccard-icon eth"><i class="fab fa-ethereum"></i></div>
          <h3 class="eth">Ethereum</h3>
          <div class="wallet" id="ethAddr">0x742d35Cc6634C0532925a3b844Bc9eC8c2F5e3B6</div>
          <button class="cbtn" onclick="copyWallet('ethAddr','ethOk')"><i class="fas fa-copy"></i> COPY</button>
          <div class="copied" id="ethOk">✓ Copied!</div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- ===================== SCRIPT ===================== -->
<script>
// ── STATE ──
let mode = 'email';
let currentJobId = null;
let resultCount = 0;
let allResults = [];    // {title, body, tag, url}
let scanHistory = JSON.parse(localStorage.getItem('st_history') || '[]');
let progTimer = null;
let progVal = 0;

// ── DOM ──
const $ = id => document.getElementById(id);
const runBtn     = $('runBtn');
const targetIn   = $('target');
const errMsg     = $('errMsg');
const okMsg      = $('okMsg');
const loading    = $('loading');
const queueCard  = $('queueCard');
const resWrap    = $('resultsWrap');
const resGrid    = $('resGrid');
const resCount   = $('resCount');
const emptyState = $('emptyState');
const progWrap   = $('progWrap');
const progFill   = $('progFill');
const progLabel  = $('progLabel');
const progPct    = $('progPct');
const exportBtn  = $('exportBtn');
const filterIn   = $('filterInput');

// ── TABS ──
const modeIcons = { email:'fa-envelope', username:'fa-user', domain:'fa-globe', phone:'fa-phone' };
const modePH    = { email:'e.g., user@example.com', username:'e.g., johndoe', domain:'e.g., example.com', phone:'e.g., +1234567890' };
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  mode = t.dataset.mode;
  targetIn.placeholder = modePH[mode];
  $('iicon').className = `fas ${modeIcons[mode]}`;
}));

// ── TAB KEY cycles modes ──
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
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); targetIn.focus(); }
  if (e.key === 'Escape') { document.querySelectorAll('.modal-bg.show').forEach(m => m.classList.remove('show')); closeMob(); }
});

// ── SCAN ──
runBtn.addEventListener('click', async () => {
  const target = targetIn.value.trim();
  if (!target) { showErr('Please enter a target'); return; }

  resetUI();
  loading.classList.add('show');
  runBtn.disabled = true;
  startFakeProgress();

  try {
    const res = await fetch('/start', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
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

// ── QUEUE POLL ──
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

// ── STREAM ──
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
    try {
      const obj = JSON.parse(e.data);
      addCard(obj);
    } catch {
      // legacy plain html fallback
    }
  };

  es.onerror = () => {
    es.close();
    loading.classList.remove('show');
    stopFakeProgress();
    showErr('Connection lost during scan');
    runBtn.disabled = false;
  };
}

// ── ADD CARD ──
function addCard(obj) {
  resultCount++;
  updateCount();
  allResults.push(obj);

  const card = document.createElement('div');
  card.className = 'rcard' + (obj.url ? ' link' : '');
  card.dataset.search = (obj.title + ' ' + obj.body).toLowerCase();

  if (obj.url) card.addEventListener('click', () => window.open(obj.url, '_blank'));

  const tagClass = {email:'tag-email', username:'tag-username', domain:'tag-domain', phone:'tag-phone'}[obj.tag] || 'tag-domain';

  card.innerHTML = `
    <div class="rcard-top">
      <div class="rcard-title"><i class="fas ${obj.icon || 'fa-info-circle'}"></i> ${obj.title}</div>
      <button class="rcard-copy" onclick="event.stopPropagation();copyText('${escJs(obj.body_plain || obj.body)}')"><i class="fas fa-copy"></i> copy</button>
    </div>
    <div class="rcard-body">${obj.body}</div>
    ${obj.tag ? `<div class="rcard-tag ${tagClass}">${obj.tag.toUpperCase()}</div>` : ''}
  `;

  resGrid.appendChild(card);
  if (!resWrap.style.display || resWrap.style.display === 'none') resWrap.style.display = 'block';
}

function escJs(s) { return (s||'').replace(/'/g,"\\'").replace(/"/g,"&quot;"); }

// ── FILTER ──
function filterResults() {
  const q = filterIn.value.toLowerCase();
  document.querySelectorAll('.rcard').forEach(c => {
    c.style.display = c.dataset.search.includes(q) ? '' : 'none';
  });
}

// ── EXPORT ──
function exportResults() {
  const blob = new Blob([JSON.stringify(allResults, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `shadowtrace_${Date.now()}.json`;
  a.click();
  showToast('Results exported as JSON');
}

// ── HISTORY ──
function saveHistory(m, t) {
  scanHistory = scanHistory.filter(x => !(x.m === m && x.t === t));
  scanHistory.unshift({m, t});
  if (scanHistory.length > 8) scanHistory = scanHistory.slice(0, 8);
  localStorage.setItem('st_history', JSON.stringify(scanHistory));
  renderHistory();
}
function renderHistory() {
  const panel = $('histPanel');
  const list  = $('histList');
  if (!scanHistory.length) { panel.classList.remove('show'); return; }
  panel.classList.add('show');
  list.innerHTML = scanHistory.map(x =>
    `<div class="hist-item" onclick="loadHistory('${x.m}','${escJs(x.t)}')">
      <i class="fas ${modeIcons[x.m]}"></i>${escHtml(x.t)}
    </div>`
  ).join('');
}
function loadHistory(m, t) {
  document.querySelector(`[data-mode="${m}"]`).click();
  targetIn.value = t;
  targetIn.focus();
}
function clearHistory() {
  scanHistory = [];
  localStorage.removeItem('st_history');
  $('histPanel').classList.remove('show');
}
function escHtml(s) { const d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

// ── PROGRESS (fake animation while streaming) ──
function startFakeProgress() {
  progVal = 0; progWrap.classList.add('show');
  progFill.style.width = '0%';
  progLabel.textContent = 'Initializing scan...';
  progPct.textContent = '0%';
  progTimer = setInterval(() => {
    if (progVal < 85) {
      progVal += Math.random() * 3;
      progFill.style.width = progVal + '%';
      progPct.textContent = Math.round(progVal) + '%';
    }
  }, 300);
}
function stopFakeProgress() {
  clearInterval(progTimer);
  progVal = 100; progFill.style.width = '100%'; progPct.textContent = '100%';
  progLabel.textContent = 'Complete';
}

// ── HELPERS ──
function resetUI() {
  clearMessages();
  emptyState.classList.remove('show');
  emptyState.querySelector('h3').textContent = 'READY TO SCAN';
  resWrap.style.display = 'none';
  queueCard.classList.remove('show');
  loading.classList.remove('show');
  resGrid.innerHTML = '';
  resultCount = 0; allResults = [];
  exportBtn.disabled = true;
  filterIn.value = '';
  updateCount();
}
function updateCount() { resCount.textContent = `${resultCount} item${resultCount !== 1 ? 's' : ''}`; }
function showErr(t) { errMsg.textContent = '⚠ ' + t; errMsg.classList.add('show'); }
function clearMessages() { errMsg.classList.remove('show'); okMsg.classList.remove('show'); }

function showToast(msg) {
  $('toastMsg').textContent = msg;
  const t = $('toast'); t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2500);
}
function copyText(text) {
  navigator.clipboard?.writeText(text).then(() => showToast('Copied to clipboard'));
}
function copyWallet(id, okId) {
  navigator.clipboard?.writeText($(id).innerText).then(() => {
    const el = $(okId); el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 2000);
  });
}

// ── MODALS ──
function openM(id) { $('modal-'+id).classList.add('show'); document.body.style.overflow='hidden'; }
function closeM(id) { $('modal-'+id).classList.remove('show'); document.body.style.overflow=''; }
document.querySelectorAll('.modal-bg').forEach(m => m.addEventListener('click', e => { if(e.target===m) { m.classList.remove('show'); document.body.style.overflow=''; } }));

// ── MOBILE MENU ──
function toggleMob() { $('mobPanel').classList.toggle('open'); $('mobOverlay').classList.toggle('open'); }
function closeMob()  { $('mobPanel').classList.remove('open'); $('mobOverlay').classList.remove('open'); }

// ── INIT ──
renderHistory();
</script>
</body>
</html>"""

# ------------------------------------------------------------------ HELPERS
def make_card(title, body, body_plain=None, icon='fa-info-circle', tag='', url=''):
    return json.dumps({
        'title': title,
        'body': body,
        'body_plain': body_plain or body,
        'icon': icon,
        'tag': tag,
        'url': url
    })

# ------------------------------------------------------------------ ROUTES
@app.after_request
def sec_headers(r):
    r.headers['X-Content-Type-Options'] = 'nosniff'
    r.headers['X-Frame-Options'] = 'DENY'
    r.headers['X-XSS-Protection'] = '1; mode=block'
    return r

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/start', methods=['POST'])
def start():
    global active_requests

    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    if not check_ip_rate_limit(ip):
        return jsonify({'status': 'error', 'message': 'Rate limit exceeded — try again in a minute'})

    data = request.get_json(force=True)
    mode   = data.get('mode', '')
    target = data.get('target', '').strip()

    ok, result = validate_target(mode, target)
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

    def runner():
        global active_requests
        try:
            if mode == 'email':
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
                    p.wait()
                except FileNotFoundError:
                    q.put(make_card('holehe not installed',
                                   'Install with: pip install holehe',
                                   icon='fa-exclamation-triangle', tag='email'))

            elif mode == 'username':
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
                    except Exception:
                        pass

            elif mode == 'domain':
                # WHOIS
                try:
                    info = whois.whois(target)
                    if info.registrar:
                        q.put(make_card('Registrar', info.registrar, icon='fa-building', tag='domain'))
                    for field, label, icon in [
                        ('creation_date',   'Created',  'fa-calendar-plus'),
                        ('expiration_date', 'Expires',  'fa-calendar-times'),
                        ('updated_date',    'Updated',  'fa-calendar-check'),
                    ]:
                        val = getattr(info, field, None)
                        if val:
                            if isinstance(val, list): val = val[0]
                            ds = val.strftime('%Y-%m-%d') if hasattr(val, 'strftime') else str(val)[:10]
                            q.put(make_card(label, ds, icon=icon, tag='domain'))
                    if info.name_servers:
                        ns = info.name_servers
                        txt = ', '.join(str(x).lower() for x in (ns[:3] if isinstance(ns,list) else [ns]))
                        q.put(make_card('Name Servers', txt, icon='fa-server', tag='domain'))
                    if info.status:
                        st = info.status
                        if isinstance(st, list): st = st[0]
                        q.put(make_card('WHOIS Status', str(st)[:80], icon='fa-tag', tag='domain'))
                    if info.emails:
                        em = info.emails
                        if isinstance(em, list): em = ', '.join(em[:3])
                        q.put(make_card('Registrant Email', str(em), icon='fa-envelope', tag='domain'))
                    if info.country:
                        q.put(make_card('Country', str(info.country), icon='fa-flag', tag='domain'))
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
                        except Exception:
                            pass
                except ImportError:
                    pass

                # IP
                try:
                    ip_addr = socket.gethostbyname(target)
                    q.put(make_card('IP Address', ip_addr, icon='fa-map-marker-alt', tag='domain'))
                    # Reverse DNS
                    try:
                        rev = socket.gethostbyaddr(ip_addr)[0]
                        q.put(make_card('Reverse DNS', rev, icon='fa-exchange-alt', tag='domain'))
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
                        cf   = 'Cloudflare' if 'cloudflare' in r.headers.get('CF-RAY','').lower() or \
                                               'cloudflare' in r.headers.get('Server','').lower() else ''
                        body = f'{scheme}{target} → HTTP {r.status_code}<br>Server: {srv}'
                        if powered: body += f'<br>Powered-By: {powered}'
                        if cf:      body += f'<br><span style="color:var(--orange)">⚡ {cf}</span>'
                        q.put(make_card('Web Server', body, body_plain=f'{scheme}{target} HTTP {r.status_code} {srv}',
                                       icon='fa-globe', tag='domain'))
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
                    col = 'var(--green)' if days and days>30 else ('var(--yellow)' if days and days>7 else 'var(--pink)')
                    parts = []
                    if cn:     parts.append(f'CN: {cn}')
                    if issuer: parts.append(f'Issuer: {issuer}')
                    if exp:    parts.append(f'Expires: {exp.strftime("%Y-%m-%d")}')
                    if days is not None: parts.append(f'<span style="color:{col}">{days} days remaining</span>')
                    # SANs
                    sans = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
                    if sans: parts.append(f'SANs: {", ".join(sans[:4])}{"..." if len(sans)>4 else ""}')
                    if parts:
                        q.put(make_card('TLS Certificate', '<br>'.join(parts),
                                       body_plain=' | '.join(p for p in parts if '<' not in p),
                                       icon='fa-lock', tag='domain'))
                except Exception as e:
                    q.put(make_card('TLS', f'No TLS or error: {str(e)[:60]}', icon='fa-lock-open', tag='domain'))

            elif mode == 'phone':
                try:
                    import phonenumbers
                    from phonenumbers import geocoder, carrier, timezone as tz_mod
                    pn = phonenumbers.parse(target, None)
                    valid = phonenumbers.is_valid_number(pn)
                    q.put(make_card('Validity', 'Valid ✓' if valid else 'Invalid ✗',
                                   icon='fa-check-circle' if valid else 'fa-times-circle', tag='phone'))
                    intl = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                    e164 = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164)
                    nat  = phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL)
                    q.put(make_card('International', intl, icon='fa-phone-alt', tag='phone'))
                    q.put(make_card('E.164 Format',  e164, icon='fa-hashtag',   tag='phone'))
                    q.put(make_card('National',      nat,  icon='fa-phone',     tag='phone'))
                    region = geocoder.description_for_number(pn, 'en')
                    if region: q.put(make_card('Region', region, icon='fa-map-marker-alt', tag='phone'))
                    carr = carrier.name_for_number(pn, 'en')
                    if carr: q.put(make_card('Carrier', carr, icon='fa-satellite-dish', tag='phone'))
                    zones = tz_mod.time_zones_for_number(pn)
                    if zones: q.put(make_card('Timezone', ', '.join(zones), icon='fa-clock', tag='phone'))
                    ntype = phonenumbers.number_type(pn)
                    type_names = {0:'Fixed Line',1:'Mobile',2:'Fixed/Mobile',3:'Toll Free',4:'Premium',6:'VOIP',7:'Personal'}
                    q.put(make_card('Number Type', type_names.get(ntype, 'Unknown'), icon='fa-tag', tag='phone'))
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

        except Exception as e:
            q.put(make_card('Unexpected Error', str(e)[:120], icon='fa-exclamation-circle'))
        finally:
            q.put('__DONE__')
            with request_lock:
                active_requests -= 1
                if request_queue:
                    next_id = request_queue.popleft()
                    # mark as ready — queue-status will promote it
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


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port, threaded=True)
