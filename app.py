import os
import sqlite3
import hashlib
import secrets
import json
import base64
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template_string, request, redirect,
                   url_for, session, flash, jsonify, send_file, abort)
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ────────────────────────────────────────────────────────────
#  CONFIGURATION
# ────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'saadan.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_IMAGE_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_PDF_EXT   = {'pdf'}

# ── بيانات الأدمن الافتراضية ──
ADMIN_DEFAULT_USERNAME = 'admin abdullah'
ADMIN_DEFAULT_PASSWORD = 'abdullah772030'

SYRIAN_CITIES = [
    'حمص', 'حلب', 'الشام', 'الرقة', 'الحسكة',
    'دير الزور', 'طرطوس', 'اللاذقية', 'جزيرة أرواد',
    'القامشلي', 'القنيطرة', 'درعا'
]

# ────────────────────────────────────────────────────────────
#  DATABASE SETUP
# ────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
    CREATE TABLE IF NOT EXISTS employers (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name      TEXT NOT NULL UNIQUE,
        company_desc      TEXT,
        phone             TEXT,
        email             TEXT UNIQUE NOT NULL,
        password_hash     TEXT NOT NULL,
        is_online         INTEGER DEFAULT 0,
        address           TEXT,
        city              TEXT,
        num_employees     TEXT,
        age_range         TEXT,
        work_location     TEXT,
        created_at        TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS employees (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name        TEXT NOT NULL,
        last_name         TEXT NOT NULL,
        gender            TEXT NOT NULL,
        age               INTEGER,
        nationality       TEXT,
        province          TEXT,
        profession        TEXT,
        phone             TEXT,
        email             TEXT UNIQUE NOT NULL,
        password_hash     TEXT NOT NULL,
        photo             BLOB,
        photo_mime        TEXT,
        cv_data           BLOB,
        cv_filename       TEXT,
        created_at        TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS job_ads (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        employer_id       INTEGER NOT NULL REFERENCES employers(id) ON DELETE CASCADE,
        title             TEXT NOT NULL,
        category          TEXT,
        description       TEXT,
        requirements      TEXT,
        created_at        TEXT DEFAULT (datetime('now')),
        updated_at        TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS applications (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        job_ad_id         INTEGER NOT NULL REFERENCES job_ads(id) ON DELETE CASCADE,
        employee_id       INTEGER NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
        extra_info        TEXT,
        cv_data           BLOB,
        cv_filename       TEXT,
        applied_at        TEXT DEFAULT (datetime('now')),
        UNIQUE(job_ad_id, employee_id)
    );
    CREATE TABLE IF NOT EXISTS admin_account (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        username          TEXT NOT NULL UNIQUE,
        password_hash     TEXT NOT NULL,
        email             TEXT,
        phone             TEXT,
        photo             BLOB,
        photo_mime        TEXT,
        created_at        TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS developers (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        name              TEXT NOT NULL,
        role              TEXT,
        photo             BLOB,
        photo_mime        TEXT,
        display_order     INTEGER DEFAULT 0,
        created_at        TEXT DEFAULT (datetime('now'))
    );
    """)

    for table in ('employers', 'employees'):
        cols = [row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()]
        if 'is_banned' not in cols:
            c.execute(f"ALTER TABLE {table} ADD COLUMN is_banned INTEGER DEFAULT 0")

    job_cols = [row[1] for row in c.execute("PRAGMA table_info(job_ads)").fetchall()]
    if 'category' not in job_cols:
        c.execute("ALTER TABLE job_ads ADD COLUMN category TEXT")

    existing = c.execute("SELECT id FROM admin_account LIMIT 1").fetchone()
    if not existing:
        c.execute("""INSERT INTO admin_account (username, password_hash, email, phone)
                     VALUES (?, ?, ?, ?)""",
                  (ADMIN_DEFAULT_USERNAME,
                   hashlib.sha256(ADMIN_DEFAULT_PASSWORD.encode()).hexdigest(),
                   'admin@saadan.com', '0986555105'))

    conn.commit()
    conn.close()

init_db()

# ────────────────────────────────────────────────────────────
#  HELPERS
# ────────────────────────────────────────────────────────────
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_col(row, col, default=''):
    """Helper آمن لقراءة عمود من sqlite3.Row"""
    try:
        val = row[col]
        return val if val is not None else default
    except (IndexError, KeyError):
        return default

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_type' not in session:
            flash('يرجى تسجيل الدخول أولاً', 'error')
            return redirect(url_for('login'))

        utype = session.get('user_type')
        if utype in ('employer', 'employee'):
            table = 'employers' if utype == 'employer' else 'employees'
            db = get_db()
            row = db.execute(f"SELECT is_banned FROM {table} WHERE id=?", (session.get('user_id'),)).fetchone()
            db.close()
            if row and row['is_banned']:
                uid = session.get('user_id')
                session.clear()
                return redirect(url_for('banned_page', user_type=utype, user_id=uid))

        return f(*args, **kwargs)
    return decorated

def employer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'employer':
            flash('هذه الصفحة لأصحاب العمل فقط', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def employee_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'employee':
            flash('هذه الصفحة للموظفين فقط', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('user_type') != 'admin':
            flash('هذه الصفحة للمسؤول فقط', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXT

def allowed_pdf(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PDF_EXT

# ────────────────────────────────────────────────────────────
#  SHARED CSS & JS
# ────────────────────────────────────────────────────────────
BASE_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700;900&family=Playfair+Display:wght@400;700&display=swap');
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --black:       #0a0a0a;
  --dark:        #111111;
  --card:        #1a1a1a;
  --card2:       #222222;
  --gold:        #c9a84c;
  --gold-light:  #e8c87a;
  --gold-dim:    #7d6530;
  --orange:      #b85c1a;
  --orange-lt:   #d4742a;
  --border:      #2e2e2e;
  --text:        #e8dcc8;
  --text-dim:    #9a8a6a;
  --danger:      #c0392b;
  --success:     #27ae60;
}

html { scroll-behavior: smooth; }

body {
  background: var(--black);
  color: var(--text);
  font-family: 'Cairo', sans-serif;
  min-height: 100vh;
  direction: rtl;
}

/* ── KEYFRAMES FOR VISUAL EFFECTS ── */
@keyframes pulseGlow {
  0% { text-shadow: 0 0 15px rgba(201,168,76,0.3); }
  50% { text-shadow: 0 0 35px rgba(201,168,76,0.8), 0 0 15px rgba(201,168,76,0.5); transform: scale(1.02); }
  100% { text-shadow: 0 0 15px rgba(201,168,76,0.3); }
}

@keyframes floatUp {
  0% { transform: translateY(30px); opacity: 0; }
  100% { transform: translateY(0); opacity: 1; }
}

@keyframes floating {
  0% { transform: translateY(0px); }
  50% { transform: translateY(-12px); }
  100% { transform: translateY(0px); }
}

@keyframes bgMove {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

/* ── TOOLTIP (لمحة عني) ── */
.my-tooltip-container {
  position: relative;
  display: inline-block;
  outline: none;
}
.my-tooltip-text {
  visibility: hidden;
  width: 320px;
  background: var(--card2);
  color: var(--text);
  text-align: right;
  border: 1px solid var(--gold-dim);
  border-radius: 10px;
  padding: 1.2rem;
  position: absolute;
  z-index: 9999;
  top: 140%;
  right: 0;
  opacity: 0;
  transform: translateY(15px);
  transition: all 0.3s ease;
  box-shadow: 0 10px 40px rgba(0,0,0,0.6);
  font-size: 0.9rem;
  line-height: 1.8;
  pointer-events: none;
}
.my-tooltip-container:hover .my-tooltip-text,
.my-tooltip-container:focus .my-tooltip-text {
  visibility: visible;
  opacity: 1;
  transform: translateY(0);
}
@media(max-width: 768px) {
  .my-tooltip-text {
    width: 270px;
    right: -60px;
  }
}

/* إخفاء شريط التمرير لمتصفحات Chrome و Safari و Opera */
html::-webkit-scrollbar, 
body::-webkit-scrollbar {
  display: none;
}

/* إخفاء شريط التمرير لمتصفحات Firefox و Edge */
html, body {
  -ms-overflow-style: none;  /* لمتصفح IE و Edge */
  scrollbar-width: none;  /* لمتصفح Firefox */
}

/* ── NAVBAR ── */
.navbar {
  background: linear-gradient(90deg, #0d0d0d 0%, #1a1208 50%, #0d0d0d 100%);
  border-bottom: 1px solid var(--gold-dim);
  padding: 0 1.5rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 64px;
  position: sticky; top: 0;
  z-index: 100;
  box-shadow: 0 2px 20px rgba(201,168,76,.15);
  gap: 1rem;
}
.navbar-brand {
  font-family: 'Cairo', sans-serif;
  font-weight: 900;
  font-size: 1.6rem;
  color: var(--gold);
  text-decoration: none;
  letter-spacing: 1px;
  display: flex; align-items: center; gap: .5rem;
  flex-shrink: 0;
}
.navbar-brand span { color: var(--orange); font-size: 1.1rem; }

/* ── NAVBAR SEARCH (في الهيدر) ── */
.navbar-search {
  display: flex;
  align-items: center;
  background: rgba(255,255,255,0.04);
  border: 1px solid var(--gold-dim);
  border-radius: 25px;
  padding: 0.3rem 0.8rem;
  transition: all 0.3s;
  flex: 1;
  max-width: 380px;
  min-width: 0;
}
.navbar-search:focus-within {
  border-color: var(--gold);
  background: rgba(201,168,76,0.05);
  box-shadow: 0 0 15px rgba(201,168,76,0.12);
}
.navbar-search input {
  background: transparent;
  border: none;
  color: var(--text);
  font-family: 'Cairo', sans-serif;
  font-size: 0.85rem;
  padding: 0.25rem 0.4rem;
  outline: none;
  flex: 1;
  min-width: 0;
  width: 100%;
}
.navbar-search input::placeholder { color: var(--text-dim); }
.navbar-search button {
  background: linear-gradient(135deg, var(--gold-dim), var(--gold));
  border: none;
  color: #0a0a0a;
  border-radius: 18px;
  padding: 0.3rem 0.8rem;
  cursor: pointer;
  font-family: 'Cairo', sans-serif;
  font-size: 0.78rem;
  font-weight: 700;
  white-space: nowrap;
  flex-shrink: 0;
  transition: opacity 0.2s;
}
.navbar-search button:hover { opacity: 0.85; }

.nav-links { display: flex; align-items: center; gap: 0.7rem; flex-wrap: nowrap; flex-shrink: 0; }
.nav-links a, .nav-links button {
  color: var(--text-dim);
  text-decoration: none;
  font-size: .85rem;
  padding: .35rem .7rem;
  border-radius: 6px;
  border: none;
  background: none;
  cursor: pointer;
  transition: all .25s;
  font-family: 'Cairo', sans-serif;
  white-space: nowrap;
}
.nav-links a:hover, .nav-links button:hover { color: var(--gold); background: rgba(201,168,76,.08); }
.nav-links .btn-nav-main {
  background: linear-gradient(135deg, var(--orange), var(--orange-lt));
  color: #fff;
  font-weight: 700;
  padding: .4rem 1rem;
  border-radius: 20px;
}
.nav-links .btn-nav-main:hover { opacity: .85; color: #fff; }
.nav-about-btn {
  background: rgba(201,168,76,.1) !important;
  border: 1px solid var(--gold-dim) !important;
  color: var(--gold) !important;
  border-radius: 8px !important;
}
.nav-about-btn:hover { background: rgba(201,168,76,.2) !important; }

/* ── SEARCH BAR (داخل الصفحة - للموظف) ── */
.search-form {
  display: flex; gap: 0.5rem; align-items: center;
  background: var(--card);
  border: 1px solid var(--gold-dim);
  border-radius: 30px;
  padding: 0.5rem 1.2rem;
  transition: all 0.3s;
  flex-wrap: wrap;
  justify-content: flex-start;
  box-shadow: 0 4px 15px rgba(0,0,0,0.3);
  width: 100%;
}
.search-form:focus-within {
  border-color: var(--gold);
  box-shadow: 0 4px 20px rgba(201,168,76,.2);
}
.search-input {
  background: transparent;
  border: none;
  color: var(--text);
  font-family: 'Cairo', sans-serif;
  font-size: 0.95rem;
  padding: 0.4rem;
  outline: none;
  flex: 1;
  min-width: 120px;
}
.search-input::placeholder { color: var(--text-dim); }
.search-divider {
  width: 1px;
  height: 24px;
  background: var(--border);
  margin: 0 0.4rem;
}

/* ── FLASH ── */
.flash-container { padding: .8rem 2rem; }
.flash {
  padding: .8rem 1.2rem;
  border-radius: 8px;
  margin-bottom: .5rem;
  font-size: .9rem;
  border-right: 4px solid;
  animation: slideDown .3s ease;
}
@keyframes slideDown { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
.flash.error   { background: rgba(192,57,43,.15); border-color: var(--danger); color: #e87b70; }
.flash.success { background: rgba(39,174,96,.15); border-color: var(--success); color: #6fcf97; }
.flash.info    { background: rgba(201,168,76,.1); border-color: var(--gold-dim); color: var(--gold); }

/* ── CARD ── */
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 2rem;
  transition: box-shadow .3s, border-color .3s;
}
.card:hover { border-color: var(--gold-dim); box-shadow: 0 4px 30px rgba(201,168,76,.08); }

/* ── FORM ── */
.form-group { margin-bottom: 1.2rem; }
.form-group label { display: block; margin-bottom: .4rem; color: var(--gold); font-size: .88rem; font-weight: 600; }
.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  background: var(--card2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: .7rem 1rem;
  color: var(--text);
  font-family: 'Cairo', sans-serif;
  font-size: .95rem;
  transition: border-color .25s, box-shadow .25s;
  outline: none;
}
.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  border-color: var(--gold-dim);
  box-shadow: 0 0 0 3px rgba(201,168,76,.12);
}
.form-group textarea { min-height: 100px; resize: vertical; }
.form-group select option { background: var(--dark); }
.form-group input[type="file"] { padding: .5rem; cursor: pointer; }
.form-group input[type="file"]::file-selector-button {
  background: var(--gold-dim);
  color: #000;
  border: none;
  padding: .3rem .8rem;
  border-radius: 6px;
  cursor: pointer;
  margin-left: .8rem;
  font-family: 'Cairo', sans-serif;
}

/* ── BUTTONS ── */
.btn {
  display: inline-flex; align-items: center; gap: .5rem;
  padding: .65rem 1.6rem;
  border: none; border-radius: 8px;
  font-family: 'Cairo', sans-serif;
  font-size: .95rem; font-weight: 700;
  cursor: pointer;
  transition: all .25s;
  text-decoration: none;
}
.btn-gold {
  background: linear-gradient(135deg, var(--gold-dim), var(--gold));
  color: #0a0a0a;
}
.btn-gold:hover { opacity: .85; transform: translateY(-1px); box-shadow: 0 4px 15px rgba(201,168,76,.3); }
.btn-orange {
  background: linear-gradient(135deg, var(--orange), var(--orange-lt));
  color: #fff;
}
.btn-orange:hover { opacity: .85; transform: translateY(-1px); box-shadow: 0 4px 15px rgba(184,92,26,.3); }
.btn-outline {
  background: transparent;
  border: 1px solid var(--gold-dim);
  color: var(--gold);
}
.btn-outline:hover { background: rgba(201,168,76,.08); }
.btn-danger {
  background: linear-gradient(135deg, #922b21, var(--danger));
  color: #fff;
}
.btn-danger:hover { opacity: .85; }
.btn-sm { padding: .4rem 1rem; font-size: .82rem; }
.btn-full { width: 100%; justify-content: center; margin-top: .5rem; }

/* ── SECTION TITLE ── */
.section-title {
  font-size: 1.5rem;
  font-weight: 900;
  color: var(--gold);
  margin-bottom: 1.5rem;
  padding-bottom: .7rem;
  border-bottom: 1px solid var(--border);
  position: relative;
}
.section-title::after {
  content: '';
  position: absolute;
  bottom: -1px; right: 0;
  width: 60px; height: 2px;
  background: var(--gold);
}

/* ── ICON CIRCLE ── */
.icon-circle {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: rgba(184,92,26,.15);
  border: 1px solid var(--orange);
  color: var(--orange);
  display: flex; align-items: center; justify-content: center;
  font-size: 1.3rem;
  flex-shrink: 0;
}

/* ── BADGE ── */
.badge {
  display: inline-block;
  padding: .2rem .7rem;
  border-radius: 20px;
  font-size: .75rem;
  font-weight: 700;
}
.badge-gold  { background: rgba(201,168,76,.15); color: var(--gold); border: 1px solid var(--gold-dim); }
.badge-orange{ background: rgba(184,92,26,.15); color: var(--orange-lt); border: 1px solid var(--orange); }
.badge-admin { background: rgba(139,0,139,.2); color: #da70d6; border: 1px solid #9932cc; }
.badge-category { background: rgba(255,255,255,0.05); color: var(--text-dim); border: 1px solid var(--border); font-size: 0.7rem;}

/* ── DIVIDER ── */
.divider {
  border: none;
  border-top: 1px solid var(--border);
  margin: 1.5rem 0;
}

/* ── PAGE FADE ── */
.page-enter { animation: pageFadeIn .4s ease; }
@keyframes pageFadeIn {
  from { opacity: 0; transform: translateY(14px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* ── GRID ── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.grid-3 { display: grid; grid-template-columns: repeat(3,1fr); gap: 1.5rem; }
@media(max-width:768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }

/* ── APPLICANT ROW ── */
.applicant-row {
  display: flex;
  align-items: center; gap: 1rem;
  padding: 1rem;
  background: var(--card2);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-bottom: .8rem;
  transition: border-color .2s;
}
.applicant-row:hover { border-color: var(--gold-dim); }
.applicant-avatar {
  width: 52px; height: 52px;
  border-radius: 50%;
  object-fit: cover;
  border: 2px solid var(--gold-dim);
  flex-shrink: 0;
}
.applicant-avatar-placeholder {
  width: 52px; height: 52px;
  border-radius: 50%;
  background: var(--card);
  border: 2px solid var(--gold-dim);
  display: flex;
  align-items: center; justify-content: center;
  color: var(--gold);
  font-size: 1.4rem;
  flex-shrink: 0;
}

/* ── JOB CARD ── */
.job-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 1.5rem;
  transition: all .3s;
}
.job-card:hover { border-color: var(--gold-dim); transform: translateY(-2px); box-shadow: 0 8px 30px rgba(0,0,0,.3); }
.job-card-header { display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1rem; }

/* ── MODAL ── */
.modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,.8);
  z-index: 1000;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 1rem;
}
.modal-overlay.show {
  display: flex;
  animation: fadeIn .2s ease;
}
@keyframes fadeIn { from{opacity:0} to{opacity:1} }
.modal {
  background: var(--card);
  border: 1px solid var(--gold-dim);
  border-radius: 16px;
  padding: 2rem;
  width: 100%;
  max-width: 600px;
  max-height: 85vh;
  overflow-y: auto;
  animation: slideUp .3s ease;
}
@keyframes slideUp { from{opacity:0;transform:translateY(30px)} to{opacity:1;transform:translateY(0)} }
.modal-header {
  display: flex;
  justify-content: space-between; align-items: center;
  margin-bottom: 1.5rem;
  padding-bottom: .8rem;
  border-bottom: 1px solid var(--border);
}
.modal-title { color: var(--gold); font-size: 1.2rem; font-weight: 700; }
.modal-close {
  background: none; border: none; color: var(--text-dim);
  font-size: 1.4rem; cursor: pointer; padding: .2rem .5rem;
  border-radius: 4px;
  transition: color .2s;
}
.modal-close:hover { color: var(--gold); }

/* ── ABOUT US MODAL ── */
.about-modal-body { text-align: center; line-height: 2; }
.about-logo {
  font-size: 3rem;
  font-weight: 900;
  color: var(--gold);
  font-family: 'Cairo', sans-serif;
  margin-bottom: .5rem;
}
.about-tagline { color: var(--orange-lt); font-size: 1.1rem; font-weight: 700; margin-bottom: 1.5rem; }
.about-text { color: var(--text); font-size: 1rem; line-height: 2; margin-bottom: 1.5rem; }
.about-contact {
  background: var(--card2);
  border: 1px solid var(--gold-dim);
  border-radius: 10px;
  padding: 1rem 1.5rem;
  margin-top: 1rem;
}
.about-contact p { color: var(--gold); font-size: 1rem; font-weight: 700; }
.about-contact span { color: var(--orange-lt); font-size: 1.2rem; font-weight: 900; letter-spacing: 1px; }

/* ── DEVELOPERS MODAL ── */
.dev-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 1.5rem;
  margin-top: 1rem;
}
.dev-card { text-align: center; }
.dev-avatar {
  width: 110px; height: 110px;
  border-radius: 50%;
  object-fit: cover;
  border: 3px solid var(--gold);
  margin: 0 auto .8rem;
  display: block;
}
.dev-avatar-placeholder {
  width: 110px; height: 110px;
  border-radius: 50%;
  background: var(--card2);
  border: 3px solid var(--gold);
  display: flex; align-items: center; justify-content: center;
  font-size: 2.8rem; color: var(--gold);
  margin: 0 auto .8rem;
}
.dev-name { color: var(--gold); font-weight: 700; font-size: 1rem; }
.dev-role { color: var(--text-dim); font-size: .85rem; margin-top: .2rem; }
.dev-empty { text-align:center; color: var(--text-dim); padding: 1.5rem 0; }

/* ── DEV ADMIN CARDS ── */
.dev-admin-card {
  background: var(--card2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1rem;
  text-align: center;
  position: relative;
}
.dev-admin-card .dev-avatar,
.dev-admin-card .dev-avatar-placeholder { width: 90px; height: 90px; font-size: 2.2rem; }
.dev-admin-actions { display:flex; gap:.5rem; justify-content:center; margin-top:.8rem; }

/* ── TABS ── */
.tab-container { margin-bottom: 2rem; }
.tabs { display: flex; gap: .5rem; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
.tab-btn {
  background: none; border: none; padding: .7rem 1.2rem;
  color: var(--text-dim);
  font-family: 'Cairo', sans-serif;
  font-size: .95rem; cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: all .2s; margin-bottom: -1px;
}
.tab-btn.active { color: var(--gold); border-bottom-color: var(--gold); }
.tab-btn:hover { color: var(--gold); }
.tab-content { display: none; }
.tab-content.active { display: block; }

/* ── RADIO CHOICE ── */
.choice-group { display: flex; gap: 1rem; flex-wrap: wrap; }
.choice-card {
  flex: 1; min-width: 150px;
  background: var(--card2);
  border: 2px solid var(--border);
  border-radius: 10px;
  padding: 1.2rem;
  cursor: pointer;
  transition: all .25s;
  text-align: center;
}
.choice-card:hover { border-color: var(--gold-dim); }
.choice-card input[type="radio"] { display: none; }
.choice-card.selected { border-color: var(--gold); background: rgba(201,168,76,.08); }
.choice-card .choice-icon { font-size: 2rem; margin-bottom: .5rem; color: var(--orange); }
.choice-card .choice-label { font-weight: 700; color: var(--text); }

/* ── HERO (بدون شريط بحث في المنتصف) ── */
.hero {
  min-height: calc(100vh - 64px);
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  text-align: center;
  padding: 3rem 1rem;
  position: relative;
  overflow: hidden;
  background: linear-gradient(-45deg, #050505, #1a1208, #111111, #221505);
  background-size: 400% 400%;
  animation: bgMove 15s ease infinite;
}
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background:
    radial-gradient(ellipse 60% 50% at 50% 30%, rgba(201,168,76,.08) 0%, transparent 70%),
    radial-gradient(ellipse 40% 40% at 20% 80%, rgba(184,92,26,.06) 0%, transparent 60%);
  pointer-events: none;
}
.hero-content {
  position: relative;
  z-index: 1;
}
.hero-logo {
  font-size: 5.5rem;
  font-weight: 900;
  color: var(--gold);
  letter-spacing: 2px;
  line-height: 1.1;
  margin-bottom: .3rem;
  font-family: 'Cairo', sans-serif;
  animation: pulseGlow 3s infinite;
  transition: transform 0.3s;
}
.hero-logo-en {
  font-family: 'Playfair Display', serif;
  font-size: 2.6rem;
  color: var(--orange);
  letter-spacing: 6px;
  margin-bottom: 1.5rem;
  display: block;
  animation: floating 4s ease-in-out infinite;
}
.hero-tagline {
  font-size: 1.3rem;
  color: var(--text-dim);
  max-width: 550px;
  line-height: 1.8;
  margin-bottom: 1.5rem;
  animation: floatUp 1s ease forwards;
  opacity: 0;
  animation-delay: 0.2s;
}
.hero-btns {
  display: flex; gap: 1rem;
  flex-wrap: wrap;
  justify-content: center;
  animation: floatUp 1s ease forwards;
  opacity: 0;
  animation-delay: 0.4s;
}

/* ── STATS ── */
.stat-box {
  text-align: center; padding: 1.8rem;
  background: rgba(26, 26, 26, 0.4);
  border: 1px solid rgba(201,168,76,.2);
  border-radius: 16px;
  backdrop-filter: blur(10px);
  transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  animation: floatUp 1s ease forwards;
  opacity: 0;
}
.stat-box:nth-child(1) { animation-delay: 0.6s; }
.stat-box:nth-child(2) { animation-delay: 0.8s; }
.stat-box:nth-child(3) { animation-delay: 1.0s; }
.stat-box:hover {
  transform: translateY(-8px) scale(1.02);
  border-color: var(--gold);
  box-shadow: 0 15px 35px rgba(201,168,76,.15);
}
.stat-num { font-size: 2.5rem; font-weight: 900; color: var(--gold); text-shadow: 0 0 10px rgba(201,168,76,.3); }
.stat-label { font-size: .9rem; color: var(--text-dim); margin-top: .4rem; font-weight: 600; }

/* ── GOLDEN LINE ── */
.golden-line {
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--gold-dim), transparent);
  border: none;
  margin: 3rem auto;
  max-width: 600px;
  animation: floatUp 1s ease forwards;
  opacity: 0;
  animation-delay: 1.2s;
}

/* ── PROFILE HEADER ── */
.profile-header { display: flex; align-items: center; gap: 1.5rem; margin-bottom: 2rem; }
.profile-avatar {
  width: 90px; height: 90px;
  border-radius: 50%;
  object-fit: cover;
  border: 3px solid var(--gold);
}
.profile-avatar-placeholder {
  width: 90px; height: 90px;
  border-radius: 50%;
  background: var(--card2);
  border: 3px solid var(--gold);
  display: flex; align-items: center; justify-content: center;
  font-size: 2.5rem; color: var(--gold);
}
.profile-name { font-size: 1.6rem; font-weight: 900; color: var(--gold); }
.profile-role { color: var(--text-dim); font-size: .9rem; margin-top: .2rem; }

/* ── ADMIN PANEL ── */
.admin-sidebar {
  background: var(--card);
  border: 1px solid var(--gold-dim);
  border-radius: 14px;
  padding: 1.5rem;
  position: sticky;
  top: 80px;
}
.admin-menu-item {
  display: flex; align-items: center; gap: .8rem;
  padding: .8rem 1rem;
  border-radius: 8px;
  cursor: pointer;
  color: var(--text-dim);
  text-decoration: none;
  font-size: .95rem;
  transition: all .2s;
  margin-bottom: .3rem;
}
.admin-menu-item:hover, .admin-menu-item.active {
  background: rgba(201,168,76,.1);
  color: var(--gold);
  border-right: 3px solid var(--gold);
}
.admin-stat-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.5rem;
  text-align: center;
  transition: all .3s;
}
.admin-stat-card:hover { border-color: var(--gold-dim); transform: translateY(-2px); }
.admin-stat-num { font-size: 2.5rem; font-weight: 900; color: var(--gold); }
.admin-stat-label { color: var(--text-dim); font-size: .9rem; margin-top: .3rem; }

/* ── DATA TABLE ── */
.data-table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
.data-table th {
  background: var(--card2);
  color: var(--gold);
  padding: .8rem 1rem;
  text-align: right;
  font-size: .85rem;
  font-weight: 700;
  border-bottom: 2px solid var(--gold-dim);
}
.data-table td {
  padding: .75rem 1rem;
  font-size: .85rem;
  color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}
.data-table tr:hover td { background: rgba(201,168,76,.03); color: var(--text); }
.data-table td small { color: var(--text-dim); font-size: .75rem; }

/* ── UTILITY ── */
.text-center { text-align: center; }
.text-gold { color: var(--gold); }
.text-orange { color: var(--orange-lt); }
.text-dim { color: var(--text-dim); }
.mt-1 { margin-top: .5rem; }
.mt-2 { margin-top: 1rem; }
.mt-3 { margin-top: 1.5rem; }
.mb-2 { margin-bottom: 1rem; }
.mb-3 { margin-bottom: 1.5rem; }
.p-3  { padding: 1.5rem; }
.gap-2 { gap: 1rem; }
.d-flex { display: flex; }
.align-center { align-items: center; }
.justify-between { justify-content: space-between; }
.flex-wrap { flex-wrap: wrap; }

@media(max-width: 768px) {
  .navbar { padding: 0 0.8rem; gap: 0.5rem; }
  .navbar-brand { font-size: 1.3rem; }
  .navbar-search { max-width: 160px; }
  .navbar-search input { font-size: 0.78rem; }
  .nav-links { gap: 0.3rem; }
  .nav-links a, .nav-links button { font-size: 0.78rem; padding: 0.3rem 0.5rem; }
}
"""

BASE_SCRIPTS = """
<script>
// Tab switching
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  event.currentTarget.classList.add('active');
}

// Choice cards
document.querySelectorAll('.choice-card').forEach(card => {
  card.addEventListener('click', () => {
    const radio = card.querySelector('input[type="radio"]');
    if (radio) {
      radio.checked = true;
      const name = radio.getAttribute('name');
      document.querySelectorAll(`.choice-card input[name="${name}"]`).forEach(r => {
        r.closest('.choice-card').classList.remove('selected');
      });
      card.classList.add('selected');
    }
  });
});

// About Us Modal
function openAboutModal() {
  document.getElementById('aboutModal').classList.add('show');
}
function closeAboutModal() {
  document.getElementById('aboutModal').classList.remove('show');
}
document.addEventListener('click', function(e) {
  const modal = document.getElementById('aboutModal');
  if (modal && e.target === modal) modal.classList.remove('show');
});

// Developers Modal
function openDevsModal() {
  document.getElementById('devsModal').classList.add('show');
}
function closeDevsModal() {
  document.getElementById('devsModal').classList.remove('show');
}
document.addEventListener('click', function(e) {
  const modal = document.getElementById('devsModal');
  if (modal && e.target === modal) modal.classList.remove('show');
});

// Login Required Modal
function openLoginRequiredModal() {
  document.getElementById('loginRequiredModal').classList.add('show');
}
function closeLoginRequiredModal() {
  document.getElementById('loginRequiredModal').classList.remove('show');
}

// Close modals on overlay click
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', function(e) {
    if (e.target === this) this.classList.remove('show');
  });
});

// Flash auto-hide
setTimeout(() => {
  document.querySelectorAll('.flash').forEach(f => {
    f.style.opacity = '0'; f.style.transition = 'opacity .5s';
    setTimeout(() => f.remove(), 500);
  });
}, 4000);
</script>
"""

# ── نافذة تسجيل الدخول المطلوب ──
def get_login_required_modal():
    from flask import url_for as _url_for
    return f"""
<div id="loginRequiredModal" class="modal-overlay">
  <div class="modal" style="max-width:480px">
    <div class="modal-header">
      <span class="modal-title">🔐 يجب تسجيل الدخول أولاً</span>
      <button class="modal-close" onclick="closeLoginRequiredModal()">✕</button>
    </div>
    <div style="text-align:center;padding:1rem 0">
      <div style="font-size:3.5rem;margin-bottom:1rem">🔍</div>
      <p style="font-size:1.05rem;color:var(--text);line-height:1.9;margin-bottom:1.5rem">
        للبحث عن الوظائف والتقديم عليها<br>
        <strong style="color:var(--gold)">يجب أن يكون لديك حساب</strong> في منصة سعدان
      </p>
      <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap">
        <a href="{_url_for('login')}" class="btn btn-gold" style="min-width:140px">
          🔑 تسجيل الدخول
        </a>
        <a href="{_url_for('register')}" class="btn btn-orange" style="min-width:140px">
          ✨ إنشاء حساب جديد
        </a>
      </div>
      <p class="text-dim" style="font-size:.85rem;margin-top:1.2rem">
        الانضمام مجاني تماماً ويستغرق دقيقة واحدة فقط
      </p>
    </div>
  </div>
</div>
"""

# ── نافذة "من نحن" ──
ABOUT_MODAL = """
<div id="aboutModal" class="modal-overlay">
  <div class="modal" style="max-width:540px">
    <div class="modal-header">
      <span class="modal-title">🌟 من نحن</span>
      <button class="modal-close" onclick="closeAboutModal()">✕</button>
    </div>
    <div class="about-modal-body">
      <div class="about-logo">سعدان</div>
      <div class="about-tagline">وكالة سعدان | Saadan Agency</div>
      <div class="about-text">
        أهلاً بكم في وكالة سعدان<br>
        وجهتك الأولى للحصول على فرص عمل كبيرة بلا حدود<br>
        <strong style="color:var(--gold)">مجالات متعددة</strong> واختصاصات كبيرة<br>
        تناسب مجالات عملك وحاجة السوق لك
      </div>
      <div class="about-contact">
        <p>📞 للاستفسار والتواصل</p>
        <p>تواصلوا مع خدمة العملاء عبر الرقم:</p>
        <span>0986555105</span>
      </div>
    </div>
  </div>
</div>
"""

def get_developers_modal():
    db = get_db()
    devs = db.execute("SELECT * FROM developers ORDER BY display_order ASC, id ASC").fetchall()
    db.close()

    if devs:
        cards = ""
        for d in devs:
            if d['photo']:
                avatar = f'<img src="{url_for("developer_photo", dev_id=d["id"])}" class="dev-avatar" alt="{d["name"]}">'
            else:
                avatar = '<div class="dev-avatar-placeholder">👤</div>'
            cards += f"""
            <div class="dev-card">
              {avatar}
              <div class="dev-name">{d['name']}</div>
              <div class="dev-role">{d['role'] or ''}</div>
            </div>
            """
        body = f'<div class="dev-grid">{cards}</div>'
    else:
        body = '<div class="dev-empty">لم تتم إضافة أعضاء الفريق بعد</div>'

    return f"""
    <div id="devsModal" class="modal-overlay">
      <div class="modal" style="max-width:640px">
        <div class="modal-header">
          <span class="modal-title"> المطورين</span>
          <button class="modal-close" onclick="closeDevsModal()">✕</button>
        </div>
        {body}
      </div>
    </div>
    """

def render_page(content, title="سعدان | Saadan"):
    from flask import get_flashed_messages
    msgs = get_flashed_messages(with_categories=True)
    flashes = ""
    for cat, msg in msgs:
        flashes += f'<div class="flash {cat}">{msg}</div>'

    user_type = session.get('user_type')
    user_name = session.get('user_name', '')

    nav_right = ""
    if user_type == 'admin':
        nav_right = f"""
        <a href="{url_for('admin_dashboard')}" style="color:#da70d6">👑 لوحة الأدمن</a>
        <span class="badge badge-admin">admin</span>
        <a href="{url_for('logout')}">تسجيل الخروج</a>
        """
    elif user_type == 'employer':
        nav_right = f"""
        <a href="{url_for('employer_dashboard')}">🏢 لوحة التحكم</a>
        <a href="{url_for('create_job_ad')}">➕ إنشاء إعلان</a>
        <a href="{url_for('logout')}">تسجيل الخروج</a>
        """
    elif user_type == 'employee':
        nav_right = f"""
        <a href="{url_for('employee_dashboard')}">👤 ملفي</a>
        <a href="{url_for('logout')}">تسجيل الخروج</a>
        """
    else:
        nav_right = f"""
        <a href="{url_for('register')}">إنشاء حساب</a>
        <a href="{url_for('login')}" class="btn-nav-main">تسجيل الدخول</a>
        """

    # شريط البحث في الهيدر
    if user_type in ('employee', 'employer', 'admin'):
        navbar_search = f"""
        <form action="{url_for('job_listings')}" method="GET" class="navbar-search">
          <input type="text" name="q" placeholder="ابحث عن وظيفة..." autocomplete="off">
          <button type="submit">بحث</button>
        </form>
        """
    else:
        navbar_search = f"""
        <div class="navbar-search" style="cursor:pointer" onclick="openLoginRequiredModal()">
          <input type="text" placeholder="ابحث عن وظيفة..." autocomplete="off"
                 onfocus="this.blur();openLoginRequiredModal()" style="cursor:pointer">
          <button type="button" onclick="openLoginRequiredModal()">بحث</button>
        </div>
        """

    return render_template_string(f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{title}</title>
  <style>{BASE_STYLE}</style>
</head>
<body>
  <nav class="navbar">
    <a href="{url_for('index')}" class="navbar-brand">
      سعدان <span>| Saadan</span>
    </a>
    {navbar_search}
    <div class="nav-links">
      <button class="nav-about-btn" onclick="openAboutModal()">من نحن</button>
      <div class="my-tooltip-container" tabindex="0">
        <button class="nav-about-btn" style="pointer-events: none;">لمحة عن الشركة</button>
        <div class="my-tooltip-text">
          نحن <strong style="color:var(--gold)">شركة الهندسة التقدمية</strong> الشريك الأول والمؤسس الرسمي للموقع.<br>
          نحن شركة هدفها ربط الموظفين والباحثين عن عمل بشركات، وربطهم برواد الأعمال فوراً.<br><br>
          أيضاً تتضمن مجموعتنا عدة وكالات آخرها وكالة <strong style="color:var(--orange-lt)">Red Media</strong> وهي وكالة تسويق رقمي، أبرزها التصوير والمونتاج وإدارة صفحات السوشيال ميديا وتصوير الإعلانات وإنشاء مونتاج للفيديوهات.<br><br>
          <span style="color:var(--text-dim)">حيث توفر جميع وكالاتنا خدمة عملاء تتوفر لمدة 24 ساعة.</span>
        </div>
      </div>
      <button class="nav-about-btn" onclick="openDevsModal()">المطورين</button>
      {nav_right}
    </div>
  </nav>
  {'<div class="flash-container">' + flashes + '</div>' if flashes else ''}
  <div class="page-enter">
    {content}
  </div>
  {ABOUT_MODAL}
  {get_developers_modal()}
  {get_login_required_modal()}
  {BASE_SCRIPTS}
</body>
</html>""")

# ════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════

# ── INDEX ──────────────────────────────────────────────────
@app.route('/')
def index():
    db = get_db()
    emp_count    = db.execute("SELECT COUNT(*) FROM employers").fetchone()[0]
    job_count    = db.execute("SELECT COUNT(*) FROM job_ads").fetchone()[0]
    worker_count = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    db.close()

    user_type_idx = session.get('user_type')
    if user_type_idx in ('employee', 'employer', 'admin'):
        hero_btns = f'''
          <a href="{url_for('job_listings')}" class="btn btn-orange">🔍 تصفح الوظائف</a>
          <a href="{url_for('employee_dashboard') if user_type_idx == 'employee' else url_for('employer_dashboard') if user_type_idx == 'employer' else url_for('admin_dashboard')}" class="btn btn-outline">👤 لوحتي</a>
        '''
    else:
        hero_btns = f'''
          <a href="{url_for('register')}" class="btn btn-gold">إنشاء حساب</a>
          <a href="{url_for('login')}" class="btn btn-outline">تسجيل الدخول</a>
          <button type="button" class="btn btn-orange" onclick="openLoginRequiredModal()">تصفح الوظائف</button>
        '''

    content = f"""
    <div class="hero">
      <div class="hero-content">
        <div class="hero-logo">سعدان</div>
        <span class="hero-logo-en">S A A D A N</span>
        <p class="hero-tagline">
          أهلاً بكم في موقع <strong style="color:var(--gold)">سعدان</strong> لفرص العمل الشاغرة<br>
          الجسر الذي يربط أصحاب العمل بالكفاءات
        </p>

        <div class="hero-btns">
          {hero_btns}
        </div>

        <hr class="golden-line">

        <div class="grid-3" style="max-width:800px;margin:0 auto">
          <div class="stat-box">
            <div class="stat-num">{emp_count}+</div>
            <div class="stat-label">شركة مسجّلة</div>
          </div>
          <div class="stat-box">
            <div class="stat-num">{job_count}+</div>
            <div class="stat-label">فرصة عمل</div>
          </div>
          <div class="stat-box">
            <div class="stat-num">{worker_count}+</div>
            <div class="stat-label">باحث عن عمل</div>
          </div>
        </div>
      </div>
    </div>
    """
    return render_page(content, "سعدان | Saadan - فرص العمل الشاغرة")

# ── REGISTER ───────────────────────────────────────────────
@app.route('/register')
def register():
    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <h1 class="section-title">📋 إنشاء حساب جديد</h1>
      <p class="text-dim mb-3">اختر نوع حسابك للبدء</p>

      <div class="choice-group mb-3">
        <div class="choice-card" onclick="window.location='{url_for('register_employer')}'">
          <div class="choice-icon">🏢</div>
          <div class="choice-label">صاحب عمل</div>
          <p style="font-size:.8rem;color:var(--text-dim);margin-top:.4rem">أنا أملك شركة وأبحث عن موظفين</p>
        </div>
        <div class="choice-card" onclick="window.location='{url_for('register_employee')}'">
          <div class="choice-icon">👨‍💼</div>
          <div class="choice-label">باحث عن عمل</div>
          <p style="font-size:.8rem;color:var(--text-dim);margin-top:.4rem">أنا أبحث عن فرصة عمل مناسبة</p>
        </div>
      </div>

      <p class="text-center text-dim" style="font-size:.9rem">
        لديك حساب؟ <a href="{url_for('login')}" style="color:var(--gold)">سجّل الدخول</a>
      </p>
    </div>
    """
    return render_page(content, "إنشاء حساب")

# ── REGISTER EMPLOYER ──────────────────────────────────────
@app.route('/register/employer', methods=['GET', 'POST'])
def register_employer():
    cities_opts = "".join(f'<option value="{c}">{c}</option>' for c in SYRIAN_CITIES)

    if request.method == 'POST':
        f = request.form
        company_name = f.get('company_name','').strip()
        company_desc = f.get('company_desc','').strip()
        phone        = f.get('phone','').strip()
        email        = f.get('email','').strip().lower()
        password     = f.get('password','')
        password2    = f.get('password2','')
        is_online    = f.get('work_type') == 'online'
        address      = f.get('address','').strip()
        city         = f.get('city','')
        num_employees= f.get('num_employees','').strip()
        age_range    = f.get('age_range','').strip()

        if password != password2:
            flash('كلمتا المرور غير متطابقتين', 'error')
            return redirect(url_for('register_employer'))
        if not company_name or not email or not password:
            flash('يرجى تعبئة جميع الحقول المطلوبة', 'error')
            return redirect(url_for('register_employer'))

        db = get_db()
        try:
            db.execute("""INSERT INTO employers
              (company_name,company_desc,phone,email,password_hash,is_online,address,city,num_employees,age_range,work_location)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
              (company_name, company_desc, phone, email,
               hash_password(password), 1 if is_online else 0,
               address, city, num_employees, age_range,
               'online' if is_online else 'office'))
            db.commit()
            row = db.execute("SELECT id FROM employers WHERE email=?", (email,)).fetchone()
            session['user_type'] = 'employer'
            session['user_id']   = row['id']
            session['user_name'] = company_name
            flash('تم إنشاء حساب شركتك بنجاح! 🎉', 'success')
            return redirect(url_for('employer_dashboard'))
        except sqlite3.IntegrityError:
            flash('الشركة أو البريد الإلكتروني مسجّل مسبقاً', 'error')
        finally:
            db.close()

    content = f"""
    <div style="max-width:800px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('register')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">🏢 تسجيل صاحب عمل</h1>
      </div>

      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">بيانات الشركة</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>اسم الشركة *</label>
              <input name="company_name" required placeholder="مثال: شركة النجوم للتقنية">
            </div>
            <div class="form-group">
              <label>رقم الهاتف *</label>
              <input name="phone" required placeholder="+963 XXX XXX XXX">
            </div>
          </div>
          <div class="form-group">
            <label>البريد الإلكتروني *</label>
            <input type="email" name="email" required placeholder="info@company.com">
          </div>
          <div class="form-group">
            <label>وصف الشركة</label>
            <textarea name="company_desc" placeholder="اكتب نبذة مختصرة عن شركتك..."></textarea>
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">نوع الشركة</h3>
          <div class="form-group">
            <label>طبيعة العمل *</label>
            <div class="choice-group" id="work-type-group">
              <label class="choice-card" id="card-online">
                <input type="radio" name="work_type" value="online" onchange="toggleOfficeFields(false)">
                <div class="choice-icon">🌐</div>
                <div class="choice-label">شركة أونلاين</div>
              </label>
              <label class="choice-card" id="card-office">
                <input type="radio" name="work_type" value="office" onchange="toggleOfficeFields(true)" checked>
                <div class="choice-icon">🏗️</div>
                <div class="choice-label">مقر رسمي</div>
              </label>
            </div>
          </div>

          <div id="office-fields">
            <div class="grid-2">
              <div class="form-group">
                <label>المدينة / المحافظة</label>
                <select name="city">
                  <option value="">-- اختر المدينة --</option>
                  {cities_opts}
                </select>
              </div>
              <div class="form-group">
                <label>العنوان التفصيلي</label>
                <input name="address" placeholder="حي، شارع، مبنى...">
              </div>
            </div>
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">شروط التوظيف</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>عدد الموظفين المطلوبين</label>
              <input name="num_employees" placeholder="مثال: 5-10">
            </div>
            <div class="form-group">
              <label>الفئة العمرية المطلوبة</label>
              <input name="age_range" placeholder="مثال: 20-35">
            </div>
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">🔐 بيانات الدخول</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>كلمة المرور *</label>
              <input type="password" name="password" required placeholder="أدخل كلمة مرور قوية">
            </div>
            <div class="form-group">
              <label>تأكيد كلمة المرور *</label>
              <input type="password" name="password2" required placeholder="أعد كتابة كلمة المرور">
            </div>
          </div>
        </div>

        <button type="submit" class="btn btn-gold btn-full">✅ إنشاء حساب الشركة</button>
      </form>
    </div>
    <script>
    function toggleOfficeFields(show) {{
      document.getElementById('office-fields').style.display = show ? 'block' : 'none';
      document.getElementById('card-office').classList.toggle('selected', show);
      document.getElementById('card-online').classList.toggle('selected', !show);
    }}
    toggleOfficeFields(true);
    document.getElementById('card-office').classList.add('selected');
    </script>
    """
    return render_page(content, "تسجيل صاحب عمل")

# ── REGISTER EMPLOYEE ──────────────────────────────────────
@app.route('/register/employee', methods=['GET', 'POST'])
def register_employee():
    cities_opts = "".join(f'<option value="{c}">{c}</option>' for c in SYRIAN_CITIES)

    if request.method == 'POST':
        f = request.form
        first_name = f.get('first_name','').strip()
        last_name  = f.get('last_name','').strip()
        gender     = f.get('gender','')
        age        = f.get('age','')
        nationality= f.get('nationality','').strip()
        province   = f.get('province','')
        profession = f.get('profession','').strip()
        phone      = f.get('phone','').strip()
        email      = f.get('email','').strip().lower()
        password   = f.get('password','')
        password2  = f.get('password2','')

        photo_data = None; photo_mime = None
        cv_data = None; cv_filename = None

        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename and allowed_image(photo_file.filename):
            photo_data = photo_file.read()
            photo_mime = photo_file.content_type

        cv_file = request.files.get('cv')
        if cv_file and cv_file.filename and allowed_pdf(cv_file.filename):
            cv_data = cv_file.read()
            cv_filename = secure_filename(cv_file.filename)

        if password != password2:
            flash('كلمتا المرور غير متطابقتين', 'error')
            return redirect(url_for('register_employee'))
        if not first_name or not last_name or not email or not password:
            flash('يرجى تعبئة جميع الحقول المطلوبة', 'error')
            return redirect(url_for('register_employee'))

        db = get_db()
        try:
            db.execute("""INSERT INTO employees
              (first_name,last_name,gender,age,nationality,province,profession,phone,email,password_hash,photo,photo_mime,cv_data,cv_filename)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (first_name, last_name, gender, age, nationality, province,
               profession, phone, email, hash_password(password),
               photo_data, photo_mime, cv_data, cv_filename))
            db.commit()
            row = db.execute("SELECT id FROM employees WHERE email=?", (email,)).fetchone()
            session['user_type']  = 'employee'
            session['user_id']    = row['id']
            session['user_name']  = first_name
            session['user_gender']= gender
            flash('تم إنشاء حسابك بنجاح! 🎉', 'success')
            return redirect(url_for('employee_dashboard'))
        except sqlite3.IntegrityError:
            flash('البريد الإلكتروني مسجّل مسبقاً', 'error')
        finally:
            db.close()

    content = f"""
    <div style="max-width:800px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('register')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">👨‍💼 تسجيل باحث عن عمل</h1>
      </div>

      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">البيانات الشخصية</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>الاسم الأول *</label>
              <input name="first_name" required placeholder="الاسم الأول">
            </div>
            <div class="form-group">
              <label>الاسم الثاني *</label>
              <input name="last_name" required placeholder="اسم العائلة">
            </div>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>الجنس *</label>
              <select name="gender" required>
                <option value="">-- اختر --</option>
                <option value="ذكر">ذكر</option>
                <option value="أنثى">أنثى</option>
              </select>
            </div>
            <div class="form-group">
              <label>العمر *</label>
              <input type="number" name="age" required min="16" max="70" placeholder="العمر بالسنوات">
            </div>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>الجنسية</label>
              <input name="nationality" placeholder="مثال: سوري">
            </div>
            <div class="form-group">
              <label>المحافظة</label>
              <select name="province">
                <option value="">-- اختر المحافظة --</option>
                {cities_opts}
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>المهنة / التخصص *</label>
            <input name="profession" required placeholder="مثال: مبرمج، محاسب، مهندس...">
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">بيانات التواصل</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>رقم الهاتف *</label>
              <input name="phone" required placeholder="+963 XXX XXX XXX">
            </div>
            <div class="form-group">
              <label>البريد الإلكتروني *</label>
              <input type="email" name="email" required placeholder="your@email.com">
            </div>
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">الملفات الشخصية</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>📷 صورة شخصية واضحة</label>
              <input type="file" name="photo" accept="image/*">
              <small class="text-dim">JPG, PNG, WEBP (اختياري)</small>
            </div>
            <div class="form-group">
              <label>📄 السيرة الذاتية (CV)</label>
              <input type="file" name="cv" accept=".pdf">
              <small class="text-dim">ملف PDF فقط (اختياري)</small>
            </div>
          </div>
        </div>

        <div class="card mb-3">
          <h3 class="text-gold mb-2">🔐 بيانات الدخول</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>كلمة المرور *</label>
              <input type="password" name="password" required placeholder="أدخل كلمة مرور قوية">
            </div>
            <div class="form-group">
              <label>تأكيد كلمة المرور *</label>
              <input type="password" name="password2" required placeholder="أعد كتابة كلمة المرور">
            </div>
          </div>
        </div>

        <button type="submit" class="btn btn-gold btn-full">✅ إنشاء الحساب</button>
      </form>
    </div>
    """
    return render_page(content, "تسجيل باحث عن عمل")

# ── LOGIN ──────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('email','').strip()
        password   = request.form.get('password','')
        utype      = request.form.get('user_type','employer')
        ph         = hash_password(password)

        if utype == 'admin' or identifier.lower() == 'admin abdullah':
            db = get_db()
            admin = db.execute("SELECT * FROM admin_account WHERE username=? AND password_hash=?",
                               (identifier, ph)).fetchone()
            db.close()
            if admin:
                session['user_type'] = 'admin'
                session['user_id']   = admin['id']
                session['user_name'] = admin['username']
                flash(f'أهلاً بك يا مسؤول 👑', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('بيانات الدخول غير صحيحة', 'error')
                return redirect(url_for('login'))

        db = get_db()
        if utype == 'employer':
            row = db.execute("SELECT * FROM employers WHERE (email=? OR company_name=?) AND password_hash=?",
                             (identifier, identifier, ph)).fetchone()
            if row:
                if row['is_banned']:
                    db.close()
                    return redirect(url_for('banned_page', user_type='employer', user_id=row['id']))
                session['user_type'] = 'employer'
                session['user_id']   = row['id']
                session['user_name'] = row['company_name']
                db.close()
                flash(f'أهلاً بك {row["company_name"]} 👋', 'success')
                return redirect(url_for('employer_dashboard'))
        elif utype == 'employee':
            row = db.execute("SELECT * FROM employees WHERE email=? AND password_hash=?",
                             (identifier, ph)).fetchone()
            if row:
                if row['is_banned']:
                    db.close()
                    return redirect(url_for('banned_page', user_type='employee', user_id=row['id']))
                session['user_type']  = 'employee'
                session['user_id']    = row['id']
                session['user_name']  = row['first_name']
                session['user_gender']= row['gender']
                db.close()
                flash(f'أهلاً بك {row["first_name"]} 👋', 'success')
                return redirect(url_for('employee_dashboard'))
        db.close()
        flash('البريد الإلكتروني أو كلمة المرور غير صحيحة', 'error')

    content = f"""
    <div style="max-width:480px;margin:4rem auto;padding:0 1rem">
      <div class="card">
        <div class="text-center mb-3">
          <div style="font-size:2.5rem;font-weight:900;color:var(--gold);font-family:'Cairo',sans-serif">سعدان</div>
          <div style="color:var(--text-dim);font-size:.9rem;margin-top:.3rem">تسجيل الدخول إلى حسابك</div>
        </div>

        <form method="POST">
          <div class="form-group">
            <label>نوع الحساب *</label>
            <div class="choice-group" style="margin-bottom:.5rem">
              <label class="choice-card" style="padding:.8rem">
                <input type="radio" name="user_type" value="employer" checked>
                <div style="font-size:1.3rem">🏢</div>
                <div style="font-size:.85rem;font-weight:700">صاحب عمل</div>
              </label>
              <label class="choice-card" style="padding:.8rem">
                <input type="radio" name="user_type" value="employee">
                <div style="font-size:1.3rem">👨‍💼</div>
                <div style="font-size:.85rem;font-weight:700">باحث عن عمل</div>
              </label>
              <label class="choice-card" style="padding:.8rem">
                <input type="radio" name="user_type" value="admin">
                <div style="font-size:1.3rem">👑</div>
                <div style="font-size:.85rem;font-weight:700">الأدمن</div>
              </label>
            </div>
          </div>
          <div class="form-group">
            <label>اسم المستخدم / البريد / اسم الشركة *</label>
            <input type="text" name="email" required placeholder="أدخل اسم المستخدم أو البريد">
          </div>
          <div class="form-group">
            <label>كلمة المرور *</label>
            <input type="password" name="password" required placeholder="كلمة المرور">
          </div>
          <button type="submit" class="btn btn-gold btn-full">🔐 تسجيل الدخول</button>
        </form>

        <hr class="divider">
        <p class="text-center text-dim" style="font-size:.9rem">
          ليس لديك حساب؟ <a href="{url_for('register')}" style="color:var(--gold)">إنشاء حساب جديد</a>
        </p>
      </div>
    </div>
    <script>
    document.querySelectorAll('.choice-card').forEach(card => {{
      card.addEventListener('click', () => {{
        const radio = card.querySelector('input');
        if(radio) {{
          radio.checked = true;
          document.querySelectorAll('.choice-card').forEach(c => c.classList.remove('selected'));
          card.classList.add('selected');
        }}
      }});
    }});
    document.querySelector('.choice-card').classList.add('selected');
    </script>
    """
    return render_page(content, "تسجيل الدخول")

# ── LOGOUT ─────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('تم تسجيل الخروج بنجاح', 'info')
    return redirect(url_for('index'))

# ── صفحة الحظر ─────────────────────────────────────────────
@app.route('/banned/<user_type>/<int:user_id>')
def banned_page(user_type, user_id):
    if user_type not in ('employer', 'employee'):
        abort(404)

    db = get_db()
    if user_type == 'employer':
        row = db.execute("SELECT company_name, is_banned FROM employers WHERE id=?", (user_id,)).fetchone()
        display_name = row['company_name'] if row else ''
        gender_word = 'عزيزي'
    else:
        row = db.execute("SELECT first_name, last_name, gender, is_banned FROM employees WHERE id=?", (user_id,)).fetchone()
        display_name = f"{row['first_name']} {row['last_name']}" if row else ''
        gender_word = 'عزيزتي' if row and row['gender'] == 'أنثى' else 'عزيزي'
    db.close()

    if not row or not row['is_banned']:
        return redirect(url_for('login'))

    return render_template_string(f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>تم حظر الحساب - سعدان</title>
  <style>
  {BASE_STYLE}
  .ban-page {{
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 2rem 1rem;
    background:
      radial-gradient(ellipse 60% 50% at 50% 20%, rgba(192,57,43,.08) 0%, transparent 70%),
      var(--black);
  }}
  .ban-card {{
    max-width: 520px; width: 100%;
    background: var(--card);
    border: 1px solid var(--danger);
    border-radius: 18px;
    padding: 2.5rem 2rem;
    text-align: center;
    box-shadow: 0 10px 50px rgba(192,57,43,.15);
    animation: pageFadeIn .4s ease;
  }}
  .ban-icon {{ font-size: 4rem; margin-bottom: 1rem; }}
  .ban-title {{ color: var(--danger); font-size: 1.6rem; font-weight: 900; margin-bottom: 1rem; }}
  .ban-text {{ color: var(--text); font-size: 1.05rem; line-height: 2.1; margin-bottom: 1.5rem; }}
  .ban-contact {{ background: var(--card2); border: 1px solid var(--gold-dim); border-radius: 10px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }}
  .ban-contact p {{ color: var(--gold); font-size: 1rem; font-weight: 700; margin-bottom: .3rem; }}
  .ban-contact span {{ color: var(--orange-lt); font-size: 1.3rem; font-weight: 900; letter-spacing: 1px; direction: ltr; display: inline-block; }}
  .ban-brand {{ color: var(--gold); font-weight: 900; font-size: 1.4rem; }}
  </style>
</head>
<body>
  <div class="ban-page">
    <div class="ban-card">
      <div class="ban-icon">🚫</div>
      <div class="ban-title">تم حظر هذا الحساب</div>
      <div class="ban-text">
        {gender_word} <strong style="color:var(--gold)">{display_name}</strong>،<br>
        لقد تم حظرك من قبل المشرفين على هذا الموقع.
      </div>
      <div class="ban-contact">
        <p>📞 يمكنك الاتصال بخدمة العملاء على الرقم:</p>
        <span>0986555105</span>
      </div>
      <div class="ban-text" style="font-size:.95rem;color:var(--text-dim)">شكراً على تعاونكم 🙏</div>
      <div class="golden-line" style="margin:1.5rem auto"></div>
      <div class="ban-brand">سعدان <span style="color:var(--orange);font-size:1rem">| Saadan</span></div>
    </div>
  </div>
</body>
</html>""")

# ════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ════════════════════════════════════════════════════════════

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    emp_count    = db.execute("SELECT COUNT(*) FROM employers").fetchone()[0]
    worker_count = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    job_count    = db.execute("SELECT COUNT(*) FROM job_ads").fetchone()[0]
    app_count    = db.execute("SELECT COUNT(*) FROM applications").fetchone()[0]
    admin        = db.execute("SELECT * FROM admin_account WHERE id=?", (session['user_id'],)).fetchone()
    db.close()

    admin_photo_html = f'<img src="{url_for("admin_photo")}" class="profile-avatar" alt="صورة الأدمن">' \
                       if admin['photo'] else '<div class="profile-avatar-placeholder">👑</div>'

    content = f"""
    <div style="max-width:1100px;margin:2rem auto;padding:0 1rem">
      <div class="profile-header">
        {admin_photo_html}
        <div>
          <div class="profile-name" style="color:#da70d6">👑 {admin['username']}</div>
          <div class="profile-role">مسؤول النظام | لوحة التحكم الكاملة</div>
          {f'<div class="text-dim" style="font-size:.85rem">📧 {admin["email"]}</div>' if admin['email'] else ''}
          {f'<div class="text-dim" style="font-size:.85rem">📞 {admin["phone"]}</div>' if admin['phone'] else ''}
        </div>
        <div style="margin-right:auto">
          <a href="{url_for('admin_edit_profile')}" class="btn btn-outline btn-sm">⚙️ تعديل الملف الشخصي</a>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem">
        <div class="admin-stat-card">
          <div class="admin-stat-num">{emp_count}</div>
          <div class="admin-stat-label">🏢 شركة مسجّلة</div>
        </div>
        <div class="admin-stat-card">
          <div class="admin-stat-num">{worker_count}</div>
          <div class="admin-stat-label">👨‍💼 باحث عن عمل</div>
        </div>
        <div class="admin-stat-card">
          <div class="admin-stat-num">{job_count}</div>
          <div class="admin-stat-label">💼 إعلان وظيفي</div>
        </div>
        <div class="admin-stat-card">
          <div class="admin-stat-num">{app_count}</div>
          <div class="admin-stat-label">📨 طلب تقديم</div>
        </div>
      </div>

      <div class="grid-2" style="margin-bottom:2rem">
        <a href="{url_for('admin_employers')}" class="card" style="text-decoration:none;display:block;text-align:center;padding:2rem">
          <div style="font-size:3rem">🏢</div>
          <div class="text-gold" style="font-size:1.2rem;font-weight:700;margin-top:.5rem">إدارة الشركات</div>
          <div class="text-dim" style="font-size:.85rem;margin-top:.3rem">عرض بيانات جميع أصحاب العمل</div>
        </a>
        <a href="{url_for('admin_employees')}" class="card" style="text-decoration:none;display:block;text-align:center;padding:2rem">
          <div style="font-size:3rem">👨‍💼</div>
          <div class="text-gold" style="font-size:1.2rem;font-weight:700;margin-top:.5rem">إدارة الموظفين</div>
          <div class="text-dim" style="font-size:.85rem;margin-top:.3rem">عرض بيانات جميع الباحثين عن عمل</div>
        </a>
        <a href="{url_for('admin_jobs')}" class="card" style="text-decoration:none;display:block;text-align:center;padding:2rem">
          <div style="font-size:3rem">💼</div>
          <div class="text-gold" style="font-size:1.2rem;font-weight:700;margin-top:.5rem">إعلانات التوظيف</div>
          <div class="text-dim" style="font-size:.85rem;margin-top:.3rem">عرض جميع إعلانات فرص العمل</div>
        </a>
        <a href="{url_for('admin_applications')}" class="card" style="text-decoration:none;display:block;text-align:center;padding:2rem">
          <div style="font-size:3rem">📨</div>
          <div class="text-gold" style="font-size:1.2rem;font-weight:700;margin-top:.5rem">طلبات التقديم</div>
          <div class="text-dim" style="font-size:.85rem;margin-top:.3rem">عرض جميع طلبات التقديم على الوظائف</div>
        </a>
        <a href="{url_for('admin_developers')}" class="card" style="text-decoration:none;display:block;text-align:center;padding:2rem">
          <div style="font-size:3rem">👨‍💻</div>
          <div class="text-gold" style="font-size:1.2rem;font-weight:700;margin-top:.5rem">التعديل على بيانات المطورين</div>
          <div class="text-dim" style="font-size:.85rem;margin-top:.3rem">إضافة أو تعديل أو إزالة أعضاء فريق المطورين</div>
        </a>
      </div>
    </div>
    """
    return render_page(content, "لوحة تحكم الأدمن - سعدان")

@app.route('/admin/edit-profile', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_profile():
    db = get_db()
    admin = db.execute("SELECT * FROM admin_account WHERE id=?", (session['user_id'],)).fetchone()

    if request.method == 'POST':
        f = request.form
        username   = f.get('username','').strip()
        email      = f.get('email','').strip()
        phone      = f.get('phone','').strip()
        new_pass   = f.get('new_password','')
        new_pass2  = f.get('new_password2','')
        remove_photo = f.get('remove_photo') == '1'

        pw_hash = admin['password_hash']
        if new_pass:
            if new_pass != new_pass2:
                flash('كلمتا المرور غير متطابقتين', 'error')
                db.close()
                return redirect(url_for('admin_edit_profile'))
            pw_hash = hash_password(new_pass)

        photo_data = admin['photo']
        photo_mime = admin['photo_mime']

        if remove_photo:
            photo_data = None
            photo_mime = None

        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename and allowed_image(photo_file.filename):
            photo_data = photo_file.read()
            photo_mime = photo_file.content_type

        if not username:
            flash('اسم المستخدم مطلوب', 'error')
            db.close()
            return redirect(url_for('admin_edit_profile'))

        try:
            db.execute("""UPDATE admin_account SET
                username=?, email=?, phone=?, password_hash=?, photo=?, photo_mime=?
                WHERE id=?""",
                (username, email, phone, pw_hash, photo_data, photo_mime, session['user_id']))
            db.commit()
            session['user_name'] = username
            flash('تم تحديث الملف الشخصي بنجاح ✅', 'success')
        except sqlite3.IntegrityError:
            flash('اسم المستخدم مستخدم مسبقاً', 'error')
        finally:
            db.close()
        return redirect(url_for('admin_dashboard'))

    db.close()
    admin_photo_html = f'<img src="{url_for("admin_photo")}" class="profile-avatar" alt="صورة">' \
                       if admin['photo'] else '<div class="profile-avatar-placeholder">👑</div>'

    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">⚙️ تعديل الملف الشخصي</h1>
      </div>
      <div class="text-center mb-3">{admin_photo_html}</div>
      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">بيانات الحساب</h3>
          <div class="form-group">
            <label>اسم الأدمن *</label>
            <input name="username" value="{admin['username']}" required>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>البريد الإلكتروني</label>
              <input type="email" name="email" value="{admin['email'] or ''}">
            </div>
            <div class="form-group">
              <label>رقم الهاتف</label>
              <input name="phone" value="{admin['phone'] or ''}">
            </div>
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">📷 الصورة الشخصية</h3>
          <div class="form-group">
            <label>رفع صورة جديدة</label>
            <input type="file" name="photo" accept="image/*">
          </div>
          {'<div class="form-group"><label><input type="checkbox" name="remove_photo" value="1" style="width:auto;margin-left:.5rem"> حذف الصورة الحالية</label></div>' if admin['photo'] else ''}
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">🔐 تغيير كلمة المرور (اختياري)</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>كلمة المرور الجديدة</label>
              <input type="password" name="new_password" placeholder="اتركها فارغة إذا لم تغيّرها">
            </div>
            <div class="form-group">
              <label>تأكيد كلمة المرور</label>
              <input type="password" name="new_password2" placeholder="تأكيد كلمة المرور الجديدة">
            </div>
          </div>
        </div>
        <button type="submit" class="btn btn-gold btn-full">💾 حفظ التغييرات</button>
      </form>
    </div>
    """
    return render_page(content, "تعديل الملف الشخصي - الأدمن")

@app.route('/admin/photo')
@login_required
@admin_required
def admin_photo():
    db = get_db()
    row = db.execute("SELECT photo, photo_mime FROM admin_account WHERE id=?", (session['user_id'],)).fetchone()
    db.close()
    if not row or not row['photo']:
        abort(404)
    return app.response_class(row['photo'], mimetype=row['photo_mime'] or 'image/jpeg')

# ── إدارة المطورين ──────────────────────────────────────────
@app.route('/admin/developers')
@login_required
@admin_required
def admin_developers():
    db = get_db()
    devs = db.execute("SELECT * FROM developers ORDER BY display_order ASC, id ASC").fetchall()
    db.close()

    cards = ""
    for d in devs:
        if d['photo']:
            avatar = f'<img src="{url_for("developer_photo", dev_id=d["id"])}" class="dev-avatar" alt="{d["name"]}">'
        else:
            avatar = '<div class="dev-avatar-placeholder">👤</div>'
        cards += f"""
        <div class="dev-admin-card">
          {avatar}
          <div class="dev-name">{d['name']}</div>
          <div class="dev-role">{d['role'] or ''}</div>
          <div class="dev-admin-actions">
            <a href="{url_for('admin_edit_developer', dev_id=d['id'])}" class="btn btn-outline btn-sm">✏️ تعديل</a>
            <form method="POST" action="{url_for('admin_delete_developer', dev_id=d['id'])}" style="display:inline" onsubmit="return confirm('هل أنت متأكد من إزالة هذا المطور؟');">
              <button type="submit" class="btn btn-outline btn-sm" style="color:#e05656;border-color:#e05656">🗑️ إزالة</button>
            </form>
          </div>
        </div>
        """

    if not devs:
        cards = '<div class="dev-empty">لم تتم إضافة أي مطور حتى الآن</div>'

    content = f"""
    <div style="max-width:1000px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">👨‍💻 التعديل على بيانات المطورين</h1>
      </div>
      <div class="card mb-3">
        <h3 class="text-gold mb-2">➕ إضافة مطور جديد</h3>
        <form method="POST" action="{url_for('admin_add_developer')}" enctype="multipart/form-data">
          <div class="grid-2">
            <div class="form-group">
              <label>اسم المطور *</label>
              <input name="name" required placeholder="اسم المطور">
            </div>
            <div class="form-group">
              <label>الوظيفة / المهنة داخل الفريق</label>
              <input name="role" placeholder="مثال: مطور واجهات، مصمم، مدير المشروع...">
            </div>
          </div>
          <div class="form-group">
            <label>صورة المطور</label>
            <input type="file" name="photo" accept="image/*">
          </div>
          <button type="submit" class="btn btn-gold">➕ إضافة المطور</button>
        </form>
      </div>
      <div class="card">
        <h3 class="text-gold mb-2">👥 فريق المطورين الحالي</h3>
        <div class="dev-grid">{cards}</div>
      </div>
    </div>
    """
    return render_page(content, "إدارة المطورين - الأدمن")

@app.route('/admin/developers/add', methods=['POST'])
@login_required
@admin_required
def admin_add_developer():
    name = request.form.get('name', '').strip()
    role = request.form.get('role', '').strip()

    if not name:
        flash('اسم المطور مطلوب', 'error')
        return redirect(url_for('admin_developers'))

    photo_data = None; photo_mime = None
    photo_file = request.files.get('photo')
    if photo_file and photo_file.filename and allowed_image(photo_file.filename):
        photo_data = photo_file.read()
        photo_mime = photo_file.content_type

    db = get_db()
    max_order = db.execute("SELECT COALESCE(MAX(display_order), 0) FROM developers").fetchone()[0]
    db.execute("INSERT INTO developers (name, role, photo, photo_mime, display_order) VALUES (?, ?, ?, ?, ?)",
               (name, role, photo_data, photo_mime, max_order + 1))
    db.commit(); db.close()
    flash('تمت إضافة المطور بنجاح ✅', 'success')
    return redirect(url_for('admin_developers'))

@app.route('/admin/developers/<int:dev_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_developer(dev_id):
    db = get_db()
    dev = db.execute("SELECT * FROM developers WHERE id=?", (dev_id,)).fetchone()
    if not dev:
        db.close(); abort(404)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        role = request.form.get('role', '').strip()
        remove_photo = request.form.get('remove_photo') == '1'

        if not name:
            flash('اسم المطور مطلوب', 'error')
            db.close()
            return redirect(url_for('admin_edit_developer', dev_id=dev_id))

        photo_data = dev['photo']; photo_mime = dev['photo_mime']
        if remove_photo:
            photo_data = None; photo_mime = None

        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename and allowed_image(photo_file.filename):
            photo_data = photo_file.read()
            photo_mime = photo_file.content_type

        db.execute("UPDATE developers SET name=?, role=?, photo=?, photo_mime=? WHERE id=?",
                   (name, role, photo_data, photo_mime, dev_id))
        db.commit(); db.close()
        flash('تم تحديث بيانات المطور بنجاح ✅', 'success')
        return redirect(url_for('admin_developers'))

    db.close()
    avatar = f'<img src="{url_for("developer_photo", dev_id=dev["id"])}" class="dev-avatar" alt="{dev["name"]}">' \
             if dev['photo'] else '<div class="dev-avatar-placeholder">👤</div>'

    content = f"""
    <div style="max-width:600px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_developers')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">✏️ تعديل بيانات المطور</h1>
      </div>
      <div class="text-center mb-3">{avatar}</div>
      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <div class="form-group">
            <label>اسم المطور *</label>
            <input name="name" value="{dev['name']}" required>
          </div>
          <div class="form-group">
            <label>الوظيفة / المهنة داخل الفريق</label>
            <input name="role" value="{dev['role'] or ''}">
          </div>
          <div class="form-group">
            <label>تغيير الصورة</label>
            <input type="file" name="photo" accept="image/*">
          </div>
          {'<div class="form-group"><label><input type="checkbox" name="remove_photo" value="1" style="width:auto;margin-left:.5rem"> حذف الصورة الحالية</label></div>' if dev['photo'] else ''}
        </div>
        <button type="submit" class="btn btn-gold btn-full">💾 حفظ التغييرات</button>
      </form>
    </div>
    """
    return render_page(content, "تعديل مطور - الأدمن")

@app.route('/admin/developers/<int:dev_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_developer(dev_id):
    db = get_db()
    db.execute("DELETE FROM developers WHERE id=?", (dev_id,))
    db.commit(); db.close()
    flash('تمت إزالة المطور بنجاح ✅', 'success')
    return redirect(url_for('admin_developers'))

@app.route('/media/developer-photo/<int:dev_id>')
def developer_photo(dev_id):
    db = get_db()
    row = db.execute("SELECT photo, photo_mime FROM developers WHERE id=?", (dev_id,)).fetchone()
    db.close()
    if not row or not row['photo']:
        abort(404)
    return app.response_class(row['photo'], mimetype=row['photo_mime'] or 'image/jpeg')

@app.route('/admin/toggle-ban/<user_type>/<int:user_id>')
@login_required
@admin_required
def admin_toggle_ban(user_type, user_id):
    if user_type not in ('employer', 'employee'):
        abort(404)

    table = 'employers' if user_type == 'employer' else 'employees'
    db = get_db()
    row = db.execute(f"SELECT is_banned FROM {table} WHERE id=?", (user_id,)).fetchone()
    if not row:
        db.close()
        flash('الحساب غير موجود', 'error')
        return redirect(url_for('admin_employers' if user_type == 'employer' else 'admin_employees'))

    new_status = 0 if row['is_banned'] else 1
    db.execute(f"UPDATE {table} SET is_banned=? WHERE id=?", (new_status, user_id))
    db.commit(); db.close()

    flash('تم حظر الحساب بنجاح 🚫' if new_status else 'تم رفع الحظر عن الحساب بنجاح ✅', 'success')
    return redirect(url_for('admin_employers' if user_type == 'employer' else 'admin_employees'))

@app.route('/admin/employers')
@login_required
@admin_required
def admin_employers():
    db = get_db()
    employers = db.execute("""
        SELECT e.*, COUNT(ja.id) as job_count
        FROM employers e
        LEFT JOIN job_ads ja ON e.id = ja.employer_id
        GROUP BY e.id
        ORDER BY e.created_at DESC
    """).fetchall()
    db.close()

    rows_html = ""
    for e in employers:
        ban_btn = (f'<a href="{url_for("admin_toggle_ban", user_type="employer", user_id=e["id"])}" class="btn btn-outline btn-sm">✅ رفع الحظر</a>'
                   if e['is_banned'] else
                   f'<a href="{url_for("admin_toggle_ban", user_type="employer", user_id=e["id"])}" class="btn btn-danger btn-sm">🚫 حظر</a>')
        status_badge = '<span class="badge" style="background:rgba(192,57,43,.15);color:#e87b70;border:1px solid var(--danger)">محظور</span>' \
                       if e['is_banned'] else '<span class="badge badge-gold">نشط</span>'
        desc = e['company_desc'] or ''
        rows_html += f"""
        <tr>
          <td><strong style="color:var(--gold)">{e['company_name']}</strong></td>
          <td>{e['email']}</td>
          <td style="color:#e87b70;font-family:monospace">{e['password_hash'][:20]}...</td>
          <td>{e['phone'] or '-'}</td>
          <td>{'🌐 أونلاين' if e['is_online'] else f'📍 {e["city"] or "-"}'}</td>
          <td>{desc[:50] + '...' if len(desc) > 50 else (desc or '-')}</td>
          <td><span class="badge badge-orange">{e['job_count']} إعلان</span></td>
          <td><small>{e['created_at'][:10]}</small></td>
          <td>{status_badge}</td>
          <td>{ban_btn}</td>
        </tr>
        """

    content = f"""
    <div style="max-width:1200px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">🏢 بيانات الشركات المسجّلة</h1>
        <span class="badge badge-gold" style="margin-right:auto">{len(employers)} شركة</span>
      </div>
      {'<div class="card text-center p-3 text-dim"><p>لا توجد شركات مسجّلة بعد</p></div>' if not employers else f'''
      <div class="card" style="overflow-x:auto;padding:1rem">
        <table class="data-table">
          <thead>
            <tr>
              <th>اسم الشركة</th><th>البريد الإلكتروني</th><th>كلمة المرور (مشفّرة)</th>
              <th>الهاتف</th><th>الموقع</th><th>الوصف</th><th>الإعلانات</th>
              <th>تاريخ التسجيل</th><th>الحالة</th><th>إجراء</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      '''}
    </div>
    """
    return render_page(content, "إدارة الشركات - الأدمن")

@app.route('/admin/employees')
@login_required
@admin_required
def admin_employees():
    db = get_db()
    workers = db.execute("""
        SELECT e.*, COUNT(ap.id) as app_count
        FROM employees e
        LEFT JOIN applications ap ON e.id = ap.employee_id
        GROUP BY e.id
        ORDER BY e.created_at DESC
    """).fetchall()
    db.close()

    rows_html = ""
    for w in workers:
        photo_html = f'<img src="{url_for("employee_photo", emp_id=w["id"])}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;border:1px solid var(--gold-dim)">' \
                      if w['photo'] else '<span style="font-size:1.5rem">👤</span>'
        ban_btn = (f'<a href="{url_for("admin_toggle_ban", user_type="employee", user_id=w["id"])}" class="btn btn-outline btn-sm">✅ رفع الحظر</a>'
                   if w['is_banned'] else
                   f'<a href="{url_for("admin_toggle_ban", user_type="employee", user_id=w["id"])}" class="btn btn-danger btn-sm">🚫 حظر</a>')
        status_badge = '<span class="badge" style="background:rgba(192,57,43,.15);color:#e87b70;border:1px solid var(--danger)">محظور</span>' \
                       if w['is_banned'] else '<span class="badge badge-gold">نشط</span>'
        rows_html += f"""
        <tr>
          <td>{photo_html}</td>
          <td><strong style="color:var(--gold)">{w['first_name']} {w['last_name']}</strong><br><small>{w['gender']}</small></td>
          <td>{w['email']}</td>
          <td style="color:#e87b70;font-family:monospace">{w['password_hash'][:20]}...</td>
          <td>{w['phone'] or '-'}</td>
          <td>{w['province'] or '-'}</td>
          <td>{w['profession'] or '-'}</td>
          <td>{w['age'] or '-'}</td>
          <td>{w['nationality'] or '-'}</td>
          <td><span class="badge badge-orange">{w['app_count']} طلب</span></td>
          <td><small>{w['created_at'][:10]}</small></td>
          <td>{status_badge}</td>
          <td>{ban_btn}</td>
        </tr>
        """

    content = f"""
    <div style="max-width:1400px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">👨‍💼 بيانات الباحثين عن عمل</h1>
        <span class="badge badge-gold" style="margin-right:auto">{len(workers)} موظف</span>
      </div>
      {'<div class="card text-center p-3 text-dim"><p>لا يوجد باحثون عن عمل بعد</p></div>' if not workers else f'''
      <div class="card" style="overflow-x:auto;padding:1rem">
        <table class="data-table">
          <thead>
            <tr>
              <th>الصورة</th><th>الاسم الكامل</th><th>البريد الإلكتروني</th>
              <th>كلمة المرور (مشفّرة)</th><th>الهاتف</th><th>المحافظة</th>
              <th>المهنة</th><th>العمر</th><th>الجنسية</th>
              <th>الطلبات</th><th>تاريخ التسجيل</th><th>الحالة</th><th>إجراء</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      '''}
    </div>
    """
    return render_page(content, "إدارة الموظفين - الأدمن")

@app.route('/admin/jobs')
@login_required
@admin_required
def admin_jobs():
    db = get_db()
    jobs = db.execute("""
        SELECT ja.*, er.company_name, COUNT(ap.id) as app_count
        FROM job_ads ja
        JOIN employers er ON ja.employer_id = er.id
        LEFT JOIN applications ap ON ja.id = ap.job_ad_id
        GROUP BY ja.id
        ORDER BY ja.created_at DESC
    """).fetchall()
    db.close()

    rows_html = ""
    for j in jobs:
        # ✅ الإصلاح: استخدام get_col بدلاً من .get()
        cat = get_col(j, 'category', '')
        cat_badge = f'<span class="badge badge-category mt-1">{cat}</span><br>' if cat else ''
        desc = get_col(j, 'description', '')
        reqs = get_col(j, 'requirements', '')
        rows_html += f"""
        <tr>
          <td>
            <strong style="color:var(--gold)">{j['title']}</strong><br>
            {cat_badge}
          </td>
          <td style="color:var(--orange-lt)">{j['company_name']}</td>
          <td>{desc[:60] + '...' if len(desc) > 60 else (desc or '-')}</td>
          <td>{reqs[:50] + '...' if len(reqs) > 50 else (reqs or '-')}</td>
          <td><span class="badge badge-orange">{j['app_count']} متقدم</span></td>
          <td><small>{j['created_at'][:10]}</small></td>
        </tr>
        """

    content = f"""
    <div style="max-width:1200px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">💼 جميع إعلانات التوظيف</h1>
        <span class="badge badge-gold" style="margin-right:auto">{len(jobs)} إعلان</span>
      </div>
      {'<div class="card text-center p-3 text-dim"><p>لا توجد إعلانات بعد</p></div>' if not jobs else f'''
      <div class="card" style="overflow-x:auto;padding:1rem">
        <table class="data-table">
          <thead>
            <tr>
              <th>عنوان الوظيفة والتصنيف</th><th>الشركة</th><th>الوصف</th>
              <th>المتطلبات</th><th>عدد المتقدمين</th><th>تاريخ النشر</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      '''}
    </div>
    """
    return render_page(content, "إعلانات التوظيف - الأدمن")

@app.route('/admin/applications')
@login_required
@admin_required
def admin_applications():
    db = get_db()
    apps = db.execute("""
        SELECT ap.*,
               e.first_name, e.last_name, e.email as emp_email, e.phone as emp_phone,
               ja.title as job_title, er.company_name
        FROM applications ap
        JOIN employees e ON ap.employee_id = e.id
        JOIN job_ads ja ON ap.job_ad_id = ja.id
        JOIN employers er ON ja.employer_id = er.id
        ORDER BY ap.applied_at DESC
    """).fetchall()
    db.close()

    rows_html = ""
    for a in apps:
        extra = get_col(a, 'extra_info', '')
        rows_html += f"""
        <tr>
          <td><strong style="color:var(--gold)">{a['first_name']} {a['last_name']}</strong></td>
          <td>{a['emp_email']}</td>
          <td>{a['emp_phone'] or '-'}</td>
          <td style="color:var(--orange-lt)">{a['job_title']}</td>
          <td>{a['company_name']}</td>
          <td>{extra[:50] if extra else '-'}</td>
          <td><small>{a['applied_at'][:10]}</small></td>
        </tr>
        """

    content = f"""
    <div style="max-width:1200px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('admin_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">📨 جميع طلبات التقديم</h1>
        <span class="badge badge-gold" style="margin-right:auto">{len(apps)} طلب</span>
      </div>
      {'<div class="card text-center p-3 text-dim"><p>لا توجد طلبات تقديم بعد</p></div>' if not apps else f'''
      <div class="card" style="overflow-x:auto;padding:1rem">
        <table class="data-table">
          <thead>
            <tr>
              <th>اسم المتقدم</th><th>البريد الإلكتروني</th><th>الهاتف</th>
              <th>الوظيفة</th><th>الشركة</th><th>معلومات إضافية</th><th>تاريخ التقديم</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
      </div>
      '''}
    </div>
    """
    return render_page(content, "طلبات التقديم - الأدمن")

# ════════════════════════════════════════════════════════════
#  EMPLOYER ROUTES
# ════════════════════════════════════════════════════════════

@app.route('/employer/dashboard')
@login_required
@employer_required
def employer_dashboard():
    db = get_db()
    emp = db.execute("SELECT * FROM employers WHERE id=?", (session['user_id'],)).fetchone()
    ads = db.execute("""
        SELECT ja.*, COUNT(ap.id) as app_count
        FROM job_ads ja
        LEFT JOIN applications ap ON ja.id = ap.job_ad_id
        WHERE ja.employer_id=?
        GROUP BY ja.id
        ORDER BY ja.created_at DESC
    """, (session['user_id'],)).fetchall()
    db.close()

    ads_html = ""
    for ad in ads:
        # ✅ الإصلاح: استخدام get_col بدلاً من ad.get()
        cat = get_col(ad, 'category', '')
        category_badge = f'<span class="badge badge-category">{cat}</span>' if cat else ''
        ads_html += f"""
        <div class="job-card mb-3">
          <div class="job-card-header">
            <div class="icon-circle">💼</div>
            <div style="flex:1">
              <div style="font-size:1.1rem;font-weight:700;color:var(--gold)">{ad['title']}</div>
              {category_badge}
              <div class="text-dim" style="font-size:.85rem;margin-top:.2rem">📅 {ad['created_at'][:10]}</div>
            </div>
            <div>
              <span class="badge badge-orange">👥 {ad['app_count']} متقدم</span>
            </div>
          </div>
          <p class="text-dim" style="font-size:.9rem;margin-bottom:1rem">{(get_col(ad,'description',''))[:150]}...</p>
          <div class="d-flex gap-2 flex-wrap">
            <a href="{url_for('view_applicants', ad_id=ad['id'])}" class="btn btn-orange btn-sm">👁️ عرض المتقدمين</a>
            <a href="{url_for('edit_job_ad', ad_id=ad['id'])}" class="btn btn-outline btn-sm">✏️ تعديل</a>
            <a href="{url_for('delete_job_ad', ad_id=ad['id'])}" class="btn btn-danger btn-sm"
               onclick="return confirm('هل أنت متأكد من حذف هذا الإعلان؟')">🗑️ حذف</a>
          </div>
        </div>
        """

    content = f"""
    <div style="max-width:1000px;margin:2rem auto;padding:0 1rem">
      <div class="profile-header">
        <div class="profile-avatar-placeholder">🏢</div>
        <div>
          <div class="profile-name">{emp['company_name']}</div>
          <div class="profile-role">{'🌐 شركة أونلاين' if emp['is_online'] else f"🏙️ {emp['city'] or 'مقر رسمي'}"}</div>
        </div>
        <div style="margin-right:auto;display:flex;gap:.8rem">
          <a href="{url_for('create_job_ad')}" class="btn btn-orange">➕ إنشاء إعلان عمل</a>
          <a href="{url_for('edit_employer')}" class="btn btn-outline btn-sm">⚙️ تعديل البيانات</a>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <h3 class="text-gold mb-2">📋 معلومات الشركة</h3>
          <p style="color:var(--text-dim);font-size:.9rem;line-height:1.7">{emp['company_desc'] or 'لا يوجد وصف'}</p>
          <hr class="divider">
          <div style="font-size:.85rem;color:var(--text-dim)">
            {'<p>📧 ' + emp['email'] + '</p>' if emp['email'] else ''}
            {'<p>📞 ' + emp['phone'] + '</p>' if emp['phone'] else ''}
            {'<p>📍 ' + (emp['city'] or '') + ' - ' + (emp['address'] or '') + '</p>' if not emp['is_online'] else '<p>🌐 عمل أونلاين</p>'}
          </div>
        </div>
        <div class="card">
          <h3 class="text-gold mb-2">📊 إحصاءات الشركة</h3>
          <div class="stat-box" style="padding:.8rem">
            <div class="stat-num">{len(ads)}</div>
            <div class="stat-label">إعلان نشط</div>
          </div>
          <div class="stat-box mt-2" style="padding:.8rem">
            <div class="stat-num">{sum(a['app_count'] for a in ads)}</div>
            <div class="stat-label">إجمالي المتقدمين</div>
          </div>
        </div>
      </div>

      <hr class="golden-line">
      <h2 class="section-title">💼 إعلانات التوظيف</h2>
      {'<div class="card text-center text-dim p-3"><p style="font-size:1.1rem">لا توجد إعلانات بعد</p><a href="' + url_for("create_job_ad") + '" class="btn btn-orange mt-2">إنشاء أول إعلان</a></div>' if not ads else ads_html}
    </div>
    """
    return render_page(content, f"{emp['company_name']} - لوحة التحكم")

@app.route('/employer/create-ad', methods=['GET', 'POST'])
@login_required
@employer_required
def create_job_ad():
    db = get_db()
    emp = db.execute("SELECT * FROM employers WHERE id=?", (session['user_id'],)).fetchone()

    if request.method == 'POST':
        title    = request.form.get('title','').strip()
        category = request.form.get('category','').strip()
        desc     = request.form.get('description','').strip()
        reqs     = request.form.get('requirements','').strip()

        if not title:
            flash('عنوان الإعلان مطلوب', 'error')
        else:
            db.execute("INSERT INTO job_ads (employer_id,title,category,description,requirements) VALUES (?,?,?,?,?)",
                       (session['user_id'], title, category, desc, reqs))
            db.commit(); db.close()
            flash('تم نشر إعلان التوظيف بنجاح! 🎉', 'success')
            return redirect(url_for('employer_dashboard'))

    db.close()
    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('employer_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">➕ إنشاء إعلان توظيف</h1>
      </div>
      <div class="card">
        <form method="POST">
          <div class="form-group">
            <label>عنوان الوظيفة *</label>
            <input name="title" required placeholder="مثال: مطلوب مبرمج ويب">
          </div>
          <div class="form-group">
            <label>القسم / التصنيف</label>
            <input name="category" placeholder="مثال: تقنية معلومات، تصميم، تسويق، مبيعات...">
          </div>
          <div class="form-group">
            <label>🏢 اسم الشركة</label>
            <input value="{emp['company_name']}" disabled style="opacity:.6">
          </div>
          {'<div class="form-group"><label>📍 موقع الشركة</label><input value="' + (emp['city'] or 'أونلاين') + '" disabled style="opacity:.6"></div>' if not emp['is_online'] else '<div class="form-group"><label>🌐 طبيعة العمل</label><input value="عمل أونلاين" disabled style="opacity:.6"></div>'}
          <div class="form-group">
            <label>📝 وصف الشركة ومتطلبات التوظيف</label>
            <textarea name="description" placeholder="اكتب وصفاً شاملاً للشركة والوظيفة المطلوبة...">{emp['company_desc'] or ''}</textarea>
          </div>
          <div class="form-group">
            <label>📋 شروط ومتطلبات الوظيفة</label>
            <textarea name="requirements" placeholder="مثال: خبرة 2 سنة، إجادة Python، العمر بين 22-35..."></textarea>
          </div>
          <button type="submit" class="btn btn-gold btn-full">🚀 نشر الإعلان</button>
        </form>
      </div>
    </div>
    """
    return render_page(content, "إنشاء إعلان توظيف")

@app.route('/employer/edit-ad/<int:ad_id>', methods=['GET', 'POST'])
@login_required
@employer_required
def edit_job_ad(ad_id):
    db = get_db()
    ad = db.execute("SELECT * FROM job_ads WHERE id=? AND employer_id=?",
                    (ad_id, session['user_id'])).fetchone()
    if not ad:
        db.close(); abort(404)

    if request.method == 'POST':
        title    = request.form.get('title','').strip()
        category = request.form.get('category','').strip()
        desc     = request.form.get('description','').strip()
        reqs     = request.form.get('requirements','').strip()
        db.execute("UPDATE job_ads SET title=?, category=?, description=?, requirements=?, updated_at=datetime('now') WHERE id=?",
                    (title, category, desc, reqs, ad_id))
        db.commit(); db.close()
        flash('تم تحديث الإعلان بنجاح ✅', 'success')
        return redirect(url_for('employer_dashboard'))

    db.close()
    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('employer_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">✏️ تعديل إعلان التوظيف</h1>
      </div>
      <div class="card">
        <form method="POST">
          <div class="form-group">
            <label>عنوان الوظيفة *</label>
            <input name="title" required value="{ad['title']}">
          </div>
          <div class="form-group">
            <label>القسم / التصنيف</label>
            <input name="category" value="{get_col(ad,'category','')}" placeholder="أضف تصنيف الوظيفة">
          </div>
          <div class="form-group">
            <label>وصف الوظيفة</label>
            <textarea name="description">{get_col(ad,'description','')}</textarea>
          </div>
          <div class="form-group">
            <label>المتطلبات</label>
            <textarea name="requirements">{get_col(ad,'requirements','')}</textarea>
          </div>
          <button type="submit" class="btn btn-gold btn-full">💾 حفظ التغييرات</button>
        </form>
      </div>
    </div>
    """
    return render_page(content, "تعديل الإعلان")

@app.route('/employer/delete-ad/<int:ad_id>')
@login_required
@employer_required
def delete_job_ad(ad_id):
    db = get_db()
    db.execute("DELETE FROM job_ads WHERE id=? AND employer_id=?", (ad_id, session['user_id']))
    db.commit(); db.close()
    flash('تم حذف الإعلان بنجاح', 'info')
    return redirect(url_for('employer_dashboard'))

@app.route('/employer/applicants/<int:ad_id>')
@login_required
@employer_required
def view_applicants(ad_id):
    db = get_db()
    ad = db.execute("SELECT * FROM job_ads WHERE id=? AND employer_id=?",
                    (ad_id, session['user_id'])).fetchone()
    if not ad: db.close(); abort(404)

    apps = db.execute("""
        SELECT ap.*, e.first_name, e.last_name, e.gender, e.age, e.nationality,
               e.province, e.profession, e.phone, e.email as emp_email,
               e.photo, e.photo_mime, e.cv_filename, ap.cv_filename as app_cv_fn
        FROM applications ap
        JOIN employees e ON ap.employee_id = e.id
        WHERE ap.job_ad_id=?
        ORDER BY ap.applied_at DESC
    """, (ad_id,)).fetchall()
    db.close()

    rows_html = ""
    for a in apps:
        photo_html = f'<img src="{url_for("employee_photo", emp_id=a["employee_id"])}" class="applicant-avatar" alt="صورة">' \
                     if a['photo'] else '<div class="applicant-avatar-placeholder">👤</div>'
        gender_title = 'السيد' if a['gender'] != 'أنثى' else 'السيدة'
        cv_btn = f'<a href="{url_for("serve_app_cv", app_id=a["id"])}" class="btn btn-outline btn-sm" target="_blank">📄 CV</a>' \
                 if get_col(a,'app_cv_fn','') or a['cv_filename'] else ''
        extra = get_col(a, 'extra_info', '')

        rows_html += f"""
        <div class="applicant-row">
          {photo_html}
          <div style="flex:1">
            <div style="font-weight:700;color:var(--gold)">{gender_title} {a['first_name']} {a['last_name']}</div>
            <div class="text-dim" style="font-size:.82rem">
              🎂 {a['age']} سنة &nbsp;|&nbsp; 💼 {a['profession']} &nbsp;|&nbsp; 📍 {a['province'] or '-'}
            </div>
            <div class="text-dim" style="font-size:.82rem">
              📞 {a['phone'] or '-'} &nbsp;|&nbsp; 📧 {a['emp_email'] or '-'}
            </div>
            {f'<div class="text-dim" style="font-size:.82rem;margin-top:.3rem">🌍 الجنسية: {a["nationality"]}</div>' if a["nationality"] else ''}
            {f'<div class="text-dim" style="font-size:.82rem;margin-top:.3rem">💬 {extra}</div>' if extra else ''}
          </div>
          <div class="d-flex gap-2">
            {cv_btn}
            <a href="{url_for('delete_applicant', app_id=a['id'], ad_id=ad_id)}" class="btn btn-danger btn-sm"
               onclick="return confirm('حذف هذا المتقدم؟')">🗑️</a>
          </div>
        </div>
        """

    content = f"""
    <div style="max-width:900px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('employer_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <div>
          <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">👥 المتقدمون</h1>
          <div class="text-dim" style="font-size:.9rem">إعلان: {ad['title']}</div>
        </div>
        <span class="badge badge-orange" style="margin-right:auto">{len(apps)} متقدم</span>
      </div>
      {'<div class="card text-center p-3 text-dim"><p>لم يتقدم أحد على هذا الإعلان بعد</p></div>' if not apps else rows_html}
    </div>
    """
    return render_page(content, "المتقدمون على الإعلان")

@app.route('/employer/delete-applicant/<int:app_id>/<int:ad_id>')
@login_required
@employer_required
def delete_applicant(app_id, ad_id):
    db = get_db()
    ad = db.execute("SELECT id FROM job_ads WHERE id=? AND employer_id=?",
                    (ad_id, session['user_id'])).fetchone()
    if ad:
        db.execute("DELETE FROM applications WHERE id=? AND job_ad_id=?", (app_id, ad_id))
        db.commit()
        flash('تم حذف الطلب', 'info')
    db.close()
    return redirect(url_for('view_applicants', ad_id=ad_id))

@app.route('/employer/edit', methods=['GET', 'POST'])
@login_required
@employer_required
def edit_employer():
    db = get_db()
    emp = db.execute("SELECT * FROM employers WHERE id=?", (session['user_id'],)).fetchone()
    cities_opts = "".join(
        f'<option value="{c}" {"selected" if c == (emp["city"] or "") else ""}>{c}</option>'
        for c in SYRIAN_CITIES)

    if request.method == 'POST':
        f = request.form
        company_desc  = f.get('company_desc','').strip()
        phone         = f.get('phone','').strip()
        email         = f.get('email','').strip().lower()
        is_online     = f.get('work_type') == 'online'
        address       = f.get('address','').strip()
        city          = f.get('city','')
        num_employees = f.get('num_employees','').strip()
        age_range     = f.get('age_range','').strip()
        new_pass      = f.get('new_password','')
        new_pass2     = f.get('new_password2','')

        pw_hash = emp['password_hash']
        if new_pass:
            if new_pass != new_pass2:
                flash('كلمتا المرور غير متطابقتين', 'error')
                db.close()
                return redirect(url_for('edit_employer'))
            pw_hash = hash_password(new_pass)

        db.execute("""UPDATE employers SET
            company_desc=?, phone=?, email=?, is_online=?, address=?,
            city=?, num_employees=?, age_range=?, password_hash=?
            WHERE id=?""",
            (company_desc, phone, email, 1 if is_online else 0,
             address, city, num_employees, age_range, pw_hash,
             session['user_id']))
        db.commit(); db.close()
        flash('تم تحديث بيانات الشركة بنجاح ✅', 'success')
        return redirect(url_for('employer_dashboard'))

    db.close()
    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('employer_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">⚙️ تعديل بيانات الشركة</h1>
      </div>
      <form method="POST">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">بيانات الشركة</h3>
          <div class="form-group">
            <label>وصف الشركة</label>
            <textarea name="company_desc">{emp['company_desc'] or ''}</textarea>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>رقم الهاتف</label>
              <input name="phone" value="{emp['phone'] or ''}">
            </div>
            <div class="form-group">
              <label>البريد الإلكتروني</label>
              <input type="email" name="email" value="{emp['email'] or ''}">
            </div>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>عدد الموظفين</label>
              <input name="num_employees" value="{emp['num_employees'] or ''}">
            </div>
            <div class="form-group">
              <label>الفئة العمرية</label>
              <input name="age_range" value="{emp['age_range'] or ''}">
            </div>
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">موقع الشركة</h3>
          <div class="form-group">
            <label>نوع العمل</label>
            <select name="work_type">
              <option value="online" {"selected" if emp['is_online'] else ""}>أونلاين</option>
              <option value="office" {"selected" if not emp['is_online'] else ""}>مقر رسمي</option>
            </select>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>المدينة</label>
              <select name="city">
                <option value="">-- اختر --</option>
                {cities_opts}
              </select>
            </div>
            <div class="form-group">
              <label>العنوان</label>
              <input name="address" value="{emp['address'] or ''}">
            </div>
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">🔐 تغيير كلمة المرور (اختياري)</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>كلمة المرور الجديدة</label>
              <input type="password" name="new_password" placeholder="اتركه فارغاً إذا لم تغيّره">
            </div>
            <div class="form-group">
              <label>تأكيد كلمة المرور</label>
              <input type="password" name="new_password2" placeholder="تأكيد كلمة المرور الجديدة">
            </div>
          </div>
        </div>
        <button type="submit" class="btn btn-gold btn-full">💾 حفظ التغييرات</button>
      </form>
    </div>
    """
    return render_page(content, "تعديل بيانات الشركة")

# ════════════════════════════════════════════════════════════
#  EMPLOYEE ROUTES
# ════════════════════════════════════════════════════════════

@app.route('/employee/dashboard')
@login_required
@employee_required
def employee_dashboard():
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE id=?", (session['user_id'],)).fetchone()
    my_apps = db.execute("""
        SELECT ap.*, ja.title as job_title, er.company_name
        FROM applications ap
        JOIN job_ads ja ON ap.job_ad_id = ja.id
        JOIN employers er ON ja.employer_id = er.id
        WHERE ap.employee_id=?
        ORDER BY ap.applied_at DESC
    """, (session['user_id'],)).fetchall()
    db.close()

    gender_title = 'السيدة' if emp['gender'] == 'أنثى' else 'السيد'
    photo_html = f'<img src="{url_for("employee_photo", emp_id=emp["id"])}" class="profile-avatar" alt="صورة">' \
                 if emp['photo'] else '<div class="profile-avatar-placeholder">👤</div>'

    apps_html = ""
    for a in my_apps:
        apps_html += f"""
        <div class="applicant-row">
          <div class="icon-circle">💼</div>
          <div style="flex:1">
            <div style="font-weight:700;color:var(--gold)">{a['job_title']}</div>
            <div class="text-dim" style="font-size:.82rem">🏢 {a['company_name']} | 📅 {a['applied_at'][:10]}</div>
          </div>
          <span class="badge badge-gold">تم التقديم ✅</span>
        </div>
        """

    content = f"""
    <div style="max-width:900px;margin:2rem auto;padding:0 1rem">
      <div class="profile-header">
        {photo_html}
        <div>
          <div class="profile-name">أهلاً {gender_title} {emp['first_name']} {emp['last_name']}</div>
          <div class="profile-role">💼 {emp['profession'] or 'لم يحدد'} &nbsp;|&nbsp; 📍 {emp['province'] or '-'}</div>
        </div>
        <div style="margin-right:auto;display:flex;gap:.8rem">
          <a href="{url_for('job_listings')}" class="btn btn-orange">🔍 تصفح الوظائف</a>
          <a href="{url_for('edit_employee')}" class="btn btn-outline btn-sm">⚙️ تعديل الملف</a>
        </div>
      </div>

      <div class="card mb-3">
        <h3 class="text-gold mb-2">🔍 ابحث عن وظيفة</h3>
        <form action="{url_for('job_listings')}" method="GET" class="search-form" style="margin:0;border-radius:12px;padding:0.8rem 1.2rem;">
          <input type="text" name="q" placeholder="ابحث عن الوظيفة..." class="search-input">
          <div class="search-divider"></div>
          <input type="text" name="category" placeholder="القسم/التصنيف" class="search-input">
          <button type="submit" class="btn btn-gold btn-sm">🔍 بحث</button>
        </form>
      </div>

      <div class="grid-2">
        <div class="card">
          <h3 class="text-gold mb-2">👤 البيانات الشخصية</h3>
          <div style="font-size:.9rem;line-height:2;color:var(--text-dim)">
            <p>🎂 العمر: <span style="color:var(--text)">{emp['age'] or '-'} سنة</span></p>
            <p>🌍 الجنسية: <span style="color:var(--text)">{emp['nationality'] or '-'}</span></p>
            <p>📍 المحافظة: <span style="color:var(--text)">{emp['province'] or '-'}</span></p>
            <p>💼 المهنة: <span style="color:var(--text)">{emp['profession'] or '-'}</span></p>
            <p>📞 الهاتف: <span style="color:var(--text)">{emp['phone'] or '-'}</span></p>
            <p>📧 البريد: <span style="color:var(--text)">{emp['email']}</span></p>
            {'<p>📄 السيرة الذاتية: <a href="' + url_for("serve_employee_cv", emp_id=emp["id"]) + '" target="_blank" style="color:var(--gold)">تحميل CV</a></p>' if emp['cv_data'] else ''}
          </div>
        </div>
        <div class="card">
          <h3 class="text-gold mb-2">📊 إحصاءاتي</h3>
          <div class="stat-box">
            <div class="stat-num">{len(my_apps)}</div>
            <div class="stat-label">طلب مقدَّم</div>
          </div>
        </div>
      </div>

      <hr class="golden-line">
      <h2 class="section-title">📋 طلباتي</h2>
      {'<div class="card text-center p-3 text-dim"><p>لم تتقدم على أي وظيفة بعد</p><a href="' + url_for("job_listings") + '" class="btn btn-orange mt-2">تصفح الوظائف</a></div>' if not my_apps else apps_html}
    </div>
    """
    return render_page(content, f"ملف {emp['first_name']}")

@app.route('/employee/edit', methods=['GET', 'POST'])
@login_required
@employee_required
def edit_employee():
    db = get_db()
    emp = db.execute("SELECT * FROM employees WHERE id=?", (session['user_id'],)).fetchone()
    cities_opts = "".join(
        f'<option value="{c}" {"selected" if c == (emp["province"] or "") else ""}>{c}</option>'
        for c in SYRIAN_CITIES)

    if request.method == 'POST':
        f = request.form
        first_name  = f.get('first_name','').strip()
        last_name   = f.get('last_name','').strip()
        gender      = f.get('gender','')
        age         = f.get('age','')
        nationality = f.get('nationality','').strip()
        province    = f.get('province','')
        profession  = f.get('profession','').strip()
        phone       = f.get('phone','').strip()
        email       = f.get('email','').strip().lower()
        new_pass    = f.get('new_password','')
        new_pass2   = f.get('new_password2','')
        remove_photo= f.get('remove_photo') == '1'

        pw_hash    = emp['password_hash']
        photo_data = emp['photo']; photo_mime = emp['photo_mime']
        cv_data    = emp['cv_data']; cv_filename = emp['cv_filename']

        if remove_photo:
            photo_data = None; photo_mime = None

        photo_file = request.files.get('photo')
        if photo_file and photo_file.filename and allowed_image(photo_file.filename):
            photo_data = photo_file.read()
            photo_mime = photo_file.content_type

        cv_file = request.files.get('cv')
        if cv_file and cv_file.filename and allowed_pdf(cv_file.filename):
            cv_data = cv_file.read()
            cv_filename = secure_filename(cv_file.filename)

        if new_pass:
            if new_pass != new_pass2:
                flash('كلمتا المرور غير متطابقتين', 'error')
                db.close()
                return redirect(url_for('edit_employee'))
            pw_hash = hash_password(new_pass)

        db.execute("""UPDATE employees SET
            first_name=?, last_name=?, gender=?, age=?, nationality=?,
            province=?, profession=?, phone=?, email=?,
            password_hash=?, photo=?, photo_mime=?, cv_data=?, cv_filename=?
            WHERE id=?""",
            (first_name, last_name, gender, age, nationality,
             province, profession, phone, email,
             pw_hash, photo_data, photo_mime, cv_data, cv_filename,
             session['user_id']))
        db.commit()
        session['user_name']   = first_name
        session['user_gender'] = gender
        db.close()
        flash('تم تحديث بياناتك بنجاح ✅', 'success')
        return redirect(url_for('employee_dashboard'))

    db.close()
    content = f"""
    <div style="max-width:700px;margin:3rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('employee_dashboard')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">⚙️ تعديل بياناتي</h1>
      </div>
      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">البيانات الشخصية</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>الاسم الأول</label>
              <input name="first_name" value="{emp['first_name']}">
            </div>
            <div class="form-group">
              <label>الاسم الثاني</label>
              <input name="last_name" value="{emp['last_name']}">
            </div>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>الجنس</label>
              <select name="gender">
                <option value="ذكر" {"selected" if emp['gender']=='ذكر' else ""}>ذكر</option>
                <option value="أنثى" {"selected" if emp['gender']=='أنثى' else ""}>أنثى</option>
              </select>
            </div>
            <div class="form-group">
              <label>العمر</label>
              <input type="number" name="age" value="{emp['age'] or ''}">
            </div>
          </div>
          <div class="grid-2">
            <div class="form-group">
              <label>الجنسية</label>
              <input name="nationality" value="{emp['nationality'] or ''}">
            </div>
            <div class="form-group">
              <label>المحافظة</label>
              <select name="province">
                <option value="">-- اختر --</option>
                {cities_opts}
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>المهنة</label>
            <input name="profession" value="{emp['profession'] or ''}">
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">بيانات التواصل</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>رقم الهاتف</label>
              <input name="phone" value="{emp['phone'] or ''}">
            </div>
            <div class="form-group">
              <label>البريد الإلكتروني</label>
              <input type="email" name="email" value="{emp['email']}">
            </div>
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">تحديث الملفات</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>📷 صورة شخصية جديدة</label>
              <input type="file" name="photo" accept="image/*">
              <small class="text-dim">اتركها فارغة للإبقاء على الحالية</small>
              {'<label style="margin-top:.5rem"><input type="checkbox" name="remove_photo" value="1" style="width:auto;margin-left:.5rem"> حذف الصورة الحالية</label>' if emp['photo'] else ''}
            </div>
            <div class="form-group">
              <label>📄 CV جديد (PDF)</label>
              <input type="file" name="cv" accept=".pdf">
              <small class="text-dim">اتركها فارغة للإبقاء على الحالي</small>
            </div>
          </div>
        </div>
        <div class="card mb-3">
          <h3 class="text-gold mb-2">🔐 تغيير كلمة المرور (اختياري)</h3>
          <div class="grid-2">
            <div class="form-group">
              <label>كلمة المرور الجديدة</label>
              <input type="password" name="new_password" placeholder="اتركها فارغة إذا لم تغيّرها">
            </div>
            <div class="form-group">
              <label>تأكيد كلمة المرور</label>
              <input type="password" name="new_password2" placeholder="تأكيد كلمة المرور الجديدة">
            </div>
          </div>
        </div>
        <button type="submit" class="btn btn-gold btn-full">💾 حفظ التغييرات</button>
      </form>
    </div>
    """
    return render_page(content, "تعديل بياناتي")

# ════════════════════════════════════════════════════════════
#  JOB LISTINGS & APPLY
# ════════════════════════════════════════════════════════════

@app.route('/jobs')
def job_listings():
    # الزوار غير المسجلين يُحوَّلون لصفحة تسجيل الدخول
    if not session.get('user_type'):
        content = f"""
    <div style="max-width:520px;margin:5rem auto;padding:0 1rem;text-align:center">
      <div style="font-size:4rem;margin-bottom:1rem">🔐</div>
      <h1 style="color:var(--gold);font-size:1.8rem;margin-bottom:.8rem">تصفح فرص العمل</h1>
      <p style="color:var(--text-dim);font-size:1rem;line-height:1.9;margin-bottom:1.5rem">
        للاطلاع على جميع الوظائف المتاحة والتقديم عليها<br>
        <strong style="color:var(--gold)">يجب أن يكون لديك حساب</strong> في منصة سعدان
      </p>
      <div class="card" style="padding:1.5rem">
        <div style="display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;margin-bottom:1rem">
          <a href="{url_for('login')}" class="btn btn-gold" style="min-width:150px;font-size:1rem">
            🔑 تسجيل الدخول
          </a>
          <a href="{url_for('register')}" class="btn btn-orange" style="min-width:150px;font-size:1rem">
            ✨ إنشاء حساب جديد
          </a>
        </div>
        <p class="text-dim" style="font-size:.85rem">التسجيل مجاني ويستغرق دقيقة واحدة فقط</p>
      </div>
      <a href="{url_for('index')}" class="btn btn-outline mt-3" style="font-size:.9rem">🏠 العودة للرئيسية</a>
    </div>
    """
        return render_page(content, "تصفح الوظائف - سعدان")

    db = get_db()

    search_q   = request.args.get('q', '').strip()
    search_cat = request.args.get('category', '').strip()

    query = """
        SELECT ja.*, er.company_name, er.company_desc, er.phone,
               er.email as emp_email, er.is_online, er.city, er.address
        FROM job_ads ja
        JOIN employers er ON ja.employer_id = er.id
        WHERE 1=1
    """
    params = []

    if search_q:
        query += " AND (ja.title LIKE ? OR ja.description LIKE ? OR ja.requirements LIKE ? OR er.company_name LIKE ? OR ja.category LIKE ?)"
        params.extend([f"%{search_q}%", f"%{search_q}%", f"%{search_q}%", f"%{search_q}%", f"%{search_q}%"])

    if search_cat:
        query += " AND (ja.category LIKE ? OR ja.title LIKE ? OR ja.description LIKE ?)"
        params.extend([f"%{search_cat}%", f"%{search_cat}%", f"%{search_cat}%"])

    query += " ORDER BY ja.created_at DESC"

    ads = db.execute(query, params).fetchall()
    db.close()

    cards = ""
    for ad in ads:
        location = "🌐 أونلاين" if ad['is_online'] else f"📍 {ad['city'] or 'غير محدد'}"
        apply_btn = ""
        if session.get('user_type') == 'employee':
            apply_btn = f'<a href="{url_for("apply_job", ad_id=ad["id"])}" class="btn btn-orange btn-sm">📨 التقديم على الوظيفة</a>'
        elif not session.get('user_type'):
            apply_btn = f'<a href="{url_for("login")}" class="btn btn-outline btn-sm">🔐 سجّل للتقديم</a>'

        # ✅ الإصلاح: استخدام get_col بدلاً من ad.get()
        cat = get_col(ad, 'category', '')
        category_badge = f'<span class="badge badge-category mt-1">{cat}</span>' if cat else ''
        desc = get_col(ad, 'description', '')
        comp_desc = get_col(ad, 'company_desc', '')
        reqs = get_col(ad, 'requirements', '')

        cards += f"""
        <div class="job-card">
          <div class="job-card-header">
            <div class="icon-circle">🏢</div>
            <div style="flex:1">
              <div style="font-size:1.1rem;font-weight:700;color:var(--gold)">{ad['title']}</div>
              <div style="color:var(--orange-lt);font-weight:600;font-size:.9rem">{ad['company_name']}</div>
              {category_badge}
              <div class="text-dim mt-1" style="font-size:.8rem">{location} &nbsp;|&nbsp; 📅 {ad['created_at'][:10]}</div>
            </div>
          </div>
          <p class="text-dim" style="font-size:.9rem;line-height:1.7;margin-bottom:.8rem">
            {comp_desc[:200]}
          </p>
          {'<div style="background:var(--card2);border-radius:8px;padding:.8rem;margin-bottom:.8rem"><p style="font-size:.85rem;color:var(--text);line-height:1.7"><strong style="color:var(--gold)">📋 المتطلبات:</strong><br>' + reqs + '</p></div>' if reqs else ''}
          <div style="font-size:.82rem;color:var(--text-dim);margin-bottom:1rem">
            {'📞 ' + ad['phone'] if ad['phone'] else ''} &nbsp; {'📧 ' + ad['emp_email'] if ad['emp_email'] else ''}
          </div>
          {apply_btn}
        </div>
        """

    is_logged_in = session.get('user_type') in ('employee', 'employer', 'admin')
    
    if is_logged_in:
        search_form_html = f"""
      <form action="{url_for('job_listings')}" method="GET" class="search-form mb-3">
        <input type="text" name="q" value="{search_q}" placeholder="ابحث عن الوظيفة..." class="search-input">
        <div class="search-divider"></div>
        <input type="text" name="category" value="{search_cat}" placeholder="القسم/التصنيف" class="search-input">
        <button type="submit" class="btn btn-gold btn-sm">🔍 بحث وتصفية</button>
      </form>"""
    else:
        search_form_html = """
      <div class="search-form mb-3" style="cursor:pointer" onclick="openLoginRequiredModal()">
        <input type="text" placeholder="ابحث عن الوظيفة..." class="search-input"
               onfocus="this.blur();openLoginRequiredModal()" style="cursor:pointer">
        <div class="search-divider"></div>
        <input type="text" placeholder="القسم/التصنيف" class="search-input"
               onfocus="this.blur();openLoginRequiredModal()" style="cursor:pointer">
        <button type="button" class="btn btn-gold btn-sm" onclick="openLoginRequiredModal()">🔍 بحث وتصفية</button>
      </div>"""

    content = f"""
    <div style="max-width:900px;margin:2rem auto;padding:0 1rem">
      <h1 class="section-title">🔍 فرص العمل المتاحة</h1>

      {search_form_html}

      <p class="text-dim mb-3">{len(ads)} فرصة عمل مطابقة</p>
      {'<div class="card text-center p-3 text-dim"><p style="font-size:1.1rem">لا توجد وظائف مطابقة لبحثك</p><p class="mt-1">حاول استخدام كلمات بحث مختلفة</p></div>' if not ads else '<div style="display:flex;flex-direction:column;gap:1.2rem">' + cards + '</div>'}
    </div>
    """
    return render_page(content, "فرص العمل - سعدان")

@app.route('/jobs/apply/<int:ad_id>', methods=['GET', 'POST'])
@login_required
@employee_required
def apply_job(ad_id):
    db = get_db()
    ad = db.execute("""
        SELECT ja.*, er.company_name, er.phone as comp_phone, er.email as comp_email,
               er.is_online, er.city, er.address, er.company_desc
        FROM job_ads ja
        JOIN employers er ON ja.employer_id = er.id
        WHERE ja.id=?
    """, (ad_id,)).fetchone()
    if not ad: db.close(); abort(404)

    emp = db.execute("SELECT * FROM employees WHERE id=?", (session['user_id'],)).fetchone()
    already = db.execute("SELECT id FROM applications WHERE job_ad_id=? AND employee_id=?",
                         (ad_id, session['user_id'])).fetchone()

    if request.method == 'POST':
        if already:
            flash('لقد تقدمت على هذه الوظيفة مسبقاً', 'error')
            db.close()
            return redirect(url_for('job_listings'))

        extra = request.form.get('extra_info','').strip()
        cv_data = emp['cv_data']; cv_filename = emp['cv_filename']

        cv_file = request.files.get('cv')
        if cv_file and cv_file.filename and allowed_pdf(cv_file.filename):
            cv_data = cv_file.read()
            cv_filename = secure_filename(cv_file.filename)

        db.execute("INSERT INTO applications (job_ad_id, employee_id, extra_info, cv_data, cv_filename) VALUES (?,?,?,?,?)",
            (ad_id, session['user_id'], extra, cv_data, cv_filename))
        db.commit(); db.close()
        return redirect(url_for('apply_success'))

    db.close()
    gender_title = 'السيدة' if emp['gender'] == 'أنثى' else 'السيد'
    photo_html = f'<img src="{url_for("employee_photo", emp_id=emp["id"])}" class="profile-avatar" alt="صورة">' \
                 if emp['photo'] else '<div class="profile-avatar-placeholder">👤</div>'

    comp_desc = get_col(ad, 'company_desc', '')
    reqs = get_col(ad, 'requirements', '')

    content = f"""
    <div style="max-width:800px;margin:2rem auto;padding:0 1rem">
      <div class="d-flex align-center gap-2 mb-3">
        <a href="{url_for('job_listings')}" class="btn btn-outline btn-sm">← رجوع</a>
        <h1 class="section-title" style="margin-bottom:0;border-bottom:none;padding-bottom:0">📨 التقديم على الوظيفة</h1>
      </div>

      <div class="card mb-3">
        <div class="d-flex align-center gap-2">
          <div class="icon-circle">🏢</div>
          <div>
            <div style="font-size:1.1rem;font-weight:700;color:var(--gold)">{ad['title']}</div>
            <div style="color:var(--orange-lt)">{ad['company_name']}</div>
            <div class="text-dim" style="font-size:.85rem">
              {'🌐 أونلاين' if ad['is_online'] else '📍 ' + (ad['city'] or '') + ' ' + (ad['address'] or '')}
            </div>
          </div>
        </div>
        <hr class="divider">
        <p class="text-dim" style="font-size:.9rem;line-height:1.7">{comp_desc}</p>
        {'<p style="font-size:.85rem;color:var(--text-dim);margin-top:.5rem">📋 المتطلبات: ' + reqs + '</p>' if reqs else ''}
        <div style="font-size:.82rem;color:var(--text-dim);margin-top:.5rem">
          {'📞 ' + ad['comp_phone'] if ad['comp_phone'] else ''} {'📧 ' + ad['comp_email'] if ad['comp_email'] else ''}
        </div>
      </div>

      {'<div class="card text-center p-3" style="border-color:var(--gold-dim)"><p style="color:var(--gold);font-size:1rem">⚠️ لقد تقدمت على هذه الوظيفة مسبقاً</p></div>' if already else f"""
      <div class="card mb-3">
        <h3 class="text-gold mb-2">📋 بيانات المتقدم</h3>
        <div class="d-flex align-center gap-2 mb-2">
          {photo_html}
          <div>
            <div style="font-weight:700;color:var(--gold)">{gender_title} {emp['first_name']} {emp['last_name']}</div>
            <div class="text-dim" style="font-size:.85rem">{emp['profession'] or '-'}</div>
          </div>
        </div>
        <div style="font-size:.85rem;color:var(--text-dim);line-height:2">
          <p>🎂 العمر: {emp['age'] or '-'} سنة</p>
          <p>🌍 الجنسية: {emp['nationality'] or '-'}</p>
          <p>📍 المحافظة: {emp['province'] or '-'}</p>
          <p>📞 الهاتف: {emp['phone'] or '-'}</p>
          <p>📧 البريد: {emp['email']}</p>
          <p>💼 الخبرة: {emp['profession'] or '-'}</p>
        </div>
      </div>

      <form method="POST" enctype="multipart/form-data">
        <div class="card mb-3">
          <h3 class="text-gold mb-2">📄 السيرة الذاتية</h3>
          <div class="form-group">
            <label>رفع ملف CV (اختياري - سيُستخدم ملفك المحفوظ إذا لم ترفع جديداً)</label>
            <input type="file" name="cv" accept=".pdf">
            {"<small class='text-dim'>لديك CV محفوظ: " + (emp['cv_filename'] or '') + "</small>" if emp['cv_data'] else ""}
          </div>
          <div class="form-group">
            <label>معلومات إضافية (اختياري)</label>
            <textarea name="extra_info" placeholder="أضف أي معلومات تريد إطلاع صاحب العمل عليها..."></textarea>
          </div>
        </div>
        <button type="submit" class="btn btn-orange btn-full">🚀 إرسال الطلب</button>
      </form>
      """}
    </div>
    """
    return render_page(content, "التقديم على وظيفة")

@app.route('/apply/success')
def apply_success():
    content = f"""
    <div style="max-width:600px;margin:5rem auto;padding:0 1rem;text-align:center">
      <div style="font-size:4rem;margin-bottom:1.5rem">🎉</div>
      <h1 style="color:var(--gold);font-size:2rem;margin-bottom:1rem">شكراً لك على التقديم!</h1>
      <div class="card">
        <p style="font-size:1.1rem;line-height:1.9;color:var(--text)">
          سيقوم صاحب العمل بدراسة ملفك والتواصل معك في أقرب وقت ممكن.
        </p>
        <p class="text-dim mt-2" style="font-size:.9rem">
          تابع بريدك الإلكتروني ورقم هاتفك للتواصل
        </p>
      </div>
      <div class="d-flex gap-2 justify-between mt-3" style="flex-wrap:wrap;justify-content:center">
        <a href="{url_for('job_listings')}" class="btn btn-gold">🔍 تصفح وظائف أخرى</a>
        <a href="{url_for('employee_dashboard')}" class="btn btn-outline">👤 ملفي الشخصي</a>
      </div>
    </div>
    """
    return render_page(content, "تم التقديم بنجاح")

# ════════════════════════════════════════════════════════════
#  MEDIA ROUTES
# ════════════════════════════════════════════════════════════

@app.route('/media/employee-photo/<int:emp_id>')
def employee_photo(emp_id):
    db = get_db()
    row = db.execute("SELECT photo, photo_mime FROM employees WHERE id=?", (emp_id,)).fetchone()
    db.close()
    if not row or not row['photo']:
        abort(404)
    return app.response_class(row['photo'], mimetype=row['photo_mime'] or 'image/jpeg')

@app.route('/media/employee-cv/<int:emp_id>')
def serve_employee_cv(emp_id):
    db = get_db()
    row = db.execute("SELECT cv_data, cv_filename FROM employees WHERE id=?", (emp_id,)).fetchone()
    db.close()
    if not row or not row['cv_data']:
        abort(404)
    resp = app.response_class(row['cv_data'], mimetype='application/pdf')
    resp.headers['Content-Disposition'] = f'inline; filename="{row["cv_filename"] or "cv.pdf"}"'
    return resp

@app.route('/media/application-cv/<int:app_id>')
@login_required
@employer_required
def serve_app_cv(app_id):
    db = get_db()
    row = db.execute("""
        SELECT ap.cv_data, ap.cv_filename, e.cv_data as emp_cv, e.cv_filename as emp_cv_fn
        FROM applications ap
        JOIN job_ads ja ON ap.job_ad_id = ja.id
        JOIN employees e ON ap.employee_id = e.id
        WHERE ap.id=? AND ja.employer_id=?
    """, (app_id, session['user_id'])).fetchone()
    db.close()
    if not row: abort(404)
    cv = row['cv_data'] or row['emp_cv']
    fn = row['cv_filename'] or row['emp_cv_fn'] or 'cv.pdf'
    if not cv: abort(404)
    resp = app.response_class(cv, mimetype='application/pdf')
    resp.headers['Content-Disposition'] = f'inline; filename="{fn}"'
    return resp

# ── 404 ─────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    content = """
    <div style="max-width:500px;margin:5rem auto;text-align:center;padding:0 1rem">
      <div style="font-size:4rem">🔍</div>
      <h1 style="color:var(--gold);font-size:2rem;margin:1rem 0">الصفحة غير موجودة</h1>
      <p class="text-dim">الصفحة التي تبحث عنها غير متوفرة</p>
      <a href="/" class="btn btn-gold mt-3">🏠 العودة للرئيسية</a>
    </div>
    """
    return render_page(content, "404 - غير موجود"), 404

if __name__ == '__main__':
    print("Server saadan is running successfully on http://127.0.0.1:5000")
    app.run(debug=True)
