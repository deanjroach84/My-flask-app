import json
import os
import socket
import threading
import uuid
import sqlite3
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash

# --- Flask app setup ---
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production')

USERS_FILE = 'users.json'
scans = {}  # Stores scan results keyed by scan_id
DB_FILE = "scan_history.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                open_ports TEXT,
                total_ports INTEGER,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()

init_db()

common_services = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
    5900: 'VNC', 8080: 'HTTP Proxy'
}

# --- User management ---
def load_users():
    try:
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        default_users = {
            'admin': generate_password_hash('admin123'),
            'dean': generate_password_hash('testpassword')
        }
        save_users(default_users)
        return default_users

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

users = load_users()

def register_user(username, password):
    if username in users:
        return False
    users[username] = generate_password_hash(password)
    save_users(users)
    return True

# --- Port scanning logic ---
def scan_ports(scan_id, target_ip, start_port, end_port, username):
    scans[scan_id] = {
        'open_ports': [],
        'total_ports': end_port - start_port + 1,
        'scanned_ports': 0,
        'done': False
    }

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                if s.connect_ex((target_ip, port)) == 0:
                    scans[scan_id]['open_ports'].append(port)
            except Exception:
                pass
            scans[scan_id]['scanned_ports'] += 1

    scans[scan_id]['done'] = True

    # Save results to database
    open_ports = scans[scan_id]['open_ports']
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO scan_history (id, username, target_ip, open_ports, total_ports, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, username, target_ip, json.dumps(open_ports), end_port, datetime.now().isoformat())
        )
        conn.commit()

def get_service_name(port):
    return common_services.get(port, "Open")

# --- Routes ---
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['user'] = username
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

# (Include other routes here exactly as in your original app)

# --- Vercel serverless handler ---
from mangum import Mangum
handler = Mangum(app)