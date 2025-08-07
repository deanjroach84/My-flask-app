import json
import os
import socket
import threading
import uuid

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')

app.secret_key = 'd0e24c18990ede4030506468331087c351d8d775d276597e7fc8035360f30059'  # Change this in production

USERS_FILE = 'users.json'

# -------- User management ---------

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

# -------- Port scanner logic ---------

scans = {}  # store scan results keyed by scan_id

def scan_ports(scan_id, target_ip, start_port, end_port):
    total_ports = end_port - start_port + 1
    scans[scan_id] = {
        'open_ports': [],
        'total_ports': total_ports,
        'scanned_ports': 0,
        'done': False
    }

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                result = s.connect_ex((target_ip, port))
                if result == 0:
                    scans[scan_id]['open_ports'].append(port)
            except Exception:
                pass
            scans[scan_id]['scanned_ports'] += 1

    scans[scan_id]['done'] = True

# Optional: simple port to service mapping for display
common_services = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP Proxy',
    # add more if you like
}

def get_service_name(port):
    return common_services.get(port, "Open")

# -------- Routes ---------

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/admin')
def admin_page():
    if 'user' not in session:
        return redirect(url_for('login'))
    return app.send_static_file('admin.html')

# --- Admin user management API ---

@app.route('/admin/users', methods=['GET'])
def admin_get_users():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(list(users.keys()))

@app.route('/admin/users', methods=['POST'])
def admin_add_user():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return "Username and password required", 400
    username = data['username'].strip()
    password = data['password']
    if not username or not password:
        return "Username and password cannot be empty", 400
    if username in users:
        return "User already exists", 400
    users[username] = generate_password_hash(password)
    save_users(users)
    return "User added", 201

@app.route('/admin/users/<username>', methods=['DELETE'])
def admin_delete_user(username):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if username not in users:
        return "User not found", 404
    del users[username]
    save_users(users)
    return '', 204

# --- Login, logout, register ---

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

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        if not username or not password:
            return render_template('register.html', error="Please fill in all fields.")
        if register_user(username, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Username already exists.")
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    global users  # important: use the global variable
    if request.method == 'POST':
        username = request.form['username'].strip()
        new_password = request.form['new_password']

        if username not in users:
            flash('Username not found.', 'danger')
            return redirect(url_for('forgot_password'))

        hashed_pw = generate_password_hash(new_password)

        # Update the global users dict in memory
        users[username] = hashed_pw

        # Save updated users to file
        save_users(users)

        flash('Password updated successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')



# --- Port scanning endpoints ---

@app.route('/start_scan', methods=['POST'])
def start_scan():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or request.form
    target_ip = data.get('ip') or data.get('target_ip')
    ports = data.get('ports')

    try:
        start_port = 1
        end_port = 100  # default

        if ports is not None:
            ports = int(ports)
            end_port = ports if ports > 0 else 100

    except Exception:
        return jsonify({'error': 'Invalid ports parameter'}), 400

    if not target_ip:
        return jsonify({'error': 'No target IP provided'}), 400

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        'open_ports': [],
        'total_ports': end_port - start_port + 1,
        'scanned_ports': 0,
        'done': False
    }

    thread = threading.Thread(target=scan_ports, args=(scan_id, target_ip, start_port, end_port))
    thread.start()

    return jsonify({'scan_id': scan_id})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if scan_id not in scans:
        return jsonify({'error': 'Scan ID not found'}), 404

    scan = scans[scan_id]

    total = scan.get('total_ports', 1)
    scanned = scan.get('scanned_ports', 0)
    progress = int((scanned / total) * 100) if total > 0 else 0

    results = [[port, get_service_name(port)] for port in scan['open_ports']]

    return jsonify({
        'progress': progress,
        'done': scan.get('done', False),
        'results': results
    })

@app.route('/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    # Optional: implement a way to stop the scan thread (complex, so just clear)
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if scan_id in scans:
        scans.pop(scan_id)
        return jsonify({'message': 'Scan stopped.'})

    return jsonify({'error': 'Scan ID not found'}), 404
