# app.py
# Enhanced Flask backend for Security Screening in Crime File Management System.
# Uses SQLite for data storage, Groq for advanced AI-powered screening, agentic behavior, summaries, and chatbot.
# Serves the frontend from index.html, provides API endpoints for UI interactions.
# Agentic AI: Screens descriptions/notes, generates suggestions, summaries, risk reports; chatbot with history.
# Security: User authentication (login/signup), profile management, query screening.
# Uploads: Saves evidence files to 'uploads' folder.
# Profiles: Users can edit profile (full_name, email, role).
# Chatbot: Groq-powered chatbot with history saving per user, clear history feature.
# To run: pip install flask groq werkzeug
# Run python app.py, access http://127.0.0.1:5000

from flask import Flask, request, jsonify, session, send_from_directory, render_template
import sqlite3
from groq import Groq
import os
from werkzeug.utils import secure_filename
import json
from datetime import datetime

app = Flask(__name__, template_folder='templates')
app.secret_key = 'super_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

GROQ_API_KEY = None
CLIENT = None

def init_db():
    conn = sqlite3.connect('crime.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            full_name TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY,
            title TEXT,
            type TEXT,
            priority TEXT,
            status TEXT,
            assigned_to TEXT,
            date TEXT,
            description TEXT,
            location TEXT,
            ai_suggestions TEXT,
            ai_summary TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS screenings (
            id INTEGER PRIMARY KEY,
            name TEXT,
            type TEXT,
            level TEXT,
            status TEXT,
            screened_by TEXT,
            date TEXT,
            notes TEXT,
            ai_suggestions TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY,
            case_id INTEGER,
            type TEXT,
            filename TEXT,
            upload_date TEXT,
            uploaded_by TEXT,
            description TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            message TEXT,
            role TEXT,  -- 'user' or 'ai'
            timestamp TEXT
        )
    ''')
    try:
        c.execute("INSERT INTO users (username, password, full_name, email, role) VALUES ('admin', 'password', 'Admin User', 'admin@example.com', 'admin')")
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect('crime.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/set_api_key', methods=['POST'])
def set_api_key():
    global GROQ_API_KEY, CLIENT
    api_key = request.json.get('api_key')
    if api_key:
        GROQ_API_KEY = api_key
        CLIENT = Groq(api_key=GROQ_API_KEY)
        return jsonify({'status': 'success'})
    return jsonify({'error': 'API key required'}), 400

@app.route('/check_api_key')
def check_api_key():
    return jsonify({'set': CLIENT is not None})

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()
    if user:
        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json['username']
    password = request.json['password']
    full_name = request.json.get('full_name', '')
    email = request.json.get('email', '')
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)", (username, password, full_name, email))
        conn.commit()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        session['user_id'] = user['id']
        session['username'] = user['username']
        conn.close()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if request.method == 'POST':
        full_name = request.json.get('full_name')
        email = request.json.get('email')
        role = request.json.get('role') if session.get('role') == 'admin' else None  # Only admins can change role
        conn = get_db()
        c = conn.cursor()
        update_sql = "UPDATE users SET full_name = ?, email = ?"
        params = [full_name, email]
        if role:
            update_sql += ", role = ?"
            params.append(role)
        update_sql += " WHERE id = ?"
        params.append(session['user_id'])
        c.execute(update_sql, params)
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    else:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (session['user_id'],))
        user = c.fetchone()
        conn.close()
        return jsonify(dict(user))

@app.route('/check_login')
def check_login():
    return jsonify({'logged_in': 'user_id' in session, 'username': session.get('username', '')})

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'status': 'success'})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM cases WHERE status = 'active'")
    active = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM cases WHERE status = 'closed'")
    resolved = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM screenings")
    screenings = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM evidence")
    evidence = c.fetchone()[0]
    conn.close()
    return jsonify({
        'activeCases': active,
        'screenings': screenings,
        'resolved': resolved,
        'evidence': evidence
    })

@app.route('/api/recent_activity')
def get_recent_activity():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT title, date FROM cases ORDER BY id DESC LIMIT 5")
    rows = c.fetchall()
    activity = [{'action': 'New case created', 'details': row['title'], 'date': row['date']} for row in rows]
    conn.close()
    return jsonify(activity)

@app.route('/api/cases', methods=['GET'])
def get_cases():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    status = request.args.get('status')
    priority = request.args.get('priority')
    date = request.args.get('date')
    search = request.args.get('search')
    conn = get_db()
    c = conn.cursor()
    where = []
    params = []
    if status:
        where.append("status = ?")
        params.append(status)
    if priority:
        where.append("priority = ?")
        params.append(priority)
    if date:
        where.append("date = ?")
        params.append(date)
    if search:
        where.append("(title LIKE ? OR description LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])
    sql = "SELECT * FROM cases"
    if where:
        sql += " WHERE " + " AND ".join(where)
    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/add_case', methods=['POST'])
def add_case():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if not CLIENT:
        return jsonify({'error': 'Groq API key not set'}), 400
    data = request.json
    title = data['title']
    crime_type = data['type']
    priority = data['priority']
    status = data['status']
    assigned_to = data['assigned_to']
    date = data['date']
    description = data['description']
    location = data.get('location', '')

    # Agentic AI screening, summary, and suggestions
    prompt = f"""
    You are an advanced security screening agent for crime file management.
    Analyze the description: '{description}'.
    1. Screen for sensitive info (names, addresses) and suggest redacted version.
    2. Flag risk: low/medium/high (high if terrorism, violence).
    3. Generate a concise summary (2-3 sentences).
    4. Suggest next steps (e.g., investigate CCTV, interview witnesses).
    Output JSON: {{"redacted_description": "text", "risk_flag": "low/medium/high", "summary": "text", "suggestions": "text"}}
    """
    response = CLIENT.chat.completions.create(
        model="llama3-70b-8192",  # Upgraded model for better agentic behavior
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    ai_output = json.loads(response.choices[0].message.content)
    redacted_description = ai_output['redacted_description']
    risk_flag = ai_output['risk_flag']
    summary = ai_output['summary']
    suggestions = ai_output['suggestions']
    if risk_flag == 'high':
        return jsonify({'error': 'High risk detected, cannot add'}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO cases (title, type, priority, status, assigned_to, date, description, location, ai_summary, ai_suggestions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (title, crime_type, priority, status, assigned_to, date, redacted_description, location, summary, suggestions))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/screenings')
def get_screenings():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM screenings")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/add_screening', methods=['POST'])
def add_screening():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if not CLIENT:
        return jsonify({'error': 'Groq API key not set'}), 400
    data = request.json
    name = data['name']
    s_type = data['type']
    level = data['level']
    status = data['status']
    screened_by = data['screened_by']
    date = data['date']
    notes = data['notes']

    # Enhanced AI screening with suggestions
    prompt = f"""
    You are an advanced security agent.
    Analyze notes: '{notes}'.
    1. Redact sensitive info.
    2. Flag risk: low/medium/high.
    3. Suggest next steps.
    JSON: {{"redacted_notes": "text", "risk_flag": "low/medium/high", "suggestions": "text"}}
    """
    response = CLIENT.chat.completions.create(
        model="llama3-70b-8192",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    ai_output = json.loads(response.choices[0].message.content)
    notes = ai_output['redacted_notes']
    risk_flag = ai_output['risk_flag']
    suggestions = ai_output['suggestions']
    if risk_flag == 'high':
        return jsonify({'error': 'High risk detected'}), 403

    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO screenings (name, type, level, status, screened_by, date, notes, ai_suggestions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              (name, s_type, level, status, screened_by, date, notes, suggestions))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/api/evidence')
def get_evidence():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM evidence")
    rows = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/upload_evidence', methods=['POST'])
def upload_evidence():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    case_id = request.form['case_id']
    description = request.form['description']
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        file_type = filename.split('.')[-1]
        upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        uploaded_by = session['username']
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO evidence (case_id, type, filename, upload_date, uploaded_by, description) VALUES (?, ?, ?, ?, ?, ?)",
                  (case_id, file_type, filename, upload_date, uploaded_by, description))
        conn.commit()
        conn.close()
        return jsonify({'status': 'success'})
    return jsonify({'error': 'No file'}), 400

@app.route('/api/case_stats')
def get_case_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT type, COUNT(*) as count FROM cases GROUP BY type")
    rows = c.fetchall()
    labels = [row['type'] for row in rows if row['type']]
    values = [row['count'] for row in rows if row['type']]
    conn.close()
    return jsonify({'labels': labels, 'values': values})

@app.route('/api/monthly_trends')
def get_monthly_trends():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT strftime('%Y-%m', date) as month, COUNT(*) as count FROM cases GROUP BY month ORDER BY month")
    rows = c.fetchall()
    months = [row['month'] for row in rows if row['month']]
    counts = [row['count'] for row in rows if row['month']]
    conn.close()
    return jsonify({'months': months, 'counts': counts})

@app.route('/api/chat', methods=['POST'])
def chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if not CLIENT:
        return jsonify({'error': 'Groq API key not set'}), 400
    message = request.json['message']
    user_id = session['user_id']

    # Save user message
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO chat_history (user_id, message, role, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, message, 'user', timestamp))
    conn.commit()

    # Get history for context
    c.execute("SELECT message, role FROM chat_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (user_id,))
    history = [{"role": row['role'], "content": row['message']} for row in c.fetchall()[::-1]]

    # Agentic AI chatbot response
    prompt = "You are an advanced AI agent for crime management. Respond helpfully to the user's query, using context from history if relevant."
    messages = [{"role": "system", "content": prompt}] + history + [{"role": "user", "content": message}]
    response = CLIENT.chat.completions.create(
        model="llama3-70b-8192",
        messages=messages
    )
    ai_response = response.choices[0].message.content

    # Save AI response
    c.execute("INSERT INTO chat_history (user_id, message, role, timestamp) VALUES (?, ?, ?, ?)",
              (user_id, ai_response, 'ai', timestamp))
    conn.commit()
    conn.close()

    return jsonify({'response': ai_response})

@app.route('/api/chat_history')
def chat_history():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT message, role, timestamp FROM chat_history WHERE user_id=? ORDER BY id", (user_id,))
    rows = c.fetchall()
    conn.close()
    return jsonify([{'message': row['message'], 'role': row['role'], 'timestamp': row['timestamp']} for row in rows])

@app.route('/api/clear_chat', methods=['POST'])
def clear_chat():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM chat_history WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True)