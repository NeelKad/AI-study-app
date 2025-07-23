from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from io import BytesIO
from fpdf import FPDF
import openaikey
from openai import OpenAI
import re
import os
import json
import certifi
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)
client = OpenAI(api_key=openaikey.key())

app.secret_key = "c64421b5faabcb967d4e9ea63ac771d94dea9e4d7f0ec2444bff59f54263ae8f"

# Setup Flask-Login
login_manager = LoginManager()
login_manager.login_view = "login"  # set the login view endpoint
login_manager.init_app(app)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(id=row[0], email=row[1], password=row[2])
    return None

# Routes for authentication
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_pw))
            conn.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'error')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[2], password):
            user = User(id=row[0], email=row[1], password=row[2])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Dashboard and notes routes
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM notes WHERE user_id=?", (current_user.id,))
    notes = c.fetchall()
    conn.close()
    return render_template('dashboard.html', notes=notes, email=current_user.email)

@app.route('/enter-notes')
@login_required
def enter_notes():
    return render_template('index.html')  # your current notes page

@app.route('/add-note', methods=['POST'])
@login_required
def add_note():
    title = request.form.get('title')
    content = request.form.get('content')

    if not title or not content:
        flash("Please provide both title and content.", "error")
        return redirect(url_for('enter_notes'))

    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (current_user.id, title, content)
    )
    conn.commit()
    conn.close()

    flash("Note saved successfully!", "success")
    return redirect(url_for('dashboard'))
from flask import jsonify

@app.route('/save-note', methods=['POST'])
@login_required
def save_note():
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title or not content:
        return jsonify({"error": "Title and content are required."}), 400

    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", (current_user.id, title, content))
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("SELECT title, content FROM notes WHERE id = ? AND user_id = ?", (note_id, current_user.id))
    note = c.fetchone()
    conn.close()
    if note:
        title, content = note
        return render_template('view_note.html', title=title, content=content)
    else:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        # If logged in, send them to dashboard
        return redirect(url_for('dashboard'))
    else:
        # If not logged in, send them to login page
        return redirect(url_for('login'))

@app.route('/flashcards')
@login_required
def flashcards():
    return render_template('flashcards.html')

@app.route('/questions')
@login_required
def questions():
    return render_template('questions.html')

@app.route('/summarise')
@login_required
def summarise():
    return render_template('summarise.html')

@app.route('/pastpaper')
@login_required
def pastpaper():
    return render_template('pastpaper.html')

@app.route('/tutor')
@login_required
def tutor():
    return render_template('tutor.html')

@app.route('/my-notes')
@login_required
def my_notes():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("SELECT id, title FROM notes WHERE user_id=?", (current_user.id,))
    notes = c.fetchall()
    conn.close()
    return render_template('my_notes.html', notes=notes)

# API routes (OpenAI integration)
@app.route('/api/flashcards', methods=['POST'])
@login_required
def api_flashcards():
    notes = request.json.get('notes', '')
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Generate flashcards from these notes. "
                        "Output a valid JSON object where keys are terms (strings) and values are short string definitions only, no nested objects."
                    ),
                },
                {"role": "user", "content": notes}
            ],
            temperature=0.7,
            max_tokens=700
        )
        text = response.choices[0].message.content.strip()
        try:
            flashcards = json.loads(text)
        except json.JSONDecodeError:
            flashcards = {}
    except Exception:
        flashcards = {}
    return jsonify(flashcards)

@app.route('/api/questions', methods=['POST'])
@login_required
def api_questions():
    notes = request.json.get('notes', '')
    prompt = f"Generate 5 concise questions from these notes:\n\n{notes}"
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=500
    )
    text = response.choices[0].message.content.strip()
    questions = [q.strip() for q in text.split('\n') if q.strip()]
    return jsonify(questions)

@app.route('/api/grade_question', methods=['POST'])
@login_required
def api_grade_question():
    data = request.json
    question = data.get('question', '')
    answer = data.get('answer', '')
    notes = data.get('notes', '')
    prompt = (
        f"Grade this answer: '{answer}' for the question: '{question}'. "
        "Reply EXACTLY in this format (no extra text):\n"
        "score: <number from 0 to 10>\n"
        "improvement: <suggestion for improvement>\n"
        "model answer: <model answer>\n"
        "Do not include the score for this model answer."
    )
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=200
    )
    text = response.choices[0].message.content.strip()
    score_match = re.search(r'score:\s*([0-9]+(?:\.[0-9]+)?)', text, re.IGNORECASE)
    improvement_match = re.search(r'improvement:\s*(.*?)(?:\nmodel answer:|$)', text, re.IGNORECASE | re.DOTALL)
    model_answer_match = re.search(r'model answer:\s*(.*)', text, re.IGNORECASE | re.DOTALL)
    grade_score = score_match.group(1) if score_match else "N/A"
    improvement = improvement_match.group(1).strip() if improvement_match else "No suggestion."
    model_answer = model_answer_match.group(1).strip() if model_answer_match else "No model answer provided."
    return jsonify({
        "grade_score": grade_score,
        "improvement": improvement,
        "model_answer": model_answer
    })

@app.route('/api/summarise', methods=['POST'])
@login_required
def api_summarise():
    notes = request.json.get('notes', '')
    prompt = f"Summarize these notes into a concise paragraph:\n\n{notes}"
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=400
    )
    summary = response.choices[0].message.content.strip()
    return jsonify({"summary": summary})

@app.route("/api/pastpaper", methods=["POST"])
@login_required
def api_pastpaper():
    data = request.get_json()
    notes = data.get("notes", "")
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "user",
                "content": (
                    f"Generate a past paper based on these notes:\n{notes}. "
                    "It should be in this order: 20 multiple choice questions, 20 True and False questions, "
                    "8 short answer questions, and 8 application questions. "
                    "It should take at least 1 hour to complete. Make sure the questions are clear and concise, "
                    "and cover a range of topics from the notes provided."
                ),
            }
        ]
    )
    past_paper = response.choices[0].message.content
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in past_paper.split("\n"):
        pdf.multi_cell(0, 10, line)
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    pdf_buffer = BytesIO(pdf_bytes)
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="past_paper.pdf"
    )

@app.route('/api/tutor_chat', methods=['POST'])
@login_required
def api_tutor_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    conversation = data.get('conversation', [])
    if not user_message:
        return jsonify({"error": "Message is empty"}), 400
    notes = data.get('notes', '')
    system_prompt = (
        "You are a professional, patient, and knowledgeable AI study tutor. "
        "Use the study notes below to help the user with clear, concise explanations and answer their questions.\n\n"
        f"Study notes:\n{notes}\n\n"
        "If the notes don't contain enough info, politely say so and try to help generally."
    )
    messages = [{"role": "system", "content": system_prompt}]
    if conversation:
        messages.extend(conversation)
    messages.append({"role": "user", "content": user_message})
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.5,
            max_tokens=500
        )
        assistant_message = response.choices[0].message.content.strip()
        return jsonify({"reply": assistant_message})
    except Exception as e:
        print("Tutor Chat API error:", e)
        return jsonify({"error": "Failed to get response from AI."}), 500

# Database initialization
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    title TEXT,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    conn.commit()
    conn.close()

init_db()

if __name__ == '__main__':
    app.run(debug=True)
