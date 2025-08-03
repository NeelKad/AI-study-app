from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from io import BytesIO
from fpdf import FPDF
from openai import OpenAI
import re
import os
import json
import certifi
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps

# SSL fix
os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Database config
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --- MODELS ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    trial_expires_at = db.Column(db.DateTime, nullable=True)
    has_unlimited_access = db.Column(db.Boolean, default=False)

    def get_id(self):
        return str(self.id)
    
    def is_trial_expired(self):
        if self.has_unlimited_access:
            return False
        if self.trial_expires_at is None:
            return True
        return datetime.utcnow() > self.trial_expires_at
    
    def get_time_remaining(self):
        if self.has_unlimited_access:
            return "Unlimited"
        if self.trial_expires_at is None:
            return "No trial expiry set"
        if self.is_trial_expired():
            return "Expired"
        remaining = self.trial_expires_at - datetime.utcnow()
        minutes = int(remaining.total_seconds() // 60)
        seconds = int(remaining.total_seconds() % 60)
        return f"{minutes}m {seconds}s"

class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    user = db.relationship('User', backref='notes')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables():
    db.create_all()

# --- DECORATOR ---
def trial_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.is_trial_expired():
            flash('Your trial has expired! Enter admin key to unlock.', 'error')
            return redirect(url_for('trial_expired'))
        return f(*args, **kwargs)
    return decorated_function

# --- AUTH ROUTES ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('signup.html')
        hashed_pw = generate_password_hash(password)
        trial_expiry = datetime.utcnow() + timedelta(minutes=10)  # 10 min trial
        new_user = User(email=email, password=hashed_pw, trial_expires_at=trial_expiry)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if user.trial_expires_at is None and not user.has_unlimited_access:
                user.trial_expires_at = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- TRIAL EXPIRED ---
@app.route('/trial-expired')
@login_required
def trial_expired():
    return render_template('trial_expired.html', user=current_user)

@app.route('/trial-expired/unlock', methods=['POST'])
@login_required
def trial_unlock():
    ADMIN_KEY = os.getenv("ADMIN_KEY", "your-secret-admin-key-here")
    entered_key = request.form.get('admin_key', '')

    if entered_key != ADMIN_KEY:
        flash('Invalid admin key!', 'error')
        return redirect(url_for('trial_expired'))

    user = current_user
    user.has_unlimited_access = True
    db.session.commit()

    flash('Unlimited access granted! Welcome back.', 'success')
    return redirect(url_for('dashboard'))

# --- ADMIN ROUTES ---
@app.route('/admin/grant-access', methods=['GET', 'POST'])
def admin_grant_access():
    ADMIN_KEY = os.getenv("ADMIN_KEY", "your-secret-admin-key-here")
    if request.method == 'POST':
        provided_key = request.form.get('admin_key')
        user_email = request.form.get('user_email')
        if provided_key != ADMIN_KEY:
            flash('Invalid admin key!', 'error')
            return render_template('admin_grant_access.html')
        user = User.query.filter_by(email=user_email).first()
        if not user:
            flash('User not found!', 'error')
            return render_template('admin_grant_access.html')
        user.has_unlimited_access = True
        db.session.commit()
        flash(f'Unlimited access granted to {user_email}!', 'success')
        return render_template('admin_grant_access.html')
    return render_template('admin_grant_access.html')

@app.route('/admin/users')
def admin_users():
    ADMIN_KEY = os.getenv("ADMIN_KEY", "your-secret-admin-key-here")
    provided_key = request.args.get('key')
    if provided_key != ADMIN_KEY:
        return "Access denied", 403
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# --- TRIAL STATUS API ---
@app.route('/api/trial-status')
@login_required
def api_trial_status():
    if current_user.has_unlimited_access:
        return jsonify({"unlimited": True, "expired": False, "time_remaining": "Unlimited", "remaining_seconds": -1})
    if current_user.is_trial_expired():
        return jsonify({"unlimited": False, "expired": True, "time_remaining": "Expired", "remaining_seconds": 0})
    if not current_user.trial_expires_at:
        return jsonify({"unlimited": False, "expired": True, "time_remaining": "No trial expiry set", "remaining_seconds": 0})
    remaining = current_user.trial_expires_at - datetime.utcnow()
    remaining_seconds = int(remaining.total_seconds())
    minutes = remaining_seconds // 60
    seconds = remaining_seconds % 60
    return jsonify({"unlimited": False, "expired": False, "time_remaining": f"{minutes}m {seconds}s", "remaining_seconds": remaining_seconds})

# --- DASHBOARD & NOTES ---
@app.route('/dashboard')
@login_required
@trial_required
def dashboard():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', notes=notes, email=current_user.email, user=current_user)

@app.route('/enter-notes')
@login_required
@trial_required
def enter_notes():
    return render_template('index.html', user=current_user)

@app.route('/add-note', methods=['POST'])
@login_required
@trial_required
def add_note():
    title = request.form.get('title')
    content = request.form.get('content')
    if not title or not content:
        flash("Please provide both title and content.", "error")
        return redirect(url_for('enter_notes'))
    note = Note(user_id=current_user.id, title=title, content=content)
    db.session.add(note)
    db.session.commit()
    flash("Note saved successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/note/<int:note_id>')
@login_required
@trial_required
def view_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if note:
        return render_template('view_note.html', title=note.title, content=note.content, note_id=note.id)
    flash("Note not found or access denied.", "error")
    return redirect(url_for('dashboard'))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

# --- STUDY TOOLS (UI) ---
@app.route('/flashcards')
@app.route('/flashcards/<int:note_id>')
@login_required
@trial_required
def flashcards(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('flashcards.html', note_content=note_content, user=current_user)

@app.route('/questions')
@app.route('/questions/<int:note_id>')
@login_required
@trial_required
def questions(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('questions.html', note_content=note_content, user=current_user)

@app.route('/summarise')
@app.route('/summarise/<int:note_id>')
@login_required
@trial_required
def summarise(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('summarise.html', note_content=note_content, user=current_user)

@app.route('/pastpaper')
@app.route('/pastpaper/<int:note_id>')
@login_required
@trial_required
def pastpaper(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('pastpaper.html', note_content=note_content, user=current_user)

@app.route('/tutor')
@app.route('/tutor/<int:note_id>')
@login_required
@trial_required
def tutor(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('tutor.html', note_content=note_content, user=current_user)

@app.route('/my-notes')
@login_required
@trial_required
def my_notes():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('my_notes.html', notes=notes)

# --- OPENAI API ROUTES ---
@app.route('/api/flashcards', methods=['POST'])
@login_required
@trial_required
def api_flashcards():
    notes = request.json.get('notes', '')
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "Generate flashcards from these notes. Output a valid JSON object where keys are terms and values are definitions."},
                {"role": "user", "content": notes}
            ],
            temperature=0.7,
            max_tokens=700
        )
        text = response.choices[0].message.content.strip()
        flashcards = json.loads(text) if text else {}
    except Exception:
        flashcards = {}
    return jsonify(flashcards)

@app.route('/api/questions', methods=['POST'])
@login_required
@trial_required
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
@trial_required
def api_grade_question():
    data = request.json
    question = data.get('question', '')
    answer = data.get('answer', '')
    prompt = (
        f"Grade this answer: '{answer}' for the question: '{question}'. "
        "Reply EXACTLY in this format:\n"
        "score: <number from 0 to 10>\n"
        "improvement: <suggestion>\n"
        "model answer: <model answer>"
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
    return jsonify({
        "grade_score": score_match.group(1) if score_match else "N/A",
        "improvement": improvement_match.group(1).strip() if improvement_match else "No suggestion.",
        "model_answer": model_answer_match.group(1).strip() if model_answer_match else "No model answer provided."
    })

@app.route('/api/summarise', methods=['POST'])
@login_required
@trial_required
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
@trial_required
def api_pastpaper():
    data = request.get_json()
    notes = data.get("notes", "")
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": f"Generate a past paper from these notes:\n{notes}. Include MCQs, True/False, short and application questions."}
        ]
    )
    past_paper = response.choices[0].message.content
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    for line in past_paper.split("\n"):
        pdf.multi_cell(0, 10, line)
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    return send_file(BytesIO(pdf_bytes), mimetype="application/pdf", as_attachment=True, download_name="past_paper.pdf")

@app.route('/api/tutor_chat', methods=['POST'])
@login_required
@trial_required
def api_tutor_chat():
    data = request.json
    user_message = data.get('message', '').strip()
    conversation = data.get('conversation', [])
    notes = data.get('notes', '')
    system_prompt = "You are a professional AI tutor."
    if notes:
        system_prompt += f"\nContext notes:\n{notes}"
    messages = [{"role": "system", "content": system_prompt}] + conversation + [{"role": "user", "content": user_message}]
    response = client.chat.completions.create(model="gpt-3.5-turbo", messages=messages, temperature=0.7, max_tokens=600)
    return jsonify({"response": response.choices[0].message.content.strip()})

if __name__ == '__main__':
    app.run(debug=True)
