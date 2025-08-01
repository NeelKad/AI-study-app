from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session
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

# Fix SSL cert issue with openai on some platforms
os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)

# Secret key for session cookies — set this securely in your environment!
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Use DATABASE_URL env var or fallback to sqlite local file for testing
# Database configuration for Render deployment
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # Render sometimes provides postgres:// but SQLAlchemy needs postgresql://
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    # Fallback to SQLite for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialize OpenAI client with your API key from environment
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

    def get_id(self):
        return str(self.id)

# Note model
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

# --- Auth routes ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('signup.html')
        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
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
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Dashboard & Notes ---

@app.route('/dashboard')
@login_required
def dashboard():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', notes=notes, email=current_user.email)

@app.route('/enter-notes')
@login_required
def enter_notes():
    return render_template('index.html')

@app.route('/add-note', methods=['POST'])
@login_required
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

@app.route('/save-note', methods=['POST'])
@login_required
def save_note():
    data = request.get_json()
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not title or not content:
        return jsonify({"error": "Title and content are required."}), 400

    note = Note(user_id=current_user.id, title=title, content=content)
    db.session.add(note)
    db.session.commit()

    return jsonify({"success": True})

@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if note:
        return render_template('view_note.html', title=note.title, content=note.content, note_id=note.id)
    else:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

# --- Modified Study Tool Routes to Accept Note ID ---

@app.route('/flashcards')
@app.route('/flashcards/<int:note_id>')
@login_required
def flashcards(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('flashcards.html', note_content=note_content)

@app.route('/questions')
@app.route('/questions/<int:note_id>')
@login_required
def questions(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('questions.html', note_content=note_content)

@app.route('/summarise')
@app.route('/summarise/<int:note_id>')
@login_required
def summarise(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('summarise.html', note_content=note_content)

@app.route('/pastpaper')
@app.route('/pastpaper/<int:note_id>')
@login_required
def pastpaper(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('pastpaper.html', note_content=note_content)

@app.route('/tutor')
@app.route('/tutor/<int:note_id>')
@login_required
def tutor(note_id=None):
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    return render_template('tutor.html', note_content=note_content)

@app.route('/my-notes')
@login_required
def my_notes():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('my_notes.html', notes=notes)

# --- OpenAI API Routes ---

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
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        user_message = data.get('message', '').strip()
        conversation = data.get('conversation', [])
        notes = data.get('notes', '')
        
        if not user_message:
            return jsonify({"error": "Message is empty"}), 400

        # Build the system prompt
        system_prompt = (
            "You are a professional, patient, and knowledgeable AI study tutor. "
            "You help students understand concepts, answer questions, and provide clear explanations. "
        )
        
        if notes:
            system_prompt += (
                f"Use the study notes below to help the user with accurate information:\n\n"
                f"Study notes:\n{notes}\n\n"
                "Base your answers on these notes when relevant, but you can also provide general knowledge to help explain concepts."
            )
        else:
            system_prompt += (
                "The user doesn't have specific study notes loaded, so help them with general study questions "
                "and provide clear, educational explanations."
            )

        # Prepare messages for OpenAI
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add conversation history (limit to last 10 exchanges to avoid token limits)
        if conversation:
            recent_conversation = conversation[-20:]  # Last 20 messages (10 exchanges)
            messages.extend(recent_conversation)
        
        # Add current user message
        messages.append({"role": "user", "content": user_message})

        # Make API call to OpenAI
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  # Using gpt-3.5-turbo instead of gpt-4o-mini for reliability
            messages=messages,
            temperature=0.7,
            max_tokens=500,
            timeout=30  # Add timeout
        )
        
        assistant_message = response.choices[0].message.content.strip()
        
        if not assistant_message:
            return jsonify({"error": "Empty response from AI"}), 500
            
        return jsonify({"reply": assistant_message})
        
    except Exception as e:
        print(f"Tutor Chat API error: {str(e)}")
        # Return a more user-friendly error message
        return jsonify({
            "error": "I'm having trouble processing your request right now. Please try again in a moment."
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
