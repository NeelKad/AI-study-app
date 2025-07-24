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

# Fix SSL cert issue for OpenAI
os.environ['SSL_CERT_FILE'] = certifi.where()

app = Flask(__name__)

# Secret key for sessions (use env var in production!)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Database config: Use DATABASE_URL or fallback to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize DB
db = SQLAlchemy(app)

# Initialize OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY", ""))

# Login Manager
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

# Create tables on app start
with app.app_context():
    db.create_all()

# ------------------- AUTH ROUTES -------------------

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

# ------------------- DASHBOARD & NOTES -------------------

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
        return render_template('view_note.html', title=note.title, content=note.content)
    else:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))

@app.route('/')
def index():
    return redirect(url_for('dashboard')) if current_user.is_authenticated else redirect(url_for('login'))

# ------------------- OTHER PAGES -------------------

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
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('my_notes.html', notes=notes)

# ------------------- API ROUTES -------------------
# (Your API routes remain unchanged from your code)

# Start the app
if __name__ == '__main__':
    app.run(debug=True)
