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

class StudyScheduleItem(db.Model):
    __tablename__ = 'study_schedule_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    study_action = db.Column(db.String(100))  # flashcards, questions, summarise, etc.
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=True)
    priority = db.Column(db.String(20), default='medium')  # low, medium, high
    estimated_time = db.Column(db.Integer, default=15)  # minutes
    completed = db.Column(db.Boolean, default=False)
    is_ai_generated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_for = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='schedule_items')
    note = db.relationship('Note', backref='schedule_items')

class Flashcard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=False)
    term = db.Column(db.String, nullable=False)
    definition = db.Column(db.String, nullable=False)
    ease_factor = db.Column(db.Float, default=2.5)
    interval = db.Column(db.Integer, default=1)  # days
    repetitions = db.Column(db.Integer, default=0)
    due_date = db.Column(db.Date, default=datetime.utcnow)
    last_reviewed = db.Column(db.DateTime, default=datetime.utcnow)


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

# --- AI SCHEDULE GENERATION ---
def generate_ai_study_schedule(user_notes):
    """Generate AI-powered study schedule based on user's notes"""
    if not user_notes:
        return []
    
    # Create a summary of all notes for the AI
    notes_summary = ""
    for note in user_notes:
        notes_summary += f"Title: {note.title}\nContent: {note.content[:200]}...\n\n"
    
    try:
        prompt = f"""
        Based on the following study notes, create a personalized study schedule. Generate 5-8 study tasks that will help the student learn effectively.

        Notes:
        {notes_summary}

        For each study task, provide:
        1. A clear title
        2. A brief description of what to study
        3. Recommended study action (flashcards, questions, summarise, tutor, or pastpaper)
        4. Priority level (high, medium, low)
        5. Estimated time in minutes (10-60)

        Prioritize recent notes and complex topics. Mix different study methods for variety.
        
        Respond with a JSON array where each item has these fields:
        - title: string
        - description: string
        - study_action: string (flashcards/questions/summarise/tutor/pastpaper)
        - priority: string (high/medium/low)
        - estimated_time: integer (minutes)
        - note_title: string (which note this relates to)
        """

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1000
        )
        
        ai_response = response.choices[0].message.content.strip()
        # Extract JSON from response (in case there's extra text)
        start_idx = ai_response.find('[')
        end_idx = ai_response.rfind(']') + 1
        if start_idx != -1 and end_idx != -1:
            json_str = ai_response[start_idx:end_idx]
            schedule_items = json.loads(json_str)
            return schedule_items
        else:
            return []
    except Exception as e:
        print(f"Error generating AI schedule: {e}")
        return []

# --- SCHEDULE API ROUTES ---
@app.route('/api/generate-schedule', methods=['POST'])
@login_required
@trial_required
def api_generate_schedule():
    """Generate AI study schedule"""
    try:
        # Get user's notes
        user_notes = Note.query.filter_by(user_id=current_user.id).all()
        
        if not user_notes:
            return jsonify({"error": "No notes found to generate schedule from"}), 400
        
        # Generate AI schedule
        ai_schedule = generate_ai_study_schedule(user_notes)
        
        if not ai_schedule:
            return jsonify({"error": "Failed to generate schedule"}), 500
        
        # Clear existing AI-generated items
        StudyScheduleItem.query.filter_by(user_id=current_user.id, is_ai_generated=True).delete()
        
        # Save new schedule items to database
        saved_items = []
        for item in ai_schedule:
            # Find matching note
            note = None
            if 'note_title' in item:
                note = Note.query.filter_by(
                    user_id=current_user.id, 
                    title=item['note_title']
                ).first()
                if not note:
                    # Try partial match
                    note = Note.query.filter(
                        Note.user_id == current_user.id,
                        Note.title.like(f"%{item['note_title']}%")
                    ).first()
            
            schedule_item = StudyScheduleItem(
                user_id=current_user.id,
                title=item.get('title', 'Study Task'),
                description=item.get('description', ''),
                study_action=item.get('study_action', 'summarise'),
                priority=item.get('priority', 'medium'),
                estimated_time=item.get('estimated_time', 15),
                note_id=note.id if note else None,
                is_ai_generated=True
            )
            db.session.add(schedule_item)
            saved_items.append({
                'title': schedule_item.title,
                'description': schedule_item.description,
                'study_action': schedule_item.study_action,
                'priority': schedule_item.priority,
                'estimated_time': schedule_item.estimated_time
            })
        
        db.session.commit()
        return jsonify({"message": "Schedule generated successfully", "items": saved_items})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/add-schedule-item', methods=['POST'])
@login_required
@trial_required
def api_add_schedule_item():
    """Add custom schedule item"""
    data = request.json
    
    try:
        schedule_item = StudyScheduleItem(
            user_id=current_user.id,
            title=data.get('title', ''),
            description=data.get('description', ''),
            study_action=data.get('study_action', 'summarise'),
            priority=data.get('priority', 'medium'),
            estimated_time=int(data.get('estimated_time', 15)),
            note_id=data.get('note_id') if data.get('note_id') else None,
            is_ai_generated=False
        )
        
        db.session.add(schedule_item)
        db.session.commit()
        
        return jsonify({"message": "Schedule item added successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/toggle-schedule-item/<int:item_id>', methods=['POST'])
@login_required
@trial_required
def api_toggle_schedule_item(item_id):
    """Toggle completion status of schedule item"""
    try:
        item = StudyScheduleItem.query.filter_by(
            id=item_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({"error": "Schedule item not found"}), 404
        
        item.completed = not item.completed
        db.session.commit()
        
        return jsonify({"message": "Schedule item updated", "completed": item.completed})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/delete-schedule-item/<int:item_id>', methods=['DELETE'])
@login_required
@trial_required
def api_delete_schedule_item(item_id):
    """Delete schedule item"""
    try:
        item = StudyScheduleItem.query.filter_by(
            id=item_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({"error": "Schedule item not found"}), 404
        
        db.session.delete(item)
        db.session.commit()
        
        return jsonify({"message": "Schedule item deleted"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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
    schedule_items = StudyScheduleItem.query.filter_by(user_id=current_user.id).order_by(
        StudyScheduleItem.completed.asc(),
        StudyScheduleItem.priority.desc(),
        StudyScheduleItem.created_at.desc()
    ).all()
    return render_template('dashboard.html', notes=notes, schedule_items=schedule_items, email=current_user.email, user=current_user)

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

@app.route('/delete-note/<int:note_id>', methods=['DELETE'])
@login_required
@trial_required
def delete_note(note_id):
    """Delete a note"""
    try:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        
        if not note:
            return jsonify({"error": "Note not found or access denied"}), 404
        
        # Also delete any schedule items related to this note
        StudyScheduleItem.query.filter_by(note_id=note_id, user_id=current_user.id).delete()
        
        db.session.delete(note)
        db.session.commit()
        
        return jsonify({"message": "Note deleted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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

@app.route('/save-note', methods=['POST'])
@login_required
@trial_required
def save_note_alias():
    return add_note()

# --- STUDY TOOLS (UI) ---
@app.route('/flashcards/<int:note_id>')
@login_required
@trial_required
def flashcards(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not note:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))
    return render_template('flashcards.html', note_content=note.content, note_id=note.id, user=current_user)

@app.route('/review-today-flashcards/<int:note_id>')
@login_required
@trial_required
def review_today_flashcards(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not note:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))
    return render_template('review_today_flashcards.html', note_id=note.id, user=current_user)

@app.route('/review-all-flashcards/<int:note_id>')
@login_required
@trial_required
def review_all_flashcards(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if not note:
        flash("Note not found or access denied.", "error")
        return redirect(url_for('dashboard'))
    return render_template('review_all_flashcards.html', note_id=note.id, user=current_user)

@app.route('/api/flashcards/all', methods=['GET'])
@login_required
@trial_required
def get_all_flashcards():
    user_id = current_user.id
    flashcards = (
        Flashcard.query
        .join(Note, Flashcard.note_id == Note.id)
        .filter(Note.user_id == user_id)
        .all()
    )
    result = [{
        "id": card.id,
        "term": card.term,
        "definition": card.definition,
        "due_date": card.due_date.isoformat(),
    } for card in flashcards]
    return jsonify(result)

@app.route('/api/flashcards/due', methods=['GET'])
@login_required
@trial_required
def get_due_flashcards():
    user_id = current_user.id
    today = datetime.utcnow().date()

    due_flashcards = (
        Flashcard.query
        .join(Note, Flashcard.note_id == Note.id)
        .filter(Note.user_id == user_id)
        .filter(Flashcard.due_date <= today)
        .all()
    )

    result = [{
        "id": card.id,
        "term": card.term,
        "definition": card.definition,
        "due_date": card.due_date.isoformat(),
    } for card in due_flashcards]

    return jsonify(result)



@app.route('/api/flashcards/review/<int:card_id>', methods=['POST'])
@login_required
@trial_required
def review_flashcard(card_id):
    data = request.json
    quality = data.get('quality')  # expects 0,1,2,3

    card = Flashcard.query.filter_by(id=card_id, user_id=current_user.id).first()
    if not card:
        return jsonify({"error": "Flashcard not found"}), 404

    # Update spaced repetition stats
    update_flashcard(card, quality)

    db.session.commit()
    return jsonify({"message": "Flashcard updated"}), 200


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
    if not notes:
        return jsonify({"error": "No notes provided"}), 400

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "user",
                    "content": (
                        "Generate flashcards from these notes. Output a valid JSON object where keys are terms and values are definitions."
                    )
                },
                {"role": "user", "content": notes}
            ],
            temperature=0.7,
            max_tokens=700
        )
        text = response.choices[0].message.content.strip()
        flashcards = json.loads(text) if text else {}

        # Optionally: Save flashcards to DB here
        # Example (if note_id is passed in JSON):
        note_id = request.json.get('note_id')
        if note_id:
            for term, definition in flashcards.items():
                # Check if flashcard already exists to avoid duplicates, or clear old ones
                existing_card = Flashcard.query.filter_by(note_id=note_id, term=term, user_id=current_user.id).first()
                if existing_card:
                    existing_card.definition = definition
                else:
                    new_card = Flashcard(
                        note_id=note_id,
                        term=term,
                        definition=definition,
                        ease_factor=2.5,
                        interval=1,
                        repetitions=0,
                        due_date=datetime.utcnow().date(),
                        last_reviewed=datetime.utcnow()
                    )
                    db.session.add(new_card)
            db.session.commit()

    except Exception as e:
        app.logger.error(f"Flashcard generation failed: {e}")
        return jsonify({"error": "Failed to generate flashcards"}), 500

    return jsonify(flashcards)


@app.route('/api/questions', methods=['POST'])
@login_required
@trial_required
def api_questions():
    notes = request.json.get('notes', '')
    prompt = f"Generate 20 concise questions from these notes:\n\n{notes}"
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=500
    )
    text = response.choices[0].message.content.strip()
    questions = [q.strip() for q in text.split('\n') if q.strip()]
    return jsonify(questions)

@app.route('/api/questions/enhanced', methods=['POST'])
@login_required
@trial_required
def api_questions_enhanced():
    data = request.json
    notes = data.get('notes', '')
    count = int(data.get('count', 15))
    difficulty = data.get('difficulty', 'intermediate')
    subject = data.get('subject', 'auto')
    types = data.get('types', ['multiple_choice', 'short_answer'])
    focus_topics = data.get('focusTopics', [])

    # Compose prompt for OpenAI
    prompt = (
        f"Generate {count} study questions from these notes. "
        f"Difficulty: {difficulty}. Subject: {subject}. "
        f"ONLY use these question types: {', '.join(types)}. "
        f"Do NOT include any other question types. "
        f"Focus topics: {', '.join(focus_topics) if focus_topics else 'none'}. "
        "For each question, provide a JSON object with: "
        "question (string), type (must be one of the selected types), difficulty (string), topic (string), options (array, if MCQ), correctAnswer, rubric (if relevant). "
        "Return a JSON array. Do NOT include any question type that is not in the list above."
        "\nNotes:\n" + notes
    )

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=2000
        )
        ai_response = response.choices[0].message.content.strip()
        # Extract JSON array from response
        start_idx = ai_response.find('[')
        end_idx = ai_response.rfind(']') + 1
        if start_idx != -1 and end_idx != -1:
            json_str = ai_response[start_idx:end_idx]
            questions = json.loads(json_str)
        else:
            questions = []
        return jsonify({"questions": questions})
    except Exception as e:
        app.logger.error(f"Enhanced question generation failed: {e}")
        return jsonify({"questions": [], "error": str(e)}), 500

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

@app.route('/api/grade_question/enhanced', methods=['POST'])
@login_required
@trial_required
def api_grade_question_enhanced():
    data = request.json
    question = data.get('question', '')
    question_type = data.get('questionType', '')
    user_answer = data.get('userAnswer', '')
    correct_answer = data.get('correctAnswer', None)
    notes = data.get('notes', '')
    difficulty = data.get('difficulty', 'intermediate')
    rubric = data.get('rubric', None)

    # Compose grading prompt
    prompt = (
        f"Grade the following answer for the question below.\n"
        f"Question: {question}\n"
        f"Type: {question_type}\n"
        f"User Answer: {user_answer}\n"
        f"Correct Answer: {correct_answer}\n"
        f"Difficulty: {difficulty}\n"
        f"Rubric: {rubric}\n"
        f"Notes: {notes}\n"
        "Return a JSON object with these fields:\n"
        "- score (0-10): number\n"
        "- isCorrect (true/false): true if the user's answer matches the correct answer (for multiple_choice, true_false, calculation, definition types), otherwise false. For essay/short_answer, set true if the answer is mostly correct.\n"
        "- feedback (string): assessment of the answer\n"
        "- improvement (string): suggestion for improvement\n"
        "- modelAnswer (string): ideal answer\n"
        "- hints (string, optional): study tips\n"
        "Be strict for auto-gradable types. For MCQ, true/false, calculation, and definition, compare exactly. For essay/short_answer, use rubric and similarity."
    )

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=700
        )
        text = response.choices[0].message.content.strip()
        # Extract JSON object from response
        start_idx = text.find('{')
        end_idx = text.rfind('}') + 1
        if start_idx != -1 and end_idx != -1:
            json_str = text[start_idx:end_idx]
            grade_data = json.loads(json_str)
        else:
            grade_data = {}
        return jsonify(grade_data)
    except Exception as e:
        app.logger.error(f"Enhanced grading failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/summarise', methods=['POST'])
@login_required
@trial_required
def api_summarise():
    notes = request.json.get('notes', '')
    prompt = f"Summarize these notes into a concise set of dotpoints, with emojis as graphics:\n\n{notes}"
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
            {"role": "user", "content": f"Generate a past paper from these notes:\n{notes}. If it is math or science related, provide 20 mcq questions, 30 calcualtion/shortanswer questions , and 2 extremely challenging problems. If it is something like Humanities or English, provide 20 MCQs, 10 short answers, and 1 extended response at the end. At the end, provide an answer key. Also, make the entire paper look good, it should look almost identical to a typical exam with space for writing answers and working out. It should have sections formated for clarity"}
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


from flask import session

@app.route("/api/tutor_chat", methods=["POST"])
@login_required
@trial_required
def tutor_chat():
    message = request.json.get("message", "").strip()
    note_content = request.json.get("note_content", "").strip()

    if not message:
        return jsonify({"error": "Empty message"}), 400

    if "tutor_chat_history" not in session:
        session["tutor_chat_history"] = [
            {"role": "system", "content": "You are a helpful AI study tutor. Always explain clearly."},
            {"role": "system", "content": f"Here are the user's study notes:\n{note_content}"}
        ]

    session["tutor_chat_history"].append({"role": "user", "content": message})

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=session["tutor_chat_history"],
            temperature=0.7,
            max_tokens=500
        )
        reply = response.choices[0].message.content.strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    session["tutor_chat_history"].append({"role": "assistant", "content": reply})
    session.modified = True

    return jsonify({"reply": reply})


def update_flashcard(card, quality):
    """
    Update flashcard stats using SM-2 algorithm.
    quality: 0 (forgot), 1 (hard), 2 (medium), 3 (easy)
    """
    # Ensure minimum values
    if card.repetitions is None:
        card.repetitions = 0
    if card.ease_factor is None:
        card.ease_factor = 2.5
    if card.interval is None:
        card.interval = 1

    # Quality: 0=forgot, 1=hard, 2=medium, 3=easy
    if quality < 2:
        card.repetitions = 0
        card.interval = 1
    else:
        card.repetitions += 1
        # SM-2 ease factor update
        card.ease_factor = max(1.3, card.ease_factor + (0.1 - (3 - quality) * (0.08 + (3 - quality) * 0.02)))
        # Interval calculation
        if card.repetitions == 1:
            card.interval = 1
        elif card.repetitions == 2:
            card.interval = 6
        else:
            card.interval = int(card.interval * card.ease_factor)
    # Set next due date
    card.due_date = datetime.utcnow().date() + timedelta(days=card.interval)
    card.last_reviewed = datetime.utcnow()


if __name__ == '__main__':
    app.run(debug=True)






