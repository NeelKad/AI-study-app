from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, session, make_response
from io import BytesIO
from fpdf import FPDF
from openai import OpenAI
import re
import os
import json
import certifi
import secrets
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

class Device(db.Model):
    __tablename__ = 'devices'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    trial_expires_at = db.Column(db.DateTime, nullable=False)

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
    study_action = db.Column(db.String(100))
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=True)
    priority = db.Column(db.String(20), default='medium')
    estimated_time = db.Column(db.Integer, default=15)
    completed = db.Column(db.Boolean, default=False)
    is_ai_generated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_for = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship('User', backref='schedule_items')
    note = db.relationship('Note', backref='schedule_items')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))


@app.before_request
def create_tables():
    db.create_all()

# --- DEVICE LOGIC ---
def get_device_token():
    token = request.cookies.get('device_token')
    if not token:
        token = secrets.token_hex(16)
        resp = make_response()
        resp.set_cookie('device_token', token, max_age=60*60*24*30)  # 30 days
        return token, resp
    return token, None

def ensure_device_trial():
    token, resp = get_device_token()
    device = Device.query.filter_by(token=token).first()
    if not device:
        expires = datetime.utcnow() + timedelta(minutes=10)
        device = Device(token=token, trial_expires_at=expires)
        db.session.add(device)
        db.session.commit()
    return device, resp

# --- DECORATOR ---
def trial_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        device, resp = ensure_device_trial()
        if datetime.utcnow() > device.trial_expires_at:
            flash('Your device trial has expired! Please unlock to continue.', 'error')
            return redirect(url_for('trial_expired'))
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.is_trial_expired():
            flash('Your account trial has expired! Please unlock to continue.', 'error')
            return redirect(url_for('trial_expired'))
        return f(*args, **kwargs)
    return decorated_function

# Trial status endpoint
@app.route('/api/trial-status', methods=['GET'])
@login_required
def api_trial_status():
    try:
        user = current_user
        if user.has_unlimited_access:
            return jsonify({
                'expired': False,
                'unlimited': True,
                'time_remaining': 'Unlimited',
                'remaining_seconds': float('inf')
            })
        
        if user.trial_expires_at is None:
            return jsonify({
                'expired': True,
                'unlimited': False,
                'time_remaining': 'No trial set',
                'remaining_seconds': 0
            })
        
        now = datetime.utcnow()
        if now > user.trial_expires_at:
            return jsonify({
                'expired': True,
                'unlimited': False,
                'time_remaining': 'Expired',
                'remaining_seconds': 0
            })
        
        remaining = user.trial_expires_at - now
        remaining_seconds = int(remaining.total_seconds())
        minutes = remaining_seconds // 60
        seconds = remaining_seconds % 60
        
        return jsonify({
            'expired': False,
            'unlimited': False,
            'time_remaining': f'{minutes}m {seconds}s',
            'remaining_seconds': remaining_seconds
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Generate AI schedule endpoint
@app.route('/api/generate-schedule', methods=['POST'])
@login_required
@trial_required
def api_generate_schedule():
    try:
        # Get user's notes
        notes = Note.query.filter_by(user_id=current_user.id).all()
        
        if not notes:
            return jsonify({'error': 'No notes found. Please add some notes first.'}), 400
        
        # Prepare notes content for AI
        notes_content = ""
        for note in notes:
            notes_content += f"Note: {note.title}\nContent: {note.content}\n\n"
        
        # Generate schedule using OpenAI
        prompt = f"""Based on these study notes, create a personalized study schedule with 5-8 items. 
        For each item, provide:
        - title: Brief task name
        - description: What to study/do
        - study_action: Choose from (summarise, flashcards, questions, tutor, pastpaper)
        - priority: Choose from (low, medium, high)
        - estimated_time: Minutes needed (5-60)
        - note_title: Which note this relates to (exact match)

        Notes:
        {notes_content}

        Return only valid JSON array like:
        [
          {{
            "title": "Review Math Concepts",
            "description": "Go through algebra fundamentals",
            "study_action": "summarise",
            "priority": "high",
            "estimated_time": 30,
            "note_title": "Algebra Basics"
          }}
        ]"""
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=1000
        )
        
        ai_content = response.choices[0].message.content.strip()
        
        # Try to parse JSON
        try:
            schedule_items = json.loads(ai_content)
        except json.JSONDecodeError:
            # If JSON parsing fails, create a fallback schedule
            schedule_items = [
                {
                    "title": "Review All Notes",
                    "description": "Go through all study materials",
                    "study_action": "summarise",
                    "priority": "medium",
                    "estimated_time": 20,
                    "note_title": notes[0].title if notes else None
                },
                {
                    "title": "Practice Questions",
                    "description": "Test your knowledge with questions",
                    "study_action": "questions",
                    "priority": "high",
                    "estimated_time": 25,
                    "note_title": notes[0].title if notes else None
                }
            ]
        
        # Clear existing AI-generated items
        StudyScheduleItem.query.filter_by(user_id=current_user.id, is_ai_generated=True).delete()
        
        # Create new schedule items
        created_items = []
        for item_data in schedule_items:
            # Find matching note
            note_id = None
            if item_data.get('note_title'):
                matching_note = Note.query.filter_by(
                    user_id=current_user.id, 
                    title=item_data['note_title']
                ).first()
                if matching_note:
                    note_id = matching_note.id
            
            # Create schedule item
            schedule_item = StudyScheduleItem(
                user_id=current_user.id,
                title=item_data.get('title', 'Study Task'),
                description=item_data.get('description', 'Study activity'),
                study_action=item_data.get('study_action', 'summarise'),
                priority=item_data.get('priority', 'medium'),
                estimated_time=item_data.get('estimated_time', 15),
                note_id=note_id,
                is_ai_generated=True
            )
            
            db.session.add(schedule_item)
            created_items.append(schedule_item)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Generated {len(created_items)} study items',
            'items_created': len(created_items)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add custom schedule item endpoint
@app.route('/api/add-schedule-item', methods=['POST'])
@login_required
@trial_required
def api_add_schedule_item():
    try:
        data = request.get_json()
        
        if not data or not data.get('title'):
            return jsonify({'error': 'Title is required'}), 400
        
        schedule_item = StudyScheduleItem(
            user_id=current_user.id,
            title=data['title'],
            description=data.get('description', ''),
            study_action=data.get('study_action', 'summarise'),
            priority=data.get('priority', 'medium'),
            estimated_time=data.get('estimated_time', 15),
            note_id=data.get('note_id') if data.get('note_id') else None,
            is_ai_generated=False
        )
        
        db.session.add(schedule_item)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Schedule item added successfully',
            'item_id': schedule_item.id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Toggle schedule item completion
@app.route('/api/toggle-schedule-item/<int:item_id>', methods=['POST'])
@login_required
@trial_required
def api_toggle_schedule_item(item_id):
    try:
        item = StudyScheduleItem.query.filter_by(
            id=item_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({'error': 'Schedule item not found'}), 404
        
        item.completed = not item.completed
        db.session.commit()
        
        return jsonify({
            'success': True,
            'completed': item.completed
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Delete schedule item endpoint
@app.route('/api/delete-schedule-item/<int:item_id>', methods=['DELETE'])
@login_required
@trial_required
def api_delete_schedule_item(item_id):
    try:
        item = StudyScheduleItem.query.filter_by(
            id=item_id, 
            user_id=current_user.id
        ).first()
        
        if not item:
            return jsonify({'error': 'Schedule item not found'}), 404
        
        db.session.delete(item)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Schedule item deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Delete note endpoint
@app.route('/delete-note/<int:note_id>', methods=['DELETE'])
@login_required
@trial_required
def delete_note(note_id):
    try:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        
        if not note:
            return jsonify({'error': 'Note not found or access denied'}), 404
        
        # Delete related schedule items
        StudyScheduleItem.query.filter_by(note_id=note_id).delete()
        
        # Delete the note
        db.session.delete(note)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Note and related schedule items deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
        trial_expiry = datetime.utcnow() + timedelta(minutes=10)
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

@app.route('/note/<int:note_id>')
@login_required
@trial_required
def view_note(note_id):
    note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
    if note:
        return render_template('view_note.html', title=note.title, content=note.content, note_id=note.id)
    flash("Note not found or access denied.", "error")
    return redirect(url_for('dashboard'))

# --- AI ROUTES ---
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

@app.route('/api/summarise', methods=['POST'])
@login_required
@trial_required
def api_summarise():
    notes = request.json.get('notes', '')
    prompt = f"Summarize these notes into a concise set of dotpoints with emojis:\n\n{notes}"
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
            {"role": "user", "content": f"Generate a past paper from these notes:\n{notes}. If it is math or science related, provide 10 mcqs, 20 short answer questions, and one challenging problem. Add answer key."}
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
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=session["tutor_chat_history"],
        temperature=0.7,
        max_tokens=500
    )
    reply = response.choices[0].message.content.strip()
    session["tutor_chat_history"].append({"role": "assistant", "content": reply})
    session.modified = True
    return jsonify({"reply": reply})

if __name__ == '__main__':
    app.run(debug=True)


