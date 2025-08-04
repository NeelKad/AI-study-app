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
from datetime import datetime, timedelta
from functools import wraps
import math

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

# --- SPACED REPETITION MODELS ---
class Flashcard(db.Model):
    __tablename__ = 'flashcards'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=True)
    term = db.Column(db.Text, nullable=False)
    definition = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Spaced Repetition fields
    ease_factor = db.Column(db.Float, default=2.5)  # How easy the card is (1.3-3.0)
    interval = db.Column(db.Integer, default=1)     # Days until next review
    repetitions = db.Column(db.Integer, default=0)  # Number of successful reviews
    next_review = db.Column(db.DateTime, default=datetime.utcnow)
    last_reviewed = db.Column(db.DateTime, nullable=True)
    
    # Learning state: 'new', 'learning', 'review', 'relearning'
    state = db.Column(db.String(20), default='new')
    
    user = db.relationship('User', backref='flashcards')
    note = db.relationship('Note', backref='flashcards')

class CardReview(db.Model):
    __tablename__ = 'card_reviews'
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('flashcards.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    quality = db.Column(db.Integer, nullable=False)  # 0-5 (fail to perfect)
    response_time = db.Column(db.Integer, nullable=True)  # Seconds to answer
    reviewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    card = db.relationship('Flashcard', backref='reviews')
    user = db.relationship('User')

# --- SPACED REPETITION ALGORITHM ---
class SpacedRepetitionEngine:
    """
    Implements the SM-2 algorithm with modern enhancements
    """
    
    @staticmethod
    def calculate_next_review(card, quality):
        """
        Calculate next review date based on SM-2 algorithm
        
        Quality scale:
        0 - Complete blackout
        1 - Incorrect response, correct answer remembered
        2 - Incorrect response, correct answer seemed easy to recall
        3 - Correct response, but required significant difficulty
        4 - Correct response, after some hesitation
        5 - Perfect response
        """
        
        if quality < 3:  # Failed recall
            # Reset to learning state
            card.repetitions = 0
            card.interval = 1
            card.state = 'relearning' if card.state == 'review' else 'learning'
            card.next_review = datetime.utcnow() + timedelta(minutes=10)  # Quick retry
        else:
            # Successful recall
            if card.repetitions == 0:
                card.interval = 1
                card.state = 'learning'
            elif card.repetitions == 1:
                card.interval = 6
                card.state = 'learning'
            else:
                # Calculate new interval using ease factor
                card.interval = math.ceil(card.interval * card.ease_factor)
                card.state = 'review'
            
            card.repetitions += 1
            card.next_review = datetime.utcnow() + timedelta(days=card.interval)
        
        # Update ease factor based on quality
        card.ease_factor = max(1.3, card.ease_factor + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02)))
        
        card.last_reviewed = datetime.utcnow()
        
        return card

    @staticmethod
    def get_due_cards(user_id, limit=20):
        """Get cards that are due for review"""
        now = datetime.utcnow()
        
        cards = Flashcard.query.filter(
            Flashcard.user_id == user_id,
            Flashcard.next_review <= now
        ).order_by(
            # Prioritize overdue cards, then by state priority
            Flashcard.next_review.asc(),
            db.case(
                (Flashcard.state == 'new', 1),
                (Flashcard.state == 'learning', 2),
                (Flashcard.state == 'relearning', 3),
                (Flashcard.state == 'review', 4)
            )
        ).limit(limit).all()
        
        return cards

    @staticmethod
    def get_daily_stats(user_id):
        """Get study statistics for today"""
        today = datetime.utcnow().date()
        tomorrow = today + timedelta(days=1)
        
        reviews_today = CardReview.query.filter(
            CardReview.user_id == user_id,
            CardReview.reviewed_at >= today,
            CardReview.reviewed_at < tomorrow
        ).count()
        
        due_cards = Flashcard.query.filter(
            Flashcard.user_id == user_id,
            Flashcard.next_review <= datetime.utcnow()
        ).count()
        
        new_cards = Flashcard.query.filter(
            Flashcard.user_id == user_id,
            Flashcard.state == 'new'
        ).count()
        
        return {
            'reviews_today': reviews_today,
            'due_cards': due_cards,
            'new_cards': new_cards
        }

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

# --- SPACED REPETITION API ROUTES ---
@app.route('/api/flashcards-enhanced', methods=['POST'])
@login_required
@trial_required
def api_flashcards_enhanced():
    """Generate and save flashcards with spaced repetition"""
    data = request.json
    notes = data.get('notes', '')
    note_id = data.get('note_id')
    
    try:
        # Generate flashcards using AI
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "Generate flashcards from these notes. Output a valid JSON object where keys are terms and values are definitions. Make 8-12 high-quality flashcards focusing on key concepts."},
                {"role": "user", "content": notes}
            ],
            temperature=0.7,
            max_tokens=800
        )
        
        text = response.choices[0].message.content.strip()
        flashcards_data = json.loads(text) if text else {}
        
        # Save flashcards to database
        saved_cards = []
        for term, definition in flashcards_data.items():
            card = Flashcard(
                user_id=current_user.id,
                note_id=note_id,
                term=term,
                definition=definition,
                next_review=datetime.utcnow()  # Available immediately
            )
            db.session.add(card)
            saved_cards.append({
                'term': term,
                'definition': definition
            })
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'flashcards': saved_cards,
            'count': len(saved_cards)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/study-session/start', methods=['POST'])
@login_required
@trial_required
def start_study_session():
    """Start a spaced repetition study session"""
    data = request.json
    session_type = data.get('type', 'review')  # 'review', 'new', 'mixed'
    limit = min(int(data.get('limit', 20)), 50)  # Max 50 cards per session
    
    if session_type == 'new':
        cards = Flashcard.query.filter(
            Flashcard.user_id == current_user.id,
            Flashcard.state == 'new'
        ).limit(limit).all()
    elif session_type == 'review':
        cards = SpacedRepetitionEngine.get_due_cards(current_user.id, limit)
    else:  # mixed
        due_cards = SpacedRepetitionEngine.get_due_cards(current_user.id, limit // 2)
        new_cards = Flashcard.query.filter(
            Flashcard.user_id == current_user.id,
            Flashcard.state == 'new'
        ).limit(limit - len(due_cards)).all()
        cards = due_cards + new_cards
    
    # Convert to JSON
    cards_data = []
    for card in cards:
        cards_data.append({
            'id': card.id,
            'term': card.term,
            'definition': card.definition,
            'state': card.state,
            'repetitions': card.repetitions,
            'ease_factor': card.ease_factor,
            'interval': card.interval,
            'is_overdue': card.next_review < datetime.utcnow()
        })
    
    return jsonify({
        'cards': cards_data,
        'session_stats': SpacedRepetitionEngine.get_daily_stats(current_user.id)
    })

@app.route('/api/review-card', methods=['POST'])
@login_required
@trial_required
def review_card():
    """Record a card review and update spaced repetition schedule"""
    data = request.json
    card_id = data.get('card_id')
    quality = int(data.get('quality'))  # 0-5
    response_time = data.get('response_time')  # seconds
    
    if quality < 0 or quality > 5:
        return jsonify({'error': 'Quality must be between 0 and 5'}), 400
    
    card = Flashcard.query.filter(
        Flashcard.id == card_id,
        Flashcard.user_id == current_user.id
    ).first()
    
    if not card:
        return jsonify({'error': 'Card not found'}), 404
    
    try:
        # Record the review
        review = CardReview(
            card_id=card_id,
            user_id=current_user.id,
            quality=quality,
            response_time=response_time
        )
        db.session.add(review)
        
        # Update card schedule
        SpacedRepetitionEngine.calculate_next_review(card, quality)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'next_review': card.next_review.isoformat(),
            'interval_days': card.interval,
            'ease_factor': card.ease_factor,
            'state': card.state,
            'message': get_feedback_message(quality, card.interval)
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/flashcard-stats', methods=['GET'])
@login_required
@trial_required
def flashcard_stats():
    """Get comprehensive flashcard statistics"""
    user_id = current_user.id
    
    # Basic counts
    total_cards = Flashcard.query.filter_by(user_id=user_id).count()
    due_cards = Flashcard.query.filter(
        Flashcard.user_id == user_id,
        Flashcard.next_review <= datetime.utcnow()
    ).count()
    
    # Cards by state
    state_counts = db.session.query(
        Flashcard.state,
        db.func.count(Flashcard.id)
    ).filter_by(user_id=user_id).group_by(Flashcard.state).all()
    
    # Recent review performance
    recent_reviews = db.session.query(
        db.func.avg(CardReview.quality),
        db.func.count(CardReview.id)
    ).filter(
        CardReview.user_id == user_id,
        CardReview.reviewed_at >= datetime.utcnow() - timedelta(days=7)
    ).first()
    
    # Learning curve data (last 30 days)
    learning_curve = []
    for i in range(30):
        date = datetime.utcnow().date() - timedelta(days=29-i)
        reviews = CardReview.query.filter(
            CardReview.user_id == user_id,
            CardReview.reviewed_at >= date,
            CardReview.reviewed_at < date + timedelta(days=1)
        ).count()
        learning_curve.append({
            'date': date.isoformat(),
            'reviews': reviews
        })
    
    return jsonify({
        'total_cards': total_cards,
        'due_cards': due_cards,
        'daily_stats': SpacedRepetitionEngine.get_daily_stats(user_id),
        'state_distribution': dict(state_counts),
        'recent_performance': {
            'avg_quality': float(recent_reviews[0]) if recent_reviews[0] else 0,
            'review_count': recent_reviews[1]
        },
        'learning_curve': learning_curve
    })

def get_feedback_message(quality, interval):
    """Generate encouraging feedback based on performance"""
    if quality >= 5:
        return f"Perfect! See you in {interval} days. 🎉"
    elif quality >= 4:
        return f"Great job! Next review in {interval} days. ✨"
    elif quality >= 3:
        return f"Good effort! Keep practicing. Next review in {interval} days."
    elif quality >= 1:
        return "Don't worry, this is part of learning! You'll see this card again soon."
    else:
        return "No problem! Let's try this again in a few minutes."

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
        
        # Delete any flashcards related to this note
        Flashcard.query.filter_by(note_id=note_id, user_id=current_user.id).delete()
        
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

# --- ENHANCED FLASHCARD ROUTES ---
@app.route('/flashcards-sr')
@app.route('/flashcards-sr/<int:note_id>')
@login_required
@trial_required
def flashcards_sr(note_id=None):
    """Enhanced flashcards page with spaced repetition"""
    note_content = None
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if note:
            note_content = note.content
    
    return render_template('flashcards.html', 
                         note_content=note_content, 
                         note_id=note_id,
                         user=current_user)

# Update your existing flashcards route to redirect to the new one
@app.route('/flashcards')
@app.route('/flashcards/<int:note_id>')
@login_required  
@trial_required
def flashcards_redirect(note_id=None):
    """Redirect to enhanced flashcards"""
    if note_id:
        return redirect(url_for('flashcards_sr', note_id=note_id))
    return redirect(url_for('flashcards_sr'))

# --- STUDY TOOLS (UI) ---
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

# --- OPENAI API ROUTES (Legacy - keeping for compatibility) ---
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
    prompt = f"Summarize these notes into a concise set of dotpoints, with emojis as graphics. Seperate each dot-point with 1 line. Make the overall set of study notes look good with emojis:\n\n{notes}"
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
            {"role": "user", "content": f"Generate a past paper from these notes:\n{notes}. If it is math or science related, provide 10 mcq questions, 20 calcualtion/shortanswer questions , and one extremely challenging problem. If it is something like Humanities or English, provide 20 MCQs, 10 short answers, and 1 extended response at the end. At the end, provide an answer key. Also, make the entire paper look good, it should look almost identical to a typical exam with space for writing answers and working out. "}
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

if __name__ == '__main__':
    app.run(debug=True)


