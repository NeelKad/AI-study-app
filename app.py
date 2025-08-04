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

from flask import send_from_directory

from flask import render_template

@app.route('/')
def home():
    return render_template('login.html')



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

# Replace the existing start_study_session route in app.py with this updated version:

@app.route('/api/study-session/start', methods=['POST'])
@login_required
@trial_required
def start_study_session():
    """Start a spaced repetition study session"""
    data = request.json
    session_type = data.get('type', 'review')  # 'review', 'new', 'mixed'
    limit = min(int(data.get('limit', 20)), 50)  # Max 50 cards per session
    note_id = data.get('note_id')  # Optional: focus on specific note
    
    # Base query
    base_query = Flashcard.query.filter(Flashcard.user_id == current_user.id)
    
    # If note_id is provided, prioritize cards from that note
    if note_id:
        note_cards_query = base_query.filter(Flashcard.note_id == note_id)
    else:
        note_cards_query = base_query
    
    if session_type == 'new':
        # Get new cards, prioritizing the specific note if provided
        if note_id:
            cards = note_cards_query.filter(Flashcard.state == 'new').limit(limit).all()
            # If not enough cards from this note, fill with other new cards
            if len(cards) < limit:
                remaining_limit = limit - len(cards)
                other_cards = base_query.filter(
                    Flashcard.state == 'new',
                    Flashcard.note_id != note_id
                ).limit(remaining_limit).all()
                cards.extend(other_cards)
        else:
            cards = base_query.filter(Flashcard.state == 'new').limit(limit).all()
            
    elif session_type == 'review':
        # Get due cards for review
        now = datetime.utcnow()
        if note_id:
            cards = note_cards_query.filter(Flashcard.next_review <= now).limit(limit).all()
            # If not enough due cards from this note, fill with other due cards
            if len(cards) < limit:
                remaining_limit = limit - len(cards)
                other_cards = base_query.filter(
                    Flashcard.next_review <= now,
                    Flashcard.note_id != note_id
                ).limit(remaining_limit).all()
                cards.extend(other_cards)
        else:
            cards = SpacedRepetitionEngine.get_due_cards(current_user.id, limit)
            
    else:  # mixed
        now = datetime.utcnow()
        half_limit = limit // 2
        
        if note_id:
            # Get due cards from the specific note first
            due_cards = note_cards_query.filter(Flashcard.next_review <= now).limit(half_limit).all()
            # Get new cards from the specific note
            new_cards = note_cards_query.filter(Flashcard.state == 'new').limit(limit - len(due_cards)).all()
            
            # Fill remaining slots with cards from other notes if needed
            total_cards = len(due_cards) + len(new_cards)
            if total_cards < limit:
                remaining_limit = limit - total_cards
                # Get additional due cards from other notes
                if len(due_cards) < half_limit:
                    additional_due = base_query.filter(
                        Flashcard.next_review <= now,
                        Flashcard.note_id != note_id
                    ).limit(remaining_limit // 2).all()
                    due_cards.extend(additional_due)
                
                # Get additional new cards from other notes
                remaining_after_due = limit - len(due_cards) - len(new_cards)
                if remaining_after_due > 0:
                    additional_new = base_query.filter(
                        Flashcard.state == 'new',
                        Flashcard.note_id != note_id
                    ).limit(remaining_after_due).all()
                    new_cards.extend(additional_new)
            
            cards = due_cards + new_cards
        else:
            # Original mixed logic for all notes
            due_cards = SpacedRepetitionEngine.get_due_cards(current_user.id, half_limit)
            new_cards = base_query.filter(Flashcard.state == 'new').limit(limit - len(due_cards)).all()
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
            'is_overdue': card.next_review < datetime.utcnow(),
            'note_id': card.note_id  # Include note_id for tracking
        })
    
    return jsonify({
        'cards': cards_data,
        'session_stats': SpacedRepetitionEngine.get_daily_stats(current_user.id),
        'note_specific': bool(note_id),
        'note_id': note_id
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
        return jsonify({'error':
                        
                        'Card not found'}), 404
    
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
    note_id = request.args.get('note_id')  # Optional parameter for note-specific stats
    
    # Base query
    base_query = Flashcard.query.filter_by(user_id=user_id)
    
    # Filter by note if specified
    if note_id:
        base_query = base_query.filter_by(note_id=note_id)
    
    # Basic counts
    total_cards = base_query.count()
    
    # Due cards (considering note filter)
    due_cards_query = base_query.filter(Flashcard.next_review <= datetime.utcnow())
    due_cards = due_cards_query.count()
    
    # Cards by state (considering note filter)
    state_counts = db.session.query(
        Flashcard.state,
        db.func.count(Flashcard.id)
    ).filter_by(user_id=user_id)

    if note_id:
        state_counts = state_counts.filter_by(note_id=note_id)

    state_counts = state_counts.group_by(Flashcard.state).all()

    # Daily stats (always global, not note-specific)
    daily_stats = SpacedRepetitionEngine.get_daily_stats(user_id)

    # If note-specific, adjust new cards count
    if note_id:
        new_cards_for_note = base_query.filter_by(state='new').count()
        daily_stats['new_cards'] = new_cards_for_note

    # Recent review performance (considering note filter)
    recent_reviews_query = db.session.query(
        db.func.avg(CardReview.quality),
        db.func.count(CardReview.id)
    ).join(Flashcard).filter(
        Flashcard.user_id == user_id,
        CardReview.reviewed_at >= datetime.utcnow() - timedelta(days=7)
    )

    if note_id:
        recent_reviews_query = recent_reviews_query.filter(Flashcard.note_id == note_id)

    recent_reviews = recent_reviews_query.first()

    # Learning curve data (last 30 days) - always global for now
    learning_curve = []
    for i in range(30):
        date = datetime.utcnow().date() - timedelta(days=29-i)
        reviews_query = CardReview.query.filter(
            CardReview.user_id == user_id,
            CardReview.reviewed_at >= date,
            CardReview.reviewed_at < date + timedelta(days=1)
        )

        # If note-specific, join with flashcards table
        if note_id:
            reviews_query = reviews_query.join(Flashcard).filter(Flashcard.note_id == note_id)

        reviews = reviews_query.count()
        learning_curve.append({
            'date': date.isoformat(),
            'reviews': reviews
        })
    
    response_data = {
        'total_cards': total_cards,
        'due_cards': due_cards,
        'daily_stats': daily_stats,
        'state_distribution': dict(state_counts),
        'recent_performance': {
            'avg_quality': float(recent_reviews[0]) if recent_reviews[0] else 0,
            'review_count': recent_reviews[1] if recent_reviews[1] else 0
        },
        'learning_curve': learning_curve
    }
    
    # Add note-specific context
    if note_id:
        note = Note.query.filter_by(id=note_id, user_id=user_id).first()
        if note:
            response_data['note_context'] = {
                'note_id': note_id,
                'note_title': note.title,
                'is_note_specific': True
            }
    
    return jsonify(response_data)

# Add these new models to your app.py file

class LearningPlan(db.Model):
    __tablename__ = 'learning_plans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    difficulty_areas = db.Column(db.Text)  # JSON string of identified weak areas
    total_modules = db.Column(db.Integer, default=0)
    completed_modules = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='learning_plans')
    note = db.relationship('Note', backref='learning_plans')

class LearningModule(db.Model):
    __tablename__ = 'learning_modules'
    id = db.Column(db.Integer, primary_key=True)
    learning_plan_id = db.Column(db.Integer, db.ForeignKey('learning_plans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)  # AI-generated explanation
    concept_area = db.Column(db.String(100))  # What specific concept this covers
    module_order = db.Column(db.Integer, nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    learning_plan = db.relationship('LearningPlan', backref='modules')

class QuizSession(db.Model):
    __tablename__ = 'quiz_sessions'
    id = db.Column(db.Integer, primary_key=True)
    learning_module_id = db.Column(db.Integer, db.ForeignKey('learning_modules.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    questions = db.Column(db.Text, nullable=False)  # JSON string of questions
    user_answers = db.Column(db.Text)  # JSON string of user answers
    scores = db.Column(db.Text)  # JSON string of individual question scores
    total_score = db.Column(db.Float, default=0.0)
    max_score = db.Column(db.Float, default=100.0)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    learning_module = db.relationship('LearningModule', backref='quiz_sessions')
    user = db.relationship('User')

class PerformanceAnalytics(db.Model):
    __tablename__ = 'performance_analytics'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=False)
    
    # Flashcard performance
    flashcard_accuracy = db.Column(db.Float, default=0.0)  # Average quality score
    flashcard_count = db.Column(db.Integer, default=0)
    weak_flashcard_concepts = db.Column(db.Text)  # JSON array of struggling concepts
    
    # Question generator performance
    question_avg_score = db.Column(db.Float, default=0.0)
    question_attempts = db.Column(db.Integer, default=0)
    weak_question_areas = db.Column(db.Text)  # JSON array of low-scoring topics
    
    # Overall analysis
    overall_competency = db.Column(db.Float, default=0.0)  # 0-100 scale
    needs_improvement = db.Column(db.Text)  # JSON array of areas needing work
    strengths = db.Column(db.Text)  # JSON array of strong areas
    
    last_analyzed = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')
    note = db.relationship('Note')

# Add this to track question generator performance (if not already exists)
class QuestionAttempt(db.Model):
    __tablename__ = 'question_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('notes.id'), nullable=True)
    question = db.Column(db.Text, nullable=False)
    user_answer = db.Column(db.Text, nullable=False)
    score = db.Column(db.Float, nullable=False)  # 0-10 score from AI
    feedback = db.Column(db.Text)  # AI feedback
    model_answer = db.Column(db.Text)  # Ideal answer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User')
    note = db.relationship('Note')

# Add this Performance Analysis Engine to your app.py

class PerformanceAnalyzer:
    """Analyzes user performance across flashcards and questions to identify learning gaps"""
    
    @staticmethod
    def analyze_user_performance(user_id, note_id=None):
        """
        Comprehensive analysis of user performance
        Returns areas of strength and weakness
        """
        
        # Get flashcard performance data
        flashcard_data = PerformanceAnalyzer._analyze_flashcard_performance(user_id, note_id)
        
        # Get question generator performance data
        question_data = PerformanceAnalyzer._analyze_question_performance(user_id, note_id)
        
        # Combine and analyze
        overall_analysis = PerformanceAnalyzer._combine_analysis(flashcard_data, question_data)
        
        # Save or update performance analytics
        if note_id:
            PerformanceAnalyzer._save_performance_analytics(user_id, note_id, overall_analysis)
        
        return overall_analysis
    
    @staticmethod
    def _analyze_flashcard_performance(user_id, note_id=None):
        """Analyze flashcard performance patterns"""
        
        # Base query for flashcard reviews
        base_query = db.session.query(CardReview).join(Flashcard).filter(
            CardReview.user_id == user_id
        )
        
        if note_id:
            base_query = base_query.filter(Flashcard.note_id == note_id)
        
        # Get recent reviews (last 30 days)
        recent_reviews = base_query.filter(
            CardReview.reviewed_at >= datetime.utcnow() - timedelta(days=30)
        ).all()
        
        if not recent_reviews:
            return {
                'accuracy': 0.0,
                'total_reviews': 0,
                'weak_concepts': [],
                'strong_concepts': [],
                'needs_review': []
            }
        
        # Calculate average accuracy (quality score / 5 * 100)
        total_quality = sum(review.quality for review in recent_reviews)
        accuracy = (total_quality / (len(recent_reviews) * 5)) * 100
        
        # Identify weak and strong concepts
        concept_performance = {}
        for review in recent_reviews:
            term = review.card.term.lower()
            
            # Simple concept extraction (first few words or key terms)
            concept = PerformanceAnalyzer._extract_concept(term)
            
            if concept not in concept_performance:
                concept_performance[concept] = {'scores': [], 'term': review.card.term}
            
            concept_performance[concept]['scores'].append(review.quality)
        
        # Categorize concepts
        weak_concepts = []
        strong_concepts = []
        needs_review = []
        
        for concept, data in concept_performance.items():
            avg_score = sum(data['scores']) / len(data['scores'])
            
            if avg_score < 2.5:  # Below average performance
                weak_concepts.append({
                    'concept': concept,
                    'score': avg_score,
                    'term': data['term'],
                    'attempts': len(data['scores'])
                })
            elif avg_score >= 4.0:  # Strong performance
                strong_concepts.append({
                    'concept': concept,
                    'score': avg_score,
                    'term': data['term']
                })
            else:  # Needs more review
                needs_review.append({
                    'concept': concept,
                    'score': avg_score,
                    'term': data['term']
                })
        
        return {
            'accuracy': accuracy,
            'total_reviews': len(recent_reviews),
            'weak_concepts': sorted(weak_concepts, key=lambda x: x['score'])[:5],
            'strong_concepts': sorted(strong_concepts, key=lambda x: x['score'], reverse=True)[:3],
            'needs_review': needs_review
        }
    
    @staticmethod
    def _analyze_question_performance(user_id, note_id=None):
        """Analyze question generator performance patterns"""
        
        # Query question attempts
        base_query = QuestionAttempt.query.filter(QuestionAttempt.user_id == user_id)
        
        if note_id:
            base_query = base_query.filter(QuestionAttempt.note_id == note_id)
        
        # Get recent attempts (last 30 days)
        recent_attempts = base_query.filter(
            QuestionAttempt.created_at >= datetime.utcnow() - timedelta(days=30)
        ).all()
        
        if not recent_attempts:
            return {
                'avg_score': 0.0,
                'total_attempts': 0,
                'weak_areas': [],
                'strong_areas': [],
                'improvement_needed': []
            }
        
        # Calculate average score
        total_score = sum(attempt.score for attempt in recent_attempts)
        avg_score = (total_score / len(recent_attempts)) * 10  # Convert to percentage
        
        # Analyze question topics and performance
        topic_performance = {}
        for attempt in recent_attempts:
            # Extract topic from question (simple keyword extraction)
            topic = PerformanceAnalyzer._extract_topic_from_question(attempt.question)
            
            if topic not in topic_performance:
                topic_performance[topic] = {'scores': [], 'questions': []}
            
            topic_performance[topic]['scores'].append(attempt.score)
            topic_performance[topic]['questions'].append(attempt.question[:100] + '...')
        
        # Categorize topics
        weak_areas = []
        strong_areas = []
        improvement_needed = []
        
        for topic, data in topic_performance.items():
            avg_score = sum(data['scores']) / len(data['scores'])
            score_percentage = avg_score * 10
            
            if score_percentage < 50:  # Below 50%
                weak_areas.append({
                    'topic': topic,
                    'score': score_percentage,
                    'attempts': len(data['scores']),
                    'sample_questions': data['questions'][:2]
                })
            elif score_percentage >= 80:  # Above 80%
                strong_areas.append({
                    'topic': topic,
                    'score': score_percentage,
                    'attempts': len(data['scores'])
                })
            else:  # 50-80% needs improvement
                improvement_needed.append({
                    'topic': topic,
                    'score': score_percentage,
                    'attempts': len(data['scores'])
                })
        
        return {
            'avg_score': avg_score,
            'total_attempts': len(recent_attempts),
            'weak_areas': sorted(weak_areas, key=lambda x: x['score'])[:5],
            'strong_areas': sorted(strong_areas, key=lambda x: x['score'], reverse=True)[:3],
            'improvement_needed': improvement_needed
        }
    
    @staticmethod
    def _combine_analysis(flashcard_data, question_data):
        """Combine flashcard and question analysis into overall assessment"""
        
        # Calculate overall competency score
        flashcard_weight = 0.6  # Flashcards are 60% of score
        question_weight = 0.4   # Questions are 40% of score
        
        overall_score = (
            flashcard_data['accuracy'] * flashcard_weight +
            question_data['avg_score'] * question_weight
        )
        
        # Combine weak areas
        all_weak_areas = []
        
        # Add flashcard weak concepts
        for concept in flashcard_data['weak_concepts']:
            all_weak_areas.append({
                'area': concept['concept'],
                'type': 'flashcard',
                'score': concept['score'] * 20,  # Convert to percentage
                'details': f"Struggling with: {concept['term']}"
            })
        
        # Add question weak areas
        for area in question_data['weak_areas']:
            all_weak_areas.append({
                'area': area['topic'],
                'type': 'question',
                'score': area['score'],
                'details': f"Low performance in {area['attempts']} attempts"
            })
        
        # Identify priority areas (appearing in both or very low scores)
        priority_areas = []
        seen_areas = {}
        
        for area in all_weak_areas:
            area_key = area['area'].lower()
            if area_key in seen_areas:
                # Appears in both - high priority
                priority_areas.append({
                    'area': area['area'],
                    'priority': 'high',
                    'types': [seen_areas[area_key]['type'], area['type']],
                    'avg_score': (seen_areas[area_key]['score'] + area['score']) / 2
                })
            else:
                seen_areas[area_key] = area
        
        # Add very low scoring single areas
        for area in all_weak_areas:
            if area['score'] < 30:  # Very low score
                area_key = area['area'].lower()
                if not any(p['area'].lower() == area_key for p in priority_areas):
                    priority_areas.append({
                        'area': area['area'],
                        'priority': 'medium',
                        'types': [area['type']],
                        'avg_score': area['score']
                    })
        
        return {
            'overall_competency': overall_score,
            'flashcard_performance': flashcard_data,
            'question_performance': question_data,
            'priority_learning_areas': sorted(priority_areas, key=lambda x: x['avg_score'])[:5],
            'total_data_points': flashcard_data['total_reviews'] + question_data['total_attempts'],
            'analysis_confidence': min(100, (flashcard_data['total_reviews'] + question_data['total_attempts']) * 5)
        }
    
    @staticmethod
    def _extract_concept(term):
        """Extract key concept from flashcard term"""
        # Simple concept extraction - take first 2-3 significant words
        words = term.lower().split()
        
        # Filter out common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'what', 'how', 'why', 'when', 'where'}
        significant_words = [w for w in words if w not in stop_words and len(w) > 2]
        
        if not significant_words:
            return term[:20]  # Fallback to first 20 characters
        
        return ' '.join(significant_words[:2])  # Take first 2 significant words
    
    @staticmethod
    def _extract_topic_from_question(question):
        """Extract topic from question text"""
        # Simple topic extraction from question
        words = question.lower().split()
        
        # Look for key topic indicators
        topic_indicators = ['about', 'regarding', 'concerning', 'explain', 'describe', 'what is', 'define']
        
        for i, word in enumerate(words):
            if word in topic_indicators and i + 1 < len(words):
                # Take next few words as topic
                topic_words = words[i+1:i+4]
                topic_words = [w for w in topic_words if w.isalpha() and len(w) > 2]
                if topic_words:
                    return ' '.join(topic_words)
        
        # Fallback: take first few significant words
        significant_words = [w for w in words if w.isalpha() and len(w) > 3][:3]
        return ' '.join(significant_words) if significant_words else 'general'
    
    @staticmethod
    def _save_performance_analytics(user_id, note_id, analysis_data):
        """Save or update performance analytics in database"""
        
        # Find or create performance record
        performance = PerformanceAnalytics.query.filter_by(
            user_id=user_id,
            note_id=note_id
        ).first()
        
        if not performance:
            performance = PerformanceAnalytics(user_id=user_id, note_id=note_id)
            db.session.add(performance)
        
        # Update with latest analysis
        performance.flashcard_accuracy = analysis_data['flashcard_performance']['accuracy']
        performance.flashcard_count = analysis_data['flashcard_performance']['total_reviews']
        performance.weak_flashcard_concepts = json.dumps([c['concept'] for c in analysis_data['flashcard_performance']['weak_concepts']])
        
        performance.question_avg_score = analysis_data['question_performance']['avg_score']
        performance.question_attempts = analysis_data['question_performance']['total_attempts']
        performance.weak_question_areas = json.dumps([a['topic'] for a in analysis_data['question_performance']['weak_areas']])
        
        performance.overall_competency = analysis_data['overall_competency']
        performance.needs_improvement = json.dumps([area['area'] for area in analysis_data['priority_learning_areas']])
        performance.last_analyzed = datetime.utcnow()
        
        db.session.commit()
        return performance

# Add this Learning Plan Generator to your app.py

class LearningPlanGenerator:
    """Generates personalized learning plans based on performance analysis"""
    
    @staticmethod
    def generate_learning_plan(user_id, note_id, analysis_data):
        """Generate a comprehensive learning plan based on performance analysis"""
        
        try:
            # Get the note content
            note = Note.query.filter_by(id=note_id, user_id=user_id).first()
            if not note:
                raise ValueError("Note not found")
            
            # Prepare analysis summary for AI
            weak_areas = [area['area'] for area in analysis_data['priority_learning_areas']]
            overall_score = analysis_data['overall_competency']
            
            # Generate learning plan structure using AI
            plan_prompt = f"""
            Based on this student's performance analysis, create a personalized learning plan:
            
            Subject: {note.title}
            Overall Competency: {overall_score:.1f}%
            Weak Areas: {', '.join(weak_areas)}
            
            Student's Note Content:
            {note.content[:1500]}...
            
            Create a learning plan with 4-6 focused modules. Each module should:
            1. Target specific weak areas identified
            2. Build progressively from basic to advanced concepts
            3. Include clear learning objectives
            4. Be designed for 15-20 minute study sessions
            
            For each module, provide:
            - Title (concise, specific to the concept)
            - Learning objectives (what student will master)
            - Key concepts to cover
            - Suggested teaching approach (explanation style)
            
            Output as JSON with this structure:
            {{
                "plan_title": "Personalized Learning Plan for [Subject]",
                "plan_description": "Brief description of what this plan will achieve",
                "estimated_duration": "Total estimated time",
                "modules": [
                    {{
                        "title": "Module title",
                        "objectives": ["objective 1", "objective 2"],
                        "key_concepts": ["concept 1", "concept 2"],
                        "teaching_approach": "How to explain this module",
                        "difficulty_level": "beginner/intermediate/advanced"
                    }}
                ]
            }}
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": plan_prompt}],
                temperature=0.7,
                max_tokens=1500
            )
            
            plan_text = response.choices[0].message.content.strip()
            
            # Extract JSON from response
            try:
                start_idx = plan_text.find('{')
                end_idx = plan_text.rfind('}') + 1
                if start_idx != -1 and end_idx != -1:
                    json_str = plan_text[start_idx:end_idx]
                    plan_data = json.loads(json_str)
                else:
                    raise ValueError("No valid JSON found in response")
                    
            except json.JSONDecodeError:
                # Fallback plan structure
                plan_data = LearningPlanGenerator._create_fallback_plan(weak_areas, note.title)
            
            # Save learning plan to database
            learning_plan = LearningPlan(
                user_id=user_id,
                note_id=note_id,
                title=plan_data.get('plan_title', f'Learning Plan for {note.title}'),
                description=plan_data.get('plan_description', 'Personalized learning plan based on your performance'),
                difficulty_areas=json.dumps(weak_areas),
                total_modules=len(plan_data.get('modules', [])),
                completed_modules=0
            )
            
            db.session.add(learning_plan)
            db.session.flush()  # Get the ID
            
            # Create learning modules
            modules_created = []
            for i, module_data in enumerate(plan_data.get('modules', [])):
                # Generate detailed content for each module
                module_content = LearningPlanGenerator._generate_module_content(
                    module_data, note.content, weak_areas
                )
                
                learning_module = LearningModule(
                    learning_plan_id=learning_plan.id,
                    title=module_data.get('title', f'Module {i+1}'),
                    content=module_content,
                    concept_area=module_data.get('key_concepts', ['general'])[0],
                    module_order=i + 1
                )
                
                db.session.add(learning_module)
                modules_created.append({
                    'title': learning_module.title,
                    'concept_area': learning_module.concept_area,
                    'order': learning_module.module_order
                })
            
            db.session.commit()
            
            return {
                'success': True,
                'learning_plan_id': learning_plan.id,
                'plan_title': learning_plan.title,
                'total_modules': learning_plan.total_modules,
                'modules': modules_created
            }
            
        except Exception as e:
            db.session.rollback()
            print(f"Error generating learning plan: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def _generate_module_content(module_data, note_content, weak_areas):
        """Generate detailed educational content for a learning module"""
        
        try:
            content_prompt = f"""
            Create educational content for this learning module:
            
            Module Title: {module_data.get('title', 'Learning Module')}
            Learning Objectives: {', '.join(module_data.get('objectives', []))}
            Key Concepts: {', '.join(module_data.get('key_concepts', []))}
            Teaching Approach: {module_data.get('teaching_approach', 'Clear explanations with examples')}
            
            Student's weak areas: {', '.join(weak_areas)}
            
            Reference material from student's notes:
            {note_content[:1000]}
            
            Create comprehensive educational content that:
            1. Explains concepts clearly with examples
            2. Addresses the student's specific weak areas
            3. Uses analogies and real-world applications
            4. Includes step-by-step breakdowns
            5. Is engaging and easy to understand
            6. Takes 15-20 minutes to read and understand
            
            Structure the content with:
            - Introduction to the concept
            - Detailed explanation with examples
            - Common misconceptions and how to avoid them
            - Practical applications
            - Key takeaways
            
            Make it conversational and encouraging, as if you're a patient tutor.
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": content_prompt}],
                temperature=0.7,
                max_tokens=1200
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            # Fallback content
            return f"""
            # {module_data.get('title', 'Learning Module')}
            
            ## Learning Objectives
            {chr(10).join('• ' + obj for obj in module_data.get('objectives', ['Master key concepts']))}
            
            ## Key Concepts to Master
            {chr(10).join('• ' + concept for concept in module_data.get('key_concepts', ['Core concepts']))}
            
            ## What You'll Learn
            This module focuses on helping you understand and master the concepts you've been struggling with. 
            We'll break down complex ideas into manageable pieces and provide plenty of examples.
            
            ## Let's Get Started
            Take your time with this material. Understanding is more important than speed.
            
            *Detailed content will be generated based on your specific learning needs.*
            """
    
    @staticmethod
    def _create_fallback_plan(weak_areas, note_title):
        """Create a basic learning plan structure if AI generation fails"""
        
        modules = []
        
        # Create modules based on weak areas
        for i, area in enumerate(weak_areas[:4]):  # Max 4 modules
            modules.append({
                'title': f'Mastering {area.title()}',
                'objectives': [f'Understand {area}', f'Apply {area} concepts', 'Build confidence'],
                'key_concepts': [area, 'related concepts', 'practical applications'],
                'teaching_approach': 'Step-by-step explanation with examples',
                'difficulty_level': 'intermediate'
            })
        
        # Add a review module
        if modules:
            modules.append({
                'title': 'Comprehensive Review',
                'objectives': ['Integrate all learned concepts', 'Test understanding'],
                'key_concepts': ['synthesis', 'application', 'problem solving'],
                'teaching_approach': 'Practice problems and review',
                'difficulty_level': 'advanced'
            })
        
        return {
            'plan_title': f'Personalized Learning Plan for {note_title}',
            'plan_description': 'A focused plan to address your learning gaps and strengthen weak areas',
            'estimated_duration': f'{len(modules) * 20} minutes',
            'modules': modules or [{
                'title': 'Foundation Review',
                'objectives': ['Review core concepts', 'Build understanding'],
                'key_concepts': ['fundamentals'],
                'teaching_approach': 'Comprehensive overview',
                'difficulty_level': 'beginner'
            }]
        }
    
    @staticmethod
    def generate_module_quiz(module_id, user_id):
        """Generate a quiz for a completed learning module"""
        
        try:
            module = LearningModule.query.get(module_id)
            if not module or module.learning_plan.user_id != user_id:
                raise ValueError("Module not found or access denied")
            
            # Generate quiz questions based on module content
            quiz_prompt = f"""
            Create a quiz to test understanding of this learning module:
            
            Module Title: {module.title}
            Module Content: {module.content[:1000]}...
            
            Generate 5-7 questions that test:
            1. Basic understanding of concepts
            2. Application of knowledge
            3. Critical thinking
            4. Problem-solving
            
            Mix question types:
            - Multiple choice (3-4 options)
            - Short answer
            - Scenario-based questions
            
            For each question, provide:
            - The question text
            - Question type
            - Correct answer/expected response
            - Explanation of the correct answer
            
            Output as JSON:
            {{
                "questions": [
                    {{
                        "question": "Question text",
                        "type": "multiple_choice" or "short_answer",
                        "options": ["A", "B", "C", "D"] (for multiple choice only),
                        "correct_answer": "Correct answer",
                        "explanation": "Why this is correct"
                    }}
                ]
            }}
            """
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": quiz_prompt}],
                temperature=0.7,
                max_tokens=1500
            )
            
            quiz_text = response.choices[0].message.content.strip()
            
            # Extract JSON
            try:
                start_idx = quiz_text.find('{')
                end_idx = quiz_text.rfind('}') + 1
                if start_idx != -1 and end_idx != -1:
                    json_str = quiz_text[start_idx:end_idx]
                    quiz_data = json.loads(json_str)
                else:
                    raise ValueError("No valid JSON found in quiz response")
                    
            except json.JSONDecodeError:
                # Fallback quiz
                quiz_data = {
                    "questions": [
                        {
                            "question": f"What are the key concepts covered in {module.title}?",
                            "type": "short_answer",
                            "correct_answer": "Based on the module content",
                            "explanation": "This tests basic understanding of the module"
                        }
                    ]
                }
            
            # Create quiz session
            quiz_session = QuizSession(
                learning_module_id=module_id,
                user_id=user_id,
                questions=json.dumps(quiz_data['questions']),
                max_score=len(quiz_data['questions']) * 10  # 10 points per question
            )
            
            db.session.add(quiz_session)
            db.session.commit()
            
            return {
                'success': True,
                'quiz_session_id': quiz_session.id,
                'questions': quiz_data['questions'],
                'total_questions': len(quiz_data['questions'])
            }
            
        except Exception as e:
            db.session.rollback()
            print(f"Error generating module quiz: {str(e)}")
            return {'success': False, 'error': str(e)}

# Add these API routes to your app.py

# First, update the existing grade_question route to save question attempts
@app.route('/api/grade_question', methods=['POST'])
@login_required
@trial_required
def api_grade_question():
    data = request.json
    question = data.get('question', '')
    answer = data.get('answer', '')
    note_id = data.get('note_id')  # Add this to track which note the question is from
    
    prompt = (
        f"Grade this answer: '{answer}' for the question: '{question}'. "
        "Reply EXACTLY in this format:\n"
        "score: <number from 0 to 10>\n"
        "improvement: <suggestion>\n"
        "model answer: <model answer>"
    )
    
    try:
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
        
        score = float(score_match.group(1)) if score_match else 0.0
        improvement = improvement_match.group(1).strip() if improvement_match else "No suggestion."
        model_answer = model_answer_match.group(1).strip() if model_answer_match else "No model answer provided."
        
        # Save question attempt for performance analysis
        question_attempt = QuestionAttempt(
            user_id=current_user.id,
            note_id=note_id,
            question=question,
            user_answer=answer,
            score=score,
            feedback=improvement,
            model_answer=model_answer
        )
        db.session.add(question_attempt)
        db.session.commit()
        
        return jsonify({
            "grade_score": str(score),
            "improvement": improvement,
            "model_answer": model_answer
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# Performance analysis API
@app.route('/api/analyze-performance/<int:note_id>', methods=['POST'])
@login_required
@trial_required
def api_analyze_performance(note_id):
    """Analyze user performance for a specific note"""
    try:
        # Verify note ownership
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        # Perform analysis
        analysis_data = PerformanceAnalyzer.analyze_user_performance(current_user.id, note_id)
        
        return jsonify({
            'success': True,
            'analysis': analysis_data,
            'note_title': note.title
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Generate learning plan API
@app.route('/api/generate-learning-plan/<int:note_id>', methods=['POST'])
@login_required
@trial_required
def api_generate_learning_plan(note_id):
    """Generate a personalized learning plan"""
    try:
        # Verify note ownership
        note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        # Check if plan already exists
        existing_plan = LearningPlan.query.filter_by(
            user_id=current_user.id,
            note_id=note_id,
            is_active=True
        ).first()
        
        if existing_plan:
            return jsonify({
                'success': False,
                'error': 'A learning plan already exists for this note. Archive the current plan first.'
            }), 400
        
        # Analyze performance first
        analysis_data = PerformanceAnalyzer.analyze_user_performance(current_user.id, note_id)
        
        # Check if there's enough data for analysis
        if analysis_data['total_data_points'] < 5:
            return jsonify({
                'success': False,
                'error': 'Not enough performance data. Please complete more flashcards and questions first.',
                'suggestion': 'Try studying with flashcards and answering questions for this note to build up performance data.'
            }), 400
        
        # Generate learning plan
        plan_result = LearningPlanGenerator.generate_learning_plan(
            current_user.id, note_id, analysis_data
        )
        
        if not plan_result['success']:
            return jsonify(plan_result), 500
        
        return jsonify(plan_result)
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Get learning plans API
@app.route('/api/learning-plans', methods=['GET'])
@login_required
@trial_required
def api_get_learning_plans():
    """Get all learning plans for the user"""
    try:
        plans = LearningPlan.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(LearningPlan.created_at.desc()).all()
        
        plans_data = []
        for plan in plans:
            completion_percentage = (plan.completed_modules / plan.total_modules * 100) if plan.total_modules > 0 else 0
            
            plans_data.append({
                'id': plan.id,
                'title': plan.title,
                'description': plan.description,
                'note_title': plan.note.title,
                'note_id': plan.note_id,
                'total_modules': plan.total_modules,
                'completed_modules': plan.completed_modules,
                'completion_percentage': completion_percentage,
                'created_at': plan.created_at.isoformat(),
                'updated_at': plan.updated_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'learning_plans': plans_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get specific learning plan API
@app.route('/api/learning-plan/<int:plan_id>', methods=['GET'])
@login_required
@trial_required
def api_get_learning_plan(plan_id):
    """Get detailed information about a specific learning plan"""
    try:
        plan = LearningPlan.query.filter_by(
            id=plan_id,
            user_id=current_user.id
        ).first()
        
        if not plan:
            return jsonify({'error': 'Learning plan not found'}), 404
        
        modules_data = []
        for module in plan.modules:
            modules_data.append({
                'id': module.id,
                'title': module.title,
                'content': module.content,
                'concept_area': module.concept_area,
                'module_order': module.module_order,
                'is_completed': module.is_completed,
                'completed_at': module.completed_at.isoformat() if module.completed_at else None
            })
        
        return jsonify({
            'success': True,
            'plan': {
                'id': plan.id,
                'title': plan.title,
                'description': plan.description,
                'note_title': plan.note.title,
                'note_id': plan.note_id,
                'total_modules': plan.total_modules,
                'completed_modules': plan.completed_modules,
                'modules': modules_data,
                'created_at': plan.created_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Complete learning module API
@app.route('/api/complete-module/<int:module_id>', methods=['POST'])
@login_required
@trial_required
def api_complete_module(module_id):
    """Mark a learning module as completed and generate quiz"""
    try:
        module = LearningModule.query.join(LearningPlan).filter(
            LearningModule.id == module_id,
            LearningPlan.user_id == current_user.id
        ).first()
        
        if not module:
            return jsonify({'error': 'Module not found'}), 404
        
        if module.is_completed:
            return jsonify({'error': 'Module already completed'}), 400
        
        # Mark module as completed
        module.is_completed = True
        module.completed_at = datetime.utcnow()
        
        # Update learning plan progress
        plan = module.learning_plan
        plan.completed_modules += 1
        plan.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Generate quiz for this module
        quiz_result = LearningPlanGenerator.generate_module_quiz(module_id, current_user.id)
        
        return jsonify({
            'success': True,
            'message': 'Module completed successfully!',
            'quiz_generated': quiz_result['success'],
            'quiz_session_id': quiz_result.get('quiz_session_id'),
            'plan_progress': {
                'completed_modules': plan.completed_modules,
                'total_modules': plan.total_modules,
                'completion_percentage': (plan.completed_modules / plan.total_modules * 100) if plan.total_modules > 0 else 0
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Get quiz for module API
@app.route('/api/module-quiz/<int:module_id>', methods=['GET'])
@login_required
@trial_required
def api_get_module_quiz(module_id):
    """Get the quiz for a completed module"""
    try:
        # Find the quiz session for this module
        quiz_session = QuizSession.query.join(LearningModule).join(LearningPlan).filter(
            QuizSession.learning_module_id == module_id,
            LearningPlan.user_id == current_user.id,
            QuizSession.user_id == current_user.id
        ).first()
        
        if not quiz_session:
            return jsonify({'error': 'Quiz not found'}), 404
        
        questions = json.loads(quiz_session.questions)
        
        return jsonify({
            'success': True,
            'quiz_session_id': quiz_session.id,
            'questions': questions,
            'completed': quiz_session.completed,
            'score': quiz_session.total_score if quiz_session.completed else None
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Submit quiz answers API
@app.route('/api/submit-quiz/<int:quiz_session_id>', methods=['POST'])
@login_required
@trial_required
def api_submit_quiz(quiz_session_id):
    """Submit quiz answers and get results"""
    try:
        quiz_session = QuizSession.query.filter_by(
            id=quiz_session_id,
            user_id=current_user.id
        ).first()
        
        if not quiz_session:
            return jsonify({'error': 'Quiz session not found'}), 404
        
        if quiz_session.completed:
            return jsonify({'error': 'Quiz already completed'}), 400
        
        data = request.json
        user_answers = data.get('answers', [])
        
        questions = json.loads(quiz_session.questions)
        
        if len(user_answers) != len(questions):
            return jsonify({'error': 'Number of answers does not match number of questions'}), 400
        
        # Grade the quiz
        scores = []
        detailed_results = []
        
        for i, (question, user_answer) in enumerate(zip(questions, user_answers)):
            if question['type'] == 'multiple_choice':
                # Simple exact match for multiple choice
                is_correct = user_answer.strip().lower() == question['correct_answer'].strip().lower()
                score = 10 if is_correct else 0
            else:
                # Use AI to grade short answer questions
                grade_prompt = f"""
                Grade this answer for the question:
                Question: {question['question']}
                Student Answer: {user_answer}
                Expected Answer: {question['correct_answer']}
                
                Give a score from 0-10 based on correctness and completeness.
                Reply with just the number.
                """
                
                try:
                    response = client.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[{"role": "user", "content": grade_prompt}],
                        temperature=0.3,
                        max_tokens=50
                    )
                    score_text = response.choices[0].message.content.strip()
                    score = float(re.search(r'(\d+(?:\.\d+)?)', score_text).group(1))
                    score = min(10, max(0, score))  # Clamp between 0-10
                except:
                    score = 5  # Default partial credit if grading fails
            
            scores.append(score)
            detailed_results.append({
                'question': question['question'],
                'user_answer': user_answer,
                'correct_answer': question['correct_answer'],
                'explanation': question.get('explanation', ''),
                'score': score,
                'max_score': 10
            })
        
        # Calculate total score
        total_score = sum(scores)
        max_possible = len(questions) * 10
        percentage = (total_score / max_possible) * 100
        
        # Update quiz session
        quiz_session.user_answers = json.dumps(user_answers)
        quiz_session.scores = json.dumps(scores)
        quiz_session.total_score = total_score
        quiz_session.completed = True
        quiz_session.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'total_score': total_score,
            'max_score': max_possible,
            'percentage': percentage,
            'detailed_results': detailed_results,
            'passed': percentage >= 70  # 70% to pass
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Archive learning plan API
@app.route('/api/archive-learning-plan/<int:plan_id>', methods=['POST'])
@login_required
@trial_required
def api_archive_learning_plan(plan_id):
    """Archive a learning plan"""
    try:
        plan = LearningPlan.query.filter_by(
            id=plan_id,
            user_id=current_user.id
        ).first()
        
        if not plan:
            return jsonify({'error': 'Learning plan not found'}), 404
        
        plan.is_active = False
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Learning plan archived successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Add this route to your app.py for the learning plan UI

@app.route('/learning-plan')
@app.route('/learning-plan/<int:plan_id>')
@login_required
@trial_required
def learning_plan_ui(plan_id=None):
    """Learning plan interface"""
    if plan_id:
        # Viewing specific learning plan
        plan = LearningPlan.query.filter_by(
            id=plan_id,
            user_id=current_user.id
        ).first()
        
        if not plan:
            flash('Learning plan not found.', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('learning_plan.html', 
                             plan=plan, 
                             user=current_user)
    else:
        # Learning plan dashboard
        plans = LearningPlan.query.filter_by(
            user_id=current_user.id,
            is_active=True
        ).order_by(LearningPlan.created_at.desc()).all()
        
        return render_template('learning_plan_dashboard.html', 
                             plans=plans, 
                             user=current_user)

if __name__ == '__main__':
    app.run(debug=True)







