import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from openai import OpenAI
from authlib.integrations.flask_client import OAuth

# Load env variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecret")
app.wsgi_app = ProxyFix(app.wsgi_app)

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///study.db").replace("postgres://", "postgresql://")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# OpenAI setup
openai_api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=openai_api_key)

# Google OAuth setup
oauth = OAuth(app)
app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config["GOOGLE_DISCOVERY_URL"] = "https://accounts.google.com/.well-known/openid-configuration"

google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url="https://accounts.google.com/o/oauth2/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v1/userinfo",
    client_kwargs={"scope": "openid email profile"},
)

# ===================== MODELS ===================== #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    has_unlimited_access = db.Column(db.Boolean, default=False)

    def is_trial_expired(self):
        if self.has_unlimited_access:
            return False
        if not self.start_time:
            return False
        return (datetime.datetime.utcnow() - self.start_time).total_seconds() > 600  # 10 mins

    def get_time_remaining(self):
        if self.has_unlimited_access:
            return "Unlimited"
        if not self.start_time:
            return "10:00"
        elapsed = (datetime.datetime.utcnow() - self.start_time).total_seconds()
        remaining = max(0, 600 - elapsed)
        mins = int(remaining // 60)
        secs = int(remaining % 60)
        return f"{mins}:{secs:02d}"


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())


with app.app_context():
    db.create_all()

# ===================== HELPERS ===================== #
def current_user():
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None

def require_login():
    if not current_user():
        flash("You must log in first", "error")
        return redirect(url_for("index"))

# ===================== ROUTES ===================== #

@app.route("/")
def index():
    user = current_user()
    if user:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/login")
def login():
    redirect_uri = url_for("authorize", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/authorize")
def authorize():
    token = google.authorize_access_token()
    user_info = google.get("userinfo").json()
    email = user_info["email"]

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, start_time=datetime.datetime.utcnow())
        db.session.add(user)
    session["user_id"] = user.id
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("index"))

    notes = Note.query.filter_by(user_id=user.id).all()
    return render_template("dashboard.html", user=user, notes=notes, email=user.email)

@app.route("/enter-notes", methods=["GET", "POST"])
def enter_notes():
    user = current_user()
    if not user:
        return redirect(url_for("index"))
    if user.is_trial_expired():
        return redirect(url_for("trial_expired"))

    return render_template("enter-notes.html")

@app.route("/save-note", methods=["POST"])
def save_note():
    user = current_user()
    if not user:
        return redirect(url_for("index"))
    if user.is_trial_expired():
        return redirect(url_for("trial_expired"))

    title = request.form.get("title")
    content = request.form.get("content")
    if not title or not content:
        flash("Please provide both title and content.", "error")
        return redirect(url_for("enter_notes"))

    note = Note(user_id=user.id, title=title, content=content)
    db.session.add(note)
    db.session.commit()
    flash("Note saved successfully!", "success")
    return redirect(url_for("dashboard"))

@app.route("/view-note/<int:note_id>")
def view_note(note_id):
    user = current_user()
    if not user:
        return redirect(url_for("index"))
    note = Note.query.get_or_404(note_id)
    if note.user_id != user.id:
        flash("Unauthorized", "error")
        return redirect(url_for("dashboard"))

    return render_template("viewnote.html", title=note.title, content=note.content, note_id=note.id)

@app.route("/trial-expired", methods=["GET", "POST"])
def trial_expired():
    user = current_user()
    if not user:
        return redirect(url_for("index"))

    if request.method == "POST":
        admin_key = request.form.get("admin_key")
        if admin_key == os.getenv("ADMIN_KEY", "letmein"):
            user.has_unlimited_access = True
            db.session.commit()
            flash("Access upgraded to unlimited!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid admin key", "error")

    return render_template("trialexpired.html")

@app.route("/api/trial-status")
def trial_status():
    user = current_user()
    if not user:
        return jsonify({"expired": True})
    return jsonify({
        "expired": user.is_trial_expired(),
        "time_remaining": user.get_time_remaining(),
        "remaining_seconds": max(0, 600 - (datetime.datetime.utcnow() - user.start_time).total_seconds()) if user.start_time else 600
    })

# ===================== AI ENDPOINTS ===================== #
@app.route("/api/tutor_chat", methods=["POST"])
def tutor_chat():
    user = current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    if user.is_trial_expired():
        return jsonify({"error": "Trial expired"}), 403

    data = request.get_json()
    user_message = data.get("message", "").strip()
    if not user_message:
        return jsonify({"error": "Message cannot be empty"}), 400

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert AI tutor. Provide detailed, helpful, and accurate answers to student questions."},
                {"role": "user", "content": user_message}
            ]
        )
        ai_reply = response.choices[0].message["content"]
        return jsonify({"reply": ai_reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Run
if __name__ == "__main__":
    app.run(debug=True)
