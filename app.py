from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import re
import requests

from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = "index"

# CSRF protection
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Session expired or invalid form submission. Please try again.", "danger")
    return redirect(url_for("index"))

# Session timeout = 2 minutes
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=2)

# --- User Model ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.String(6))
    otp_requested_at = db.Column(db.DateTime)
    otp_request_count = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Password Strength Checker ---
def is_strong_password(password):
    return (len(password) >= 8 and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[0-9]", password) and
            re.search(r"[@$!%*?&]", password))

# --- OTP sender ---
def send_otp(user):
    now = datetime.utcnow()
    if not user.otp_requested_at or (now - user.otp_requested_at) > timedelta(hours=1):
        user.otp_request_count = 0
    if user.otp_request_count >= 2:
        flash("You can request max 2 OTPs per hour", "danger")
        return False

    otp = str(random.randint(100000, 999999))
    user.otp = otp
    user.otp_requested_at = now
    user.otp_request_count += 1
    db.session.commit()

    msg = Message("Your OTP Code", sender=app.config["MAIL_USERNAME"], recipients=[user.email])
    msg.body = f"Your OTP is: {otp}. Valid for 5 minutes."
    mail.send(msg)
    flash("OTP sent to your email!", "info")
    print(f"DEBUG: OTP for {user.email} is {otp}")  # debug
    return True

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        captcha_response = request.form.get("g-recaptcha-response")

        # Verify reCAPTCHA
        secret = app.config["RECAPTCHA_SECRET_KEY"]
        payload = {"secret": secret, "response": captcha_response}
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
        result = r.json()
        if not result.get("success"):
            flash("Invalid CAPTCHA. Please try again.", "danger")
            return redirect(url_for("index"))

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if user.verified:
                login_user(user)
                session.permanent = True
                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Please verify your email first", "warning")
        else:
            flash("Invalid credentials", "danger")
    return render_template("index.html", site_key=app.config["RECAPTCHA_SITE_KEY"])

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        if not is_strong_password(password):
            flash("Password must be at least 8 characters long, include uppercase, lowercase, number, and special character.", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        send_otp(user)
        return redirect(url_for("verify_otp", email=email))
    return render_template("register.html")

@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("register"))

    if request.method == "POST":
        otp_input = request.form["otp"]
        if otp_input == user.otp:
            user.verified = True
            user.otp = None
            db.session.commit()
            flash("Email verified! You can login now.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid OTP.", "danger")
    return render_template("verify_otp.html", email=email)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            if send_otp(user):
                return redirect(url_for("reset_password", email=email))
        else:
            flash("Email not found", "danger")
    return render_template("forgot_password.html")

@app.route("/reset_password/<email>", methods=["GET", "POST"])
def reset_password(email):
    user = User.query.filter_by(email=email).first()
    if request.method == "POST":
        otp = request.form["otp"]
        new_password = request.form["new_password"]

        if not is_strong_password(new_password):
            flash("Password must be strong (min 8 chars, upper, lower, number, special char).", "danger")
            return redirect(url_for("reset_password", email=email))

        if otp == user.otp:
            hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=8)
            user.password = hashed_password
            user.otp = None
            db.session.commit()
            flash("Password reset successfully! You can login now.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid OTP", "danger")
    return render_template("reset_password.html", email=email)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.email)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
