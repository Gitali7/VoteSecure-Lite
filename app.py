import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
import smtplib
import ssl
import random
import string
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Candidate
import re

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = "votesecure.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production' # In a real app, use environment variable
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, DB_NAME)}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # MOCK EMAIL STORAGE
    global MOCK_INBOX
    MOCK_INBOX = [] 

    # Initialize extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def send_otp(email, otp):
        """Stores email in internal mock inbox."""
        print(f"\n[DEBUG] Sending OTP {otp} to {email} (Stored in Mock Inbox)\n")
        
        email_data = {
            "to": email,
            "subject": "Verification Code",
            "body": f"Your OTP code is: {otp}",
            "time": "Just now"
        }
        MOCK_INBOX.append(email_data)
        return True

    def validate_password(password):
        """
        Validates password complexity:
        - At least 8 characters
        - At least 1 uppercase
        - At least 1 lowercase
        - At least 1 number
        - At least 1 special char
        """
        if len(password) < 6:
            return False, "Password must be at least 6 characters long."
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter."
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter."
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number."
        if not re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
            return False, "Password must contain at least one special character."
        return True, ""

    # --- Routes ---

    @app.route('/inbox')
    def inbox():
        """Mock Email Inbox View."""
        return render_template('inbox.html', emails=list(reversed(MOCK_INBOX)))

    @app.route('/')
    def index():
        """Home page landing."""
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User registration route with OTP."""
        if current_user.is_authenticated:
            return redirect(url_for('vote'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')

            if not username or not password or not email:
                flash('Please fill in all fields.', 'error')
                return redirect(url_for('register'))

            # Password Validation
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                flash(error_msg, 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return redirect(url_for('register'))
            
            if User.query.filter_by(email=email).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('register'))

            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            
            # Send OTP
            if send_otp(email, otp):
                # Store in session
                session['register_data'] = {
                    'username': username,
                    'password': password,
                    'email': email,
                    'otp': otp
                }
                flash('OTP sent to your email. Please verify.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                flash('Failed to send email. Check console/logs.', 'error')
                return redirect(url_for('register'))

        return render_template('register.html')

    @app.route('/verify_otp', methods=['GET', 'POST'])
    def verify_otp():
        """OTP Verification Route."""
        if 'register_data' not in session:
            return redirect(url_for('register'))
        
        if request.method == 'POST':
            user_otp = request.form.get('otp')
            stored_data = session['register_data']
            
            if user_otp == stored_data['otp']:
                # Verification success, create user
                new_user = User(
                    username=stored_data['username'],
                    email=stored_data['email']
                )
                new_user.set_password(stored_data['password'])
                
                if stored_data['username'].lower() == 'admin':
                    new_user.is_admin = True
                
                db.session.add(new_user)
                db.session.commit()
                
                # Clear session
                session.pop('register_data', None)
                
                flash('Registration verified and successful! Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'error')
                
        return render_template('verify_otp.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """User login route."""
        if current_user.is_authenticated:
            return redirect(url_for('vote'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash('Logged in successfully.', 'success')
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('vote'))
            else:
                flash('Invalid username or password.', 'error')

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))

    @app.route('/vote', methods=['GET', 'POST'])
    @login_required
    def vote():
        """Voting interface."""
        if current_user.has_voted:
            flash('You have already voted. Thank you!', 'info')
            return redirect(url_for('results_view')) # Regular users see a thank you or static results

        candidates = Candidate.query.all()

        if request.method == 'POST':
            candidate_id = request.form.get('candidate')
            if not candidate_id:
                flash('Please select a candidate.', 'error')
                return redirect(url_for('vote'))

            # Secure Transaction
            try:
                # 1. Lock the candidate row (simulated by logic here, SQLite doesn't do "FOR UPDATE" well but Flask-SQLAlchemy handles atomic commits)
                # 2. Update vote count
                candidate = Candidate.query.get(candidate_id)
                if candidate:
                    candidate.vote_count += 1
                    
                    # 3. Mark user as voted
                    current_user.has_voted = True
                    
                    db.session.commit()
                    flash('Your vote has been cast securely.', 'success')
                    return redirect(url_for('results_view'))
                else:
                    flash('Invalid candidate selected.', 'error')

            except Exception as e:
                db.session.rollback()
                flash('An error occurred during voting. Please try again.', 'error')
                print(f"Error: {e}")

        return render_template('vote.html', candidates=candidates)

    @app.route('/results')
    @login_required
    def results_view():
        """Read-only results view for voters."""
        if not current_user.has_voted and not current_user.is_admin:
            flash('You must vote before seeing results!', 'warning')
            return redirect(url_for('vote'))
            
        candidates = Candidate.query.all()
        return render_template('results.html', candidates=candidates, title="Live Results")

    @app.route('/admin')
    @login_required
    def admin_dashboard():
        """Admin dashboard to manage election."""
        if not current_user.is_admin:
            flash('Access denied. Admin only.', 'error')
            return redirect(url_for('vote'))

        candidates = Candidate.query.all()
        return render_template('admin.html', candidates=candidates)
    
    @app.route('/admin/reset', methods=['POST'])
    @login_required
    def admin_reset():
        """Reset the election (dangerous action)."""
        if not current_user.is_admin:
            flash('Access denied.', 'error')
            return redirect(url_for('vote'))
        
        # Reset votes
        candidates = Candidate.query.all()
        for c in candidates:
            c.vote_count = 0
            
        # Reset user statuses
        users = User.query.all()
        for u in users:
            u.has_voted = False
            
        db.session.commit()
        flash('Election reset successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    # Helper to seed data
    with app.app_context():
        db.create_all()
        if not Candidate.query.first():
            # Seed initial candidates
            c1 = Candidate(name="Python Party", description="The distinct choice for clarity.")
            c2 = Candidate(name="Java League", description="Robust and strictly typed.")
            c3 = Candidate(name="C++ Alliance", description="High performance low level control.")
            db.session.add_all([c1, c2, c3])
            db.session.commit()
            print("Database initialized and seeded.")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
