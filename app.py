import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Candidate

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_NAME = "votesecure.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production' # In a real app, use environment variable
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, DB_NAME)}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Routes ---

    @app.route('/')
    def index():
        """Home page landing."""
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User registration route."""
        if current_user.is_authenticated:
            return redirect(url_for('vote'))

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if not username or not password:
                flash('Please fill in all fields.', 'error')
                return redirect(url_for('register'))

            if User.query.filter_by(username=username).first():
                flash('Username already exists.', 'error')
                return redirect(url_for('register'))

            new_user = User(username=username)
            new_user.set_password(password)
            
            # For demonstration: if username is 'admin', verify as admin
            if username.lower() == 'admin':
                new_user.is_admin = True

            db.session.add(new_user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

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
