import re
from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, limiter
from app.models import User, ActivityLog

bp = Blueprint('auth', __name__, url_prefix='/auth')

# --- SECURITY CONSTANTS ---
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
USERNAME_REGEX = r'^[a-zA-Z0-9_]{3,20}$' # Alphanumeric + underscore, 3-20 chars

def validate_password_strength(password):
    """
    Enforce Strong Passwords:
    - At least 12 characters
    - At least 1 Uppercase
    - At least 1 Lowercase
    - At least 1 Number
    - At least 1 Special Character
    """
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character."
    return None

def log_activity(user_id, action):
    log = ActivityLog(user_id=user_id, action=action, ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()

@bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Rate Limit: Prevent bot account creation
def register():
    if current_user.is_authenticated: return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # --- 1. STRICT VALIDATION ---
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('auth.register'))

        if not re.match(USERNAME_REGEX, username):
            flash('Username must be 3-20 characters, alphanumeric or underscore only.', 'error')
            return redirect(url_for('auth.register'))
            
        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email address format.', 'error')
            return redirect(url_for('auth.register'))

        password_error = validate_password_strength(password)
        if password_error:
            flash(password_error, 'error')
            return redirect(url_for('auth.register'))

        # --- 2. CHECK DATABASE ---
        if User.query.filter((User.username==username) | (User.email==email)).first():
            flash('Username or Email already exists.', 'error')
            return redirect(url_for('auth.register'))
        
        # --- 3. CREATE USER ---
        try:
            new_user = User(
                username=username, 
                email=email, 
                password_hash=generate_password_hash(password, method='pbkdf2:sha256')
            )
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('auth.login'))
        except Exception:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')

    return render_template('auth/register.html')

@bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute") # Rate Limit: Brute force protection
def login():
    if current_user.is_authenticated: return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Validation
        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('auth.login'))
            
        user = User.query.filter_by(email=email).first()
        
        # --- SECURE LOGIN CHECK ---
        # We use a generic error message to prevent User Enumeration
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('auth.login'))
            
        login_user(user) # Session created with HttpOnly cookie
        log_activity(user.id, "User Logged In")
        return redirect(url_for('main.dashboard'))
        
    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, "User Logged Out")
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))



# ... (at the bottom of app/routes/auth.py)
@bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Get form data and strip whitespace
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '')
        
        changes_made = False

        # --- 1. Username Update Logic ---
        if new_username and new_username != current_user.username:
            # [FIX] Enforce length check
            if len(new_username) < 3:
                flash('Username must be at least 3 characters long.', 'error')
            
            # [FIX] Enforce character check
            elif not re.match(USERNAME_REGEX, new_username):
                flash('Username must be 3-20 characters, alphanumeric or underscore only.', 'error')
            
            # Check uniqueness
            elif User.query.filter_by(username=new_username).first():
                flash('Username is already taken.', 'error')
            
            else:
                current_user.username = new_username
                flash('Username updated successfully.', 'success')
                changes_made = True
        
        # --- 2. Password Update Logic ---
        if new_password:
            # [FIX] Use the shared strong password validator function
            password_error = validate_password_strength(new_password)
            
            if password_error:
                flash(password_error, 'error')
            else:
                current_user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
                flash('Password updated successfully.', 'success')
                changes_made = True
        
        # Only commit to DB if valid changes were made
        if changes_made:
            db.session.commit()
            log_activity(current_user.id, "User updated profile")
        
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html')