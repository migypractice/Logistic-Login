from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta
import hmac

# Configure Flask to use the Template folder (Flask defaults to 'templates')
app = Flask(__name__, template_folder='Template')
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey_change_in_production_use_environment_variable')

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# User credentials (in production, use a database with hashed passwords)
USER = {
    "email": "admin@logistics.com",
    "password": "12345678"  # Minimum 8 characters
}

# Store OTP codes temporarily (in production, use Redis or database)
otp_storage = {}

# Generate secure OTP
def generate_otp():
    return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

# Verify OTP
def verify_otp(email, otp_code):
    if email in otp_storage:
        stored_data = otp_storage[email]
        if time.time() - stored_data['timestamp'] < 300:  # 5 minutes expiry
            return stored_data['otp'] == otp_code
    return False

# Sanitize input to prevent XSS
def sanitize_input(input_str):
    if not input_str:
        return ""
    # Remove potentially dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '/', '\\']
    for char in dangerous_chars:
        input_str = input_str.replace(char, '')
    return input_str.strip()

# Create secure remember me cookie
def create_remember_me_cookie(email):
    timestamp = str(int(time.time()))
    data = f"{email}:{timestamp}"
    # In production, use proper encryption
    cookie_value = hashlib.sha256(f"{data}:{app.secret_key}".encode()).hexdigest()
    return f"{email}:{cookie_value}"

# Verify remember me cookie
def verify_remember_me_cookie(cookie_value):
    try:
        parts = cookie_value.split(':')
        if len(parts) == 2:
            email, hash_value = parts
            # Verify hash (simplified - use proper encryption in production)
            expected_hash = hashlib.sha256(f"{email}:{app.secret_key}".encode()).hexdigest()
            if hmac.compare_digest(hash_value, expected_hash):
                return email
    except:
        pass
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    # Check remember me cookie
    remember_cookie = request.cookies.get('remember_me')
    if remember_cookie and 'user' not in session:
        email = verify_remember_me_cookie(remember_cookie)
        if email and email == USER['email']:
            session['user'] = email
            session['login_time'] = time.time()
            return redirect(url_for('dashboard'))
    
    # Redirect to dashboard if already logged in
    if 'user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = sanitize_input(request.form.get('email', '')).strip()
        password = request.form.get('password', '')
        
        # Debug logging (remove in production)
        print(f"Login attempt - Email: {email}, Password length: {len(password)}")
        
        # Validate email format
        if '@' not in email or '.' not in email.split('@')[1]:
            return render_template('login.html', error="Invalid email format")
        
        # Validate password length
        if len(password) < 8:
            return render_template('login.html', error="Password must be at least 8 characters")
        
        # Check credentials (case-insensitive email comparison)
        email_lower = email.lower()
        user_email_lower = USER['email'].lower()
        
        if email_lower == user_email_lower and password == USER['password']:
            # Generate OTP for 2FA
            otp_code = generate_otp()
            otp_storage[email] = {
                'otp': otp_code,
                'timestamp': time.time()
            }
            
            # Store email in session temporarily
            session['pending_email'] = email
            session['otp_attempts'] = 0
            
            # Store remember me choice
            remember_me = request.form.get('remember_me')
            if remember_me:
                session['remember_me_choice'] = True
            
            # In production, send OTP via email/SMS
            # For demo purposes, we'll show it (remove in production!)
            flash(f'🔐 Your OTP Code is: {otp_code} (This is for development only - remove in production!)', 'info')
            
            # Also print to console for easy access during development
            print(f"\n{'='*50}")
            print(f"OTP CODE FOR {email}: {otp_code}")
            print(f"{'='*50}\n")
            
            return redirect(url_for('verify_otp'))
        else:
            # More helpful error message
            if email_lower != user_email_lower:
                return render_template('login.html', error=f"Email not found. Use: {USER['email']}")
            else:
                return render_template('login.html', error="Incorrect password. Please try again.")

    return render_template('login.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_email' not in session:
        return redirect(url_for('login'))
    
    email = session['pending_email']
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip()
        
        # Limit OTP attempts
        if 'otp_attempts' not in session:
            session['otp_attempts'] = 0
        
        session['otp_attempts'] += 1
        
        if session['otp_attempts'] > 5:
            session.pop('pending_email', None)
            session.pop('otp_attempts', None)
            return render_template('login.html', error="Too many OTP attempts. Please login again.", show_otp=False)
        
        if verify_otp(email, otp_code):
            # Successful login
            session['user'] = email
            session['login_time'] = time.time()
            session['last_activity'] = time.time()
            session.pop('pending_email', None)
            session.pop('otp_attempts', None)
            
            # Handle Remember Me from original login
            remember_me = session.get('remember_me_choice', False)
            response = make_response(redirect(url_for('dashboard')))
            
            if remember_me:
                cookie_value = create_remember_me_cookie(email)
                response.set_cookie(
                    'remember_me',
                    cookie_value,
                    max_age=30*24*60*60,  # 30 days
                    httponly=True,
                    secure=False,  # Set to True in production with HTTPS
                    samesite='Lax'
                )
                session.pop('remember_me_choice', None)
            
            return response
        else:
            attempts_left = 5 - session['otp_attempts']
            return render_template('login.html', error=f"Invalid OTP code. Attempts remaining: {attempts_left}", show_otp=True)
    
    return render_template('login.html', show_otp=True)


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Check inactivity timeout (30 minutes)
    if 'last_activity' in session:
        if time.time() - session['last_activity'] > 30 * 60:  # 30 minutes
            session.clear()
            return redirect(url_for('login'))
    
    # Update last activity
    session['last_activity'] = time.time()
    
    return render_template('dashboard.html', user=session['user'])


@app.route('/logout')
def logout():
    # Secure logout - clear all session data
    email = session.get('user')
    session.clear()
    
    # Clear remember me cookie
    response = make_response(redirect(url_for('login')))
    response.set_cookie('remember_me', '', expires=0, httponly=True)
    
    # Clear OTP storage for this user
    if email and email in otp_storage:
        del otp_storage[email]
    
    return response


# Activity endpoint to reset inactivity timer
@app.route('/api/activity', methods=['POST'])
def update_activity():
    if 'user' in session:
        session['last_activity'] = time.time()
        return {'status': 'ok'}, 200
    return {'status': 'unauthorized'}, 401


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
