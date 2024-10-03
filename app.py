from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_mail import Mail, Message
from flask_otp import OTP
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
import logging
import re
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a random secret key
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)  # CSRF secret key
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Use only secure cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent CSRF

# Set up email configuration
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Replace with your email server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'  # Replace with your email password
mail = Mail(app)
limiter = Limiter(app, key_func=lambda: session.get('username'))

# Initialize logging
logging.basicConfig(filename='login_attempts.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Initialize OTP for two-factor authentication
otp = OTP(app)

# Generate a key for encryption (store securely in environment variables)
key = Fernet.generate_key()  
cipher_suite = Fernet(key)

# In-memory user store (for demonstration purposes only)
users = {}
failed_logins = {}  # Track failed login attempts for lockout

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate password strength
        if not validate_password(password):
            flash("Password must be at least 12 characters long and include uppercase, lowercase, digit, and special character!", "danger")
            return redirect(url_for('register'))

        # Encrypt the password (store securely)
        encrypted_password = cipher_suite.encrypt(password.encode()).decode()
        
        users[username] = {
            'password': encrypted_password,
            'messages': [],
            'totp_secret': 'JBSWY3DPEHPK3PXP',  # Example TOTP secret
            'contacts': [],
            'login_attempts': 0,
            'is_locked': False
        }

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        captcha = request.form['captcha']

        # Log the login attempt
        logging.info(f"Login attempt: Username: {username}")

        # Check if the user exists
        if username in users:
            user = users[username]
            
            # Check if the account is locked
            if user['is_locked']:
                flash("Your account is temporarily locked due to multiple failed login attempts.", "danger")
                return redirect(url_for('login'))

            encrypted_password = user['password']
            decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()

            # Check if the decrypted password matches the input
            if decrypted_password == password and captcha == session.get('captcha_text'):
                # Send OTP after successful password validation
                otp.send_otp(username)

                # Render OTP verification page
                return render_template('verify_otp.html', username=username)

            # Log failed login attempt
            user['login_attempts'] += 1
            if user['login_attempts'] >= 5:
                user['is_locked'] = True
                flash("Your account has been locked due to multiple failed login attempts.", "danger")
            else:
                flash("Invalid credentials or CAPTCHA!", "danger")

        else:
            flash("Invalid credentials or CAPTCHA!", "danger")
        
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    username = request.form['username']
    otp_code = request.form['otp_code']

    if otp.verify_otp(username, otp_code):
        session['logged_in'] = True
        session['username'] = username
        session['last_active'] = datetime.now()  # Track last active time
        users[username]['login_attempts'] = 0  # Reset attempts on successful login
        return redirect(url_for('chat'))
    
    flash("Invalid OTP!", "danger")
    return redirect(url_for('login'))

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        message = request.form['message']
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        encrypted_message = cipher_suite.encrypt(message.encode()).decode()
        users[session['username']]['messages'].append((encrypted_message, timestamp))
        return redirect(url_for('chat'))

    # Decrypt messages for display
    decrypted_messages = [(cipher_suite.decrypt(msg[0].encode()).decode(), msg[1]) for msg in users[session['username']]['messages']]
    return render_template('chat.html', messages=decrypted_messages)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        if validate_password(new_password):
            encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()
            users[session['username']]['password'] = encrypted_password
            flash("Password updated successfully!", "success")
        else:
            flash("Password must meet the requirements!", "danger")
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/delete_message/<int:msg_index>')
def delete_message(msg_index):
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if 0 <= msg_index < len(users[session['username']]['messages']):
        users[session['username']]['messages'].pop(msg_index)
        flash("Message deleted successfully!", "success")
    else:
        flash("Invalid message index!", "danger")

    return redirect(url_for('chat'))

@app.route('/generate-captcha')
def generate_captcha():
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    captcha_text = ''.join(random.choices(characters, k=6))
    session['captcha_text'] = captcha_text

    return captcha_text  # Return the CAPTCHA text as a response

@app.route('/captcha.png')
def captcha_image():
    return app.send_static_file('captcha.png')

# Set various security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self';"
    return response

def validate_password(password):
    return (
        len(password) >= 12 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+]", password)
    )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
