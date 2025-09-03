from flask import Flask, render_template, redirect, request, url_for, jsonify, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from datetime import datetime, timedelta
import os

app = Flask(__name__)


app.config['DATABASE'] = 'database.db'
app.config['SMTP_SERVER'] = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_PORT'] = int(os.getenv('SMTP_PORT', 587))
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dreek_default_secret_key')
app.config['EMAIL_ADDRESS'] = os.getenv('EMAIL_ADDRESS', 'malacai404@gmail.com')
app.config['EMAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD', 'rlelnhlpffkbvkin')


def validate_email(email):
    """Validate the format of an email address."""
    if not email or not isinstance(email, str):
        return False
    pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    return re.match(pattern, email) is not None

def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.executescript(f.read())
        db.commit()

@app.route('/')
def mainpage():
    return render_template('mainpage.html')

@app.route('/signup/init', methods=['POST'])
def signup_init():
    email = request.form.get('email')
    if not validate_email(email):
        flash('Invalid email', 'error')
        return redirect(url_for('mainpage'))
    
    db = get_db()
    try:
        user = db.execute(
            'SELECT verified FROM user_info WHERE email = ?',
            (email,)
        ).fetchone()
        
        if user and user['verified']:
            flash('Account already exists. Please log in with your username.', 'info')
            return redirect(url_for('login'))  
            
        session['registration_email'] = email
        return redirect(url_for('signup'))
        
    except Exception as e:
        flash('Error checking account status', 'error')
        return redirect(url_for('mainpage'))
    finally:
        db.close()

@app.route('/verify')
def verify_email():
    """Handle email verification links and redirect to login after success."""
    token = request.args.get('token')
    
   
    if not token:
        flash('Missing verification token', 'error')
        return redirect(url_for('login'))
    
    db = get_db()
    try:
        token_data = db.execute(
            '''SELECT * FROM verification_tokens 
               WHERE token = ? AND expires_at > datetime('now')''',
            (token,)
        ).fetchone()
        
        if not token_data:
            expired_token = db.execute(
                'SELECT * FROM verification_tokens WHERE token = ?',
                (token,)
            ).fetchone()
            
            if expired_token:
                flash('Verification link expired. A new one has been sent.', 'error')
                new_token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=24)
                
                db.execute(
                    'UPDATE verification_tokens SET token = ?, expires_at = ? WHERE email = ?',
                    (new_token, expires_at, expired_token['email'])
                )
                db.commit()
                
                send_confirmation_email(expired_token['email'], new_token)
                return redirect(url_for('verify_pending', email=expired_token['email']))
            else:
                flash('Invalid verification link', 'error')
                return redirect(url_for('login'))
        
        db.execute(
            'UPDATE user_info SET verified = 1 WHERE email = ?',
            (token_data['email'],)
        )
        
        db.execute(
            'DELETE FROM verification_tokens WHERE token = ?',
            (token,)
        )
        db.commit()
        
        user = db.execute(
            'SELECT username FROM user_info WHERE email = ?',
            (token_data['email'],)
        ).fetchone()
        
        flash(
            f'Email verified successfully! Welcome {user["username"]}. You can now log in.',
            'success'
        )
        return redirect(url_for('login'))
        
    except Exception as e:
        db.rollback()
        app.logger.error(f"Verification error: {str(e)}")
        flash('An error occurred during verification. Please try again.', 'error')
        return redirect(url_for('login'))
    finally:
        db.close()


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password or len(password) < 8:
            flash('Passwords must match and be at least 8 characters long.', 'error')
            return redirect(url_for('signup'))

        db = get_db()
        try:
            db.execute(
                'INSERT INTO user_info (username, email, password, verified) VALUES (?, ?, ?, ?)',
                (username, email, generate_password_hash(password), False)
            )
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=24)
            db.execute(
                'INSERT INTO verification_tokens (token, email, expires_at) VALUES (?, ?, ?)',
                (token, email, expires_at)
            )
            db.commit()
            send_confirmation_email(email, token)
            flash('registation successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('verify_pending'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return redirect(url_for('signup'))
        finally:
            db.close()

    return render_template('signup.html')

@app.route('/verify_pending')
def verify_pending():
    return render_template('verify_pending.html')


def send_confirmation_email(recipient_email, token):
    verification_link = url_for('verify_email', token=token, _external=True)
    
    message = MIMEMultipart()
    message['From'] = app.config['EMAIL_ADDRESS']
    message['To'] = recipient_email
    message['Subject'] = "Confirm Your Email for Dionvi"
    
    body = f"""<h2>Welcome to Dionvi!</h2>
    <p>Please click the following link to verify your email address:</p>
    <p><a href="{verification_link}">{verification_link}</a></p>
    <p>This link will expire in 24 hours.</p>"""
    message.attach(MIMEText(body, 'html'))
    
    try:
        with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
            server.ehlo()
            server.starttls()
            server.login(app.config['EMAIL_ADDRESS'], app.config['EMAIL_PASSWORD'])
            server.send_message(message)
        return True
    except Exception:
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db()
        try:
            user = db.execute(
                'SELECT user_info_id, username, email, password, verified FROM user_info WHERE username = ?', 
                (username,)
            ).fetchone()

            if not user:
                flash('Username not found', 'error')
                return redirect(url_for('login'))

            if not check_password_hash(user['password'], password):
                flash('Incorrect password', 'error')
                return redirect(url_for('login'))

            if not user['verified']:
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=24)
                db.execute(
                    'INSERT OR REPLACE INTO verification_tokens (token, email, expires_at) VALUES (?, ?, ?)',
                    (token, user['email'], expires_at)
                )
                db.commit()
                send_confirmation_email(user['email'], token)
                flash('Your account is not verified. A new verification email has been sent.', 'info')
                return redirect(url_for('verify_pending'))

            session['user_id'] = user['user_info_id']
            session['username'] = user['username']
            return redirect(url_for('mainpage'))

        except Exception as e:
            flash(f'Login error: {str(e)}', 'error')
            return redirect(url_for('login'))
        finally:
            db.close()

    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)