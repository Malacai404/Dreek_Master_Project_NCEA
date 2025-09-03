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
    try:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        return db
    except Exception as e:
        print(f"[DB ERROR] Connection failed: {str(e)}")
        raise

def init_db():
    with app.app_context():
        db = get_db()

@app.route('/')
def mainpage():
    return render_template('mainpage.html')
@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/signup/init', methods=['POST'])
def register_init():
    email = request.form.get('email')
    if not validate_email(email):
        flash('Invalid email', 'error')
        return redirect(url_for('index'))
    
    db = get_db()
    try:
        user = db.execute(
            'SELECT verified FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        
        if user and user['verified']:
            flash('Account already exists. Please log in with your username.', 'info')
            return redirect(url_for('login'))  
            
        session['registration_email'] = email
        return redirect(url_for('register'))
        
    except Exception as e:
        flash('Error checking account status', 'error')
        return redirect(url_for('index'))
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
            'UPDATE users SET verified = 1 WHERE email = ?',
            (token_data['email'],)
        )
        
        db.execute(
            'DELETE FROM verification_tokens WHERE token = ?',
            (token,)
        )
        db.commit()
        
        user = db.execute(
            'SELECT username FROM users WHERE email = ?',
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
def register():
    email = session.pop('registration_email', None) or request.args.get('email')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')  
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('register', email=email))
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register', email=email))
            
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register', email=email))
            
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            flash('Username must be 3-20 characters (letters, numbers, underscores)', 'error')
            return redirect(url_for('register', email=email))
            
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, email, password, verified) VALUES (?, ?, ?, ?)',
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
            return redirect(url_for('verify_pending', email=email))
            
        except sqlite3.IntegrityError as e:
            flash('Username or email already exists', 'error')
            return redirect(url_for('register', email=email))
        except Exception as e:
            flash(f'Registration error: {str(e)}', 'error')
            return redirect(url_for('register', email=email))
        finally:
            db.close()
    
    return render_template('register.html', prefilled_email=email)

@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)