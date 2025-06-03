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
@app.route('/signup')
def signup():
    return render_template('signup.html')
@app.route('/login')
def login():
    return render_template('login.html')

if __name__ == "__main__":
    app.run(debug=True)