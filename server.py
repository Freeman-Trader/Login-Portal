import os
import logging
import socket
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# -------------------------
# Host Info & UTC Configuration
# -------------------------
hostname = socket.gethostname()
host_ip = socket.gethostbyname(hostname)

@app.context_processor
def inject_host_info():
    return dict(host_name=hostname, host_ip=host_ip)

# Set logging to use UTC
logging.Formatter.converter = time.gmtime 

# -------------------------
# Custom Apache Formatters
# -------------------------
class ApacheAccessFormatter(logging.Formatter):
    """Mimics Apache Access Log: 127.0.0.1 - user [10/Oct/2000:13:55:36 +0000] \"...\""""
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime('%d/%b/%Y:%H:%M:%S +0000')
        client_ip = request.remote_addr if request else "-"
        user_id = current_user.username if (current_user and current_user.is_authenticated) else "-"
        return f'{client_ip} - {user_id} [{timestamp}] "{record.getMessage()}" {hostname} {host_ip}'

class ApacheErrorFormatter(logging.Formatter):
    """Mimics Apache Error Log: [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] Message"""
    def format(self, record):
        timestamp = datetime.fromtimestamp(record.created).strftime('%a %b %d %H:%M:%S %Y')
        client_ip = request.remote_addr if request else "system"
        level = record.levelname.lower()
        return f'[{timestamp}] [{level}] [client {client_ip}] {record.getMessage()} (Host: {hostname} {host_ip})'

# -------------------------
# Logging Setup
# -------------------------
# 1. Access Log (INFO and above)
access_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
access_handler.setLevel(logging.INFO)
access_handler.setFormatter(ApacheAccessFormatter())

# 2. Error Log (ERROR and above)
error_handler = RotatingFileHandler('error.log', maxBytes=1000000, backupCount=5)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(ApacheErrorFormatter())

# Configure Flask app logger
app.logger.addHandler(access_handler)
app.logger.addHandler(error_handler)
app.logger.setLevel(logging.INFO)

app.logger.info("SYSTEM_STARTUP - Server initialized")

# -------------------------
# Azure SQL Connection
# -------------------------
server = os.getenv("DB_SERVER")
database = os.getenv("DB_NAME")
username = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")

# Ensure you have the 'ODBC Driver 18 for SQL Server' installed in your environment
connection_string = (
    f"mssql+pyodbc://{username}:{password}@{server}/{database}"
    "?driver=ODBC+Driver+18+for+SQL+Server"
    "&Encrypt=yes"
    "&TrustServerCertificate=no"
    "&Connection+Timeout=30"
)

app.config['SQLALCHEMY_DATABASE_URI'] = connection_string
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -------------------------
# Model
# -------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -------------------------
# Routes
# -------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = request.form.get("username")
        pw = request.form.get("password")

        if User.query.filter_by(username=uname).first():
            app.logger.warning(f"POST /register HTTP/1.1 400 - User {uname} exists")
            flash("User already exists")
            return redirect(url_for("register"))

        try:
            user = User(username=uname, password=generate_password_hash(pw))
            db.session.add(user)
            db.session.commit()
            app.logger.info(f"POST /register HTTP/1.1 201 - Created {uname}")
            flash("Account created")
            return redirect(url_for("login"))
        except Exception as e:
            # Errors will be logged to BOTH access.log and error.log
            app.logger.error(f"POST /register HTTP/1.1 500 - Registration failed: {str(e)}")
            db.session.rollback()
            flash("An error occurred during registration.")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uname = request.form.get("username")
        pw = request.form.get("password")
        user = User.query.filter_by(username=uname).first()

        if not user or not check_password_hash(user.password, pw):
            app.logger.warning(f"POST /login HTTP/1.1 401 - Failed login: {uname}")
            flash("Invalid credentials")
            return redirect(url_for("login"))

        login_user(user)
        app.logger.info(f"POST /login HTTP/1.1 200 - User {uname} logged in")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    uname = current_user.username
    logout_user()
    app.logger.info(f"GET /logout HTTP/1.1 200 - User {uname} logged out")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)

# -------------------------
# Execution
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("SYSTEM - Database tables verified")
        except Exception as e:
            app.logger.error(f"SYSTEM - Startup DB Error: {str(e)}")
    
    # Binding to 0.0.0.0 is often preferred for Docker/Cloud environments
    # Change back to host_ip if you need a specific local bind
    app.run(host='0.0.0.0', port=80)