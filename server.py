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

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

# -------------------------
# Host Info & UTC Configuration
# -------------------------
hostname = socket.gethostname()
host_ip = socket.gethostbyname(hostname)

# Set logging to use UTC
logging.Formatter.converter = time.gmtime 

class ApacheFormatter(logging.Formatter):
    """Custom formatter to mimic Apache Access Log format in UTC"""
    def format(self, record):
        # Apache Date Format: [10/Oct/2000:13:55:36 +0000]
        timestamp = datetime.fromtimestamp(record.created).strftime('%d/%b/%Y:%H:%M:%S +0000')
        
        # Get client IP and user info if available
        client_ip = request.remote_addr if request else "-"
        user_id = current_user.username if current_user and current_user.is_authenticated else "-"
        
        # Build the Apache-style string
        # Added [Host: {hostname}] at the end for your specific machine tracking
        return f'{client_ip} - {user_id} [{timestamp}] "{record.getMessage()}" {hostname} {host_ip}'

# -------------------------
# Logging Setup
# -------------------------
file_handler = RotatingFileHandler('access.log', maxBytes=1000000, backupCount=5)
file_handler.setFormatter(ApacheFormatter())
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

app.logger.info("SYSTEM_STARTUP - Server initialized")

# -------------------------
# Azure SQL Connection
# -------------------------
server = os.getenv("DB_SERVER")
database = os.getenv("DB_NAME")
username = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")

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
        password = request.form.get("password")

        if User.query.filter_by(username=uname).first():
            app.logger.warning(f"POST /register HTTP/1.1 400 - User {uname} exists")
            flash("User already exists")
            return redirect(url_for("register"))

        try:
            user = User(username=uname, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            app.logger.info(f"POST /register HTTP/1.1 201 - Created {uname}")
            flash("Account created")
            return redirect(url_for("login"))
        except Exception as e:
            app.logger.error(f"POST /register HTTP/1.1 500 - Error: {str(e)}")
            db.session.rollback()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uname = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=uname).first()

        if not user or not check_password_hash(user.password, password):
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

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("GET /db-init HTTP/1.1 200 - Tables verified")
        except Exception as e:
            app.logger.error(f"SYSTEM HTTP/1.1 500 - DB Error: {str(e)}")
    
    app.run(debug=True)