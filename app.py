print("--- STARTING POWER BI VERCEL SERVER ---")

import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load local .env file for local testing (will be ignored on Vercel)
load_dotenv()

app = Flask(__name__)

# --- SECURE SESSION KEY ---
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local_development_fallback_key")

# --- VERCEL-COMPATIBLE DATABASE CONFIGURATION ---
# We write the database to the /tmp folder because the rest of Vercel's filesystem is read-only
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- FLASK-LOGIN CONFIGURATION ---
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


# --- USER MODEL (Database Table Schema) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --- ENVIRONMENT VARIABLES FOR SECURITY ---
TENANT_ID = os.environ.get("TENANT_ID")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
WORKSPACE_ID = os.environ.get("WORKSPACE_ID")


# --- POWER BI REST API HELPER FUNCTIONS ---

def get_azure_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://analysis.windows.net/powerbi/api/.default"
    }
    res = requests.post(url, data=data)
    res.raise_for_status()
    return res.json().get("access_token")

def get_all_reports(access_token):
    url = f"https://api.powerbi.com/v1.0/myorg/groups/{WORKSPACE_ID}/reports"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    return res.json().get("value", [])

def get_embed_token(access_token, report_id):
    url = f"https://api.powerbi.com/v1.0/myorg/groups/{WORKSPACE_ID}/reports/{report_id}/GenerateToken"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    body = {
        "accessLevel": "View"
    }
    res = requests.post(url, headers=headers, json=body)
    res.raise_for_status()
    return res.json().get("token")


# --- ROUTE 1: THE SECURE DASHBOARD ---
@app.route('/')
@login_required
def home():
    try:
        # Check if environment variables are configured correctly
        if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
            return "Configuration Error: Missing Environment Variables on the Server.", 500

        access_token = get_azure_access_token()
        reports = get_all_reports(access_token)
        
        if not reports:
            return "No reports found in this workspace.", 404

        selected_report_id = request.args.get('reportId')
        if not selected_report_id:
            selected_report_id = reports[0]['id']

        selected_report = next((r for r in reports if r['id'] == selected_report_id), None)
        if not selected_report:
            return "Selected report not found in this workspace.", 404

        embed_url = selected_report['embedUrl']
        embed_token = get_embed_token(access_token, selected_report_id)

        return render_template(
            "index.html",
            reports=reports,
            selected_report_id=selected_report_id,
            embed_token=embed_token,
            embed_url=embed_url,
            user=current_user
        )
    except Exception as e:
        return f"Error loading Power BI Reports: {str(e)}", 500


# --- ROUTE 2: THE LOGIN SCREEN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return render_template("login.html", error="Invalid Username or Password")
            
    return render_template("login.html")


# --- ROUTE 3: LOGOUT ROUTE ---
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# --- INITIALIZE DATABASE AND SEED DEFAULT USER ---
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('password123', method='pbkdf2:sha256')
        admin_user = User(username='admin', password_hash=hashed_password)
        db.session.add(admin_user)
        db.session.commit()
        print("--- Database successfully configured and seeded with secure admin account ---")

# Expose the WSGI app for Vercel
app = app