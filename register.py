import os
import requests
import logging
from flask import Flask, render_template, request, redirect, flash, url_for
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, db

# ---------------------------------------------------------------------------
# SETUP & CONFIGURATION
# ---------------------------------------------------------------------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
SERVICE_ACCOUNT_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "Key.json")
SECRET_KEY = os.getenv("SECRET_KEY")

if not FIREBASE_API_KEY or not FIREBASE_DB_URL:
    raise RuntimeError("Set FIREBASE_API_KEY and FIREBASE_DB_URL in .env")

# Initialize Firebase Admin
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
        firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
        logger.info("✅ Firebase initialized successfully")
    except Exception as e:
        logger.error(f"❌ Firebase initialization failed: {e}")
        raise

# Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_SECURE'] = True  # Use True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------
def validate_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    errors = []
    if len(password) < 6:
        errors.append("Password must be at least 6 characters long")
    return errors

def normalize_role(role):
    """Normalize role names"""
    role = role.lower().strip()
    if role in ["counselor", "counsellor"]:
        return "counselor"
    return role

def normalize_class_section_name(name):
    """Normalize class and section names for consistency"""
    # Remove extra whitespace and capitalize properly
    return " ".join(word.capitalize() for word in name.strip().split())

def check_user_exists(email):
    """Check if user already exists in database"""
    try:
        users_ref = db.reference("users")
        users = users_ref.get() or {}
        for uid, user_data in users.items():
            if user_data.get("email", "").lower() == email.lower():
                return True
        return False
    except Exception as e:
        logger.error(f"Error checking user existence: {e}")
        return False

def get_existing_classes():
    """Get list of existing classes and sections"""
    try:
        classes_ref = db.reference("Classes")
        classes = classes_ref.get() or {}
        return classes
    except Exception as e:
        logger.error(f"Error fetching classes: {e}")
        return {}

# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def register():
    # Get existing classes for the form
    existing_classes = get_existing_classes()
    
    if request.method == "POST":
        # Get form data
        username = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = normalize_role(request.form.get("role", "").strip())
        assigned_class = normalize_class_section_name(request.form.get("assignedClass", "").strip())
        assigned_section = normalize_class_section_name(request.form.get("assignedSection", "").strip())

        # Validation
        errors = []
        
        if not username:
            errors.append("Name is required")
        elif len(username) < 2:
            errors.append("Name must be at least 2 characters long")
        elif len(username) > 100:
            errors.append("Name must be less than 100 characters")
        
        if not email:
            errors.append("Email is required")
        elif not validate_email(email):
            errors.append("Please enter a valid email address")
        elif check_user_exists(email):
            errors.append("A user with this email already exists")
        
        if not password:
            errors.append("Password is required")
        else:
            password_errors = validate_password(password)
            errors.extend(password_errors)
        
        if role not in ["teacher", "counselor"]:
            errors.append("Role must be either teacher or counselor")
        
        if role == "teacher":
            if not assigned_class:
                errors.append("Teachers must have an assigned class")
            if not assigned_section:
                errors.append("Teachers must have an assigned section")
        
        # If there are errors, show them and stop
        if errors:
            for error in errors:
                flash(error, "danger")
            return redirect(url_for("register"))

        # Create user in Firebase Auth
        try:
            url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }
            
            r = requests.post(url, json=payload, timeout=10)
            res = r.json()

            if "error" in res:
                error_msg = res["error"].get("message", "Unknown error")
                
                # Translate Firebase error messages
                if "EMAIL_EXISTS" in error_msg:
                    flash("This email is already registered", "danger")
                elif "WEAK_PASSWORD" in error_msg:
                    flash("Password is too weak. Please use at least 6 characters", "danger")
                elif "INVALID_EMAIL" in error_msg:
                    flash("Invalid email format", "danger")
                else:
                    flash(f"Error creating user: {error_msg}", "danger")
                
                return redirect(url_for("register"))

            uid = res["localId"]

            # Store user metadata in Firebase Realtime Database
            user_data = {
                "name": username,
                "email": email,
                "role": role,
                "createdAt": request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
                "registeredAt": int(request.environ.get('REQUEST_TIME_FLOAT', 0) * 1000)
            }
            
            # Add class/section only for teachers
            if role == "teacher":
                user_data["assignedClass"] = assigned_class
                user_data["assignedSection"] = assigned_section
                
                # Create class/section structure if it doesn't exist
                try:
                    class_section_ref = db.reference(f"Classes/{assigned_class}/{assigned_section}")
                    existing_data = class_section_ref.get()
                    
                    if existing_data is None:
                        # Initialize empty section with a placeholder
                        class_section_ref.set({
                            "_info": {
                                "createdAt": int(request.environ.get('REQUEST_TIME_FLOAT', 0) * 1000),
                                "createdBy": uid,
                                "teacherName": username,
                                "className": assigned_class,
                                "sectionName": assigned_section
                            }
                        })
                        logger.info(f"✅ Created new class/section: {assigned_class}/{assigned_section}")
                        flash(f"✅ New class '{assigned_class}' and section '{assigned_section}' created!", "success")
                    else:
                        logger.info(f"ℹ️ Class/section already exists: {assigned_class}/{assigned_section}")
                except Exception as e:
                    logger.error(f"Error creating class/section: {e}", exc_info=True)
                    # Don't fail registration if class creation fails
                    flash(f"⚠️ User registered but class/section creation had an issue", "warning")
            else:
                user_data["assignedClass"] = ""
                user_data["assignedSection"] = ""
            
            db.reference(f"users/{uid}").set(user_data)

            logger.info(f"✅ User registered successfully: {email} ({role})")
            flash(f"✅ User '{username}' registered successfully as {role}!", "success")
            
            # Clear form by redirecting
            return redirect(url_for("register"))
            
        except requests.exceptions.Timeout:
            flash("Request timed out. Please try again.", "danger")
            return redirect(url_for("register"))
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during registration: {e}")
            flash("Network error. Please check your connection and try again.", "danger")
            return redirect(url_for("register"))
        except Exception as e:
            logger.error(f"Error during registration: {e}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html", existing_classes=existing_classes)

# ---------------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return "<h1>404 - Page Not Found</h1>", 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return "<h1>500 - Internal Server Error</h1>", 500

# ---------------------------------------------------------------------------
# RUN SERVER
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5001))
    debug = os.getenv("FLASK_ENV") == "development"
    
    logger.info(f"🚀 Starting Registration Server on port {port}")
    app.run(debug=debug, host="0.0.0.0", port=port)

