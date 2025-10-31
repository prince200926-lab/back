import os, time, logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import firebase_admin
from firebase_admin import credentials, db
import requests
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
from flask_cors import CORS

# ---------------------------------------------------------------------------
# 1️⃣ LOAD ENVIRONMENT & LOGGING
# ---------------------------------------------------------------------------
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
SERVICE_ACCOUNT_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "serviceAccountKey.json")
SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET= os.urandom(32)

if not FIREBASE_API_KEY or not FIREBASE_DB_URL:
    raise RuntimeError("Set FIREBASE_API_KEY and FIREBASE_DB_URL in .env")

if not SECRET_KEY:
    logger.warning("⚠️ SECRET_KEY not set! Using random key (sessions will reset on restart)")
    SECRET_KEY = os.urandom(24)

# ---------------------------------------------------------------------------
# 2️⃣ INITIALIZE FIREBASE ADMIN
# ---------------------------------------------------------------------------
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
        firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
        logger.info("✅ Firebase initialized successfully")
    except Exception as e:
        logger.error(f"❌ Firebase initialization failed: {e}")
        raise

# -------------------------------------------------------------------------
# 3️⃣ FLASK APP SETUP
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, origins=["https://eattend.netlify.app/"])
app.secret_key = SECRET_KEY
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_COOKIE_SECURE'] = True  # Use True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
def remove_https_redirect():
    if request.url.startswith("http://"):
        pass

# ---------------------------------------------------------------------------
# 4️⃣ FIREBASE HELPERS
# ---------------------------------------------------------------------------
def firebase_sign_in(email, password):
    """Authenticate user using Firebase REST API"""
    try:
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload, timeout=10)
        
        if r.status_code == 200:
            return r.json()
        else:
            error_msg = r.json().get("error", {}).get("message", "Unknown error")
            return {"error": error_msg}
    except Exception as e:
        logger.error(f"Firebase sign in error: {e}")
        return {"error": "Connection error"}

def firebase_refresh_token(refresh_token):
    """Refresh Firebase ID token"""
    try:
        url = f"https://securetoken.googleapis.com/v1/token?key={FIREBASE_API_KEY}"
        payload = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        r = requests.post(url, json=payload, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            return {
                "idToken": data.get("id_token"),
                "refreshToken": data.get("refresh_token"),
                "expiresIn": int(data.get("expires_in", 3600))
            }
        return None
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return None

def get_user_metadata(uid):
    """Fetch user info from Realtime Database"""
    try:
        return db.reference(f"users/{uid}").get() or {}
    except Exception as e:
        logger.error(f"Error fetching user metadata: {e}")
        return {}

def student_key_from_name(name):
    """Generate Firebase-safe key"""
    return "".join(ch if ch.isalnum() else "_" for ch in name.strip())

def normalize_role(role):
    """Normalize role names"""
    role = role.lower().strip()
    if role in ["counselor", "counsellor"]:
        return "counselor"
    return role

def validate_student_data(data):
    """Validate student form data"""
    errors = []
    
    if not data.get("name", "").strip():
        errors.append("Student name is required")
    elif len(data.get("name", "")) > 100:
        errors.append("Name must be less than 100 characters")
    
    if data.get("specialNeeds") and len(data.get("specialNeeds", "")) > 500:
        errors.append("Special needs must be less than 500 characters")
    
    if data.get("progress") and len(data.get("progress", "")) > 1000:
        errors.append("Progress notes must be less than 1000 characters")
    
    if data.get("accommodations") and len(data.get("accommodations", "")) > 1000:
        errors.append("Accommodations must be less than 1000 characters")
    
    if data.get("notes") and len(data.get("notes", "")) > 2000:
        errors.append("Notes must be less than 2000 characters")
    
    return errors

# ---------------------------------------------------------------------------
# 5️⃣ AUTH DECORATORS & MIDDLEWARE
# ---------------------------------------------------------------------------
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Please log in first", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

def role_required(*allowed_roles):
    """Decorator to check user role"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_role = session.get("role")
            if user_role not in allowed_roles:
                flash("You don't have permission to access this page", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)
        return wrapper
    return decorator

@app.before_request
def check_token_expiration():
    """Check if token needs refresh"""
    if session.get("uid") and request.endpoint not in ["login", "logout", "static"]:
        token_expires = session.get("tokenExpires", 0)
        current_time = time.time()
        
        # Refresh token 5 minutes before expiration
        if current_time >= (token_expires - 300):
            refresh_token = session.get("refreshToken")
            if refresh_token:
                new_tokens = firebase_refresh_token(refresh_token)
                if new_tokens:
                    session["idToken"] = new_tokens["idToken"]
                    session["refreshToken"] = new_tokens["refreshToken"]
                    session["tokenExpires"] = current_time + new_tokens["expiresIn"]
                    logger.info("✅ Token refreshed successfully")
                else:
                    logger.warning("⚠️ Token refresh failed - logging out")
                    session.clear()
                    flash("Session expired. Please log in again", "warning")
                    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# 6️⃣ AUTH & LOGIN SYSTEM
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if session.get("idToken") and session.get("uid"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Please enter both email and password", "warning")
            return redirect(url_for("login"))

        res = firebase_sign_in(email, password)
        if "error" in res:
            flash(f"Login failed: {res['error']}", "danger")
            return redirect(url_for("login"))

        uid = res["localId"]
        id_token = res["idToken"]
        refresh_token = res.get("refreshToken")
        expires_in = int(res.get("expiresIn", 3600))

        # Fetch user metadata
        meta = get_user_metadata(uid)
        
        if not meta:
            flash("User metadata not found. Please contact administrator.", "danger")
            return redirect(url_for("login"))

        # Normalize and save to session
        role = normalize_role(meta.get("role", ""))
        
        if role not in ["teacher", "counselor"]:
            flash("Invalid user role. Please contact administrator.", "danger")
            return redirect(url_for("login"))

        session.clear()
        session.permanent = True
        session.update({
            "uid": uid,
            "idToken": id_token,
            "refreshToken": refresh_token,
            "tokenExpires": time.time() + expires_in,
            "role": role,
            "assignedClass": meta.get("assignedClass", ""),
            "assignedSection": meta.get("assignedSection", ""),
            "username": meta.get("name", email.split("@")[0]),
            "email": email
        })
    
        logger.info(f"✅ User logged in: {uid} ({role})")
        flash(f"Welcome back, {session['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    username = session.get("username", "User")
    session.clear()
    flash(f"Goodbye, {username}! Logged out successfully.", "info")
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# 7️⃣ DASHBOARDS
# ---------------------------------------------------------------------------
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps
import jwt
from datetime import datetime, timedelta

# Enable CORS
app = Flask(__name__)
CORS(app, 
     origins=[
         "https://eattend.netlify.app/",  # Replace with your Netlify URL
         "http://localhost:3000",  # For local development
         "http://localhost:5000"
     ],
     supports_credentials=True)

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-this")
JWT_EXPIRATION = 12  # hours

# ---------------------------------------------------------------------------
# JWT Helper Functions
# ---------------------------------------------------------------------------
def create_token(uid, role, username, email, assigned_class="", assigned_section=""):
    """Create JWT token"""
    payload = {
        "uid": uid,
        "role": role,
        "username": username,
        "email": email,
        "assignedClass": assigned_class,
        "assignedSection": assigned_section,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    """Verify and decode JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({"success": False, "message": "Token is missing"}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        data = verify_token(token)
        if not data:
            return jsonify({"success": False, "message": "Token is invalid or expired"}), 401
        
        # Add user data to request context
        request.user = data
        return f(*args, **kwargs)
    
    return decorated

def role_required(*allowed_roles):
    """Decorator to check user role"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not hasattr(request, 'user'):
                return jsonify({"success": False, "message": "Unauthorized"}), 401
            
            user_role = request.user.get('role')
            if user_role not in allowed_roles:
                return jsonify({"success": False, "message": "Insufficient permissions"}), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------------------------------------------------------
# API ROUTES
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    """Login endpoint - returns JWT token"""
    try:
        data = request.get_json()
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()

        if not email or not password:
            return jsonify({
                "success": False,
                "message": "Please enter both email and password"
            }), 400

        # Authenticate with Firebase
        res = firebase_sign_in(email, password)
        if "error" in res:
            return jsonify({
                "success": False,
                "message": f"Login failed: {res['error']}"
            }), 401

        uid = res["localId"]
        
        # Fetch user metadata
        meta = get_user_metadata(uid)
        if not meta:
            return jsonify({
                "success": False,
                "message": "User metadata not found"
            }), 404

        role = normalize_role(meta.get("role", ""))
        if role not in ["teacher", "counselor"]:
            return jsonify({
                "success": False,
                "message": "Invalid user role"
            }), 403

        # Create JWT token
        token = create_token(
            uid=uid,
            role=role,
            username=meta.get("name", email.split("@")[0]),
            email=email,
            assigned_class=meta.get("assignedClass", ""),
            assigned_section=meta.get("assignedSection", "")
        )

        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "role": role,
            "username": meta.get("name", email.split("@")[0]),
            "assignedClass": meta.get("assignedClass", ""),
            "assignedSection": meta.get("assignedSection", "")
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during login"
        }), 500

@app.route("/api/dashboard", methods=["GET"])
@token_required
def api_dashboard():
    """Get dashboard data based on user role"""
    try:
        user = request.user
        role = user.get("role")
        
        if role == "teacher":
            assigned_class = user.get("assignedClass")
            assigned_section = user.get("assignedSection")
            
            students = db.reference(f"Classes/{assigned_class}/{assigned_section}").get() or {}
            
            student_list = []
            for key, data in students.items():
                if key != "_info" and isinstance(data, dict):
                    data["key"] = key
                    student_list.append(data)
            
            student_list.sort(key=lambda x: x.get("name", "").lower())
            
            return jsonify({
                "success": True,
                "role": "teacher",
                "students": student_list,
                "className": assigned_class,
                "sectionName": assigned_section,
                "username": user.get("username")
            }), 200
            
        elif role == "counselor":
            all_classes = db.reference("Classes").get() or {}
            
            structured_data = []
            classes_set = set()
            sections_set = set()
            
            for class_name, sections in all_classes.items():
                if not isinstance(sections, dict):
                    continue
                    
                classes_set.add(class_name)
                for section_name, students in sections.items():
                    if not isinstance(students, dict):
                        continue
                        
                    sections_set.add(section_name)
                    for key, student_data in students.items():
                        if key == "_info" or not isinstance(student_data, dict):
                            continue
                        
                        student_data["key"] = key
                        student_data["className"] = class_name
                        student_data["sectionName"] = section_name
                        structured_data.append(student_data)
            
            structured_data.sort(key=lambda x: (
                x.get("className", ""),
                x.get("sectionName", ""),
                x.get("name", "").lower()
            ))
            
            return jsonify({
                "success": True,
                "role": "counselor",
                "students": structured_data,
                "classes": sorted(list(classes_set)),
                "sections": sorted(list(sections_set)),
                "username": user.get("username")
            }), 200
        
        else:
            return jsonify({
                "success": False,
                "message": "Invalid role"
            }), 403
            
    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Error loading dashboard data"
        }), 500

@app.route("/api/students/<class_name>/<section>/<student_key>", methods=["GET"])
@token_required
def api_get_student(class_name, section, student_key):
    """Get single student details"""
    try:
        user = request.user
        role = user.get("role")
        
        # Check permissions for teachers
        if role == "teacher":
            if class_name != user.get("assignedClass") or section != user.get("assignedSection"):
                return jsonify({
                    "success": False,
                    "message": "You can only view students in your assigned class"
                }), 403
        
        student_data = db.reference(f"Classes/{class_name}/{section}/{student_key}").get()
        
        if not student_data or not isinstance(student_data, dict):
            return jsonify({
                "success": False,
                "message": "Student not found"
            }), 404
        
        student_data["key"] = student_key
        student_data["className"] = class_name
        student_data["sectionName"] = section
        
        return jsonify({
            "success": True,
            "student": student_data
        }), 200
        
    except Exception as e:
        logger.error(f"Get student error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Error loading student data"
        }), 500

@app.route("/api/students/add", methods=["POST"])
@token_required
def api_add_student():
    """Add new student"""
    try:
        user = request.user
        role = user.get("role")
        data = request.get_json()
        
        # Determine target class/section
        if role == "teacher":
            target_class = user.get("assignedClass")
            target_section = user.get("assignedSection")
        else:
            target_class = data.get("class", "").strip()
            target_section = data.get("section", "").strip()
            
            if not target_class or not target_section:
                return jsonify({
                    "success": False,
                    "message": "Please specify class and section"
                }), 400

        # Validate student data
        form_data = {
            "name": data.get("name", "").strip(),
            "specialNeeds": data.get("specialNeeds", "").strip(),
            "progress": data.get("progress", "").strip(),
            "accommodations": data.get("accommodations", "").strip(),
            "notes": data.get("notes", "").strip()
        }
        
        errors = validate_student_data(form_data)
        if errors:
            return jsonify({
                "success": False,
                "message": "; ".join(errors)
            }), 400
        
        # Generate key and save
        key = student_key_from_name(form_data["name"])
        
        # Check if student already exists
        existing = db.reference(f"Classes/{target_class}/{target_section}/{key}").get()
        if existing:
            return jsonify({
                "success": False,
                "message": f"Student '{form_data['name']}' already exists"
            }), 409
        
        payload = {
            **form_data,
            "createdBy": user.get("uid"),
            "createdAt": int(time.time() * 1000),
            "lastUpdated": int(time.time() * 1000),
            "lastUpdatedBy": user.get("uid")
        }
        
        db.reference(f"Classes/{target_class}/{target_section}/{key}").set(payload)
        
        return jsonify({
            "success": True,
            "message": f"Student '{form_data['name']}' added successfully",
            "studentKey": key
        }), 201
        
    except Exception as e:
        logger.error(f"Add student error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Error adding student"
        }), 500

@app.route("/api/students/<class_name>/<section>/<student_key>", methods=["PUT"])
@token_required
def api_update_student(class_name, section, student_key):
    """Update student"""
    try:
        user = request.user
        role = user.get("role")
        
        # Check permissions for teachers
        if role == "teacher":
            if class_name != user.get("assignedClass") or section != user.get("assignedSection"):
                return jsonify({
                    "success": False,
                    "message": "You can only edit students in your assigned class"
                }), 403
        
        student_ref = db.reference(f"Classes/{class_name}/{section}/{student_key}")
        student_data = student_ref.get()
        
        if not student_data:
            return jsonify({
                "success": False,
                "message": "Student not found"
            }), 404
        
        data = request.get_json()
        
        form_data = {
            "name": data.get("name", "").strip(),
            "specialNeeds": data.get("specialNeeds", "").strip(),
            "progress": data.get("progress", "").strip(),
            "accommodations": data.get("accommodations", "").strip(),
            "notes": data.get("notes", "").strip()
        }
        
        errors = validate_student_data(form_data)
        if errors:
            return jsonify({
                "success": False,
                "message": "; ".join(errors)
            }), 400
        
        new_key = student_key_from_name(form_data["name"])
        
        payload = {
            **form_data,
            "createdBy": student_data.get("createdBy"),
            "createdAt": student_data.get("createdAt"),
            "lastUpdated": int(time.time() * 1000),
            "lastUpdatedBy": user.get("uid")
        }
        
        if new_key != student_key:
            db.reference(f"Classes/{class_name}/{section}/{new_key}").set(payload)
            db.reference(f"Classes/{class_name}/{section}/{student_key}").delete()
        else:
            student_ref.update(payload)
        
        return jsonify({
            "success": True,
            "message": "Student updated successfully",
            "newKey": new_key
        }), 200
        
    except Exception as e:
        logger.error(f"Update student error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Error updating student"
        }), 500

@app.route("/api/students/<class_name>/<section>/<student_key>", methods=["DELETE"])
@token_required
def api_delete_student(class_name, section, student_key):
    """Delete student"""
    try:
        user = request.user
        role = user.get("role")
        
        # Check permissions for teachers
        if role == "teacher":
            if class_name != user.get("assignedClass") or section != user.get("assignedSection"):
                return jsonify({
                    "success": False,
                    "message": "You can only delete students in your assigned class"
                }), 403
        
        student_ref = db.reference(f"Classes/{class_name}/{section}/{student_key}")
        student_data = student_ref.get()
        
        if not student_data:
            return jsonify({
                "success": False,
                "message": "Student not found"
            }), 404
        
        student_name = student_data.get("name", "Unknown")
        student_ref.delete()
        
        return jsonify({
            "success": True,
            "message": f"Student '{student_name}' deleted successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Delete student error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "Error deleting student"
        }), 500

# Health check endpoint
@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({
        "status": "healthy",
        "timestamp": int(time.time())
    }), 200
# ---------------------------------------------------------------------------
# 9️⃣ ERROR HANDLERS
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return render_template("500.html"), 500

# ---------------------------------------------------------------------------
# 🔟 RUN SERVER
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV") == "development"
    
    logger.info(f"🚀 Starting Flask app on port {port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
