import os, time, logging
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import firebase_admin
from firebase_admin import credentials, db
import requests
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta

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
@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    
    if role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    elif role == "counselor":
        return redirect(url_for("counselor_dashboard"))
    else:
        flash("Unknown role. Please contact administrator.", "danger")
        return redirect(url_for("login"))

@app.route("/teacher")
@login_required
@role_required("teacher")
def teacher_dashboard():
    assigned_class = session.get("assignedClass")
    assigned_section = session.get("assignedSection")
    
    try:
        students = db.reference(f"Classes/{assigned_class}/{assigned_section}").get() or {}
        
        # Convert to list for easier template rendering
        student_list = []
        for key, data in students.items():
            data["key"] = key
            student_list.append(data)
        
        # Sort by name
        student_list.sort(key=lambda x: x.get("name", "").lower())
        
        return render_template(
            "teacher_dashboard.html",
            students=student_list,
            class_name=assigned_class,
            section_name=assigned_section,
            username=session.get("username")
        )
    except Exception as e:
        logger.error(f"Error loading teacher dashboard: {e}")
        flash("Error loading student data", "danger")
        return render_template(
            "teacher_dashboard.html",
            students=[],
            class_name=assigned_class,
            section_name=assigned_section,
            username=session.get("username")
        )

@app.route("/counselor")
@login_required
@role_required("counselor")
def counselor_dashboard():
    try:
        all_classes = db.reference("Classes").get() or {}
        
        # Restructure data for easier rendering
        structured_data = []
        classes_set = set()
        sections_set = set()
        
        for class_name, sections in all_classes.items():
            classes_set.add(class_name)
            for section_name, students in sections.items():
                sections_set.add(section_name)
                for key, student_data in students.items():
                    student_data["key"] = key
                    student_data["className"] = class_name
                    student_data["sectionName"] = section_name
                    structured_data.append(student_data)
        
        # Sort by class, section, then name
        structured_data.sort(key=lambda x: (
            x.get("className", ""),
            x.get("sectionName", ""),
            x.get("name", "").lower()
        ))
        
        # Convert sets to sorted lists for template
        classes_list = sorted(list(classes_set))
        sections_list = sorted(list(sections_set))
        
        return render_template(
            "counselor_dashboard.html",
            all_students=structured_data,
            classes=classes_list,
            sections=sections_list,
            username=session.get("username")
        )
    except Exception as e:
        logger.error(f"Error loading counselor dashboard: {e}")
        flash("Error loading student data", "danger")
        return render_template(
            "counselor_dashboard.html",
            all_students=[],
            classes=[],
            sections=[],
            username=session.get("username")
        )

# ---------------------------------------------------------------------------
# 8️⃣ STUDENT MANAGEMENT (ADD / EDIT / DELETE)
# ---------------------------------------------------------------------------
@app.route("/add_student", methods=["GET", "POST"])
@login_required
def add_student():
    if request.method == "POST":
        # Determine target class/section
        if session.get("role") == "teacher":
            target_class = session.get("assignedClass")
            target_section = session.get("assignedSection")
        else:
            target_class = request.form.get("class", "").strip()
            target_section = request.form.get("section", "").strip()
            
            if not target_class or not target_section:
                flash("Please specify class and section", "warning")
                return redirect(url_for("add_student"))

        # Get form data
        form_data = {
            "name": request.form.get("name", "").strip(),
            "specialNeeds": request.form.get("specialNeeds", "").strip(),
            "progress": request.form.get("progress", "").strip(),
            "accommodations": request.form.get("accommodations", "").strip(),
            "notes": request.form.get("notes", "").strip()
        }
        
        # Validate
        errors = validate_student_data(form_data)
        if errors:
            for error in errors:
                flash(error, "danger")
            return redirect(url_for("add_student"))
        
        # Generate key and save
        key = student_key_from_name(form_data["name"])
        payload = {
            **form_data,
            "createdBy": session.get("uid"),
            "createdAt": int(time.time() * 1000),
            "lastUpdated": int(time.time() * 1000),
            "lastUpdatedBy": session.get("uid")
        }
        
        try:
            # Check if student already exists
            existing = db.reference(f"Classes/{target_class}/{target_section}/{key}").get()
            if existing:
                flash(f"Student '{form_data['name']}' already exists in {target_class}/{target_section}", "warning")
                return redirect(url_for("add_student"))
            
            db.reference(f"Classes/{target_class}/{target_section}/{key}").set(payload)
            flash(f"✅ Student '{form_data['name']}' added successfully!", "success")
            logger.info(f"Student added: {key} in {target_class}/{target_section}")
            return redirect(url_for("dashboard"))
        except Exception as e:
            logger.error(f"Error adding student: {e}")
            flash("Error adding student. Please try again.", "danger")
            return redirect(url_for("add_student"))

    return render_template(
        "add_edit_student.html",
        mode="add",
        role=session.get("role"),
        student=None
    )

@app.route("/edit_student/<class_name>/<section>/<student_key>", methods=["GET", "POST"])
@login_required
def edit_student(class_name, section, student_key):
    # Check permissions
    role = session.get("role")
    if role == "teacher":
        if class_name != session.get("assignedClass") or section != session.get("assignedSection"):
            flash("You can only edit students in your assigned class", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        student_ref = db.reference(f"Classes/{class_name}/{section}/{student_key}")
        student_data = student_ref.get()
        
        if not student_data:
            flash("Student not found", "danger")
            return redirect(url_for("dashboard"))
        
        if request.method == "POST":
            # Get form data
            form_data = {
                "name": request.form.get("name", "").strip(),
                "specialNeeds": request.form.get("specialNeeds", "").strip(),
                "progress": request.form.get("progress", "").strip(),
                "accommodations": request.form.get("accommodations", "").strip(),
                "notes": request.form.get("notes", "").strip()
            }
            
            # Validate
            errors = validate_student_data(form_data)
            if errors:
                for error in errors:
                    flash(error, "danger")
                return redirect(url_for("edit_student", class_name=class_name, section=section, student_key=student_key))
            
            # Check if name changed (key might change)
            new_key = student_key_from_name(form_data["name"])
            
            # Update payload
            payload = {
                **form_data,
                "createdBy": student_data.get("createdBy"),
                "createdAt": student_data.get("createdAt"),
                "lastUpdated": int(time.time() * 1000),
                "lastUpdatedBy": session.get("uid")
            }
            
            if new_key != student_key:
                # Name changed - move to new key
                db.reference(f"Classes/{class_name}/{section}/{new_key}").set(payload)
                db.reference(f"Classes/{class_name}/{section}/{student_key}").delete()
                flash(f"✅ Student '{form_data['name']}' updated successfully!", "success")
            else:
                # Same key - just update
                student_ref.update(payload)
                flash(f"✅ Student updated successfully!", "success")
            
            logger.info(f"Student edited: {student_key} -> {new_key}")
            return redirect(url_for("dashboard"))
        
        # GET request - show form
        student_data["key"] = student_key
        student_data["className"] = class_name
        student_data["sectionName"] = section
        
        return render_template(
            "add_edit_student.html",
            mode="edit",
            role=role,
            student=student_data
        )
    
    except Exception as e:
        logger.error(f"Error editing student: {e}")
        flash("Error loading student data", "danger")
        return redirect(url_for("dashboard"))

@app.route("/delete_student/<class_name>/<section>/<student_key>", methods=["POST"])
@login_required
def delete_student(class_name, section, student_key):
    # Check permissions
    role = session.get("role")
    if role == "teacher":
        if class_name != session.get("assignedClass") or section != session.get("assignedSection"):
            flash("You can only delete students in your assigned class", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        student_ref = db.reference(f"Classes/{class_name}/{section}/{student_key}")
        student_data = student_ref.get()
        
        if not student_data:
            flash("Student not found", "danger")
            return redirect(url_for("dashboard"))
        
        student_name = student_data.get("name", "Unknown")
        student_ref.delete()
        
        flash(f"✅ Student '{student_name}' deleted successfully", "success")
        logger.info(f"Student deleted: {student_key} from {class_name}/{section}")
        
    except Exception as e:
        logger.error(f"Error deleting student: {e}")
        flash("Error deleting student", "danger")
    
    return redirect(url_for("dashboard"))

@app.route("/view_student/<class_name>/<section>/<student_key>")
@login_required
def view_student(class_name, section, student_key):
    # Check permissions
    role = session.get("role")
    if role == "teacher":
        if class_name != session.get("assignedClass") or section != session.get("assignedSection"):
            flash("You can only view students in your assigned class", "danger")
            return redirect(url_for("dashboard"))
    
    try:
        # Log the path for debugging
        path = f"Classes/{class_name}/{section}/{student_key}"
        logger.info(f"Attempting to fetch student from path: {path}")
        
        student_data = db.reference(path).get()
        
        if not student_data:
            logger.error(f"Student not found at path: {path}")
            flash("Student not found", "danger")
            return redirect(url_for("dashboard"))
        
        # Ensure student_data is a dictionary
        if not isinstance(student_data, dict):
            logger.error(f"Invalid student data type: {type(student_data)}")
            flash("Invalid student data", "danger")
            return redirect(url_for("dashboard"))
        
        student_data["key"] = student_key
        student_data["className"] = class_name
        student_data["sectionName"] = section
        
        logger.info(f"Successfully loaded student: {student_data.get('name', 'Unknown')}")
        return render_template("view_student.html", student=student_data, role=role)
    
    except Exception as e:
        logger.error(f"Error viewing student: {e}", exc_info=True)
        flash(f"Error loading student data: {str(e)}", "danger")
        return redirect(url_for("dashboard"))

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
