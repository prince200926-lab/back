import os, time
from flask import Flask, render_template, request, redirect, url_for, session, flash
import firebase_admin
from firebase_admin import credentials, db
import requests
from dotenv import load_dotenv
from functools import wraps

# ---------------------------------------------------------------------------
# 1️⃣ LOAD ENVIRONMENT
# ---------------------------------------------------------------------------
load_dotenv()
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
SERVICE_ACCOUNT_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "serviceAccountKey.json")

if not FIREBASE_API_KEY or not FIREBASE_DB_URL:
    raise RuntimeError("Set FIREBASE_API_KEY and FIREBASE_DB_URL in .env")

# ---------------------------------------------------------------------------
# 2️⃣ INITIALIZE FIREBASE ADMIN
# ---------------------------------------------------------------------------
if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})

# ---------------------------------------------------------------------------
# 3️⃣ FLASK APP SETUP
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key ="d8982ee6abda2734f45587540b4bfcd924207215eac5bb3dbd9af392549ab36e"  
app.config["SESSION_TYPE"] = "filesystem" # use default in-browser cookie sessions
# ---------------------------------------------------------------------------
# 4️⃣ FIREBASE HELPERS
# ---------------------------------------------------------------------------
def firebase_sign_in(email, password):
    #Authenticate user using Firebase REST API
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    return r.json() if r.status_code == 200 else {"error": r.json()}

def get_user_metadata(uid):
    """Fetch user info from Realtime Database"""
    return db.reference(f"users/{uid}").get() or {}

def student_key_from_name(name):
    """Generate Firebase-safe key"""
    return "".join(ch if ch.isalnum() else "_" for ch in name.strip())

# ---------------------------------------------------------------------------
# 5️⃣ AUTH & LOGIN SYSTEM
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
            flash("Enter email and password", "warning")
            return redirect(url_for("login"))

        res = firebase_sign_in(email, password)
        if "error" in res:
            flash("Login failed: " + str(res["error"]), "danger")
            return redirect(url_for("login"))

        uid = res["localId"]
        id_token = res["idToken"]
        refresh_token = res.get("refreshToken")

        # 🔍 Fetch user role and class info
        meta = get_user_metadata(uid)
        print("🔹 META FETCHED:", meta)

        if not meta:
            flash("User metadata not found in database.", "danger")
            return redirect(url_for("login"))

        # 🧠 Save user info in session
        session.clear()
        session.update({
            "uid": uid,
            "idToken": id_token,
            "refreshToken": refresh_token,
            "role": meta.get("role", "").lower(),
            "assignedClass": meta.get("assignedClass", ""),
            "assignedSection": meta.get("assignedSection", ""),
            "username": meta.get("name", ""),
        })
    
        print("UID from Firebase Auth:", uid)
        print("✅ SESSION AFTER LOGIN:", dict(session))
        flash(f"Logged in as {meta.get('role')}", "success")
        return redirect(url_for("dashboard")) 
        


    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Please log in first", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

# ---------------------------------------------------------------------------
# 6️⃣ DASHBOARDS
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required #make login needed to open
def dashboard():
    role = session.get("role")
    print("🧭 DASHBOARD SESSION:", dict(session))

    if role == "teacher":
        return redirect(url_for("teacher_dashboard"))
    elif role == "counselor" or role == "counsellor":
        return redirect(url_for("counselor_dashboard"))
    else:
        flash("Unknown role — please contact admin.", "danger")
        return redirect(url_for("login"))

@app.route("/teacher")
@login_required
def teacher_dashboard():
    if session.get("role") != "teacher":
        flash("Not authorized for teacher dashboard", "danger")
        return redirect(url_for("dashboard"))

    assigned_class = session.get("assignedClass")
    assigned_section = session.get("assignedSection")
    students = db.reference(f"Classes/{assigned_class}/{assigned_section}").get() or {}


    return render_template(
        "teacher_dashboard.html",
        students=students,
        class_name=assigned_class,
        section_name=assigned_section,
        Username=session.get("username")  # pass email if you want to display it
    )



@app.route("/counselor")
@login_required
def counselor_dashboard():
    Username = session.get("username")
    role = session.get("role")
    if role not in ["counselor", "counsellor"]:
        flash("Not authorized for counselor dashboard", "danger")
        return redirect(url_for("dashboard"))

        

    all_students = db.reference("Classes").get() or {}
    print(Username)
    return render_template("counselor_dashboard.html", all_students=all_students, Username=Username)

# ---------------------------------------------------------------------------
# 7️⃣ ADD / EDIT STUDENTS
# ---------------------------------------------------------------------------
@app.route("/add_student", methods=["GET", "POST"])
@login_required
def add_student():
    if request.method == "POST":
        if session.get("role") == "teacher":
            target_class = session.get("assignedClass")
            target_section = session.get("assignedSection")
        else:
            target_class = request.form.get("class", "").strip()
            target_section = request.form.get("section", "").strip()

        name = request.form.get("name", "").strip()
        key = student_key_from_name(name)
        payload = {
            "name": name,
            "specialNeeds": request.form.get("specialNeeds", "").strip(),
            "progress": request.form.get("progress", "").strip(),
            "accommodations": request.form.get("accommodations", "").strip(),
            "notes": request.form.get("notes", "").strip(),
            "createdBy": session.get("uid"),
            "lastUpdated": int(time.time() * 1000)
        }
        db.reference(f"Classes/{target_class}/{target_section}/{key}").set(payload)
        flash(f"Student {name} added to {target_class}/{target_section}", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_edit_student.html", role=session.get("role"))

# ---------------------------------------------------------------------------
# 8️⃣ RUN SERVER
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
#st