import os
import requests
from flask import Flask, render_template, request, redirect, flash
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, db

# Load environment variables
load_dotenv()

FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
SERVICE_ACCOUNT_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "Key.json")

if not FIREBASE_API_KEY or not FIREBASE_DB_URL:
    raise RuntimeError("Set FIREBASE_API_KEY and FIREBASE_DB_URL in .env")

# Initialize Firebase Admin
if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})

# Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "super-secret-key")

# Registration Route
@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()  # teacher / counselor
        assigned_class = request.form.get("assignedClass", "").strip()
        assigned_section = request.form.get("assignedSection", "").strip()

        # Validation
        if not email or not password or not username or role not in ["teacher", "counselor"]:
            flash("All fields required and role must be teacher or counselor", "danger")
            return redirect("/")

        # Create user in Firebase Auth
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        r = requests.post(url, json=payload)
        res = r.json()

        if "error" in res:
            flash("Error creating user: " + str(res["error"]["message"]), "danger")
            return redirect("/")

        uid = res["localId"]

        # Store user metadata in Firebase Realtime Database
        db.reference(f"users/{uid}").set({
            "username": username,
            "email": email,
            "password": password,
            "role": role,
            "assignedClass": assigned_class if role == "teacher" else "",
            "assignedSection": assigned_section if role == "teacher" else ""
        })

        flash(f"User {username} registered successfully as {role}", "success")
        return redirect("/")

    return render_template("register.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5001)))
