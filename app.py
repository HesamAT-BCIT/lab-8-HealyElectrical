from __future__ import annotations
from functools import wraps


import os
from typing import Optional, Tuple, Union

import requests
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask.typing import ResponseReturnValue

import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin.firestore import DocumentReference

import re



app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-key")

# A dummy user for the login. 
dummy_user = {
    "username": "student",
    "password": "secret"
}

# Initialize Firestore
if not firebase_admin._apps:
    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT", "serviceAccountKey.json")
    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        expected_key = (os.getenv("SENSOR_API_KEY") or "").strip()
        provided_key = (request.headers.get("X-API-Key") or "").strip()

        if not expected_key or provided_key != expected_key:
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """
    Web (HTML) identity: token stored in session after login.
    Returns dict {uid, email} or None.
    """
    token = session.get("token")
    if not token:
        return None
    try:
        decoded = auth.verify_id_token(token)
        return {"uid": decoded.get("uid"), "email": decoded.get("email")}
    except Exception:
        return None


def get_user_or_401():
    """
    API identity: Authorization: Bearer <JWT>
    Returns uid (str) OR (json, status)
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ", 1)[1].strip()
    try:
        decoded = auth.verify_id_token(token)
        uid = decoded.get("uid")
        if not uid:
            return jsonify({"error": "Unauthorized"}), 401
        return uid
    except Exception:
        return jsonify({"error": "Unauthorized"}), 401


def get_profile_doc_ref(uid: str):
    return db.collection("profiles").document(uid)


def get_profile_data(uid: str):
    doc = get_profile_doc_ref(uid).get()
    return doc.to_dict() if doc.exists else {}


def validate_profile_data(first_name: str, last_name: str, student_id: str):
    """
    Validate profile fields for BOTH web form and API.
    Rules:
      - all fields required
      - first_name/last_name <= 50 chars
      - student_id = 8 or 9 alphanumeric
    Returns: None if ok, otherwise a single error string.
    """
    errors = []

    fn = (first_name or "").strip()
    ln = (last_name or "").strip()
    sid = str(student_id or "").strip()

    if not fn or not ln or not sid:
        errors.append("All fields are required.")

    if fn and len(fn) > 50:
        errors.append("First name must be 50 characters or less.")
    if ln and len(ln) > 50:
        errors.append("Last name must be 50 characters or less.")

    if sid and not re.fullmatch(r"[A-Za-z0-9]{8,9}", sid):
        errors.append("Student ID must be exactly 8 or 9 alphanumeric characters.")

    if errors:
        return " ".join(errors)
    return None


def normalize_profile_data(first_name: str, last_name: str, student_id: str):
    """Normalize profile field values (strip whitespace, stringify student_id)."""
    return {
        "first_name": first_name.strip() if first_name else "",
        "last_name": last_name.strip() if last_name else "",
        "student_id": str(student_id).strip() if student_id else ""
    }


def require_json_content_type():
    """Ensure the request is JSON; returns an error response tuple if not."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    return None


def set_profile(uid: str, profile_data: dict[str, str], *, merge: bool):
    get_profile_doc_ref(uid).set(profile_data, merge=merge)

# --- Web Routes ---

@app.route("/")
def home():
    user = get_current_user()
    if user:
        display_name = user.get("email") or user["uid"]
        return render_template("dashboard.html", username=display_name)
    return redirect(url_for("login"))


WEB_API_KEY = os.getenv("FIREBASE_WEB_API_KEY", "")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    if not WEB_API_KEY:
        return render_template("login.html", error="Missing FIREBASE_WEB_API_KEY in .env")

    # JSON vs HTML form
    if request.is_json:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
    else:
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}

    res = requests.post(url, json=payload, timeout=10)
    if res.status_code != 200:
        print("Login error:", res.text)  # prints Firebase reason in your Flask terminal
        if request.is_json:
            # return the Firebase error info to the client (curl)
            try:
                return jsonify({"error": "Invalid credentials", "details": res.json()}), 401
            except Exception:
                return jsonify({"error": "Invalid credentials", "details": res.text}), 401
        return render_template("login.html", error="Invalid credentials")

    token = res.json().get("idToken")
    if request.is_json:
        return jsonify({"token": token}), 200

    session["token"] = token
    return redirect(url_for("home"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    # GET -> show form
    if request.method == "GET":
        return render_template("signup.html")

    # POST -> accept either HTML form or JSON
    wants_json = request.is_json
    if wants_json:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip()
        password = data.get("password") or ""
        confirm_password = data.get("confirm_password") or ""
    else:
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""

    errors = []
    if not email:
        errors.append("Email is required")
    if not password:
        errors.append("Password is required")
    if password != confirm_password:
        errors.append("Passwords do not match")

    if errors:
        if wants_json:
            return jsonify({"errors": errors}), 400
        return render_template("signup.html", error="; ".join(errors))

    try:
        # 1) Create identity in Firebase Auth
        user = auth.create_user(email=email, password=password)

        # 2) Initialize profile in Firestore using uid as Document ID
        db.collection("profiles").document(user.uid).set(
            {"email": email, "role": "user"},
            merge=True
        )

        # Success response
        if wants_json:
            return jsonify({"uid": user.uid, "email": email}), 201

        return redirect(url_for("login"))

    except auth.EmailAlreadyExistsError:
        msg = "That email is already registered."
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template("signup.html", error=msg)

    except Exception as e:
        print("Signup error:", repr(e))  # shows the real reason in the terminal
        msg = f"Signup failed: {e}"
        if wants_json:
            return jsonify({"error": msg}), 400
        return render_template("signup.html", error=msg)


@app.route("/logout")
def logout():
    session.clear()  # clears session["token"]
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for("login"))

    uid = user["uid"]

    if request.method == "GET":
        profile_data = get_profile_data(uid)
        return render_template("profile.html", profile=profile_data, error=None)

    first_name = request.form.get("first_name", "")
    last_name = request.form.get("last_name", "")
    student_id = request.form.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        profile_data = {"first_name": first_name, "last_name": last_name, "student_id": student_id}
        return render_template("profile.html", profile=profile_data, error=error)

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(uid, normalized, merge=False)
    return redirect(url_for("home"))

@app.route("/api/sensor_data", methods=["POST"])
@require_api_key
def api_sensor_data():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 415
    data = request.get_json(silent=True) or {}
    return jsonify({"message": "Sensor data received", "data": data}), 200

# --- API Routes ---

@app.get("/api/profile")
def api_get_profile():
    uid_or_response = get_user_or_401()
    if not isinstance(uid_or_response, str):
        return uid_or_response

    uid = uid_or_response
    profile_data = get_profile_data(uid)
    return jsonify({"uid": uid, "profile": profile_data}), 200


@app.post("/api/profile")
def api_create_profile():
    uid_or_response = get_user_or_401()
    if not isinstance(uid_or_response, str):
        return uid_or_response
    uid = uid_or_response

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    first_name = data.get("first_name", "")
    last_name = data.get("last_name", "")
    student_id = data.get("student_id", "")

    error = validate_profile_data(first_name, last_name, student_id)
    if error:
        return jsonify({"error": error}), 400

    normalized = normalize_profile_data(first_name, last_name, student_id)
    set_profile(uid, normalized, merge=False)
    return jsonify({"message": "Profile saved successfully", "profile": normalized}), 200


@app.put("/api/profile")
def api_update_profile():
    uid_or_response = get_user_or_401()
    if not isinstance(uid_or_response, str):
        return uid_or_response
    uid = uid_or_response

    content_error = require_json_content_type()
    if content_error:
        return content_error

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict) or not data:
        return jsonify({"errors": ["Request body cannot be empty"]}), 400

    allowed = {"first_name", "last_name", "student_id"}
    errors = []

    # 1) Whitelist: reject any unexpected fields
    for key in data.keys():
        if key not in allowed:
            errors.append(f"Field '{key}' is not allowed")

    # 2) Bounds checking
    if "first_name" in data:
        v = (data.get("first_name") or "").strip()
        if len(v) > 50:
            errors.append("first_name must be 50 characters or less")

    if "last_name" in data:
        v = (data.get("last_name") or "").strip()
        if len(v) > 50:
            errors.append("last_name must be 50 characters or less")

    if "student_id" in data:
        v = str(data.get("student_id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9]{8,9}", v):
            errors.append("student_id must be exactly 8 or 9 alphanumeric characters")

    # 3) Collect all errors
    if errors:
        return jsonify({"errors": errors}), 400

    # Build clean update (only allowed keys)
    update_data = {}
    if "first_name" in data:
        update_data["first_name"] = (data.get("first_name") or "").strip()
    if "last_name" in data:
        update_data["last_name"] = (data.get("last_name") or "").strip()
    if "student_id" in data:
        update_data["student_id"] = str(data.get("student_id") or "").strip()

    if not update_data:
        return jsonify({"errors": ["No updatable fields provided"]}), 400

    set_profile(uid, update_data, merge=True)
    return jsonify({"message": "Profile updated successfully", "profile": get_profile_data(uid)}), 200

@app.delete("/api/profile")
def api_delete_profile():
    """Delete the current user's profile."""
    user_or_response = get_user_or_401()
    if not isinstance(user_or_response, str):
        return user_or_response

    uid = user_or_response
    get_profile_doc_ref(uid).delete()
    return jsonify({"message": "Profile deleted successfully"}), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)
