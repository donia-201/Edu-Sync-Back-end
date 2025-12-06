from flask import Flask, request, jsonify, make_response
import os
import json
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)

# ---- FIX 1: Enable CORS properly ----
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ---- FIX 2: Add CORS headers to all responses ----
@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# -----------------------------
# Firebase Initialization
# -----------------------------
SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

cred = credentials.Certificate(json.loads(SERVICE_ACCOUNT_JSON))
try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app(cred)

db = firestore.client()
users_ref = db.collection("users")


# -----------------------------
# GOOGLE SIGN-IN (FIXED)
# -----------------------------
@app.route("/google-signin", methods=["POST", "OPTIONS"])
def google_signin():

    # ---- FIX 3: Handle OPTIONS preflight ----
    if request.method == "OPTIONS":
        return make_response("", 200)

    data = request.get_json()
    token = data.get("token")

    if not token:
        return jsonify({"success": False, "msg": "Token missing"}), 400

    try:
        # ---- FIX 4: Correct verification for Google ID Tokens ----
        idinfo = id_token.verify_token(
            token,
            google_requests.Request(),
            audience=GOOGLE_CLIENT_ID
        )

        userid = idinfo["sub"]
        email = idinfo["email"]
        name = idinfo.get("name", "Unknown")

        # Create or update user
        user_ref = users_ref.document(userid)

        if not user_ref.get().exists:
            user_ref.set({
                "email": email,
                "name": name
            })

        return jsonify({"success": True})

    except Exception as e:
        print("Google Sign-In Error:", e)
        return jsonify({"success": False, "msg": "Invalid token"}), 400


# -----------------------------
# REST OF YOUR ROUTES (unchanged)
# -----------------------------

@app.post("/signup")
def signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()

        if not username or not email or not password:
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        if list(users_ref.where("email", "==", email).stream()):
            return jsonify({"success": False, "msg": "Email already exists"}), 400

        if list(users_ref.where("username", "==", username).stream()):
            return jsonify({"success": False, "msg": "Username already exists"}), 400

        hashed_password = generate_password_hash(password)

        users_ref.add({
            "username": username,
            "email": email,
            "password": hashed_password
        })

        return jsonify({"success": True, "msg": "User registered successfully"})

    except Exception as e:
        print("Signup error:", e)
        return jsonify({"success": False, "msg": "Server error"}), 500


@app.post("/login")
def login():
    data = request.json
    user_input = data.get("user", "").strip()
    password = data.get("password", "").strip()

    if not user_input or not password:
        return jsonify({"success": False, "msg": "All fields are required"}), 400

    query = users_ref.where("email", "==", user_input).get()

    if not query:
        query = users_ref.where("username", "==", user_input).get()

    if not query:
        return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

    user_data = query[0].to_dict()

    if not check_password_hash(user_data["password"], password):
        return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

    return jsonify({"success": True, "msg": "Login successful"})


@app.get("/")
def home():
    return "Backend with Firebase is running!"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
