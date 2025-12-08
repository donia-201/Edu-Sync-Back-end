from flask import Flask, request, jsonify, make_response, redirect
import os
import json
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://edu-sync-back-end-production.up.railway.app/google-callback"

cred = credentials.Certificate(json.loads(SERVICE_ACCOUNT_JSON))
try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app(cred)

db = firestore.client()
users_ref = db.collection("users")
sessions_ref = db.collection("sessions")


def generate_session_token():
    """Generate a secure random session token"""
    return secrets.token_urlsafe(32)


def create_session(user_id, username, email):
    """Create a session in Firestore and return token"""
    token = generate_session_token()
    session_data = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=7)
    }
    sessions_ref.document(token).set(session_data)
    return token


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

        # حفظ المستخدم في Firestore
        doc_ref = users_ref.add({
            "username": username,
            "email": email,
            "password": hashed_password,
            "created_at": datetime.utcnow()
        })

        # إنشاء session
        user_id = doc_ref[1].id
        token = create_session(user_id, username, email)

        return jsonify({
            "success": True,
            "msg": "User registered successfully",
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email
            }
        })

    except Exception as e:
        print("Signup error:", e)
        return jsonify({"success": False, "msg": "Server error"}), 500


@app.post("/login" )
def login():
    try:
        data = request.json
        user_input = data.get("user", "").strip()
        password = data.get("password", "").strip()

        if not user_input or not password:
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        # البحث بالـ email أولاً
        query = list(users_ref.where("email", "==", user_input).stream())

        # لو مش موجود، ابحث بالـ username
        if not query:
            query = list(users_ref.where("username", "==", user_input).stream())

        if not query:
            return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

        user_doc = query[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id

        # التحقق من الـ password
        if not check_password_hash(user_data["password"], password):
            return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

        # إنشاء session
        token = create_session(user_id, user_data["username"], user_data["email"])

        return jsonify({
            "success": True,
            "msg": "Login successful",
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data["username"],
                "email": user_data["email"]
            }
        })

    except Exception as e:
        print("Login error:", e)
        return jsonify({"success": False, "msg": "Server error"}), 500


@app.route("/google-callback")
def google_callback():
    try:
        code = request.args.get("code")
        if not code:
            return redirect("https://edu-sync-gold.vercel.app/?error=no_code")

        # استبدال الـ code بـ token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        r = requests.post(token_url, data=data)
        token_response = r.json()

        google_id_token = token_response.get("id_token")

        if not google_id_token:
            return redirect("https://edu-sync-gold.vercel.app/?error=no_token")

        # فك تشفير الـ Google token
        idinfo = id_token.verify_oauth2_token(
            google_id_token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )

        email = idinfo.get("email")
        name = idinfo.get("name")
        google_user_id = idinfo.get("sub")

        # البحث عن المستخدم أو إنشاء حساب جديد
        query = list(users_ref.where("email", "==", email).stream())

        if query:
            # المستخدم موجود
            user_doc = query[0]
            user_id = user_doc.id
            user_data = user_doc.to_dict()
            username = user_data.get("username", name)
        else:
            # إنشاء مستخدم جديد
            username = email.split("@")[0]  # استخدام اسم من الـ email
            doc_ref = users_ref.add({
                "username": username,
                "email": email,
                "google_id": google_user_id,
                "created_at": datetime.utcnow(),
                "auth_provider": "google"
            })
            user_id = doc_ref[1].id

        # إنشاء session
        session_token = create_session(user_id, username, email)

        return redirect(f'https://edu-sync-gold.vercel.app/pages/home.html?token={session_token}')

    except Exception as e:
        print("Google callback error:", e)
        return redirect("https://edu-sync-gold.vercel.app/?error=auth_failed")


@app.post("/logout")
def logout():
    """حذف الـ session"""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            sessions_ref.document(token).delete()
        return jsonify({"success": True, "msg": "Logged out successfully"})
    except Exception as e:
        print("Logout error:", e)
        return jsonify({"success": False, "msg": "Logout failed"}), 500


@app.get("/verify-session" )
def verify_session():
    """ check validation of session"""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "msg": "No token provided"}), 401

        session_doc = sessions_ref.document(token).get()
        if not session_doc.exists:
            return jsonify({"success": False, "msg": "Invalid session"}), 401

        session_data = session_doc.to_dict()
        
        # التحقق من انتهاء الصلاحية
        if session_data["expires_at"] < datetime.utcnow():
            sessions_ref.document(token).delete()
            return jsonify({"success": False, "msg": "Session expired"}), 401

        return jsonify({
            "success": True,
            "user": {
                "id": session_data["user_id"],
                "username": session_data["username"],
                "email": session_data["email"]
            }
        })

    except Exception as e:
        print("Verify session error:", e)
        return jsonify({"success": False, "msg": "Verification failed"}), 500


@app.get("/")
def home():
    return "Backend with Firebase is running!"


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)