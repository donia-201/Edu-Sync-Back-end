from flask import Blueprint, request, jsonify, redirect
from firebase_admin import firestore
from firebase_admin.firestore import FieldFilter
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests

from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI, FRONTEND_ORIGIN
from utils.firebase_config import users_ref, sessions_ref
from utils.session import create_session

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        email = data.get('email', '').strip().lower()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        study_field = data.get('study_field', '').strip()

        if not (email and username and password):
            return jsonify({"success": False, "msg": "Missing required fields"}), 400

        # Check for existing email or username
        if users_ref.where(filter=FieldFilter('email', '==', email)).get():
            return jsonify({"success": False, "msg": "Email already exists"}), 400
        if users_ref.where(filter=FieldFilter('username', '==', username)).get():
            return jsonify({"success": False, "msg": "Username already exists"}), 400

        # Hash password and create user
        hashed = generate_password_hash(password)
        user_ref = users_ref.document()
        user_ref.set({
            'username': username,
            'email': email,
            'password': hashed,
            'study_field': study_field,
            'created_at': firestore.SERVER_TIMESTAMP
        })

        token = create_session(user_ref.id, username, email)

        return jsonify({
            "success": True,
            "msg": "User created successfully",
            "token": token,
            "user": {
                "id": user_ref.id,
                "username": username,
                "email": email,
                "study_field": study_field
            }
        }), 201

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": f"Server error: {str(e)}"}), 500

@auth_bp.post("/login")
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        user_input = data.get("user", "").strip()
        password = data.get("password", "").strip()

        if not (user_input and password):
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        # Search by email first, then username
        query = users_ref.where(filter=FieldFilter("email", "==", user_input.lower())).get()
        if not query:
            query = users_ref.where(filter=FieldFilter("username", "==", user_input)).get()

        if not query:
            return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

        user_doc = query[0]
        user_data = user_doc.to_dict()
        user_id = user_doc.id

        # Verify password
        if not check_password_hash(user_data["password"], password):
            return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

        token = create_session(user_id, user_data["username"], user_data["email"])

        return jsonify({
            "success": True,
            "msg": "Login successful",
            "token": token,
            "user": {
                "id": user_id,
                "username": user_data["username"],
                "email": user_data["email"],
                "study_field": user_data.get("study_field", "")
            }
        })

    except Exception as e:
        print("Login error:", e)
        return jsonify({"success": False, "msg": f"Server error: {str(e)}"}), 500

@auth_bp.route("/google-callback")
def google_callback():
    try:
        code = request.args.get("code")
        if not code:
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_code")

        # Exchange code for token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI,
            "grant_type": "authorization_code"
        }
        r = requests.post(token_url, data=data)

        if not r.ok:
            print("Token exchange failed:", r.status_code, r.text)
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_token")

        token_response = r.json()
        google_id_token = token_response.get("id_token")
        if not google_id_token:
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_token")

        # Verify Google ID token
        idinfo = id_token.verify_oauth2_token(google_id_token, google_requests.Request(), GOOGLE_CLIENT_ID)

        email = idinfo.get("email")
        name = idinfo.get("name")
        google_user_id = idinfo.get("sub")

        # Search for user or create new
        query = users_ref.where(filter=FieldFilter("email", "==", email)).get()
        if query:
            user_doc = query[0]
            user_id = user_doc.id
            user_data = user_doc.to_dict()
            username = user_data.get("username", name)
        else:
            username = email.split("@")[0]
            user_ref = users_ref.document()
            user_ref.set({
                "username": username,
                "email": email,
                "google_id": google_user_id,
                "created_at": firestore.SERVER_TIMESTAMP,
                "auth_provider": "google"
            })
            user_id = user_ref.id

        session_token = create_session(user_id, username, email)
        return redirect(f"{FRONTEND_ORIGIN}/pages/home.html?token={session_token}")

    except Exception as e:
        print("Google callback error:", e)
        return redirect(f"{FRONTEND_ORIGIN}/?error=auth_failed")

@auth_bp.post("/logout")
def logout():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            sessions_ref.document(token).delete()
        return jsonify({"success": True, "msg": "Logged out successfully"})
    except Exception as e:
        print("Logout error:", e)
        return jsonify({"success": False, "msg": f"Logout failed: {str(e)}"}), 500

@auth_bp.get("/verify-session")
def verify_session():
    """التحقق من صلاحية الـ session"""
    try:
        from datetime import datetime, timezone
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "msg": "No token provided"}), 401

        session_doc = sessions_ref.document(token).get()
        if not session_doc.exists:
            return jsonify({"success": False, "msg": "Invalid session"}), 401

        session_data = session_doc.to_dict()
        expires_at = session_data.get("expires_at")

        if expires_at:
            if hasattr(expires_at, 'timestamp'):
                expires_at = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc).replace(tzinfo=None)
            
            if datetime.utcnow() > expires_at:
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
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": f"Verification failed: {str(e)}"}), 500