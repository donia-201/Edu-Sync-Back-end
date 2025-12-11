from flask import Flask, request, jsonify, redirect
import os
import json
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from firebase_admin.firestore import FieldFilter
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)

# Use a specific origin for CORS
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://edu-sync-gold.vercel.app")
CORS(app, resources={r"/*": {"origins": FRONTEND_ORIGIN}}, supports_credentials=True)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Initialize Firebase
SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://edu-sync-back-end-production.up.railway.app/google-callback")

if SERVICE_ACCOUNT_JSON:
    try:
        cred = credentials.Certificate(json.loads(SERVICE_ACCOUNT_JSON))
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
    except Exception as e:
        print("Firebase initialization error:", e)
else:
    print("Warning: FIREBASE_SERVICE_ACCOUNT_JSON not provided.")

db = firestore.client()
users_ref = db.collection("users")
sessions_ref = db.collection("sessions")

def generate_session_token():
    """Generate a secure random session token"""
    return secrets.token_urlsafe(32)

def create_session(user_id, username, email, days_valid=7):
    """Create a session in Firestore and return token"""
    token = generate_session_token()
    session_data = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "created_at": firestore.SERVER_TIMESTAMP,
        "expires_at": datetime.utcnow() + timedelta(days=days_valid)
    }
    sessions_ref.document(token).set(session_data)
    return token

@app.route('/signup', methods=['POST'])
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

@app.post("/login")
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

@app.route("/google-callback")
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

@app.post("/logout")
def logout():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            sessions_ref.document(token).delete()
        return jsonify({"success": True, "msg": "Logged out successfully"})
    except Exception as e:
        print("Logout error:", e)
        return jsonify({"success": False, "msg": f"Logout failed: {str(e)}"}), 500

@app.get("/verify-session")
def verify_session():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "msg": "No token provided"}), 401

        session_doc = sessions_ref.document(token).get()
        if not session_doc.exists:
            return jsonify({"success": False, "msg": "Invalid session"}), 401

        session_data = session_doc.to_dict()
        expires_at = session_data.get("expires_at")

        if expires_at and datetime.utcnow() > expires_at:
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
        return jsonify({"success": False, "msg": f"Verification failed: {str(e)}"}), 500

@app.get("/")
def home():
    return "Backend with Firebase is running!"

@app.get("/recommended-videos")
def recommended_videos():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        study_field = None

        if token:
            session_doc = sessions_ref.document(token).get()
            if session_doc.exists:
                session_data = session_doc.to_dict()
                user_id = session_data.get("user_id")
                user_doc = users_ref.document(user_id).get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    study_field = user_data.get("study_field", "").strip().lower()

        STUDY_FIELD_KEYWORDS = {
            "architecture": ["architecture tutorial", "architectural design", "building design"],
            "ai": ["artificial intelligence course", "machine learning tutorial", "deep learning"],
            "biology": ["biology lecture", "molecular biology", "genetics tutorial"],
            "business administration": ["business management", "MBA course", "entrepreneurship"],
            "chemistry": ["chemistry lecture", "organic chemistry", "chemistry tutorial"],
            "computer science": ["computer science course", "programming tutorial", "data structures"],
            "cyber security": ["cybersecurity tutorial", "ethical hacking", "network security"],
            "data science": ["data science course", "python data analysis", "statistics tutorial"],
            "education": ["teaching methods", "educational psychology", "pedagogy"],
            "engineering": ["engineering tutorial", "mechanical engineering", "civil engineering"],
            "graphic design": ["graphic design tutorial", "adobe photoshop", "design principles"],
            "law": ["law lecture", "legal studies", "constitutional law"],
            "marketing": ["digital marketing", "marketing strategy", "social media marketing"],
            "mathematics": ["mathematics course", "calculus tutorial", "algebra"],
            "medicine": ["medical lecture", "anatomy tutorial", "physiology course"],
            "pharmacy": ["pharmacy course", "pharmacology", "pharmaceutical sciences"],
            "physics": ["physics lecture", "quantum physics", "physics tutorial"],
            "psychology": ["psychology course", "cognitive psychology", "behavioral psychology"],
            "statistics": ["statistics course", "statistical analysis", "probability theory"],
            "frontend": ["frontend development", "html css javascript", "react tutorial", "web design"],
            "backend": ["backend development", "node.js tutorial", "express js course", "databases mysql mongodb"]
        }

        default_topics = [
            "programming tutorial", "mathematics lesson", "science education",
            "language learning", "history explained", "physics tutorial",
            "chemistry lesson", "biology education"
        ]

        search_queries = STUDY_FIELD_KEYWORDS.get(study_field, default_topics) if study_field else default_topics
        if study_field and study_field not in STUDY_FIELD_KEYWORDS:
            search_queries = [f"{study_field} tutorial", f"{study_field} course", f"{study_field} lecture", f"learn {study_field}"]

        import random
        search_query = random.choice(search_queries)

        max_results = request.args.get("max", "20")
        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            return jsonify({"error": "YouTube API key not configured"}), 500

        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": max_results,
            "q": search_query,
            "videoCategoryId": "27",
            "safeSearch": "strict",
            "videoEmbeddable": "true",
            "order": "relevance",
            "key": YT_KEY
        }

        r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=15)
        if not r.ok:
            try:
                err = r.json()
            except:
                err = {"text": r.text}
            return jsonify({"error": "YouTube API error", "status": r.status_code, "details": err}), 502

        data = r.json()
        items = data.get("items", [])

        allowed_keywords = [
            "tutorial", "course", "learn", "education", "explain", "lesson", "how to", 
            "guide", "teaching", "study", "lecture", "class", "training", "beginner", 
            "advanced", "شرح", "تعليم", "محاضرة", "دورة", "كورس", "درس"
        ]

        def is_educational(item):
            title = item["snippet"]["title"].lower()
            description = item["snippet"]["description"].lower()
            return any(kw in title or kw in description for kw in allowed_keywords)

        filtered_items = [i for i in items if is_educational(i)]

        return jsonify({
            "items": filtered_items,
            "total": len(filtered_items),
            "search_query": search_query,
            "study_field": study_field if study_field else "general",
            "field_type": "predefined" if study_field in STUDY_FIELD_KEYWORDS else ("custom" if study_field else "general")
        })

    except Exception as e:
        print("recommended_videos error:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.get("/youtube-search")
def youtube_search():
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            return jsonify({"error": "YouTube API key not configured"}), 500

        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": max_results,
            "q": q,
            "videoCategoryId": "27",
            "safeSearch": "strict",
            "videoEmbeddable": "true",
            "order": "relevance",
            "key": YT_KEY
        }

        r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=15)
        if not r.ok:
            try:
                err = r.json()
            except:
                err = {"text": r.text}
            return jsonify({"error": "YouTube API error", "status": r.status_code, "details": err}), 502

        data = r.json()
        items = data.get("items", [])

        allowed_keywords = [
            "tutorial", "course", "learn", "education", "explain", "lesson", "how to",
            "شرح", "تعليم", "محاضرة"
        ]

        def is_educational(item):
            title = item["snippet"]["title"].lower()
            description = item["snippet"]["description"].lower()
            return any(kw in title or kw in description for kw in allowed_keywords)

        filtered_items = [i for i in items if is_educational(i)]
        if not filtered_items:
            filtered_items = items

        return jsonify({
            "items": filtered_items,
            "total": len(filtered_items),
            "original_total": len(items)
        })

    except requests.exceptions.Timeout:
        print("YouTube API request timed out")
        return jsonify({"error": "YouTube API timeout"}), 504
    except requests.exceptions.RequestException as e:
        print(f"Network error: {str(e)}")
        return jsonify({"error": "Network error", "details": str(e)}), 503
    except Exception as e:
        print(f"youtube_search error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)