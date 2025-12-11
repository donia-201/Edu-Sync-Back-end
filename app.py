# app.py
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

# Use a specific origin (recommended) — read from env or fallback to your frontend origin
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://edu-sync-gold.vercel.app")

# CORS: allow only the frontend origin (avoid "*")
CORS(app, resources={r"/*": {"origins": FRONTEND_ORIGIN}}, supports_credentials=True)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

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
        # If Firebase init fails, print and continue (will error later when used)
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
        "created_at": datetime.utcnow(),
        "expires_at": datetime.utcnow() + timedelta(days=days_valid)
    }
    sessions_ref.document(token).set(session_data)
    return token


from werkzeug.security import generate_password_hash

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')

        if not email or not username or not password:
            return jsonify({'message': 'Missing required fields'}), 400

        email_results = db.collection('users').where(
            filter=('email', '==', email)
        ).limit(1).get()
        
        if len(email_results) > 0:
            return jsonify({'message': 'Email already exists'}), 400

        username_results = db.collection('users').where(
            filter=('username', '==', username)
        ).limit(1).get()
        
        if len(username_results) > 0:
            return jsonify({'message': 'Username already exists'}), 400

        hashed_password = generate_password_hash(password)

        user_ref = db.collection('users').document()
        user_ref.set({
            'email': email,
            'username': username,
            'password': hashed_password,
            'created_at': firestore.SERVER_TIMESTAMP
        })

        return jsonify({
            'message': 'User created successfully',
            'user_id': user_ref.id
        }), 201

    except Exception as e:
        import traceback
        print(f"Signup error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'message': 'Server error'}), 500
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "").strip()
        study_field = data.get("study_field", "").strip()

        if not username or not email or not password:
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        if list(users_ref.where("email", "==", email).stream()):
            return jsonify({"success": False, "msg": "Email already exists"}), 400

        if list(users_ref.where("username", "==", username).stream()):
            return jsonify({"success": False, "msg": "Username already exists"}), 400

        hashed_password = generate_password_hash(password)

        doc_ref = users_ref.add({
            "username": username,
            "email": email,
            "password": hashed_password,
            "study_field": study_field,
            "created_at": datetime.utcnow()
        })

        user_id = doc_ref[0].id
        token = create_session(user_id, username, email)

        return jsonify({
            "success": True,
            "msg": "User registered successfully",
            "token": token,
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "study_field": study_field
            }
        })

    except Exception as e:
        print("Signup error:", e)
        return jsonify({"success": False, "msg": "Server error"}), 500


@app.post("/login")
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        user_input = data.get("user", "").strip()
        password = data.get("password", "").strip()

        if not user_input or not password:
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        # normalize input for email check
        # search by email first
        query = list(users_ref.where("email", "==", user_input.lower()).stream())

        # if not found, search by username (case-sensitive as stored)
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
                "email": user_data["email"],
                "study_field": user_data.get("study_field", "")
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
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_code")

        # exchange code for token
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

        # verify google id token
        idinfo = id_token.verify_oauth2_token(
            google_id_token, 
            google_requests.Request(), 
            GOOGLE_CLIENT_ID
        )

        email = idinfo.get("email")
        name = idinfo.get("name")
        google_user_id = idinfo.get("sub")

        # search user or create
        query = list(users_ref.where("email", "==", email).stream())

        if query:
            user_doc = query[0]
            user_id = user_doc.id
            user_data = user_doc.to_dict()
            username = user_data.get("username", name)
        else:
            username = email.split("@")[0]
            doc_ref = users_ref.add({
                "username": username,
                "email": email,
                "google_id": google_user_id,
                "created_at": datetime.utcnow(),
                "auth_provider": "google"
            })
            user_id = doc_ref[0].id

        # create session
        session_token = create_session(user_id, username, email)

        # Use POST/HttpOnly cookie ideally; for now redirect with token (existing behavior)
        return redirect(f'{FRONTEND_ORIGIN}/pages/home.html?token={session_token}')

    except Exception as e:
        print("Google callback error:", e)
        return redirect(f"{FRONTEND_ORIGIN}/?error=auth_failed")


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
    
@app.get("/verify-session")
def verify_session():
    """التحقق من صلاحية الـ session"""
    try:
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
                expires_datetime = datetime.fromtimestamp(expires_at.timestamp())
            else:
                expires_datetime = expires_at
            
            if datetime.utcnow() > expires_datetime:
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

@app.get("/recommended-videos")
def recommended_videos():
    """
    Get educational recommended videos based on user's study field or general educational topics
    Returns ONLY educational content
    """
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
            "programming tutorial",
            "mathematics lesson",
            "science education",
            "language learning",
            "history explained",
            "physics tutorial",
            "chemistry lesson",
            "biology education"
        ]
        
        search_queries = []
        
        if study_field:
            if study_field in STUDY_FIELD_KEYWORDS:
                search_queries = STUDY_FIELD_KEYWORDS[study_field]
            else:
                search_queries = [
                    f"{study_field} tutorial",
                    f"{study_field} course",
                    f"{study_field} lecture",
                    f"learn {study_field}"
                ]
        else:
            search_queries = default_topics
        
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
            "key": YT_KEY,
        }

        r = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params=params,
            timeout=15
        )

        if not r.ok:
            try:
                err = r.json()
            except:
                err = {"text": r.text}
            return jsonify({
                "error": "YouTube API error",
                "status": r.status_code,
                "details": err
            }), 502

        data = r.json()
        items = data.get("items", [])

        allowed_keywords = [
            "tutorial", "course", "learn", "education", "explain",
            "lesson", "how to", "guide", "teaching", "study",
            "lecture", "class", "training", "beginner", "advanced",
            "شرح", "تعليم", "محاضرة", "دورة", "كورس", "درس"
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
        return jsonify({"error": "Server error"}), 500

@app.get("/youtube-search")
def youtube_search():
    """
    Educational-only YouTube search endpoint.
    Forces educational results even if user searches for unrelated topics.
    """
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")

        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            return jsonify({"error": "YouTube API key not configured"}), 500

        # Force education category + strict safety
        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": max_results,
            "q": q,
            "videoCategoryId": "27",      
            "safeSearch": "strict",
            "videoEmbeddable": "true",
            "order": "relevance",
            "key": YT_KEY,
        }

        r = requests.get(
            "https://www.googleapis.com/youtube/v3/search",
            params=params,
            timeout=15
        )

        if not r.ok:
            try:
                err = r.json()
            except:
                err = {"text": r.text}
            return jsonify({
                "error": "YouTube API error",
                "status": r.status_code,
                "details": err
            }), 502

        data = r.json()
        items = data.get("items", [])

        # -------------------------------------------------------------------
        # Local filtering to remove non-educational videos
        # -------------------------------------------------------------------
        allowed_keywords = [
            "tutorial", "course", "learn", "education", "explain",
            "lesson", "how to", "شرح", "تعليم", "محاضرة"
        ]

        def is_educational(item):
            title = item["snippet"]["title"].lower()
            return any(kw in title for kw in allowed_keywords)

        filtered_items = [i for i in items if is_educational(i)]

        # If filtered list is empty → fallback to raw category 27 results
        if not filtered_items:
            filtered_items = items

        return jsonify({
            "items": filtered_items,
            "total": len(filtered_items),
            "original_total": len(items)
        })

    except Exception as e:
        print("youtube_search error:", e)
        return jsonify({"error": "Server error"}), 500

    """
    Proxy endpoint: frontend calls this endpoint.
    Backend uses API_KEY from environment to call YouTube Data API.
    """
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")
        
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            print(" ERROR: API_KEY not found in environment variables")
            return jsonify({
                "error": "YouTube API key not configured",
                "hint": "Add API_KEY to Railway environment variables"
            }), 500

        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": max_results,
            "q": q,
            "key": YT_KEY,
            "order": "relevance", 
            "videoEmbeddable": "true", 
            "safeSearch": "moderate"  
        }

        url = "https://www.googleapis.com/youtube/v3/search"
        
        print(f"🔍 Searching YouTube for: '{q}' (max: {max_results})")
        
        r = requests.get(url, params=params, timeout=15)
        
        if not r.ok:
            error_data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {"text": r.text}
            print(f" YouTube API Error {r.status_code}:")
            print(f"   Response: {error_data}")
            
            if r.status_code == 403:
                return jsonify({
                    "error": "YouTube API quota exceeded or invalid key",
                    "details": error_data
                }), 403
            elif r.status_code == 400:
                return jsonify({
                    "error": "Invalid YouTube API request",
                    "details": error_data
                }), 400
            else:
                return jsonify({
                    "error": "YouTube API error",
                    "status": r.status_code,
                    "details": error_data
                }), 502

        data = r.json()
        results_count = len(data.get('items', []))
        print(f" YouTube returned {results_count} results")
        
        return jsonify(data)

    except requests.exceptions.Timeout:
        print("⏱️ YouTube API request timed out")
        return jsonify({"error": "YouTube API timeout"}), 504
        
    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error: {str(e)}")
        return jsonify({"error": "Network error", "details": str(e)}), 503
        
    except Exception as e:
        print(f" Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Server error", "details": str(e)}), 500
    """
    Proxy endpoint: frontend calls this endpoint.
    Backend uses API_KEY from environment (API_KEY) to call YouTube Data API.
    """
    try:
        q = request.args.get("q")
        max_results = request.args.get("max", 10)
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            return jsonify({"error": "YouTube API key not configured on server"}), 500

        url = (
            "https://www.googleapis.com/youtube/v3/search"
            f"?part=snippet&type=video&maxResults={int(max_results)}"
            f"&q={requests.utils.requote_uri(q)}&key={YT_KEY}"
        )

        r = requests.get(url, timeout=10)
        if not r.ok:
            try:
                err_json = r.json()
            except Exception:
                err_json = {"status_code": r.status_code, "text": r.text}
            print("YouTube API returned error:", err_json)
            return jsonify({"error": "YouTube API error", "details": err_json}), 502

        data = r.json()
        return jsonify(data)

    except Exception as e:
        print("youtube_search error:", e)
        return jsonify({"error": "Server error"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
