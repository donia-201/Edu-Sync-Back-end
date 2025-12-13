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
    """التحقق من صلاحية الـ session - نسخة واحدة فقط مُصلحة"""
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"success": False, "msg": "No token provided"}), 401

        session_doc = sessions_ref.document(token).get()
        if not session_doc.exists:
            return jsonify({"success": False, "msg": "Invalid session"}), 401

        session_data = session_doc.to_dict()
        expires_at = session_data.get("expires_at")

        # حل مشكلة Firestore Timestamp
        if expires_at:
            if hasattr(expires_at, 'timestamp'):
                from datetime import timezone
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

@app.get("/")
def home():
    return "Backend with Firebase is running!"

def is_educational_content(video_item):
    """
    فلترة ذكية: يسمح بالمحتوى التعليمي ويمنع الترفيهي
    """
    snippet = video_item.get("snippet", {})
    title = snippet.get("title", "").lower()
    description = snippet.get("description", "").lower()
    channel = snippet.get("channelTitle", "").lower()
    
    # كلمات تعليمية إيجابية
    educational_keywords = [
        "tutorial", "course", "learn", "education", "teach", "lesson", "lecture",
        "guide", "how to", "explain", "study", "training", "class", "university",
        "college", "school", "professor", "instructor", "programming", "coding",
        "science", "math", "physics", "chemistry", "biology", "engineering",
        "medicine", "pharmacy", "law", "business", "marketing", "design",
        "development", "developer", "beginner", "advanced", "fundamental",
        "introduction", "basics", "complete", "full course", "bootcamp",
        "شرح", "تعليم", "درس", "محاضرة", "كورس", "دورة", "تدريب", "جامعة"
    ]
    
    # كلمات ترفيهية سلبية (نمنعها)
    entertainment_keywords = [
        "game", "gaming", "gameplay", "lets play", "playing", "gamer",
        "dance", "dancing", "song", "music video", "mv", "official video",
        "concert", "live performance", "singing", "rapper", "hip hop",
        "funny", "comedy", "prank", "challenge", "reaction", "vlog",
        "unboxing", "haul", "makeup tutorial", "beauty", "fashion",
        "مهرجان", "اغنية", "اغاني", "كليب", "موسيقى", "رقص", "لعبة", "العاب",
        "فيلم", "مسلسل", "كوميدي", "مضحك", "تحدي", "فلوج", "برانك"
    ]
    
    # قنوات تعليمية معروفة (نسمح بيها دايماً)
    educational_channels = [
        "ted", "khan academy", "crash course", "mit", "stanford",
        "harvard", "udemy", "coursera", "edx", "freecodecamp",
        "the coding train", "traversy media", "net ninja", "academind",
        "elzero", "theNewBaghdad", "codezilla", "algorithm academy"
    ]
    
    # فحص القنوات التعليمية المعروفة
    if any(edu_channel in channel for edu_channel in educational_channels):
        return True
    
    # عدد الكلمات التعليمية والترفيهية
    edu_count = sum(1 for kw in educational_keywords if kw in title or kw in description)
    entertainment_count = sum(1 for kw in entertainment_keywords if kw in title or kw in description)
    
    # قرار الفلترة:
    # 1. لو فيه كلمات ترفيهية كتير (أكتر من 2) -> نرفض
    if entertainment_count >= 2:
        return False
    
    # 2. لو فيه كلمة ترفيهية واحدة بس ومفيش كلمات تعليمية -> نرفض
    if entertainment_count >= 1 and edu_count == 0:
        return False
    
    # 3. لو فيه كلمات تعليمية -> نقبل
    if edu_count > 0:
        return True
    
    # 4. لو مفيش كلمات ترفيهية ولا تعليمية -> نقبل (محايد)
    if entertainment_count == 0:
        return True
    
    # 5. في الحالات الباقية -> نرفض
    return False


@app.get("/youtube-search")
def youtube_search():
    """بحث YouTube مع فلترة ذكية للمحتوى التعليمي"""
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")
        
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            print("❌ ERROR: API_KEY not found")
            return jsonify({"error": "YouTube API key not configured"}), 500

        # نطلب أكتر من المطلوب عشان بعد الفلترة نوصل للعدد المطلوب
        api_max_results = str(int(max_results) * 2)
        
        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": api_max_results,
            "q": q,
            "videoCategoryId": "27",  # Education category
            "order": "relevance",
            "videoEmbeddable": "true",
            "safeSearch": "strict",
            "key": YT_KEY
        }

        print(f"🔍 Searching YouTube: '{q}' (requesting: {api_max_results})")
        
        r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=15)
        
        if not r.ok:
            try:
                err = r.json()
            except:
                err = {"text": r.text}
            print(f"❌ YouTube API Error {r.status_code}:", err)
            return jsonify({"error": "YouTube API error", "status": r.status_code, "details": err}), 502

        data = r.json()
        all_items = data.get("items", [])
        
        print(f"📥 YouTube returned {len(all_items)} results")
        
        # تطبيق الفلترة الذكية
        filtered_items = [item for item in all_items if is_educational_content(item)]
        
        # نحدد العدد المطلوب فقط
        final_items = filtered_items[:int(max_results)]
        
        print(f"✅ After filtering: {len(final_items)} educational videos")
        print(f"🚫 Filtered out: {len(all_items) - len(filtered_items)} non-educational videos")

        return jsonify({
            "items": final_items,
            "total": len(final_items),
            "original_total": len(all_items),
            "filtered_count": len(all_items) - len(filtered_items)
        })

    except requests.exceptions.Timeout:
        print("⏱️ YouTube API timeout")
        return jsonify({"error": "YouTube API timeout"}), 504
    except requests.exceptions.RequestException as e:
        print(f"🌐 Network error: {str(e)}")
        return jsonify({"error": "Network error", "details": str(e)}), 503
    except Exception as e:
        print(f"💥 youtube_search error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)