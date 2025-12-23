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
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from urllib.parse import urlencode



app = Flask(__name__)

def verify_session_token(token):
    """التحقق من صلاحية الـ session token"""
    try:
        if not token:
            return None
        
        session_doc = sessions_ref.document(token).get()
        if not session_doc.exists:
            return None
        
        session_data = session_doc.to_dict()
        expires_at = session_data.get("expires_at")
        
        if expires_at:
            if hasattr(expires_at, 'timestamp'):
                from datetime import timezone
                expires_at = datetime.fromtimestamp(expires_at.timestamp(), tz=timezone.utc).replace(tzinfo=None)
            
            if datetime.utcnow() > expires_at:
                sessions_ref.document(token).delete()
                return None
        
        return session_data
    except Exception as e:
        print(f"Session verification error: {e}")
        return None

def require_auth(f):
    """Decorator للتحقق من الـ authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        
        if not token:
            # Try to get from cookie
            token = request.cookies.get("session_token")
        
        session_data = verify_session_token(token)
        
        if not session_data:
            return jsonify({"success": False, "msg": "Unauthorized"}), 401
        
        # Pass user data to the route
        request.user_data = session_data
        return f(*args, **kwargs)
    
    return decorated_function
# Use a specific origin for CORS
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://edu-sync-gold.vercel.app")
CORS(app, resources={
    r"/*": {
        "origins": [FRONTEND_ORIGIN, "http://localhost:5000", "http://127.0.0.1:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})


# Initialize Firebase
SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://edu-sync-back-end-production.up.railway.app/google-callback")
REDIRECT_URI_CALENDAR="https://edu-sync-back-end-production.up.railway.app/google-calendar-callback"
REDIRECT_URI_CALENDAR = os.getenv(
    "REDIRECT_URI_CALENDAR",
    "https://edu-sync-back-end-production.up.railway.app/google-calendar-callback"
)
CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.events"


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

def get_calendar_service(refresh_token):
    """Create Google Calendar service with refresh token"""
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET
    )
    return build("calendar", "v3", credentials=creds)

def convert_to_google_calendar_format(event_data):
    """Convert our event format to Google Calendar format"""
    return {
        "summary": event_data.get("title"),
        "description": event_data.get("description", ""),
        "start": {
            "dateTime": event_data.get("start"),
            "timeZone": "Africa/Cairo"
        },
        "end": {
            "dateTime": event_data.get("end"),
            "timeZone": "Africa/Cairo"
        },
        "colorId": "1" if event_data.get("type") == "focus" else "11"
    }

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

# ===================================
# Google Calendar OAuth Routes
# ===================================
@app.get("/connect-google-calendar")
@require_auth
def connect_google_calendar():
    """Initiate Google Calendar OAuth flow"""
    user_id = request.user_data["user_id"]
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI_CALENDAR,
        "response_type": "code",
        "scope": CALENDAR_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "state": user_id
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return redirect(auth_url)

@app.get("/google-calendar-callback")
def google_calendar_callback():
    """Handle Google Calendar OAuth callback"""
    try:
        code = request.args.get("code")
        user_id = request.args.get("state")
        
        if not code or not user_id:
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")
        
        # Exchange code for tokens
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI_CALENDAR,
            "grant_type": "authorization_code"
        }
        
        r = requests.post(token_url, data=data)
        if not r.ok:
            print("Calendar token error:", r.text)
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_token_failed")
        
        token_data = r.json()
        refresh_token = token_data.get("refresh_token")
        
        if not refresh_token:
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_refresh_token")
        
        # Save refresh token to Firestore
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": refresh_token,
            "google_calendar_connected": True
        })
        
        return redirect(f"{FRONTEND_ORIGIN}/pages/home.html?calendar=connected")
    
    except Exception as e:
        print("Calendar callback error:", e)
        return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")

@app.get("/disconnect-google-calendar")
@require_auth
def disconnect_google_calendar():
    """Disconnect Google Calendar"""
    try:
        user_id = request.user_data["user_id"]
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": firestore.DELETE_FIELD,
            "google_calendar_connected": False
        })
        return jsonify({"success": True, "msg": "Calendar disconnected"})
    except Exception as e:
        print("Disconnect error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500

@app.get("/calendar-status")
@require_auth
def calendar_status():
    """Check if Google Calendar is connected"""
    try:
        user_id = request.user_data["user_id"]
        user_doc = users_ref.document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({"success": False, "msg": "User not found"}), 404
        
        user_data = user_doc.to_dict()
        is_connected = user_data.get("google_calendar_connected", False)
        
        return jsonify({
            "success": True,
            "connected": is_connected
        })
    except Exception as e:
        print("Calendar status error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500


# ===================================
# Events Routes (Local Database)
# ===================================
@app.post("/api/events")
@require_auth
def create_event():
    """Create a new event in local database and optionally sync to Google Calendar"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        # Validate required fields
        required_fields = ["title", "start", "end", "type"]
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "msg": f"Missing field: {field}"}), 400
        
        # Create event document
        event_data = {
            "user_id": user_id,
            "title": data["title"],
            "start": data["start"],
            "end": data["end"],
            "type": data["type"],
            "description": data.get("description", ""),
            "created_at": datetime.now().isoformat(),
            "synced_to_google": False,
            "google_event_id": None
        }
        
        # Save to Firestore
        events_ref = db.collection("events")
        event_ref = events_ref.add(event_data)
        event_id = event_ref[1].id
        
        # Try to sync to Google Calendar if connected
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            refresh_token = user_data.get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    google_event = convert_to_google_calendar_format(event_data)
                    
                    result = service.events().insert(
                        calendarId='primary',
                        body=google_event
                    ).execute()
                    
                    # Update event with Google Calendar ID
                    events_ref.document(event_id).update({
                        "synced_to_google": True,
                        "google_event_id": result.get("id")
                    })
                    
                    print(f"Event synced to Google Calendar: {result.get('id')}")
                except Exception as e:
                    print(f"Failed to sync to Google Calendar: {e}")
                    # Continue anyway - event is saved locally
        
        return jsonify({
            "success": True,
            "msg": "Event created successfully",
            "event_id": event_id
        }), 201
        
    except Exception as e:
        print("Create event error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500

@app.get("/api/events")
@require_auth
def get_events():
    """Get all events for the authenticated user"""
    try:
        user_id = request.user_data["user_id"]
        
        # Get events from Firestore
        events_ref = db.collection("events")
        query = events_ref.where("user_id", "==", user_id).order_by("start")
        docs = query.stream()
        
        events = []
        for doc in docs:
            event_data = doc.to_dict()
            event_data["id"] = doc.id
            events.append(event_data)
        
        # Optionally fetch from Google Calendar and merge
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            refresh_token = user_data.get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    
                    # Get events from Google Calendar (next 30 days)
                    now = datetime.utcnow().isoformat() + 'Z'
                    future = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
                    
                    google_events = service.events().list(
                        calendarId='primary',
                        timeMin=now,
                        timeMax=future,
                        singleEvents=True,
                        orderBy='startTime'
                    ).execute()
                    
                    # Add Google Calendar events that aren't already in our database
                    for g_event in google_events.get('items', []):
                        google_id = g_event.get('id')
                        
                        # Check if this event is already in our database
                        already_exists = any(e.get('google_event_id') == google_id for e in events)
                        
                        if not already_exists:
                            start = g_event['start'].get('dateTime', g_event['start'].get('date'))
                            end = g_event['end'].get('dateTime', g_event['end'].get('date'))
                            
                            events.append({
                                "id": f"google_{google_id}",
                                "title": g_event.get('summary', 'No Title'),
                                "start": start,
                                "end": end,
                                "type": "focus",
                                "description": g_event.get('description', ''),
                                "synced_to_google": True,
                                "google_event_id": google_id,
                                "source": "google_calendar"
                            })
                    
                except Exception as e:
                    print(f"Failed to fetch from Google Calendar: {e}")
                    # Continue with local events only
        
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events)
        })
        
    except Exception as e:
        print("Get events error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500

@app.put("/api/events/<event_id>")
@require_auth
def update_event(event_id):
    """Update an existing event"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        events_ref = db.collection("events")
        event_doc = events_ref.document(event_id).get()
        
        if not event_doc.exists:
            return jsonify({"success": False, "msg": "Event not found"}), 404
        
        event_data = event_doc.to_dict()
        
        # Check ownership
        if event_data.get("user_id") != user_id:
            return jsonify({"success": False, "msg": "Unauthorized"}), 403
        
        # Update fields
        update_data = {}
        for field in ["title", "start", "end", "type", "description"]:
            if field in data:
                update_data[field] = data[field]
        
        update_data["updated_at"] = datetime.now().isoformat()
        
        # Update in Firestore
        events_ref.document(event_id).update(update_data)
        
        # Update in Google Calendar if synced
        google_event_id = event_data.get("google_event_id")
        if google_event_id:
            user_doc = users_ref.document(user_id).get()
            if user_doc.exists:
                refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
                
                if refresh_token:
                    try:
                        service = get_calendar_service(refresh_token)
                        
                        # Get current event from Google
                        g_event = service.events().get(
                            calendarId='primary',
                            eventId=google_event_id
                        ).execute()
                        
                        # Update fields
                        if "title" in update_data:
                            g_event["summary"] = update_data["title"]
                        if "description" in update_data:
                            g_event["description"] = update_data["description"]
                        if "start" in update_data:
                            g_event["start"] = {
                                "dateTime": update_data["start"],
                                "timeZone": "Africa/Cairo"
                            }
                        if "end" in update_data:
                            g_event["end"] = {
                                "dateTime": update_data["end"],
                                "timeZone": "Africa/Cairo"
                            }
                        
                        # Update in Google Calendar
                        service.events().update(
                            calendarId='primary',
                            eventId=google_event_id,
                            body=g_event
                        ).execute()
                        
                        print(f"Event updated in Google Calendar: {google_event_id}")
                    except Exception as e:
                        print(f"Failed to update in Google Calendar: {e}")
        
        return jsonify({
            "success": True,
            "msg": "Event updated successfully"
        })
        
    except Exception as e:
        print("Update event error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500

@app.delete("/api/events/<event_id>")
@require_auth
def delete_event(event_id):
    """Delete an event"""
    try:
        user_id = request.user_data["user_id"]
        
        events_ref = db.collection("events")
        event_doc = events_ref.document(event_id).get()
        
        if not event_doc.exists:
            return jsonify({"success": False, "msg": "Event not found"}), 404
        
        event_data = event_doc.to_dict()
        
        # Check ownership
        if event_data.get("user_id") != user_id:
            return jsonify({"success": False, "msg": "Unauthorized"}), 403
        
        # Delete from Google Calendar if synced
        google_event_id = event_data.get("google_event_id")
        if google_event_id:
            user_doc = users_ref.document(user_id).get()
            if user_doc.exists:
                refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
                
                if refresh_token:
                    try:
                        service = get_calendar_service(refresh_token)
                        service.events().delete(
                            calendarId='primary',
                            eventId=google_event_id
                        ).execute()
                        print(f"Event deleted from Google Calendar: {google_event_id}")
                    except Exception as e:
                        print(f"Failed to delete from Google Calendar: {e}")
        
        # Delete from Firestore
        events_ref.document(event_id).delete()
        
        return jsonify({
            "success": True,
            "msg": "Event deleted successfully"
        })
        
    except Exception as e:
        print("Delete event error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500

# ---------------Log Out-----------
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
    فلترة خفيفة جداً: فقط يمنع المحتوى الترفيهي الواضح
    """
    snippet = video_item.get("snippet", {})
    title = snippet.get("title", "").lower()
    description = snippet.get("description", "").lower()
    
    banned_keywords = [
        # ألعاب
        "gameplay", "let's play", "gaming channel", "game walkthrough", "fortnite", 
        "minecraft", "pubg", "call of duty", "fifa", "ps5", "xbox",
        
        "official music video", "official video", "music video", "مهرجان", "كليب",
        "dance cover", "choreography", "اغنية", "اغاني",
        
        "prank", "funny moments", "comedy sketch", "stand up comedy",
        "reaction video", "تحدي", "برانك", "مقلب",
        
        "trailer", "full movie", "episode", "مسلسل", "فيلم"
    ]
    
    text_to_check = title + " " + description
    for banned in banned_keywords:
        if banned in text_to_check:
            return False
    
    return True


@app.get("/youtube-search")
def youtube_search():
    """بحث YouTube مع فلترة خفيفة جداً"""
    try:
        q = request.args.get("q", "").strip()
        max_results = request.args.get("max", "10")
        
        if not q:
            return jsonify({"error": "Missing query parameter 'q'"}), 400

        YT_KEY = os.getenv("API_KEY")
        if not YT_KEY:
            return jsonify({
                "error": "YouTube API key not configured",
                "hint": "Add API_KEY to environment variables",
                "display_message": "YouTube API is not exist"
            }), 500

        api_max_results = str(min(int(max_results) * 3, 50))
        
        params = {
            "part": "snippet",
            "type": "video",
            "maxResults": api_max_results,
            "q": q,
            "order": "relevance",
            "videoEmbeddable": "true",
            "safeSearch": "moderate",
            "key": YT_KEY
        }

        print(f"🔍 Searching YouTube: '{q}' (requesting: {api_max_results})")
        
        r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=15)
        
        if not r.ok:
            try:
                err = r.json()
                error_msg = err.get('error', {}).get('message', 'Unknown error')
            except:
                err = {"text": r.text}
                error_msg = f"HTTP {r.status_code}"
            
            print(f" YouTube API Error {r.status_code}:", err)
            
            return jsonify({
                "error": "YouTube API error",
                "status": r.status_code,
                "details": err,
                "display_message": f"error in YouTube API: {error_msg}"
            }), 502

        data = r.json()
        all_items = data.get("items", [])
        
        print(f" YouTube returned {len(all_items)} results")
        
        if not all_items:
            return jsonify({
                "items": [],
                "total": 0,
                "display_message": f" no videos match with'{q}' ,try another words"
            })
        
        filtered_items = [item for item in all_items if is_educational_content(item)]
        
        final_items = filtered_items[:int(max_results)]
        
        print(f" After filtering: {len(final_items)} videos")
        print(f" Filtered out: {len(all_items) - len(filtered_items)} entertainment videos")
        
        if not final_items:
            return jsonify({
                "items": [],
                "total": 0,
                "display_message": f" couldn't fine any educational content match with{q}', try another words like 'tutorial' or 'course'."
            })

        return jsonify({
            "items": final_items,
            "total": len(final_items),
            "original_total": len(all_items),
            "filtered_count": len(all_items) - len(filtered_items),
            "display_message": f" we found {len(final_items)} video"
        })

    except requests.exceptions.Timeout:
        print("⏱ YouTube API timeout")
        return jsonify({
            "error": "YouTube API timeout",
            "display_message": " انتهت مهلة الاتصال بـ YouTube. حاول مرة أخرى."
        }), 504
    except requests.exceptions.RequestException as e:
        print(f" Network error: {str(e)}")
        return jsonify({
            "error": "Network error",
            "details": str(e),
            "display_message": " خطأ في الاتصال بالإنترنت. تحقق من اتصالك."
        }), 503
    except Exception as e:
        print(f" youtube_search error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": f"Server error: {str(e)}",
            "display_message": "    حدث خطأ في السيرفر. حاول مرة أخرى لاحقاً."
        }), 500

# -------------Notes API Routes-----------------
@app.route('/api/notes', methods=['GET'])
@require_auth
def get_notes():
    """الحصول على جميع الملاحظات الخاصة بالمستخدم الحالي"""
    try:
        user_id = request.user_data['user_id']
        notes_ref = db.collection('users').document(user_id).collection('notes')
        
        notes_docs = notes_ref.order_by('createdAt', direction=firestore.Query.DESCENDING).stream()
        
        notes_list = []
        for note_doc in notes_docs:
            note_data = note_doc.to_dict()
            note_data['id'] = note_doc.id
            notes_list.append(note_data)
        
        return jsonify({'notes': notes_list, 'success': True})
    except Exception as e:
        print(f"Error fetching notes: {e}")
        return jsonify({'error': 'Failed to fetch notes', 'success': False}), 500


@app.route('/api/notes', methods=['POST'])
@require_auth
def create_note():
    """إنشاء ملاحظة جديدة"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        note_data = {
            'type': data.get('type', 'note'),
            'content': data.get('content', ''),
            'color': data.get('color', '#ffffff'),
            'checked': data.get('checked', False),
            'createdAt': data.get('createdAt', datetime.utcnow().isoformat()),
            'updatedAt': datetime.utcnow().isoformat()
        }
        
        notes_ref = db.collection('users').document(user_id).collection('notes')
        
        if 'id' in data:
            note_ref = notes_ref.document(data['id'])
            note_ref.set(note_data)
            note_id = data['id']
        else:
            doc_ref = notes_ref.add(note_data)
            note_id = doc_ref[1].id
        
        note_data['id'] = note_id
        
        return jsonify({'note': note_data, 'success': True}), 201
    except Exception as e:
        print(f"Error creating note: {e}")
        return jsonify({'error': 'Failed to create note', 'success': False}), 500


@app.route('/api/notes/<note_id>', methods=['PUT'])
@require_auth
def update_note(note_id):
    """تحديث ملاحظة موجودة (PUT)"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        print(f"Update received for Note ID: {note_id}, Data: {data}")

        update_data = {
            'updatedAt': datetime.utcnow().isoformat()
        }
        
        allowed_fields = ['content', 'color', 'checked', 'type']
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        note_ref = db.collection('users').document(user_id).collection('notes').document(note_id)
        
        if not note_ref.get().exists:
            return jsonify({'error': 'Note not found', 'success': False}), 404
        
        note_ref.update(update_data)
        
        print(f"Note {note_id} updated successfully in Firestore with content: {update_data.get('content')}") 

        updated_note = note_ref.get().to_dict()
        updated_note['id'] = note_id
        
        return jsonify({'note': updated_note, 'success': True})
    except Exception as e:
        print(f"Error updating note: {e}")
        return jsonify({'error': 'Failed to update note', 'success': False}), 500
@app.route('/api/notes/reorder', methods=['POST'])
@require_auth
def reorder_notes():
    """تحديث ترتيب الملاحظات (إرسال ID بترتيب جديد)"""
    try:
        user_id = request.user_data['user_id']
        data = request.get_json()
        
        if not data or 'order' not in data:
            return jsonify({'error': 'Invalid data', 'success': False}), 400
        
        order = data['order']
        
        batch = db.batch()
        for index, note_id in enumerate(order):
            note_ref = db.collection('users').document(user_id).collection('notes').document(note_id)
            batch.update(note_ref, {
                'order': index, 
                'updatedAt': datetime.utcnow().isoformat()
            })
        
        batch.commit()
        
        return jsonify({'message': 'Order updated successfully', 'success': True})
    except Exception as e:
        print(f"Error reordering notes: {e}")
        return jsonify({'error': 'Failed to reorder notes', 'success': False}), 500




if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    app.run(host="0.0.0.0", port=port)