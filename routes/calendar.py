from flask import Blueprint, request, jsonify, redirect
from datetime import datetime, timedelta
from firebase_admin import firestore
from urllib.parse import urlencode
import requests

from config import (
    GOOGLE_CLIENT_ID, 
    GOOGLE_CLIENT_SECRET, 
    REDIRECT_URI_CALENDAR, 
    CALENDAR_SCOPE, 
    FRONTEND_ORIGIN
)
from utils.firebase_config import db, users_ref
from utils.auth import require_auth
from utils.calendar import get_calendar_service, convert_to_google_calendar_format

calendar_bp = Blueprint('calendar', __name__)


# ===================================
# Helper Functions
# ===================================
def validate_iso_datetime(date_str):
    """Validate and normalize ISO datetime string"""
    if not date_str:
        return None

    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        iso_str = dt.isoformat()
        # Normalize +00:00 to Z for UTC
        if '+00:00' in iso_str:
            iso_str = iso_str.replace('+00:00', 'Z')
        return iso_str
    except (ValueError, AttributeError):
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            return dt.isoformat() + 'Z'
        except (ValueError, AttributeError):
            return None


# ===================================
# Google Calendar OAuth Routes
# ===================================
@calendar_bp.get("/connect-google-calendar")
@require_auth
def connect_google_calendar():
    """Initiate Google Calendar OAuth flow"""
    try:
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
        print(f"🔗 Redirecting to Google OAuth: {auth_url}")
        
        return redirect(auth_url)
    except Exception as e:
        print(f"❌ Connect calendar error: {e}")
        return jsonify({"success": False, "msg": str(e)}), 500


@calendar_bp.get("/google-calendar-callback")
def google_calendar_callback():
    """Handle Google Calendar OAuth callback"""
    try:
        code = request.args.get("code")
        user_id = request.args.get("state")
        
        if not code or not user_id:
            print("❌ Missing code or user_id in callback")
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
            print(f"❌ Token exchange failed: {r.status_code} - {r.text}")
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_token_failed")
        
        token_data = r.json()
        refresh_token = token_data.get("refresh_token")
        
        if not refresh_token:
            print("❌ No refresh token received")
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_refresh_token")
        
        # Save to Firestore
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": refresh_token,
            "google_calendar_connected": True
        })
        
        print(f"✅ Google Calendar connected for user: {user_id}")
        return redirect(f"{FRONTEND_ORIGIN}/pages/home.html?calendar=connected")
    
    except Exception as e:
        print(f"❌ Calendar callback error: {e}")
        import traceback
        traceback.print_exc()
        return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")


@calendar_bp.get("/disconnect-google-calendar")
@require_auth
def disconnect_google_calendar():
    """Disconnect Google Calendar"""
    try:
        user_id = request.user_data["user_id"]
        
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": firestore.DELETE_FIELD,
            "google_calendar_connected": False
        })
        
        print(f"✅ Google Calendar disconnected for user: {user_id}")
        return jsonify({"success": True, "msg": "Calendar disconnected"})
    
    except Exception as e:
        print(f"❌ Disconnect error: {e}")
        return jsonify({"success": False, "msg": str(e)}), 500


@calendar_bp.get("/calendar-status")
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
        print(f"❌ Calendar status error: {e}")
        return jsonify({"success": False, "msg": str(e)}), 500


# ===================================
# Calendar Routes (Display + Add Only)
# ===================================

@calendar_bp.route("/api/calendar/events", methods=["POST"])
@require_auth
def add_calendar_event():
    """Add new event from Calendar page"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        print(f"📅 [CALENDAR] Add event request from user: {user_id}")
        print(f"📦 [CALENDAR] Data: {data}")
        
        # Validate required fields
        title = data.get("title", "").strip()
        start_raw = data.get("start")
        end_raw = data.get("end")
        
        if not title:
            print("❌ [CALENDAR] Missing title")
            return jsonify({
                "success": False, 
                "msg": "Title is required"
            }), 400
        
        if not start_raw:
            print("❌ [CALENDAR] Missing start")
            return jsonify({
                "success": False, 
                "msg": "Start time is required"
            }), 400
            
        if not end_raw:
            print("❌ [CALENDAR] Missing end")
            return jsonify({
                "success": False, 
                "msg": "End time is required"
            }), 400
        
        # Validate and normalize datetime
        start = validate_iso_datetime(start_raw)
        end = validate_iso_datetime(end_raw)
        
        if not start:
            print(f"❌ [CALENDAR] Invalid start: {start_raw}")
            return jsonify({
                "success": False,
                "msg": f"Invalid start datetime: {start_raw}"
            }), 400
        
        if not end:
            print(f"❌ [CALENDAR] Invalid end: {end_raw}")
            return jsonify({
                "success": False,
                "msg": f"Invalid end datetime: {end_raw}"
            }), 400
        
        # Validate end > start
        try:
            start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
            
            if end_dt <= start_dt:
                print("❌ [CALENDAR] End <= start")
                return jsonify({
                    "success": False,
                    "msg": "End time must be after start time"
                }), 400
        except Exception as e:
            print(f"❌ [CALENDAR] Date validation error: {e}")
            return jsonify({
                "success": False,
                "msg": "Invalid date format"
            }), 400
        
        # Get optional fields
        description = data.get("description", "")
        reminder = data.get("reminder")
        remind_at = data.get("remindAt")
        
        # Validate remindAt
        if remind_at:
            remind_at = validate_iso_datetime(remind_at)
        
        # Create event data
        now_iso = datetime.utcnow().isoformat() + "Z"
        
        event_data = {
            "user_id": user_id,
            "title": title,
            "start": start,
            "end": end,
            "description": description,
            "reminder": reminder if reminder else {},
            "remindAt": remind_at,
            "created_at": now_iso,
            "updated_at": now_iso,
            "synced_to_google": False
        }
        
        # Save to Firestore
        events_ref = db.collection("events")
        doc_ref = events_ref.add(event_data)[1]
        event_id = doc_ref.id
        event_data["id"] = event_id
        
        print(f"✅ [CALENDAR] Event saved: {event_id} - {title}")
        
        # Try Google Calendar sync
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    g_event_body = convert_to_google_calendar_format(event_data)
                    
                    g_event = service.events().insert(
                        calendarId='primary',
                        body=g_event_body
                    ).execute()
                    
                    google_event_id = g_event.get("id")
                    
                    events_ref.document(event_id).update({
                        "google_event_id": google_event_id,
                        "synced_to_google": True
                    })
                    
                    event_data["google_event_id"] = google_event_id
                    event_data["synced_to_google"] = True
                    
                    print(f"✅ [CALENDAR] Synced to Google: {google_event_id}")
                
                except Exception as e:
                    print(f"⚠️ [CALENDAR] Google sync failed: {e}")
        
        return jsonify({
            "success": True,
            "event": event_data,
            "msg": "Event created successfully"
        }), 201
        
    except Exception as e:
        print(f"❌ [CALENDAR] Create error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False, 
            "msg": f"Server error: {str(e)}"
        }), 500


@calendar_bp.route("/api/calendar/events", methods=["GET"])
@require_auth
def get_calendar_events():
    """Get all events for Calendar display"""
    try:
        user_id = request.user_data["user_id"]
        
        print(f"📅 [CALENDAR] Fetch events for user: {user_id}")
        
        # Get from Firestore
        events_ref = db.collection("events")
        query = events_ref.where("user_id", "==", user_id)
        docs = query.stream()
        
        events = []
        for doc in docs:
            event_data = doc.to_dict()
            event_data["id"] = doc.id
            events.append(event_data)
        
        events.sort(key=lambda x: x.get("start", ""))
        
        print(f"✅ [CALENDAR] Found {len(events)} events in Firestore")
        
        # Merge with Google Calendar
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    
                    now = datetime.utcnow().isoformat() + 'Z'
                    future = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
                    
                    google_events = service.events().list(
                        calendarId='primary',
                        timeMin=now,
                        timeMax=future,
                        singleEvents=True,
                        orderBy='startTime'
                    ).execute()
                    
                    google_items = google_events.get('items', [])
                    
                    for g_event in google_items:
                        google_id = g_event.get('id')
                        
                        if not any(e.get('google_event_id') == google_id for e in events):
                            start = g_event['start'].get('dateTime', g_event['start'].get('date'))
                            end = g_event['end'].get('dateTime', g_event['end'].get('date'))
                            
                            events.append({
                                "id": f"google_{google_id}",
                                "title": g_event.get('summary', 'No Title'),
                                "start": start,
                                "end": end,
                                "description": g_event.get('description', ''),
                                "reminder": {},
                                "synced_to_google": True,
                                "google_event_id": google_id,
                                "source": "google_calendar"
                            })
                    
                    print(f" [CALENDAR] Merged {len(google_items)} Google events")
                
                except Exception as e:
                    print(f"⚠️ [CALENDAR] Google fetch failed: {e}")
        
        print(f" [CALENDAR] Returning {len(events)} total events")
        
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events)
        })
        
    except Exception as e:
        print(f"❌ [CALENDAR] Get events error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False, 
            "msg": str(e)
        }), 500