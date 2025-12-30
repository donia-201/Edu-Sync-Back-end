from flask import Blueprint, request, jsonify, redirect
from datetime import datetime, timedelta
from firebase_admin import firestore
from urllib.parse import urlencode
import requests

from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI_CALENDAR, CALENDAR_SCOPE, FRONTEND_ORIGIN
from utils.firebase_config import db, users_ref
from utils.auth import require_auth
from utils.calendar import get_calendar_service, convert_to_google_calendar_format

events_bp = Blueprint('events', __name__)

# ===================================
# Helper Functions
# ===================================
def validate_iso_datetime(date_str):
    """Validate and normalize ISO datetime string"""
    if not date_str:
        return None
    
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.isoformat() + ('Z' if not date_str.endswith('Z') else '')
    except ValueError:
        try:
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            return dt.isoformat() + 'Z'
        except ValueError:
            return None


# ===================================
# Google Calendar OAuth Routes
# ===================================
@events_bp.get("/connect-google-calendar")
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


@events_bp.get("/google-calendar-callback")
def google_calendar_callback():
    """Handle Google Calendar OAuth callback"""
    try:
        code = request.args.get("code")
        user_id = request.args.get("state")
        
        if not code or not user_id:
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")
        
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
            print("❌ Calendar token error:", r.text)
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_token_failed")
        
        token_data = r.json()
        refresh_token = token_data.get("refresh_token")
        
        if not refresh_token:
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_refresh_token")
        
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": refresh_token,
            "google_calendar_connected": True
        })
        
        print(f"✅ Google Calendar connected for user: {user_id}")
        return redirect(f"{FRONTEND_ORIGIN}/pages/home.html?calendar=connected")
    
    except Exception as e:
        print(f"❌ Calendar callback error: {e}")
        import traceback; traceback.print_exc()
        return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")


@events_bp.get("/disconnect-google-calendar")
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


@events_bp.get("/calendar-status")
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
        
        return jsonify({"success": True, "connected": is_connected})
    except Exception as e:
        print(f"❌ Calendar status error: {e}")
        return jsonify({"success": False, "msg": str(e)}), 500


# ===================================
# Events CRUD Routes
# ===================================

# ✅ CREATE EVENT (من Calendar)
@events_bp.route("/api/events", methods=["POST"])
@require_auth
def create_event():
    """Create a new event from Calendar UI"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        print(f"📥 Received event data: {data}")
        
        # Validate required fields
        title = data.get("title", "").strip()
        start_raw = data.get("start")
        end_raw = data.get("end")
        
        if not title:
            return jsonify({"success": False, "msg": "Title is required"}), 400
        
        if not start_raw or not end_raw:
            return jsonify({"success": False, "msg": "Start and end times are required"}), 400
        
        # Validate and normalize datetime
        start = validate_iso_datetime(start_raw)
        end = validate_iso_datetime(end_raw)
        
        if not start or not end:
            return jsonify({
                "success": False,
                "msg": "Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"
            }), 400
        
        # Validate end > start
        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))
        
        if end_dt <= start_dt:
            return jsonify({
                "success": False,
                "msg": "End time must be after start time"
            }), 400
        
        description = data.get("description", "")
        reminder = data.get("reminder")
        remind_at = data.get("remindAt")
        
        # Validate remindAt if provided
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
        
        print(f"✅ Event created in Firestore: {event_id} - {title}")
        
        # Try to sync to Google Calendar
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
                    
                    # Update with Google event ID
                    events_ref.document(event_id).update({
                        "google_event_id": g_event.get("id"),
                        "synced_to_google": True
                    })
                    
                    event_data["google_event_id"] = g_event.get("id")
                    event_data["synced_to_google"] = True
                    
                    print(f"✅ Event synced to Google Calendar: {g_event.get('id')}")
                except Exception as e:
                    print(f"⚠️ Failed to sync to Google Calendar: {e}")
        
        return jsonify({
            "success": True,
            "event": event_data,
            "msg": "Event created successfully"
        }), 201
        
    except Exception as e:
        print(f"❌ Create event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": f"Server error: {str(e)}"}), 500


# ✅ GET ALL EVENTS (للعرض في Calendar)
@events_bp.route("/api/events", methods=["GET"])
@require_auth
def get_events():
    """Get all events for display in Calendar"""
    try:
        user_id = request.user_data["user_id"]
        
        # Get events from Firestore
        events_ref = db.collection("events")
        query = events_ref.where("user_id", "==", user_id)
        docs = query.stream()
        
        events = []
        for doc in docs:
            event_data = doc.to_dict()
            event_data["id"] = doc.id
            events.append(event_data)
        
        # Sort by start time
        events.sort(key=lambda x: x.get("start", ""))
        
        # Merge with Google Calendar events
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    
                    # Get next 30 days
                    now = datetime.utcnow().isoformat() + 'Z'
                    future = (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z'
                    
                    google_events = service.events().list(
                        calendarId='primary',
                        timeMin=now,
                        timeMax=future,
                        singleEvents=True,
                        orderBy='startTime'
                    ).execute()
                    
                    # Add Google events that don't exist in Firestore
                    for g_event in google_events.get('items', []):
                        google_id = g_event.get('id')
                        
                        # Check if already exists
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
                    
                    print(f"✅ Merged {len(google_events.get('items', []))} Google Calendar events")
                except Exception as e:
                    print(f"⚠️ Failed to fetch Google Calendar events: {e}")
        
        print(f"✅ Returning {len(events)} total events")
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events)
        })
        
    except Exception as e:
        print(f"❌ Get events error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500


# ✅ UPDATE EVENT
@events_bp.route("/api/events/<event_id>", methods=["PUT"])
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
        
        # Build update data
        update_data = {}
        
        if "title" in data:
            title = data["title"].strip()
            if not title:
                return jsonify({"success": False, "msg": "Title cannot be empty"}), 400
            update_data["title"] = title
        
        if "start" in data:
            start = validate_iso_datetime(data["start"])
            if not start:
                return jsonify({"success": False, "msg": "Invalid start datetime"}), 400
            update_data["start"] = start
        
        if "end" in data:
            end = validate_iso_datetime(data["end"])
            if not end:
                return jsonify({"success": False, "msg": "Invalid end datetime"}), 400
            update_data["end"] = end
        
        # Validate start < end
        if "start" in update_data and "end" in update_data:
            start_dt = datetime.fromisoformat(update_data["start"].replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(update_data["end"].replace('Z', '+00:00'))
            if end_dt <= start_dt:
                return jsonify({"success": False, "msg": "End must be after start"}), 400
        
        if "description" in data:
            update_data["description"] = data["description"]
        if "reminder" in data:
            update_data["reminder"] = data["reminder"]
        if "remindAt" in data:
            remind_at = validate_iso_datetime(data["remindAt"])
            update_data["remindAt"] = remind_at
        
        update_data["updated_at"] = datetime.utcnow().isoformat() + "Z"
        
        # Update in Firestore
        events_ref.document(event_id).update(update_data)
        
        print(f"✅ Event updated in Firestore: {event_id}")
        
        # Update in Google Calendar if synced
        google_event_id = event_data.get("google_event_id")
        if google_event_id:
            user_doc = users_ref.document(user_id).get()
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    g_event = service.events().get(
                        calendarId='primary',
                        eventId=google_event_id
                    ).execute()
                    
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
                    
                    service.events().update(
                        calendarId='primary',
                        eventId=google_event_id,
                        body=g_event
                    ).execute()
                    
                    print(f"✅ Event updated in Google Calendar: {google_event_id}")
                except Exception as e:
                    print(f"⚠️ Failed to update in Google Calendar: {e}")
        
        return jsonify({"success": True, "msg": "Event updated successfully"})
        
    except Exception as e:
        print(f"❌ Update event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500


# ✅ DELETE EVENT
@events_bp.route("/api/events/<event_id>", methods=["DELETE"])
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
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    service.events().delete(
                        calendarId='primary',
                        eventId=google_event_id
                    ).execute()
                    print(f" Event deleted from Google Calendar: {google_event_id}")
                except Exception as e:
                    print(f" Failed to delete from Google Calendar: {e}")
        
        # Delete from Firestore
        events_ref.document(event_id).delete()
        
        print(f" Event deleted from Firestore: {event_id}")
        return jsonify({"success": True, "msg": "Event deleted successfully"})
        
    except Exception as e:
        print(f" Delete event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500