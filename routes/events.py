from flask import Blueprint, request, jsonify, redirect
from datetime import datetime, timedelta
from firebase_admin import firestore
from urllib.parse import urlencode

from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI_CALENDAR, CALENDAR_SCOPE, FRONTEND_ORIGIN
from utils.firebase_config import db, users_ref
from utils.auth import require_auth
from utils.calendar import get_calendar_service, convert_to_google_calendar_format
import requests

events_bp = Blueprint('events', __name__)

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
        return jsonify({"success": True, "msg": "Calendar disconnected"})
    except Exception as e:
        print("Disconnect error:", e)
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
@events_bp.post("/api/events")
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
            "reminder": data.get("reminder"),
            "reminder_sent": False,
            "created_at": datetime.utcnow().isoformat(),
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
                    
                    print(f"✅ Event synced to Google Calendar: {result.get('id')}")
                except Exception as e:
                    print(f"❌ Failed to sync to Google Calendar: {e}")
        
        return jsonify({
            "success": True,
            "msg": "Event created successfully",
            "event_id": event_id
        }), 201
        
    except Exception as e:
        print("Create event error:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.get("/api/events")
@require_auth
def get_events():
    """Get all events for the authenticated user - ✨ FIXED"""
    try:
        user_id = request.user_data["user_id"]
        
        # ✅ FIX: Get events without order_by to avoid index error
        events_ref = db.collection("events")
        query = events_ref.where("user_id", "==", user_id)
        docs = query.stream()
        
        events = []
        for doc in docs:
            event_data = doc.to_dict()
            event_data["id"] = doc.id
            events.append(event_data)
        
        # ✅ Sort in Python instead of Firestore
        events.sort(key=lambda x: x.get("start", ""))
        
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
                    
                    print(f"✅ Fetched {len(google_events.get('items', []))} events from Google Calendar")
                except Exception as e:
                    print(f"❌ Failed to fetch from Google Calendar: {e}")
        
        return jsonify({
            "success": True,
            "events": events,
            "count": len(events)
        })
        
    except Exception as e:
        print("Get events error:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.put("/api/events/<event_id>")
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
        for field in ["title", "start", "end", "type", "description", "reminder"]:
            if field in data:
                update_data[field] = data[field]
        
        update_data["updated_at"] = datetime.utcnow().isoformat()
        
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
                        
                        print(f"✅ Event updated in Google Calendar: {google_event_id}")
                    except Exception as e:
                        print(f"❌ Failed to update in Google Calendar: {e}")
        
        return jsonify({
            "success": True,
            "msg": "Event updated successfully"
        })
        
    except Exception as e:
        print("Update event error:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.delete("/api/events/<event_id>")
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
                        print(f" Event deleted from Google Calendar: {google_event_id}")
                    except Exception as e:
                        print(f" Failed to delete from Google Calendar: {e}")
        
        # Delete from Firestore
        events_ref.document(event_id).delete()
        
        return jsonify({
            "success": True,
            "msg": "Event deleted successfully"
        })
        
    except Exception as e:
        print("Delete event error:", e)
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500