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
# Google Calendar OAuth Routes
# ===================================
@events_bp.get("/connect-google-calendar")
@require_auth
def connect_google_calendar():
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
            print("Calendar token error:", r.text)
            return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_token_failed")

        token_data = r.json()
        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            return redirect(f"{FRONTEND_ORIGIN}/?error=no_refresh_token")

        users_ref.document(user_id).update({
            "google_calendar_refresh_token": refresh_token,
            "google_calendar_connected": True
        })

        return redirect(f"{FRONTEND_ORIGIN}/pages/home.html?calendar=connected")
    except Exception as e:
        print("Calendar callback error:", e)
        import traceback; traceback.print_exc()
        return redirect(f"{FRONTEND_ORIGIN}/?error=calendar_auth_failed")

@events_bp.get("/disconnect-google-calendar")
@require_auth
def disconnect_google_calendar():
    try:
        user_id = request.user_data["user_id"]
        users_ref.document(user_id).update({
            "google_calendar_refresh_token": firestore.DELETE_FIELD,
            "google_calendar_connected": False
        })
        return jsonify({"success": True, "msg": "Calendar disconnected"})
    except Exception as e:
        print("Disconnect error:", e)
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.get("/calendar-status")
@require_auth
def calendar_status():
    try:
        user_id = request.user_data["user_id"]
        user_doc = users_ref.document(user_id).get()
        if not user_doc.exists:
            return jsonify({"success": False, "msg": "User not found"}), 404

        user_data = user_doc.to_dict()
        is_connected = user_data.get("google_calendar_connected", False)
        return jsonify({"success": True, "connected": is_connected})
    except Exception as e:
        print("Calendar status error:", e)
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500


# ===================================
# Events CRUD Routes
# ===================================
@events_bp.route("/api/events", methods=["POST"])
@require_auth
def create_event():
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()

        title = data.get("title")
        start = data.get("start")
        end = data.get("end")
        if not title or not start or not end:
            return jsonify({"success": False, "msg": "Missing required fields: title, start, end"}), 400

        description = data.get("description", "")
        reminder = data.get("reminder", {})

        # Ensure ISO format for start/end
        if "T" not in start:
            start += "T00:00:00Z"
        if "T" not in end:
            end += "T00:00:00Z"

        now_iso = datetime.utcnow().isoformat() + "Z"

        event_data = {
            "user_id": user_id,
            "title": title,
            "start": start,
            "end": end,
            "description": description,
            "reminder": reminder,
            "created_at": now_iso,
            "updated_at": now_iso
        }

        events_ref = db.collection("events")
        doc_ref = events_ref.add(event_data)[1]
        event_id = doc_ref.id
        event_data["id"] = event_id

        # Google Calendar sync
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    g_event_body = convert_to_google_calendar_format(event_data)
                    g_event = service.events().insert(calendarId='primary', body=g_event_body).execute()
                    events_ref.document(event_id).update({"google_event_id": g_event.get("id")})
                    event_data["google_event_id"] = g_event.get("id")
                    event_data["synced_to_google"] = True
                    print(f"✅ Event created in Google Calendar: {g_event.get('id')}")
                except Exception as e:
                    print(f"Failed to sync event to Google Calendar: {e}")

        return jsonify({"success": True, "event": event_data})
    except Exception as e:
        print(f"Create event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.route("/api/events", methods=["GET"])
@require_auth
def get_events():
    try:
        user_id = request.user_data["user_id"]
        events_ref = db.collection("events")
        query = events_ref.where("user_id", "==", user_id)
        docs = query.stream()
        events = []

        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            events.append(data)

        events.sort(key=lambda x: x.get("start", ""))
        
        # Google Calendar merge (next 30 days)
        user_doc = users_ref.document(user_id).get()
        if user_doc.exists:
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    now = datetime.utcnow().isoformat() + "Z"
                    future = (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z"
                    google_events = service.events().list(
                        calendarId='primary', timeMin=now, timeMax=future, singleEvents=True, orderBy='startTime'
                    ).execute()

                    for g_event in google_events.get('items', []):
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
                                "reminder": g_event.get('reminders', {}),
                                "synced_to_google": True,
                                "google_event_id": google_id,
                                "source": "google_calendar"
                            })
                except Exception as e:
                    print(f"Failed to fetch from Google Calendar: {e}")

        return jsonify({"success": True, "events": events, "count": len(events)})
    except Exception as e:
        print(f"Get events error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.route("/api/events/<event_id>", methods=["PUT"])
@require_auth
def update_event(event_id):
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        events_ref = db.collection("events")
        event_doc = events_ref.document(event_id).get()
        if not event_doc.exists:
            return jsonify({"success": False, "msg": "Event not found"}), 404

        event_data = event_doc.to_dict()
        if event_data.get("user_id") != user_id:
            return jsonify({"success": False, "msg": "Unauthorized"}), 403

        update_data = {}
        for field in ["title", "start", "end", "description", "reminder"]:
            if field in data:
                value = data[field]
                if field in ["start", "end"] and "T" not in value:
                    value += "T00:00:00Z"
                update_data[field] = value

        update_data["updated_at"] = datetime.utcnow().isoformat() + "Z"
        events_ref.document(event_id).update(update_data)

        google_event_id = event_data.get("google_event_id")
        if google_event_id:
            user_doc = users_ref.document(user_id).get()
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    g_event = service.events().get(calendarId='primary', eventId=google_event_id).execute()
                    if "title" in update_data:
                        g_event["summary"] = update_data["title"]
                    if "description" in update_data:
                        g_event["description"] = update_data["description"]
                    if "start" in update_data:
                        g_event["start"] = {"dateTime": update_data["start"], "timeZone": "Africa/Cairo"}
                    if "end" in update_data:
                        g_event["end"] = {"dateTime": update_data["end"], "timeZone": "Africa/Cairo"}
                    service.events().update(calendarId='primary', eventId=google_event_id, body=g_event).execute()
                except Exception as e:
                    print(f"Failed to update in Google Calendar: {e}")

        return jsonify({"success": True, "msg": "Event updated successfully"})
    except Exception as e:
        print(f"Update event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@events_bp.route("/api/events/<event_id>", methods=["DELETE"])
@require_auth
def delete_event(event_id):
    try:
        user_id = request.user_data["user_id"]
        events_ref = db.collection("events")
        event_doc = events_ref.document(event_id).get()
        if not event_doc.exists:
            return jsonify({"success": False, "msg": "Event not found"}), 404

        event_data = event_doc.to_dict()
        if event_data.get("user_id") != user_id:
            return jsonify({"success": False, "msg": "Unauthorized"}), 403

        google_event_id = event_data.get("google_event_id")
        if google_event_id:
            user_doc = users_ref.document(user_id).get()
            refresh_token = user_doc.to_dict().get("google_calendar_refresh_token")
            if refresh_token:
                try:
                    service = get_calendar_service(refresh_token)
                    service.events().delete(calendarId='primary', eventId=google_event_id).execute()
                except Exception as e:
                    print(f"Failed to delete from Google Calendar: {e}")

        events_ref.document(event_id).delete()
        return jsonify({"success": True, "msg": "Event deleted successfully"})
    except Exception as e:
        print(f"Delete event error: {e}")
        import traceback; traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500
