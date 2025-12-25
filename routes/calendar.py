from flask import Blueprint, redirect, jsonify
from urllib.parse import urlencode
import os

from utils.auth import require_auth
from utils.firebase_config import users_ref

calendar_bp = Blueprint("calendar", __name__)

@calendar_bp.get("/connect-google-calendar")
@require_auth
def connect_calendar():
    params = {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "redirect_uri": os.getenv("REDIRECT_URI_CALENDAR"),
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/calendar.events",
        "access_type": "offline",
        "prompt": "consent",
        "state": request.user_data["user_id"]
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))


@calendar_bp.get("/calendar-status")
@require_auth
def calendar_status():
    user = users_ref.document(request.user_data["user_id"]).get().to_dict()
    return jsonify({"connected": user.get("google_calendar_connected", False)})
