from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET

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