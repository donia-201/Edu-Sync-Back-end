import os

# Frontend Configuration
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://edu-sync-gold.vercel.app")

# Firebase Configuration
SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://edu-sync-back-end-production.up.railway.app/google-callback")

# Google Calendar Configuration
REDIRECT_URI_CALENDAR = os.getenv(
    "REDIRECT_URI_CALENDAR",
    "https://edu-sync-back-end-production.up.railway.app/google-calendar-callback"
)
CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.events"

# YouTube API Configuration
YOUTUBE_API_KEY = os.getenv("API_KEY")

# Server Configuration
PORT = int(os.getenv("PORT", 8080))