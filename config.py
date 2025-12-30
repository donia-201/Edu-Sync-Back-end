import os

# ====================================
# Frontend Configuration
# ====================================
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "https://edu-sync-gold.vercel.app")

# Multiple allowed origins for CORS
ALLOWED_ORIGINS = [
    "https://edu-sync-gold.vercel.app",
    "https://edu-sync-front-end.pages.dev",
    "http://localhost:5500",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
]

# ====================================
# Firebase Configuration
# ====================================
SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")

# ====================================
# Google OAuth Configuration
# ====================================
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv(
    "REDIRECT_URI", 
    "https://edu-sync-back-end-production.up.railway.app/google-callback"
)

# ====================================
# Google Calendar Configuration
# ====================================
REDIRECT_URI_CALENDAR = os.getenv(
    "REDIRECT_URI_CALENDAR",
    "https://edu-sync-back-end-production.up.railway.app/google-calendar-callback"
)
CALENDAR_SCOPE = "https://www.googleapis.com/auth/calendar.events"

# ====================================
# YouTube API Configuration
# ====================================
YOUTUBE_API_KEY = os.getenv("API_KEY")

# ====================================
# Email Configuration (Contact Form)
# ====================================
EMAIL_USER = os.getenv("EMAIL_USER")          
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

# Email validation
if not EMAIL_USER or not EMAIL_PASSWORD:
    print("  WARNING: EMAIL_USER or EMAIL_PASSWORD not set!")
    print("   Contact form will not work without these credentials.")

# ====================================
# Server Configuration
# ====================================
PORT = int(os.getenv("PORT", 8080))
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# ====================================
# Environment Info (for debugging)
# ====================================
ENV = os.getenv("ENVIRONMENT", "production")

