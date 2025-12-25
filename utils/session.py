import secrets
from datetime import datetime, timedelta
from firebase_admin import firestore
from utils.firebase_config import sessions_ref

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