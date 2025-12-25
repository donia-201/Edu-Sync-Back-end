from functools import wraps
from flask import request, jsonify
from datetime import datetime, timezone
from utils.firebase_config import sessions_ref

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
                expires_at = datetime.fromtimestamp(
                    expires_at.timestamp(), 
                    tz=timezone.utc
                ).replace(tzinfo=None)
            
            if datetime.utcnow() > expires_at:
                sessions_ref.document(token).delete()
                return None
        
        return session_data
    except Exception as e:
        print(f"Session verification error: {e}")
        return None

def require_auth(f):
    """Decorator للتحقق من الـ authentication"""
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