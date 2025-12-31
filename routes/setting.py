from flask import Blueprint, request, jsonify
from datetime import datetime
from utils.firebase_config import db, users_ref
from utils.auth import require_auth

setting_bp = Blueprint('setting', __name__)


# ===================================
# Get User Profile & Settings
# ===================================
@setting_bp.route("/api/user/profile", methods=["GET"])
@require_auth
def get_user_profile():
    """Get user profile and setting"""
    try:
        user_id = request.user_data["user_id"]
        
        print(f"📥 [SETTINGS] Get profile for user: {user_id}")
        
        # Get user document
        user_doc = users_ref.document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "msg": "User not found"
            }), 404
        
        user_data = user_doc.to_dict()
        
        # Prepare response with safe data
        profile_data = {
            "user_id": user_id,
            "name": user_data.get("name", ""),
            "email": user_data.get("email", ""),
            "photo_url": user_data.get("photo_url", ""),
            "created_at": user_data.get("created_at", ""),
            
            # Settings
            "settings": {
                "theme": user_data.get("theme", "light"),
                "language": user_data.get("language", "en"),
                "font_size": user_data.get("font_size", "medium"),
                "pomodoro_duration": user_data.get("pomodoro_duration", 25),
                "short_break": user_data.get("short_break", 5),
                "long_break": user_data.get("long_break", 15),
                "notifications_enabled": user_data.get("notifications_enabled", True),
                "sound_enabled": user_data.get("sound_enabled", True)
            },
            
            # Stats
            "google_calendar_connected": user_data.get("google_calendar_connected", False)
        }
        
        print(f" [SETTINGS] Profile retrieved for: {user_data.get('name')}")
        
        return jsonify({
            "success": True,
            "user": profile_data
        })
        
    except Exception as e:
        print(f" [SETTINGS] Get profile error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "msg": str(e)
        }), 500


# ===================================
# Update User Settings
# ===================================
@setting_bp.route("/api/user/settings", methods=["PUT"])
@require_auth
def update_user_settings():
    """Update user settings"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        print(f" [SETTINGS] Update settings for user: {user_id}")
        print(f" [SETTINGS] Data: {data}")
        
        # Validate and prepare update data
        update_data = {}
        
        # Theme settings
        if "theme" in data:
            theme = data["theme"]
            if theme in ["light", "dark", "auto"]:
                update_data["theme"] = theme
            else:
                return jsonify({
                    "success": False,
                    "msg": "Invalid theme value. Must be: light, dark, or auto"
                }), 400
        
        # Language settings
        if "language" in data:
            language = data["language"]
            if language in ["en", "ar", "fr"]:
                update_data["language"] = language
            else:
                return jsonify({
                    "success": False,
                    "msg": "Invalid language. Must be: en, ar, or fr"
                }), 400
        
        # Font size
        if "font_size" in data:
            font_size = data["font_size"]
            if font_size in ["small", "medium", "large", "xlarge"]:
                update_data["font_size"] = font_size
            else:
                return jsonify({
                    "success": False,
                    "msg": "Invalid font_size. Must be: small, medium, large, or xlarge"
                }), 400
        
        # Pomodoro timer settings
        if "pomodoro_duration" in data:
            duration = int(data["pomodoro_duration"])
            if 1 <= duration <= 60:
                update_data["pomodoro_duration"] = duration
            else:
                return jsonify({
                    "success": False,
                    "msg": "Pomodoro duration must be between 1 and 60 minutes"
                }), 400
        
        if "short_break" in data:
            short_break = int(data["short_break"])
            if 1 <= short_break <= 30:
                update_data["short_break"] = short_break
            else:
                return jsonify({
                    "success": False,
                    "msg": "Short break must be between 1 and 30 minutes"
                }), 400
        
        if "long_break" in data:
            long_break = int(data["long_break"])
            if 1 <= long_break <= 60:
                update_data["long_break"] = long_break
            else:
                return jsonify({
                    "success": False,
                    "msg": "Long break must be between 1 and 60 minutes"
                }), 400
        
        # Notification settings
        if "notifications_enabled" in data:
            update_data["notifications_enabled"] = bool(data["notifications_enabled"])
        
        if "sound_enabled" in data:
            update_data["sound_enabled"] = bool(data["sound_enabled"])
        
        # Update timestamp
        update_data["settings_updated_at"] = datetime.utcnow().isoformat() + "Z"
        
        # Update in Firestore
        users_ref.document(user_id).update(update_data)
        
        print(f" [SETTINGS] Settings updated for user: {user_id}")
        print(f" [SETTINGS] Updated fields: {list(update_data.keys())}")
        
        return jsonify({
            "success": True,
            "msg": "Settings updated successfully",
            "updated_fields": list(update_data.keys())
        })
        
    except ValueError as e:
        print(f"[SETTINGS] Validation error: {e}")
        return jsonify({
            "success": False,
            "msg": f"Invalid data format: {str(e)}"
        }), 400
        
    except Exception as e:
        print(f" [SETTINGS] Update settings error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "msg": str(e)
        }), 500


# ===================================
# Update User Profile
# ===================================
@setting_bp.route("/api/user/profile", methods=["PUT"])
@require_auth
def update_user_profile():
    """Update user profile (name, etc.)"""
    try:
        user_id = request.user_data["user_id"]
        data = request.get_json()
        
        print(f" [SETTINGS] Update profile for user: {user_id}")
        
        update_data = {}
        
        # Update name
        if "name" in data:
            name = data["name"].strip()
            if name:
                update_data["name"] = name
            else:
                return jsonify({
                    "success": False,
                    "msg": "Name cannot be empty"
                }), 400
        
        # Note: Email cannot be changed (linked to Google auth)
        
        # Update photo URL
        if "photo_url" in data:
            update_data["photo_url"] = data["photo_url"]
        
        update_data["profile_updated_at"] = datetime.utcnow().isoformat() + "Z"
        
        # Update in Firestore
        users_ref.document(user_id).update(update_data)
        
        print(f" [SETTINGS] Profile updated for user: {user_id}")
        
        return jsonify({
            "success": True,
            "msg": "Profile updated successfully"
        })
        
    except Exception as e:
        print(f" [SETTINGS] Update profile error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "msg": str(e)
        }), 500


# ===================================
# Get All Settings (Quick endpoint)
# ===================================
@setting_bp.route("/api/user/settings", methods=["GET"])
@require_auth
def get_user_settings():
    """Get only settings (faster than full profile)"""
    try:
        user_id = request.user_data["user_id"]
        
        user_doc = users_ref.document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({
                "success": False,
                "msg": "User not found"
            }), 404
        
        user_data = user_doc.to_dict()
        
        settings = {
            "theme": user_data.get("theme", "light"),
            "language": user_data.get("language", "en"),
            "font_size": user_data.get("font_size", "medium"),
            "pomodoro_duration": user_data.get("pomodoro_duration", 25),
            "short_break": user_data.get("short_break", 5),
            "long_break": user_data.get("long_break", 15),
            "notifications_enabled": user_data.get("notifications_enabled", True),
            "sound_enabled": user_data.get("sound_enabled", True)
        }
        
        return jsonify({
            "success": True,
            "settings": settings
        })
        
    except Exception as e:
        print(f" [SETTINGS] Get settings error: {e}")
        return jsonify({
            "success": False,
            "msg": str(e)
        }), 500