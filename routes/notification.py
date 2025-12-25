from flask import Blueprint, request, jsonify
from firebase_admin import firestore
from datetime import datetime

from utils.firebase_config import db
from utils.auth import require_auth

notifications_bp = Blueprint('notifications', __name__, url_prefix='/api/notifications')

@notifications_bp.get("")
@require_auth
def get_notifications():
    """Get all notifications for the authenticated user"""
    try:
        user_id = request.user_data["user_id"]

        notifications_ref = db.collection("notifications")
        docs = notifications_ref.where("user_id", "==", user_id)\
                                .order_by("created_at", direction=firestore.Query.DESCENDING)\
                                .stream()

        notifications = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            notifications.append(data)

        return jsonify({
            "success": True,
            "notifications": notifications,
            "count": len(notifications)
        })
    except Exception as e:
        print(f"Get notifications error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "msg": str(e)}), 500

@notifications_bp.put("/<notification_id>/read")
@require_auth
def mark_notification_read(notification_id):
    """Mark a notification as read"""
    try:
        notif_ref = db.collection("notifications").document(notification_id)
        
        if not notif_ref.get().exists:
            return jsonify({"success": False, "msg": "Notification not found"}), 404

        notif_ref.update({"is_read": True})

        return jsonify({"success": True, "msg": "Notification marked as read"})
    except Exception as e:
        print(f"Mark notification read error: {e}")
        return jsonify({"success": False, "msg": str(e)}), 500

def process_event_reminders():
    """Background process to send event reminders (call this from a scheduler)"""
    try:
        now = datetime.utcnow().isoformat()
        
        events_ref = db.collection("events")
        query = events_ref.where("reminder_sent", "==", False)

        for doc in query.stream():
            event = doc.to_dict()
            reminder_time = event.get("reminder")

            if reminder_time and reminder_time <= now:
                # Create notification
                db.collection("notifications").add({
                    "user_id": event["user_id"],
                    "title": "Event Reminder",
                    "message": f"You have {event['title']} session soon",
                    "event_id": doc.id,
                    "is_read": False,
                    "created_at": now
                })

                # Mark reminder as sent
                events_ref.document(doc.id).update({
                    "reminder_sent": True
                })
                
                print(f" Reminder sent for event: {event['title']}")
    except Exception as e:
        print(f" Process reminders error: {e}")