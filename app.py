from flask import Flask, jsonify
from flask_cors import CORS


# Import configuration
from config import FRONTEND_ORIGIN, PORT

# Initialize Firebase
from utils.firebase_config import initialize_firebase
initialize_firebase()

# Initialize Flask app
app = Flask(__name__)

# CORS Configuration
CORS(app, resources={
    r"/*": {
        "origins": [FRONTEND_ORIGIN, "http://localhost:5000", "http://127.0.0.1:5000"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

@app.after_request
def apply_cors(response):
    """Apply CORS headers to all responses"""
    response.headers["Access-Control-Allow-Origin"] = FRONTEND_ORIGIN
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# Register Blueprints (Routes)
from routes.auth_routes import auth_bp
from routes.notes import notes_bp
from routes.events import events_bp
from routes.calendar import calendar_bp
from routes.notification import notifications_bp
from routes.youtube import youtube_bp
from routes.mail import mail_bp


app.register_blueprint(auth_bp)
app.register_blueprint(notes_bp)
app.register_blueprint(events_bp)
app.register_blueprint(calendar_bp)
app.register_blueprint(notifications_bp)
app.register_blueprint(youtube_bp)
app.register_blueprint(mail_bp)

# Root route
@app.get("/")
def home():
    return jsonify({
        "status": "online",
        "message": "EduSync Backend API is running! 🚀",
        "version": "2.0",
        "endpoints": {
            "auth": ["/signup", "/login", "/logout", "/verify-session", "/google-callback"],
            "notes": ["/api/notes"],
            "events": ["/api/events", "/connect-google-calendar", "/calendar-status"],
            "notifications": ["/api/notifications"],
            "youtube": ["/youtube-search"]
        }
    })

# Health check endpoint
@app.get("/health")
def health_check():
    return jsonify({
        "status": "healthy",
        "timestamp": "2025-12-16"
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "msg": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "msg": "Internal server error"}), 500

# Run the application
if __name__ == "__main__":
    print("=" * 50)
    print("🚀 Starting EduSync Backend Server")
    print(f"📡 PORT: {PORT}")
    print(f"🌐 Frontend Origin: {FRONTEND_ORIGIN}")
    print("=" * 50)
    app.run(host="0.0.0.0", port=PORT, debug=False)