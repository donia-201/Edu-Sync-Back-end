from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = Flask(__name__)
CORS(app)

# -----------------------------
# Firebase Initialization
# -----------------------------
SERVICE_ACCOUNT_PATH = r"C:\Users\Dona\Downloads\edu-sync-adcb0-firebase-adminsdk-fbsvc-81ea8023ac.json"  
GOOGLE_CLIENT_ID = "562682529890-tq8hjqqtml1kp2oop25i6j7gheiu89h1.apps.googleusercontent.com"  

cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app(cred)

db = firestore.client()
users_ref = db.collection("users")
# sign up
@app.post("/signup")
def signup():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "msg": "Invalid JSON"}), 400

        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "").strip()

        if not username or not email or not password:
            return jsonify({"success": False, "msg": "All fields are required"}), 400

        # Check if email exists
        if list(users_ref.where("email", "==", email).stream()):
            return jsonify({"success": False, "msg": "Email already exists"}), 400

        # Check if username exists
        if list(users_ref.where("username", "==", username).stream()):
            return jsonify({"success": False, "msg": "Username already exists"}), 400

        hashed_password = generate_password_hash(password)

        users_ref.add({
            "username": username,
            "email": email,
            "password": hashed_password
        })

        return jsonify({"success": True, "msg": "User registered successfully"})

    except Exception as e:
        print("Signup error:", e)
        return jsonify({"success": False, "msg": "Server error"}), 500


# -----------------------------
# TRADITIONAL LOGIN
# -----------------------------
@app.post("/login")
def login():
    data = request.json
    user_input = data.get("user", "").strip()
    password = data.get("password", "").strip()

    if not user_input or not password:
        return jsonify({"success": False, "msg": "All fields are required"}), 400

    query = users_ref.where("email", "==", user_input).get()

    if not query:
        query = users_ref.where("username", "==", user_input).get()

    if not query:
        return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

    user_data = query[0].to_dict()

    if not check_password_hash(user_data["password"], password):
        return jsonify({"success": False, "msg": "Invalid username/email or password"}), 401

    return jsonify({"success": True, "msg": "Login successful"})

# -----------------------------
# GOOGLE SIGN-IN
# -----------------------------
@app.route("/google-signin", methods=["POST"])
def google_signin():
    token = request.json.get("token")
    if not token:
        return jsonify({"success": False, "msg": "Token is required"}), 400

    try:
        # تحقق من الـ token
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        userid = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')

        # تحقق لو اليوزر موجود في Firestore
        user_doc = users_ref.document(userid).get()
        if not user_doc.exists:
            users_ref.document(userid).set({
                "name": name,
                "email": email
            })

        return jsonify({"success": True})

    except ValueError:
        return jsonify({"success": False, "msg": "Invalid token"}), 400

# -----------------------------
# HOME ROUTE
# -----------------------------
@app.get("/")
def home():
    return "Backend with Firebase is running!"

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
