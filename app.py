from flask import Flask, request, jsonify, make_response
import os
import json
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests
print("ENV:", os.environ)


app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response



SERVICE_ACCOUNT_JSON = os.getenv("FIREBASE_SERVICE_ACCOUNT_JSON")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

cred = credentials.Certificate(json.loads(SERVICE_ACCOUNT_JSON))
try:
    firebase_admin.get_app()
except ValueError:
    firebase_admin.initialize_app(cred)

db = firestore.client()
users_ref = db.collection("users")




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

        if list(users_ref.where("email", "==", email).stream()):
            return jsonify({"success": False, "msg": "Email already exists"}), 400

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

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "https://b72a9bfe-19ab-4e55-aa04-388ba10e8bc9-00-kxyqxw13s269.worf.replit.dev/google-callback"

@app.route("/google-callback")
def google_callback():
    code = request.args.get("code")
    if not code:
        return "No code received", 400

    # استبدال الـ code بـ token
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    r = requests.post(token_url, data=data)
    token_response = r.json()

    id_token = token_response.get("id_token")
    access_token = token_response.get("access_token")

    if id_token:
        # هنا ممكن تتحقق من الـ id_token أو تخزن البيانات في الـ Firestore
        return "Login successful!"
    else:
        return "Failed to get token", 400

@app.get("/")
def home():
    return "Backend with Firebase is running!"


if __name__ == "__main__":
    port = os.getenv("PORT")
    port = int(os.getenv("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
    
