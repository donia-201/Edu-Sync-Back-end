from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore
from werkzeug.security import generate_password_hash, check_password_hash
import os, json

app = Flask(__name__)
CORS(app)

# -----------------------------
# Firebase Connection
# -----------------------------
firebase_key = os.environ.get("FIREBASE_KEY")

if firebase_key:
    firebase_key_dict = json.loads(firebase_key)
    cred = credentials.Certificate(firebase_key_dict)
    firebase_admin.initialize_app(cred)
else:
    raise Exception("Firebase key missing!")

db = firestore.client()
users_ref = db.collection("users")


# -----------------------------
# SIGNUP
# -----------------------------
@app.post("/signup")
def signup():
    data = request.json  
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not username or not email or not password:
        return jsonify({"success": False, "msg": "All fields are required"}), 400

    if users_ref.where("email", "==", email).get():
        return jsonify({"success": False, "msg": "Email already exists"}), 400

    if users_ref.where("username", "==", username).get():
        return jsonify({"success": False, "msg": "Username already exists"}), 400

    hashed_password = generate_password_hash(password)

    users_ref.add({
        "username": username,
        "email": email,
        "password": hashed_password
    })

    return jsonify({"success": True, "msg": "User registered successfully"})


# -----------------------------
# LOGIN
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
# HOME
# -----------------------------
@app.get("/")
def home():
    return "Backend with Firebase is running!"


if __name__ == "__main__":
    app.run()