import json
import firebase_admin
from firebase_admin import credentials, firestore
from config import SERVICE_ACCOUNT_JSON

def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    if SERVICE_ACCOUNT_JSON:
        try:
            cred = credentials.Certificate(json.loads(SERVICE_ACCOUNT_JSON))
            if not firebase_admin._apps:
                firebase_admin.initialize_app(cred)
            print("Firebase initialized successfully")
        except Exception as e:
            print(f"Firebase initialization error: {e}")
    else:
        print("Warning: FIREBASE_SERVICE_ACCOUNT_JSON not provided.")

initialize_firebase()

db = firestore.client()
users_ref = db.collection("users")
sessions_ref = db.collection("sessions")
events_ref = db.collection("events")
notifications_ref = db.collection("notifications")
