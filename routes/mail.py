from flask import Blueprint, request, jsonify
import smtplib
from email.mime.text import MIMEText
import os
from email.mime.multipart import MIMEMultipart
from config import EMAIL_USER, EMAIL_PASSWORD, FRONTEND_ORIGIN
from flask_cors import CORS

mail_bp = Blueprint("mail", __name__)

CORS(mail_bp, origins=[FRONTEND_ORIGIN])

# ===========================
# Route لإرسال البريد
# ===========================
@mail_bp.route("/api/send-email", methods=["POST"])
def send_email():
    try:
        data = request.get_json()
        name = data.get("name")
        email = data.get("email")
        subject = data.get("subject")
        message = data.get("message")

        if not all([name, email, subject, message]):
            return jsonify({"success": False, "msg": "Missing fields"}), 400

        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER       
        msg["Subject"] = f"Contact Form: {subject}"

        body = f"Name: {name}\nEmail: {email}\nMessage:\n{message}"
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.send_message(msg)

        return jsonify({"success": True, "msg": "Email sent successfully"})

    except Exception as e:
        print("Email send error:", e)
        return jsonify({"success": False, "msg": str(e)}), 500


