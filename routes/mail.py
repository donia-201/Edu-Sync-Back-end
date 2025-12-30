from flask import Blueprint, request, jsonify
import smtplib
from email.mime.text import MIMEText
import os

mail_bp = Blueprint("mail", __name__)

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL", EMAIL_ADDRESS)


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

        msg = MIMEText(f"""
        New message from website:

        Name: {name}
        Email: {email}

        Message:
        {message}
        """)

        msg["Subject"] = f" {subject}"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = RECEIVER_EMAIL

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        return jsonify({"success": True, "message": "Email sent successfully"})

    except Exception as e:
        print("EMAIL ERROR:", e)
        return jsonify({"success": False, "error": str(e)}), 500
