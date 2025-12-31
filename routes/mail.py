from flask import Blueprint, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_ADDRESS, EMAIL_PASSWORD

mail_bp = Blueprint("mail", __name__)

@mail_bp.route("/api/send-email", methods=["POST"])
def send_email():
    data = request.get_json()

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    subject = data.get("subject", "").strip()
    message = data.get("message", "").strip()

    if not all([name, email, subject, message]):
        return jsonify({"success": False, "msg": "All fields are required"}), 400

    if "@" not in email:
        return jsonify({"success": False, "msg": "Invalid email format"}), 400

    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return jsonify({"success": False, "msg": "Email not configured"}), 500

    msg = MIMEMultipart()
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = EMAIL_ADDRESS
    msg["Subject"] = f"EduSync Contact: {subject}"
    msg["Reply-To"] = email

    msg.attach(MIMEText(message, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)

        return jsonify({"success": True, "msg": "Email sent successfully"}), 200

    except Exception as e:
        print("EMAIL ERROR:", e)
        return jsonify({"success": False, "msg": "Failed to send email"}), 500
