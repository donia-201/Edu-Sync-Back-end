from flask import Blueprint, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import EMAIL_USER, EMAIL_PASSWORD, ALLOWED_ORIGINS
from flask_cors import CORS

mail_bp = Blueprint("mail", __name__)

# ✅ Use ALLOWED_ORIGINS from config
CORS(mail_bp, 
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
    supports_credentials=True)

@mail_bp.route("/api/send-email", methods=["POST", "OPTIONS"])
def send_email():
    # Handle preflight OPTIONS request
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        origin = request.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            response.headers.add("Access-Control-Allow-Origin", origin)
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        return response, 200
    
    try:
        # Get request data
        data = request.get_json()
        
        # Validation
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        subject = data.get("subject", "").strip()
        message = data.get("message", "").strip()
        
        if not all([name, email, subject, message]):
            return jsonify({
                "success": False, 
                "msg": "All fields are required"
            }), 400
        
        # Basic email validation
        if "@" not in email or "." not in email.split("@")[1]:
            return jsonify({
                "success": False, 
                "msg": "Invalid email format"
            }), 400
        
        # Check if email credentials are configured
        if not EMAIL_USER or not EMAIL_PASSWORD:
            print(" Email credentials not configured!")
            return jsonify({
                "success": False,
                "msg": "Email service not configured"
            }), 500
        
        # Create email message
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = EMAIL_USER
        msg["Subject"] = f"EduSync Contact: {subject}"
        msg["Reply-To"] = email
        
        # Email body
        body = f"""
 New Contact Form Submission
========================================

 Name: {name}
 Email: {email}
 Subject: {subject}

 Message:
{message}

========================================
Sent from: EduSync Contact Form
Time: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        msg.attach(MIMEText(body, "plain"))
        
        # Send email with proper error handling
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
                server.starttls()
                server.login(EMAIL_USER, EMAIL_PASSWORD)
                server.send_message(msg)
            
            print(f" Email sent successfully from: {email}")
            
            response = jsonify({
                "success": True, 
                "msg": "Email sent successfully"
            })
            
            # Add CORS header
            origin = request.headers.get("Origin")
            if origin in ALLOWED_ORIGINS:
                response.headers.add("Access-Control-Allow-Origin", origin)
            
            return response, 200
            
        except smtplib.SMTPAuthenticationError as auth_err:
            print(f" SMTP Authentication Error: {auth_err}")
            return jsonify({
                "success": False, 
                "msg": "Email authentication failed. Please check server configuration."
            }), 500
            
        except smtplib.SMTPException as smtp_err:
            print(f" SMTP Error: {smtp_err}")
            return jsonify({
                "success": False, 
                "msg": "Failed to send email. Please try again later."
            }), 500
        
    except Exception as e:
        print(f" Unexpected Error: {type(e).__name__}: {str(e)}")
        return jsonify({
            "success": False, 
            "msg": "Server error occurred. Please try again later."
        }), 500


# Health check endpoint for the mail service
@mail_bp.route("/api/mail-status", methods=["GET"])
def mail_status():
    """Check if email service is configured properly"""
    is_configured = bool(EMAIL_USER and EMAIL_PASSWORD)
    
    return jsonify({
        "status": "configured" if is_configured else "not_configured",
        "email_user": EMAIL_USER if is_configured else None,
        "ready": is_configured
    }), 200