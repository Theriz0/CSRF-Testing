from flask import Flask, request, jsonify, send_file
import os
import hashlib

app = Flask(__name__)

# Simulated session storage for CSRF tokens
session = {}

# Generate CSRF token
def generate_csrf_token():
    # Generate a random token using os.urandom and hash it
    return hashlib.sha256(os.urandom(64)).hexdigest()

# Assign CSRF token to a user
def assign_csrf_token(user_id):
    token = generate_csrf_token()
    session[user_id] = token
    return token

# Validate CSRF token
def validate_csrf_token(user_id, submitted_token):
    stored_token = session.get(user_id)
    return stored_token == submitted_token

# Simulated user data
users = {"1": {"email": "user@example.com"}}

@app.route('/profile')
def profile():
    return send_file('profile.html')

@app.route('/malicious')
def malicious():
    return send_file('malicious.html')

@app.route('/generate-csrf', methods=['POST'])
def generate_csrf():
    data = request.json
    user_id = data.get("id")
    if user_id not in users:
        return jsonify({"error": "User not found"}), 404
    token = assign_csrf_token(user_id)
    return jsonify({"csrfToken": token})

@app.route('/profile/change-email-vulnerable', methods=['POST'])
def change_email_vulnerable():
    data = request.json
    user_id = "1"  # Simulated logged-in user
    email = data.get("email")
    if user_id in users:
        users[user_id]["email"] = email
        return jsonify({"message": "Email changed successfully (vulnerable)."})
    return jsonify({"error": "User not found"}), 404

@app.route('/profile/change-email-safe', methods=['POST'])
def change_email_safe():
    data = request.json
    user_id = "1"  # Simulated logged-in user
    email = data.get("email")
    csrf_token = request.headers.get("csrf-token")
    if validate_csrf_token(user_id, csrf_token):
        if user_id in users:
            users[user_id]["email"] = email
            return jsonify({"message": "Email changed successfully (safe)."})
    return jsonify({"error": "Invalid CSRF token"}), 403

@app.route('/profile/account-email', methods=['GET'])
def account_email():
    user_id = "1"  # Simulated logged-in user
    if user_id in users:
        return jsonify(users[user_id]["email"])
    return jsonify({"error": "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)