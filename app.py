from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import re
import os

app = Flask(__name__)
CORS(app)

# ✅ Use environment variable (Render best practice)
MONGO_URI = os.environ.get("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client["phishing_db"]
users = db["users"]
scans = db["scans"]

# ✅ Home route (fixes "Not Found")
@app.route("/")
def home():
    return jsonify({"message": "Phishing Detector API is running 🚀"})


# 🔍 Detection
def detect_phishing(url):
    score = 0
    reasons = []

    if len(url) > 75:
        score += 20
        reasons.append("Long URL")

    if "login" in url.lower():
        score += 15
        reasons.append("Contains login keyword")

    if url.startswith("http://"):
        score += 20
        reasons.append("Not HTTPS")

    if url.count('.') > 3:
        score += 15
        reasons.append("Too many subdomains")

    if re.match(r"^http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("IP address used")

    if score >= 60:
        label = "Phishing"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Safe"

    return {"score": score, "label": label, "reasons": reasons}


# 🔐 Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"message": "Invalid input"}), 400

    if users.find_one({"username": data["username"]}):
        return jsonify({"message": "User already exists"}), 400

    users.insert_one({
        "username": data["username"],
        "password": generate_password_hash(data["password"]),
        "tokens": []
    })

    return jsonify({"message": "Signup successful"})


# 🔑 Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    user = users.find_one({"username": data.get("username")})

    if user and check_password_hash(user["password"], data.get("password")):
        token = str(uuid.uuid4())

        users.update_one(
            {"username": data["username"]},
            {"$push": {"tokens": token}}
        )

        return jsonify({
            "message": "Login successful",
            "token": token,
            "username": data["username"]
        })

    return jsonify({"message": "Invalid credentials"}), 401


# 🔍 Scan
@app.route("/scan", methods=["POST"])
def scan():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"message": "Token missing"}), 401

    user = users.find_one({"tokens": token})

    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"message": "URL missing"}), 400

    result = detect_phishing(data["url"])

    scans.insert_one({
        "url": data["url"],
        "result": result,
        "user": user["username"]
    })

    return jsonify(result)


# 📜 History
@app.route("/history", methods=["GET"])
def history():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"message": "Token missing"}), 401

    user = users.find_one({"tokens": token})

    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = list(scans.find({"user": user["username"]}, {"_id": 0}))
    return jsonify(data)


# 🚪 Logout
@app.route("/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"message": "Token missing"}), 400

    users.update_one(
        {"tokens": token},
        {"$pull": {"tokens": token}}
    )

    return jsonify({"message": "Logged out successfully"})


# ✅ Deployment-ready
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
