from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import re

app = Flask(__name__)
CORS(app)

client = MongoClient("mongodb://localhost:27017/")
db = client["phishing_db"]
users = db["users"]
scans = db["scans"]

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

# Signup
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if users.find_one({"username": data["username"]}):
        return jsonify({"message": "User exists"}), 400

    users.insert_one({
        "username": data["username"],
        "password": generate_password_hash(data["password"]),
        "token": ""
    })

    return jsonify({"message": "Signup successful"})

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = users.find_one({"username": data["username"]})

    if user and check_password_hash(user["password"], data["password"]):
        token = str(uuid.uuid4())

        users.update_one(
            {"username": data["username"]},
            {"$set": {"token": token}}
        )

        return jsonify({"token": token})

    return jsonify({"message": "Invalid credentials"}), 401

# Scan
@app.route("/scan", methods=["POST"])
def scan():
    token = request.headers.get("Authorization")
    user = users.find_one({"token": token})

    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = request.get_json()
    result = detect_phishing(data["url"])

    scans.insert_one({
        "url": data["url"],
        "result": result,
        "user": user["username"]
    })

    return jsonify(result)

# History
@app.route("/history", methods=["GET"])
def history():
    token = request.headers.get("Authorization")
    user = users.find_one({"token": token})

    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    data = list(scans.find({"user": user["username"]}, {"_id": 0}))
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)