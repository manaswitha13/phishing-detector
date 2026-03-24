
# 🔐 Phishing Attack Detection System

A full-stack web application that detects phishing URLs in real-time using intelligent rule-based analysis. This system helps users identify potentially malicious websites and protects them from cyber threats.

---

## 🚀 Features

- 🔐 User Authentication (Signup/Login)
- 🔍 Real-time URL Scanning
- 🧠 Intelligent Phishing Detection Algorithm
- 📊 Scan History Tracking
- 📈 Analytics Dashboard (Pie Chart Visualization)
- 🌐 Full Stack Web Application

---

## 🛠️ Tech Stack

### Frontend
- HTML
- CSS (Modern UI)
- JavaScript
- Chart.js (for analytics)

### Backend
- Python (Flask)
- REST API Architecture

### Database
- MongoDB

---

## ⚙️ How It Works

1. User signs up and logs in
2. User enters a URL
3. System analyzes the URL using multiple rules:
   - URL length
   - Suspicious keywords
   - HTTP vs HTTPS
   - Number of subdomains
   - IP-based URLs
4. Based on score, it classifies:
   - ✅ Safe
   - ⚠️ Suspicious
   - ❌ Phishing
5. Results are stored and shown in dashboard

---

## 📊 Detection Logic

The system uses heuristic-based scoring:

| Condition | Score |
|----------|------|
| Long URL | +20 |
| Suspicious Keywords | +15 |
| HTTP (not HTTPS) | +20 |
| Too many subdomains | +15 |
| IP address in URL | +25 |

---

## 🖥️ Screenshots

(Add screenshots here for better presentation)

---

## 🧪 Run Locally

### Backend

```bash
cd backend
pip install -r requirements.txt
python app.py