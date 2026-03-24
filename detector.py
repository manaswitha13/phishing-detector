import re

def detect_phishing(url):
    score = 0
    reasons = []

    if len(url) > 75:
        score += 20
        reasons.append("URL is too long")

    keywords = ["login", "secure", "verify", "update", "bank"]
    for word in keywords:
        if word in url.lower():
            score += 15
            reasons.append(f"Contains suspicious keyword: {word}")

    if url.startswith("http://"):
        score += 20
        reasons.append("Not using HTTPS")

    if url.count('.') > 3:
        score += 15
        reasons.append("Too many subdomains")

    if re.match(r"^http[s]?://\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("Uses IP address instead of domain")

    if score >= 60:
        label = "Phishing"
    elif score >= 30:
        label = "Suspicious"
    else:
        label = "Safe"

    return {
        "score": score,
        "label": label,
        "reasons": reasons
    }