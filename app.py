"""
app.py
=======
Flask application for the AI Phishing & Scam Detector.

What this file does:
  - Serves the main dashboard page (index.html) at the root URL.
  - Provides a JSON API endpoint at /api/analyze that accepts a URL
    or a text message and returns a risk analysis.
  - Loads the trained machine-learning model saved by train_model.py.
  - Combines the ML prediction with rule-based heuristics (suspicious
    keywords, URL structure checks) to produce a risk level, risk score,
    warning signs, and safety advice.

Run with:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

import os
import re
import urllib.parse
import joblib
from flask import Flask, request, jsonify, render_template

# --------------------------------------------------------------------
# Flask app setup
# --------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")

app = Flask(__name__)

# --------------------------------------------------------------------
# Load the trained model
# --------------------------------------------------------------------
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print(f"Model loaded from {MODEL_PATH}")
else:
    print("WARNING: Model file not found. Run 'python train_model.py' first.")
    print("The app will use rule-based heuristics only until the model is trained.")

# --------------------------------------------------------------------
# Suspicious keyword lists used by the rule-based checker
# --------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "free", "winner", "win", "prize", "claim", "urgent", "verify",
    "suspended", "compromised", "password", "bank", "account", "credit",
    "card", "ssn", "social security", "wire", "transfer", "gift card",
    "limited time", "act now", "click here", "congratulations",
    "selected", "cash prize", "refund", "irs", "tax", "arrest",
    "rich", "work from home", "no credit check", "pre-approved",
    "processing fee", "lucky", "unlock", "deactivate", "secure login",
    "reset your password", "confirm your details", "update payment",
]

SUSPICIOUS_URL_PATTERNS = [
    r"\bbit\.ly\b",          # short link services (often used to hide real URL)
    r"\btinyurl\b",
    r"\bgoo\.gl\b",
    r"\bip-\d",              # IP-address-based URLs
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # raw IP address
    r"@{1}",                 # @ symbol in URL (can redirect to a different site)
    r"//.*//",               # double slashes after the protocol
    r"-{2,}",                # many dashes (common in fake URLs)
]

URL_SECURITY_KEYWORDS = [
    "secure", "login", "signin", "account", "verify", "update",
    "password", "bank", "paypal", "apple", "amazon", "netflix",
]


# --------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------
def _keyword_hits(text):
    """Return the list of suspicious keywords found in *text*."""
    lower = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]


def _url_warning_signs(url):
    """Return a list of human-readable warning signs for a URL."""
    signs = []
    lower = url.lower()

    for pattern in SUSPICIOUS_URL_PATTERNS:
        if re.search(pattern, lower):
            if "bit.ly" in pattern or "tinyurl" in pattern or "goo.gl" in pattern:
                signs.append("Uses a link-shortening service that hides the real destination")
            elif "ip" in pattern or re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", pattern):
                signs.append("Uses a raw IP address instead of a domain name")
            elif "@" in pattern:
                signs.append("Contains an '@' symbol which can redirect to a different site")
            elif "//.*//" in pattern:
                signs.append("Has unusual double-slash patterns in the address")
            else:
                signs.append("Contains multiple dashes, often used in fake URLs")

    # Check for many subdomains (e.g. login.secure.account.attacker.com)
    if lower.startswith("http"):
        try:
            parsed = urllib.parse.urlparse(lower)
            host = parsed.netloc or parsed.path
            dots = host.count(".")
            if dots >= 4:
                signs.append("Has an unusually high number of subdomains")
        except Exception:
            pass

    # Security-sensitive words in a non-HTTPS URL
    if lower.startswith("http://"):
        security_word = next((kw for kw in URL_SECURITY_KEYWORDS if kw in lower), None)
        if security_word:
            signs.append(f"Contains the word '{security_word}' but is not using HTTPS encryption")

    # Very long URLs
    if len(url) > 75:
        signs.append("The URL is unusually long, which can be used to hide the real destination")

    return signs


def _message_warning_signs(text):
    """Return a list of human-readable warning signs for a message."""
    signs = []
    lower = text.lower()
    hits = _keyword_hits(text)

    if hits:
        signs.append(f"Contains suspicious keywords: {', '.join(hits[:5])}")

    if any(w in lower for w in ["urgent", "immediately", "act now", "right now"]):
        signs.append("Creates a false sense of urgency to pressure you into acting quickly")

    if any(w in lower for w in ["free", "winner", "prize", "congratulations", "lucky"]):
        signs.append("Offers something for free or claims you won a prize")

    if any(w in lower for w in ["password", "bank", "card", "ssn", "social security", "account"]):
        signs.append("Asks for sensitive personal or financial information")

    if re.search(r"http[s]?://\S+", lower):
        signs.append("Contains a clickable link -- verify the destination before clicking")

    if any(w in lower for w in ["wire", "transfer", "send money", "processing fee", "send $"]):
        signs.append("Asks you to send money or pay a fee")

    if any(w in lower for w in ["deactivate", "suspend", "locked", "closed", "terminate"]):
        signs.append("Threatens that your account will be closed or suspended")

    return signs


def _score_from_signs(signs):
    """Convert a list of warning signs into a 0-100 risk score."""
    base = 5  # small base score so a totally clean input is not 0
    per_sign = min(15, max(8, 100 // max(len(signs), 1)))
    return min(95, base + len(signs) * per_sign) if signs else base


def _risk_level(score):
    """Map a 0-100 risk score to a human-readable risk level."""
    if score >= 70:
        return "High Risk"
    if score >= 40:
        return "Medium Risk"
    return "Low Risk"


def _safety_advice(risk_level, check_type):
    """Return safety advice appropriate to the risk level and check type."""
    base_advice = {
        "High Risk": (
            "This looks very suspicious. Do NOT click any links, download attachments, "
            "or share personal information. Delete the message or close the page."
        ),
        "Medium Risk": (
            "This has some warning signs. Be cautious. Do not share personal information "
            "and verify the source through an official channel before taking any action."
        ),
        "Low Risk": (
            "No major warning signs were detected, but always stay alert. If something "
            "feels wrong, trust your instincts and verify independently."
        ),
    }
    advice = base_advice.get(risk_level, base_advice["Low Risk"])

    if check_type == "url" and risk_level != "Low Risk":
        advice += "  Type the website address directly into your browser instead of clicking the link."
    if check_type == "message" and risk_level != "Low Risk":
        advice += "  Contact the organisation directly using a phone number or website you trust."

    return advice


def analyze_input(text, check_type):
    """
    Run the full analysis pipeline and return a results dictionary.
    This combines the ML model prediction with rule-based heuristics.
    """
    # --- Rule-based warning signs ---------------------------------------
    if check_type == "url":
        signs = _url_warning_signs(text)
        keyword_hits = _keyword_hits(text)
        if keyword_hits:
            signs.append(f"Contains suspicious keywords: {', '.join(keyword_hits[:5])}")
    else:
        signs = _message_warning_signs(text)

    rule_score = _score_from_signs(signs)

    # --- Machine-learning prediction ------------------------------------
    ml_label = None
    ml_prob = None
    if model is not None:
        try:
            prediction = model.predict([text])[0]
            probabilities = model.predict_proba([text])[0]
            classes = model.classes_
            prob_map = dict(zip(classes, probabilities))
            ml_label = prediction
            ml_prob = prob_map.get(prediction, 0.0)
        except Exception:
            ml_label = None

    # --- Combine ML and rule-based scores -------------------------------
    if ml_label == "phishing":
        # Weight the ML score higher when the model is confident
        ml_score = int(40 + (ml_prob or 0.5) * 50)  # 40-90 range
        final_score = max(rule_score, ml_score)
    elif ml_label == "legitimate":
        # If the model says legitimate, reduce the score somewhat
        # but do NOT override clear rule-based warnings
        if rule_score >= 60:
            final_score = rule_score  # keep the high warning
        else:
            final_score = max(5, int(rule_score * 0.5))
    else:
        # No model available -- rely on rules only
        final_score = rule_score

    final_score = max(0, min(100, final_score))
    risk_level = _risk_level(final_score)
    advice = _safety_advice(risk_level, check_type)

    # Source of the prediction for transparency
    sources = []
    if model is not None and ml_label is not None:
        sources.append(f"ML model predicts: {ml_label} ({(ml_prob or 0):.0%} confidence)")
    sources.append(f"Rule-based heuristics found {len(signs)} warning sign(s)")

    return {
        "risk_level": risk_level,
        "risk_score": final_score,
        "warning_signs": signs if signs else ["No specific warning signs detected."],
        "safety_advice": advice,
        "model_prediction": ml_label,
        "model_confidence": round(ml_prob, 2) if ml_prob is not None else None,
        "analysis_sources": sources,
    }


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------
@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """API endpoint that receives text and returns the risk analysis."""
    data = request.get_json(silent=True)

    if not data or "text" not in data or not data.get("text", "").strip():
        return jsonify({"error": "Please provide text or a URL to analyze."}), 400

    check_type = data.get("check_type", "message")
    if check_type not in ("url", "message"):
        check_type = "message"

    text = data["text"].strip()

    # Basic length guard
    if len(text) > 5000:
        return jsonify({"error": "Input is too long. Please keep it under 5000 characters."}), 400

    try:
        results = analyze_input(text, check_type)
        results["input_text"] = text
        results["check_type"] = check_type
        results["disclaimer"] = (
            "This is an educational demonstration using a small sample dataset. "
            "Results are NOT a guarantee of safety. Always use your own judgement."
        )
        return jsonify(results)
    except Exception as exc:
        # Never treat a failed analysis as safe
        return jsonify({
            "error": "An error occurred during analysis. This does NOT mean the input is safe.",
            "details": str(exc),
        }), 500


# --------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
