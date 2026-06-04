import os
import re
from google import genai


# Only run this block for Gemini Developer API
client = genai.Client()

# ──────────────────────────────────────────
# PART A: Rule-Based Scorer (No AI needed)
# ──────────────────────────────────────────
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "limited time", "expires", 
    "suspended", "verify now", "confirm now", "unusual activity", 
    "unauthorized", "locked", "restricted", "within 24 hours"
]
CREDENTIAL_WORDS = [
    "enter your password", "confirm your password", "verify your identity", 
    "update your billing", "enter your credit card", "social security", 
    "login credentials", "sign in to verify"
]
SUSPICIOUS_PHRASES = [
    "click here", "click the link", "dear customer", "dear user", 
    "dear account holder", "you have won", "congratulations you", 
    "free gift", "you were selected", "claim your prize"
]

def check_suspicious_links(text):
    """Find URLs with suspicious patterns"""
    urls = re.findall(r'http[s]?://\S+', text)
    suspicious = []
    for url in urls:
        if any(bad in url.lower() for bad in ['-secure', '-login', '-verify', '-update', '-account', '.xyz', '.tk', '.ml', '.ga', '.cf']):
            suspicious.append(url)
    return suspicious

def rule_based_score(email_text):
    """Scores an email based on traditional phishing indicators."""
    text_lower = email_text.lower()
    score = 0
    reasons = []

    if found_urgency := [w for w in URGENCY_WORDS if w in text_lower]:
        score += min(len(found_urgency) * 15, 40)
        reasons.append(f"⚠️ Urgency language detected: {', '.join(found_urgency[:3])}")

    if found_creds := [w for w in CREDENTIAL_WORDS if w in text_lower]:
        score += min(len(found_creds) * 25, 40)
        reasons.append(f"🔑 Credential request detected: {', '.join(found_creds[:2])}")

    if found_phrases := [w for w in SUSPICIOUS_PHRASES if w in text_lower]:
        score += min(len(found_phrases) * 10, 20)
        reasons.append(f"🎯 Suspicious phrases: {', '.join(found_phrases[:3])}")

    if bad_links := check_suspicious_links(email_text):
        score += 30
        reasons.append(f"🔗 Suspicious URLs found: {', '.join(bad_links[:2])}")

    return min(score, 100), reasons

# ──────────────────────────────────────────
# PART B: AI-Powered Analysis (Gemini API)
# ──────────────────────────────────────────
def ai_analysis(email_text):
    """Sends email to Google Gemini for deep security analysis."""
    # This automatically picks up the GEMINI_API_KEY environment variable
    client = genai.Client()
    
    prompt = f"""You are a cybersecurity expert specializing in phishing detection. 
    Analyze this email and determine if it is PHISHING, SUSPICIOUS, or SAFE.
    
    EMAIL:
    {email_text}
    
    Respond in this EXACT format:
    VERDICT: [PHISHING / SUSPICIOUS / SAFE]
    CONFIDENCE: [HIGH / MEDIUM / LOW]
    REASONS:
    - [reason 1]
    - [reason 2]
    - [reason 3]
    RECOMMENDATION: [What should the user do?]"""

    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
    )
    return response.text

# ──────────────────────────────────────────
# PART C: Combined Analysis (Main Function)
# ──────────────────────────────────────────
def analyze_email(email_text):
    """Runs BOTH rule-based and Gemini AI analysis."""
    score, reasons = rule_based_score(email_text)
    
    if score >= 60:
        risk_level = "PHISHING"
        risk_color = "red"
    elif score >= 30:
        risk_level = "SUSPICIOUS"
        risk_color = "orange"
    else:
        risk_level = "SAFE"
        risk_color = "green"

    ai_result = ai_analysis(email_text)
    
    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "rule_reasons": reasons,
        "ai_analysis": ai_result
    }
