import os
import re
from google import genai

# ──────────────────────────────────────────────────────────────────────────
# ENGINE 1: RULE-BASED SCORER (Signature Pattern Isolation)
# ──────────────────────────────────────────────────────────────────────────
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
    """Isolates URLs matching standard heuristic indicators of compromise."""
    urls = re.findall(r'http[s]?://\S+', text)
    suspicious = []
    for url in urls:
        if any(bad in url.lower() for bad in ['-secure', '-login', '-verify', '-update', '-account', '.xyz', '.tk', '.ml', '.ga', '.cf']):
            suspicious.append(url)
    return suspicious

def rule_based_score(email_text):
    """Evaluates target text segments to build an immutable risk profile index."""
    text_lower = email_text.lower()
    score = 0
    reasons = []

    found_urgency = [w for w in URGENCY_WORDS if w in text_lower]
    if found_urgency:
        score += min(len(found_urgency) * 15, 40)
        reasons.append(f"⚠️ Urgency language detected: {', '.join(found_urgency[:3])}")

    found_creds = [w for w in CREDENTIAL_WORDS if w in text_lower]
    if found_creds:
        score += min(len(found_creds) * 25, 40)
        reasons.append(f"🔑 Credential request detected: {', '.join(found_creds[:2])}")

    found_phrases = [w for w in SUSPICIOUS_PHRASES if w in text_lower]
    if found_phrases:
        score += min(len(found_phrases) * 10, 20)
        reasons.append(f"🎯 Suspicious phrases: {', '.join(found_phrases[:3])}")

    bad_links = check_suspicious_links(email_text)
    if bad_links:
        score += 30
        reasons.append(f"🔗 Suspicious URLs found: {', '.join(bad_links[:2])}")

    score = min(score, 100)
    return score, reasons

# ──────────────────────────────────────────────────────────────────────────
# ENGINE 2: DEEP MODEL INTELLIGENCE (Google GenAI Core Integration)
# ──────────────────────────────────────────────────────────────────────────
def ai_analysis(email_text):
    """Interfaces with neural models to safely isolate social engineering vectors."""
    try:
        # Secure token retrieval from isolated container layer
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return "Engine Execution Failure: GEMINI_API_KEY token missing from deployment context configuration parameters."
            
        client = genai.Client(api_key=api_key)
        
        prompt = f"""You are a cybersecurity expert specializing in phishing detection. 
        Analyze this email and determine if it is PHISHING, SUSPICIOUS, or SAFE.
        
        EMAIL PAYLOAD:
        {email_text}
        
        Respond format baseline:
        VERDICT: [PHISHING / SUSPICIOUS / SAFE]
        REASONS:
        - Provide explicit contextual analysis matching threat mechanics.
        """
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"AI Interface Communication Failure: {str(e)}"

# ──────────────────────────────────────────────────────────────────────────
# DUAL ENGINE AGGREGATOR PIPELINE
# ──────────────────────────────────────────────────────────────────────────
def analyze_email(email_text):
    """Combines rule signatures and AI vectors into a single telemetry payload."""
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
