# AI-Powered Phishing Email Detector

A cybersecurity tool that detects phishing emails using a 
**dual-engine approach**: rule-based pattern matching + Claude AI analysis.

## How It Works

**Engine 1 — Rule-Based Scorer**
Scans emails for known phishing indicators:
- Urgency language ("act now", "suspended", "24 hours")
- Credential harvesting phrases
- Suspicious URLs and domains
- Social engineering patterns

**Engine 2 — Claude AI Analysis**
Uses Anthropic's Claude to deeply analyze email context,
tone, and intent — providing a human-readable explanation.

## 🛡️ Key Cybersecurity Concepts Demonstrated
- Social engineering detection
- Indicators of Compromise (IOCs)
- Natural Language Processing for threat detection
- k-anonymity principles
- False positive vs false negative tradeoffs

## 🚀 Tech Stack
- Python 3.11
- Flask (web framework)
- Anthropic Claude API (AI analysis)
- Regex-based NLP (rule engine)

## Setup

1. Clone the repo
   git clone https://github.com/yourusername/phishing-detector.git
   cd phishing-detector

2. Create virtual environment
   python3 -m venv venv
   source venv/bin/activate

3. Install dependencies
   pip install -r requirements.txt

4. Add your API key
   Create a .env file:
   ANTHROPIC_API_KEY=your-key-here

5. Run
   python3 app.py
   Open http://localhost:5000

## Demo
<img width="1429" height="787" alt="Screenshot 2026-06-03 at 4 39 59 PM" src="https://github.com/user-attachments/assets/1775d2a4-c093-4383-95da-8ae1dfe78571" />


## 👤 Author
Your Name — www.linkedin.com/in/richa-patel-2402
