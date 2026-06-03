import os
import google.generativeai as genai

# Configure the Gemini API client using your Render environment variable
api_key = os.environ.get("GEMINI_API_KEY", "").strip()
genai.configure(api_key=api_key)

def analyze_email(email_text):
    """
    Analyzes the target email text payload using the Gemini Flash model
    to detect deep social engineering and phishing threat signatures.
    """
    try:
        # Initialize the correct model
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = f"""
        Analyze the following email payload for phishing markers, urgent behavioral pressure, 
        spoofing identifiers, or malicious intent. Provide a concise safety breakdown:
        
        Email Payload:
        \"\"\"{email_text}\"\"\"
        """
        
        response = model.generate_content(prompt)
        
        # Return the structure your frontend expects
        return {
            "analysis": response.text
        }
    except Exception as e:
        return {
            "analysis": f"Deep Model Engine analysis failed: {str(e)}"
        }
