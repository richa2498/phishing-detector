import os
from flask import Flask, render_template, request, jsonify
from detector import analyze_email

app = Flask(__name__)

@app.route("/")
def home():
    # Serves the clean dark-theme dashboard UI
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid payload transmission context."}), 400
            
        email_text = data.get("email_text", "")
        if not email_text.strip():
            return jsonify({"error": "Please paste target email content before initiating scanning sequences."}), 400

        # Pass target data down to your dual-engine pipeline
        result = analyze_email(email_text)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": f"Internal System Link Layer Failure: {str(e)}"}), 500

if __name__ == "__main__":
    # Standard production binding properties
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
