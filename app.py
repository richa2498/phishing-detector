from flask import Flask, render_template, request, jsonify
from detector import analyze_email

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    email_text = data.get("email_text", "")

    if not email_text.strip():
        return jsonify({"error": "Please paste an email to analyze."}), 400

    result = analyze_email(email_text)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True, port=8080)
    
