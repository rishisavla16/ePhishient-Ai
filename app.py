from flask import Flask, request, jsonify, render_template
import joblib
import os
from urllib.parse import urlparse
from train_model import PhishingDetector

app = Flask(__name__)

# Load Model
detector = PhishingDetector()
try:
    model = joblib.load('phishing_model.pkl')
    detector.model = model
    print("Model loaded successfully.")
except Exception:
    print("Model not found. It will be trained on the first request.")


def normalize_input_url(url):
    url = (url or '').strip()
    if not url:
        return ''

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    return PhishingDetector.normalize_url(url)


def is_valid_url(url):
    parsed = urlparse(url)
    hostname = (parsed.netloc or '').strip()
    return bool(parsed.scheme in {'http', 'https'} and hostname and ('.' in hostname or hostname.isdigit()))


def ensure_model_ready():
    try:
        _ = detector.model.n_features_in_
    except Exception:
        print("Model missing or not fitted. Training model...")
        detector.train()
        detector.model = joblib.load('phishing_model.pkl')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    raw_url = request.form.get('url')
    url = normalize_input_url(raw_url)
    if not url:
        return jsonify({'error': 'No URL provided'})

    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format.'})

    ensure_model_ready()

    # 1. Extract Features
    features = detector.extract_features(url)
    
    # 2. Predict
    try:
        prediction = detector.model.predict([features])[0]
        prob = detector.model.predict_proba([features])[0][1] # Malicious risk score
    except (ValueError, AttributeError):
        # Handle feature mismatch or model not fitted
        print("Model mismatch or not trained. Retraining now...")
        detector.train()
        prediction = detector.model.predict([features])[0]
        prob = detector.model.predict_proba([features])[0][1]

    confidence = prob if prediction == 1 else (1 - prob)
    
    # 3. Explain
    explanation = detector.explain_prediction(features, prediction, url)
    
    result = {
        'url': url,
        'is_malicious': bool(prediction),
        'risk_score': float(prob),
        'confidence': float(confidence),
        'explanation': explanation
    }
    return jsonify(result)

@app.route('/retrain', methods=['POST'])
def retrain_model():
    """
    Manually trigger model retraining.
    """
    accuracy = detector.train()
    # Reload the model into memory
    detector.model = joblib.load('phishing_model.pkl')
    return jsonify({'status': 'success', 'message': f'Model retrained with new data! Accuracy: {accuracy:.2%}'})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
