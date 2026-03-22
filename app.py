from flask import Flask, request, jsonify, render_template
import joblib
import os
from urllib.parse import urlparse
from train_model import PhishingDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')
IS_VERCEL = os.environ.get('VERCEL') == '1'

app = Flask(__name__, template_folder='templates', static_folder='static')

# Load Model
detector = PhishingDetector()
try:
    model = joblib.load(MODEL_PATH)
    detector.model = model
    print("Model loaded successfully.")
except Exception:
    print("Model not found. It will be trained on first request outside serverless.")


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
        if IS_VERCEL:
            raise RuntimeError("Model is unavailable in serverless runtime. Commit phishing_model.pkl and redeploy.")
        print("Model missing or not fitted. Training model...")
        detector.train()
        detector.model = joblib.load(MODEL_PATH)

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

    try:
        ensure_model_ready()
    except RuntimeError as exc:
        return jsonify({'error': str(exc)}), 503

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
    if IS_VERCEL:
        return jsonify({
            'status': 'error',
            'message': 'Retraining is disabled on Vercel serverless runtime. Train locally and redeploy the model file.'
        }), 400

    accuracy = detector.train()
    # Reload the model into memory
    detector.model = joblib.load(MODEL_PATH)
    return jsonify({'status': 'success', 'message': f'Model retrained with new data! Accuracy: {accuracy:.2%}'})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
