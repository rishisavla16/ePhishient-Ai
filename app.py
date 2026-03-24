from flask import Flask, request, jsonify, render_template
import joblib
import os
from urllib.parse import urlparse
import pandas as pd
from train_model import PhishingDetector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'phishing_model.pkl')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
IS_VERCEL = os.environ.get('VERCEL') == '1'
TRUSTED_DOMAINS_PATH = os.path.join(BASE_DIR, 'top-1m.csv')

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path='/static'
)

# Load Model
detector = PhishingDetector()
try:
    model = joblib.load(MODEL_PATH)
    detector.model = model
    print("Model loaded successfully.")
except Exception:
    print("Model not found. It will be trained on first request outside serverless.")


def registered_domain(hostname):
    host = (hostname or '').split(':')[0].lower().strip()
    if host.startswith('www.'):
        host = host[4:]
    parts = host.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host


def load_trusted_domains(limit=50000):
    if not os.path.exists(TRUSTED_DOMAINS_PATH):
        return set()

    try:
        df = pd.read_csv(TRUSTED_DOMAINS_PATH, header=None, names=['rank', 'domain'], nrows=limit)
        return set(df['domain'].astype(str).str.lower().str.strip())
    except Exception:
        return set()


TRUSTED_DOMAINS = load_trusted_domains()


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

    feature_map = dict(zip(detector.feature_names, features))

    # Guardrail: avoid false positives on well-known trusted domains unless clear obfuscation exists.
    domain = registered_domain(urlparse(url).netloc)
    high_risk_obfuscation = (
        feature_map.get('is_ip', 0) == 1
        or feature_map.get('short_url', 0) == 1
        or feature_map.get('count_at', 0) > 0
        or feature_map.get('suspicious_tld', 0) == 1
    )

    if prediction == 1 and domain in TRUSTED_DOMAINS and not high_risk_obfuscation and prob < 0.999:
        prediction = 0
        prob = min(prob, 0.20)

    confidence = prob if prediction == 1 else (1 - prob)
    
    # 3. Explain
    explanation = detector.explain_prediction(features, prediction, url)
    if prediction == 0 and domain in TRUSTED_DOMAINS and not high_risk_obfuscation:
        explanation = [
            "Domain appears in a trusted top-sites list and has no strong obfuscation indicators.",
            "URL structure appears legitimate."
        ]
    
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
