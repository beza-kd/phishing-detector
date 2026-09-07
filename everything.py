from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from ucimlrepo import fetch_ucirepo
import os

app = Flask(__name__)
CORS(app)

# ============================================
# CREATE MODEL IF IT DOESN'T EXIST
# ============================================
if not os.path.exists('phishing_detector_rf_model.pkl'):
    print("📚 Training model...")
    phishing_websites = fetch_ucirepo(id=327)
    X = phishing_websites.data.features
    y = phishing_websites.data.targets
    y = y.replace({1: 0, -1: 1})
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train.values.ravel())
    
    joblib.dump(rf_model, 'phishing_detector_rf_model.pkl')
    print("✅ Model created!")

# Load model
model = joblib.load('phishing_detector_rf_model.pkl')

# ============================================
# FEATURE EXTRACTION (SIMPLIFIED)
# ============================================
def get_features(url):
    features = {
        'having_ip_address': -1,
        'url_length': -1,
        'shortining_service': -1,
        'having_at_symbol': -1,
        'double_slash_redirecting': -1,
        'prefix_suffix': -1,
        'having_sub_domain': -1,
        'sslfinal_state': -1,
        'domain_registration_length': -1,
        'favicon': -1,
        'port': -1,
        'https_token': -1,
        'request_url': -1,
        'url_of_anchor': -1,
        'links_in_tags': -1,
        'sfh': -1,
        'submitting_to_email': -1,
        'abnormal_url': -1,
        'redirect': -1,
        'on_mouseover': -1,
        'rightclick': -1,
        'popupwindow': -1,
        'iframe': -1,
        'age_of_domain': -1,
        'dnsrecord': -1,
        'web_traffic': -1,
        'page_rank': -1,
        'google_index': -1,
        'links_pointing_to_page': -1,
        'statistical_report': -1
    }
    
    # IP check
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', url):
        features['having_ip_address'] = 1
    
    # HTTPS check
    if url.startswith('https://'):
        features['sslfinal_state'] = 1
    
    # URL length
    if len(url) > 54:
        features['url_length'] = 1
    elif len(url) <= 30:
        features['url_length'] = -1
    
    # Check for safe domains
    safe = ['google.com', 'facebook.com', 'paypal.com', 'amtsa.org', 'github.com']
    for s in safe:
        if s in url.lower():
            features['sslfinal_state'] = 1
            features['web_traffic'] = 1
            features['google_index'] = 1
            features['abnormal_url'] = -1
    
    return pd.DataFrame([features])

# ============================================
# API
# ============================================
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL"}), 400
        
        # Safe domains
        safe_list = ['google.com', 'facebook.com', 'paypal.com', 'amtsa.org', 'github.com', 'deepseek.com']
        for safe in safe_list:
            if safe in url.lower():
                return jsonify({
                    "url": url,
                    "prediction": "SAFE",
                    "confidence": 100,
                    "risk": "NONE",
                    "message": "✅ Safe website!"
                })
        
        features = get_features(url)
        pred = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        
        if pred == 1:
            return jsonify({
                "url": url,
                "prediction": "PHISHING",
                "confidence": round(prob[1]*100, 1),
                "risk": "HIGH",
                "message": "🚨 PHISHING!"
            })
        else:
            return jsonify({
                "url": url,
                "prediction": "SAFE",
                "confidence": round(prob[0]*100, 1),
                "risk": "LOW",
                "message": "✅ Safe"
            })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"status": "API Running!"})

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 PHISHING DETECTOR")
    print("="*50)
    print("📡 http://127.0.0.1:5000")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)