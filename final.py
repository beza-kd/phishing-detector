from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import os

app = Flask(__name__)
CORS(app)

# ============================================
# CREATE MODEL IF IT DOESN'T EXIST
# ============================================
def create_model():
    print("📊 Loading training data...")
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from ucimlrepo import fetch_ucirepo
    
    phishing_websites = fetch_ucirepo(id=327)
    X = phishing_websites.data.features
    y = phishing_websites.data.targets
    y = y.replace({1: 0, -1: 1})
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    print("🤖 Training model...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train.values.ravel())
    
    print("💾 Saving model...")
    joblib.dump(rf_model, 'phishing_detector_rf_model.pkl')
    return rf_model

# Load or create model
if not os.path.exists('phishing_detector_rf_model.pkl'):
    model = create_model()
else:
    try:
        model = joblib.load('phishing_detector_rf_model.pkl')
        print("✅ Model loaded from file!")
    except:
        print("⚠️ Model file corrupted. Creating new one...")
        model = create_model()

# ============================================
# FEATURE EXTRACTION
# ============================================
def extract_features(url):
    try:
        url = url.strip()
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        scheme = parsed.scheme
        
        if not domain:
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
            else:
                domain = url.split('/')[0]
        
        domain_lower = domain.lower()
        
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
        
        # IP Address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            features['having_ip_address'] = 1
        
        # URL Length
        if len(url) > 54:
            features['url_length'] = 1
        elif len(url) <= 30:
            features['url_length'] = -1
        
        # SSL/HTTPS
        if scheme == 'https':
            features['sslfinal_state'] = 1
        
        # Sub Domain
        parts = domain.split('.')
        subdomain_count = len(parts) - 2
        if subdomain_count > 2:
            features['having_sub_domain'] = 1
        elif subdomain_count > 0:
            features['having_sub_domain'] = 0
        else:
            features['having_sub_domain'] = -1
        
        # Prefix Suffix (dash)
        if '-' in domain:
            features['prefix_suffix'] = 1
        
        # Web Traffic (approximate)
        if len(domain) < 10 and len(domain) > 3:
            features['web_traffic'] = 1
        elif len(domain) < 20:
            features['web_traffic'] = 0
        else:
            features['web_traffic'] = -1
        
        # Safe domain check
        safe_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'youtube.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'deepseek.com', 'openai.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'netflix.com', 'spotify.com', 'paypal.com',
            'ethiotelecom.et', 'amtsa.org', 'amtsos.org'
        ]
        
        for safe in safe_domains:
            if domain_lower == safe or domain_lower.endswith('.' + safe):
                features['sslfinal_state'] = 1
                features['web_traffic'] = 1
                features['google_index'] = 1
                features['abnormal_url'] = -1
                break
        
        return pd.DataFrame([features])
    
    except Exception as e:
        print(f"Error: {e}")
        return None

# ============================================
# API ROUTE
# ============================================
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # ADD HTTPS CHECK FIRST!
        # Check if URL uses HTTPS
        if not url.startswith('https://'):
            return jsonify({
                "url": url,
                "prediction": "SUSPICIOUS",
                "confidence": 70,
                "risk": "MEDIUM",
                "risk_score": 70,
                "message": "⚠️ NO HTTPS! Connection is NOT secure!",
                "checks": [
                    "⚠️ Website does NOT use HTTPS",
                    "⚠️ Your data could be intercepted",
                    "⚠️ Use https:// for secure connection"
                ]
            })
        
        # CHECK SAFE DOMAINS
        safe_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'youtube.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'deepseek.com', 'openai.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'netflix.com', 'spotify.com', 'paypal.com',
            'ethiotelecom.et', 'amtsa.org', 'amtsos.org', 'gmail.com'
        ]
        
        for safe in safe_domains:
            if safe in url.lower():
                return jsonify({
                    "url": url,
                    "prediction": "SAFE",
                    "confidence": 100,
                    "risk": "NONE",
                    "risk_score": 0,
                    "message": "✅ This is a safe and trusted website!",
                    "checks": [
                        "✅ Domain is trusted",
                        "✅ HTTPS is secure",
                        "✅ Safe to visit"
                    ]
                })
        
        # GET FEATURES
        features_df = extract_features(url)
        if features_df is None:
            return jsonify({"error": "Error processing URL"}), 400
        
        # PREDICT
        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]
        
        # CHECK FOR PHISHING
        if prediction == 1:
            return jsonify({
                "url": url,
                "prediction": "PHISHING",
                "confidence": round(probability[1] * 100, 1),
                "risk": "HIGH",
                "risk_score": round(probability[1] * 100, 1),
                "message": "🚨 PHISHING DETECTED!",
                "checks": ["🚨 Suspicious URL detected", "🚨 Do NOT enter data!"]
            })
        else:
            return jsonify({
                "url": url,
                "prediction": "SAFE",
                "confidence": round(probability[0] * 100, 1),
                "risk": "LOW",
                "risk_score": 0,
                "message": "✅ Website appears safe",
                "checks": ["✅ No threats detected"]
            })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"status": "API is running!"})

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🛡️  PHISHING DETECTOR (UPDATED - HTTPS CHECK)")
    print("=" * 60)
    print("📡 Server: http://127.0.0.1:5000")
    print("📌 Endpoint: POST /predict")
    print("=" * 60)
    print("\n✅ Ready! Open your phishing.html file.")
    print("⏳ Waiting for requests...")
    app.run(debug=True, port=5000)