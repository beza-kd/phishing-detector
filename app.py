from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import pandas as pd
import re
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# LOAD YOUR TRAINED MODEL
model = joblib.load('phishing_detector_rf_model.pkl')
print("✅ Model loaded successfully!")

# FEATURE EXTRACTION FUNCTION (from your notebook)
def extract_features_from_url(url):
    """Extract features from URL for prediction"""
    try:
        url = url.strip()
        url_lower = url.lower()
        
        # Parse URL
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
        path_lower = path.lower()
        
        # Initialize all 30 features
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
        
        # 1. having_ip_address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            features['having_ip_address'] = 1
        
        # 2. url_length
        url_len = len(url)
        if url_len > 54:
            features['url_length'] = 1
        elif url_len <= 30:
            features['url_length'] = -1
        else:
            features['url_length'] = 0
        
        # 3. shortining_service
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
        if any(s in domain_lower for s in shorteners):
            features['shortining_service'] = 1
        
        # 4. having_at_symbol
        if '@' in url:
            features['having_at_symbol'] = 1
        
        # 5. double_slash_redirecting
        if '//' in path and not path.startswith('//'):
            features['double_slash_redirecting'] = 1
        
        # 6. prefix_suffix
        if '-' in domain:
            features['prefix_suffix'] = 1
        
        # 7. having_sub_domain
        parts = domain.split('.')
        subdomain_count = len(parts) - 2
        if subdomain_count > 2:
            features['having_sub_domain'] = 1
        elif subdomain_count > 0:
            features['having_sub_domain'] = 0
        else:
            features['having_sub_domain'] = -1
        
        # 8. sslfinal_state
        if scheme == 'https':
            features['sslfinal_state'] = 1
        
        # 9. https_token
        if 'https' in domain_lower:
            features['https_token'] = 1
        
        # 10. web_traffic (approximate)
        if len(domain) < 10 and len(domain) > 3:
            features['web_traffic'] = 1
        elif len(domain) < 20:
            features['web_traffic'] = 0
        else:
            features['web_traffic'] = -1
        
        # 11. google_index
        if len(domain) < 20 and '.' in domain:
            features['google_index'] = 1
        
        # 12. links_pointing_to_page
        if len(path) > 50:
            features['links_pointing_to_page'] = 1
        elif len(path) > 20:
            features['links_pointing_to_page'] = 0
        else:
            features['links_pointing_to_page'] = -1
        
        # BRAND SPOOFING DETECTION
        brand_names = ['paypal', 'google', 'facebook', 'apple', 'microsoft',
                       'amazon', 'wellsfargo', 'bankofamerica', 'chase',
                       'netflix', 'spotify', 'instagram', 'twitter']
        
        real_domains = {
            'paypal': 'paypal.com',
            'google': 'google.com',
            'facebook': 'facebook.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'amazon': 'amazon.com',
            'wellsfargo': 'wellsfargo.com',
            'bankofamerica': 'bankofamerica.com',
            'chase': 'chase.com',
            'netflix': 'netflix.com',
            'spotify': 'spotify.com',
            'instagram': 'instagram.com',
            'twitter': 'twitter.com'
        }
        
        brand_detected = None
        for brand in brand_names:
            if brand in domain_lower:
                brand_detected = brand
                break
        
        if brand_detected and brand_detected in real_domains:
            real_domain = real_domains[brand_detected]
            if not (domain_lower == real_domain or domain_lower.endswith('.' + real_domain)):
                features['abnormal_url'] = 1
                features['prefix_suffix'] = 1
                features['having_sub_domain'] = 1
        
        # Suspicious keywords
        suspicious_keywords = ['login', 'signin', 'verify', 'account', 'secure', 'update']
        for keyword in suspicious_keywords:
            if keyword in url_lower or keyword in path_lower:
                features['abnormal_url'] = 1
                break
        
        if 'redirect' in url_lower or 'goto' in url_lower:
            features['redirect'] = 1
        
        if 'phish' in url_lower or 'pish' in url_lower:
            features['abnormal_url'] = 1
        
        # SAFE DOMAIN WHITELIST
        safe_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'instagram.com',
            'youtube.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'deepseek.com', 'chat.deepseek.com',
            'openai.com', 'anthropic.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'netflix.com', 'spotify.com',
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
        print(f"Error extracting features: {e}")
        return None

# API ROUTE
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        
        # Extract features
        features_df = extract_features_from_url(url)
        if features_df is None:
            return jsonify({"error": "Error processing URL"}), 400
        
        # Make prediction
        prediction = model.predict(features_df)[0]
        probability = model.predict_proba(features_df)[0]
        
        # Brand spoofing check (extra safety)
        domain = url.split('/')[2] if len(url.split('/')) > 2 else url
        
        brand_names = ['paypal', 'google', 'facebook', 'apple', 'microsoft',
                       'amazon', 'wellsfargo', 'bankofamerica', 'chase',
                       'netflix', 'spotify', 'instagram', 'twitter']
        
        real_domains = {
            'paypal': 'paypal.com',
            'google': 'google.com',
            'facebook': 'facebook.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'amazon': 'amazon.com',
            'wellsfargo': 'wellsfargo.com',
            'bankofamerica': 'bankofamerica.com',
            'chase': 'chase.com',
            'netflix': 'netflix.com',
            'spotify': 'spotify.com',
            'instagram': 'instagram.com',
            'twitter': 'twitter.com'
        }
        
        is_brand_spoof = False
        for brand in brand_names:
            if brand in domain.lower():
                real_domain = real_domains[brand]
                if not (domain.lower() == real_domain or 
                       domain.lower().endswith('.' + real_domain)):
                    is_brand_spoof = True
                    break
        
        # SAFE DOMAIN WHITELIST
        always_safe = [
            'google.com', 'www.google.com', 'facebook.com', 'www.facebook.com',
            'github.com', 'www.github.com', 'openai.com', 'www.openai.com',
            'deepseek.com', 'www.deepseek.com', 'chat.deepseek.com',
            'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
            'paypal.com', 'www.paypal.com', 'amtsa.org', 'www.amtsa.org'
        ]
        
        is_safe_domain = any(safe in url.lower() for safe in always_safe)
        
        # Determine result
        if is_safe_domain:
            final_prediction = "SAFE"
            confidence = 100.0
            risk = "NONE"
            message = "This is a recognized legitimate website."
        elif is_brand_spoof:
            final_prediction = "PHISHING"
            confidence = 99.0
            risk = "CRITICAL"
            message = "This URL is impersonating a known brand!"
        elif prediction == 1:
            final_prediction = "PHISHING"
            confidence = round(probability[1] * 100, 1)
            risk = "HIGH"
            message = "🚨 Do NOT enter personal information!"
        else:
            final_prediction = "SAFE"
            confidence = round(probability[0] * 100, 1)
            risk = "LOW"
            message = "The website appears to be safe."
        
        # Return result
        return jsonify({
            "url": url,
            "prediction": final_prediction,
            "confidence": confidence,
            "risk": risk,
            "risk_score": confidence if final_prediction == "PHISHING" else 100 - confidence,
            "message": message,
            "checks": [
                "✅ Domain analysis complete",
                "✅ SSL status checked",
                "✅ Brand spoofing check complete",
                f"✅ Prediction: {final_prediction}"
            ]
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    return jsonify({"status": "API is running!", "message": "Send POST to /predict with {url: 'your_url'}"})

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 PHISHING API STARTING...")
    print("=" * 60)
    print("📡 API running on: http://127.0.0.1:5000")
    print("📌 Endpoint: POST /predict")
    print("=" * 60)
    app.run(debug=True, port=5000)