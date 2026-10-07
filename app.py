from flask import Flask, request, render_template
import joblib
import pandas as pd
import os

app = Flask(__name__)

# Load the trained model safely
if os.path.exists('phishing_model.pkl'):
    model = joblib.load('phishing_model.pkl')
    print("AI Model loaded successfully into SENTINEL!")
else:
    model = None
    print("Warning: 'phishing_model.pkl' not found!")

def extract_features(url):
    # Clean up double prefixes if a full link was pasted
    url = url.strip()
    while "https://https://" in url or "http://https://" in url or "http://http://" in url:
        url = url.replace("https://https://", "https://").replace("http://https://", "https://").replace("http://http://", "http://")

    if not url.lower().startswith("http"):
        full_url = "https://" + url
    else:
        full_url = url
        
    # Create DataFrame with columns in the exact order trained by model.py
    features = pd.DataFrame([{
        'url_length': len(full_url),
        'digit_count': sum(c.isdigit() for c in full_url),
        'special_char_count': sum(not c.isalnum() for c in full_url),
        'slash_count': full_url.count('/'),
        'hyphen_count': full_url.count('-'),
        'https_flag': 1 if 'https' in full_url.lower() else 0,
        'at_flag': 1 if '@' in full_url else 0
    }])
    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    user_url = request.form.get('url')
    if not user_url:
        return render_template('index.html')
    
    if model:
        try:
            test_features = extract_features(user_url)
            pred = model.predict(test_features)[0]
            
            # Print the raw AI prediction to your terminal to inspect it
            print(f"-> Tested URL: {user_url}")
            print(f"-> Raw AI Prediction Output: {pred}")
            
            # Map prediction to UI status
            if pred == 1 or str(pred) == '1':
                status = 'Phishing'
            else:
                status = 'Safe'
        except Exception as err:
            print(f"Prediction Error: {err}")
            status = 'Safe'
    else:
        status = 'Safe'

    return render_template('index.html', result=status, url_tested=user_url)

if __name__ == '__main__':
    app.run(debug=True)