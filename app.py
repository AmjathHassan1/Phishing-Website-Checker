from flask import Flask, render_template, request
import pickle
import numpy as np
import feature_extractor
import pandas as pd

app = Flask(__name__)

# Load Model : from pickle file
try:
    with open('phishing_model.pkl', 'rb') as f:
        model = pickle.load(f)
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# Feature list based on Arff file order
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 
    'Statistical_report'
]

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction_text = ""
    if request.method == 'POST':
        input_type = request.form.get('input_type')
        
        input_data = []

        if input_type == 'url':
            url = request.form.get('url')
            if url:
                try:
                    features_dict = feature_extractor.extract_features(url)
                    for feature in FEATURE_NAMES:
                        input_data.append(features_dict.get(feature, 0)) # Default 0 if missing
                except Exception as e:
                    prediction_text = f"Error extracting features: {e}"
        
        elif input_type == 'manual':
            try:
                for feature in FEATURE_NAMES:
                    val = request.form.get(feature)
                    if val is None:
                        val = 0 # taking as efault
                    input_data.append(int(val))
            except ValueError:
                prediction_text = "Invalid input data."

        if input_data and model:
            try:
                # Prediction
                # Some models expect specific shape or dataframe
                # Let's try passing dataframe to preserve feature names if the model supports it (like XGBoost)
                # Or just numpy array
                if hasattr(model, "feature_names_in_"):
                     # If sklearn model with feature names, it might warn if we pass array
                     input_df = pd.DataFrame([input_data], columns=FEATURE_NAMES)
                     prediction = model.predict(input_df)[0]
                else: 
                     prediction = model.predict([input_data])[0]

                # Map result
                # Features often: 1 (safe), -1 (risky), 0 (suspicious).
                
                # If we mapped -1 -> 0 and 1 -> 1 in training.
                # Then 1 is Legitimate (original 1), 0 is Phishing (original -1).
                # But wait, typically dataset has -1 as Phishing. 
                # Let's check `Training Dataset.arff` data lines.
                # @data
                # -1,1,1...., -1
                # The Result is the last column.
                # Let's assume 1 is Phishing or 0 is Phishing based on simple logic: if model predicts 1 (from original 1) or 0 (from original -1).
                # I'll just show the raw result and the label.

                if prediction == 1:
                    result_label = "Legitimate" # Assuming 1 was Legitimate/ Safe
                    # result_class = "success"
                else:
                    result_label = "Phishing" # Assuming 0 (mapped from -1) was Phishing : considering -1 as 0
                    # result_class = "danger"

                prediction_text = f"Prediction: {result_label} ({prediction})"
            except Exception as e:
                prediction_text = f"Prediction Error: {e}"
        elif not model:
            prediction_text = "Model not loaded."

    return render_template('index.html', prediction_text=prediction_text, features=FEATURE_NAMES)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
