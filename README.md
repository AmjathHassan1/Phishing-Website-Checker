Phishing Website Detection Project
====================================

Description
-----------
This project is a Flask-based web application designed to detect phishing websites. It uses a pre-trained machine learning model (`phishing_model.pkl`) to classify URLs or manually entered feature sets as either "Legitimate" or "Phishing".

Key Features:
- URL Feature Extraction: Automatically extracts features from a given URL using `feature_extractor.py`.
- Manual Input: Allows users to manually input values for 30 specific features (e.g., IP Address, SSL State, Anchor URL).
- Prediction: Uses the loaded model to predict if the site is safe.

Project Structure
-----------------
- app.py: Main Flask application.
- feature_extractor.py: Helper script to process URLs into feature vectors.
- phishing_model.pkl: The serialized Machine Learning model.
- templates/: Contains the HTML frontend (`index.html`).
- Training Dataset.arff: Original dataset used for training (referencing 30 features).

Developer Comments (from app.py)
--------------------------------
Below are important comments extracted from the source code regarding model logic and data mapping:

1. Model Loading:
   "Load Model. Try loading 'phishing_model.pkl'. If fails, sets model to None."

2. Feature List:
   "Feature list based on Arff file order: ['having_IP_Address', 'URL_Length', ... 'Statistical_report']"

3. Prediction Logic & Data Shape:
   "Some models expect specific shape or dataframe. Let's try passing dataframe to preserve feature names if the model supports it (like XGBoost) Or just numpy array."
   "If sklearn model with feature names, it might warn if we pass array."

4. Result Mapping (Legitimate vs Phishing):
   "1 = Phishing, 0 or -1 = Legitimate? Need to check target mapping from training."
   "In training code: `y = y.apply(lambda x: 0 if x == -1 else 1)`. So 1 was original 1, 0 was original -1."
   "Usually in this dataset: 1 is Phishing, -1 is Legitimate. Wait, let's verify arff. Result {-1, 1}."
   "Typically -1: Phishing, 1: Legitimate or vice versa. Let's assume the standard: Legitimate = 1, Phishing = -1."
   "Features often: 1 (safe), -1 (risky), 0 (suspicious)."
   "If we mapped -1 -> 0 and 1 -> 1 in training. Then 1 is Legitimate (original 1), 0 is Phishing (original -1)."
   "Let's assume 1 is Phishing or 0 is Phishing based on simple logic: if model predicts 1 (from original 1) or 0 (from original -1)."

   "Current Logic in Code:
    - If prediction == 1 -> Result: Legitimate (Assuming 1 was Legitimate)
    - Else -> Result: Phishing (Assuming 0 (mapped from -1) was Phishing)"
