import streamlit as st
import pickle
import numpy as np
import feature_extractor
import pandas as pd

# Feature list
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]


# Load Model
@st.cache_resource
def load_model():
    try:
        with open('phishing_model.pkl', 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None


model = load_model()

st.title("Phishing Website Detection")
st.write("This app uses a machine learning model to detect whether a website is **Legitimate** or **Phishing**.")

# Input Method Selection
input_type = st.radio("Choose Input Method", ("Enter URL", "Manual Feature Input"))

input_data = []

if input_type == "Enter URL":
    url = st.text_input("Enter the Website URL:")
    if st.button("Predict"):
        if url:
            try:
                features_dict = feature_extractor.extract_features(url)
                # Display extracted features (optional, helpful for debugging)
                with st.expander("Show Extracted Features"):
                    st.json(features_dict)

                for feature in FEATURE_NAMES:
                    input_data.append(features_dict.get(feature, 0))
            except Exception as e:
                st.error(f"Error extracting features: {e}")
        else:
            st.warning("Please enter a URL first.")

elif input_type == "Manual Feature Input":
    st.write("Enter values for the features below (typically -1, 0, or 1):")

    # Create a form to keep inputs organized
    with st.form("manual_input_form"):
        col1, col2, col3 = st.columns(3)
        input_values = {}

        for i, feature in enumerate(FEATURE_NAMES):
            # Distribute fields across 3 columns
            if i % 3 == 0:
                with col1:
                    val = st.number_input(feature, value=0, step=1)
            elif i % 3 == 1:
                with col2:
                    val = st.number_input(feature, value=0, step=1)
            else:
                with col3:
                    val = st.number_input(feature, value=0, step=1)
            input_values[feature] = val

        submitted = st.form_submit_button("Predict")

        if submitted:
            for feature in FEATURE_NAMES:
                input_data.append(input_values[feature])

# Prediction Logic
if input_data and model:
    try:
        if hasattr(model, "feature_names_in_"):
            input_df = pd.DataFrame([input_data], columns=FEATURE_NAMES)
            prediction = model.predict(input_df)[0]
        else:
            prediction = model.predict([input_data])[0]

        if prediction == 1:
            st.success(f"Prediction: Legitimate ({prediction})")
        else:
            st.error(f"Prediction: Phishing ({prediction})")

    except Exception as e:
        st.error(f"Prediction Error: {e}")

elif not model:
    st.warning("Model could not be loaded. Please check the 'phishing_model.pkl' file.")
