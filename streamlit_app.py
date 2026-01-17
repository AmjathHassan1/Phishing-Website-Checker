import streamlit as st
import pickle
import numpy as np
import feature_extractor
import pandas as pd

# Page config
st.set_page_config(page_title="Phishing Website Detector", layout="centered")

# Custom CSS to match the requested UI
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #f8f9fa;
    }

    /* Card container */
    .main-card {
        background-color: white;
        padding: 2rem;
        border-radius: 10px;
        box_shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        max-width: 800px;
        margin: auto;
    }

    /* Title */
    h1 {
        text-align: center;
        color: #333;
        font-family: 'Arial', sans-serif;
        font-weight: bold;
        margin-bottom: 2rem;
    }

    /* Prediction Box */
    .prediction-box {
        padding: 1rem;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
        margin-bottom: 2rem;
        font-size: 1.1rem;
    }
    .safe {
        background-color: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
    }
    .phishing {
        background-color: #d1ecf1; /* Light blue as in screenshot */
        color: #0c5460;
        border: 1px solid #bee5eb;
    }

    /* Button Styling */
    .stButton>button {
        width: 100%;
        background-color: #007bff;
        color: white;
        border-radius: 5px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #0056b3;
        color: white;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: transparent;
        border-bottom: 2px solid #007bff;
        color: #007bff;
        font-weight: bold;
    }

</style>
""", unsafe_allow_html=True)

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
        return None


model = load_model()

# --- Application Logic ---

st.title("Phishing Website Detector")

# Container for the main content to simulate a card
with st.container():
    # State management for prediction result
    if 'prediction_result' not in st.session_state:
        st.session_state['prediction_result'] = None

    # Display Prediction immediately below title if exists (like in screenshot)
    if st.session_state['prediction_result']:
        res = st.session_state['prediction_result']
        if res['type'] == 'Legitimate':
            st.markdown(f'<div class="prediction-box safe">Prediction: Legitimate ({res["val"]})</div>',
                        unsafe_allow_html=True)
        else:
            # Using the light blue style from screenshot for phishing/suspicious as well, or red for danger
            # The screenshot showed light blue for phishing.
            st.markdown(f'<div class="prediction-box phishing">Prediction: Phishing ({res["val"]})</div>',
                        unsafe_allow_html=True)

    # Tabs
    tab1, tab2 = st.tabs(["Check by URL", "Manual Entry"])

    input_data = []
    run_prediction = False

    # TAB 1: Check by URL
    with tab1:
        st.markdown("<br>", unsafe_allow_html=True)
        st.write("Enter Website URL")
        url_input = st.text_input("URL Input", placeholder="https://example.com", label_visibility="collapsed")

        if st.button("Check URL"):
            if url_input:
                try:
                    features_dict = feature_extractor.extract_features(url_input)
                    # Prepare input_data
                    input_data = [features_dict.get(f, 0) for f in FEATURE_NAMES]
                    run_prediction = True
                except Exception as e:
                    st.error(f"Error extracting features: {e}")
            else:
                st.warning("Please enter a URL.")

    # TAB 2: Manual Entry
    with tab2:
        st.markdown("<br>", unsafe_allow_html=True)

        # Mapping options to values
        option_map = {
            "1 (Legitimate/Safe)": 1,
            "0 (Suspicious)": 0,
            "-1 (Phishing)": -1
        }
        reverse_option_map = list(option_map.keys())

        # Form for manual input
        with st.form("manual_form"):
            cols = st.columns(3)
            manual_inputs = {}

            for i, feature in enumerate(FEATURE_NAMES):
                col = cols[i % 3]
                with col:
                    # Default to 0 or 1 depending on what makes sense, here using 1 (Safe) as visual default
                    # Screenshot shows select boxes
                    selection = st.selectbox(
                        label=feature,
                        options=reverse_option_map,
                        index=0  # Default to first option
                    )
                    manual_inputs[feature] = option_map[selection]

            st.markdown("<br>", unsafe_allow_html=True)
            submitted = st.form_submit_button("Predict")
            if submitted:
                input_data = [manual_inputs[f] for f in FEATURE_NAMES]
                run_prediction = True

    # Run Prediction if triggered
    if run_prediction and model:
        try:
            if hasattr(model, "feature_names_in_"):
                input_df = pd.DataFrame([input_data], columns=FEATURE_NAMES)
                prediction = model.predict(input_df)[0]
            else:
                prediction = model.predict([input_data])[0]

            # Logic: 1 = Legitimate, Else (0 or -1) = Phishing
            if prediction == 1:
                st.session_state['prediction_result'] = {"type": "Legitimate", "val": prediction}
            else:
                st.session_state['prediction_result'] = {"type": "Phishing", "val": prediction}

            st.rerun()

        except Exception as e:
            st.error(f"Prediction Error: {e}")
    elif run_prediction and not model:
        st.error("Model not loaded.")

