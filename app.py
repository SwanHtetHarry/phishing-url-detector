from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from src.feature_extraction import extract_url_features
from src.virustotal import (
    get_url_report,
    submit_url_scan,
    get_analysis_status,
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="AI Phishing URL Detector",
    page_icon="🔐",
)


# =========================================================
# LOAD MODEL
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "phishing_random_forest_final.pkl"
)


@st.cache_resource
def load_model():
    bundle = joblib.load(MODEL_PATH)

    return (
        bundle["model"],
        bundle["features"],
    )


model, feature_names = load_model()


# =========================================================
# SESSION STATE
# =========================================================

if "prediction" not in st.session_state:
    st.session_state.prediction = None

if "phishing_probability" not in st.session_state:
    st.session_state.phishing_probability = None

if "legitimate_probability" not in st.session_state:
    st.session_state.legitimate_probability = None

if "analyzed_url" not in st.session_state:
    st.session_state.analyzed_url = None

if "vt_found" not in st.session_state:
    st.session_state.vt_found = False

if "vt_malicious" not in st.session_state:
    st.session_state.vt_malicious = 0

if "vt_suspicious" not in st.session_state:
    st.session_state.vt_suspicious = 0

if "vt_harmless" not in st.session_state:
    st.session_state.vt_harmless = 0

if "vt_undetected" not in st.session_state:
    st.session_state.vt_undetected = 0

if "vt_message" not in st.session_state:
    st.session_state.vt_message = None


# =========================================================
# API KEY
# =========================================================

try:
    vt_api_key = st.secrets["VIRUSTOTAL_API_KEY"]

except KeyError:
    vt_api_key = None


# =========================================================
# PAGE TITLE
# =========================================================

st.title("AI Phishing URL Detector")

st.write(
    "Analyze a URL using machine learning and security reputation data."
)


# =========================================================
# URL INPUT
# =========================================================

url = st.text_input(
    "Enter URL",
    placeholder="https://example.com"
)


# =========================================================
# ANALYZE BUTTON
# =========================================================

if st.button("Analyze URL"):

    if not url.strip():

        st.warning("Please enter a URL.")

    else:

        # Add HTTPS if user enters only google.com
        if "://" not in url:
            url = "https://" + url.strip()

        try:

            # -------------------------------------------------
            # ML FEATURE EXTRACTION
            # -------------------------------------------------

            features = extract_url_features(url)

            input_data = pd.DataFrame(
                [features]
            )

            input_data = input_data[
                feature_names
            ]


            # -------------------------------------------------
            # ML PREDICTION
            # -------------------------------------------------

            prediction = int(
                model.predict(
                    input_data
                )[0]
            )

            probabilities = model.predict_proba(
                input_data
            )[0]

            classes = list(
                model.classes_
            )

            phishing_probability = float(
                probabilities[
                    classes.index(0)
                ]
            )

            legitimate_probability = float(
                probabilities[
                    classes.index(1)
                ]
            )


            # -------------------------------------------------
            # SAVE ML RESULTS
            # -------------------------------------------------

            st.session_state.prediction = prediction

            st.session_state.phishing_probability = (
                phishing_probability
            )

            st.session_state.legitimate_probability = (
                legitimate_probability
            )

            st.session_state.analyzed_url = url


            # -------------------------------------------------
            # RESET VT RESULTS
            # -------------------------------------------------

            st.session_state.vt_found = False
            st.session_state.vt_malicious = 0
            st.session_state.vt_suspicious = 0
            st.session_state.vt_harmless = 0
            st.session_state.vt_undetected = 0
            st.session_state.vt_message = None


            # -------------------------------------------------
            # VIRUSTOTAL LOOKUP
            # -------------------------------------------------

            if vt_api_key:

                vt_result = get_url_report(
                    url,
                    vt_api_key
                )

                if vt_result.get("found"):

                    st.session_state.vt_found = True

                    st.session_state.vt_malicious = (
                        vt_result["malicious"]
                    )

                    st.session_state.vt_suspicious = (
                        vt_result["suspicious"]
                    )

                    st.session_state.vt_harmless = (
                        vt_result["harmless"]
                    )

                    st.session_state.vt_undetected = (
                        vt_result["undetected"]
                    )

                elif "error" in vt_result:

                    st.session_state.vt_message = (
                        "VirusTotal lookup failed."
                    )

                else:

                    st.session_state.vt_message = (
                        vt_result.get(
                            "message",
                            "No VirusTotal report found."
                        )
                    )

        except Exception as error:

            st.error(
                "Unable to analyze this URL."
            )

            st.code(
                str(error)
            )


# =========================================================
# MACHINE LEARNING RESULT
# =========================================================

if st.session_state.prediction is not None:

    st.divider()

    st.subheader(
        "Machine Learning Analysis"
    )

    if st.session_state.prediction == 0:

        st.error(
            "⚠️ Phishing-like URL"
        )

        st.write(
            "Model confidence: "
            f"**{st.session_state.phishing_probability * 100:.2f}%**"
        )

    else:

        st.success(
            "✅ Legitimate-like URL"
        )

        st.write(
            "Model confidence: "
            f"**{st.session_state.legitimate_probability * 100:.2f}%**"
        )

    st.info(
        "This prediction is based on URL characteristics only."
    )


# =========================================================
# VIRUSTOTAL REPUTATION
# =========================================================

if st.session_state.prediction is not None:

    st.divider()

    st.subheader(
        "VirusTotal Reputation"
    )

    if not vt_api_key:

        st.warning(
            "VirusTotal API key is not configured."
        )

    elif st.session_state.vt_found:

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Malicious",
            st.session_state.vt_malicious
        )

        col2.metric(
            "Suspicious",
            st.session_state.vt_suspicious
        )

        col3.metric(
            "Harmless",
            st.session_state.vt_harmless
        )

        col4.metric(
            "Undetected",
            st.session_state.vt_undetected
        )


        if st.session_state.vt_malicious > 0:

            st.error(
                "VirusTotal reported malicious detections."
            )

        elif st.session_state.vt_suspicious > 0:

            st.warning(
                "VirusTotal reported suspicious detections."
            )

        else:

            st.success(
                "No malicious or suspicious detections were "
                "reported in the available VirusTotal analysis."
            )

    else:

        st.info(
            st.session_state.vt_message
            or "No existing VirusTotal report was found."
        )


# =========================================================
# OVERALL RISK ASSESSMENT
# =========================================================

if st.session_state.prediction is not None:

    st.divider()

    st.subheader(
        "Overall Risk Assessment"
    )


    if (
        st.session_state.vt_found
        and st.session_state.vt_malicious > 0
    ):

        st.error(
            "HIGH RISK — VirusTotal reported "
            f"{st.session_state.vt_malicious} "
            "malicious detection(s)."
        )


    elif (
        st.session_state.vt_found
        and st.session_state.vt_suspicious > 0
    ):

        st.warning(
            "SUSPICIOUS — VirusTotal reported "
            f"{st.session_state.vt_suspicious} "
            "suspicious detection(s)."
        )


    elif st.session_state.prediction == 0:

        if st.session_state.vt_found:

            st.warning(
                "CAUTION — VirusTotal has no malicious "
                "detections, but the ML model considers "
                "this URL phishing-like."
            )

        else:

            st.warning(
                "CAUTION — The ML model considers this URL "
                "phishing-like, but no existing VirusTotal "
                "report was available."
            )


    else:

        if st.session_state.vt_found:

            st.success(
                "No strong malicious indicators were found "
                "by the ML model or the available "
                "VirusTotal report."
            )

        else:

            st.info(
                "The ML model considers this URL legitimate-like, "
                "but no existing VirusTotal report was available."
            )


# =========================================================
# FRESH VIRUSTOTAL SCAN
# =========================================================

if st.session_state.prediction is not None:

    st.subheader(
        "Fresh VirusTotal Scan"
    )

    st.warning(
        "Submitting a fresh scan sends this URL to VirusTotal. "
        "Do not submit private, internal, or sensitive URLs."
    )

    if not vt_api_key:

        st.warning(
            "VirusTotal API key is not configured."
        )

    elif st.button(
        "Run Fresh VirusTotal Scan"
    ):

        scan_url = (
            st.session_state.analyzed_url
        )

        scan_result = submit_url_scan(
            scan_url,
            vt_api_key
        )


        # -----------------------------------------
        # SUBMISSION SUCCESSFUL
        # -----------------------------------------

        if scan_result.get("success"):

            analysis_id = (
                scan_result["analysis_id"]
            )

            st.success(
                "URL submitted to VirusTotal."
            )

            status_result = (
                get_analysis_status(
                    analysis_id,
                    vt_api_key
                )
            )


            # -------------------------------------
            # STATUS SUCCESSFUL
            # -------------------------------------

            if status_result.get("success"):

                with st.expander(
                    "Technical scan details"
                ):

                    st.write(
                        "Analysis ID:",
                        analysis_id
                    )

                    st.write(
                        "Status:",
                        status_result["status"]
                    )


                # ---------------------------------
                # COMPLETED
                # ---------------------------------

                if (
                    status_result["status"]
                    == "completed"
                ):

                    stats = (
                        status_result["stats"]
                    )

                    st.success(
                        "Fresh VirusTotal analysis completed."
                    )

                    col1, col2, col3, col4 = (
                        st.columns(4)
                    )

                    col1.metric(
                        "Malicious",
                        stats.get(
                            "malicious",
                            0
                        )
                    )

                    col2.metric(
                        "Suspicious",
                        stats.get(
                            "suspicious",
                            0
                        )
                    )

                    col3.metric(
                        "Harmless",
                        stats.get(
                            "harmless",
                            0
                        )
                    )

                    col4.metric(
                        "Undetected",
                        stats.get(
                            "undetected",
                            0
                        )
                    )


                    if (
                        stats.get(
                            "malicious",
                            0
                        ) > 0
                    ):

                        st.error(
                            "Fresh VirusTotal analysis "
                            "found malicious detections."
                        )

                    elif (
                        stats.get(
                            "suspicious",
                            0
                        ) > 0
                    ):

                        st.warning(
                            "Fresh VirusTotal analysis "
                            "found suspicious detections."
                        )

                    else:

                        st.success(
                            "No malicious or suspicious "
                            "detections were reported in "
                            "the fresh VirusTotal analysis."
                        )


                # ---------------------------------
                # STILL PROCESSING
                # ---------------------------------

                else:

                    st.info(
                        "VirusTotal is still analyzing "
                        "the URL. Check again shortly."
                    )


            # -------------------------------------
            # STATUS FAILED
            # -------------------------------------

            else:

                st.error(
                    "Could not retrieve analysis status."
                )

                st.code(
                    status_result.get(
                        "error",
                        "Unknown VirusTotal error"
                    )
                )


        # -----------------------------------------
        # SUBMISSION FAILED
        # -----------------------------------------

        else:

            st.error(
                "VirusTotal submission failed."
            )

            st.code(
                scan_result.get(
                    "error",
                    "Unknown VirusTotal error"
                )
            )


# =========================================================
# DISCLAIMER
# =========================================================

st.divider()

st.caption(
    "This project is an educational machine-learning "
    "security tool. Results should not be treated as "
    "a guarantee that a website is safe or malicious."
)