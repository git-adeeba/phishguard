import streamlit as st
import sys
import os


# ============================================================
# ALLOW IMPORTS FROM SRC
# ============================================================

ROOT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

SRC_DIR = os.path.join(
    ROOT_DIR,
    "src"
)

if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)


from risk_engine import analyze_risk
from feature_extraction import extract_features

from scan_storage import (
    load_scan_history,
    add_scan
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard | URL Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# ============================================================
# SESSION STATE
# ============================================================

if "scan_history" not in st.session_state:

    st.session_state["scan_history"] = (
        load_scan_history()
    )


if "result" not in st.session_state:

    st.session_state["result"] = None


# ============================================================
# CSS
# ============================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(
            circle at 50% 0%,
            rgba(80, 80, 180, 0.12),
            transparent 35%
        ),
        #08090d;
    color: #f5f5f5;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 4rem;
    max-width: 1200px;
}


/* =========================================================
   HEADER
========================================================= */

.logo {
    font-size: 24px;
    font-weight: 800;
    letter-spacing: -0.5px;
}

.logo-icon {
    color: #7c5cff;
}

.nav-text {
    color: #8d91a1;
    font-size: 14px;
}


/* =========================================================
   HERO
========================================================= */

.hero {
    text-align: center;
    padding: 70px 20px 45px;
}

.hero-badge {
    display: inline-block;
    padding: 7px 14px;
    border-radius: 999px;
    background: rgba(124, 92, 255, 0.10);
    border: 1px solid rgba(124, 92, 255, 0.25);
    color: #a996ff;
    font-size: 12px;
    font-weight: 600;
    margin-bottom: 20px;
}

.hero h1 {
    font-size: 52px;
    line-height: 1.05;
    letter-spacing: -2px;
    margin: 0;
}

.hero h1 span {
    color: #8c72ff;
}

.hero p {
    color: #8d91a1;
    font-size: 17px;
    max-width: 650px;
    margin: 18px auto 0;
    line-height: 1.7;
}


/* =========================================================
   URL INPUT
========================================================= */

.input-label {
    color: #aeb2c0;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 7px;
}

div[data-testid="stTextInput"] input {
    background: #11131a !important;
    border: 1px solid #292c38 !important;
    border-radius: 12px !important;
    color: #ffffff !important;
    padding: 15px !important;
    font-size: 15px !important;
}

div[data-testid="stTextInput"] input:focus {
    border-color: #7c5cff !important;
    box-shadow: 0 0 0 1px #7c5cff !important;
}


/* =========================================================
   BUTTON
========================================================= */

.stButton > button {
    width: 100%;
    height: 50px;
    border-radius: 12px;
    border: none;
    background: #7c5cff;
    color: white;
    font-size: 15px;
    font-weight: 700;
    transition: 0.2s;
}

.stButton > button:hover {
    background: #8c72ff;
    transform: translateY(-1px);
}


/* =========================================================
   RESULT CARDS
========================================================= */

.card {
    background: #11131a;
    border: 1px solid #252833;
    border-radius: 18px;
    padding: 25px;
    height: 100%;
}

.card-title {
    color: #8d91a1;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 1px;
    margin-bottom: 12px;
}

.prediction {
    font-size: 28px;
    font-weight: 800;
}

.probability {
    margin-top: 16px;
}

.prob-label {
    display: flex;
    justify-content: space-between;
    color: #9b9fad;
    font-size: 12px;
    margin-bottom: 6px;
}

.progress {
    width: 100%;
    height: 7px;
    background: #242733;
    border-radius: 20px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    border-radius: 20px;
}


/* =========================================================
   RISK SCORE
========================================================= */

.risk-card {
    background: linear-gradient(
        145deg,
        #12141d,
        #0e1016
    );
    border: 1px solid #292c38;
    border-radius: 22px;
    padding: 35px;
    text-align: center;
}

.risk-score {
    font-size: 64px;
    font-weight: 800;
    letter-spacing: -3px;
}

.risk-max {
    color: #777b8b;
    font-size: 15px;
}

.risk-level {
    display: inline-block;
    margin-top: 12px;
    padding: 8px 18px;
    border-radius: 999px;
    font-size: 13px;
    font-weight: 700;
}


/* =========================================================
   REASONS
========================================================= */

.reason {
    padding: 13px 16px;
    background: #11131a;
    border: 1px solid #252833;
    border-radius: 10px;
    margin-bottom: 8px;
    color: #c9ccd6;
    font-size: 13px;
}


/* =========================================================
   FEATURE TABLE
========================================================= */

.feature-box {
    background: #0e1016;
    border: 1px solid #252833;
    border-radius: 14px;
    padding: 20px;
}

.feature-name {
    color: #858998;
    font-size: 12px;
}

.feature-value {
    color: #f4f4f5;
    font-weight: 600;
    font-size: 14px;
}


/* =========================================================
   FOOTER
========================================================= */

.footer {
    text-align: center;
    color: #555967;
    font-size: 12px;
    padding: 50px 0 10px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# HEADER
# ============================================================

header_left, header_right = st.columns([4, 1])

with header_left:

    st.html("""
        <div class="logo">
            <span class="logo-icon">◈</span> PHISHGUARD
        </div>
    """)

with header_right:

    st.html("""
        <div class="nav-text">
            AI SECURITY ANALYSIS
        </div>
    """)


# ============================================================
# NAVIGATION
# ============================================================

nav1, nav2 = st.columns([1, 1])

with nav1:

    st.page_link(
        "app.py",
        label="URL Scanner",
        icon="🔎"
    )

with nav2:

    st.page_link(
        "pages/2_Security_Dashboard.py",
        label="Security Dashboard",
        icon="📊"
    )


# ============================================================
# HERO
# ============================================================

st.html("""
<div class="hero">

    <div class="hero-badge">
        ● AI-POWERED URL SECURITY
    </div>

    <h1>
        Know before<br>
        <span>you click.</span>
    </h1>

    <p>
        Analyze suspicious URLs using machine learning and
        rule-based cybersecurity intelligence.
    </p>

</div>
""")


# ============================================================
# URL INPUT
# ============================================================

st.html("""
<div class="input-label">
    URL TO ANALYZE
</div>
""")

url = st.text_input(
    "URL",
    placeholder="https://example.com/login",
    label_visibility="collapsed",
    key="url_input"
)


analyze_button = st.button(
    "◈  ANALYZE URL"
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze_button:

    if not url.strip():

        st.warning(
            "Please enter a URL to analyze."
        )

    else:

        clean_url = url.strip()

        with st.spinner("Analyzing URL..."):

            try:

                # ------------------------------------------------
                # RUN ANALYSIS
                # ------------------------------------------------

                result = analyze_risk(
                    clean_url
                )


                # ------------------------------------------------
                # SAVE LATEST RESULT
                # ------------------------------------------------

                st.session_state["result"] = result


                # ------------------------------------------------
                # CREATE SCAN RECORD
                # ------------------------------------------------

                scan_record = {

                    "url": result.get(
                        "url",
                        clean_url
                    ),

                    "prediction": result.get(
                        "prediction",
                        "Unknown"
                    ),

                    "risk_level": result.get(
                        "risk_level",
                        "Unknown"
                    ),

                    "risk_score": result.get(
                        "risk_score",
                        0
                    ),

                    "rule_score": result.get(
                        "rule_score",
                        0
                    ),

                    "rule_level": result.get(
                        "rule_level",
                        "Unknown"
                    ),

                    "phishing_probability": result.get(
                        "phishing_probability",
                        0
                    ),

                    "legitimate_probability": result.get(
                        "legitimate_probability",
                        0
                    ),

                    "reasons": result.get(
                        "reasons",
                        []
                    )
                }


                # ------------------------------------------------
                # PERMANENTLY SAVE SCAN
                # ------------------------------------------------

                st.session_state["scan_history"] = add_scan(
                    scan_record
                )


                st.success(
                    "URL analyzed successfully."
                )


            except Exception as e:

                st.error(
                    f"Analysis failed: {e}"
                )


# ============================================================
# DISPLAY RESULT
# ============================================================

if st.session_state.get("result") is not None:

    result = st.session_state["result"]

    st.markdown(
        "<br>",
        unsafe_allow_html=True
    )

    st.markdown(
        "### ANALYSIS RESULT"
    )


    # ========================================================
    # RISK + ML
    # ========================================================

    col1, col2 = st.columns(
        [1, 1.5]
    )


    # ========================================================
    # RISK CARD
    # ========================================================

    with col1:

        score = result["risk_score"]
        level = result["risk_level"]


        if level == "High Risk":

            badge_color = "#ff4d6d"

        elif level == "Suspicious":

            badge_color = "#ffb84d"

        elif level == "Low Risk":

            badge_color = "#ffd166"

        else:

            badge_color = "#45d483"


        st.html(f"""
        <div class="risk-card">

            <div class="card-title">
                FINAL RISK SCORE
            </div>

            <div class="risk-score">
                {score}
            </div>

            <div class="risk-max">
                out of 100
            </div>

            <div
                class="risk-level"
                style="
                    background:{badge_color}18;
                    color:{badge_color};
                    border:1px solid {badge_color}40;
                "
            >
                {level.upper()}
            </div>

        </div>
        """)


    # ========================================================
    # ML CARD
    # ========================================================

    with col2:

        phishing = (
            result["phishing_probability"] * 100
        )

        legitimate = (
            result["legitimate_probability"] * 100
        )

        prediction = result["prediction"]


        if prediction == "Phishing":

            prediction_icon = "⚠"

        else:

            prediction_icon = "✓"


        st.html(f"""
        <div class="card">

            <div class="card-title">
                MACHINE LEARNING ANALYSIS
            </div>

            <div class="prediction">
                {prediction_icon} {prediction.upper()}
            </div>

            <div class="probability">

                <div class="prob-label">
                    <span>Phishing probability</span>
                    <span>{phishing:.2f}%</span>
                </div>

                <div class="progress">

                    <div
                        class="progress-fill"
                        style="
                            width:{phishing}%;
                            background:#ff4d6d;
                        "
                    ></div>

                </div>

            </div>

            <div class="probability">

                <div class="prob-label">
                    <span>Legitimate probability</span>
                    <span>{legitimate:.2f}%</span>
                </div>

                <div class="progress">

                    <div
                        class="progress-fill"
                        style="
                            width:{legitimate}%;
                            background:#45d483;
                        "
                    ></div>

                </div>

            </div>

        </div>
        """)


    # ========================================================
    # RULE ANALYSIS
    # ========================================================

    st.markdown(
        "<br>",
        unsafe_allow_html=True
    )


    rule_col1, rule_col2 = st.columns(2)


    with rule_col1:

        st.html(f"""
        <div class="card">

            <div class="card-title">
                RULE-BASED ANALYSIS
            </div>

            <div class="prediction">
                {result["rule_score"]}/100
            </div>

            <div style="color:#858998;margin-top:8px;">

                Rule Level:
                <b>{result["rule_level"]}</b>

            </div>

        </div>
        """)


    with rule_col2:

        st.html(f"""
        <div class="card">

            <div class="card-title">
                ANALYZED URL
            </div>

            <div style="
                word-break:break-all;
                color:#c9ccd6;
                font-size:14px;
                line-height:1.6;
            ">
                {result["url"]}
            </div>

        </div>
        """)


    # ========================================================
    # REASONS
    # ========================================================

    st.markdown(
        "<br>",
        unsafe_allow_html=True
    )

    st.markdown(
        "### WHY WAS THIS URL FLAGGED?"
    )


    reasons = result.get(
        "reasons",
        []
    )


    if reasons:

        for reason in reasons:

            st.html(f"""
            <div class="reason">
                ⚠ &nbsp; {reason}
            </div>
            """)

    else:

        st.info(
            "No suspicious indicators were reported."
        )


    # ========================================================
    # FEATURE ANALYSIS
    # ========================================================

    st.markdown(
        "<br>",
        unsafe_allow_html=True
    )


    with st.expander(
        "▸  VIEW URL FEATURE ANALYSIS"
    ):

        features = extract_features(
            result["url"]
        )

        feature_items = list(
            features.items()
        )


        for i in range(
            0,
            len(feature_items),
            3
        ):

            cols = st.columns(3)


            for col, (name, value) in zip(
                cols,
                feature_items[i:i + 3]
            ):

                with col:

                    st.html(f"""
                    <div class="feature-box">

                        <div class="feature-name">
                            {name.replace("_", " ").upper()}
                        </div>

                        <div class="feature-value">
                            {value}
                        </div>

                    </div>
                    """)

                    st.markdown(
                        "<div style='height:8px'></div>",
                        unsafe_allow_html=True
                    )


# ============================================================
# FOOTER
# ============================================================

st.html("""
<div class="footer">

    PHISHGUARD • AI-POWERED PHISHING URL DETECTION

    <br><br>

    Machine Learning + Rule-Based Security Analysis

</div>
""")