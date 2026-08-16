import streamlit as st
import pandas as pd
import sys
import os


# ============================================================
# PROJECT ROOT
# ============================================================

ROOT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)


from scan_storage import load_scan_history


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard | Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


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
    max-width: 1250px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}

h1, h2, h3 {
    font-weight: 800 !important;
}

[data-testid="stMetric"] {
    background: #11131a;
    border: 1px solid #252833;
    padding: 18px;
    border-radius: 16px;
}

[data-testid="stMetricValue"] {
    font-weight: 800;
}

[data-testid="stDataFrame"] {
    border: 1px solid #252833;
    border-radius: 14px;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# HEADER
# ============================================================

header_left, header_right = st.columns([4, 1])


with header_left:

    st.markdown(
        "## ◈ PHISHGUARD"
    )


with header_right:

    st.caption(
        "SECURITY DASHBOARD"
    )


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
# TITLE
# ============================================================

st.title(
    "Security Dashboard"
)

st.caption(
    "Real-time monitoring of phishing detection activity, "
    "risk intelligence and model performance."
)


# ============================================================
# LOAD PERMANENT SCAN HISTORY
# ============================================================

scan_history = load_scan_history()


# Keep Streamlit session synchronized
st.session_state["scan_history"] = scan_history


# ============================================================
# BASIC STATISTICS
# ============================================================

total_scans = len(
    scan_history
)


phishing_scans = sum(
    1
    for scan in scan_history
    if scan.get("prediction") == "Phishing"
)


legitimate_scans = sum(
    1
    for scan in scan_history
    if scan.get("prediction") == "Legitimate"
)


high_risk_scans = sum(
    1
    for scan in scan_history
    if scan.get("risk_level") == "High Risk"
)


suspicious_scans = sum(
    1
    for scan in scan_history
    if scan.get("risk_level") == "Suspicious"
)


low_risk_scans = sum(
    1
    for scan in scan_history
    if scan.get("risk_level") == "Low Risk"
)


# ============================================================
# AVERAGE RISK
# ============================================================

risk_scores = []


for scan in scan_history:

    try:

        risk_scores.append(
            float(
                scan.get(
                    "risk_score",
                    0
                )
            )
        )

    except:

        pass


if risk_scores:

    average_risk = (
        sum(risk_scores)
        / len(risk_scores)
    )

else:

    average_risk = 0


# ============================================================
# THREAT RATE
# ============================================================

if total_scans > 0:

    threat_rate = (
        phishing_scans
        / total_scans
    ) * 100

else:

    threat_rate = 0


# ============================================================
# SECURITY STATUS
# ============================================================

st.subheader(
    "Security Status"
)

st.caption(
    "Current security posture based on analyzed URLs."
)


if total_scans == 0:

    st.info(
        "🟡 Waiting for URL scans."
    )


elif threat_rate >= 50:

    st.error(
        f"🔴 High Threat Activity — "
        f"{threat_rate:.1f}% of analyzed URLs "
        f"were detected as phishing."
    )


elif threat_rate >= 20:

    st.warning(
        f"🟠 Elevated Threat Activity — "
        f"{threat_rate:.1f}% of analyzed URLs "
        f"were detected as phishing."
    )


else:

    st.success(
        f"🟢 Low Threat Activity — "
        f"{threat_rate:.1f}% of analyzed URLs "
        f"were detected as phishing."
    )


st.caption(
    f"{total_scans} URL(s) analyzed."
)


# ============================================================
# SECURITY OVERVIEW
# ============================================================

st.subheader(
    "Security Overview"
)


c1, c2, c3, c4, c5 = st.columns(5)


with c1:

    st.metric(
        "URLs Analyzed",
        total_scans
    )


with c2:

    st.metric(
        "Threats Detected",
        phishing_scans
    )


with c3:

    st.metric(
        "Legitimate",
        legitimate_scans
    )


with c4:

    st.metric(
        "High Risk",
        high_risk_scans
    )


with c5:

    st.metric(
        "Average Risk",
        f"{average_risk:.1f}"
    )


# ============================================================
# THREAT ANALYTICS
# ============================================================

st.subheader(
    "Threat Analytics"
)

st.caption(
    "Distribution of URL classifications and risk levels."
)


left, right = st.columns(2)


# ============================================================
# DETECTION RATE
# ============================================================

with left:

    st.markdown(
        "#### Detection Rate"
    )


    if total_scans > 0:

        phishing_percentage = (
            phishing_scans
            / total_scans
        ) * 100


        legitimate_percentage = (
            legitimate_scans
            / total_scans
        ) * 100


        st.metric(
            "Phishing Detection Rate",
            f"{phishing_percentage:.1f}%"
        )


        st.progress(
            phishing_percentage / 100
        )


        st.write(
            f"🔴 Phishing: "
            f"{phishing_percentage:.1f}%"
        )


        st.write(
            f"🟢 Legitimate: "
            f"{legitimate_percentage:.1f}%"
        )


    else:

        st.info(
            "No URLs analyzed yet."
        )


# ============================================================
# RISK DISTRIBUTION
# ============================================================

with right:

    st.markdown(
        "#### Risk Distribution"
    )


    if total_scans > 0:

        risk_data = pd.DataFrame({

            "Risk Level": [
                "High Risk",
                "Suspicious",
                "Low Risk"
            ],

            "URLs": [
                high_risk_scans,
                suspicious_scans,
                low_risk_scans
            ]

        })


        st.bar_chart(
            risk_data.set_index(
                "Risk Level"
            )
        )


    else:

        st.info(
            "Risk distribution will appear "
            "after scanning URLs."
        )


# ============================================================
# ML CONFIDENCE
# ============================================================

st.subheader(
    "Machine Learning Confidence"
)

st.caption(
    "Confidence levels generated by the "
    "phishing classification model."
)


if scan_history:

    confidence_data = []


    for scan in scan_history[-10:]:

        try:

            phishing_probability = (

                float(
                    scan.get(
                        "phishing_probability",
                        0
                    )
                )

                * 100

            )


            confidence_data.append({

                "Phishing":
                    phishing_probability,

                "Legitimate":
                    100 - phishing_probability

            })


        except:

            continue


    if confidence_data:

        confidence_df = pd.DataFrame(
            confidence_data
        )


        st.line_chart(
            confidence_df,
            height=280
        )


    else:

        st.info(
            "Confidence information is unavailable."
        )


else:

    st.info(
        "Analyze URLs to generate "
        "ML confidence information."
    )


# ============================================================
# RECENT SCANS
# ============================================================

st.subheader(
    "Recent Scan Intelligence"
)

st.caption(
    "Latest URLs analyzed by the PhishGuard "
    "detection engine."
)


if scan_history:

    recent_scans = (
        scan_history[-10:]
        [::-1]
    )


    recent_data = []


    for scan in recent_scans:

        prediction = scan.get(
            "prediction",
            "Unknown"
        )


        risk_level = scan.get(
            "risk_level",
            "Unknown"
        )


        risk_score = scan.get(
            "risk_score",
            "-"
        )


        rule_score = scan.get(
            "rule_score",
            "-"
        )


        try:

            phishing_probability = (

                float(
                    scan.get(
                        "phishing_probability",
                        0
                    )
                )

                * 100

            )


            confidence = (
                f"{phishing_probability:.1f}%"
            )


        except:

            confidence = "-"


        if prediction == "Phishing":

            status = "⚠ Phishing"

        elif prediction == "Legitimate":

            status = "✓ Legitimate"

        else:

            status = "Unknown"


        recent_data.append({

            "URL": scan.get(
                "url",
                "Unknown"
            ),

            "Detection": status,

            "Risk Level": risk_level,

            "Risk Score": risk_score,

            "ML Confidence": confidence,

            "Rule Score": rule_score

        })


    recent_df = pd.DataFrame(
        recent_data
    )


    st.dataframe(
        recent_df,
        use_container_width=True,
        hide_index=True
    )


else:

    st.info(
        "No scans yet. Analyze a URL on "
        "the Scanner page to populate "
        "your dashboard."
    )


# ============================================================
# THREAT INDICATORS
# ============================================================

st.subheader(
    "Threat Indicators"
)

st.caption(
    "Common indicators observed across "
    "the current scan history."
)


indicator_counts = {}


for scan in scan_history:

    reasons = scan.get(
        "reasons",
        []
    )


    if isinstance(
        reasons,
        list
    ):

        for reason in reasons:

            reason = str(
                reason
            ).strip()


            if reason:

                indicator_counts[reason] = (
                    indicator_counts.get(
                        reason,
                        0
                    ) + 1
                )


if indicator_counts:

    sorted_indicators = sorted(
        indicator_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:8]


    for reason, count in sorted_indicators:

        st.write(
            f"⚠ **{reason}** — "
            f"{count} occurrence(s)"
        )


else:

    st.info(
        "Threat indicators will appear "
        "after URLs are analyzed."
    )


# ============================================================
# MODEL PERFORMANCE
# ============================================================

st.subheader(
    "Model Performance"
)

st.caption(
    "Performance of the Random Forest "
    "phishing classification model."
)


model_left, model_right = st.columns(
    [1, 3]
)


with model_left:

    st.markdown(
        "### 🌲 Random Forest"
    )

    st.caption(
        "Primary machine-learning model "
        "used for phishing URL classification."
    )


with model_right:

    m1, m2, m3, m4 = st.columns(4)


    with m1:

        st.metric(
            "Accuracy",
            "99.53%"
        )


    with m2:

        st.metric(
            "Precision",
            "99.74%"
        )


    with m3:

        st.metric(
            "Recall",
            "99.15%"
        )


    with m4:

        st.metric(
            "F1 Score",
            "99.45%"
        )


# ============================================================
# MODEL EVALUATION
# ============================================================

st.subheader(
    "Model Evaluation"
)

st.caption(
    "Random Forest — Domain-level test set."
)


tn = 26857
fp = 66
fn = 145
tp = 19653


c1, c2, c3, c4 = st.columns(4)


with c1:

    st.metric(
        "True Negatives",
        f"{tn:,}"
    )

    st.caption(
        "Legitimate → Legitimate"
    )


with c2:

    st.metric(
        "False Positives",
        f"{fp:,}"
    )

    st.caption(
        "Legitimate → Phishing"
    )


with c3:

    st.metric(
        "False Negatives",
        f"{fn:,}"
    )

    st.caption(
        "Phishing → Legitimate"
    )


with c4:

    st.metric(
        "True Positives",
        f"{tp:,}"
    )

    st.caption(
        "Phishing → Phishing"
    )


# ============================================================
# ERROR ANALYSIS
# ============================================================

st.subheader(
    "🔍 Error Analysis"
)


error1, error2 = st.columns(2)


with error1:

    st.metric(
        "False Positives",
        f"{fp:,}"
    )

    st.caption(
        "Legitimate URLs incorrectly "
        "classified as phishing."
    )


with error2:

    st.metric(
        "False Negatives",
        f"{fn:,}"
    )

    st.caption(
        "Phishing URLs incorrectly "
        "classified as legitimate."
    )


# ============================================================
# DATASET INFORMATION
# ============================================================

st.subheader(
    "Dataset Information"
)


d1, d2, d3 = st.columns(3)


with d1:

    st.metric(
        "Total URLs",
        "235,795"
    )


with d2:

    st.metric(
        "Training Samples",
        "189,074"
    )


with d3:

    st.metric(
        "Testing Samples",
        "46,721"
    )


# ============================================================
# DETECTION ARCHITECTURE
# ============================================================

st.subheader("Detection Architecture")

st.caption(
    "How PhishGuard processes a URL from input to final risk verdict."
)

a1, a2, a3, a4 = st.columns(4)

with a1:
    with st.container(border=True):
        st.markdown("**STEP 01**")
        st.markdown("### URL Input")
        st.caption(
            "Suspicious URL submitted for security analysis."
        )

with a2:
    with st.container(border=True):
        st.markdown("**STEP 02**")
        st.markdown("### Feature Extraction")
        st.caption(
            "URL characteristics are extracted for analysis."
        )

with a3:
    with st.container(border=True):
        st.markdown("**STEP 03**")
        st.markdown("### ML + Rules")
        st.caption(
            "Random Forest and rule-based detection run."
        )

with a4:
    with st.container(border=True):
        st.markdown("**STEP 04**")
        st.markdown("### Risk Engine")
        st.caption(
            "Signals are combined into a final risk score."
        )
# ============================================================
# DETECTION SYSTEM
# ============================================================

st.subheader(
    "Detection System"
)


system_data = pd.DataFrame({

    "Component": [

        "Machine Learning",

        "Rule-Based Detection",

        "Feature Extraction",

        "Risk Engine"

    ],

    "Purpose": [

        "Classifies URLs as phishing or legitimate",

        "Identifies suspicious URL characteristics",

        "Extracts cybersecurity-related URL features",

        "Combines ML and rule-based signals"

    ]

})


st.dataframe(
    system_data,
    use_container_width=True,
    hide_index=True
)


# ============================================================
# FOOTER
# ============================================================

st.divider()


st.caption(
    "PHISHGUARD • AI-POWERED PHISHING URL DETECTION"
)


st.caption(
    "Machine Learning + Rule-Based Security Analysis"
)