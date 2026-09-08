import sys
import os

# Project root added to path because Streamlit runs this file from
# app/pages/, where model/ isn't otherwise importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import streamlit as st
import pandas as pd
import joblib

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
DROP_IF_PRESENT = ["label", "difficulty_level"]

st.set_page_config(page_title="ANIDS - ML Classifier", page_icon="🧠")
st.title("🧠 ML Intrusion Classifier")
st.caption(
    "This model performs misuse-based detection: it recognizes known attack "
    "patterns learned from NSL-KDD, rather than flagging general anomalies. "
    "Upload a CSV with NSL-KDD feature columns to classify each row as "
    "normal or attack."
)

model = joblib.load("model/trained_model.pkl")
encoder = joblib.load("model/encoder.pkl")

uploaded_file = st.file_uploader("Upload CSV", type="csv")

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)

    # NSL-KDD's own label/difficulty_level columns aren't model inputs, but
    # may be present if the user uploads a labeled file (e.g. the test set).
    true_labels = df["label"] if "label" in df.columns else None
    features_df = df.drop(columns=[c for c in DROP_IF_PRESENT if c in df.columns])

    # Same encoding path used in preprocess.py, reusing the fitted encoder
    # so new rows map to the exact same columns the model was trained on.
    encoded_array = encoder.transform(features_df[CATEGORICAL_COLS])
    encoded_df = pd.DataFrame(
        encoded_array,
        columns=encoder.get_feature_names_out(CATEGORICAL_COLS),
        index=features_df.index
    )
    numeric_df = features_df.drop(columns=CATEGORICAL_COLS)
    X = pd.concat([numeric_df, encoded_df], axis=1)

    predictions = model.predict(X)
    df["prediction"] = ["attack" if p == 1 else "normal" for p in predictions]

    st.subheader("Results")
    st.dataframe(df)

    attack_count = (df["prediction"] == "attack").sum()
    normal_count = (df["prediction"] == "normal").sum()
    st.caption(f"{len(df)} rows classified — {normal_count} normal, {attack_count} attack")

    # Optional accuracy display if the uploaded file already had true labels
    if true_labels is not None:
        binary_true = true_labels.apply(lambda x: 0 if str(x) == "normal" else 1)
        accuracy = (predictions == binary_true.values).mean()
        st.metric("Accuracy on this file", f"{accuracy:.2%}")

    csv_output = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download results as CSV", csv_output, "classified_results.csv", "text/csv")