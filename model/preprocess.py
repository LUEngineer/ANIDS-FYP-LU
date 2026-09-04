"""
preprocess.py
Converts raw NSL-KDD data into numeric input for the Random Forest:
binary labels, one-hot encoded categorical columns, difficulty_level dropped.
"""

import pandas as pd
from sklearn.preprocessing import OneHotEncoder

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level"
]

train_df = pd.read_csv("data/KDDTrain+.txt", header=None, names=COLUMN_NAMES)
test_df = pd.read_csv("data/KDDTest+.txt", header=None, names=COLUMN_NAMES)

train_df = train_df.drop(columns=["difficulty_level"])
test_df = test_df.drop(columns=["difficulty_level"])

# Binary labels: normal -> 0, any attack type -> 1
train_df["label"] = (train_df["label"] != "normal").astype(int)
test_df["label"] = (test_df["label"] != "normal").astype(int)

# Encode the 3 text categorical columns into numbers.
# Fit only on train to avoid test-set information leaking into feature setup.
# handle_unknown="ignore" encodes any service value seen only in test as all-zeros.
categorical_cols = ["protocol_type", "service", "flag"]
encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
encoder.fit(train_df[categorical_cols])

def encode(df):
    encoded_array = encoder.transform(df[categorical_cols])
    encoded_df = pd.DataFrame(
        encoded_array,
        columns=encoder.get_feature_names_out(categorical_cols),
        index=df.index
    )
    numeric_df = df.drop(columns=categorical_cols)
    return pd.concat([numeric_df, encoded_df], axis=1)

train_encoded = encode(train_df)
test_encoded = encode(test_df)

print("Train encoded shape:", train_encoded.shape)
print("Test encoded shape:", test_encoded.shape)
print()
print("Binary label distribution (train):")
print(train_encoded["label"].value_counts())

train_encoded.to_csv("data/train_processed.csv", index=False)
test_encoded.to_csv("data/test_processed.csv", index=False)
print("\nSaved to data/train_processed.csv and data/test_processed.csv")