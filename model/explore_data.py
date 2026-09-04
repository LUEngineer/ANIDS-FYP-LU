"""
explore_data.py
First look at the raw NSL-KDD data before preprocessing.
"""

import pandas as pd

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

print("Train shape:", train_df.shape)
print("Test shape:", test_df.shape)
print()

print("First 5 rows:")
print(train_df.head())
print()

print("Unique labels and their counts:")
print(train_df["label"].value_counts())