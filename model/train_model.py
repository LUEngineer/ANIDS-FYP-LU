"""
train_model.py
Trains a Random Forest classifier on the NSL-KDD dataset and evaluates it
on the official test set.
"""

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

train_df = pd.read_csv("data/train_processed.csv")
test_df = pd.read_csv("data/test_processed.csv")

X_train = train_df.drop(columns=["label"])
y_train = train_df["label"]
X_test = test_df.drop(columns=["label"])
y_test = test_df["label"]

# random_state fixes the randomness so results are reproducible across runs
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print()
print("Classification report:")
print(classification_report(y_test, y_pred, target_names=["normal", "attack"]))
print()
print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred))

# Feature importances show which network features drive the model's decisions
importances = pd.Series(model.feature_importances_, index=X_train.columns)
print("\nTop 10 most important features:")
print(importances.sort_values(ascending=False).head(10))

joblib.dump(model, "model/trained_model.pkl")
print("\nModel saved to model/trained_model.pkl")