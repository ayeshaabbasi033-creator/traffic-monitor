import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib  # lets us save the trained model to a file

# ---------------------------------------------------------
# STEP 1: Load the column names
# ---------------------------------------------------------
# Field Names.csv has two columns: the feature name, and its type.
# It does NOT include the final "label" and "difficulty" columns, so we add those ourselves.
field_names_df = pd.read_csv("Field Names.csv", header=None)
column_names = list(field_names_df[0]) + ["label", "difficulty"]

# ---------------------------------------------------------
# STEP 2: Load the actual data
# ---------------------------------------------------------
# KDDTrain+.txt and KDDTest+.txt have no header row, so we supply our column_names
train_df = pd.read_csv("KDDTrain+.txt", names=column_names)
test_df = pd.read_csv("KDDTest+.txt", names=column_names)

print(f"Training data: {train_df.shape[0]} rows, {train_df.shape[1]} columns")
print(f"Test data: {test_df.shape[0]} rows, {test_df.shape[1]} columns")

# ---------------------------------------------------------
# STEP 3: Simplify the label
# ---------------------------------------------------------
# The 'label' column has specific attack names (e.g. "neptune", "smurf", "satan").
# For a first model, we simplify this into a binary problem: "normal" vs "attack".
train_df["binary_label"] = train_df["label"].apply(lambda x: "normal" if x == "normal" else "attack")
test_df["binary_label"] = test_df["label"].apply(lambda x: "normal" if x == "normal" else "attack")

print("\nTraining label distribution:")
print(train_df["binary_label"].value_counts())

# ---------------------------------------------------------
# STEP 4: Encode categorical columns
# ---------------------------------------------------------
# ML models need numbers, not text. protocol_type, service, and flag are text columns.
categorical_cols = ["protocol_type", "service", "flag"]

encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    # Fit on combined train+test values so we don't hit an "unseen category" error later
    combined = pd.concat([train_df[col], test_df[col]])
    le.fit(combined)
    train_df[col] = le.transform(train_df[col])
    test_df[col] = le.transform(test_df[col])
    encoders[col] = le

# ---------------------------------------------------------
# STEP 5: Prepare X (features) and y (labels)
# ---------------------------------------------------------
# Drop the columns that aren't actual features
feature_cols = [c for c in column_names if c not in ["label", "difficulty"]]

X_train = train_df[feature_cols]
y_train = train_df["binary_label"]

X_test = test_df[feature_cols]
y_test = test_df["binary_label"]

# ---------------------------------------------------------
# STEP 6: Train the model
# ---------------------------------------------------------
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1, class_weight="balanced")
model.fit(X_train, y_train)

# ---------------------------------------------------------
# STEP 7: Evaluate it
# ---------------------------------------------------------
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\nAccuracy on test set: {accuracy:.4f}")
print("\nDetailed report:")
print(classification_report(y_test, predictions))

# ---------------------------------------------------------
# STEP 8: Save the model + encoders for later use
# ---------------------------------------------------------
joblib.dump(model, "traffic_model.pkl")
joblib.dump(encoders, "encoders.pkl")
joblib.dump(feature_cols, "feature_cols.pkl")

print("\nModel saved as traffic_model.pkl")