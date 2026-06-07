# =============================================================================
# ml/train_model.py — Train the Attack Classifier
# =============================================================================
# This is a ONE-TIME script. Run it before starting the proxy.
#
# What it does:
#   1. Loads the UNSW-NB15 dataset from data/
#   2. Cleans and preprocesses the data
#   3. Trains a Random Forest classifier (10 classes)
#   4. Evaluates accuracy on a held-out test set
#   5. Saves the model, scaler, and label encoder to models/
#
# How to run:
#   python ml/train_model.py
#
# Required files in data/ folder:
#   UNSW_NB15_training-set.csv
#   UNSW_NB15_testing-set.csv   (optional — used for evaluation)
# =============================================================================

import os
import sys
import logging
import pickle
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Make sure we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DATA_DIR, MODELS_DIR, CLASSIFIER_MODEL_PATH, SCALER_PATH, LABEL_ENCODER_PATH

# Set up logging so progress is easy to follow
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("train_model")


# =============================================================================
# FEATURE SELECTION
# =============================================================================
# These are the columns we pull from the dataset.
# They represent measurable properties of network connections.
# We skip raw IP addresses and other non-generalizable identifiers.

FEATURE_COLUMNS = [
    "dur",          # Duration of the connection in seconds
    "spkts",        # Number of packets sent by source
    "dpkts",        # Number of packets sent by destination
    "sbytes",       # Bytes sent by source
    "dbytes",       # Bytes sent by destination
    "rate",         # Packet rate (packets per second)
    "sttl",         # Source time-to-live value
    "dttl",         # Destination time-to-live value
    "sload",        # Source load (bits per second)
    "dload",        # Destination load (bits per second)
    "sinpkt",       # Source inter-packet arrival time
    "dinpkt",       # Destination inter-packet arrival time
    "smean",        # Mean packet size sent by source
    "dmean",        # Mean packet size sent by destination
    "ct_srv_src",   # Connections to same service from same source (last 100)
    "ct_dst_ltm",   # Connections to destination in last time window
    "ct_src_ltm",   # Connections from source in last time window
    "ct_src_dport_ltm",  # Connections from source to same dest port
    "ct_dst_sport_ltm",  # Connections to destination from same source port
    "ct_dst_src_ltm",    # Connections between source and destination
]

# Categorical columns that need to be converted to numbers
CATEGORICAL_COLUMNS = ["proto", "service", "state"]

# The column containing attack labels
LABEL_COLUMN = "attack_cat"

# All possible attack categories in UNSW-NB15
# "Normal" means legitimate traffic
ALL_CATEGORIES = [
    "Normal", "Analysis", "Backdoor", "DoS",
    "Exploits", "Fuzzers", "Generic",
    "Reconnaissance", "Shellcode", "Worms"
]


# =============================================================================
# STEP 1: LOAD DATA
# =============================================================================

def load_data() -> pd.DataFrame:
    """
    Loads and merges the UNSW-NB15 CSV files from the data/ directory.

    The dataset comes in two files:
    - UNSW_NB15_training-set.csv  (main training data)
    - UNSW_NB15_testing-set.csv   (optional, merged for more data)

    Returns:
        A single merged DataFrame with all rows.
    """
    train_path = os.path.join(DATA_DIR, "UNSW_NB15_training-set.csv")
    test_path  = os.path.join(DATA_DIR, "UNSW_NB15_testing-set.csv")

    dataframes = []

    # Load training set (required)
    if os.path.exists(train_path):
        logger.info(f"Loading training set: {train_path}")
        df_train = pd.read_csv(train_path, low_memory=False)
        logger.info(f"  → {len(df_train):,} rows loaded")
        dataframes.append(df_train)
    else:
        raise FileNotFoundError(
            f"Training CSV not found at: {train_path}\n"
            f"Please download UNSW_NB15_training-set.csv and place it in data/"
        )

    # Load test set (optional but recommended)
    if os.path.exists(test_path):
        logger.info(f"Loading test set: {test_path}")
        df_test = pd.read_csv(test_path, low_memory=False)
        logger.info(f"  → {len(df_test):,} rows loaded")
        dataframes.append(df_test)
    else:
        logger.warning("Test CSV not found — using training data only.")

    # Merge into a single DataFrame
    df = pd.concat(dataframes, ignore_index=True)
    logger.info(f"Total rows after merge: {len(df):,}")

    return df


# =============================================================================
# STEP 2: PREPROCESS DATA
# =============================================================================

def preprocess(df: pd.DataFrame):
    """
    Cleans and prepares the raw dataset for training.

    Steps:
      1. Normalize column names (lowercase, strip spaces)
      2. Fix the label column (handle NaN, strip whitespace, capitalize)
      3. Keep only known attack categories
      4. Select feature columns (drop any that are missing)
      5. Encode categorical features as integers
      6. Fill missing numeric values with column median
      7. Extract feature matrix X and label vector y

    Args:
        df: Raw DataFrame from load_data()

    Returns:
        X: numpy array of features  (shape: n_samples × n_features)
        y: numpy array of labels    (shape: n_samples,)
        feature_names: list of column names used (for SHAP later)
        cat_encoders: dict of {column_name: LabelEncoder} for runtime use
    """
    logger.info("Preprocessing data...")

    # --- Normalize column names ---
    df.columns = [c.strip().lower() for c in df.columns]

    # --- Fix label column ---
    # The label column may have different capitalizations or trailing spaces
    if LABEL_COLUMN not in df.columns:
        # Some versions use "label" (0/1) instead of "attack_cat"
        # Try to find the right column
        possible = [c for c in df.columns if "attack" in c or "label" in c or "cat" in c]
        logger.warning(f"Column '{LABEL_COLUMN}' not found. Available: {possible}")
        if possible:
            df = df.rename(columns={possible[0]: LABEL_COLUMN})
        else:
            raise ValueError("Cannot find attack label column in dataset.")

    # Clean up label strings
    df[LABEL_COLUMN] = (
        df[LABEL_COLUMN]
        .fillna("Normal")           # NaN → "Normal"
        .astype(str)
        .str.strip()                # Remove whitespace
        .str.capitalize()           # Normalize capitalization
    )

    # Replace empty strings with "Normal"
    df[LABEL_COLUMN] = df[LABEL_COLUMN].replace("", "Normal")

    # Keep only known categories (drop any rows with unknown labels)
    before = len(df)
    df = df[df[LABEL_COLUMN].isin(ALL_CATEGORIES)]
    dropped = before - len(df)
    if dropped > 0:
        logger.warning(f"Dropped {dropped:,} rows with unknown labels.")

    # Show label distribution
    logger.info("Label distribution:")
    for cat, count in df[LABEL_COLUMN].value_counts().items():
        pct = 100 * count / len(df)
        logger.info(f"  {cat:<20} {count:>8,}  ({pct:.1f}%)")

    # --- Select feature columns ---
    # Only keep columns that actually exist in the dataset
    available_features = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing_features   = [c for c in FEATURE_COLUMNS if c not in df.columns]

    if missing_features:
        logger.warning(f"Missing feature columns (will skip): {missing_features}")

    # Also try to include categorical columns if available
    available_cats = [c for c in CATEGORICAL_COLUMNS if c in df.columns]

    all_input_cols = available_features + available_cats
    logger.info(f"Using {len(all_input_cols)} feature columns.")

    # --- Encode categorical features ---
    # Machine learning needs numbers, not strings like "tcp" or "http"
    cat_encoders = {}  # Save these so we can reuse at runtime

    for col in available_cats:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str).fillna("unknown"))
        cat_encoders[col] = le
        logger.info(f"  Encoded '{col}': {list(le.classes_[:5])} ...")

    # --- Extract feature matrix ---
    X = df[all_input_cols].copy()

    # Fill any remaining NaN values with the column median
    # (median is more robust than mean for skewed network data)
    X = X.fillna(X.median(numeric_only=True))

    # Convert to numpy for sklearn
    X = X.values.astype(np.float32)

    # --- Extract labels ---
    y = df[LABEL_COLUMN].values

    logger.info(f"Feature matrix shape: {X.shape}")
    logger.info(f"Label vector shape:   {y.shape}")

    return X, y, all_input_cols, cat_encoders


# =============================================================================
# STEP 3: ENCODE LABELS
# =============================================================================

def encode_labels(y: np.ndarray):
    """
    Converts string labels to integers for the classifier.

    Example:
        "Normal"    → 0
        "Analysis"  → 1
        "Backdoor"  → 2
        ... etc.

    Args:
        y: Array of string labels

    Returns:
        y_encoded: Array of integer labels
        label_encoder: Fitted LabelEncoder (save this for decoding predictions)
    """
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    logger.info("Label encoding:")
    for i, cls in enumerate(label_encoder.classes_):
        logger.info(f"  {i} → {cls}")

    return y_encoded, label_encoder


# =============================================================================
# STEP 4: TRAIN MODEL
# =============================================================================

def train(X_train, y_train) -> RandomForestClassifier:
    """
    Trains a Random Forest classifier.

    Why Random Forest?
    - Handles mixed data types well (numeric + encoded categoricals)
    - Naturally resistant to overfitting via ensemble averaging
    - Provides feature importance scores (used by SHAP later)
    - Gives probability estimates (confidence scores for each prediction)
    - Works well out-of-the-box without heavy tuning

    Hyperparameters chosen for balance of speed and accuracy:
    - n_estimators=100: 100 decision trees in the forest
    - max_depth=20: prevents trees from memorizing training data
    - min_samples_split=10: a node needs 10+ samples to split (reduces noise)
    - class_weight="balanced": compensates for imbalanced attack categories
    - n_jobs=-1: use all CPU cores for parallel training
    - random_state=42: reproducible results

    Args:
        X_train: Feature matrix (numpy array)
        y_train: Integer labels (numpy array)

    Returns:
        Trained RandomForestClassifier
    """
    logger.info("Training Random Forest classifier...")
    logger.info(f"  Training samples: {len(X_train):,}")
    logger.info(f"  Number of features: {X_train.shape[1]}")

    model = RandomForestClassifier(
        n_estimators=100,       # 100 trees — good accuracy/speed tradeoff
        max_depth=20,           # Limit tree depth to prevent overfitting
        min_samples_split=10,   # Require 10+ samples to split a node
        class_weight="balanced",# Handle imbalanced classes automatically
        n_jobs=-1,              # Use all available CPU cores
        random_state=42,        # Reproducible training
        verbose=1               # Print progress
    )

    model.fit(X_train, y_train)
    logger.info("Training complete.")

    return model


# =============================================================================
# STEP 5: EVALUATE
# =============================================================================

def evaluate(model, X_test, y_test, label_encoder):
    """
    Measures how well the trained model performs on unseen data.

    Prints:
    - Overall accuracy (% of correctly classified samples)
    - Per-class precision, recall, F1-score

    Args:
        model: Trained RandomForestClassifier
        X_test: Test feature matrix
        y_test: True integer labels for test set
        label_encoder: To decode integers back to class names
    """
    logger.info("Evaluating model on test set...")

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)

    logger.info(f"\nOverall Accuracy: {accuracy * 100:.2f}%\n")

    # Classification report shows per-class performance
    report = classification_report(
        y_test, y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    )
    print("\n" + "=" * 60)
    print("Classification Report:")
    print("=" * 60)
    print(report)

    return accuracy


# =============================================================================
# STEP 6: SAVE ARTIFACTS
# =============================================================================

def save_artifacts(model, scaler, label_encoder, cat_encoders, feature_names):
    """
    Saves all trained objects to disk so the proxy can load them at runtime.

    Files saved to models/:
    - attack_classifier.pkl  → the Random Forest model
    - scaler.pkl             → StandardScaler (normalize live requests)
    - label_encoder.pkl      → decode model output integers to attack names
    - feature_names.pkl      → ordered list of features (must match at inference)
    - cat_encoders.pkl       → categorical encoders for runtime use

    Args:
        model:         Trained RandomForestClassifier
        scaler:        Fitted StandardScaler
        label_encoder: Fitted LabelEncoder for attack categories
        cat_encoders:  Dict of fitted LabelEncoders for categorical columns
        feature_names: List of feature column names used during training
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    artifacts = {
        CLASSIFIER_MODEL_PATH: model,
        SCALER_PATH: scaler,
        LABEL_ENCODER_PATH: label_encoder,
        os.path.join(MODELS_DIR, "feature_names.pkl"): feature_names,
        os.path.join(MODELS_DIR, "cat_encoders.pkl"): cat_encoders,
    }

    for path, obj in artifacts.items():
        with open(path, "wb") as f:
            pickle.dump(obj, f)
        logger.info(f"Saved: {path}")

    logger.info("All artifacts saved to models/")


# =============================================================================
# MAIN — Run everything in sequence
# =============================================================================

def main():
    logger.info("=" * 60)
    logger.info("Zero Trust Proxy — Model Training")
    logger.info("=" * 60)

    # 1. Load raw data
    df = load_data()

    # 2. Preprocess (clean, encode categoricals, select features)
    X, y, feature_names, cat_encoders = preprocess(df)

    # 3. Encode string labels → integers
    y_encoded, label_encoder = encode_labels(y)

    # 4. Split into train/test (80% train, 20% test)
    logger.info("Splitting data: 80% train / 20% test")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded  # Keep class ratios the same in both splits
    )
    logger.info(f"  Train: {len(X_train):,} samples")
    logger.info(f"  Test:  {len(X_test):,} samples")

    # 5. Scale features (mean=0, std=1)
    # This helps the model treat all features equally regardless of magnitude
    # e.g. "sbytes" (could be millions) vs "rate" (could be <100)
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)  # Fit on train only
    X_test  = scaler.transform(X_test)       # Apply same scale to test

    # 6. Train the Random Forest
    model = train(X_train, y_train)

    # 7. Evaluate on held-out test set
    evaluate(model, X_test, y_test, label_encoder)

    # 8. Save everything to models/
    save_artifacts(model, scaler, label_encoder, cat_encoders, feature_names)

    logger.info("=" * 60)
    logger.info("Training complete! You can now start the proxy.")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
