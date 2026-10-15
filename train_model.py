"""
train_model.py
================
This script prepares the sample dataset, trains a machine learning model
to classify messages as "phishing" or "legitimate", and saves the
trained model to the models/ folder so the Flask app can use it.

How to run:
    python train_model.py

The script will:
1. Load the sample data from data/sample_data.csv
2. Convert the text into numbers using TF-IDF (a common NLP technique)
3. Train a Logistic Regression classifier
4. Print the accuracy on a test set
5. Save the model and the vectorizer to models/phishing_model.pkl
"""

import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report


# ---- Paths ----------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "sample_data.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")


def load_data():
    """Read the CSV file and return the text samples and their labels."""
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} samples from {DATA_PATH}")
    print(f"Phishing samples:    {(df['label'] == 'phishing').sum()}")
    print(f"Legitimate samples:  {(df['label'] == 'legitimate').sum()}")
    return df["text"].values, df["label"].values


def build_pipeline():
    """
    Create a machine-learning pipeline that:
      1. Converts text to numbers using TF-IDF (term frequency / inverse
         document frequency) -- a standard NLP technique.
      2. Feeds those numbers into a Logistic Regression classifier.
    """
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            stop_words="english",   # remove common words like "the", "is"
            ngram_range=(1, 2),     # look at single words and word pairs
            min_df=1,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            random_state=42,
        )),
    ])
    return pipeline


def main():
    print("=" * 60)
    print("  AI Phishing & Scam Detector - Model Training")
    print("=" * 60)

    # 1. Load the data
    X, y = load_data()

    # 2. Split into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTraining samples: {len(X_train)}")
    print(f"Testing samples:  {len(X_test)}")

    # 3. Build the pipeline and train the model
    print("\nTraining the model...")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # 4. Evaluate on the test set
    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nTest accuracy: {accuracy:.2%}")
    print("\nClassification report:")
    print(classification_report(y_test, y_pred))

    # 5. Save the trained pipeline (vectorizer + model) to disk
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")
    print("\nTraining complete. You can now run the app with:  python app.py")


if __name__ == "__main__":
    main()
