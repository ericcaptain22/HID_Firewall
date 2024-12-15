import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os

def load_data_from_csv(payload_file):
    """Load data from payload.csv."""
    df = pd.read_csv(payload_file)
    return df['filepath']  # Return the file paths for training

def train_model(payload_file):
    # Load dataset
    X = load_data_from_csv(payload_file)

    # Split dataset (labels are implicit for payloads)
    X_train, X_test = train_test_split(X, test_size=0.2, random_state=42)

    # Vectorize file paths
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)

    # Train model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, [1] * len(X_train))  # Assume all payloads are malicious (label = 1)

    # Save the trained model
    os.makedirs('models', exist_ok=True)
    with open('models/payload_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Model trained and saved as 'payload_model.pkl'")

if __name__ == "__main__":
    train_model('./data/payload.csv')


