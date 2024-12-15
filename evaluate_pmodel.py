import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
import pickle

from models.train_payload_model import read_file_content, preprocess_content

def load_payload_data(payload_file):
    """Load payload data and extract file contents."""
    df = pd.read_csv(payload_file)

    # Read file contents and preprocess them
    df['content'] = df['filepath'].apply(read_file_content).apply(preprocess_content)

    # Ensure no empty or NaN content
    df = df.dropna(subset=['content'])
    df = df[df['content'].str.strip() != ""]

    X = df['content']
    y = [1] * len(df)  # All file contents are assumed malicious
    return X, y

def evaluate_payload_model(file_path):
    """Evaluate the payload classification model."""
    # Load dataset
    df = pd.read_csv(file_path)
    X = df['filepath']  # Extract file paths
    y = [1] * len(df)   # All payloads in the dataset are malicious (label = 1)

    # Split dataset into training and testing
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorize file paths
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)

    # Train model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, y_train)

    # Predict on test data
    y_pred = clf.predict(X_test_vectorized)

    # Evaluate performance
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Payload Model Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    # Save the trained model
    with open('models/payload_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Payload model re-trained and saved as 'payload_model.pkl'")

if __name__ == "__main__":
    evaluate_payload_model('./data/payload.csv')
