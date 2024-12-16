# File: scripts/malicious_input_engine.py
import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from models.train_payload_model import read_file_content, preprocess_content

# Malicious patterns for regex matching
MALICIOUS_PATTERNS = [
    re.compile(r'echo\s+bad', re.IGNORECASE),
    re.compile(r'rm\s+-rf\s+/', re.IGNORECASE),
    re.compile(r'dd\s+if=/dev/zero', re.IGNORECASE),
]

def is_malicious_regex(keystroke):
    """
    Check if the keystroke matches any known malicious patterns using regex.
    """
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(keystroke):
            return True
    return False

#def load_trained_model():
    """
    Load the trained model and vectorizer from 'keystroke_model.pkl'.
    """
    try:
        with open('models/models/keystroke_model.pkl', 'rb') as model_file:
            vectorizer, clf = pickle.load(model_file)
        print("Random Forest Model successfully loaded.")
        return vectorizer, clf
    except FileNotFoundError:
        print("Error: The trained Random Forest model 'keystroke_model.pkl' was not found. Please train the model first.")
        exit(1)


def load_keystroke_model():
    """Load the trained keystroke model."""
    with open('models/keystroke_model.pkl', 'rb') as model_file:
        vectorizer, clf = pickle.load(model_file)
    return vectorizer, clf

def load_payload_model():
    """Load the trained payload model."""
    with open('models/payload_model.pkl', 'rb') as model_file:
        vectorizer, clf = pickle.load(model_file)
    return vectorizer, clf

def analyze_keystroke(command, vectorizer, clf):
    """Analyze a command to check if it is malicious."""
    X_test = vectorizer.transform([command])
    prediction = clf.predict(X_test)
    print(f"Keystroke Analysis - Command: {command}, Prediction: {'Malicious' if prediction[0] == 1 else 'Benign'}")
    return prediction[0] == 1

def analyze_payload(filepath, vectorizer, clf):
    """Analyze a file path to check if it is malicious."""
    try:
        content = preprocess_content(read_file_content(filepath))
        X_test = vectorizer.transform([content])
        prediction = clf.predict(X_test)
        return prediction[0] == 1
    except Exception as e:
        print(f"Error analyzing payload {filepath}: {e}")
        return False

def is_malicious_ml(keystroke, vectorizer, clf):
    """
    Check if the keystroke is malicious using a machine learning model.
    """
    X_test = vectorizer.transform([keystroke])
    prediction = clf.predict(X_test)
    return prediction[0] == 1


# Example usage
if __name__ == "__main__":
    keystroke_vectorizer, keystroke_clf = load_keystroke_model()
    payload_vectorizer, payload_clf = load_payload_model()

    # Example keystroke and payload analysis
    commands = ["ls -la", "rm -rf /"]
    filepaths = ["/tmp/malicious.sh", "/usr/bin/legit"]

    for command in commands:
        if analyze_keystroke(command, keystroke_vectorizer, keystroke_clf):
            print(f"Malicious command detected: {command}")
        else:
            print(f"Command is benign: {command}")

    for filepath in filepaths:
        if analyze_payload(filepath, payload_vectorizer, payload_clf):
            print(f"Malicious file detected: {filepath}")
        else:
            print(f"File is benign: {filepath}")






