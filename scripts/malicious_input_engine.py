# File: scripts/malicious_input_engine.py
import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier

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

def load_trained_model():
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

def is_malicious_ml(keystroke, vectorizer, clf):
    """
    Check if the keystroke is malicious using a machine learning model.
    """
    X_test = vectorizer.transform([keystroke])
    prediction = clf.predict(X_test)
    return prediction[0] == 1

def analyze_keystroke(keystroke, vectorizer, clf):
    """
    Analyze the keystroke to determine if it is malicious using both regex and ML.
    """
    if is_malicious_regex(keystroke):
        return True
    if is_malicious_ml(keystroke, vectorizer, clf):
        return True
    return False

if __name__ == "__main__":
    # Load the trained model and vectorizer
    vectorizer, clf = load_trained_model()

    # Example usage
    test_keystrokes = ["echo bad", "ls -la", "rm -rf /", "cat /etc/passwd", "dd if=/dev/zero"]
    for keystroke in test_keystrokes:
        if analyze_keystroke(keystroke, vectorizer, clf):
            print(f"Malicious keystroke detected: {keystroke}")
        else:
            print(f"Keystroke is safe: {keystroke}")
