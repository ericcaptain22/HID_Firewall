# File: scripts/malicious_input_engine.py
import pickle
import sys
import re
import os
import numpy as np
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.feature_extraction.text import TfidfVectorizer
from tensorflow.keras.models import load_model

# Dynamically add the models directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_base_dir = os.path.abspath(os.path.join(current_dir, '..'))
models_dir = os.path.join(project_base_dir, 'models')

if models_dir not in sys.path:
    sys.path.append(models_dir)

# Import functions from train_payload_model from scripts 
from train_payload_model import read_file_content, preprocess_content

# Malicious patterns for regex matching
MALICIOUS_PATTERNS = [
    re.compile(r'echo\s+bad', re.IGNORECASE),
    re.compile(r'rm\s+-rf\s+/', re.IGNORECASE),
    re.compile(r'dd\s+if=/dev/zero', re.IGNORECASE),
]

# LSTM parameters
MAX_SEQUENCE_LENGTH = 100

def generate_ngrams(command, n=2):
    """Generate n-grams from a command string."""
    tokens = command.split()
    return [" ".join(tokens[i:i+n]) for i in range(len(tokens)-n+1)] if len(tokens) >= n else [command]

def is_malicious_regex(keystroke):
    """
    Check if the keystroke matches any known malicious patterns using regex.
    """
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(keystroke):
            return True
    return False

def load_keystroke_model():
    """Load the trained keystroke model."""
    with open(os.path.join(models_dir, 'keystroke_model.pkl'), 'rb') as model_file:
        vectorizer, clf = pickle.load(model_file)
    return vectorizer, clf

def load_payload_model_rf():
    """Load the Random Forest payload model."""
    with open(os.path.join(models_dir, 'rf_payload_model.pkl'), 'rb') as model_file:
        vectorizer, clf = pickle.load(model_file)
    return vectorizer, clf

def load_payload_model_lstm():
    """Load the LSTM payload model and tokenizer."""
    model = load_model(os.path.join(models_dir, 'lstm_payload_model.h5'))
    with open(os.path.join(models_dir, 'tokenizer.pkl'), 'rb') as tokenizer_file:
        tokenizer = pickle.load(tokenizer_file)
    return model, tokenizer

def analyze_keystroke(command, vectorizer, clf):
    """Analyze a command using Random Forest to check if it is malicious."""
    ngrams = generate_ngrams(command)
    for ngram in ngrams:
        X_test = vectorizer.transform([ngram])
        prediction = clf.predict(X_test)
        if prediction[0] == 1:
            print(f"Keystroke Analysis - Malicious n-gram: {ngram}")
            return True
    print(f"Keystroke Analysis - Command: {command}, Prediction: Benign")
    return False

def analyze_payload_rf(filepath, vectorizer, clf):
    """Analyze a payload using Random Forest to check if it is malicious."""
    try:
        content = preprocess_content(read_file_content(filepath))
        X_test = vectorizer.transform([content])
        prediction = clf.predict(X_test)
        return prediction[0] == 1
    except Exception as e:
        print(f"Error analyzing payload {filepath} with Random Forest: {e}")
        return False

def analyze_payload_lstm(filepath, model, tokenizer):
    """Analyze a payload using LSTM to check if it is malicious."""
    try:
        content = preprocess_content(read_file_content(filepath))
        if not content.strip():
            return False

        # Tokenize and pad the content
        sequences = tokenizer.texts_to_sequences([content])
        padded_sequences = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH, padding='post', truncating='post')

        # Predict
        prediction = model.predict(padded_sequences)
        is_malicious = prediction[0][0] > 0.5
        return is_malicious
    except Exception as e:
        print(f"Error analyzing payload {filepath} with LSTM: {e}")
        return False
    

def analyze_keystroke_partial(command, vectorizer, clf):
    """
    Analyze a command, including its substrings (n-grams), to check if it's malicious.
    """
    ngrams = generate_ngrams(command)
    is_malicious = False  # Track if any n-gram is malicious

    print(f"Keystroke Analysis - Command: {command}, Prediction: ", end="")
    for ngram in ngrams:
        X_test = vectorizer.transform([ngram])
        prediction = clf.predict(X_test)
        
        if prediction[0] == 1:  # Malicious
            print(f"Malicious n-gram: {ngram}")
            is_malicious = True
            break  # Stop at the first malicious match
    if is_malicious:
        print(f"Malicious command detected: {command}")
    else:
        print("Benign")
    return is_malicious


# Example usage
if __name__ == "__main__":
    # Load models
    keystroke_vectorizer, keystroke_clf = load_keystroke_model()
    rf_vectorizer, rf_clf = load_payload_model_rf()
    lstm_model, lstm_tokenizer = load_payload_model_lstm()

    # Example commands and filepaths
    commands = ["chmod +x bad_script.sh", "chmod +x", "ls -la"]
    filepaths = ["/tmp/malicious.sh", "/usr/bin/legit"]

    print("\n--- Keystroke Analysis ---")
    for command in commands:
        if analyze_keystroke(command, keystroke_vectorizer, keystroke_clf):
            print(f"Malicious command detected: {command}")
        else:
            print(f"Command is benign: {command}")

    print("\n--- Payload Analysis (Random Forest) ---")
    for filepath in filepaths:
        if analyze_payload_rf(filepath, rf_vectorizer, rf_clf):
            print(f"Malicious file detected (RF): {filepath}")
        else:
            print(f"File is benign (RF): {filepath}")

    print("\n--- Payload Analysis (LSTM) ---")
    for filepath in filepaths:
        if analyze_payload_lstm(filepath, lstm_model, lstm_tokenizer):
            print(f"Malicious file detected (LSTM): {filepath}")
        else:
            print(f"File is benign (LSTM): {filepath}")
