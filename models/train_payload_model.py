import os
import pandas as pd
import numpy as np
from tensorflow.keras.models import Sequential, load_model, Model
from tensorflow.keras.layers import Input, Dense, LSTM, Dense, Embedding, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle

# Define the base directory of your project
BASE_DIR = './data'  # Adjust to the actual base directory if needed

def read_file_content(filepath):
    """Read the content of a file given its filepath."""
    try:
        full_path = os.path.join(BASE_DIR, filepath)
        with open(full_path, 'r', encoding='utf-8') as file:
            return file.read()
    except UnicodeDecodeError:
        print(f"Skipping binary file: {filepath}")
        return None
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return None


def analyze_payload_lstm(filepath, lstm_model, tokenizer):
    """Analyze a file's content using the LSTM model."""
    try:
        content = read_file_content(filepath)
        processed_content = preprocess_content(content)
        sequence = tokenizer.texts_to_sequences([processed_content])
        padded_sequence = pad_sequences(sequence, maxlen=100, padding='post', truncating='post')
        prediction = lstm_model.predict(padded_sequence)
        return prediction[0][0] > 0.5  # Threshold for malicious detection
    except Exception as e:
        print(f"Error analyzing file with LSTM: {e}")
        return False

def analyze_payload_rf(filepath, vectorizer, clf):
    """Analyze a file's content using the Random Forest model."""
    try:
        content = read_file_content(filepath)
        processed_content = preprocess_content(content)
        X_test = vectorizer.transform([processed_content])
        prediction = clf.predict(X_test)
        return prediction[0] == 1
    except Exception as e:
        print(f"Error analyzing file with Random Forest: {e}")
        return False

def preprocess_content(content):
    """Preprocess the file content by removing unnecessary text (e.g., comments)."""
    if content is None:
        return None
    lines = content.splitlines()
    processed_lines = [line for line in lines if not line.strip().startswith("REM")]
    return " ".join(processed_lines)

def load_payload_data(payload_file):
    """Load payload data and extract file contents."""
    df = pd.read_csv(payload_file)

    # Read and preprocess file contents
    df['content'] = df['filepath'].apply(read_file_content).apply(preprocess_content)

    # Remove rows with missing or empty content
    df = df.dropna(subset=['content'])
    df = df[df['content'].str.strip() != ""]

    return df

def prepare_lstm_data(df):
    """Prepare data for LSTM training."""
    tokenizer = Tokenizer(num_words=5000, oov_token='<OOV>')
    tokenizer.fit_on_texts(df['content'])

    # Convert text to sequences and pad them
    sequences = tokenizer.texts_to_sequences(df['content'])
    padded_sequences = pad_sequences(sequences, maxlen=100, padding='post', truncating='post')
    labels = [1] * len(padded_sequences)  # Label all payloads as malicious
    return padded_sequences, labels, tokenizer

def train_lstm_model(X, y):
    """Train LSTM model."""
    # Define LSTM model
    model = Sequential([
        Embedding(input_dim=5000, output_dim=128),
        Bidirectional(LSTM(64, return_sequences=False)),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Train the model
    model.fit(X, np.array(y), epochs=10, batch_size=32, validation_split=0.2)
    return model

def prepare_rf_data(df):
    """Prepare data for Random Forest training."""
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X = vectorizer.fit_transform(df['content'])
    y = [1] * X.shape[0]  # Label all payloads as malicious
    return X, y, vectorizer

def train_rf_model(X, y):
    """Train Random Forest model."""
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf

if __name__ == "__main__":
    payload_file = './data/payload.csv'

    # Load and preprocess the data
    print("Loading and preprocessing data...")
    df = load_payload_data(payload_file)

    # Train LSTM Model
    print("Training LSTM model...")
    X_lstm, y_lstm, tokenizer = prepare_lstm_data(df)
    lstm_model = train_lstm_model(X_lstm, y_lstm)

    # Save the LSTM model and tokenizer
    os.makedirs('models', exist_ok=True)
    lstm_model.save('models/lstm_payload_model.keras')
    with open('models/tokenizer.pkl', 'wb') as f:
        pickle.dump(tokenizer, f)
    print("LSTM model and tokenizer saved.")

    # Train Random Forest Model
    print("Training Random Forest model...")
    X_rf, y_rf, vectorizer = prepare_rf_data(df)
    rf_model = train_rf_model(X_rf, y_rf)

    # Save the Random Forest model
    with open('models/rf_payload_model.pkl', 'wb') as f:
        pickle.dump((vectorizer, rf_model), f)
    print("Random Forest model saved as 'rf_payload_model.pkl'.")
