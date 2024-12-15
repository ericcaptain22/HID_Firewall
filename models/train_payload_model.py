import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os

# Define the base directory of your project
BASE_DIR = './data'  # Adjust to the actual base directory if needed

def read_file_content(filepath):
    """Read the content of a file given its filepath."""
    try:
        # Resolve relative paths to absolute paths
        full_path = os.path.join(BASE_DIR, filepath)
        with open(full_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return None

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

    X = df['content']
    y = [1] * len(df)  # Assume all file contents are malicious
    return X, y

def train_payload_model(payload_file):
    # Load dataset
    X, y = load_payload_data(payload_file)

    # Split dataset
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorize file contents
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)

    # Train the model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, y_train)

    # Save the model
    os.makedirs('models', exist_ok=True)
    with open('models/payload_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Payload model trained using file contents and saved as 'payload_model.pkl'")

if __name__ == "__main__":
    train_payload_model('./data/payload.csv')
