import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pickle
import os

def train_keystroke_model(keystroke_file):
    # Load the dataset
    df = pd.read_csv(keystroke_file)

    # Ensure no NaN values
    df = df.dropna(subset=['command', 'label'])
    X, y = df['command'].astype(str), df['label']

    # Split dataset
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorize commands
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)

    # Train model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, y_train)

    # Save the model
    os.makedirs('models', exist_ok=True)
    with open('models/keystroke_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Keystroke model trained and saved as 'keystroke_model.pkl'")

if __name__ == "__main__":
    train_keystroke_model('./data/keystrokes.csv')
