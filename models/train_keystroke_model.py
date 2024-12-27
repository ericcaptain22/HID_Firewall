import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
import pickle
import os
import sys

# Add the project base directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_base_dir = os.path.abspath(os.path.join(current_dir, '..'))
if project_base_dir not in sys.path:
    sys.path.append(project_base_dir)

from scripts.keystroke_interception import preprocess_command

def generate_ngrams(command, n=2):
    """Generate n-grams from a command string."""
    tokens = command.split()
    return [" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)] if len(tokens) >= n else [command]

def preprocess_keystroke_data(df):
    """Preprocess keystroke data to include n-grams."""
    df['command'] = df['command'].apply(preprocess_command)
    df['ngrams'] = df['command'].apply(lambda cmd: generate_ngrams(cmd, n=2))
    df = df.explode('ngrams')  # Expand the n-grams into separate rows
    df = df.dropna(subset=['ngrams', 'label'])  # Remove rows with NaN values
    return df

def tune_model(X_train, y_train, vectorizer):
    """
    Perform hyperparameter tuning using GridSearchCV on RandomForestClassifier.
    """
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_depth': [None, 10, 20, 30],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
    }
    rf = RandomForestClassifier(random_state=42)
    grid_search = GridSearchCV(rf, param_grid, cv=3, scoring='accuracy', verbose=2, n_jobs=-1)
    grid_search.fit(vectorizer.transform(X_train), y_train)
    print(f"Best Parameters: {grid_search.best_params_}")
    return grid_search.best_estimator_

def train_keystroke_model(keystroke_file):
    """
    Train the keystroke detection model with hyperparameter tuning.
    """
    # Load the dataset
    df = pd.read_csv(keystroke_file)

    # Preprocess dataset to include n-grams
    df = preprocess_keystroke_data(df)
    X, y = df['ngrams'].astype(str), df['label']

    # Split dataset
    X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorize commands using n-grams
    vectorizer = TfidfVectorizer(ngram_range=(1, 2))  # Includes unigrams and bigrams
    vectorizer.fit(X_train)

    # Tune the Random Forest model
    clf = tune_model(X_train, y_train, vectorizer)

    # Save the model
    os.makedirs('models', exist_ok=True)
    with open('models/keystroke_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Keystroke model trained and saved as 'keystroke_model.pkl'")

if __name__ == "__main__":
    train_keystroke_model('./data/keystrokes.csv')
