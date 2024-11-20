import re
import pickle
from sklearn.feature_extraction.text import CountVectorizer
#rom sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import os


# Load the dataset from CSV
def load_data_from_csv(csv_file):
    try:
        df = pd.read_csv(csv_file)
        return df['command'], df['label']
    except FileNotFoundError:
        print(f"Error: The file {csv_file} was not found.")
        exit(1)

 
def preprocess_data(data):
    # Here we can add more preprocessing steps if needed
    X, y = zip(*data)
    return X, y

def train_model(csv_file):
    # Load dataset from CSV
    X_train, y_train = load_data_from_csv(csv_file)
    
    # Initialize vectorizer and transform data
    vectorizer = CountVectorizer()
    X_train_vectorized = vectorizer.fit_transform(X_train)
    
    # Initialize and train the classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, y_train)

    # Ensure the models directory exists
    os.makedirs('models', exist_ok=True)
    
    # Save the trained model and vectorizer
    with open('models/keystroke_model.pkl', 'wb') as model_file:
        pickle.dump((vectorizer, clf), model_file)
    print("Model trained and saved as 'models/keystroke_model.pkl'")

if __name__ == "__main__":
    # Ensure the correct path to the CSV file
    train_model('./data/keystrokes.csv')
