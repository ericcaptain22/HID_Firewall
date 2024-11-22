from sklearn.feature_extraction.text import TfidfVectorizer
# from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

import pandas as pd

def evaluate_model(csv_file):
    # Load dataset
    df = pd.read_csv(csv_file)
    X = df['command']  # Features
    y = df['label']    # Labels

    # Split the dataset into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Vectorize the text data
    vectorizer = TfidfVectorizer()
    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)

    # Train the model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_vectorized, y_train)

    # Make predictions on the test set
    y_pred = clf.predict(X_test_vectorized)

    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")
    
    #Precision, Recall, F1-score
    print(classification_report(y_test, y_pred))
    
    #Confusion Metrics
    print(confusion_matrix(y_test, y_pred))



if __name__ == "__main__":
    # Evaluate the model using the dataset
    evaluate_model('./data/keystrokes.csv')
