import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import pickle
import os

# Load Kaggle dataset
def load_and_preprocess_kaggle_dataset(file_path):
    # Load dataset
    data = pd.read_csv(file_path)

    # Check for missing values and handle them
    data.dropna(inplace=True)

    # Ensure correct column name for labels
    target_column = "Label"  # Change this to the actual column name for labels
    if target_column not in data.columns:
        raise KeyError(f"Target column '{target_column}' not found in the dataset. Available columns: {list(data.columns)}")

    # Convert labels to numeric if necessary
    label_encoder = LabelEncoder()
    data[target_column] = label_encoder.fit_transform(data[target_column])  # Convert 'non-malicious' to 0, 'malicious' to 1

    # Separate features and labels
    X = data.drop(columns=[target_column])  # All feature columns
    y = data[target_column]  # Target column

    # Keep only numeric columns in X
    X = X.select_dtypes(include=['number'])

    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y

# Train Random Forest model
def train_kaggle_model(X, y):
    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train Random Forest model
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_clf.fit(X_train, y_train)

    # Evaluate on the test set
    y_pred = rf_clf.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Save the trained model
    os.makedirs('models', exist_ok=True)
    with open('models/kaggle_payload_model.pkl', 'wb') as model_file:
        pickle.dump(rf_clf, model_file)

    print("Kaggle model trained and saved as 'models/kaggle_payload_model.pkl'")

if __name__ == "__main__":
    # Path to Kaggle dataset
    file_path = './data/uci_malware.csv'
    X, y = load_and_preprocess_kaggle_dataset(file_path)
    train_kaggle_model(X, y)
