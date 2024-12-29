import pickle
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

def load_and_preprocess_kaggle_dataset(file_path):
    """
    Load and preprocess the Kaggle dataset for evaluation.
    """
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

def evaluate_kaggle_model(model_path, file_path):
    """
    Evaluate the Kaggle model on the dataset and display metrics.
    """
    # Load the trained model
    with open(model_path, 'rb') as model_file:
        model = pickle.load(model_file)

    # Load and preprocess the dataset
    X, y = load_and_preprocess_kaggle_dataset(file_path)

    # Split into train and test sets (evaluation on test set)
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Predict on the test set
    y_pred = model.predict(X_test)

    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)

    print(f"Accuracy: {accuracy:.2f}")
    print("\nClassification Report:")
    print(report)

if __name__ == "__main__":
    # Path to the trained Kaggle model
    model_path = './models/kaggle_payload_model.pkl'

    # Path to the Kaggle dataset
    file_path = './data/uci_malware.csv'

    # Evaluate the Kaggle model
    evaluate_kaggle_model(model_path, file_path)
