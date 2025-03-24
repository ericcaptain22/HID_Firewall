import pandas as pd

# Load the dataset
dataset_path = '/home/ericcaptain22/Downloads/uci_malware_detection.csv'
df = pd.read_csv(dataset_path)

# Add a simulated filepath column
df['filepath'] = [f"/synthetic/path/file_{i}.exe" for i in range(len(df))]

# Save the dataset with filepaths
df.to_csv('uci_malware_with_filepaths.csv', index=False)
