import os
import pandas as pd

# Load the dataset
payload_file = './data/payload.csv'  # Path to payload.csv
df = pd.read_csv(payload_file)

# Print a few file paths
print(df['filepath'].head())

# Base directory of your project
base_dir = './data'

# Check if the files exist
df['exists'] = df['filepath'].apply(lambda x: os.path.exists(os.path.join(base_dir, x)))
print(df[['filepath', 'exists']])
