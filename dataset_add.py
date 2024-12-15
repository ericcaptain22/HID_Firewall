import os
import pandas as pd

# Step 1: Specify the root directory of the payloads folder
payloads_dir = 'data/payloads'

# Step 2: Get the list of all files in the payloads directory and its subdirectories
file_paths = []
for root, _, files in os.walk(payloads_dir):
    for file in files:
        relative_path = os.path.relpath(os.path.join(root, file), start='data')
        file_paths.append(relative_path)  # Store the relative path relative to the 'data/' folder

# Step 3: Create a DataFrame with a single column for file paths
df = pd.DataFrame({'filepath': file_paths})

# Step 4: Save the DataFrame as payload.csv in the 'data' folder
output_path = 'data/payload.csv'
df.to_csv(output_path, index=False)

print(f"Successfully created {output_path} with {len(file_paths)} file paths from {payloads_dir}.")
