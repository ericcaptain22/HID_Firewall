import pandas as pd

# Step 1: Load the CSV file into a DataFrame
df = pd.read_csv('/home/ericcaptain22/Documents/MSc Project/HID-F/data/payload.csv')

# Step 2: Define the list of extensions and filenames to exclude
exclude_files = {".png", ".jpg", ".gif", "README.md"}

# Step 3: Filter the DataFrame based on the condition that the file path does not end with the specified extensions or filenames
filtered_df = df[~df['filepath'].apply(lambda path: any(path.endswith(ext) for ext in exclude_files))]

# Step 4: Save the filtered DataFrame back to a new CSV
filtered_df.to_csv('filtered_payload.csv', index=False)

print("Filtered data saved to 'filtered_payload.csv'")
