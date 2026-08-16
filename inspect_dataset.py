import pandas as pd

DATASET_PATH = "data/phiusiil+phishing+url+dataset/phishing_dataset.csv"

df = pd.read_csv(DATASET_PATH)

print("\n========== DATASET SHAPE ==========")
print(df.shape)

print("\n========== COLUMN NAMES ==========")
for column in df.columns:
    print(column)

print("\n========== DATA TYPES ==========")
print(df.dtypes)

print("\n========== MISSING VALUES ==========")
print(df.isnull().sum())

print("\n========== DUPLICATE ROWS ==========")
print(df.duplicated().sum())

print("\n========== LABEL DISTRIBUTION ==========")
print(df["label"].value_counts())

print("\n========== LABEL PERCENTAGE ==========")
print(df["label"].value_counts(normalize=True) * 100)

print("\n========== SAMPLE URLs ==========")
print(df["URL"].head(10).to_string(index=False))