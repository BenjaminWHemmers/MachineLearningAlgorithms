import pandas as pd
from sklearn.model_selection import train_test_split
import numpy as np
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

if __name__ == "__main__":
    print("Running neuralNetwork.py...")



    # PART 1 - READING AND PREPROCESSING DATA

    # Define the path to your pcap spreadsheet file
    #file_path = 'MachineLearningCSV/MachineLearningCVE/Wednesday-workingHours.pcap_ISCX.csv'
    file_path = 'Wednesday-workingHours.pcap_ISCX.csv'

    # Read data from the pcap spreadsheet file
    try:
        data = pd.read_csv(file_path)

        # Step 2: Parse the specified columns. These data types will be analyzed for suspicious DoS/Heartbleed features.
        selected_columnsDOS = [" Flow Duration", " Bwd Packet Length Std", "Active Mean", " Flow IAT Std", " Label"]
        selected_columnsHeartbleed = [" Bwd Packet Length Std", " Subflow Fwd Bytes", " Flow Duration", "Total Length of Fwd Packets", " Label"]
        parsed_dataDOS = data[selected_columnsDOS]
        parsed_dataHeartbleed = data[selected_columnsHeartbleed]

        # Display the parsed data
        print(parsed_dataDOS)
        print(parsed_dataHeartbleed)

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    


    # STEP 2 - SPLIT THE DATA INTO TRAINING AND TESTING SETS

    # Define the feature columns (excluding the label column)
    feature_columns = [" Flow Duration", " Bwd Packet Length Std", "Active Mean", " Flow IAT Std", " Subflow Fwd Bytes", "Total Length of Fwd Packets"]

    # Define the target column (label)
    target_column = " Label"

    # Split the data into features (X) and labels (y)
    X = data[feature_columns]
    y = data[target_column]

    # Split the data into training and testing sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Convert string labels to numeric values
    y_train = y_train.map({'DoS Hulk': 1, 'DoS GoldenEye': 1, 'DoS Slowhttptest': 1, 'DoS slowloris': 1, 'Heartbleed': 1, 'BENIGN': 0})
    y_test = y_test.map({'DoS Hulk': 1, 'DoS GoldenEye': 1, 'DoS Slowhttptest': 1, 'DoS slowloris': 1, 'Heartbleed': 1, 'BENIGN': 0})

    # Display the shapes of the training and testing sets
    print("Training data shape:", X_train.shape)
    print("Testing data shape:", X_test.shape)



    # STEP 3 - MODEL DEVELOPMENT, TRAINING, AND EVALUATION

    # Define a simple neural network model
    model = keras.Sequential([
        keras.layers.Dense(units=32, activation='relu', input_dim=X_train.shape[1]),
        keras.layers.Dense(units=16, activation='relu'),
        keras.layers.Dense(units=1, activation='sigmoid')
    ])

    # Compile the model
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Train the model
    model.fit(X_train, y_train, epochs=10, batch_size=32, validation_split=0.2)

    # Evaluate the model on the testing set
    y_pred = model.predict(X_test)
    y_pred_binary = (y_pred > 0.5).astype(int)

    # Print evaluation metrics
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred_binary))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred_binary))