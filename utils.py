import json
import os

def load_configuration(file_path):
    if not os.path.exists(file_path):
        print(f"Configuration file not found at {file_path}.")
        print("Please provide a configuration file or pass necessary parameters via command-line arguments.")
        exit(1)

    with open(file_path, 'r') as file:
        config = json.load(file)
    return config
