
import os
import json
import logging
from typing import Any

def load_json_file(filename: str, default: Any) -> Any:
    """Load JSON file with error handling and default value."""
    try:
        if not os.path.exists(filename):
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as file:
                json.dump(default, file, indent=4, ensure_ascii=False)
            return default
            
        with open(filename, 'r', encoding='utf-8') as file:
            data = json.load(file)
            if not data and default:
                return default
            return data
    except Exception as e:
        logging.error(f"Error loading JSON file {filename}: {str(e)}")
        return default

def save_json_file(data: Any, filename: str) -> bool:
    """Save data to JSON file with error handling."""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        logging.error(f"Error saving JSON file {filename}: {str(e)}")
        return False

def load_json_file_with_retry(filename: str, default: Any, retries: int = 3) -> Any:
    last_error = None
    for attempt in range(retries):
        try:
            return load_json_file(filename, default)
        except Exception as e:
            last_error = e
            if attempt < retries - 1:
                logging.warning(f"Retry {attempt + 1}/{retries} loading {filename}")
                continue
    logging.error(f"Failed to load {filename} after {retries} attempts: {str(last_error)}")
    return default
