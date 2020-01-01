from typing import Any
import json
from os.path import expanduser

# simple utility to load a JSON file by name
def load_json(filename: str) -> Any:
    with open(filename, 'r') as f:
        data_raw = f.read()
    data_json = json.loads(data_raw)
    return data_json

def load_user_data() -> Any:
    filename = expanduser('~/.config/Bitwarden CLI/data.json')
    return load_json(filename)
