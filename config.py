import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / 'config.json'

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

config = load_config()
