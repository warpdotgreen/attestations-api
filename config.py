import json

CONFIG_PATH = 'config.json'

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

config = load_config()
