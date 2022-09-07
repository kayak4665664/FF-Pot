import json
import os


def get_state(honeypot):
    """Get the statu of the honeypot from json."""
    json_path = os.path.abspath(os.path.dirname(__file__)) + "/state_of_honeypots.json"
    with open(json_path, "r") as input:
        return json.load(input)[honeypot]


def set_state(honeypot, state):
    """Set the state of the honeypot and save it to json."""
    json_path = os.path.abspath(os.path.dirname(__file__)) + "/state_of_honeypots.json"
    params = {}
    with open(json_path, "r") as input:
        params = json.load(input)
    params[honeypot] = state
    with open(json_path, "w") as output:
        json.dump(params, output)


def init_state_of_honeypots():
    """Initialize json."""
    json_path = os.path.abspath(os.path.dirname(__file__)) + "/state_of_honeypots.json"
    with open(json_path, "w") as output:
        params = {"Telnet": False, "SSH": False}
        json.dump(params, output)
