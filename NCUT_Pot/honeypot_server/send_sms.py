import subprocess
from NCUT_Pot.database import get_config_value, start_adding_honeypots_log


def send_sms(numbers, params):
    """Send SMS using twilio's API."""
    sms_number = get_config_value("sms_number")
    sms_sid = get_config_value("sms_sid")
    sms_token = get_config_value("sms_token")
    for number in numbers:
        message = "Warn! {0} connected to the {1} honeypot at {2}.".format(
            params[0], params[1], params[2]
        )
        subprocess.call(
            'curl -X POST https://api.twilio.com/2010-04-01/Accounts/AC0ae9b7c192f646cbb7c4216546437237/Messages.json \
                --data-urlencode "Body='
            + message
            + '" \
                --data-urlencode "From='
            + sms_number
            + '" \
                --data-urlencode "To='
            + number
            + '" \
                -u '
            + sms_sid
            + ":"
            + sms_token,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )
        start_adding_honeypots_log("SMS", "Try sending a message to " + number + ".")
