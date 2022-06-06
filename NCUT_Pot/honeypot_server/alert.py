from .send_mail import send_mail
from .send_sms import send_sms
import time
import threading
from NCUT_Pot.database import get_config_value, get_phone_numbers, get_mail_addresses


def alert(ip, honeypot_type):
    params = [
        ip,
        honeypot_type,
        time.strftime("%m/%d-%H:%M", time.localtime()),
    ]
    if get_config_value("send_sms") == True:
        numbers = get_phone_numbers()
        threading.Thread(target=send_sms, args=(numbers, params)).start()
    if get_config_value("send_mail") == True:
        mails = get_mail_addresses()
        threading.Thread(target=send_mail, args=(mails, params)).start()


def start_alert(ip, honeypot_type):
    threading.Thread(
        target=alert,
        args=(
            ip,
            honeypot_type,
        ),
    ).start()
