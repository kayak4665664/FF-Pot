from .ssh_handler import SSHHandler, getRsaKeyFile
from .telnet_honeypot import TelnetHoneypot
import random
from NCUT_Pot.database import get_usernames, get_passwords


class SSHHoneypot(SSHHandler):
    telnet_handler = TelnetHoneypot
    # Create or open the server key file
    host_key = getRsaKeyFile("server_rsa.key")

    def authCallbackUsername(self, username):
        raise

    def authCallback(self, username, password):
        """Called to validate the username/password."""
        self.telnet_handler.honeypot_type = "SSH"
        usernames = get_usernames()
        if username not in usernames:
            # complain by raising any exception
            raise
        count = int(0)
        wrong_passwords = []
        passwords = get_passwords()
        while True:
            count += 1
            if password in passwords:
                break
            elif (
                password not in wrong_passwords
                and len(password) > 4
                and random.randint(0, 3) != 0
            ):
                break
            elif count == 3:
                raise
            else:
                wrong_passwords.append(password)
                password = self.telnet_handler.readline(
                    prompt="Permission denied, please try again.\nPassword: ",
                    echo=False,
                    use_history=False,
                )
        self.telnet_handler.password = password