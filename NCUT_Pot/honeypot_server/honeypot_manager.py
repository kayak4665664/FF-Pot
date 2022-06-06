import gevent, gevent.server
from .telnet_honeypot import TelnetHoneypot
from .ssh_honeypot import SSHHoneypot
from .state_of_honeypots import set_state
from NCUT_Pot.database import get_config_value, start_adding_honeypots_log
import threading


TELNET_HONEYPOT = gevent.server.StreamServer
SSH_HONEYPOT = gevent.server.StreamServer


def telnet_honeypot_server():
    port = get_config_value("telnet_honeypot_port")
    global TELNET_HONEYPOT
    TELNET_HONEYPOT = gevent.server.StreamServer(
        (
            "0.0.0.0",
            port,
        ),
        TelnetHoneypot.streamserver_handle,
    )
    start_adding_honeypots_log("Telnet", "Start server at port " + str(port) + ".")
    try:
        TELNET_HONEYPOT.serve_forever()
    except OSError:
        start_adding_honeypots_log("Telnet", "Port " + str(port) + "is unavailable.")
        set_state("Telnet", False)
    except:
        start_adding_honeypots_log("Telnet", "Server shut down.")
        set_state("Telnet", False)


def ssh_honeypot_server():
    port = get_config_value("ssh_honeypot_port")
    global SSH_HONEYPOT
    SSH_HONEYPOT = gevent.server.StreamServer(
        (
            "0.0.0.0",
            port,
        ),
        SSHHoneypot.streamserver_handle,
    )
    start_adding_honeypots_log("SSH", "Start server at port " + str(port) + ".")
    try:
        SSH_HONEYPOT.serve_forever()
    except OSError:
        start_adding_honeypots_log("SSH", "Port " + str(port) + "is unavailable.")
        set_state("SSH", False)
    except:
        start_adding_honeypots_log("SSH", "Server shut down.")
        set_state("SSH", False)


def start_telnet_honeypot():
    set_state("Telnet", True)
    threading.Thread(target=telnet_honeypot_server).start()


def start_ssh_honeypot():
    set_state("SSH", True)
    threading.Thread(target=ssh_honeypot_server).start()


def terminate_telnet_honeypot():
    global TELNET_HONEYPOT
    TELNET_HONEYPOT.stop()
    start_adding_honeypots_log("Telnet", "Server shut down.")
    set_state("Telnet", False)


def terminate_ssh_honeypot():
    global SSH_HONEYPOT
    SSH_HONEYPOT.stop()
    start_adding_honeypots_log("SSH", "Server shut down.")
    set_state("SSH", False)
