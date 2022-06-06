#!/usr/bin/env python
from gevent import monkey
monkey.patch_all()
from NCUT_Pot.honeypot_server.state_of_honeypots import init_state_of_honeypots

"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'NCUT_Pot.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':

    init_state_of_honeypots() # Initialize the state of honeypots

    main()
