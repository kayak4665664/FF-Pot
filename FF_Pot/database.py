import hashlib
import json
import os
import random
import shutil
import string
import urllib.request
import ipaddress
import time
import threading
from FF_Pot_Model.models import (
    Configs,
    Users,
    Hidden_paths,
    Caught,
    Replace_names,
    Honeypots_log,
    Usernames,
    Passwords,
    Connections,
    Connections_log,
    Not_allowed_commands,
    Users_log,
)
from .honeypot_server.state_of_honeypots import get_state
from django.db.models import Q, Count


def get_config_value(config_key):
    value = Configs.objects.filter(id=1).values()[0][config_key]
    if value is None:
        return "none"
    else:
        return value


def get_parameters():
    config = Configs.objects.filter(id=1).values()[0]
    telnet_honeypot_port = config["telnet_honeypot_port"]
    ssh_honeypot_port = config["ssh_honeypot_port"]
    root = config["root"]
    default_directory = config["default_directory"]
    return telnet_honeypot_port, ssh_honeypot_port, root, default_directory


class User:
    def __init__(self, user_id, user_type, phone_number, mail_address):
        self.user_id = user_id
        if user_type == True:
            self.user_type = "admin"
        else:
            self.user_type = "visitor"
        if phone_number is None:
            self.phone_number = "none"
        else:
            self.phone_number = phone_number
        if mail_address is None:
            self.mail_address = "none"
        else:
            self.mail_address = mail_address


def get_user(user_id):
    user = Users.objects.filter(user_id=user_id).values()[0]
    user_type = user["user_type"]
    phone_number = user["phone_number"]
    mail_address = user["mail_address"]
    return User(user_id, user_type, phone_number, mail_address)


def get_all_users():
    all_users = []
    for user in Users.objects.all().values():
        user_id = user["user_id"]
        user_type = user["user_type"]
        phone_number = user["phone_number"]
        mail_address = user["mail_address"]
        all_users.append(User(user_id, user_type, phone_number, mail_address))
    return all_users


def get_hidden_paths():
    return list(Hidden_paths.objects.values_list("hidden_path", flat=True))


def remove_hidden_paths():
    Hidden_paths.objects.all().delete()


def set_hidden_paths(hidden_paths):
    for hidden_path in hidden_paths:
        if Hidden_paths.objects.filter(hidden_path=hidden_path).count() == 0:
            Hidden_paths(hidden_path=hidden_path).save()


def get_phone_numbers():
    return list(
        Users.objects.all()
        .exclude(phone_number=None)
        .values_list("phone_number", flat=True)
    )


def get_mail_addresses():
    return list(
        Users.objects.all()
        .exclude(mail_address=None)
        .values_list("mail_address", flat=True)
    )


def get_salt():
    return "".join(random.sample(string.ascii_letters + string.digits, 32))


def get_md5(password, salt):
    return hashlib.md5((password + salt).encode()).hexdigest()


def get_caught_paths():
    return list(Caught.objects.values_list("path", flat=True))


def add_path_to_caught(path):
    if Caught.objects.filter(path=path).count() == 0:
        Caught(path=path).save()


def start_adding_path_to_caught(path):
    threading.Thread(target=add_path_to_caught, args=(path,)).start()


def rename_path_in_caught(source, dest):
    Caught.objects.filter(path=source).update(path=dest)


def start_renaming_path_in_caught(source, dest):
    threading.Thread(
        target=rename_path_in_caught,
        args=(
            source,
            dest,
        ),
    ).start()


def empty_caught_files():
    caught_files = get_caught_paths()
    for caught_file in caught_files:
        Caught.objects.filter(path=caught_file).delete()
        if os.path.exists(caught_file):
            if os.path.isfile(caught_file):
                os.remove(caught_file)
            elif os.path.isdir(caught_file):
                shutil.rmtree(caught_file)


def get_replace_names():
    return list(Replace_names.objects.values_list("replace_name", flat=True))


def remove_replace_names():
    Replace_names.objects.all().delete()


def set_replace_names(replace_names):
    for replace_name in replace_names:
        if Replace_names.objects.filter(replace_name=replace_name).count() == 0:
            Replace_names(replace_name=replace_name).save()


def add_honeypots_log(honeypot_type, action):
    Honeypots_log(
        time=time.strftime("%Y/%m/%d-%H:%M:%S", time.localtime()),
        honeypot_type=honeypot_type,
        action=action,
    ).save()


def start_adding_honeypots_log(honeypot_type, action):
    threading.Thread(
        target=add_honeypots_log,
        args=(
            honeypot_type,
            action,
        ),
    ).start()


def get_honeypots_log_count_by_honeypot_type(time, honeypot_type):
    return Honeypots_log.objects.filter(
        Q(time__startswith=time), honeypot_type=honeypot_type
    ).count()


class Honeypots_logs:
    def __init__(self, time, honeypot_type, action):
        self.time = time
        self.honeypot_type = honeypot_type
        self.action = action


def get_honeypots_logs():
    honeypots_logs = []
    for honeypots_log in Honeypots_log.objects.all().values():
        honeypots_logs.append(
            Honeypots_logs(
                honeypots_log["time"],
                honeypots_log["honeypot_type"],
                honeypots_log["action"],
            )
        )
    return honeypots_logs


def get_usernames():
    return list(Usernames.objects.values_list("username", flat=True))


def remove_usernames():
    Usernames.objects.all().delete()


def set_usernames(usernames):
    for username in usernames:
        if Usernames.objects.filter(username=username).count() == 0:
            Usernames(username=username).save()


def get_passwords():
    return list(Passwords.objects.values_list("password", flat=True))


def is_lan(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except:
        return False


def get_country_and_city(ip):
    if is_lan(ip):
        return "LAN", "LAN"
    else:
        try:
            req = urllib.request.Request("http://ip-api.com/json/" + ip)
            response = urllib.request.urlopen(req).read()
            json_response = json.loads(response.decode("utf-8"))
            return json_response["country"], json_response["city"]
        except:
            return "None", "None"


def add_connections(ip, honeypot_type):
    if Connections.objects.filter(ip=ip, honeypot_type=honeypot_type).count() == 0:
        Connections(
            ip=ip, honeypot_type=honeypot_type, country="None", city="None"
        ).save()
    country, city = get_country_and_city(ip)
    Connections.objects.filter(ip=ip, honeypot_type=honeypot_type).update(
        country=country, city=city
    )


def start_adding_connections(ip, honeypot_type):
    threading.Thread(
        target=add_connections,
        args=(
            ip,
            honeypot_type,
        ),
    ).start()


def add_connections_log(ip, honeypot_type, action):
    Connections_log(
        ip=ip,
        time=time.strftime("%Y/%m/%d-%H:%M:%S", time.localtime()),
        honeypot_type=honeypot_type,
        action=action,
    ).save()


def start_adding_connections_log(ip, honeypot_type, action):
    threading.Thread(
        target=add_connections_log,
        args=(
            ip,
            honeypot_type,
            action,
        ),
    ).start()


def get_connections_log_count_by_honeypot_type(time, honeypot_type):
    return Connections_log.objects.filter(
        Q(time__startswith=time), honeypot_type=honeypot_type
    ).count()


class Connections_logs:
    def __init__(self, ip, time, honeypot_type, id, action, region):
        self.ip = ip
        self.time = time
        self.honeypot_type = honeypot_type
        self.id = id
        self.action = action
        self.region = region


def get_connection_region(ip, honeypot_type):
    connection = Connections.objects.filter(
        ip=ip, honeypot_type=honeypot_type
    ).values()[0]
    return connection["city"] + ", " + connection["country"]


def get_connection_log(id):
    connection = Connections_log.objects.filter(id=id).values()[0]
    ip = connection["ip"]
    honeypot_type = connection["honeypot_type"]
    connection_log = Connections_log.objects.filter(
        Q(id__gt=id),
        ip=ip,
        honeypot_type=honeypot_type,
    ).values()
    file_name = (
        "connection_log_"
        + connection["time"].replace("/", "-")
        + "_"
        + ip
        + "_"
        + honeypot_type
        + ".log"
    )
    out_text = connection["time"] + " " + ip + " " + honeypot_type + "\n"
    for log in connection_log:
        if log["action"] == "START":
            break
        out_text += (
            log["time"]
            + " "
            + log["ip"]
            + " "
            + log["honeypot_type"]
            + " "
            + log["action"]
            + "\n"
        )
    return file_name, out_text


def get_connections_logs():
    connections_logs = []
    for connections_log in Connections_log.objects.filter(action="START").values():
        connections_logs.append(
            Connections_logs(
                connections_log["ip"],
                connections_log["time"],
                connections_log["honeypot_type"],
                connections_log["id"],
                connections_log["action"],
                get_connection_region(
                    connections_log["ip"], connections_log["honeypot_type"]
                ),
            )
        )
    return connections_logs


def get_all_connections_logs():
    all_connections_logs = []
    for connections_log in Connections_log.objects.all().values():
        all_connections_logs.append(
            Connections_logs(
                connections_log["ip"],
                connections_log["time"],
                connections_log["honeypot_type"],
                connections_log["id"],
                connections_log["action"],
                get_connection_region(
                    connections_log["ip"], connections_log["honeypot_type"]
                ),
            )
        )
    return all_connections_logs


def get_number_of_logs():
    return Connections_log.objects.count()


def get_most_connected():
    ips = (
        Connections_log.objects.filter(action="START")
        .order_by("ip")
        .values_list("ip")
        .annotate(count=Count("ip"))
        .distinct()
        .order_by("-count")
        .values_list("ip", flat=True)
    )
    ips = ips[:3]
    most_connected = []
    for ip in ips:
        connection = Connections.objects.filter(ip=ip).values()[0]
        country, city = connection["country"], connection["city"]
        most_connected.append(ip + " " + city + ", " + country)
    return most_connected


def get_numbers_of_telnet_and_ssh_connections():
    telnet_connections = Connections_log.objects.filter(
        honeypot_type="Telnet", action="START"
    ).count()
    ssh_connections = Connections_log.objects.filter(
        honeypot_type="SSH", action="START"
    ).count()
    return telnet_connections, ssh_connections


def get_numbers_of_connections_over_a_period_of_time():
    current_time = time.strftime("%Y/%m/%d-%H:%M:%S", time.localtime())
    hour = current_time.split(":")[0]
    day = current_time.split("-")[0]
    month = current_time.replace(current_time.split("/")[2], "")
    connections_in_1_hour = Connections_log.objects.filter(
        Q(action="START", time__startswith=hour)
    ).count()
    connections_in_1_day = Connections_log.objects.filter(
        Q(action="START", time__startswith=day)
    ).count()
    connections_in_1_month = Connections_log.objects.filter(
        Q(action="START", time__startswith=month)
    ).count()
    return connections_in_1_hour, connections_in_1_day, connections_in_1_month


def get_overview():
    overview = {}
    overview["state_of_telnet"] = get_state("Telnet")
    overview["state_of_ssh"] = get_state("SSH")
    (
        overview["telnet_connections"],
        overview["ssh_connections"],
    ) = get_numbers_of_telnet_and_ssh_connections()
    overview["total_connections"] = (
        overview["telnet_connections"] + overview["ssh_connections"]
    )
    (
        overview["connections_in_1_hour"],
        overview["connections_in_1_day"],
        overview["connections_in_1_month"],
    ) = get_numbers_of_connections_over_a_period_of_time()
    overview["most_connected"] = get_most_connected()
    overview["number_of_logs"] = get_number_of_logs()
    return overview


def get_connection_id(ip, honeypot_type):
    return Connections.objects.filter(ip=ip, honeypot_type=honeypot_type).values()[0][
        "id"
    ]


class Connection:
    def __init__(self, ip, honeypot_type, country, city):
        self.ip = ip
        self.honeypot_type = honeypot_type
        self.country = country
        self.city = city


def get_connections():
    connections = []
    for connection in Connections.objects.all().values():
        connections.append(
            Connection(
                connection["ip"],
                connection["honeypot_type"],
                connection["country"],
                connection["city"],
            )
        )
    return connections


def get_not_allowed_commands():
    return list(
        Not_allowed_commands.objects.values_list("not_allowed_command", flat=True)
    )


def remove_not_allowed_commands():
    Not_allowed_commands.objects.all().delete()


def set_not_allowed_commands(not_allowed_commands):
    for command in not_allowed_commands:
        if (
            Not_allowed_commands.objects.filter(not_allowed_command=command).count()
            == 0
        ):
            Not_allowed_commands(not_allowed_command=command).save()


def add_password(password):
    if Passwords.objects.filter(password=password).count() == 0:
        Passwords(password=password).save()


def start_adding_password(password):
    threading.Thread(target=add_password, args=(password,)).start()


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def add_users_log(user_id, user_type, action, request):
    ip = get_client_ip(request)
    Users_log(
        user_id=user_id,
        user_type=user_type,
        time=time.strftime("%Y/%m/%d-%H:%M:%S", time.localtime()),
        action=action,
        ip=ip,
    ).save()


def start_adding_users_log(user_id, user_type, action, request):
    threading.Thread(
        target=add_users_log, args=(user_id, user_type, action, request)
    ).start()


def get_users_log_count_by_user_type(time, user_type):
    return Users_log.objects.filter(
        Q(time__startswith=time), user_type=user_type
    ).count()


class Users_logs:
    def __init__(self, user_id, user_type, time, action, ip):
        self.user_id = user_id
        self.user_type = user_type
        self.time = time
        self.action = action
        self.ip = ip


def get_users_logs():
    users_logs = []
    for users_log in Users_log.objects.all().values():
        user_id = users_log["user_id"]
        if users_log["user_type"] == True:
            user_type = "Admin"
        else:
            user_type = "Visitor"
        time = users_log["time"]
        action = users_log["action"]
        ip = users_log["ip"]
        users_logs.append(Users_logs(user_id, user_type, time, action, ip))
    return users_logs
