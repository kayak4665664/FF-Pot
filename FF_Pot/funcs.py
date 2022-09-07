import os
import time
from django.http import FileResponse
from FF_Pot_Model.models import (
    Configs,
    Users,
)
from .database import (
    get_parameters,
    get_md5,
    get_salt,
    get_users_logs,
    remove_not_allowed_commands,
    remove_replace_names,
    set_not_allowed_commands,
    remove_usernames,
    set_usernames,
    remove_replace_names,
    set_replace_names,
    remove_hidden_paths,
    set_hidden_paths,
    empty_caught_files,
    get_users_log_count_by_user_type,
    get_honeypots_log_count_by_honeypot_type,
    get_honeypots_logs,
    get_connections_log_count_by_honeypot_type,
    get_all_connections_logs,
    get_connections_logs,
)
from .honeypot_server.honeypot_manager import (
    start_telnet_honeypot,
    start_ssh_honeypot,
    terminate_ssh_honeypot,
    terminate_telnet_honeypot,
)
from .honeypot_server.fake_files import dir_exists, empty_temporary_files, get_zip_path
from .honeypot_server.state_of_honeypots import get_state
import re
import time


def set_telnet_port(telnet_honeypot_port):
    if telnet_honeypot_port.isdigit() == False:
        return "The port format is incorrect."
    elif int(telnet_honeypot_port) < 0 or int(telnet_honeypot_port) > 65535:
        return "The port format is incorrect."
    else:
        Configs.objects.filter(id=1).update(telnet_honeypot_port=telnet_honeypot_port)
        return "The telnet honeypot port has been set."


def set_ssh_port(ssh_honeypot_port):
    if ssh_honeypot_port.isdigit() == False:
        return "The port format is incorrect."
    elif int(ssh_honeypot_port) < 0 or int(ssh_honeypot_port) > 65535:
        return "The port format is incorrect."
    else:
        Configs.objects.filter(id=1).update(ssh_honeypot_port=ssh_honeypot_port)
        return "The SSH honeypot port has been set."


def set_root_and_default_directory(root, default_directory):
    if root[-1] != "/":
        root += "/"
    if default_directory[-1] != "/":
        default_directory += "/"
    if default_directory.lower().startswith(root.lower()) == False:
        return "The directory format is incorrect."
    if dir_exists(root) == False or dir_exists(default_directory) == False:
        return "The directory does not exist."
    Configs.objects.filter(id=1).update(root=root, default_directory=default_directory)
    return "Root and default directory have been set."


def set_telnet_and_ssh_state(telnet_honeypot, ssh_honeypot):
    result = ""
    telnet_honeypot_state = get_state("Telnet")
    ssh_honeypot_state = get_state("SSH")
    (
        telnet_honeypot_port,
        ssh_honeypot_port,
        root,
        default_directory,
    ) = get_parameters()
    if telnet_honeypot == "on":
        if telnet_honeypot_state == True:
            result += "Telnet honeypot is running."
        elif telnet_honeypot_port is None or root is None or default_directory is None:
            result += "Missing parameters."
        else:
            start_telnet_honeypot()
            time.sleep(1)
            telnet_honeypot_state = get_state("Telnet")
            if telnet_honeypot_state == True:
                result += "Telnet honeypot is running."
            else:
                result += "Telnet honeypot port is occupied"
    else:
        if telnet_honeypot_state == True:
            terminate_telnet_honeypot()
            time.sleep(1)
            result += "Telnet honeypot stopped."
        else:
            result += "Telnet honeypot stopped."
    if ssh_honeypot == "on":
        if ssh_honeypot_state == True:
            result += " SSH honeypot is running."
        elif ssh_honeypot_port is None or root is None or default_directory is None:
            result += " Missing parameters."
        else:
            start_ssh_honeypot()
            time.sleep(1)
            ssh_honeypot_state = get_state("SSH")
            if ssh_honeypot_state == True:
                result += " SSH honeypot is running."
            else:
                result += " SSH honeypot port is occupied"
    else:
        if ssh_honeypot_state == True:
            terminate_ssh_honeypot()
            time.sleep(1)
            result += " SSH honeypot stopped."
        else:
            result += " SSH honeypot stopped."
    return result


def add_visitor(new_user_id):
    if new_user_id == "" or new_user_id is None:
        return "The User ID format is incorrect."
    if Users.objects.filter(user_id=new_user_id).count() != 0:
        return "User ID already exists."
    salt = get_salt()
    user_password = get_md5("123456", salt)
    Users(
        user_id=new_user_id, user_type=False, salt=salt, user_password=user_password
    ).save()
    return "The user is created, the initial password is 123456."


def delete_visitor(user_id_to_delete):
    user = Users.objects.filter(user_id=user_id_to_delete).values()
    if user.count() == 0:
        return "User does not exist."
    if user[0]["user_type"] == True:
        return "Can't delete admin."
    Users.objects.filter(user_id=user_id_to_delete).delete()
    return "Deleted."


def change_user_password(user_id, user_password, repeat_password):
    if user_password != repeat_password:
        return "The two entered passwords do not match."
    elif len(user_password) < 5:
        return "Password is too short, at least 5 characters."
    user = Users.objects.filter(user_id=user_id)
    salt = user.values()[0]["salt"]
    user.update(user_password=get_md5(user_password, salt))
    return "Password has been changed, please log in again."


def set_user_phone_number(user_id, phone_number):
    if phone_number == "":
        Users.objects.filter(user_id=user_id).update(phone_number=None)
        return "Phone number has been set."
    elif phone_number[0] == "+" and (phone_number[1:]).isdigit():
        Users.objects.filter(user_id=user_id).update(phone_number=phone_number)
        return "Phone number has been set."
    else:
        return "The phone number format is incorrect."


def set_user_mail_address(user_id, mail_address):
    if mail_address == "":
        Users.objects.filter(user_id=user_id).update(mail_address=None)
        return "Mail address has been set."
    elif re.match(
        r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}$",
        mail_address,
    ):
        Users.objects.filter(user_id=user_id).update(mail_address=mail_address)
        return "Mail address has been set."
    else:
        return "The mail address format is incorrect."


def lines_to_list(lines):
    list = []
    for line in lines:
        line = line.decode().replace("\n", "")
        if line != "":
            list.append(line)
    return list


def set_not_allowed(lines):
    remove_not_allowed_commands()
    not_allowed_commands = lines_to_list(lines)
    set_not_allowed_commands(not_allowed_commands)


def set_allowed_usernames(lines):
    remove_usernames()
    usernames = lines_to_list(lines)
    set_usernames(usernames)


def set_replace(lines):
    remove_replace_names()
    replace_names = lines_to_list(lines)
    set_replace_names(replace_names)


def set_hidden(lines):
    remove_hidden_paths()
    hidden_paths = []
    for line in lines:
        line = line.decode().replace("\n", "")
        if line != "" and line != "/":
            if line[-1] != "/":
                line += "/"
            if dir_exists(line):
                hidden_paths.append(line)
    set_hidden_paths(hidden_paths)


def set_number(sms_number):
    if sms_number[0] == "+" and (sms_number[1:]).isdigit():
        Configs.objects.filter(id=1).update(sms_number=sms_number)
        return "SMS number has been set."
    else:
        return "The SMS number format is incorrect."


def set_sid(sms_sid):
    if sms_sid != "":
        Configs.objects.filter(id=1).update(sms_sid=sms_sid)
        return "SMS SID has been set."
    else:
        return "The SMS SID format is incorrect."


def set_token(sms_token):
    if sms_token != "":
        Configs.objects.filter(id=1).update(sms_token=sms_token)
        return "SMS token has been set."
    else:
        return "The SMS token format is incorrect."


def set_sms_state(sms_alert):
    if sms_alert == "on":
        Configs.objects.filter(id=1).update(send_sms=True)
        return "SMS alarm turned on."
    else:
        Configs.objects.filter(id=1).update(send_sms=False)
        return "SMS alarm turned off."


def set_host(mail_host):
    if mail_host != "":
        Configs.objects.filter(id=1).update(mail_host=mail_host)
        return "Mail host has been set."
    else:
        return "The mail host format is incorrect."


def set_user(mail_user):
    if re.match(
        r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}$",
        mail_user,
    ):
        Configs.objects.filter(id=1).update(mail_user=mail_user)
        return "Mail user has been set."
    else:
        return "The mail user format is incorrect."


def set_password(mail_password):
    if mail_password != "":
        Configs.objects.filter(id=1).update(mail_password=mail_password)
        return "Mail password has been set."
    else:
        return "The mail password format is incorrect."


def set_ssl(ssl_port):
    if ssl_port.isdigit() == False:
        return "The port format is incorrect."
    elif int(ssl_port) < 0 or int(ssl_port) > 65535:
        return "The port format is incorrect."
    else:
        Configs.objects.filter(id=1).update(ssl_port=ssl_port)
        return "The SSL port has been set."


def set_mail_state(mail_alert):
    if mail_alert == "on":
        Configs.objects.filter(id=1).update(send_mail=True)
        return "Mail alarm turned on."
    else:
        Configs.objects.filter(id=1).update(send_mail=False)
        return "Mail alarm turned off."


def empty_temporary():
    telnet_honeypot_state = get_state("Telnet")
    ssh_honeypot_state = get_state("SSH")
    if telnet_honeypot_state == True or ssh_honeypot_state == True:
        return "Please stop the honeypots before emptying the temporary files."
    empty_temporary_files()
    return "Temporary files have been emptied."


def empty_caught():
    telnet_honeypot_state = get_state("Telnet")
    ssh_honeypot_state = get_state("SSH")
    if telnet_honeypot_state == True or ssh_honeypot_state == True:
        return "Please stop the honeypots before emptying the caught files."
    empty_caught_files()
    return ""


def get_filtered_connections(connections, telnet, ssh):
    filtered_connections = []
    if telnet == "on" and ssh is None:
        for connection in connections:
            if connection.honeypot_type == "Telnet":
                filtered_connections.append(connection)
    elif ssh == "on" and telnet is None:
        for connection in connections:
            if connection.honeypot_type == "SSH":
                filtered_connections.append(connection)
    else:
        filtered_connections = connections
    return filtered_connections


def filter_by_date(list, start_date, end_date):
    filtered_list = []
    if start_date == "" or end_date == "" or start_date is None or end_date is None:
        start_date = end_date = time.strftime("%Y/%m/%d", time.localtime())
    for item in list:
        date = item.time.split("-")[0]
        if date >= start_date and date <= end_date:
            filtered_list.append(item)
    return filtered_list


def get_filtered_users_logs(users_logs, admin, visitor, start_date, end_date):
    filtered_users_logs = []
    if admin == "on" and visitor is None:
        for users_log in users_logs:
            if users_log.user_type == "Admin":
                filtered_users_logs.append(users_log)
    elif visitor == "on" and admin is None:
        for users_log in users_logs:
            if users_log.user_type == "Visitor":
                filtered_users_logs.append(users_log)
    else:
        filtered_users_logs = users_logs
    filtered_users_logs = filter_by_date(filtered_users_logs, start_date, end_date)
    return filtered_users_logs


def get_file_name_by_date(file_name, start_date, end_date):
    if not (
        start_date != ""
        and end_date != ""
        and start_date is not None
        and end_date is not None
    ):
        file_name += "_" + time.strftime("%Y-%m-%d", time.localtime())
    elif start_date == end_date:
        file_name += "_" + start_date.replace("/", "-")
    else:
        file_name += (
            "_" + start_date.replace("/", "-") + "_" + end_date.replace("/", "-")
        )
    file_name += ".log"
    return file_name


def get_file_name_and_out_text_of_users_logs(
    admin, visitor, start_date, end_date, filtered_users_logs
):
    file_name = time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime()) + "_" + "users_log"
    if admin == "on" and visitor is None:
        file_name += "_admin"
    elif visitor == "on" and admin is None:
        file_name += "_visitor"
    file_name = get_file_name_by_date(file_name, start_date, end_date)
    out_text = ""
    for filtered_users_log in filtered_users_logs:
        out_text += (
            filtered_users_log.time
            + " "
            + filtered_users_log.ip
            + " "
            + filtered_users_log.user_type
            + " "
            + filtered_users_log.user_id
            + " "
            + filtered_users_log.action
            + "\n"
        )
    return file_name, out_text


def get_filtered_honeypots_logs(
    honeypots_logs, telnet, ssh, sms, mail, honeypot_server, start_date, end_date
):
    filtered_honeypots_logs = []
    if (
        telnet is None
        and ssh is None
        and sms is None
        and mail is None
        and honeypot_server is None
        or telnet == "on"
        and ssh == "on"
        and sms == "on"
        and mail == "on"
        and honeypot_server == "on"
    ):
        filtered_honeypots_logs = honeypots_logs
    else:
        for honeypots_log in honeypots_logs:
            if (
                telnet == "on"
                and honeypots_log.honeypot_type == "Telnet"
                or ssh == "on"
                and honeypots_log.honeypot_type == "SSH"
                or sms == "on"
                and honeypots_log.honeypot_type == "SMS"
                or mail == "on"
                and honeypots_log.honeypot_type == "Mail"
                or honeypot_server == "on"
                and honeypots_log.honeypot_type == "Honeypot"
            ):
                filtered_honeypots_logs.append(honeypots_log)
    filtered_honeypots_logs = filter_by_date(
        filtered_honeypots_logs, start_date, end_date
    )
    return filtered_honeypots_logs


def get_filtered_connections_logs(connections_logs, telnet, ssh, start_date, end_date):
    filtered_connections_logs = []
    if telnet == "on" and ssh is None:
        for connections_log in connections_logs:
            if connections_log.honeypot_type == "Telnet":
                filtered_connections_logs.append(connections_log)
    elif ssh == "on" and telnet is None:
        for connections_log in connections_logs:
            if connections_log.honeypot_type == "SSH":
                filtered_connections_logs.append(connections_log)
    else:
        filtered_connections_logs = connections_logs
    filtered_connections_logs = filter_by_date(
        filtered_connections_logs, start_date, end_date
    )
    return filtered_connections_logs


def get_file_name_and_out_text_of_honeypots_logs(
    telnet,
    ssh,
    sms,
    mail,
    honeypot_server,
    start_date,
    end_date,
    filtered_honeypots_logs,
):
    file_name = (
        time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime()) + "_" + "honeypots_log"
    )
    if not (
        telnet is None
        and ssh is None
        and sms is None
        and mail is None
        and honeypot_server is None
        or telnet == "on"
        and ssh == "on"
        and sms == "on"
        and mail == "on"
        and honeypot_server == "on"
    ):
        if telnet == "on":
            file_name += "_telnet"
        if ssh == "on":
            file_name += "_ssh"
        if sms == "on":
            file_name += "_sms"
        if mail == "on":
            file_name += "_mail"
        if honeypot_server == "on":
            file_name += "_honeypot"
    file_name = get_file_name_by_date(file_name, start_date, end_date)
    out_text = ""
    for filtered_honeypots_log in filtered_honeypots_logs:
        out_text += (
            filtered_honeypots_log.time
            + " "
            + filtered_honeypots_log.honeypot_type
            + " "
            + filtered_honeypots_log.action
            + "\n"
        )
    return file_name, out_text


def get_file_response(path, name):
    if os.path.isdir(path):
        path = get_zip_path(path, name)
    file = open(path, "rb")
    file_response = FileResponse(file)
    file_response["Content-Type"] = "application/octet-stream"
    file_response["Content-Disposition"] = 'attachment;filename="' + name + '"'
    return file_response


def get_data_list(
    line_chart_point_start,
    line_chart_point_end,
    count_list,
    data_list,
    time_start,
    span,
    func,
):
    for time in range(line_chart_point_start, line_chart_point_end + 1):
        sum = int(0)
        for count in count_list:
            if span == "year":
                count[0] = func(str(time) + "/", count[1])
            elif span == "month" or span == "day" or span == "hour":
                time = str(time)
                if len(time) == 1:
                    time = "0" + time
                if span == "month":
                    count[0] = func(time_start + time + "/", count[1])
                elif span == "day":
                    count[0] = func(time_start + time + "-", count[1])
                else:
                    count[0] = func(time_start + time + ":", count[1])
            sum += count[0]
        data_list[0].append(sum)
        for index in range(1, len(data_list)):
            data_list[index].append(count_list[index - 1][0])
    return data_list


def get_line_chart(line_chart_title, start_date, end_date, func, count_list, data_list):
    if (
        start_date != ""
        and end_date != ""
        and start_date is not None
        and end_date is not None
    ):
        start_year = start_date.split("/")[0]
        start_month = start_date.split("/")[1]
        start_day = start_date.split("/")[2]
        end_year = end_date.split("/")[0]
        end_month = end_date.split("/")[1]
        end_day = end_date.split("/")[2]
        if start_year != end_year:
            line_chart_title += " (" + start_year + " - " + end_year + ")"
            line_chart_point_start = int(start_year)
            line_chart_point_end = int(end_year)
            data_list = get_data_list(
                line_chart_point_start,
                line_chart_point_end,
                count_list,
                data_list,
                "",
                "year",
                func,
            )
        elif start_month != end_month:
            line_chart_title += (
                " ("
                + start_year
                + "/"
                + start_month
                + " - "
                + end_year
                + "/"
                + end_month
                + ")"
            )
            time_start = start_year + "/"
            line_chart_point_start = int(start_month)
            line_chart_point_end = int(end_month)
            data_list = get_data_list(
                line_chart_point_start,
                line_chart_point_end,
                count_list,
                data_list,
                time_start,
                "month",
                func,
            )
        elif start_day != end_day:
            line_chart_title += " (" + start_date + " - " + end_date + ")"
            time_start = start_year + "/" + start_month + "/"
            line_chart_point_start = int(start_day)
            line_chart_point_end = int(end_day)
            data_list = get_data_list(
                line_chart_point_start,
                line_chart_point_end,
                count_list,
                data_list,
                time_start,
                "day",
                func,
            )
        else:
            line_chart_title += " (" + start_date + ")"
            time_start = start_date + "-"
            line_chart_point_start = int(0)
            line_chart_point_end = int(23)
            data_list = get_data_list(
                line_chart_point_start,
                line_chart_point_end,
                count_list,
                data_list,
                time_start,
                "hour",
                func,
            )
    else:
        today = time.strftime("%Y/%m/%d", time.localtime())
        line_chart_title += " (" + today + ")"
        time_start = today + "-"
        line_chart_point_start = int(0)
        line_chart_point_end = int(23)
        data_list = get_data_list(
            line_chart_point_start,
            line_chart_point_end,
            count_list,
            data_list,
            time_start,
            "hour",
            func,
        )
    return line_chart_title, line_chart_point_start, data_list


def get_users_line_chart(start_date, end_date):
    users_line_chart_title = "Users Action"
    count_list = [
        [int, True],
        [int, False],
    ]
    data_list = [[], [], []]
    users_line_chart_title, users_line_chart_point_start, data_list = get_line_chart(
        users_line_chart_title,
        start_date,
        end_date,
        get_users_log_count_by_user_type,
        count_list,
        data_list,
    )
    return (
        users_line_chart_title,
        users_line_chart_point_start,
        data_list[0],
        data_list[1],
        data_list[2],
    )


class Pie_chart:
    def __init__(self, name, y):
        self.name = name
        self.y = y


def get_pie_chart_title(title, start_date, end_date):
    if not (
        start_date != ""
        and end_date != ""
        and start_date is not None
        and end_date is not None
    ):
        start_date = time.strftime("%Y/%m/%d", time.localtime())
        end_date = start_date
        pie_chart_title = title + " (" + start_date + ")"
    elif start_date == end_date:
        pie_chart_title = title + " (" + start_date + ")"
    else:
        pie_chart_title = title + " (" + start_date + " - " + end_date + ")"
    return pie_chart_title, start_date, end_date


def get_pie_chart(count):
    sum = int(0)
    pie_chart = []
    for key in count:
        sum += count[key]
    for key in count:
        pie_chart.append(Pie_chart(key, round(count[key] / sum * 100, 5)))
    return pie_chart


def get_users_pie_chart(start_date, end_date):
    users_action_count = {}
    users_pie_chart_title, start_date, end_date = get_pie_chart_title(
        "Users Action", start_date, end_date
    )
    users_logs = get_users_logs()
    for users_log in users_logs:
        date = users_log.time.split("-")[0]
        if date >= start_date and date <= end_date:
            key = users_log.user_id
            if key in users_action_count:
                users_action_count[key] += 1
            else:
                users_action_count[key] = 1
    users_pie_chart = get_pie_chart(users_action_count)
    return users_pie_chart_title, users_pie_chart


def get_honeypots_line_chart(start_date, end_date):
    honeypots_line_chart_title = "Honeypots Action"
    count_list = [
        [int, "Telnet"],
        [int, "SSH"],
        [int, "SMS"],
        [int, "Mail"],
        [int, "Honeypot"],
    ]
    data_list = [[], [], [], [], [], []]
    (
        honeypots_line_chart_title,
        honeypots_line_chart_point_start,
        data_list,
    ) = get_line_chart(
        honeypots_line_chart_title,
        start_date,
        end_date,
        get_honeypots_log_count_by_honeypot_type,
        count_list,
        data_list,
    )
    return (
        honeypots_line_chart_title,
        honeypots_line_chart_point_start,
        data_list[0],
        data_list[1],
        data_list[2],
        data_list[3],
        data_list[4],
        data_list[5],
    )


def get_honeypots_pie_chart(start_date, end_date):
    honeypots_action_count = {}
    honeypots_pie_chart_title, start_date, end_date = get_pie_chart_title(
        "Honeypots Action", start_date, end_date
    )
    honeypots_logs = get_honeypots_logs()
    for honeypots_log in honeypots_logs:
        date = honeypots_log.time.split("-")[0]
        if date >= start_date and date <= end_date:
            key = honeypots_log.honeypot_type
            if key in honeypots_action_count:
                honeypots_action_count[key] += 1
            else:
                honeypots_action_count[key] = 1
    honeypots_pie_chart = get_pie_chart(honeypots_action_count)
    return honeypots_pie_chart_title, honeypots_pie_chart


def get_connections_line_chart(start_date, end_date):
    connections_line_chart_title = "Connections Action"
    count_list = [[int, "Telnet"], [int, "SSH"]]
    data_list = [[], [], []]
    (
        connections_line_chart_title,
        connections_line_chart_point_start,
        data_list,
    ) = get_line_chart(
        connections_line_chart_title,
        start_date,
        end_date,
        get_connections_log_count_by_honeypot_type,
        count_list,
        data_list,
    )
    return (
        connections_line_chart_title,
        connections_line_chart_point_start,
        data_list[0],
        data_list[1],
        data_list[2],
    )


def get_connections_pie_chart(start_date, end_date):
    connections_action_count = {}
    connections_pie_chart_title, start_date, end_date = get_pie_chart_title(
        "Connections Action", start_date, end_date
    )
    all_connections_logs = get_all_connections_logs()
    for connections_log in all_connections_logs:
        date = connections_log.time.split("-")[0]
        if date >= start_date and date <= end_date:
            key = connections_log.ip + ", " + connections_log.honeypot_type
            if key in connections_action_count:
                connections_action_count[key] += 1
            else:
                connections_action_count[key] = 1
    connections_pie_chart = get_pie_chart(connections_action_count)
    return connections_pie_chart_title, connections_pie_chart


def get_connection_regions_pie_chart(start_date, end_date):
    connection_regions_action_count = {}
    regions_pie_chart_title, start_date, end_date = get_pie_chart_title(
        "Connections Region", start_date, end_date
    )
    connections_logs = get_connections_logs()
    for connections_log in connections_logs:
        date = connections_log.time.split("-")[0]
        if date >= start_date and date <= end_date:
            key = connections_log.region
            if key in connection_regions_action_count:
                connection_regions_action_count[key] += 1
            else:
                connection_regions_action_count[key] = 1
    connection_regions_pie_chart = get_pie_chart(connection_regions_action_count)
    return regions_pie_chart_title, connection_regions_pie_chart

def get_connection_commands_pie_chart(start_date, end_date):
    connection_commands_action_count = {}
    commands_pie_chart_title, start_date, end_date = get_pie_chart_title(
        "Connections Command", start_date, end_date
    )
    connections_logs = get_all_connections_logs()
    for connections_log in connections_logs:
        if connections_log.action == "START":
            continue
        date = connections_log.time.split("-")[0]
        if date >= start_date and date <= end_date:
            key = connections_log.action.split(" ")[0]
            if key in connection_commands_action_count:
                connection_commands_action_count[key] += 1
            else:
                connection_commands_action_count[key] = 1
    connection_commands_pie_chart = get_pie_chart(connection_commands_action_count)
    return commands_pie_chart_title, connection_commands_pie_chart