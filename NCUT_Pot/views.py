import os
import re
import time
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from NCUT_Pot_Model.models import Users
from .database import (
    get_caught_paths,
    get_config_value,
    get_md5,
    start_adding_users_log,
    get_overview,
    get_user,
    get_usernames,
    get_all_users,
    get_parameters,
    get_not_allowed_commands,
    get_replace_names,
    get_hidden_paths,
    get_connections,
    get_users_logs,
    get_honeypots_logs,
    get_connections_logs,
    get_connection_log,
)
from .funcs import (
    add_visitor,
    delete_visitor,
    change_user_password,
    get_connections_pie_chart,
    set_user_phone_number,
    set_user_mail_address,
    set_telnet_port,
    set_ssh_port,
    set_root_and_default_directory,
    set_telnet_and_ssh_state,
    set_not_allowed,
    set_allowed_usernames,
    set_replace,
    set_hidden,
    set_number,
    set_sid,
    set_token,
    set_sms_state,
    set_host,
    set_user,
    set_password,
    set_ssl,
    set_mail_state,
    empty_temporary,
    get_filtered_connections,
    get_filtered_users_logs,
    get_file_name_and_out_text_of_users_logs,
    get_filtered_honeypots_logs,
    get_filtered_connections_logs,
    get_file_name_and_out_text_of_honeypots_logs,
    empty_caught,
    get_file_response,
    get_users_line_chart,
    get_users_pie_chart,
    get_honeypots_pie_chart,
    get_honeypots_line_chart,
    get_connections_line_chart,
    get_connections_pie_chart,
    get_connection_regions_pie_chart,
    get_connection_commands_pie_chart
)
from .honeypot_server.state_of_honeypots import get_state
from .honeypot_server.fake_files import write_download_file, get_temporary_files_count


@csrf_exempt
def login(request):
    result = ""
    if request.method == "POST":
        user_id = request.POST.get("user_id")
        user_password = request.POST.get("user_password")
        users = Users.objects.filter(user_id=user_id)
        if users.count() == 1:
            user = users.values()[0]
            if user["user_password"] == get_md5(user_password, user["salt"]):

                request.session["user_type"] = user["user_type"]
                request.session["user_id"] = user["user_id"]
                request.session["logged"] = True
                start_adding_users_log(
                    user["user_id"], user["user_type"], "Logged.", request
                )
                overview = get_overview()
                return render(
                    request,
                    "overview.html",
                    {"title": "Overview", "overview": overview, "itemed": "Logs"},
                )
            else:
                result = "Input error, please try again!"
        else:
            result = "Input error, please try again!"
    return render(request, "login.html", {"result": result})


def error(request, exceptions):
    return render(request, "error.html")


def error_500(request):
    return render(request, "error.html")


def get_render(request, html, dict, log, add_log=True):
    if add_log:
        start_adding_users_log(
            request.session["user_id"],
            request.session["user_type"],
            log,
            request,
        )
    return render(request, html, dict)


@csrf_exempt
def home(request):
    is_logged = request.session.get("logged")
    if not is_logged:
        return get_render(request, "login.html", {"result": ""}, "", add_log=False)

    elif Users.objects.filter(user_id=request.session["user_id"]).count() == 0:
        start_adding_users_log(
            request.session["user_id"],
            request.session["user_type"],
            "Logged out.",
            request,
        )
        request.session.flush()
        return get_render(request, "login.html", {"result": ""})

    else:
        if request.method == "GET":
            log_out = request.GET.get("log_out")
            if log_out == "True":
                start_adding_users_log(
                    request.session["user_id"],
                    request.session["user_type"],
                    "Logged out.",
                    request,
                )
                request.session.flush()
                return render(request, "login.html", {"result": ""})

            user_settings = request.GET.get("user_settings")
            if user_settings == "True":
                user = get_user(request.session["user_id"])
                return render(
                    request,
                    "user_settings.html",
                    {
                        "title": "User Settings",
                        "result": "",
                        "user": user,
                        "itemed": "User settings",
                    },
                )

            change_password = request.GET.get("change_password")
            if change_password == "True":
                user_password = request.GET.get("user_password")
                repeat_password = request.GET.get("repeat_password")
                result = change_user_password(
                    request.session["user_id"], user_password, repeat_password
                )
                start_adding_users_log(
                    request.session["user_id"],
                    request.session["user_type"],
                    "Try to change password.",
                    request,
                )
                if result == "Password has been changed, please log in again.":
                    start_adding_users_log(
                        request.session["user_id"],
                        request.session["user_type"],
                        "Logged out.",
                        request,
                    )
                    request.session.flush()
                    return render(request, "login.html", {"result": result})
                else:
                    user = get_user(request.session["user_id"])
                    return get_render(
                        request,
                        "user_settings.html",
                        {
                            "title": "User Settings",
                            "result": result,
                            "user": user,
                            "anchor": "anchor",
                            "itemed": "User settings",
                        },
                        "",
                        add_log=False,
                    )

            set_phone_number = request.GET.get("set_phone_number")
            if set_phone_number == "True":
                phone_number = request.GET.get("phone_number")
                result = set_user_phone_number(request.session["user_id"], phone_number)
                user = get_user(request.session["user_id"])
                return get_render(
                    request,
                    "user_settings.html",
                    {
                        "title": "User Settings",
                        "result": result,
                        "user": user,
                        "anchor": "anchor",
                        "itemed": "User settings",
                    },
                    "Try to change phone number.",
                )

            set_mail_address = request.GET.get("set_mail_address")
            if set_mail_address == "True":
                mail_address = request.GET.get("mail_address")
                result = set_user_mail_address(request.session["user_id"], mail_address)
                user = get_user(request.session["user_id"])
                return get_render(
                    request,
                    "user_settings.html",
                    {
                        "title": "User Settings",
                        "result": result,
                        "user": user,
                        "anchor": "anchor",
                        "itemed": "User settings",
                    },
                    "Try to change mail address.",
                )

            filter_connections = request.GET.get("filter_connections")
            if filter_connections == "True":
                telnet = request.GET.get("telnet")
                ssh = request.GET.get("ssh")
                connections = get_connections()
                filtered_connections = get_filtered_connections(
                    connections, telnet, ssh
                )
                return render(
                    request,
                    "connections.html",
                    {
                        "title": "Connections",
                        "count": len(filtered_connections),
                        "connections": filtered_connections,
                        "itemed": "Logs",
                        "telnet": telnet,
                        "ssh": ssh,
                    },
                )

            filter_connections_log = request.GET.get("filter_connections_log")
            if filter_connections_log == "True":
                telnet = request.GET.get("telnet")
                ssh = request.GET.get("ssh")
                start_date = request.GET.get("start_date")
                end_date = request.GET.get("end_date")
                connections_logs = get_connections_logs()
                filtered_connections_logs = get_filtered_connections_logs(
                    connections_logs, telnet, ssh, start_date, end_date
                )
                return render(
                    request,
                    "connections_log.html",
                    {
                        "title": "Connections Log",
                        "itemed": "Logs",
                        "connections_logs": filtered_connections_logs,
                        "count": len(filtered_connections_logs),
                        "filtered": True,
                        "telnet": telnet,
                        "ssh": ssh,
                        "start_date": start_date,
                        "end_date": end_date,
                    },
                )

            view_connection_details = request.GET.get("view_connection_details")
            if view_connection_details is not None:
                id = int(view_connection_details)
                telnet = request.GET.get("telnet")
                ssh = request.GET.get("ssh")
                start_date = request.GET.get("start_date")
                end_date = request.GET.get("end_date")
                file_name, out_text = get_connection_log(id)
                return render(
                    request,
                    "connection_log_details.html",
                    {
                        "title": "Connection Details",
                        "itemed": "Logs",
                        "out_text": out_text,
                        "telnet": telnet,
                        "ssh": ssh,
                        "start_date": start_date,
                        "end_date": end_date,
                        "id": id,
                    },
                )

            back_to_connections_log = request.GET.get("back_to_connections_log")
            if back_to_connections_log is not None:
                anchor = back_to_connections_log
                telnet = request.GET.get("telnet")
                ssh = request.GET.get("ssh")
                start_date = request.GET.get("start_date")
                end_date = request.GET.get("end_date")
                connections_logs = get_connections_logs()
                filtered_connections_logs = get_filtered_connections_logs(
                    connections_logs, telnet, ssh, start_date, end_date
                )
                return render(
                    request,
                    "connections_log.html",
                    {
                        "title": "Connections Log",
                        "itemed": "Logs",
                        "connections_logs": filtered_connections_logs,
                        "count": len(filtered_connections_logs),
                        "filtered": True,
                        "telnet": telnet,
                        "ssh": ssh,
                        "start_date": start_date,
                        "end_date": end_date,
                        "anchor": anchor,
                    },
                )

            download_connection_log = request.GET.get("download_connection_log")
            if download_connection_log is not None:
                id = int(download_connection_log)
                file_name, out_text = get_connection_log(id)
                start_adding_users_log(
                    request.session["user_id"],
                    request.session["user_type"],
                    "Download " + file_name + ".",
                    request,
                )
                file_path = write_download_file(file_name, out_text)
                return get_file_response(file_path, file_name)

            filter_connections_charts = request.GET.get("filter_connections_charts")
            if filter_connections_charts == "True":
                start_date = request.GET.get("start_date")
                end_date = request.GET.get("end_date")
                (
                    connections_line_chart_title,
                    connections_line_chart_point_start,
                    sum,
                    telnet,
                    ssh,
                ) = get_connections_line_chart(start_date, end_date)
                (
                    connections_pie_chart_title,
                    connections_pie_chart,
                ) = get_connections_pie_chart(start_date, end_date)
                (
                    regions_pie_chart_title,
                    connection_regions_pie_chart,
                ) = get_connection_regions_pie_chart(start_date, end_date)
                (
                    commands_pie_chart_title,
                    connection_commands_pie_chart,
                ) = get_connection_commands_pie_chart(start_date, end_date)
                return render(
                    request,
                    "connections_charts.html",
                    {
                        "title": "Connections Charts",
                        "itemed": "Charts",
                        "filtered": True,
                        "connections_line_chart_title": connections_line_chart_title,
                        "connections_line_chart_point_start": connections_line_chart_point_start,
                        "sum": sum,
                        "telnet": telnet,
                        "ssh": ssh,
                        "connections_pie_chart_title": connections_pie_chart_title,
                        "connections_pie_chart": connections_pie_chart,
                        "regions_pie_chart_title": regions_pie_chart_title,
                        "connection_regions_pie_chart": connection_regions_pie_chart,
                        "commands_pie_chart_title": commands_pie_chart_title,
                        "connection_commands_pie_chart": connection_commands_pie_chart,
                        "start_date": start_date,
                        "end_date": end_date,
                    },
                )

            if request.session["user_type"] == True:
                new_user = request.GET.get("new_user")
                if new_user == "True":
                    new_user_id = request.GET.get("new_user_id")
                    result = add_visitor(new_user_id)
                    return get_render(
                        request,
                        "new_user.html",
                        {
                            "title": "New User",
                            "result": result,
                            "itemed": "User settings",
                        },
                        "Try to create a new user: " + new_user_id + ".",
                    )

                delete_user = request.GET.get("delete_user")
                if delete_user == "True":
                    user_id_to_delete = request.GET.get("user_id_to_delete")
                    result = delete_visitor(user_id_to_delete)
                    return get_render(
                        request,
                        "delete_user.html",
                        {
                            "title": "Delete User",
                            "result": result,
                            "itemed": "User settings",
                        },
                        "Try to delete: " + user_id_to_delete + ".",
                    )

                set_telnet_honetpot_port = request.GET.get("set_telnet_honetpot_port")
                if set_telnet_honetpot_port == "True":
                    telnet_honeypot_port = request.GET.get("telnet_honeypot_port")
                    result = set_telnet_port(telnet_honeypot_port)
                    (
                        telnet_honeypot_port,
                        ssh_honeypot_port,
                        root,
                        default_directory,
                    ) = get_parameters()
                    count = get_temporary_files_count()
                    return get_render(
                        request,
                        "parameters.html",
                        {
                            "title": "Parameters",
                            "result": result,
                            "telnet_honeypot_port": telnet_honeypot_port,
                            "ssh_honeypot_port": ssh_honeypot_port,
                            "root": root,
                            "default_directory": default_directory,
                            "telnet_honeypot_is_running": get_state("Telnet"),
                            "ssh_honeypot_is_running": get_state("SSH"),
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                            "count": count,
                        },
                        "Try to set telnet honeypot port.",
                    )

                set_ssh_honetpot_port = request.GET.get("set_ssh_honetpot_port")
                if set_ssh_honetpot_port == "True":
                    ssh_honeypot_port = request.GET.get("ssh_honeypot_port")
                    result = set_ssh_port(ssh_honeypot_port)
                    (
                        telnet_honeypot_port,
                        ssh_honeypot_port,
                        root,
                        default_directory,
                    ) = get_parameters()
                    count = get_temporary_files_count()
                    return get_render(
                        request,
                        "parameters.html",
                        {
                            "title": "Parameters",
                            "result": result,
                            "telnet_honeypot_port": telnet_honeypot_port,
                            "ssh_honeypot_port": ssh_honeypot_port,
                            "root": root,
                            "default_directory": default_directory,
                            "telnet_honeypot_is_running": get_state("Telnet"),
                            "ssh_honeypot_is_running": get_state("SSH"),
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                            "count": count,
                        },
                        "Try to set ssh honeypot port.",
                    )

                set_directory = request.GET.get("set_directory")
                if set_directory == "True":
                    root = request.GET.get("root")
                    default_directory = request.GET.get("default_directory")
                    result = set_root_and_default_directory(root, default_directory)
                    (
                        telnet_honeypot_port,
                        ssh_honeypot_port,
                        root,
                        default_directory,
                    ) = get_parameters()
                    count = get_temporary_files_count()
                    return get_render(
                        request,
                        "parameters.html",
                        {
                            "title": "Parameters",
                            "result": result,
                            "telnet_honeypot_port": telnet_honeypot_port,
                            "ssh_honeypot_port": ssh_honeypot_port,
                            "root": root,
                            "default_directory": default_directory,
                            "telnet_honeypot_is_running": get_state("Telnet"),
                            "ssh_honeypot_is_running": get_state("SSH"),
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                            "count": count,
                        },
                        "Try to set directory.",
                    )

                set_honeypot_state = request.GET.get("set_honeypot_state")
                if set_honeypot_state == "True":
                    telnet_honeypot = request.GET.get("telnet_honeypot")
                    ssh_honeypot = request.GET.get("ssh_honeypot")
                    result = set_telnet_and_ssh_state(telnet_honeypot, ssh_honeypot)
                    (
                        telnet_honeypot_port,
                        ssh_honeypot_port,
                        root,
                        default_directory,
                    ) = get_parameters()
                    count = get_temporary_files_count()
                    return get_render(
                        request,
                        "parameters.html",
                        {
                            "title": "Parameters",
                            "result": result,
                            "telnet_honeypot_port": telnet_honeypot_port,
                            "ssh_honeypot_port": ssh_honeypot_port,
                            "root": root,
                            "default_directory": default_directory,
                            "telnet_honeypot_is_running": get_state("Telnet"),
                            "ssh_honeypot_is_running": get_state("SSH"),
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                            "count": count,
                        },
                        "Try to set honeypot state.",
                    )

                empty_temporary_files = request.GET.get("empty_temporary_files")
                if empty_temporary_files == "True":
                    result = empty_temporary()
                    (
                        telnet_honeypot_port,
                        ssh_honeypot_port,
                        root,
                        default_directory,
                    ) = get_parameters()
                    count = get_temporary_files_count()
                    return get_render(
                        request,
                        "parameters.html",
                        {
                            "title": "Parameters",
                            "result": result,
                            "telnet_honeypot_port": telnet_honeypot_port,
                            "ssh_honeypot_port": ssh_honeypot_port,
                            "root": root,
                            "default_directory": default_directory,
                            "telnet_honeypot_is_running": get_state("Telnet"),
                            "ssh_honeypot_is_running": get_state("SSH"),
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                            "count": count,
                        },
                        "Try to empty temporary files.",
                    )

                set_sms_number = request.GET.get("set_sms_number")
                if set_sms_number == "True":
                    sms_number = request.GET.get("sms_number")
                    result = set_number(sms_number)
                    send_sms = get_config_value("send_sms")
                    sms_number = get_config_value("sms_number")
                    sms_sid = get_config_value("sms_sid")
                    return get_render(
                        request,
                        "sms_settings.html",
                        {
                            "title": "SMS Settings",
                            "result": result,
                            "send_sms": send_sms,
                            "sms_number": sms_number,
                            "sms_sid": sms_sid,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set SMS number.",
                    )

                set_sms_sid = request.GET.get("set_sms_sid")
                if set_sms_sid == "True":
                    sms_sid = request.GET.get("sms_sid")
                    result = set_sid(sms_sid)
                    send_sms = get_config_value("send_sms")
                    sms_number = get_config_value("sms_number")
                    sms_sid = get_config_value("sms_sid")
                    return get_render(
                        request,
                        "sms_settings.html",
                        {
                            "title": "SMS Settings",
                            "result": result,
                            "send_sms": send_sms,
                            "sms_number": sms_number,
                            "sms_sid": sms_sid,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set SMS SID.",
                    )

                set_sms_token = request.GET.get("set_sms_token")
                if set_sms_token == "True":
                    sms_token = request.GET.get("sms_token")
                    result = set_token(sms_token)
                    send_sms = get_config_value("send_sms")
                    sms_number = get_config_value("sms_number")
                    sms_sid = get_config_value("sms_sid")
                    return get_render(
                        request,
                        "sms_settings.html",
                        {
                            "title": "SMS Settings",
                            "result": result,
                            "send_sms": send_sms,
                            "sms_number": sms_number,
                            "sms_sid": sms_sid,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set SMS token.",
                    )

                set_sms_alert_state = request.GET.get("set_sms_alert_state")
                if set_sms_alert_state == "True":
                    sms_alert = request.GET.get("sms_alert")
                    result = set_sms_state(sms_alert)
                    send_sms = get_config_value("send_sms")
                    sms_number = get_config_value("sms_number")
                    sms_sid = get_config_value("sms_sid")
                    return get_render(
                        request,
                        "sms_settings.html",
                        {
                            "title": "SMS Settings",
                            "result": result,
                            "send_sms": send_sms,
                            "sms_number": sms_number,
                            "sms_sid": sms_sid,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set SMS alert state.",
                    )

                set_mail_host = request.GET.get("set_mail_host")
                if set_mail_host == "True":
                    mail_host = request.GET.get("mail_host")
                    result = set_host(mail_host)
                    send_mail = get_config_value("send_mail")
                    ssl_port = get_config_value("ssl_port")
                    mail_user = get_config_value("mail_user")
                    mail_host = get_config_value("mail_host")
                    return get_render(
                        request,
                        "mail_settings.html",
                        {
                            "title": "Mail Settings",
                            "result": result,
                            "send_mail": send_mail,
                            "ssl_port": ssl_port,
                            "mail_user": mail_user,
                            "mail_host": mail_host,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set mail host.",
                    )

                set_mail_user = request.GET.get("set_mail_user")
                if set_mail_user == "True":
                    mail_user = request.GET.get("mail_user")
                    result = set_user(mail_user)
                    send_mail = get_config_value("send_mail")
                    ssl_port = get_config_value("ssl_port")
                    mail_user = get_config_value("mail_user")
                    mail_host = get_config_value("mail_host")
                    return get_render(
                        request,
                        "mail_settings.html",
                        {
                            "title": "Mail Settings",
                            "result": result,
                            "send_mail": send_mail,
                            "ssl_port": ssl_port,
                            "mail_user": mail_user,
                            "mail_host": mail_host,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set mail user.",
                    )

                set_mail_password = request.GET.get("set_mail_password")
                if set_mail_password == "True":
                    mail_password = request.GET.get("mail_password")
                    result = set_password(mail_password)
                    send_mail = get_config_value("send_mail")
                    ssl_port = get_config_value("ssl_port")
                    mail_user = get_config_value("mail_user")
                    mail_host = get_config_value("mail_host")
                    return get_render(
                        request,
                        "mail_settings.html",
                        {
                            "title": "Mail Settings",
                            "result": result,
                            "send_mail": send_mail,
                            "ssl_port": ssl_port,
                            "mail_user": mail_user,
                            "mail_host": mail_host,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set mail password.",
                    )

                set_ssl_port = request.GET.get("set_ssl_port")
                if set_ssl_port == "True":
                    ssl_port = request.GET.get("ssl_port")
                    result = set_ssl(ssl_port)
                    send_mail = get_config_value("send_mail")
                    ssl_port = get_config_value("ssl_port")
                    mail_user = get_config_value("mail_user")
                    mail_host = get_config_value("mail_host")
                    return get_render(
                        request,
                        "mail_settings.html",
                        {
                            "title": "Mail Settings",
                            "result": result,
                            "send_mail": send_mail,
                            "ssl_port": ssl_port,
                            "mail_user": mail_user,
                            "mail_host": mail_host,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set SSL port.",
                    )

                set_mail_alert_state = request.GET.get("set_mail_alert_state")
                if set_mail_alert_state == "True":
                    mail_alert = request.GET.get("mail_alert")
                    result = set_mail_state(mail_alert)
                    send_mail = get_config_value("send_mail")
                    ssl_port = get_config_value("ssl_port")
                    mail_user = get_config_value("mail_user")
                    mail_host = get_config_value("mail_host")
                    return get_render(
                        request,
                        "mail_settings.html",
                        {
                            "title": "Mail Settings",
                            "result": result,
                            "send_mail": send_mail,
                            "ssl_port": ssl_port,
                            "mail_user": mail_user,
                            "mail_host": mail_host,
                            "anchor": "anchor",
                            "itemed": "Honeypots settings",
                        },
                        "Try to set mail alert state",
                    )

                filter_users_log = request.GET.get("filter_users_log")
                download_users_log = request.GET.get("download_users_log")
                if filter_users_log == "True" or download_users_log == "True":
                    admin = request.GET.get("admin")
                    visitor = request.GET.get("visitor")
                    start_date = request.GET.get("start_date")
                    end_date = request.GET.get("end_date")
                    users_logs = get_users_logs()
                    filtered_users_logs = get_filtered_users_logs(
                        users_logs, admin, visitor, start_date, end_date
                    )
                    file_name, out_text = get_file_name_and_out_text_of_users_logs(
                        admin, visitor, start_date, end_date, filtered_users_logs
                    )
                    if filter_users_log == "True":
                        return render(
                            request,
                            "users_log.html",
                            {
                                "title": "Users Log",
                                "filtered": True,
                                "count": len(filtered_users_logs),
                                "out_text": out_text,
                                "itemed": "Logs",
                                "admin": admin,
                                "visitor": visitor,
                                "start_date": start_date,
                                "end_date": end_date,
                            },
                        )
                    else:
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Download " + file_name + ".",
                            request,
                        )
                        file_path = write_download_file(file_name, out_text)
                        return get_file_response(file_path, file_name)

                filter_honeypots_log = request.GET.get("filter_honeypots_log")
                download_honeypots_log = request.GET.get("download_honeypots_log")
                if filter_honeypots_log == "True" or download_honeypots_log == "True":
                    telnet = request.GET.get("telnet")
                    ssh = request.GET.get("ssh")
                    sms = request.GET.get("sms")
                    mail = request.GET.get("mail")
                    honeypot_server = request.GET.get("honeypot_server")
                    start_date = request.GET.get("start_date")
                    end_date = request.GET.get("end_date")
                    honeypots_logs = get_honeypots_logs()
                    filtered_honeypots_logs = get_filtered_honeypots_logs(
                        honeypots_logs,
                        telnet,
                        ssh,
                        sms,
                        mail,
                        honeypot_server,
                        start_date,
                        end_date,
                    )
                    file_name, out_text = get_file_name_and_out_text_of_honeypots_logs(
                        telnet,
                        ssh,
                        sms,
                        mail,
                        honeypot_server,
                        start_date,
                        end_date,
                        filtered_honeypots_logs,
                    )
                    if filter_honeypots_log == "True":
                        return render(
                            request,
                            "honeypots_log.html",
                            {
                                "title": "Honeypots Log",
                                "filtered": True,
                                "count": len(filtered_honeypots_logs),
                                "out_text": out_text,
                                "itemed": "Logs",
                                "telnet": telnet,
                                "ssh": ssh,
                                "sms": sms,
                                "mail": mail,
                                "honeypot_server": honeypot_server,
                                "start_date": start_date,
                                "end_date": end_date,
                            },
                        )
                    else:
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Download " + file_name + ".",
                            request,
                        )
                        file_path = write_download_file(file_name, out_text)
                        return get_file_response(file_path, file_name)

                empty_caught_files = request.GET.get("empty_caught_files")
                if empty_caught_files == "True":
                    start_adding_users_log(
                        request.session["user_id"],
                        request.session["user_type"],
                        "Try to empty caught files.",
                        request,
                    )
                    result = empty_caught()
                    caughts = get_caught_paths()
                    return render(
                        request,
                        "caught.html",
                        {
                            "title": "Caught",
                            "caughts": caughts,
                            "result": result,
                            "count": len(caughts),
                            "itemed": "Logs",
                        },
                    )

                download_caught = request.GET.get("download_caught")
                if download_caught is not None:
                    start_adding_users_log(
                        request.session["user_id"],
                        request.session["user_type"],
                        "Try to download " + download_caught,
                        request,
                    )
                    if os.path.isfile(download_caught):
                        file_name = (
                            time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime())
                            + "_"
                            + download_caught.split("/")[-1]
                        )
                        return get_file_response(download_caught, file_name)
                    elif os.path.isdir(download_caught):
                        file_name = (
                            time.strftime("%Y-%m-%d-%H:%M:%S", time.localtime())
                            + "_"
                            + download_caught.split("/")[-2]
                            + ".zip"
                        )
                        return get_file_response(download_caught, file_name)
                    else:
                        caughts = get_caught_paths()
                        return render(
                            request,
                            "caught.html",
                            {
                                "title": "Caught",
                                "caughts": caughts,
                                "result": download_caught + " does not exist.",
                                "count": len(caughts),
                                "itemed": "Logs",
                            },
                        )

                filter_users_charts = request.GET.get("filter_users_charts")
                if filter_users_charts == "True":
                    start_date = request.GET.get("start_date")
                    end_date = request.GET.get("end_date")
                    (
                        users_line_chart_title,
                        users_line_chart_point_start,
                        sum,
                        admin,
                        visitor,
                    ) = get_users_line_chart(start_date, end_date)
                    users_pie_chart_title, users_pie_chart = get_users_pie_chart(
                        start_date, end_date
                    )
                    return render(
                        request,
                        "users_charts.html",
                        {
                            "title": "Users Charts",
                            "itemed": "Charts",
                            "filtered": True,
                            "users_line_chart_title": users_line_chart_title,
                            "users_line_chart_point_start": users_line_chart_point_start,
                            "sum": sum,
                            "admin": admin,
                            "visitor": visitor,
                            "users_pie_chart_title": users_pie_chart_title,
                            "users_pie_chart": users_pie_chart,
                            "start_date": start_date,
                            "end_date": end_date,
                        },
                    )

                filter_honeypots_charts = request.GET.get("filter_honeypots_charts")
                if filter_honeypots_charts == "True":
                    start_date = request.GET.get("start_date")
                    end_date = request.GET.get("end_date")
                    (
                        honeypots_line_chart_title,
                        honeypots_line_chart_point_start,
                        sum,
                        telnet,
                        ssh,
                        sms,
                        mail,
                        honeypot_server,
                    ) = get_honeypots_line_chart(start_date, end_date)
                    (
                        honeypots_pie_chart_title,
                        honeypots_pie_chart,
                    ) = get_honeypots_pie_chart(start_date, end_date)
                    return render(
                        request,
                        "honeypots_charts.html",
                        {
                            "title": "Honeypots Charts",
                            "itemed": "Charts",
                            "filtered": True,
                            "honeypots_line_chart_title": honeypots_line_chart_title,
                            "honeypots_line_chart_point_start": honeypots_line_chart_point_start,
                            "sum": sum,
                            "telnet": telnet,
                            "ssh": ssh,
                            "sms": sms,
                            "mail": mail,
                            "honeypot_server": honeypot_server,
                            "honeypots_pie_chart_title": honeypots_pie_chart_title,
                            "honeypots_pie_chart": honeypots_pie_chart,
                            "start_date": start_date,
                            "end_date": end_date,
                        },
                    )

            page = request.GET.get("page")
            if page == "settings":
                user = get_user(request.session["user_id"])
                return render(
                    request,
                    "user_settings.html",
                    {
                        "title": "User Settings",
                        "result": "",
                        "user": user,
                        "itemed": "User settings",
                    },
                )

            elif page == "connections":
                connections = get_connections()
                return render(
                    request,
                    "connections.html",
                    {
                        "title": "Connections",
                        "connections": connections,
                        "count": len(connections),
                        "itemed": "Logs",
                    },
                )

            elif page == "connections_log":
                return render(
                    request,
                    "connections_log.html",
                    {
                        "title": "Connections Log",
                        "itemed": "Logs",
                    },
                )

            elif page == "connections_charts":
                return render(
                    request,
                    "connections_charts.html",
                    {"title": "Connections Charts", "itemed": "Charts"},
                )

            elif page == "overview" or page is None:
                overview = get_overview()
                return render(
                    request,
                    "overview.html",
                    {
                        "title": "Overview",
                        "overview": overview,
                        "itemed": "Logs",
                    },
                )

            if request.session["user_type"] == False:
                return render(request, "error.html")

            elif page == "all_users":
                all_users = get_all_users()
                return render(
                    request,
                    "all_users.html",
                    {
                        "title": "All Users",
                        "all_users": all_users,
                        "count": len(all_users),
                        "itemed": "User settings",
                    },
                )

            elif page == "new_user":
                return render(
                    request,
                    "new_user.html",
                    {
                        "title": "New User",
                        "result": "",
                        "itemed": "User settings",
                    },
                )

            elif page == "delete_user":
                return render(
                    request,
                    "delete_user.html",
                    {
                        "title": "Delete User",
                        "result": "",
                        "itemed": "User settings",
                    },
                )

            elif page == "parameters":
                (
                    telnet_honeypot_port,
                    ssh_honeypot_port,
                    root,
                    default_directory,
                ) = get_parameters()
                count = get_temporary_files_count()
                return render(
                    request,
                    "parameters.html",
                    {
                        "title": "Parameters",
                        "result": "",
                        "telnet_honeypot_port": telnet_honeypot_port,
                        "ssh_honeypot_port": ssh_honeypot_port,
                        "root": root,
                        "default_directory": default_directory,
                        "telnet_honeypot_is_running": get_state("Telnet"),
                        "ssh_honeypot_is_running": get_state("SSH"),
                        "itemed": "Honeypots settings",
                        "count": count,
                    },
                )

            elif page == "not_allowed_commands":
                not_allowed_commands = get_not_allowed_commands()
                return render(
                    request,
                    "not_allowed_commands.html",
                    {
                        "title": "Not Allowed Commands",
                        "count": len(not_allowed_commands),
                        "not_allowed_commands": not_allowed_commands,
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "usernames":
                usernames = get_usernames()
                return render(
                    request,
                    "usernames.html",
                    {
                        "title": "Usernames",
                        "count": len(usernames),
                        "usernames": usernames,
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "replace_names":
                replace_names = get_replace_names()
                return render(
                    request,
                    "replace_names.html",
                    {
                        "title": "Names to be Replaced",
                        "count": len(replace_names),
                        "replace_names": replace_names,
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "hidden_paths":
                hidden_paths = get_hidden_paths()
                return render(
                    request,
                    "hidden_paths.html",
                    {
                        "title": "Hidden Paths",
                        "count": len(hidden_paths),
                        "hidden_paths": hidden_paths,
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "sms_settings":
                send_sms = get_config_value("send_sms")
                sms_number = get_config_value("sms_number")
                sms_sid = get_config_value("sms_sid")
                return render(
                    request,
                    "sms_settings.html",
                    {
                        "title": "SMS Settings",
                        "send_sms": send_sms,
                        "sms_number": sms_number,
                        "sms_sid": sms_sid,
                        "result": "",
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "mail_settings":
                send_mail = get_config_value("send_mail")
                ssl_port = get_config_value("ssl_port")
                mail_user = get_config_value("mail_user")
                mail_host = get_config_value("mail_host")
                return render(
                    request,
                    "mail_settings.html",
                    {
                        "title": "Mail Settings",
                        "send_mail": send_mail,
                        "ssl_port": ssl_port,
                        "mail_user": mail_user,
                        "mail_host": mail_host,
                        "result": "",
                        "itemed": "Honeypots settings",
                    },
                )

            elif page == "caught":
                caughts = get_caught_paths()
                return render(
                    request,
                    "caught.html",
                    {
                        "title": "Caught",
                        "caughts": caughts,
                        "count": len(caughts),
                        "result": "",
                        "itemed": "Logs",
                    },
                )

            elif page == "users_log":
                return render(
                    request,
                    "users_log.html",
                    {
                        "title": "Users Log",
                        "itemed": "Logs",
                    },
                )

            elif page == "honeypots_log":
                return render(
                    request,
                    "honeypots_log.html",
                    {
                        "title": "Honeypots Log",
                        "itemed": "Logs",
                    },
                )

            elif page == "users_charts":
                return render(
                    request,
                    "users_charts.html",
                    {"title": "Users Charts", "itemed": "Charts"},
                )

            elif page == "honeypots_charts":
                return render(
                    request,
                    "honeypots_charts.html",
                    {"title": "Honeypots Charts", "itemed": "Charts"},
                )

        if request.method == "POST":
            if request.session["user_type"] == True:
                set_not_allowed_commands = request.POST.get("set_not_allowed_commands")
                if set_not_allowed_commands == "True":
                    not_allowed_commands_file = request.FILES.get(
                        "not_allowed_commands_file"
                    )
                    if not_allowed_commands_file is not None:
                        set_not_allowed(not_allowed_commands_file.readlines())
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Set not allowed commands.",
                            request,
                        )
                    not_allowed_commands = get_not_allowed_commands()
                    return render(
                        request,
                        "not_allowed_commands.html",
                        {
                            "title": "Not Allowed Commands",
                            "count": len(not_allowed_commands),
                            "not_allowed_commands": not_allowed_commands,
                            "itemed": "Honeypots settings",
                        },
                    )

                set_usernames = request.POST.get("set_usernames")
                if set_usernames == "True":
                    usernames_file = request.FILES.get("usernames_file")
                    if usernames_file is not None:
                        set_allowed_usernames(usernames_file.readlines())
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Set usernames.",
                            request,
                        )
                    usernames = get_usernames()
                    return render(
                        request,
                        "usernames.html",
                        {
                            "title": "Usernames",
                            "count": len(usernames),
                            "usernames": usernames,
                            "itemed": "Honeypots settings",
                        },
                    )

                set_replace_names = request.POST.get("set_replace_names")
                if set_replace_names == "True":
                    replace_names_file = request.FILES.get("replace_names_file")
                    if replace_names_file is not None:
                        set_replace(replace_names_file.readlines())
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Set replace names.",
                            request,
                        )
                    replace_names = get_replace_names()
                    return render(
                        request,
                        "replace_names.html",
                        {
                            "title": "Names to be Replaced",
                            "count": len(replace_names),
                            "replace_names": replace_names,
                            "itemed": "Honeypots settings",
                        },
                    )

                set_hidden_paths = request.POST.get("set_hidden_paths")
                if set_hidden_paths == "True":
                    hidden_paths_file = request.FILES.get("hidden_paths_file")
                    if hidden_paths_file is not None:
                        set_hidden(hidden_paths_file.readlines())
                        start_adding_users_log(
                            request.session["user_id"],
                            request.session["user_type"],
                            "Set hidden paths.",
                            request,
                        )
                    hidden_paths = get_hidden_paths()
                    return render(
                        request,
                        "hidden_paths.html",
                        {
                            "title": "Hidden Paths",
                            "count": len(hidden_paths),
                            "hidden_paths": hidden_paths,
                            "itemed": "Honeypots settings",
                        },
                    )

    return render(request, "error.html")
