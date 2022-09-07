from django.db import models

class Users(models.Model):
    user_id = models.TextField()
    user_password = models.TextField()
    salt = models.TextField()
    user_type = models.BooleanField(default=False)  # True: admin, False: vistor
    phone_number = models.TextField(null=True)
    mail_address = models.TextField(null=True)


class Users_log(models.Model):
    user_id = models.TextField()
    user_type = models.BooleanField()
    time = models.TextField()
    action = models.TextField()
    ip = models.TextField()


class Connections(models.Model):
    ip = models.TextField()
    honeypot_type = models.TextField()
    country = models.TextField()
    city = models.TextField()


class Connections_log(models.Model):
    ip = models.TextField()
    time = models.TextField()
    honeypot_type = models.TextField()
    action = models.TextField()


class Honeypots_log(models.Model):
    time = models.TextField()
    honeypot_type = models.TextField()
    action = models.TextField()


class Caught(models.Model):
    path = models.TextField()


class Passwords(models.Model):
    password = models.TextField()


class Usernames(models.Model):
    username = models.TextField()


class Replace_names(models.Model):
    replace_name = models.TextField()


class Hidden_paths(models.Model):
    hidden_path = models.TextField()


class Not_allowed_commands(models.Model):
    not_allowed_command = models.TextField()


class Configs(models.Model):
    telnet_honeypot_port = models.PositiveIntegerField(default=23)
    ssh_honeypot_port = models.PositiveIntegerField(default=22)
    default_directory = models.TextField(default="/home/ubuntu/")
    root = models.TextField(default="/")
    send_mail = models.BooleanField(default=False)
    mail_host = models.TextField()
    mail_user = models.TextField()
    mail_password = models.TextField()
    ssl_port = models.PositiveIntegerField(default=465)
    send_sms = models.BooleanField(default=False)
    sms_number = models.TextField()
    sms_sid = models.TextField()
    sms_token = models.TextField()
