import smtplib
from email.mime.text import MIMEText
from email.header import Header
from NCUT_Pot.database import get_config_value, start_adding_honeypots_log


def send_mail(mails, params):
    """Send mail using smtplib."""
    mail_host = get_config_value("mail_host")
    mail_user = get_config_value("mail_user")
    mail_password = get_config_value("mail_password")
    message = MIMEText(
        "Warn! {0} connected to the {1} honeypot at {2}.".format(
            params[0], params[1], params[2]
        ),
        "plain",
        "utf-8",
    )
    subject = "NCUT-Pot"
    message["Subject"] = Header(subject, "utf-8")
    try:
        smtp = smtplib.SMTP_SSL(mail_host, get_config_value("ssl_port"))
        smtp.login(mail_user, mail_password)
        smtp.sendmail(mail_user, mails, message.as_string())
        start_adding_honeypots_log("Mail", "Mails has been sent.")
    except smtplib.SMTPException:
        start_adding_honeypots_log("Mail", "Mail sending error.")