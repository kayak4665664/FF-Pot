import os
from .telnet_handler import TelnetHandler, command
from .command_execution import get_out_text, output
import copy
import random
from .alert import start_alert
from .fake_files import (
    change_prompt,
    get_parent_path,
    get_real_path,
    get_fake_dir,
    get_fake_file,
    file_exists,
    dir_exists,
    change_directory,
    get_real_params,
    separate_paths_and_params,
    get_fake_output_text,
    check_permission,
    separate_urls_and_params,
)
from NCUT_Pot.database import (
    get_usernames,
    get_passwords,
    start_adding_connections,
    start_adding_connections_log,
    start_adding_path_to_caught,
    get_connection_id,
    start_adding_password,
    start_renaming_path_in_caught,
)


class TelnetHoneypot(TelnetHandler):

    # Override items to customize the honeypot

    WELCOME = """
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-96-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
 """
    authNeedUser = True
    authNeedPass = True

    def authCallback(self, username, password):
        """Called to validate the username/password."""
        self.honeypot_type = "Telnet"
        usernames = get_usernames()
        if username not in usernames:
            raise
        count = int(0)
        passwords = get_passwords()
        wrong_passwords = []
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
                password = self.readline(
                    prompt="Permission denied, please try again.\nPassword: ",
                    echo=False,
                    use_history=False,
                )
        self.password = password

    def session_start(self):
        """Called after the user successfully logs in."""
        start_adding_connections(self.ip, self.honeypot_type)
        start_adding_connections_log(self.ip, self.honeypot_type, "START")
        start_adding_password(self.password)
        self.id = get_connection_id(self.ip, self.honeypot_type)
        self.pipe_file = "/temporary_files/" + str(self.id) + ".txt"
        self.PROMPT = change_prompt(
            self.username, self.root, self.directory, self.default_directory
        )
        start_alert(self.ip, self.honeypot_type)

    def session_end(self):
        """Called after the user logs off."""
        pass

    @command("cal")
    def command_cal(self, params):
        out_text = get_out_text(self, "cal", params)
        output(self, out_text)

    @command("cat")
    def command_cat(self, params):
        real_params, append_directory = get_real_params(
            params, self.root, self.directory, self.default_directory, self.username
        )
        if append_directory == True:
            out_text = get_out_text(self, "cat", real_params, missing_argument=True)
            output(self, out_text)
        else:
            out_text = ""
            error_out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            for p in paths:
                if out_text != "":
                    out_text += "\n"
                if error_out_text != "":
                    error_out_text += "\n"
                if dir_exists(p[0]):
                    result = False
                    error_out_text += "cat: " + params[p[1]] + " is a directory"
                elif file_exists(p[0]):
                    if not check_permission(p[0]):
                        result = False
                        error_out_text += "cat: " + params[p[1]] + ": Permission denied"
                    else:
                        temporary_params = copy.deepcopy(params_without_paths)
                        temporary_params.append(p[0])
                        out_text += get_out_text(
                            self, "cat", temporary_params, change_cmd_result=False
                        )
                else:
                    result = False
                    error_out_text += (
                        "cat: " + params[p[1]] + ": No such file or directory"
                    )
            self.result = result
            output(
                self, out_text, error=error_out_text, ignore_result=True, replace=False
            )

    @command("cd")
    def command_cd(self, params):
        if len(params) > 1:
            self.result = False
            output(self, error="-bash: cd: too many arguments")
        else:
            real_path = get_real_path(
                params[0],
                self.root,
                self.directory,
                self.default_directory,
                self.username,
            )
            if dir_exists(real_path):
                self.directory, self.PROMPT = change_directory(
                    real_path, self.root, self.default_directory, self.username
                )
                self.result = True
                output(self, new_line=False)
            else:
                self.result = False
                output(
                    self,
                    error="-bash: cd: %s: No such file or directory" % params[0],
                )

    @command("chmod")
    def command_chmod(self, params):
        if params == [] or len(params) == 1:
            self.result = False
            error = """usage:  chmod [-fhv] [-R [-H | -L | -P]] [-a | +a | =a  [i][# [ n]]] mode|entry file ...
        chmod [-fhv] [-R [-H | -L | -P]] [-E | -C | -N | -i | -I] file ..."""
            output(self, error=error, replace=False)
        else:
            real_params, append_directory = get_real_params(
                params[1:],
                self.root,
                self.directory,
                self.default_directory,
                self.username,
            )
            error_out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            params_without_paths = [params[0]]
            for p in paths:
                if error_out_text != "":
                    error_out_text += "\n"
                if dir_exists(p[0]) or file_exists(p[0]):
                    if not check_permission(p[0]):
                        result = False
                        error_out_text += (
                            "chmod: " + params[p[1] + 1] + ": Permission denied"
                        )
                    else:
                        temporary_params = copy.deepcopy(params_without_paths)
                        temporary_params.append(p[0])
                        get_out_text(
                            self,
                            "chmod",
                            temporary_params,
                        )
                else:
                    result = False
                    error_out_text += (
                        "chmod: " + params[p[1] + 1] + ": No such file or directory"
                    )
            self.result = result
            output(
                self,
                "",
                error=error_out_text,
                ignore_result=True,
                new_line=False,
                replace=False,
            )

    @command("clear")
    def command_clear(self, params):
        out_text = get_out_text(self, "clear", [])
        output(self, out_text, new_line=False)

    @command("cp")
    def command_cp(self, params):
        if params == []:
            self.result = False
            out_text = """cp: missing file operand
Try 'cp --help' for more information."""
            output(self, out_text, error="", ignore_result=True)
        else:
            real_params, append_directory = get_real_params(
                params, self.root, self.directory, self.default_directory, self.username
            )
            if append_directory == True:
                out_text = get_out_text(self, "cp", real_params)
                output(self, out_text)
            else:
                paths, params_without_paths = separate_paths_and_params(real_params)
                if len(paths) == 1:
                    self.result = False
                    out_text = (
                        "cp: missing destination file operand after '"
                        + params[paths[0][1]]
                        + "'\n"
                        + "Try 'cp --help' for more information."
                    )
                    output(self, out_text, error="", ignore_result=True)
                else:
                    if len(paths) == 2:
                        source = paths[0]
                        dest = paths[1]
                        real_params_without_paths = []
                        if "-r" in params or "-R" in params:
                            real_params_without_paths.append("-r")
                        if not dir_exists(source[0]) and not file_exists(source[0]):
                            self.result = False
                            out_text = (
                                "cp: cannot stat '"
                                + params[source[1]]
                                + "': No such file or directory"
                            )
                            output(self, out_text, error="", ignore_result=True)
                        elif (
                            dir_exists(source[0])
                            and "-r" not in real_params_without_paths
                        ):
                            self.result = False
                            out_text = (
                                "cp: -r not specified; omitting directory '"
                                + params[source[1]]
                                + "'"
                            )
                            output(self, out_text, error="", ignore_result=True)
                        elif not dir_exists(get_parent_path(dest[0])):
                            self.result = False
                            out_text = (
                                "cp: cannot create directory  '"
                                + params[dest[1]]
                                + "': No such file or directory"
                            )
                            output(self, out_text, error="", ignore_result=True)
                        elif os.path.isdir(dest[0]) or os.path.isfile(dest[0]):
                            self.result = False
                            output(self, "", ignore_result=True)
                        elif check_permission(source[0]) == False:
                            self.result = False
                            out_text = "cp: permission denied"
                            output(self, out_text, error="", ignore_result=True)
                        else:
                            real_params_without_paths.append(source[0])
                            real_params_without_paths.append(dest[0])
                            get_out_text(self, "cp", real_params_without_paths)
                            if os.path.isdir(source[0]) and dest[0][-1] != "/":
                                dest[0] += "/"
                            start_adding_path_to_caught(dest[0])
                            output(self, "")
                    else:
                        self.result = False
                        out_text = "mkdir: too many arguments"
                        output(self, out_text, error="", ignore_result=True)

    @command("date")
    def command_date(self, params):
        out_text = get_out_text(self, "date", params)
        output(self, out_text)

    @command("echo")
    def command_echo(self, params):
        out_text = get_out_text(self, "echo", params)
        output(self, out_text)

    @command("grep")
    def command_grep(self, params):
        if params == []:
            self.result = False
            error = """usage: grep [-abcdDEFGHhIiJLlMmnOopqRSsUVvwXxZz] [-A num] [-B num] [-C[num]]
        [-e pattern] [-f file] [--binary-files=value] [--color=when]
        [--context[=num]] [--directories=action] [--label] [--line-buffered]
        [--null] [pattern] [file ...]"""
            output(self, error=error, replace=False)
        else:
            if params[0][0] == "-":
                self.result = False
                output(self)
            else:
                real_params, append_directory = get_real_params(
                    params[1:],
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                )
                if append_directory == True:
                    real_params.insert(0, params[0])
                    out_text = get_fake_output_text(
                        get_out_text(self, "grep", real_params, missing_argument=True),
                        self.username,
                        self.directory,
                    )
                    output(self, out_text)
                else:
                    out_text = ""
                    error_out_text = ""
                    result = True
                    paths, params_without_paths = separate_paths_and_params(real_params)
                    for p in paths:
                        if out_text != "":
                            out_text += "\n"
                        if error_out_text != "":
                            error_out_text += "\n"
                        if dir_exists(p[0]):
                            result = False
                            error_out_text += (
                                "grep: " + params[p[1] + 1] + " is a directory"
                            )
                        elif file_exists(p[0]):
                            if not check_permission(p[0]):
                                result = False
                                error_out_text += (
                                    "grep: " + params[p[1] + 1] + ": Permission denied"
                                )
                            else:
                                temporary_params = copy.deepcopy(params_without_paths)
                                temporary_params.append(p[0])
                                temporary_params.insert(0, params[0])
                                text = get_fake_output_text(
                                    get_out_text(
                                        self,
                                        "grep",
                                        temporary_params,
                                        change_cmd_result=False,
                                    ),
                                    self.username,
                                    self.directory,
                                )
                                if text != "" and len(paths) > 1:
                                    out_text += params[p[1] + 1] + ":" + text
                                elif text != "" and len(paths) == 1:
                                    out_text += text
                        else:
                            result = False
                            out_text += (
                                "grep: "
                                + params[p[1] + 1]
                                + ": No such file or directory"
                            )
                    self.result = result
                    output(
                        self,
                        out_text,
                        error=error_out_text,
                        ignore_result=True,
                        replace=False,
                    )

    @command("less")
    def command_less(self, params):
        real_params, append_directory = get_real_params(
            params, self.root, self.directory, self.default_directory, self.username
        )
        if append_directory == True:
            out_text = get_out_text(self, "less", real_params)
            output(self, get_fake_output_text(out_text, self.username, self.directory))
        else:
            out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            for p in paths:
                if out_text != "":
                    out_text += "\n"
                if dir_exists(p[0]):
                    result = False
                    out_text += params[p[1]] + " is a directory"
                elif file_exists(p[0]):
                    if not check_permission(p[0]):
                        result = False
                        out_text += params[p[1]] + ": Permission denied"
                    else:
                        temporary_params = copy.deepcopy(params_without_paths)
                        temporary_params.append(p[0])
                        out_text += params[p[1]] + ":\n"
                        out_text += get_out_text(
                            self, "less", temporary_params, change_cmd_result=False
                        )
                else:
                    result = False
                    out_text += params[p[1]] + ": No such file or directory"
            self.result = result
            output(self, out_text, error="", ignore_result=True)

    @command("ls")
    def command_ls(self, params):
        real_params, append_directory = get_real_params(
            params, self.root, self.directory, self.default_directory, self.username
        )
        if append_directory == True:
            real_params.append(self.directory)
            out_text = get_out_text(self, "ls", real_params)
            output(self, get_fake_output_text(out_text, self.username, self.directory))
        else:
            file_out_text = ""
            dir_out_text = ""
            error_out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            for p in paths:
                if dir_exists(p[0]):
                    temporary_params = copy.deepcopy(params_without_paths)
                    temporary_params.append(p[0])
                    if dir_out_text != "":
                        dir_out_text += "\n\n"
                    if len(paths) > 1:
                        dir_out_text += (
                            get_fake_dir(
                                p[0], self.root, self.default_directory, self.username
                            )
                            + ":\n"
                        )
                    dir_out_text += get_fake_output_text(
                        get_out_text(
                            self, "ls", temporary_params, change_cmd_result=False
                        ),
                        self.username,
                        p[0],
                    )
                elif file_exists(p[0]):
                    temporary_params = copy.deepcopy(params_without_paths)
                    temporary_params.append(p[0])
                    if file_out_text != "":
                        file_out_text += "\n"
                    file_out_text += get_fake_output_text(
                        get_out_text(
                            self, "ls", temporary_params, change_cmd_result=False
                        ),
                        self.username,
                        p[0],
                    )
                else:
                    result = False
                    if error_out_text != "":
                        error_out_text += "\n"
                    error_out_text += (
                        "ls: cannot access '%s': No such file or directory"
                        % params[p[1]]
                    )
            self.result = result
            out_text = file_out_text
            if dir_out_text != "":
                if out_text != "":
                    out_text += "\n\n"
                elif error_out_text != "":
                    out_text += "\n"
                out_text += dir_out_text
            output(
                self, out_text, error=error_out_text, ignore_result=True, replace=False
            )

    @command("mkdir")
    def command_mkdir(self, params):
        if params == []:
            self.result = False
            error_out_text = """mkdir: missing operand
Try 'mkdir --help' for more information."""
            output(self, error=error_out_text, replace=False)
        else:
            real_params, append_directory = get_real_params(
                params, self.root, self.directory, self.default_directory, self.username
            )
            if append_directory == True:
                out_text = get_out_text(self, "mkdir", real_params)
                output(self, out_text)
            else:
                out_text = ""
                result = True
                paths, params_without_paths = separate_paths_and_params(real_params)
                for p in paths:
                    if out_text != "":
                        out_text += "\n"
                    if dir_exists(p[0]) or file_exists(p[0]):
                        result = False
                        out_text = (
                            "mkdir: cannot create directory ‘"
                            + params[p[1]]
                            + "’: File exists"
                        )
                    elif not dir_exists(get_parent_path(p[0])):
                        result = False
                        out_text = (
                            "mkdir: cannot create directory ‘"
                            + params[p[1]]
                            + "’: No such file or directory"
                        )
                    elif not os.path.isdir(p[0]):
                        temporary_params = []
                        temporary_params.append(p[0])
                        get_out_text(
                            self, "mkdir", temporary_params, change_cmd_result=False
                        )
                        if p[0][-1] != "/":
                            p[0] += "/"
                        start_adding_path_to_caught(p[0])
                    else:
                        result = False
                self.result = result
                output(self, out_text, error="")

    @command("mv")
    def command_mv(self, params):
        if params == []:
            self.result = False
            out_text = """mv: missing file operand
Try 'mv --help' for more information."""
            output(self, out_text, error="", ignore_result=True)
        else:
            real_params, append_directory = get_real_params(
                params, self.root, self.directory, self.default_directory, self.username
            )
            if append_directory == True:
                out_text = get_out_text(self, "mv", real_params)
                output(self, out_text)
            else:
                paths, params_without_paths = separate_paths_and_params(real_params)
                if len(paths) == 1:
                    self.result = False
                    out_text = (
                        "mv: missing destination file operand after '"
                        + params[paths[0][1]]
                        + "'\n"
                        + "Try 'mv --help' for more information."
                    )
                    output(self, out_text, error="", ignore_result=True)
                else:
                    if len(paths) == 2:
                        source = paths[0]
                        dest = paths[1]
                        real_params_without_paths = []
                        if not dir_exists(source[0]) and not file_exists(source[0]):
                            self.result = False
                            out_text = (
                                "mv: cannot stat '"
                                + params[source[1]]
                                + "': No such file or directory"
                            )
                            output(self, out_text, error="", ignore_result=True)
                        elif not dir_exists(get_parent_path(dest[0])):
                            self.result = False
                            out_text = (
                                "mv: cannot move '"
                                + params[source[1]]
                                + "' to '"
                                + params[dest[1]]
                                + "': No such file or directory"
                            )
                            output(self, out_text, error="", ignore_result=True)
                        elif os.path.isdir(dest[0]) or os.path.isfile(dest[0]):
                            self.result = False
                            output(self, "", ignore_result=True)
                        elif check_permission(source[0]) == False:
                            self.result = False
                            out_text = "mv: permission denied"
                            output(self, out_text, error="", ignore_result=True)
                        else:
                            real_params_without_paths.append(source[0])
                            real_params_without_paths.append(dest[0])
                            get_out_text(self, "mv", real_params_without_paths)
                            if os.path.isdir(dest[0]):
                                if dest[0][-1] != "/":
                                    dest[0] += "/"
                                if source[0][-1] != "/":
                                    source[0] += "/"
                            start_renaming_path_in_caught(source[0], dest[0])
                            output(self, "")
                    else:
                        self.result = False
                        out_text = "mv: too many arguments"
                        output(self, out_text, error="", ignore_result=True)

    @command("pwd")
    def command_pwd(self, params):
        real_params, append_directory = get_real_params(
            params, self.root, self.directory, self.default_directory, self.username
        )
        if append_directory == False:
            self.result = False
            output(self, error="pwd: too many arguments")
        else:
            error_index = int(-1)
            for index in range(len(params)):
                if params[index] != "-L" and params[index] != "-P":
                    self.result = False
                    error_index = index
                    break
            if error_index == -1:
                self.result = True
                output(
                    self,
                    get_fake_dir(
                        self.directory, self.root, self.default_directory, self.username
                    ),
                )
            else:
                self.result = False
                output(self, error="pwd: bad option: " + params[error_index])

    @command("sudo")
    def command_sudo(self, params):
        self.result = False
        if params == []:
            error = """usage: sudo -h | -K | -k | -V
usage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]
usage: sudo -l [-AknS] [-g group] [-h host] [-p prompt] [-U user] [-u user] [command]
usage: sudo [-AbEHknPS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] [VAR=value] [-i|-s] [<command>]
usage: sudo -e [-AknS] [-r role] [-t type] [-C num] [-g group] [-h host] [-p prompt] [-T timeout] [-u user] file ..."""
            output(self, error=error, replace=False)
        else:
            output(self, error="sudo: permission denied")

    @command("stat")
    def command_stat(self, params):
        real_params, append_directory = get_real_params(
            params, self.root, self.directory, self.default_directory, self.username
        )
        if append_directory == True:
            real_params.append(self.directory)
            out_text = get_out_text(self, "stat", real_params)
            output(self, get_fake_output_text(out_text, self.username, self.directory))
        else:
            out_text = ""
            error_out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            for p in paths:
                if dir_exists(p[0]) or file_exists(p[0]):
                    temporary_params = copy.deepcopy(params_without_paths)
                    temporary_params.append(p[0])
                    if out_text != "":
                        out_text += "\n"
                    out_text += get_fake_output_text(
                        get_out_text(
                            self, "stat", temporary_params, change_cmd_result=False
                        ),
                        self.username,
                        p[0],
                    )
                else:
                    result = False
                    if error_out_text != "":
                        error_out_text += "\n"
                    error_out_text += (
                        "stat: '%s': stat: No such file or directory" % params[p[1]]
                    )
            self.result = result
            output(
                self, out_text, error=error_out_text, ignore_result=True, replace=False
            )

    @command("touch")
    def command_touch(self, params):
        if params == []:
            self.result = False
            error_out_text = """touch: missing file operand
Try 'touch --help' for more information."""
            output(self, error=error_out_text, replace=False)
        else:
            real_params, append_directory = get_real_params(
                params, self.root, self.directory, self.default_directory, self.username
            )
            if append_directory == True:
                out_text = get_out_text(self, "touch", real_params)
                output(self, out_text)
            else:
                error_out_text = ""
                result = True
                paths, params_without_paths = separate_paths_and_params(real_params)
                for p in paths:
                    if error_out_text != "":
                        error_out_text += "\n"
                    if dir_exists(p[0]) or file_exists(p[0]):
                        temporary_params = copy.deepcopy(params_without_paths)
                        temporary_params.append(p[0])
                        get_out_text(
                            self, "touch", temporary_params, change_cmd_result=False
                        )
                    elif (
                        p[0][-1] == "/"
                        or not dir_exists(get_parent_path(p[0]))
                        or os.path.isdir(p[0])
                    ):
                        result = False
                        error_out_text += (
                            "touch: setting times of "
                            + params[p[1]]
                            + ": No such file or directory"
                        )
                    else:
                        file_path = p[0]
                        temporary_params = copy.deepcopy(params_without_paths)
                        temporary_params.append(p[0])
                        get_out_text(
                            self, "touch", temporary_params, change_cmd_result=False
                        )
                        start_adding_path_to_caught(file_path)
                self.result = result
                output(self, error=error_out_text, replace=False)

    @command("wget")
    def command_wget(self, params):
        if params == []:
            self.result = False
            out_text = """wget: missing URL
Usage: wget [OPTION]... [URL]...

Try `wget --help' for more options."""
            output(self, out_text=out_text, error="", ignore_result=True)
        else:
            urls, params_without_urls = separate_urls_and_params(params)
            if urls == []:
                real_params_without_urls, append_directory = get_real_params(
                    params_without_urls,
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                )
                out_text = get_out_text(self, "wget", real_params_without_urls)
                print(out_text)
                output(self, out_text, error="", ignore_result=True)
            else:
                result = True
                out_text = ""
                for url in urls:
                    if out_text != "":
                        out_text += "\n"
                    file_name = ""
                    for string in list(reversed(url.split("/"))):
                        if string != "":
                            file_name = string
                            break
                    file_path = self.directory + file_name
                    if os.path.isdir(file_path) or os.path.isfile(file_path):
                        num = int(2)
                        while os.path.isdir(
                            file_path + " " + str(num)
                        ) or os.path.isfile(file_path + " " + str(num)):
                            num += 1
                        file_path += " " + str(num)
                    temporary_params = ["-O"]
                    temporary_params.append(file_path)
                    temporary_params.append(url)
                    out_text += get_fake_output_text(
                        get_out_text(self, "wget", temporary_params),
                        self.username,
                        self.directory,
                    )
                    if self.result == False:
                        result = False
                    start_adding_path_to_caught(file_path)
                self.result = result
                output(self, out_text, error="", ignore_result=True)

    @command("which")
    def command_which(self, params):
        real_params, append_directory = get_real_params(
            params,
            self.root,
            self.directory,
            self.default_directory,
            self.username,
            change_file_params=False,
        )
        if append_directory == True:
            result = False
        else:
            out_text = ""
            result = True
            paths, params_without_paths = separate_paths_and_params(real_params)
            for p in paths:
                if out_text != "":
                    out_text += "\n"
                temporary_params = copy.deepcopy(params_without_paths)
                temporary_params.append(p[0])
                text = get_out_text(
                    self, "which", temporary_params, change_cmd_result=False
                )
                if text == "":
                    result = False
                    out_text += params[p[1]] + " not found"
                elif file_exists(text):
                    out_text += get_fake_file(
                        text, self.root, self.default_directory, self.username
                    )
                else:
                    result = False
                    out_text += params[p[1]] + " not found"
            self.result = result
            output(self, out_text, error="", ignore_result=True)
