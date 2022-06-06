import os
from pathlib import Path
import subprocess
import zipfile
from django.core.validators import URLValidator
from NCUT_Pot.database import (
    get_hidden_paths,
    get_caught_paths,
    start_adding_path_to_caught,
    get_replace_names,
)


def set_pipe_output(pipe_file, out_text):
    with open(os.path.abspath(os.path.dirname(__file__)) + pipe_file, "w") as output:
        output.write(out_text)


def get_parent_path(path):
    parent_path = os.path.dirname(path)
    if path[-1] == "/":
        parent_path = os.path.dirname(parent_path)
    return parent_path


def get_real_path(fake_path, root, directory, default_directory, username):
    """Fake path to real path."""
    is_dir = False
    if fake_path != "" and fake_path[-1] == "/":
        is_dir = True
    path = fake_path.split("/")
    if path[0] == "":
        real_path = "/"
    elif path[0] == "~" or path[0] == "~" + username:
        user_directory = default_directory
        real_path = user_directory.replace(root, "/", 1)
        path[0] = ""
    else:
        real_path = directory.replace(root, "/", 1)
    for p in path:
        if p == "." or p == "":
            continue
        elif p == "..":
            real_path = get_parent_path(real_path)
        else:
            if real_path[-1] != "/":
                real_path += "/"
            real_path += p
    real_path = root[:-1] + real_path
    parent_path = get_parent_path(default_directory)
    if real_path.lower().startswith(parent_path.lower()):
        real_path = real_path.replace(
            parent_path + "/" + username, default_directory[:-1], 1
        )
    if is_dir and real_path[-1] != "/":
        real_path += "/"
    return real_path


def get_fake_dir(real_dir, root, default_directory, username):
    """Real dir path to fake dir path."""
    if real_dir[-1] != "/":
        real_dir += "/"
    if real_dir.lower().startswith(default_directory.lower()):
        fake_dir = default_directory.split("/")
        fake_dir[-2] = username
        fake_dir = "/".join(fake_dir)
        fake_dir = real_dir.replace(default_directory, fake_dir, 1)
    else:
        fake_dir = real_dir
    fake_dir = fake_dir.replace(root, "/", 1)
    return fake_dir


def get_fake_file(real_file, root, default_directory, username):
    """Real file path to fake file path."""
    if real_file.lower().startswith(default_directory.lower()):
        fake_file = default_directory.split("/")
        fake_file[-2] = username
        fake_file = "/".join(fake_file)
        fake_file = real_file.replace(default_directory, fake_file, 1)
    else:
        fake_file = real_file
    fake_file = fake_file.replace(root, "/", 1)
    return fake_file


def change_prompt(username, root, directory, default_directory):
    if directory == default_directory:
        dir = "~"
    else:
        fake_path = get_fake_dir(directory, root, default_directory, username)
        if fake_path[-1] == "/":
            fake_path = fake_path[:-1]
        dir = fake_path.split("/")[-1]
        if dir == "":
            dir = "/"
    return (
        "\x1b[1;32m" + username + "@20-04-ubuntu\x1b[0m:\x1b[1;34m" + dir + "\x1b[0m$ "
    )  # username@20-04-ubuntu:dir$


def change_directory(real_path, root, default_directory, username):
    if real_path[-1] != "/":
        real_path += "/"
    return real_path, change_prompt(username, root, real_path, default_directory)


def file_exists(real_path):
    path = Path(real_path)
    if not path.is_file():
        return False
    hidden_paths = get_hidden_paths()
    for hidden_path in hidden_paths:
        if real_path.lower().startswith(hidden_path.lower()):
            return False
    return True


def dir_exists(real_path):
    if real_path[-1] != "/":
        real_path += "/"
    path = Path(real_path)
    if not path.is_dir():
        return False
    hidden_paths = get_hidden_paths()
    for hidden_path in hidden_paths:
        if real_path.lower().startswith(hidden_path.lower()):
            return False
    return True


def check_file_owner(real_file):
    out_bytes = subprocess.check_output(
        ["ls", "-l", real_file], stderr=subprocess.STDOUT
    )
    out_text = out_bytes.decode("utf-8")
    owner = out_text.split()[2]
    if owner != "root":
        return True
    else:
        return False


def check_permission(real_file):
    caught_paths = get_caught_paths()
    if os.path.isdir(real_file) and real_file[-1] != "/":
        real_file += "/"
    if real_file in caught_paths:
        return True
    else:
        return False


def check_redirect(redirect, root, directory, default_directory, username):
    for char in redirect:
        fake_path = redirect[char]
        real_path = get_real_path(
            fake_path, root, directory, default_directory, username
        )
        if dir_exists(real_path):
            return "-bash: " + fake_path + ": Is a directory"
        if char == "<":
            if not file_exists(real_path):
                return "-bash: " + fake_path + ": No such file or directory"
            if not check_permission(real_path):
                return "-bash: " + fake_path + ": Permission denied"
        else:
            if not file_exists(real_path):
                if Path(real_path).is_file() == True:
                    return "-bash: command execution error"
                if not dir_exists(os.path.dirname(real_path)):
                    return "-bash: " + fake_path + ": No such file or directory"
            elif not check_permission(real_path):
                return "-bash: " + fake_path + ": Permission denied"
    return ""


def write_file(real_file, out_text):
    with open(real_file, "w") as output:
        start_adding_path_to_caught(real_file)
        output.write(out_text)


def append_file(real_file, out_text):
    with open(real_file, "a") as output:
        start_adding_path_to_caught(real_file)
        output.write(out_text)


def url_validator(url):
    validator = URLValidator()
    try:
        validator(url)
        return True
    except:
        return False


def separate_urls_and_params(params):
    index = int(0)
    urls = []
    params_without_urls = []
    for index in range(len(params)):
        if url_validator(params[index]):
            urls.append(params[index])
        else:
            params_without_urls.append(params[index])
    return urls, params_without_urls


def get_real_params(
    params, root, directory, default_directory, username, change_file_params=True
):
    real_params = []
    append_directory = True
    for param in params:
        if param[0] == "-" or param[0] == "=":
            real_params.append(param)
        else:
            if change_file_params:
                real_params.append(
                    get_real_path(param, root, directory, default_directory, username)
                )
            else:
                real_params.append(param)
            append_directory = False
    return real_params, append_directory


def separate_paths_and_params(params):
    index = int(0)
    paths = []
    params_without_paths = []
    for index in range(len(params)):
        if params[index][0] != "-":
            paths.append([params[index], index])
        else:
            params_without_paths.append(params[index])
    return paths, params_without_paths


def replace_username(text, username):
    replace_names = get_replace_names()
    for replace_name in replace_names:
        text = text.replace(replace_name, username)
    return text


def get_fake_output_text(output_text, username, real_path):
    fake_output_text = ""
    paths = get_hidden_paths()
    hidden_paths = []
    for path in paths:
        parent_path = get_parent_path(path)
        if real_path[-1] == "/" and parent_path[-1] != "/":
            parent_path += "/"
        if parent_path == real_path:
            path = path.split("/")
            if path[-1] == "":
                hidden_paths.append(path[-2])
            else:
                hidden_paths.append(path[-1])
    for line in output_text.splitlines():
        hidden = False
        for hidden_path in hidden_paths:
            if hidden_path.lower() in line.lower():
                hidden = True
                break
        if hidden == False:
            if fake_output_text != "":
                fake_output_text += "\n"
            fake_output_text += line
    fake_output_text = replace_username(fake_output_text, username)
    return fake_output_text


def get_all_paths(root, directory, default_directory, username):
    paths = []
    out_bytes = subprocess.check_output(
        ["ls", "-a", directory], stderr=subprocess.STDOUT
    )
    out_text = out_bytes.decode("utf-8")
    for path in out_text.splitlines():
        real_path = get_real_path(path, root, directory, default_directory, username)
        if file_exists(real_path):
            paths.append(path)
        elif dir_exists(real_path):
            paths.append(path + "/")
    return paths


def get_longest_common_prefix(completions):
    prefix = completions[0]
    index = int(1)
    while index < len(completions):
        while completions[index].find(prefix) != 0:
            prefix = prefix[0 : len(prefix) - 1]
        index += 1
    return prefix


def get_tokens(input):
    input = input.lstrip().split(" ")
    if len(input) == 1 and "/" not in input[0] and "." not in input[0]:
        return input[0], True
    else:
        next = ""
        index = len(input) - 1
        while index >= 0:
            if input[index] != "":
                if next != "":
                    next = input[index]
                    break
                else:
                    next = input[index]
            index -= 1
        if (
            len(input) > 1
            and next in ["|", "||", "&&", ";", "sudo"]
            and input[-1] != ""
            and "/" not in input[-1]
            and "." not in input[-1]
        ):
            return input[-1], True
        elif input[-1] != "":
            return input[-1], False
        else:
            return "", False


def tab_completion(self, input):
    token, command = get_tokens(input)
    if token == "":
        return ""
    if command == True:
        completion = ""
        count = int(0)
        for cmd in self.COMMANDS:
            if cmd.startswith(token):
                count += 1
                completion = cmd.replace(token, "", 1)
        for cmd in self.not_allowed:
            if cmd.startswith(token) and cmd != token:
                count += 1
                completion = cmd.replace(token, "", 1)
        if count == 1:
            return completion
        else:
            return ""
    else:
        if "/" not in token or token[-1] != "/":
            completions = []
            if "/" not in token:
                directory = self.directory
            else:
                index = token.rfind("/")
                real_path = get_real_path(
                    token[:index],
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                )
                if dir_exists(real_path):
                    directory = real_path
                else:
                    return ""
                token = token[index + 1 :]

            paths = get_all_paths(
                self.root, directory, self.default_directory, self.username
            )
            parent_path = get_parent_path(self.default_directory)
            if parent_path[-1] != "/":
                parent_path += "/"
            if directory[-1] != "/":
                directory += "/"
            if directory == parent_path:
                index = int(0)
                for index in range(len(paths)):
                    paths[index] = replace_username(paths[index], self.username)
            for path in paths:
                if path.startswith(token) and token != path:
                    completions.append(path.replace(token, "", 1))
            count = len(completions)
            if count == 1:
                return completions[0]
            elif count > 1:
                return get_longest_common_prefix(completions)
            else:
                return ""
        else:
            return ""


def empty_temporary_files():
    temporary_files_path = (
        os.path.abspath(os.path.dirname(__file__)) + "/temporary_files/"
    )
    temporary_files = os.listdir(temporary_files_path)
    for temporary_file in temporary_files:
        if temporary_file == ".gitkeep":
            continue
        temporary_file_path = os.path.join(temporary_files_path, temporary_file)
        if os.path.isfile(temporary_file_path):
            os.remove(temporary_file_path)


def write_download_file(file_name, out_text):
    file_path = (
        os.path.abspath(os.path.dirname(__file__)) + "/temporary_files/" + file_name
    )
    with open(file_path, "w") as output:
        output.write(out_text)
    return file_path


def get_temporary_files_count():
    temporary_files_path = (
        os.path.abspath(os.path.dirname(__file__)) + "/temporary_files/"
    )
    temporary_files = os.listdir(temporary_files_path)
    count = 0
    for temporary_file in temporary_files:
        if temporary_file == ".gitkeep":
            continue
        temporary_file_path = os.path.join(temporary_files_path, temporary_file)
        if os.path.isfile(temporary_file_path):
            count += 1
    return count


def get_zip_path(dir_path, zip_name):
    zip_path = (
        os.path.abspath(os.path.dirname(__file__)) + "/temporary_files/" + zip_name
    )
    zip = zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED)
    for path, dir_names, file_names in os.walk(dir_path):
        file_path = path.replace(dir_path, "")
        for file_name in file_names:
            zip.write(os.path.join(path, file_name), os.path.join(file_path, file_name))
    zip.close()
    return zip_path
