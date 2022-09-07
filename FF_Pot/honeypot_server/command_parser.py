import shlex
import copy
from .fake_files import url_validator

SUPPORT = ["<", ">", "|", "||", "&&", ">>", ";"]
NON_SUPPORT = [
    "<<",
    "{",
    "}",
    "[",
    "]",
    "(",
    ")",
    "&",
    "$",
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "for",
    "in",
    "do",
    "done",
    "while",
    "until",
    "case",
    "esac",
    "break",
    "continue",
]


def parse_syntax(input):
    class command:
        def __init__(self):
            self.cmd = ""
            self.params = []
            self.redirect = {}
            self.next = ""

    commands = []
    input_with_urls = ""
    for string in input.split(" "):
        if input_with_urls != "":
            input_with_urls += " "
        if url_validator(string):
            input_with_urls += '"' + string + '"'
        else:
            input_with_urls += string
    try:
        s = list(shlex.shlex(input_with_urls, posix=True, punctuation_chars=True))
    except:
        return "\\n", []
    cmd = command()
    complete = True
    redirect = ""
    for index in range(len(s)):
        if s[index] in NON_SUPPORT:
            return s[index], []
        if (
            index > 0
            and s[index] in SUPPORT
            and s[index - 1] in SUPPORT
            and (s[index] != ";" or s[index - 1] != ";")
        ):
            return s[index], []
        if complete:
            cmd.__init__()
            if s[index] == ";":
                cmd.next = ";"
                commands.append(copy.deepcopy(cmd))
            elif s[index] in SUPPORT:
                return s[index], []
            else:
                complete = False
                cmd.cmd = s[index]
        else:
            if s[index] in SUPPORT:
                if (
                    s[index] == "&&"
                    or s[index] == "||"
                    or s[index] == "|"
                    or s[index] == ";"
                ):
                    if index == len(s) - 1 and (
                        s[index] == "&&" or s[index] == "||" or s[index] == "|"
                    ):
                        return s[index], []
                    if cmd.redirect:
                        for key in cmd.redirect:
                            if cmd.redirect[key] is None:
                                return s[index], []
                    cmd.next = s[index]
                    commands.append(copy.deepcopy(cmd))
                    complete = True
                else:
                    if (
                        s[index] in cmd.redirect
                        or ">>" in cmd.redirect
                        and s[index] == ">"
                        or ">" in cmd.redirect
                        and s[index] == ">>"
                    ):
                        return s[index], []
                    cmd.redirect[s[index]] = None
                    redirect = s[index]
            else:
                if redirect != "":
                    cmd.redirect[redirect] = s[index]
                    redirect = ""
                else:
                    cmd.params.append(s[index])
    if not complete:
        if cmd.redirect:
            for key in cmd.redirect:
                if cmd.redirect[key] is None:
                    return "\\n", []
        commands.append(copy.deepcopy(cmd))
        complete = True
    return "", commands