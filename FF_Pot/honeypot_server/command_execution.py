import os
import subprocess
from .fake_files import set_pipe_output, get_real_path, write_file, append_file


def get_out_text(self, cmd, params, change_cmd_result=True, missing_argument=False):
    try:
        params.insert(0, cmd)
        if self.pipe == True:
            with open(
                os.path.abspath(os.path.dirname(__file__)) + self.pipe_file, "r"
            ) as input:
                out_bytes = subprocess.check_output(
                    params, stderr=subprocess.STDOUT, stdin=input
                )
        elif "<" in self.redirect:
            with open(
                get_real_path(
                    self.redirect["<"],
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                ),
                "r",
            ) as input:
                out_bytes = subprocess.check_output(
                    params, stderr=subprocess.STDOUT, stdin=input
                )
        elif missing_argument == True:
            self.result = False
            return ""
        else:
            out_bytes = subprocess.check_output(params, stderr=subprocess.STDOUT)
        if change_cmd_result:
            self.result = True
        return out_bytes.decode("utf-8").strip("\n")
    except:
        if change_cmd_result:
            self.result = False
        return ""


def output(
    self,
    out_text="",
    new_line=True,
    error="-bash: command execution error",
    ignore_result=False,
    replace=True,
):
    if self.result == False and error != "" or ignore_result and error != "":
        if replace:
            self.writeresponse(error.replace("\n", "\\n"))
        else:
            self.writeresponse(error)
    if self.next == "|" or ">" in self.redirect or ">>" in self.redirect:
        if self.next == "|":
            set_pipe_output(self.pipe_file, out_text)
        if ">" in self.redirect:
            write_file(
                get_real_path(
                    self.redirect[">"],
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                ),
                out_text,
            )
        elif ">>" in self.redirect:
            append_file(
                get_real_path(
                    self.redirect[">>"],
                    self.root,
                    self.directory,
                    self.default_directory,
                    self.username,
                ),
                out_text,
            )
    elif self.result == True or ignore_result and out_text != "":
        if new_line == True and out_text != "":
            self.writeresponse(out_text)
        else:
            self.write(out_text)
