"""
Utiltiies used across other modules
"""
from subprocess import PIPE, Popen
from os import readlink
import logging
from re import findall

class UserInfo():
    """
    Chom
    """
    def __init__(self, line):
        comps = line.split(":")
        self.username = comps[0]
        self.password = comps[1]
        self.uid = int(comps[2])
        self.gid = int(comps[3])
        self.userinfo = comps[4]
        self.homedir = comps[5]
        self.shell = comps[6]

    @staticmethod
    def get_all_users():
        """
        eee
        """
        out = []
        with open('/etc/passwd', "r", encoding="utf-8") as file:
            for line in file:
                try:
                    out.append(UserInfo(line))
                except IndexError:
                    pass
                except ValueError:
                    pass
        return out

    def shutdown(self):
        """
        Run neccessary tasks to disable unwated user account
        """
        exec_cmd(["usermod","-L",self.username])
        exec_cmd(["usermod","-s","/bin/false",self.username])
        exec_cmd(["gpasswd","--delete",self.username,"sudo"])


class PIDInfo():
    """
    Contains critical information of a process based on a PID
    """
    def __init__(self, pid):
        self.pid = pid
        self.exe = readlink(f"/proc/{pid}/exe")
        self.root = readlink(f"/proc/{pid}/root")
        self.cwd = readlink(f"/proc/{pid}/cwd")
        with open(f"/proc/{pid}/cmdline", "r", encoding="utf-8") as file:
            self.cmdline = file.read()
        with open(f"/proc/{pid}/environ", "r", encoding="utf-8") as file:
            self.environ = file.read()

    def terminate(self):
        """
        Sends SIGKILL to the process
        """
        exec_cmd(["kill","-9",str(self.pid)])

    def __str__(self) -> str:
        return f"{self.pid} | {self.exe} | {self.root} | {self.cwd} | {self.cmdline}"

    def __repr__(self) -> str:
        return self.__str__()


class PIDInfoWindows():
    """
    Contains critical information of a process based on a PID

    But... Windows!
    """
    def __init__(self, pid):
        self.pid = pid
        file_info = exec_cmd_pwsh(f"Get-Process -Id {pid} -FileVersionInfo")
        try:
            self.exe = findall("[A-Z]:\\\\.*", str(file_info[0], "utf8"))[0].strip()
        except IndexError:
            self.exe = f"\033[31m{str(file_info[1], 'utf8')}\033[0m"

    def terminate(self):
        """
        Sends SIGKILL to the process, but Wumbos
        """
        exec_cmd_pwsh(f"End-Process -Id {self.pid}")

    def __str__(self) -> str:
        return f"{self.pid} | {self.exe}"

    def __repr__(self) -> str:
        return self.__str__()


def exec_cmd(cmd):
    """
    Executes given command

    Command provided as list of arguments
    """
    with Popen(cmd, stdout=PIPE, stderr=PIPE) as sub:
        output = sub.communicate()
        return output[0], output[1], sub.returncode


def exec_cmd_pwsh(cmd):
    """
    Executes given command

    Command provided as list of arguments
    """
    with Popen(["powershell","-ExecutionPolicy","Bypass", cmd], stdout=PIPE, stderr=PIPE) as sub:
        output = sub.communicate()
        return output[0], output[1], sub.returncode


def yes_no(question):
    """
    Prompts user to respond yes or no to a question, and returns result

    Yes = True
    No = False
    """
    print(f"{question} (y/n)? ", end="")
    while True:
        verification = input()
        if len(verification) == 0:
            print("Invalid Response")
            print(f"{question} (y/n)? ", end="")
        elif verification.lower()[0] == "y":
            return True
        elif verification.lower()[0] == "n":
            return False
        else:
            print("Invalid Response")
            print(f"{question} (y/n)? ", end="")

def verify_config(config):
    """
    Ensures that config file was not tampered before continuing
    """
    print("Verify config:", config, split="\n")
    return yes_no("Config ok")

def checkraw():
    """
    Checks for raw sockets and has user ensure that those active are desired
    """
    stdout, _, return_code = exec_cmd(["ss","-0","-p"])
    if return_code == 0:
        rows = str(stdout,"utf-8").split("\n")[1:-1]
        for row in rows:
            pid_loc = row.find("pid=")+4
            pid_end = row[pid_loc:].find(",")
            pid_data = PIDInfo(row[pid_loc:pid_loc+pid_end])
            logging.warning("Raw socket detected! %s", pid_data)
            print(pid_data)
            kill = yes_no("Do you want to terminate this raw socket")
            if kill:
                pid_data.terminate()
