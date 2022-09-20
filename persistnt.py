"""
Persistn't

Scan all common persistence locations for a file
"""
import argparse
import re
from utils import UserInfo, exec_cmd

parser = argparse.ArgumentParser()
parser.add_argument("target", type=str, help="Target name")

args = parser.parse_args()

target = args.target


def main():
    """
    Executes all persistence detectors
    """
    print("===SERVICES===")
    services_cmd = exec_cmd(["/usr/bin/systemctl","status","--all","--type=service"])
    lines = str(services_cmd[0], "utf8").split("\n")
    for line in lines:
        service = re.findall(".*\.service", line)
        if service:
            most_recent = service
        target_check = re.findall(target, line)
        if target_check:
            print("\n\nTarget Found!")
            print(line)
            print(f"Suspected Service(s): {most_recent}")
            input()
    print("===CRON===")
    for cron_location in ["anacrontab", "cron.d", "cron.daily", "cron.hourly", "cron.monthly", "cron.weekly", "crontab"]:
        cron_grep = exec_cmd(["/bin/grep","-R",target,f"/etc/{cron_location}"])
        if not cron_grep[2]:
            print(f"Target Found in /etc/{cron_location}!")
            print(str(cron_grep[0], "utf8"))
            input()
    print("===COMMON FILES===")
    for user in UserInfo.get_all_users():
        for shell_config in [".*rc", ".*profile",".*history",".*env","*login", "*logout"]:
            user_find = exec_cmd(["/bin/find",user.homedir,"-name",shell_config])
            if not user_find[2]:
                for result in str(user_find[0], "utf8").split("\n"):
                    user_grep = exec_cmd(["/bin/grep", "-R", target, result])
                    if not user_grep[2]:
                        print(f"Target Found in {result}!")
                        print(str(user_grep[0], "utf8"))
                        input()
    for file_location in ["/etc/profile", "/etc/bashrc", "/etc/bash.bashrc", "/etc/bash_completion", "/etc/bash_completion.d", "/etc/zsh", "/etc/profile.d", "/etc/inputrc"]:
        file_grep = exec_cmd(["/bin/grep","-R",target,file_location])
        if not file_grep[2]:
            print(f"Target Found in {file_location}!")
            print(str(file_grep[0], "utf8"))
            input()
    print("If you didn't find anything, red team is playing games. Good luck soldier.")

if __name__ == "__main__":
    main()
