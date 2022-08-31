"""
Allows user to establish baseline for system

- Audits Users
- Establishes Firewall
- Keeps track of needed services
- Hardens config files
- Checks for SUID/SGID files
- Checks for world-writable
- Checks for raw sockets
"""
from asyncio.subprocess import PIPE
from subprocess import Popen
from datetime import datetime
import json
from getpass import getpass
import logging
from scapy.all import get_if_addr
import requests
from utils import checkraw, exec_cmd, yes_no # pylint: disable=E0611
# pylint: disable=W1401


def change_password(user, password):
    """
    Execute proper command to change the password of a given user
    """
    logging.info("Changing password of %s", user)
    with Popen(["passwd", user], stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:
        proc.communicate(input=f"{password}\n{password}".encode())
        return proc.returncode

def configure_firewall():
    """
    Requests internet interface and ports to allow traffic on

    Configures firewall and returns data for config file
    """
    ports = []

    stdout, _, _ = exec_cmd(["ip","a"])[0]

    print(stdout)

    print("Enter internet interface: ", end="")
    interface = input()
    ip = get_if_addr(interface) # pylint: disable=C0103

    print("Enter Service Port: ", end = "")
    port = input()

    while port != "":
        try:
            port_int = int(port)
            if port_int > 0 and port_int < 65536:
                ports.append(port)
            else:
                print("Invalid Port Number!")
        except ValueError:
            print("Invalid Port Number!")
        print("Enter Service Port: ", end = "")
        port = input()

    exec_cmd(["iptables","-F"])
    exec_cmd(["iptables","-t","mangle","-F"])
    exec_cmd(["iptables","-P","INPUT","DROP"])
    exec_cmd(["iptables","-P","OUTPUT","ACCEPT"])
    exec_cmd(["iptables","-P","FORWARD","ACCEPT"])
    exec_cmd(["iptables","-A","INPUT","-p","imcp","-j","ACCEPT"])

    for port in ports:
        exec_cmd(["iptables","-A","INPUT","-p","tcp","--dport",port,"-j","ACCEPT"])
        exec_cmd(["iptables","-A","INPUT","-p","udp","--dport",port,"-j","ACCEPT"])

    return ip, interface, ports

def audit_users():
    """
    Goes through all users on system, prompts to keep or remove
    Returns list of accepted users
    """
    with open('/etc/passwd', "r", encoding="utf-8") as file:
        users = []
        for line in file:
            comps = line.split(":")
            user = comps[0]
            uid = int(comps[2])
            gid = int(comps[3])
            default_sh = comps[6]
            if not (default_sh == "/bin/false" or default_sh == "/usr/sbin/nologin"):
                keep_user = yes_no(f"Keep user {user}")
                if keep_user:
                    users.append(user)
                else:
                    exec_cmd(["usermod","-L",user])
                    exec_cmd(["usermod","-s","/bin/false"])
                    exec_cmd(["gpasswd","--delete",user,"sudo"])
                    logging.info("Disabled user %s", user)
            stdout, _, _ = exec_cmd(["crontab","-u",user,"-l"])[0]
            with open(f"cron_{user}", "wb") as cron_file:
                cron_file.write(stdout)
            if uid == 0:
                logging.critical("User %s has root UID!", user)
            elif uid < 1000:
                logging.warning("User %s has admin-level UID!", user)
            if gid == 0:
                logging.critical("User %s has root GID!", user)
        return users

def select_services():
    """
    Prompts to enter services that are needed to be kept open

    Returns list of all services needed
    """
    services = []
    print("Enter Service File to Keep Alive: ", end = "")
    service = input()

    while service != "":
        service = service.rstrip("\.service")
        exec_cmd(["systemctl","enable",service])
        exec_cmd(["systemctl","start",service])
        services.append(service)
        print("Enter Service File to Keep Alive: ", end = "")
        service = input()
    return services

def sudo_protection():
    """
    Audits for all users with sudo permissions

    Re-writes sudoers file to have proper permissions
    """
    sudo_users, _ = exec_cmd(["getent","group","sudo"])
    sudo_users = sudo_users.split(":")[3].split(",")
    for user in sudo_users:
        if exec_cmd(f"Remove {user} from sudo"):
            exec_cmd(["gpasswd","-d",user,"sudo"])
        else:
            logging.warning("%s has sudo power", user)
    exec_cmd(["mkdir","/root/documentation/old_files/sudo"])
    exec_cmd(["cp","/etc/sudoers","/root/documentation/old_files/sudo"])
    exec_cmd(["cp","/etc/sudoers.d","/root/documentation/old_files/sudo"])
    new_sudoers = requests.get(
        "https://raw.githubusercontent.com/jabbate19/LinuxConfigs/master/sudoers"
    ).text
    exec_cmd(["chmod","/etc/sudoers","540"])
    with open("/etc/sudoers","w", encoding="utf-8") as sudoers:
        sudoers.write(new_sudoers)
    exec_cmd(["chmod","/etc/sudoers","440"])
    exec_cmd(["rm","-rf","/etc/sudoers.d/*"])

def sshd_protection():
    """
    Re-writes sshd_config to eliminate common vulnerbilities

    Finds all authorized_keys and id_rsa files that may allow entry
    """
    exec_cmd(["mkdir","/root/documentation/old_files/ssh"])
    exec_cmd(["cp","/etc/ssh","/root/documenation/old_files/ssh"])
    new_sshd_config = requests.get(
        "https://raw.githubusercontent.com/jabbate19/LinuxConfigs/master/sshd_config"
    ).text
    with open("/etc/ssh/sshd_config","w", encoding="utf-8") as sshd_config:
        sshd_config.write(new_sshd_config)
    exec_cmd(["rm","-rf","/etc/ssh/sshd_config.d/*"])
    exec_cmd(["systemctl","restart","sshd"])
    for file in ["authorized_keys", "id_rsa"]:
        stdout, _, _ = exec_cmd(["find","/","-name",file])
        for target in stdout.split("\n")[:-1]:
            print(f"{file} file found: {target}")
            if yes_no(f"Remove {target}"):
                exec_cmd(["rm",target])
                logging.info("%s was found on system and removed", target)
            else:
                logging.warning("%s was found on system and not removed", target)

def scan_file_permissions():
    """
    Checks for SUID, SGID, and World-Writable Files/Directories
    """
    stdout, _, _ = exec_cmd(["find","/","-perm","-4000","-print"])
    for file in stdout:
        logging.warning("%s has SUID Permissions!", file)
    stdout, _, _ = exec_cmd(["find","/","-perm","-2000","-print"])
    for file in stdout:
        logging.warning("%s has SGID Permissions!", file)
    stdout, _, _ = exec_cmd(
        ["find","/","-type","d","\(","-perm","-g+w","-or","-perm","-o+w","\)","-print"]
    )
    for directory in stdout:
        logging.warning("Directory %s is world writable!", directory)
    stdout, _, _ = exec_cmd(
        ["find","/","-!","-path","*/proc/*","-perm","-2","-type","f","-print"]
    )
    for file in stdout:
        logging.warning("%s is world writable!", file)

def main():
    """
    Executed function when ran
    """
    exec_cmd(["mkdir","/root/documentation"])

    time = datetime.now().strftime("%H_%M_%S")
    logging.basicConfig(filename=f'/root/documentation/setup_{time}.log',
                        encoding='utf-8',
                        level=logging.DEBUG)

    print("Enter primary account (one the scorer is looking for/the one you're using): ", end="")
    main_account = input()

    with open("setup/sshd_config", "a", encoding="utf-8") as sshd:
        sshd.write(f"AllowUsers {main_account}")

    password = "a"
    verify = "b"

    while password != verify:
        print("Enter password for account and root: ")
        password = getpass()
        print("Verify password for account and root: ")
        verify = getpass()

    change_password(main_account, password)
    change_password("root", password)

    ip, interface, ports = configure_firewall() # pylint: disable=C0103

    users = audit_users()

    services = select_services()

    config = {
        "ip": ip,
        "iface": interface,
        "ports": ports,
        "services": services,
        "users": users
    }

    config_json = json.dumps(config, indent=4)

    with open("config.json", "w", encoding="utf-8") as config_file:
        config_file.write(config_json)

    exec_cmd(["mkdir","/root/documentation/old_files"])

    if yes_no("Execute sudo protection?"):
        sudo_protection()

    if yes_no("Execute sshd protection?"):
        sshd_protection()

    scan_file_permissions()

    checkraw()

    print(
        "Please Check All Files:",
        ".bashrc",
        ".bash_profile",
        "/etc/bash.bashrc",
        "/etc/profile",
        "/etc/inputrc",
        sep = "\n"
    )

if __name__ == "__main__":
    main()
