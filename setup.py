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


def change_password(user, password):
    """
    Execute proper command to change the password of a given user
    """
    logging.info(f"Changing password of {user}")
    p = Popen(["passwd", user], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.communicate(input=f"{password}\n{password}".encode())
    return p.returncode

exec_cmd(["mkdir","/root/documentation"])

t = datetime.now().strftime("%H_%M_%S")
logging.basicConfig(filename='/root/documentation/setup_{t}.log', encoding='utf-8', level=logging.DEBUG)

ports = []
users = []
services = []

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

stdout, stderr = exec_cmd(["ip","a"])[0]

print(stdout)

print("Enter internet interface: ", end="")
interface = input()
ip = get_if_addr(interface)

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

with open('/etc/passwd', "r", encoding="utf-8") as file:
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
                logging.info(f"Disabled user {user}")
        stdout, stderr = exec_cmd(["crontab","-u",user,"-l"])[0]
        with open(f"cron_{user}", "wb") as cron_file:
            cron_file.write(stdout)
        if uid == 0:
            logging.critical(f"User {user} has root UID!")
        elif uid < 1000:
            logging.warning(f"User {user} has admin-level UID!")
        if gid == 0:
            logging.critical(f"User {user} has root GID!")
        

print("Enter Service File to Keep Alive: ", end = "")
service = input()

while service != "":
    service = service.rstrip("\.service")
    exec_cmd(["systemctl","enable",service])
    exec_cmd(["systemctl","start",service])
    services.append(service)
    print("Enter Service File to Keep Alive: ", end = "")
    service = input()

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
    sudo_users, _ = exec_cmd(["getent","group","sudo"])
    sudo_users = sudo_users.split(":")[3].split(",")
    for user in sudo_users:
        if exec_cmd(f"Remove {user} from sudo"):
            exec_cmd(["gpasswd","-d",user,"sudo"])
        else:
            logging.warning(f"{user} has sudo power")
    exec_cmd(["mkdir","/root/documentation/old_files/sudo"])
    exec_cmd(["cp","/etc/sudoers","/root/documentation/old_files/sudo"])
    exec_cmd(["cp","/etc/sudoers.d","/root/documentation/old_files/sudo"])
    new_sudoers = requests.get("https://raw.githubusercontent.com/jabbate19/LinuxConfigs/master/sudoers").text
    exec_cmd(["chmod","/etc/sudoers","540"])
    with open("/etc/sudoers","w", encoding="utf-8") as sudoers:
        sudoers.write(new_sudoers)
    exec_cmd(["chmod","/etc/sudoers","440"])
    exec_cmd(["rm","-rf","/etc/sudoers.d/*"])
    

if yes_no("Execute sshd protection?"):
    exec_cmd(["mkdir","/root/documentation/old_files/ssh"])
    exec_cmd(["cp","/etc/ssh","/root/documenation/old_files/ssh"])
    new_sshd_config = requests.get("https://raw.githubusercontent.com/jabbate19/LinuxConfigs/master/sshd_config").text
    with open("/etc/ssh/sshd_config","w", encoding="utf-8") as sshd_config:
        sshd_config.write(new_sshd_config)
    exec_cmd(["rm","-rf","/etc/ssh/sshd_config.d/*"])
    exec_cmd(["systemctl","restart","sshd"])
    for file in ["authorized_keys", "id_rsa"]:
        stdout, stderr = exec_cmd(["find","/","-name",file])
        for target in stdout.split("\n")[:-1]:
            print(f"{file} file found: {target}")
            if yes_no(f"Remove {target}"):
                exec_cmd(["rm",target])
                logging.info(f"{target} was found on system and removed")
            else:
                logging.warning(f"{target} was found on system and not removed")

stdout, stderr = exec_cmd(["find","/","-perm","-4000","-print"])
for file in stdout:
    logging.warning(f"{file} has SUID Permissions!")
stdout, stderr = exec_cmd(["find","/","-perm","-2000","-print"])
for file in stdout:
    logging.warning(f"{file} has SGID Permissions!")
stdout, stderr = exec_cmd(["find","/","-type","d","\(","-perm","-g+w","-or","-perm","-o+w","\)","-print"])
for dir in stdout:
    logging.warning(f"Directory {dir} is world writable!")
stdout, stderr = exec_cmd(["find","/","-!","-path","*/proc/*","-perm","-2","-type","f","-print"])
for file in stdout:
    logging.warning(f"{file} is world writable!")

checkraw()

print("Please Check All Files:")
print(".bashrc")
print(".bash_profile")
print("/etc/bash.bashrc")
print("/etc/profile")
print("/etc/inputrc")
