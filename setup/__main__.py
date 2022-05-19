from asyncio.subprocess import PIPE
from subprocess import Popen
from scapy.all import get_if_addr
import json
from getpass import getpass

def exec_cmd(cmd):
    sub = Popen(cmd, stdout=PIPE, stderr=PIPE)
    return sub.communicate(), sub.returncode

def change_password(user, password):
    p = Popen(["passwd", user], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    p.communicate(input=f"{password}\n{password}".encode())
    return p.returncode

def yes_no(question):
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

ports = []
users = []
services = []

print("Enter primary account (one the scorer is looking for/the one you're using): ", end="")
main_account = input()

with open("setup/sshd_config", "a") as sshd:
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
    except:
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

with open('/etc/passwd', "r") as file:
    for line in file:
        comps = line.split(":")
        user = comps[0]
        default_sh = comps[6]
        if not (default_sh == "/bin/false" or default_sh == "/usr/sbin/nologin"):
            keep_user = yes_no(f"Keep user {user}")
            if keep_user:
                users.append(user)
            else:
                exec_cmd(["usermod","-L",user])
                exec_cmd(["usermod","-s","/bin/false"])
            stdout, stderr = exec_cmd(["crontab","-u",user,"-l"])[0]
            with open(f"cron_{user}", "wb") as cron_file:
                cron_file.write(stdout)
            # exec_cmd(["crontab","-u",user,"-r"])

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

with open("config.json", "w") as config_file:
    config_file.write(config_json)

if yes_no("Execute sshd protection?"):
    exec_cmd(["cp","setup/sshd_config","/root"])
    exec_cmd(["chown","root","/root/sshd_config"])
    exec_cmd(["chown",":root","/root/sshd_config"])
    exec_cmd(["chmod","440","/root/sshd_config"])
    exec_cmd(["cp","/root/sshd_config","/etc/ssh/sshd_config"])
    exec_cmd(["rm","/etc/ssh/sshd_config.d/*"])
    exec_cmd(["systemctl","restart","sshd"])

print("Please Check All Files:")
print(".bashrc")
print(".bash_profile")
print("/etc/bash.bashrc")
print("/etc/profile")
print("/etc/inputrc")