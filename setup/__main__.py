from asyncio.subprocess import PIPE
import subprocess
from scapy.all import get_if_addr
import json

def exec_cmd(cmd):
    sub = subprocess.Popen(cmd, stdout=PIPE, stderr=PIPE)
    return sub.communicate()

ports = []
users = []
services = []

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
    except:
        pass
    print("Enter Service Port: ", end = "")
    port = input()

exec_cmd(["iptables","-F"])
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
        if not default_sh in ["/bin/false", "/usr/sbin/nologin"]:
            print(f"Keep user {user} (y/n)? ", end="")
            verification_complete = False
            while not verification_complete:
                verification = input()
                if len(verification) == 0:
                    print("Invalid Response")
                    print(f"Keep user {user} (y/n)? ", end="")
                elif verification.lower()[0] == "y":
                    users.append(user)
                    verification_complete = True
                elif verification.lower()[0] == "n":
                    exec_cmd(["usermod","-L",user])
                    exec_cmd(["usermod","-s","/bin/false"])
                    stdout, stderr = exec_cmd(["crontab","-u",user,"-l"])
                    with open(f"cron_{user}", "wb") as cron_file:
                        cron_file.write(stdout)
                    exec_cmd(["crontab","-u",user,"-r"])
                    verification_complete = True
                else:
                    print("Invalid Response")
                    print(f"Keep user {user} (y/n)? ", end="")
                    keep = input().lower()[0] == "y"

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

