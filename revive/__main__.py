import sys
import json
from utils import *

if len(sys.argv) >= 2:
    config_file = open(sys.argv[1], "r")
else:
    print("Input Config File Path: ", end="")
    config_file = open(input(), "r")

config = json.load(config_file)
config_file.close()

if not verify_config(config):
    raise Exception("Config Invalid")

exec_cmd(["iptables","-F"])
exec_cmd(["iptables","-t","mangle","-F"])
exec_cmd(["iptables","-P","INPUT","DROP"])
exec_cmd(["iptables","-P","OUTPUT","ACCEPT"])
exec_cmd(["iptables","-P","FORWARD","ACCEPT"])
exec_cmd(["iptables","-A","INPUT","-p","imcp","-j","ACCEPT"])

for port in config["ports"]:
    exec_cmd(["iptables","-A","INPUT","-p","tcp","--dport",port,"-j","ACCEPT"])
    exec_cmd(["iptables","-A","INPUT","-p","udp","--dport",port,"-j","ACCEPT"])

print("Reset the Firewall!")

with open('/etc/passwd', "r") as file:
    for line in file:
        comps = line.split(":")
        user = comps[0]
        default_sh = comps[6]
        if not ( (default_sh == "/bin/false" or default_sh == "/usr/sbin/nologin") or user in config["users"] ):
            print(f"{user} became active again, it has been shut down again.")
            exec_cmd(["usermod","-L",user])
            exec_cmd(["usermod","-s","/bin/false"])

for service in config["services"]:
    std, code = exec_cmd(["systemctl","status",service])
    stdout, stderr = std
    print(stdout)
    print(stderr)
    exec_cmd(["systemctl","enable",service])
    exec_cmd(["systemctl","start",service])
