"""
Resets vital systems to config-specified settings

Includes Firewall, Services, and Users
"""
import argparse
import json
import logging
from datetime import datetime
from utils import checkraw, exec_cmd, verify_config, yes_no # pylint: disable=E0611


def main():
    """
    Executed function when ran
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=str, help="Configuration file")

    t = datetime.now().strftime("%H_%M_%S")
    logging.basicConfig(filename=f'/root/documentation/revive_{t}.log',
                        encoding='utf-8',
                        level=logging.DEBUG)

    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not verify_config(config):
        raise Exception("Config Invalid")

    stdout, stderr, return_code = exec_cmd(["iptables","-L"])
    print(stdout)

    stdout, stderr, return_code = exec_cmd(["iptables","-t","mangle","-L"])
    print(stdout)

    if yes_no("Is the firewall ok?"):
        logging.info("Firewall was stated to be OK")
    else:
        exec_cmd(["iptables","-F"])
        exec_cmd(["iptables","-t","mangle","-F"])
        exec_cmd(["iptables","-P","INPUT","DROP"])
        exec_cmd(["iptables","-P","OUTPUT","ACCEPT"])
        exec_cmd(["iptables","-P","FORWARD","ACCEPT"])
        exec_cmd(["iptables","-A","INPUT","-p","imcp","-j","ACCEPT"])

        ports = config["ports"]

        for port in ports:
            exec_cmd(["iptables","-A","INPUT","-p","tcp","--dport",port,"-j","ACCEPT"])
            exec_cmd(["iptables","-A","INPUT","-p","udp","--dport",port,"-j","ACCEPT"])

        logging.info("Firewall reset to allow ports %s", ports)

    with open('/etc/passwd', "r", encoding="utf-8") as file:
        for line in file:
            comps = line.split(":")
            user = comps[0]
            default_sh = comps[6]
            if not ((default_sh in {"/bin/false","/usr/sbin/nologin"}) or user in config["users"]):
                print(f"{user} became active again, it has been shut down again.")
                exec_cmd(["usermod","-L",user])
                exec_cmd(["usermod","-s","/bin/false"])

    for service in config["services"]:
        stdout, stderr, code = exec_cmd(["systemctl","status",service])
        print(stdout)
        print(stderr)
        if yes_no("Re-enable/start service?"):
            exec_cmd(["systemctl","enable",service])
            exec_cmd(["systemctl","start",service])
            logging.warning("Re-enabled and started service %s", service)

    checkraw()

if __name__ == "__main__":
    main()