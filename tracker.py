"""
Scans network traffic for unauthorized port usage

Will log anything occuring on a local port (send/recv) not specified in the config
Can also automatically kill if desired
"""
from datetime import datetime
import argparse
import logging
import json
from scapy.all import sniff, Ether, IP, ARP, TCP, UDP, ICMP # pylint: disable=E0611
from utils import exec_cmd, verify_config, PIDInfo # pylint: disable=E0611


def main():
    """
    Executed function when ran
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=str, help="Configuration file")
    parser.add_argument("--kill", action="store_true", help="Auto-kill PIDs")

    t = datetime.now().strftime("%H_%M_%S")
    logging.basicConfig(filename='/root/documentation/tracker_{t}.log',
                        encoding='utf-8',
                        level=logging.DEBUG)

    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not verify_config(config):
        raise Exception("Config Invalid")

    ports = config["ports"]

    ip = config["ip"]

    interface = config["iface"]

    kill_mode = args.kill

    sniff(iface=interface, prn=investigate)

    def investigate(packet):
        """
        Analyze packet to see if is abnormal activity for the given config
        """
        out = ""
        layer_2 = packet[0][0]
        if isinstance(packet[0][0], Ether):
            out += f"Ether({layer_2.src} => {layer_2.dst})\n"
            layer_3 = packet[0][1]
            if isinstance(layer_3, ARP):
                out += "ARP\n"
                return out
            if isinstance(layer_3, IP):
                out += f"IP({layer_3.src} => {layer_3.dst})\n"
                outgoing_packet = layer_3.src == ip
                layer_4 = packet[0][2]
                if isinstance(layer_4, (TCP, UDP)):
                    out += f"TCP({layer_4.sport} => {layer_4.dport})\n"
                    local_port = layer_4.sport if outgoing_packet else layer_4.dport
                    if not local_port in ports:
                        out += "DANGER!\n"
                        get_pids(local_port)
                    return out
                if isinstance(layer_4, ICMP):
                    out += "ICMP\n"
                    return out
        return None

    def get_pids(port):
        """
        Get PID of process listening on given port

        Logs data and kills if active
        """
        stdout, _, _ = exec_cmd(["lsof","-i",f":{port}"])
        out_lines = [line.split() for line in str(stdout,"utf-8").split("\n")]
        for line in out_lines[1:-1]:
            pid = PIDInfo(line[1])
            logging.warning(
                "PID %s was communicting on unauthorized port %s | cwd: %s | exe: %s | cmd: %s",
                pid, port, pid.cwd, pid.exe, pid.cmdline
            )
            if kill_mode:
                exec_cmd(["kill","-9",pid])

if __name__ == "__main__":
    main()