from asyncio.subprocess import PIPE
from scapy.all import sniff, Ether, IP, ARP, TCP, UDP, ICMP, get_if_addr
import logging
import subprocess
import json
import sys

logging.basicConfig(filename='tracker.log', encoding='utf-8', level=logging.DEBUG)

config_file = open(sys.argv[1], "r")
config = json.load(config_file)
config_file.close()

ports = config["ports"]

ip = config["ip"]

interface = config["interface"]

try:
    kill_mode = sys.argv[2] == "-k"
except:
    pass

def investigate(packet):
    out = ""
    l2 = packet[0][0]
    if type(packet[0][0]) == Ether:
        out += f"Ether({l2.src} => {l2.dst})\n"
        l3 = packet[0][1]
        if type(l3) == ARP:
            out += "ARP\n"
            return out
        if type(l3) == IP:
            out += f"IP({l3.src} => {l3.dst})\n"
            outgoing_packet = l3.src == ip
            l4 = packet[0][2]
            if type(l4) == TCP or type(l4) == UDP:
                out += f"TCP({l4.sport} => {l4.dport})\n"
                local_port = l4.sport if outgoing_packet else l4.dport
                if not local_port in ports:
                    out += "DANGER!\n"
                    get_pids(local_port)
                return out
            if type(l4) == ICMP:
                out += "ICMP\n"
                return out
    return None

def get_pids(port):
    lsof = subprocess.Popen(["lsof","-i",f":{port}"], stdout=PIPE, stderr=PIPE)
    stdout, stderr = lsof.communicate()
    out_lines = [line.split() for line in str(stdout,"utf-8").split("\n")]
    for line in out_lines[1:-1]:
        pid = line[1]
        binary = subprocess.Popen(["file",f"/proc/{pid}/exe"], stdout=PIPE, stderr=PIPE)
        if binary.returncode == 0:
            stdout, stderr = binary.communicate()
            binary_path = str(stdout, "utf-8").lstrip(f"/proc/{pid}/exe: symbolic link to ")
            logging.warning(f"PID {pid} was communicting on unauthorized port {port} using command {binary_path}")
            if kill_mode:
                kill = subprocess.Popen(["kill","-9",pid], stdout=PIPE, stderr=PIPE)
        else:
            logging.warning(f"PID {pid} was communicting on unauthorized port {port} using unknown command. This could mean it was already killed or something went wrong.")

sniff(iface=interface, prn=investigate)
