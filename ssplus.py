"""
Takes advantage of the ss command to quickly identify connections, even temporary ones!


"""
from datetime import datetime
import argparse
import logging
import json
from time import sleep
from utils import exec_cmd, verify_config, yes_no, PIDInfo # pylint: disable=E0611

parser = argparse.ArgumentParser()
# parser.add_argument("config", type=str, help="Configuration file")
parser.add_argument("--kill", action="store_true", help="Auto-kill PIDs")

args = parser.parse_args()

# with open(args.config, "r", encoding="utf-8") as config_file:
#     config = json.load(config_file)

# if not verify_config(config):
#     raise Exception("Config Invalid")

# ports = config["ports"]

# ip = config["ip"] # pylint: disable=C0103

# interface = config["iface"]

kill_mode = args.kill

class Socket:
    """
    Chom
    """
    def __init__(self, line):
        comps = line.split()
        self.net_id = comps[0]
        self.state = comps[1]
        self.recv_q = comps[2]
        self.send_q = comps[3]
        local = comps[4]
        port_pos = local.rfind(":")
        self.local_addr = local[:port_pos]
        self.local_port = local[(port_pos+1):]
        peer = comps[5]
        port_pos = peer.rfind(":")
        self.peer_addr = peer[:port_pos]
        self.peer_port = peer[(port_pos+1):]
        self.process = comps[6]

    def analyze_pid(self):
        """
        Get list of PIDs as PIDInfo objects
        """
        out = []
        pid_pos = 0
        while (pid_pos := self.process.find("pid=", pid_pos)) != -1:
            pid_start = pid_pos + 4
            pid_end = self.process.find(",", pid_start)
            out.append(PIDInfo(int(self.process[pid_start:pid_end])))
            pid_pos += 1
        return out

    def __str__(self):
        return f"{self.net_id} | {self.state} | {self.recv_q} | " \
               f"{self.send_q} | {self.local_addr} | {self.local_port} | " \
               f"{self.peer_addr} | {self.peer_port} | {self.process}"

    def __hash__(self):
        return self.__str__().__hash__()

    def __repr__(self):
        return str(self.__hash__())
    
    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

def main():
    """
    Chom
    """
    time = datetime.now().strftime("%H_%M_%S")
    logging.basicConfig(filename=f'/root/documentation/ssplus_{time}.log',
                        encoding='utf-8',
                        level=logging.DEBUG)
    safe = set()
    while True:
        ss = exec_cmd(["/bin/ss", "-tupn0"])
        if not ss[2]:
            lines = str(ss[0], "utf8").split("\n")[1:-1]
            for line in lines:
                sock = Socket(line)
                if not (sock in safe):
                    logging.info("New socket detected: %s", sock)
                    print(sock)
                    print(sock in safe)
                    if yes_no("Keep network socket?"):
                        safe.add(sock)
                    else:
                        logging.warning("Socket idenitifed as malicious: %s", sock)
                        for pid in sock.analyze_pid():
                            logging.warning("Terminated PID: %s", pid)
                            print(pid)
                            if kill_mode:
                                pid.terminate()
        sleep(0.01)

if __name__ == "__main__":
    main()
