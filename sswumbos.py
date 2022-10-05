"""
Takes advantage of the netstat command to quickly identify connections, even temporary ones!

Powershell is the demon in disguise. Don't trust it.
"""
from datetime import datetime
import argparse
import logging
from time import sleep
from utils import exec_cmd, yes_no # pylint: disable=E0611


class Socket:
    """
    Chom
    """
    def __init__(self, line):
        comps = line.split()
        self.proto = comps[0]
        local = comps[1]
        port_pos = local.rfind(":")
        self.local_addr = local[:port_pos]
        self.local_port = local[(port_pos+1):]
        peer = comps[2]
        port_pos = peer.rfind(":")
        self.peer_addr = peer[:port_pos]
        self.peer_port = peer[(port_pos+1):]
        self.state = comps[3]
        try:
            self.pid = comps[4]
        except IndexError:
            self.pid = -1

    def analyze_pid(self):
        """
        Get list of PIDs as PIDInfo objects
        """
        return PIDInfoWindows(self.pid)

    def __str__(self):
        return f"{self.proto} | {self.local_addr} | {self.local_port} | " \
               f"{self.peer_addr} | {self.peer_port} | {self.state}"

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
    logging.basicConfig(filename=f'.\\sswumbos_{time}.log',
                        encoding='utf-8',
                        level=logging.DEBUG)
    safe = set()
    while True:
        ss = exec_cmd(["C:\\Windows\\System32\\NETSTAT.EXE", "-noq"])
        if not ss[2]:
            lines = str(ss[0], "utf8").split("\n")[4:-1]
            for line in lines:
                sock = Socket(line)
                pid = sock.analyze_pid()
                if not sock.pid in safe:
                    logging.info("New socket detected: %s | %s", sock, pid)
                    print(sock)
                    print(pid)
                    if yes_no("Keep network socket?"):
                        safe.add(sock.pid)
                    else:
                        logging.warning("Socket idenitifed as malicious: %s | %s", sock, pid)
                        if kill_mode:
                            logging.warning("Terminated PID: %s", pid)
                            pid.terminate()
        if not speed_mode:
            sleep(0.01)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--kill", action="store_true", help="Auto-kill PIDs")
    parser.add_argument("--speed", action="store_true", help="FAST")


    args = parser.parse_args()

    kill_mode = args.kill

    speed_mode = args.speed
    main()
