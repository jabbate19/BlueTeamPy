from subprocess import PIPE, Popen


def exec_cmd(cmd):
    sub = Popen(cmd, stdout=PIPE, stderr=PIPE)
    return sub.communicate(), sub.returncode

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

def verify_config(config):
    print("Verify config:", config, split="\n")
    return yes_no("Config ok")