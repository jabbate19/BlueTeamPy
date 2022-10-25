# Blue Team Tooling

## This project has been moved to https://github.com/BlueTeamRust

A collection of Python scripts to use in Blue Team Competitions (UB Lockdown, IRSec, ISTS) on Linux systems

## Subsystems

This set is split into a variety of scripts, each to be used in different stages of the competition

### Setup

This is the first thing that should be executed. This script handles the following tasks:

- Reset Password of Primary and root user
- Establish needed ports and services
- Harden common services (ssh)
- User management
    - Verify each user to be wanted or disabled
    - Check for users with root UID/GID
- Find all SUID, SGID, World-Writable Files
- Creates a config.json to be referenced by other modules

### Tracker

Network Monitor for undesired traffic

- Alerts/Logs for all traffic done using a local port not authorized by config
- Attempts to locate the Process/PID that caused this traffic
    - Upon finding, logs all necessary information
    - If enabled (`-k`), kills the process automatically

### Revive

Resets configuration in the event of lost services

- Resets firewall
- Restarts services
- Re-hardens configs/users

## Requirements

This set requires [scapy](https://scapy.net) to run the tracker. This can be installed via pip.

`pip install scapy` or `pip3 install scapy`

## Running

Since the files are named `__main__`, you can call all files from the root folder and using the module folder name. Ex. `python setup`
