# Blue Team Tooling

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

