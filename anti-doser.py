# Author: Pari Malam

import subprocess
import socket
from datetime import datetime

NO_OF_CONNECTIONS = 150
FILTER_STATE = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]  # Adjust filter states as needed
IGNORE_DEFAULT_IP = 1  # Set to 1 to ignore default IP addresses like 127.0.0.1
IGNORE_IP_LIST = []  # Add IP addresses to ignore here
EMAIL_TO = ""  # Set your email for notifications

# Reverse IP ranges to ignore
REVERSE_IP1 = ["10", "224", "225", "226", "227", "228", "229", "230", "231", "231", "234", "235", "236", "237", "238", "239"]
REVERSE_IP2 = ["192.168", "172.16", "172.17", "172.18", "172.19", "172.20", "172.21", "172.22", "172.23", "172.24", "172.25", "172.26", "172.27", "172.28", "172.29", "172.30", "172.31"]
ALL_STATE = ["all", "connected", "synchronized", "syn-sent", "syn-recv", "established", "fin-wait-1", "fin-wait-2", "time-wait", "close-wait", "last-ack", "closing", "closed"]

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_ignored_ip(ip):
    if IGNORE_DEFAULT_IP and ip == '127.0.0.1':
        return True
    local_ip1 = ip.split('.')[0]
    if local_ip1 in REVERSE_IP1:
        return True
    local_ip2 = '.'.join(ip.split('.')[:2])
    if local_ip2 in REVERSE_IP2:
        return True
    return False

def ban_ip(ip):
    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])

def unban_ips(banned_ips, ban_period):
    unban_script = "#!/bin/sh\n"
    unban_script += "sleep " + str(ban_period) + "\n"
    for ip in banned_ips:
        unban_script += f"iptables -D INPUT -s {ip} -j DROP\n"
    unban_script += "grep -v --file=" + banned_ip_list + " " + banned_ip_list + " > " + tmp_file + "\n"
    unban_script += "mv " + tmp_file + " " + banned_ip_list + "\n"
    unban_script += "rm -f " + tmp_banned_ip_list + "\n"
    unban_script += "rm -f " + unban_script + "\n"
    unban_script += "rm -f " + tmp_file + "\n"

    with open(unban_script_file, "w") as script:
        script.write(unban_script)

    subprocess.Popen(["bash", unban_script_file])

tmp_prefix = "/tmp/ddos"
tmp_file = "mktemp " + tmp_prefix + ".XXXXXXXX"
banned_ip_mail = tmp_file
tmp_banned_ip_list = "mktemp /tmp/ban.XXXXXXXXX"

with_filter = ""
multi_filter = 0
if FILTER_STATE:
    for state in FILTER_STATE:
        if not multi_filter:
            with_filter = "state " + ALL_STATE[state]
            multi_filter = 1
        else:
            with_filter += " state " + ALL_STATE[state]

ss_output = subprocess.check_output(["ss", "-ntu", with_filter], universal_newlines=True)
connections = ss_output.split('\n')[1:]
bad_ip_list = {}

for connection in connections:
    parts = connection.split()
    if len(parts) < 6:
        continue
    state = parts[5]
    ip = parts[6].split(':')[0]
    if not is_valid_ip(ip):
        continue
    if state != 'ESTAB' or (IGNORE_DEFAULT_IP and ip == '127.0.0.1') or is_ignored_ip(ip):
        continue
    if ip in bad_ip_list:
        bad_ip_list[ip] += 1
    else:
        bad_ip_list[ip] = 1

banned_ips = []
banned_ip_mail_content = f"Banned the following IP addresses on {datetime.now()}\n\n"

for ip, conn_count in bad_ip_list.items():
    if conn_count >= NO_OF_CONNECTIONS:
        ban_ip(ip)
        banned_ips.append(ip)
        banned_ip_mail_content += f"{ip} with {conn_count} connections\n"

if banned_ips:
    with open(banned_ip_mail, "w") as mail_file:
        mail_file.write(banned_ip_mail_content)
    if EMAIL_TO:
        subprocess.run(["mail", "-s", f"IP addresses banned on {datetime.now()}", EMAIL_TO], input=banned_ip_mail.encode())
if banned_ips:
    unban_ips(banned_ips, BAN_PERIOD)
subprocess.run(["rm", "-f", tmp_prefix + ".*"])
