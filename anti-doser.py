#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
import platform
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration
MAX_CONNECTIONS_PER_IP = 30  # Max connections from a single IP
CONNECTION_RATE_LIMIT = 50   # Max new connections per second
SYN_FLOOD_THRESHOLD = 100    # Max SYN packets per second
BAN_DURATION = 3600          # Ban duration in seconds (1 hour)
WHITELIST = ['192.168.1.100', '10.0.0.5']  # Trusted IPs
MONITOR_INTERVAL = 5         # Monitoring interval in seconds
LOG_FILE = 'antiddos.log'

class AntiDDoS:
    def __init__(self):
        self.system = platform.system().lower()
        self.connections = defaultdict(list)
        self.syn_counts = defaultdict(int)
        self.banned_ips = {}
        self.connection_rates = []
        self.start_time = time.time()
        
        # Initialize based on OS
        if self.system == 'linux':
            self.init_linux()
        elif self.system == 'windows':
            self.init_windows()
        else:
            print("Unsupported OS")
            sys.exit(1)
            
        self.log("Anti-DDoS protection initialized for " + self.system)
    
    def init_linux(self):
        """Initialize Linux-specific protections"""
        try:
            # Enable SYN cookies
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syncookies=1'], check=True)
            
            # Reduce SYN retries
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_syn_retries=3'], check=True)
            
            # Enable TCP SYN backlog
            subprocess.run(['sysctl', '-w', 'net.ipv4.tcp_max_syn_backlog=2048'], check=True)
            
            # Drop SYN packets coming in too fast
            subprocess.run(['iptables', '-N', 'SYN_FLOOD'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '-j', 'SYN_FLOOD'], check=True)
            subprocess.run(['iptables', '-A', 'SYN_FLOOD', '-m', 'limit', '--limit', '50/s', '--limit-burst', '100', '-j', 'RETURN'], check=True)
            subprocess.run(['iptables', '-A', 'SYN_FLOOD', '-j', 'DROP'], check=True)
            
            # General rate limiting
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', 'your_game_port', '-m', 'connlimit', '--connlimit-above', str(MAX_CONNECTIONS_PER_IP), '--connlimit-mask', '32', '-j', 'DROP'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', 'your_game_port', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'], check=True)
            subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', 'your_game_port', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--seconds', '60', '--hitcount', str(CONNECTION_RATE_LIMIT), '-j', 'DROP'], check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"Linux init failed: {e}")
    
    def init_windows(self):
        """Initialize Windows-specific protections"""
        try:
            # Enable SYN attack protection
            subprocess.run(['netsh', 'int', 'ip', 'set', 'dynamicport', 'tcp', 'start=49152', 'num=16384'], check=True)
            subprocess.run(['netsh', 'int', 'ip', 'set', 'global', 'synattackprotect=1'], check=True)
            subprocess.run(['netsh', 'int', 'ip', 'set', 'global', 'tcpmaxconnectresponse=3'], check=True)
            
        except subprocess.CalledProcessError as e:
            self.log(f"Windows init failed: {e}")
    
    def log(self, message):
        """Log messages to file and stdout"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f"[{timestamp}] {message}"
        print(log_msg)
        
        with open(LOG_FILE, 'a') as f:
            f.write(log_msg + '\n')
    
    def ban_ip(self, ip, reason):
        """Ban an IP address"""
        if ip in WHITELIST:
            self.log(f"Attempt to ban whitelisted IP {ip} blocked ({reason})")
            return
            
        self.banned_ips[ip] = time.time()
        
        if self.system == 'linux':
            try:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                self.log(f"Banned {ip} via iptables ({reason})")
            except subprocess.CalledProcessError as e:
                self.log(f"Failed to ban {ip}: {e}")
        elif self.system == 'windows':
            try:
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name="Block {ip}"', 'dir=in', 'action=block', f'remoteip={ip}'], check=True)
                self.log(f"Banned {ip} via Windows Firewall ({reason})")
            except subprocess.CalledProcessError as e:
                self.log(f"Failed to ban {ip}: {e}")
    
    def unban_expired_ips(self):
        """Remove expired bans"""
        now = time.time()
        expired = [ip for ip, timestamp in self.banned_ips.items() if now - timestamp > BAN_DURATION]
        
        for ip in expired:
            if self.system == 'linux':
                try:
                    subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                    self.log(f"Unbanned {ip} (ban expired)")
                except subprocess.CalledProcessError as e:
                    self.log(f"Failed to unban {ip}: {e}")
            elif self.system == 'windows':
                try:
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="Block {ip}"'], check=True)
                    self.log(f"Unbanned {ip} (ban expired)")
                except subprocess.CalledProcessError as e:
                    self.log(f"Failed to unban {ip}: {e}")
            
            del self.banned_ips[ip]
    
    def monitor_connections(self):
        """Monitor active connections and detect attacks"""
        # Get current connections (simplified - you'll need to adapt this to your game server)
        try:
            if self.system == 'linux':
                netstat = subprocess.run(['netstat', '-ntu'], capture_output=True, text=True).stdout.splitlines()
            else:  # windows
                netstat = subprocess.run(['netstat', '-n'], capture_output=True, text=True).stdout.splitlines()
            
            current_connections = defaultdict(int)
            
            for line in netstat:
                if 'your_game_port' in line:  # Replace with your game server port
                    parts = line.split()
                    if len(parts) > 4:
                        ip = parts[4].split(':')[0]
                        if ip != '127.0.0.1':
                            current_connections[ip] += 1
            
            # Check for connection limit violations
            for ip, count in current_connections.items():
                if ip in WHITELIST:
                    continue
                    
                if count > MAX_CONNECTIONS_PER_IP:
                    self.ban_ip(ip, f"too many connections ({count})")
            
            # Update connection rate tracking
            now = time.time()
            total_connections = sum(current_connections.values())
            self.connection_rates.append((now, total_connections))
            
            # Remove old rate data (last 60 seconds)
            self.connection_rates = [(t, c) for t, c in self.connection_rates if now - t <= 60]
            
            # Calculate connections per second
            if len(self.connection_rates) > 1:
                time_diff = self.connection_rates[-1][0] - self.connection_rates[0][0]
                conn_diff = self.connection_rates[-1][1] - self.connection_rates[0][1]
                if time_diff > 0:
                    cps = conn_diff / time_diff
                    if cps > CONNECTION_RATE_LIMIT:
                        self.log(f"High connection rate detected: {cps:.1f} connections/second")
            
        except Exception as e:
            self.log(f"Monitoring error: {e}")
    
    def run(self):
        """Main monitoring loop"""
        self.log("Starting Anti-DDoS protection")
        
        try:
            while True:
                self.unban_expired_ips()
                self.monitor_connections()
                time.sleep(MONITOR_INTERVAL)
                
        except KeyboardInterrupt:
            self.log("Stopping Anti-DDoS protection")
            sys.exit(0)

if __name__ == '__main__':
    # Check for root/admin privileges
    if (platform.system().lower() == 'linux' and os.geteuid() != 0) or \
       (platform.system().lower() == 'windows' and not ctypes.windll.shell32.IsUserAnAdmin()):
        print("This script requires administrator/root privileges")
        sys.exit(1)
    
    protector = AntiDDoS()
    protector.run()
