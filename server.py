#!/usr/bin/env python3
import socket
import threading
import time
import random
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import subprocess
import shlex

# ---------- CONFIGURATION ----------
HOST = "0.0.0.0"
PORT = 34962
FLAG = "flag{St11l_M11l_APT_Araintel_2025}"
SECRET_KEY = hashlib.sha256(b"Th1s1sN0tS3cur3").digest()
SIMATIC_CONTROLLER_INFO = """
SIMATIC S7-1500 CPU (firmware v2.5.3)
PROFINET Device ID: 0xB133D481
Module: SIMATIC ET 200SP
Vendor: Siemens AG
IP: 192.168.1.15
MAC: 00:1B:1B:1A:1A:1A
"""

# ---------- ICS SYSTEM STATE ----------
class SteelMillSystem:
    def __init__(self):
        self.furnace_temp = 850  # °C
        self.cooling_rate = 3.2  # °C/sec when cooling active
        self.overheat_threshold = 1250  # °C
        self.solenoids = {0x1A: False, 0x2B: False, 0x3C: True}
        self.alarm_status = False
        self.operator_override = False
        self.security_log = []
        self.incident_stage = 0
        self.profibus_attack_detected = False  # Track if a Profibus attack has occurred
        self.flag_released = False  # Track if the flag has been released

    def log_event(self, event, severity="INFO"):
        timestamp = datetime.now().strftime("2014-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] [{severity}] {event}"
        self.security_log.append(log_entry)
        if severity in ["WARNING", "CRITICAL"]:
            print(log_entry)

    def update_physics(self):
        while True:
            time.sleep(1)
            if self.furnace_temp > 1500:  # Stop updating and release flag
                if not self.flag_released:
                    self.flag_released = True
                    self.log_event("FURNACE TEMPERATURE EXCEEDED 1500°C - FLAG DISPENSED", "CRITICAL")
                    print(FLAG)  # Release the flag in the server output
                break  # Stop the loop
            if self.furnace_temp > 950:  # Log critical event after 950°C
                self.log_event(f"CRITICAL TEMPERATURE WARNING: {self.furnace_temp}°C", "CRITICAL")
            if self.profibus_attack_detected:  # Only update temperature after an attack
                if self.solenoids[0x1A] or self.solenoids[0x2B]:
                    self.furnace_temp -= self.cooling_rate * random.uniform(0.9, 1.1)
                else:
                    self.furnace_temp += 8.7 * (0.8 if self.solenoids[0x3C] else 1.2)
            if all(self.solenoids.values()):  # All solenoids are active
                self.furnace_temp += 15  # Increase temperature by 15°C
            if self.furnace_temp > self.overheat_threshold:
                self.alarm_status = True
                self.incident_stage = 2
                self.log_event(f"CRITICAL TEMPERATURE REACHED: {self.furnace_temp}°C", "CRITICAL")

# ---------- PROTOCOL HANDLERS ----------
class ICSProtocolHandler:
    @staticmethod
    def handle_profibus(data, system):
        try:
            if data.startswith(b"\x10\x02"):
                addr = data[2]
                cmd = data[3]
                if cmd == 0x4B:
                    solenoid_id = data[4]
                    state = data[5]
                    if addr == 0x1F:
                        if not system.operator_override:
                            system.solenoids[solenoid_id] = bool(state)
                            system.profibus_attack_detected = True  # Mark attack as detected
                            return True
                        else:
                            system.log_event("Blocked Profibus command during override", "WARNING")
        except:
            pass
        return False

    @staticmethod
    def handle_modbus(data, system):
        try:
            if len(data) > 8 and data[7] == 0x06:
                reg = int.from_bytes(data[8:10], 'big')
                value = int.from_bytes(data[10:12], 'big')
                if reg == 0x4000:
                    system.solenoids[0x1A] = bool(value & 0x1)
                    system.solenoids[0x2B] = bool(value & 0x2)
                    return True
        except:
            pass
        return False

# ---------- MAIN SERVER ----------
class SteelMillServer:
    def __init__(self):
        self.system = SteelMillSystem()
        self.physics_thread = threading.Thread(target=self.system.update_physics, daemon=True)
        self.physics_thread.start()
        self.root_mode = False  # Track if the user is in root mode
        self.current_user = None  # Track the current user
        self.directories = {
            "regis": ["/home", "/home/logs", "/home/config"],
            "root": ["/etc", "/etc/security", "/etc/network", "/root"]
        }
        self.current_directory = "/home"  # Start in the /home directory
        self.file_contents = {
            "/home/logs/error.log": "Error log: No critical errors found.\n",
            "/home/logs/access.log": "Access log: User regis logged in.\nWarning: Multiple failed authentication attempts from 192.168.1.135\n",
            "/home/config/app.conf": "App configuration: Debug mode enabled.\nController: SIMATIC S7-1500 CPU\nFirmware: v2.5.3\nUpdate Required: YES - Security patch pending (CVE-2020-15782)\n",
            "/home/config/db.conf": "Database configuration: Connection stable.\nHMI: SIMATIC HMI Panel KTP900\nVersion: V14 SP1\nSecurity Updates: NONE SINCE INSTALL\n",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nregis:x:1000:1000:regis:/home:/bin/bash\nsimatic:x:999:999:Siemens SIMATIC Service:/opt/siemens:/bin/false\n",
            "/etc/shadow": "root:$6$randomsalt$hashedpassword\nregis:$6$randomsalt$hashedpassword\nsimatic:!!:19052:0:99999:7:::\n",
            "/etc/network/interfaces": "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n    address 10.10.15.1\n    netmask 255.255.255.0\n    gateway 10.10.15.254\n    # PROFINET communication interface\n",
            "/etc/network/routes": "default via 10.10.15.254 dev eth0\n10.10.15.0/24 dev eth0 src 10.10.15.1\n192.168.1.0/24 via 10.10.15.254 dev eth0\n",
            "/etc/security/firewall.rules": "# WARNING: Default factory settings - minimal protection\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 102 -j ACCEPT # S7comm port\n-A INPUT -p udp --dport 161 -j ACCEPT # SNMP\n-A INPUT -p tcp --dport 502 -j ACCEPT # Modbus/TCP\n-A INPUT -p udp --dport 34962 -j ACCEPT # PROFINET\nCOMMIT\n",
            "/etc/security/auth.conf": "Authentication: Enabled\nTLS: 1.0, 1.1, 1.2\nSignature Algorithm: SHA1withRSA # VULNERABLE\nMessage Integrity: HMAC-based with static key\n# TODO: Update cryptographic protocols - current implementation vulnerable to CVE-2020-15782\n",
            "/root/simatic_info.txt": SIMATIC_CONTROLLER_INFO + "\nKnown vulnerabilities:\n- CVE-2020-15782: SIMATIC S7-1500 CPU message integrity bypass\n- CVE-2019-10929: PROFINET DCP message handling vulnerability\n\nTechnical Info:\nPort 102/tcp is used for S7comm communication\nIntegrity protection uses weak calculation method\nPROFINET communication vulnerable to DCP message flooding\n",
        }
        self.bash_history = []
        self.bash_vars = {"PATH": "/usr/bin:/bin", "HOME": "/home/regis"}
        self.bash_env = {}  # Para variables de entorno bash
        self.bash_aliases = {}  # Para alias de bash
        self.profinet_vulnerability_triggered = False  # Track if Profinet vulnerability is exploited
        self.profinet_safety_lock = True  # Safety lock for DISABLE_SAFETY_LOCK command
        self.dcp_identify_count = 0  # Count DCP_Identify messages for Profinet (CVE-2019-10929)
        self.s7comm_bypass_attempted = False  # Track S7comm message integrity bypass (CVE-2020-15782)

    def handle_bash_command(self, command):
        """Handle basic bash commands"""
        try:
            args = shlex.split(command.lower())
            if not args:
                return ""
                
            if args[0] == "echo":
                return " ".join(args[1:]) + "\n"
                
            elif args[0] == "grep" and len(args) > 2:
                pattern = args[1]
                text = args[2]
                if text in self.file_contents:
                    content = self.file_contents[text]
                    return "\n".join(line for line in content.splitlines() if pattern in line) + "\n"
                    
            elif args[0] == "find" and len(args) > 1:
                path = args[1]
                results = []
                for filepath in self.file_contents:
                    if filepath.startswith(path):
                        results.append(filepath)
                return "\n".join(results) + "\n"
                
            return f"{args[0]}: command not found\n"  # Remove "bash:" prefix
            
        except Exception as e:
            return f"error: {str(e)}\n"

    def handle_bash_script(self, script):
        """Handle bash script execution"""
        try:
            # Simple bash script interpreter
            lines = script.split(';')
            output = []
            for line in lines:
                line = line.strip()
                if line.startswith('#!/bin/bash') or not line:
                    continue
                if '=' in line and not line.startswith('echo'):
                    # Variable assignment
                    var, value = line.split('=', 1)
                    self.bash_env[var.strip()] = value.strip().strip('"\'')
                    continue
                if line.startswith('$'):
                    # Variable expansion
                    var = line[1:]
                    output.append(self.bash_env.get(var, ''))
                    continue
                # Execute existing commands as normal
                output.append(self.handle_bash_command(line))
            return '\n'.join(filter(None, output))
        except Exception as e:
            return f"bash: script error: {str(e)}\n"

    def handle_client(self, conn, addr):
        try:
            conn.sendall(b"STEEL MILL ICS CONTROL SYSTEM\n=============================\n")
            conn.sendall(b"Enter username: ")

            # User authentication
            username = conn.recv(1024).decode().strip().lower()
            if username not in ["regis", "root"]:
                conn.sendall(b"Unknown user. Connection closed.\n")
                conn.close()
                return

            conn.sendall(b"Enter authentication key: ")
            auth_key = conn.recv(1024).decode().strip()

            # Validate authentication key
            valid_credentials = {
                "regis": "STILLMILL-REGIS1",
                "root": "STILLMILL-ROOT1"
            }
            if username in valid_credentials and auth_key == valid_credentials[username]:
                self.current_user = username  # Set the current user
                conn.sendall(f"Authentication successful. Welcome, {username}.\n".encode())
            else:
                conn.sendall(b"Authentication failed. Connection closed.\n")
                conn.close()
                return

            while True:
                prompt = f"{self.current_user}@stillmill:{self.current_directory}"
                if self.current_user == "root":
                    prompt += "$ "
                else:
                    prompt += ": "
                conn.sendall(prompt.encode())  # Display prompt

                data = conn.recv(1024)
                if not data:
                    break
                command = data.decode().strip()

                # Handle cd command for directory navigation
                if command.lower().startswith("cd"):
                    target_dir = command[3:].strip().lower()
                    if target_dir in self.directories[self.current_user] or (self.current_user == "root" and target_dir == "/root"):
                        self.current_directory = target_dir
                        conn.sendall(f"Switched to {target_dir} directory.\n".encode())
                    else:
                        conn.sendall(b"Invalid directory. Available directories:\n")
                        conn.sendall("\n".join(self.directories[self.current_user]).encode() + b"\n")
                    continue

                # Handle ls command to list files in the current directory
                if command.lower() == "ls":
                    if self.current_directory == "/home":
                        conn.sendall(b"Available files: logs.txt, config.ini, system_status.txt\n")
                    elif self.current_directory == "/home/logs":
                        conn.sendall(b"Available files: error.log, access.log\n")
                    elif self.current_directory == "/home/config":
                        conn.sendall(b"Available files: app.conf, db.conf\n")
                    elif self.current_directory == "/etc":
                        conn.sendall(b"Available files: passwd, shadow, network.conf\n")
                    elif self.current_directory == "/etc/security":
                        conn.sendall(b"Available files: firewall.rules, auth.conf\n")
                    elif self.current_directory == "/etc/network":
                        conn.sendall(b"Available files: interfaces, routes\n")
                    elif self.current_directory == "/root" and self.current_user == "root":
                        conn.sendall(b"No files available in this directory.\n")
                    else:
                        conn.sendall(b"No files available in this directory.\n")
                    continue

                # Handle industrial commands
                if command.upper() in [
                    "STATUS", "OPEN_MAIN_VALVE", "CLOSE_MAIN_VALVE", "OPEN_EMERGENCY_VALVE",
                    "CLOSE_EMERGENCY_VALVE", "SHUTDOWN_GAS", "ENABLE_GAS", "GET_TEMPERATURE",
                    "GET_LOGS", "TRIGGER_ALARM", "RESET_ALARM", "ENGAGE_OVERRIDE", "DISABLE_OVERRIDE",
                    "GET_INCIDENT_STAGE", "PROFINET_DCP_OVERRIDE", "S7COMM_OVERRIDE",
                    "TERMINAL"
                ]:
                    if self.current_user != "root":
                        conn.sendall(b"Permission denied. Only root can execute industrial commands.\n")
                        continue

                    if command == "STATUS":
                        conn.sendall(self.system_status().encode() + b"\n")
                    elif command == "TERMINAL":
                        conn.sendall(b"\033c")  # Clear terminal
                        conn.sendall(b"Terminal initialized. To close, type 'close'.\n")
                        conn.sendall(b"Type 'OPEN_PORT_(PORT)' to open a port.\n")
                        while True:
                            conn.sendall(b"terminal> ")
                            terminal_command = conn.recv(1024).decode().strip().lower()
                            if terminal_command == "close" or terminal_command == "back" or terminal_command == "exit":
                                conn.sendall(b"Exiting terminal...\n")
                                break
                            elif terminal_command.startswith("open_port_"):
                                try:
                                    port = int(terminal_command.split("_")[-1])
                                    if port == 102:
                                        conn.sendall(b"Port 102/TCP opened. Listening on port 102...\n")
                                        self.handle_admin_terminal(conn)
                                        break
                                    else:
                                        conn.sendall(b"Invalid port. Try again.\n")
                                except ValueError:
                                    conn.sendall(b"Invalid command format. Use 'OPEN_PORT_(PORT)'.\n")
                            else:
                                conn.sendall(b"Unknown command. Type 'close', 'back', or 'exit' to leave.\n")
                    else:
                        pass

                # Handle PROFINET status command
                if command.upper() == "PROFINET_STATUS":
                    conn.sendall(b"SIMATIC S7-1500 PROFINET Status:\n")
                    conn.sendall(f"Safety Mechanism: {'BYPASSED' if not self.profinet_safety_lock else 'ACTIVE'}\n".encode())
                    conn.sendall(f"DCP_Identify Count: {self.dcp_identify_count}/3\n".encode())
                    conn.sendall(f"Message Integrity: {'COMPROMISED' if self.s7comm_bypass_attempted else 'INTACT'}\n".encode())
                    continue

                # Handle sudo -l command to list privileges
                if command.lower() == "sudo -l":
                    if self.current_user == "regis":
                        conn.sendall(b"User regis may run the following commands on stillmill:\n")
                        conn.sendall(b"    (ALL) ALL\n")
                        conn.sendall(b"    Factory commands available to root:\n")
                        conn.sendall(b"        STATUS, OPEN_MAIN_VALVE, CLOSE_MAIN_VALVE, OPEN_EMERGENCY_VALVE,\n")
                        conn.sendall(b"        CLOSE_EMERGENCY_VALVE, SHUTDOWN_GAS, ENABLE_GAS, GET_TEMPERATURE,\n")
                        conn.sendall(b"        GET_LOGS, TRIGGER_ALARM, RESET_ALARM, ENGAGE_OVERRIDE, DISABLE_OVERRIDE,\n")
                        conn.sendall(b"        GET_INCIDENT_STAGE, DISABLE_SAFETY_LOCK, ENABLE_SAFETY_LOCK\n")
                        conn.sendall(b"    Sudo commands:\n")
                        conn.sendall(b"        sudo su, sudo -l\n")
                    else:
                        conn.sendall(b"Permission denied. Only regis can use sudo -l.\n")
                    continue

                # Handle sudo su for switching to root
                if command.lower() == "sudo su" and self.current_user == "regis":
                    conn.sendall(b"Enter root password: ")
                    password = conn.recv(1024).decode().strip()
                    if password == "4531":  # Correct root password
                        self.current_user = "root"
                        self.root_mode = True
                        self.current_directory = "/root"  # Change directory to root's home
                        conn.sendall(b"Switched to root. You now have full access to factory commands.\n")
                    else:
                        conn.sendall(b"Incorrect password. Access denied.\n")
                    continue

                # Handle exit command for root to switch back to regis
                if command.lower() == "exit" and self.current_user == "root":
                    self.current_user = "regis"
                    self.root_mode = False
                    self.current_directory = "/home"  # Reset directory to /home
                    conn.sendall(b"Switched back to regis. Limited access restored.\n")
                    continue

                # Handle system commands
                if command.upper() in ["WHOAMI", "PWD", "HELP", "CAT LOGS.TXT"]:
                    command = command.upper()
                    if command == "WHOAMI":
                        conn.sendall(f"{self.current_user}\n".encode())
                        continue
                    elif command == "PWD":
                        conn.sendall(f"{self.current_directory}\n".encode())
                        continue
                    elif command == "HELP":
                        if self.current_user == "root":
                            conn.sendall(b"Available commands: STATUS, OPEN_MAIN_VALVE, CLOSE_MAIN_VALVE, OPEN_EMERGENCY_VALVE, CLOSE_EMERGENCY_VALVE, SHUTDOWN_GAS, ENABLE_GAS, GET_TEMPERATURE, GET_LOGS, TRIGGER_ALARM, RESET_ALARM, ENGAGE_OVERRIDE, DISABLE_OVERRIDE, GET_INCIDENT_STAGE, LS, WHOAMI, PWD, CAT LOGS.TXT, SUDO SU, SUDO -L, DISABLE_SAFETY_LOCK, ENABLE_SAFETY_LOCK, PROFINET_DCP_OVERRIDE, S7COMM_OVERRIDE, PROFINET_STATUS, CHECK_PRESSURE, CALIBRATE_SENSORS, RUN_DIAGNOSTICS, RESET_SYSTEM, CHECK_POWER_GRID, SYNC_CLOCK, UPDATE_FIRMWARE, PROFINET_SCAN, PROFINET_DEVICE_LIST, S7_DIAGNOSTICS, S7_CPU_STATUS, S7_MEMORY_USAGE, S7_IO_MODULES, PROFINET_TRAFFIC_STATS, PROFINET_PORT_STATUS, S7_RACK_INFO, S7_MODULE_INFO, PROFINET_ERROR_LOG, S7_SECURITY_LOG, SIMULATE_PORT_102_ATTACK\n")
                        else:
                            conn.sendall(b"Available commands: STATUS, OPEN_MAIN_VALVE, CLOSE_MAIN_VALVE, OPEN_EMERGENCY_VALVE, CLOSE_EMERGENCY_VALVE, SHUTDOWN_GAS, ENABLE_GAS, GET_TEMPERATURE, GET_LOGS, TRIGGER_ALARM, RESET_ALARM, ENGAGE_OVERRIDE, DISABLE_OVERRIDE, GET_INCIDENT_STAGE, LS, WHOAMI, PWD, CAT LOGS.TXT, SUDO SU, SUDO -L\n")
                        continue
                    elif command == "CAT LOGS.TXT":
                        logs = "\n".join(self.system.security_log[-5:])
                        conn.sendall(logs.encode() + b"\n")
                        continue

                # Handle bash-style commands if they don't match system commands
                result = self.handle_bash_command(command)
                conn.sendall(result.encode())
        except Exception as e:
            self.system.log_event(f"Connection error: {str(e)}", "ERROR")
        finally:
            conn.close()

    def handle_admin_terminal(self, conn):
        """Simulate an administrator terminal for executing commands."""
        conn.sendall(b"\033c")  # Clear terminal
        conn.sendall(b"Administrator terminal. Insert administrator command.\n")
        conn.sendall(b"OPTIONS: DISABLE_SAFETY_LOCK, STOP\n")
        safety_disabled = False
        while True:
            conn.sendall(b"administrator> ")
            admin_command = conn.recv(1024).decode().strip().upper()
            if admin_command == "DISABLE_SAFETY_LOCK":
                if not safety_disabled:
                    self.profinet_safety_lock = False
                    self.system.solenoids[0x1A] = True
                    self.system.solenoids[0x2B] = True
                    self.system.solenoids[0x3C] = True
                    self.system.log_event("Safety lock disabled. Furnace temperature control compromised.", "CRITICAL")
                    conn.sendall(b"Safety lock disabled. Proceed with 'STOP'.\n")
                    safety_disabled = True
                else:
                    conn.sendall(b"Safety lock already disabled. Use 'STOP' to finalize.\n")
            elif admin_command == "STOP":
                if safety_disabled:
                    self.system.furnace_temp = 1500  # Trigger temperature increase
                    self.system.log_event("Critical error: Furnace temperature reached 1500°C.", "CRITICAL")
                    conn.sendall(b"Critical error. Check console.\n")
                    conn.sendall(b"Returning to root...\n")
                    break
                else:
                    conn.sendall(b"Cannot execute 'STOP' before disabling safety lock.\n")
            else:
                conn.sendall(b"Unknown command. OPTIONS: DISABLE_SAFETY_LOCK, STOP\n")

    def system_status(self):
        """Generate a status report for the system."""
        return (
            f"SIMATIC S7-1500 CONTROL SYSTEM STATUS:\n"
            f"FURNACE TEMPERATURE: {self.system.furnace_temp:.2f}°C\n"
            f"MAIN COOLING VALVE: {'OPEN' if self.system.solenoids[0x1A] else 'CLOSED'}\n"
            f"EMERGENCY COOLING VALVE: {'OPEN' if self.system.solenoids[0x2B] else 'CLOSED'}\n"
            f"GAS SUPPLY: {'ENABLED' if self.system.solenoids[0x3C] else 'SHUT DOWN'}\n"
            f"ALARM STATUS: {'TRIGGERED' if self.system.alarm_status else 'NORMAL'}\n"
            f"INCIDENT STAGE: {self.system.incident_stage}\n"
            f"SECURITY STATUS: {'COMPROMISED' if not self.profinet_safety_lock or self.s7comm_bypass_attempted else 'NORMAL'}\n"
        )

    def decrypt_command(self, data):
        iv = data[:16]
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data[16:]), 16).decode()

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen(5)
            print(f"[+] ICS Simulation Server running on {HOST}:{PORT}")
            while True:
                conn, addr = s.accept()
                self.system.log_event(f"New connection from {addr[0]}:{addr[1]}")
                thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                thread.start()

if __name__ == "__main__":
    server = SteelMillServer()
    server.start_server()

# ---------- FURNACE MODULE ----------
class Furnace:
    def __init__(self):
        self.temperature = 850  # °C
        self.pressure = 101.3  # kPa
        self.status = "Operational"

    def increase_temperature(self, amount):
        self.temperature += amount
        if self.temperature > 1250:
            self.status = "Overheated"
        return self.temperature

    def decrease_temperature(self, amount):
        self.temperature -= amount
        if self.temperature < 850:
            self.status = "Cooling"
        return self.temperature

    def get_status(self):
        return {
            "temperature": self.temperature,
            "pressure": self.pressure,
            "status": self.status,
        }

# Example usage of Furnace class
if __name__ == "__main__":
    furnace = Furnace()
    print(f"Initial Furnace Status: {furnace.get_status()}")
    furnace.increase_temperature(100)
    print(f"Updated Furnace Status: {furnace.get_status()}")

# ---------- PROTOCOL MODULE ----------
class ProtocolHandler:
    def __init__(self):
        self.supported_protocols = ["PROFIBUS", "MODBUS"]

    def handle_profibus(self, data, system):
        """Handle Profibus protocol commands."""
        try:
            if data.startswith(b"\x10\x02"):
                addr = data[2]
                cmd = data[3]
                if cmd == 0x4B:
                    solenoid_id = data[4]
                    state = data[5]
                    if addr == 0x1F:
                        system.solenoids[solenoid_id] = bool(state)
                        return f"Profibus: Solenoid {hex(solenoid_id)} set to {'ON' if state else 'OFF'}"
        except Exception as e:
            return f"Error handling Profibus: {str(e)}"
        return "Invalid Profibus command"

    def handle_modbus(self, data, system):
        """Handle Modbus protocol commands."""
        try:
            if len(data) > 8 and data[7] == 0x06:
                reg = int.from_bytes(data[8:10], 'big')
                value = int.from_bytes(data[10:12], 'big')
                if reg == 0x4000:
                    system.solenoids[0x1A] = bool(value & 0x1)
                    system.solenoids[0x2B] = bool(value & 0x2)
                    return f"Modbus: Solenoids updated with value {value}"
        except Exception as e:
            return f"Error handling Modbus: {str(e)}"
        return "Invalid Modbus command"

    def handle_protocol(self, protocol, data, system):
        """Dispatch protocol-specific handlers."""
        if protocol.upper() == "PROFIBUS":
            return self.handle_profibus(data, system)
        elif protocol.upper() == "MODBUS":
            return self.handle_modbus(data, system)
        else:
            return f"Unsupported protocol: {protocol}"

# Example usage of ProtocolHandler class
if __name__ == "__main__":
    protocol_handler = ProtocolHandler()
    example_data = b"\x10\x02\x1F\x4B\x1A\x01"
    print(protocol_handler.handle_profibus(example_data, SteelMillSystem()))