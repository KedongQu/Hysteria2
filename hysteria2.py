# Hysteria2 Installation Script
import glob
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib import parse

import requests


def agree_treaty():       #Agree terms or not
    def hy_shortcut():   #Add hy2 shortcut
        hy2_shortcut = Path(r"/usr/local/bin/hy2")  #Create shortcut
        hy2_shortcut.write_text("#!/bin/bash\nwget -O hy2.py https://raw.githubusercontent.com/KedongQu/Hysteria2/refs/heads/main/hysteria2.py && chmod +x hy2.py && python3 hy2.py\n") 
        hy2_shortcut.chmod(0o755)
    file_agree = Path(r"/etc/hy2config/agree.txt") 
    if file_agree.exists():       #.exists()Check if the file exists; if it exists, return true and skip this step
        print("You've already agreed, thank you")
        hy_shortcut()
    else:
        while True:
            print("I agree that when using this program I must comply with the laws and regulations of the jurisdiction where the deployment server is located, the country where the server is located, and the user’s country. The author of this program is not responsible for any improper actions by the user. This program is intended solely for learning and communication purposes and must not be used for any commercial purposes.")
            choose_1 = input("Do you agree and read above the terms and conditions for installing Hysteria2? [y/n]:")
            if choose_1 == "y":
                check_file = subprocess.run("mkdir /etc/hy2config && touch /etc/hy2config/agree.txt && touch /etc/hy2config/hy2_url_scheme.txt",shell = True)
                print(check_file)    #This file is created when the user agrees to the installation, this step is skipped during the next automatic check
                hy_shortcut()
                break
            elif choose_1 == "n":
                print("Please agree to these terms and conditions before installation")
                sys.exit()
            else:
                print("\033[91mPlease enter the correct option!\033[m")

def hysteria2_install():    #Install hysteria2
    while True:
        choice_1 = input("Install/Update hysteria2 [y/n] :")
        if choice_1 == "y":
            print("1. Install the latest version by default\n2. Install the specified version")
            choice_2 = input("Please enter your options:")
            if choice_2 == "1":
                hy2_install = subprocess.run("bash <(curl -fsSL https://get.hy2.sh/)",shell = True,executable="/bin/bash")  #Install using the official hy2 script
                print(hy2_install)
                print("--------------")
                print("\033[91mhysteria2 Installation complete. Please modify the configuration\033[m")
                print("--------------")
                hysteria2_config()
                break
            elif choice_2 == "2":
                version_1 = input("Please enter the version number you wish to install (just enter the version number directly, no need to add \"v\", e.g., 2.6.0): ")
                hy2_install_2 = subprocess.run(f"bash <(curl -fsSL https://get.hy2.sh/) --version v{version_1}",shell=True,executable="/bin/bash")  #Install the specified version
                print(hy2_install_2)
                print("--------------")
                print(f"\033[91mHysteria2 version{version_1}installation complete. Please enter options to modify configuration!\033[m")
                print("--------------")
                hysteria2_config()
                break
            else:
                print("\033[91mInput error, please re-enter\033[m")
        elif choice_1 == "n":
            print("Hysteria2 installation has been cancelled")
            break
        else:
            print("\033[91mInput error, please re-enter\033[m")

def hysteria2_uninstall():   #Uninstall hysteria2
    while True:
        choice_1 = input("Do you want to uninstall Hysteria2? [y/n] :")
        if choice_1 == "y":
            hy2_uninstall_1 = subprocess.run("bash <(curl -fsSL https://get.hy2.sh/) --remove",shell = True,executable="/bin/bash")   #Uninstall using the official hy2 script
            print(hy2_uninstall_1)
            #Stop and disable the iptables recovery service
            subprocess.run(["systemctl", "stop", "hysteria-iptables.service"], stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "hysteria-iptables.service"], stderr=subprocess.DEVNULL)
            #Clean up iptables rules
            subprocess.run(["/bin/bash", "/etc/hy2config/jump_port_back.sh"], stderr=subprocess.DEVNULL)
            #Delete all configuration files and services
            
            #Using glob to handle wildcard patterns
            wildcard_paths = glob.glob("/etc/systemd/system/multi-user.target.wants/hysteria-server@*.service")
            for path in wildcard_paths:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
            
            #Delete other paths
            paths_to_remove = [
                "/etc/hysteria",
                "/etc/systemd/system/multi-user.target.wants/hysteria-server.service",
                "/etc/systemd/system/hysteria-iptables.service",
                "/etc/hy2config/iptables-rules.v4",
                "/etc/hy2config/iptables-rules.v6",
                "/etc/ssl/private/",
                "/etc/hy2config",
                "/usr/local/bin/hy2"
            ]
            for path_str in paths_to_remove:
                try:
                    path = Path(path_str)
                    if path.is_file():
                        path.unlink(missing_ok=True)
                    elif path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                except Exception:
                    pass
            
            subprocess.run(["systemctl", "daemon-reload"])
            print("Hysteria2 uninstallation complete")
            sys.exit()
        elif choice_1 == "n":
            print("The uninstallation of hysteria2 has been cancelled")
            break
        else:
            print("\033[91mInput error, please re-enter\033[m")

def server_manage():   #Hysteria2 Service Management
    while True:
            print("1. Start(Set to start on boot)\n2. Stop\n3. Restart\n4. Service Status\n5. Logs\n6. View hy2 version information\n0. Back")
            choice_2 = input("Please enter your options:")
            if choice_2 == "1":
                print(subprocess.run("systemctl enable --now hysteria-server.service",shell=True))
            elif choice_2 == "2":
                print(subprocess.run("systemctl stop hysteria-server.service",shell=True))
            elif choice_2 == "3":
                print(subprocess.run("systemctl restart hysteria-server.service",shell=True))
            elif choice_2 == "4":
                print("\033[91mType q to exit\033[m")
                print(subprocess.run("systemctl status hysteria-server.service",shell=True))
            elif choice_2 == "5":
                print(subprocess.run("journalctl --no-pager -e -u hysteria-server.service",shell=True))
            elif choice_2 == "6":
                os.system("/usr/local/bin/hysteria version")
            elif choice_2 == "0":
                break
            else:
                print("\033[91mInput error, please re-enter\033[m")

def create_iptables_persistence_service():
    """Create a systemd service to restore iptables rules at startup"""
    #Create a recovery script that includes error handling
    restore_script_content = """#!/bin/bash
# Hysteria2 iptables rules restoration script

set -e  #Exit when an error occurs

#Verify and restore IPv4 rules
if [ -f /etc/hy2config/iptables-rules.v4 ]; then
    if [ -s /etc/hy2config/iptables-rules.v4 ]; then
        if iptables-restore -t < /etc/hy2config/iptables-rules.v4 2>/dev/null; then
            iptables-restore < /etc/hy2config/iptables-rules.v4
            echo "IPv4 iptables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "The IPv4 iptables rule file is invalid, skip restoration" | logger -t hysteria2-iptables
        fi
    fi
fi

#Verify and restore IPv6 rules
if [ -f /etc/hy2config/iptables-rules.v6 ]; then
    if [ -s /etc/hy2config/iptables-rules.v6 ]; then
        if ip6tables-restore -t < /etc/hy2config/iptables-rules.v6 2>/dev/null; then
            ip6tables-restore < /etc/hy2config/iptables-rules.v6
            echo "IPv6 iptables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "The IPv6 iptables rule file is invalid, skip restoration" | logger -t hysteria2-iptables
        fi
    fi
fi

exit 0
"""
    restore_script_path = Path("/etc/hy2config/restore-iptables.sh")
    
    #Create systemd service
    service_content = """[Unit]
Description=Restore Hysteria2 iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/hy2config/restore-iptables.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
"""
    service_path = Path("/etc/systemd/system/hysteria-iptables.service")
    try:
        # Recovery script
        restore_script_path.write_text(restore_script_content)
        restore_script_path.chmod(0o755)
        
        # Service Documents
        service_path.write_text(service_content)
        
        # Reload systemd and enable services
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "hysteria-iptables.service"], check=True)
        print("iptables persistent service has been created")
    except Exception as e:
        print(f"\033[91mFailed to create iptables persistent service: {e}\033[m")

def save_iptables_rules():
    """Save the current iptables and ip6tables rules"""
    try:
        # Create configuration directory
        config_dir = Path("/etc/hy2config")
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Save IPv4 rules
        with open("/etc/hy2config/iptables-rules.v4", "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True, text=True)
        print("IPv4 iptables rules have been saved")
        
        # Save IPv6 rules
        with open("/etc/hy2config/iptables-rules.v6", "w") as f:
            subprocess.run(["ip6tables-save"], stdout=f, check=True, text=True)
        print("IPv6 iptables rules have been saved")
        
        return True
    except Exception as e:
        print(f"\033[91mFailed to save iptables rules: {e}\033[m")
        return False

hy2_domain = "You are handsome"   #These two variables are purely for praising you who are watching my code
domain_name = "Super handsome"
insecure = "You're so handsome"
def hysteria2_config():     #Hysteria2 configuration
    global hy2_domain,domain_name, insecure
    hy2_config = Path(r"/etc/hysteria/config.yaml")  # Configuration file path
    hy2_url_scheme = Path(r"/etc/hy2config/hy2_url_scheme.txt")  # Configuration file path
    while True:
        choice_1 = input("1. hy2 configuration view\n2. hy2 configuration modification\n3. Manually modify hy2 configuration\n0. Back\nPlease enter your options:")
        if choice_1 == "1":
            while True:
                    try:
                        os.system("clear")
                        print("Your official configuration file:\n")
                        print(hy2_config.read_text())
                        print(hy2_url_scheme.read_text())
                        print("clash,surge,singbox templates under /etc/hy2config/, please check by yourself\n")
                        break
                    except FileNotFoundError:     #If the configuration file cannot be found, output "Configuration file not found"
                        print("\033[91mConfiguration file not found\033[m")
                    break
        elif choice_1 == "2":
            try:
                while True:
                    try:
                        hy2_port = int(input("Please enter the port number:"))
                        if hy2_port <= 0 or hy2_port >= 65536:
                            print("The port number range is 1 to 65535. Please re-enter")
                        else:
                            break
                    except ValueError:     #The error message indicates a problem with the system. It checks if the user input is a number. Since the `int` has already been converted to a number, inputting a decimal point or other strings will trigger this error
                        print("The port number can only be a number and cannot contain a decimal point. Please re-enter")
                hy2_username = input("Please enter your username:\n")
                hy2_username = urllib.parse.quote(hy2_username)
                hy2_passwd = input("Please enter your strong password:\n")
                hy2_url = input("Please enter the domain name you want to disguise(Please add https:// in front):\n")
                while True:
                    hy2_brutal = input("Enable Brutal mode(Disable recommended)?[y/n]:")
                    if hy2_brutal == "y":
                        brutal_mode = "false"
                        break
                    elif hy2_brutal == "n":
                        brutal_mode = "true"
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    hy2_obfs = input("Enable obfuscation mode(Disable recommended)?[y/n]:")
                    if hy2_obfs == "y":
                        obfs_passwd = input("Please enter your obfuscation password:\n")
                        obfs_mode = f"obfs:\n  type: salamander\n  \n  salamander:\n    password: {obfs_passwd}"
                        obfs_passwd = urllib.parse.quote(obfs_passwd)
                        obfs_scheme = f"&obfs=salamander&obfs-password={obfs_passwd}"
                        break
                    elif hy2_obfs == "n":
                        obfs_mode = ""
                        obfs_scheme = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    hy2_sniff = input("Enable protocol sniffing(Sniff)[y/n]:")
                    if hy2_sniff == "y":
                        sniff_mode = "sniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: false\n  tcpPorts: 80,443,8000-9000\n  udpPorts: all"
                        break
                    elif hy2_sniff == "n":
                        sniff_mode = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    jump_port_choice = input("Enable port hopping?(y/n):")
                    if jump_port_choice == "y":
                        print("Please select your v4 network interface(default eth0)")
                        # Display available network interfaces
                        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
                        if result.returncode == 0:
                            for line in result.stdout.strip().split('\n'):
                                # Extract Interface Name
                                if ':' in line:
                                    parts = line.split(':', 2)
                                    if len(parts) >= 2:
                                        print(f"  - {parts[1].strip()}")
                        interface_name = input("Please enter the network interface name:")
                        try:
                            first_port = int(input("Start port number:"))
                            last_port = int(input("End port number:"))
                            if first_port <= 0 or first_port >= 65536:
                                print("Start port number range is 1~65535, please re-enter")
                            elif last_port <= 0 or last_port >= 65536:
                                print("End port number range is 1~65535, please re-enter")
                            elif first_port > last_port:
                                print("Start port number cannot be greater than the end port number, please re-enter")
                            else:
                                # Initialize IPv6 variables
                                has_ipv6 = False
                                ipv6_interface = None
                                
                                while True:
                                    jump_port_ipv6 = input("Enable IPv6 port hopping?(y/n):")
                                    if jump_port_ipv6 == "y":
                                        print("Please select your v6 network interface:")
                                        # Display available network interfaces
                                        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
                                        if result.returncode == 0:
                                            for line in result.stdout.strip().split('\n'):
                                                if ':' in line:
                                                    parts = line.split(':', 2)
                                                    if len(parts) >= 2:
                                                        print(f"  - {parts[1].strip()}")
                                        interface6_name = input("Please enter your v6 network interface name:")
                                        subprocess.run(["ip6tables", "-t", "nat", "-A", "PREROUTING", "-i", interface6_name,
                                                      "-p", "udp", "--dport", f"{first_port}:{last_port}",
                                                      "-j", "REDIRECT", "--to-ports", str(hy2_port)])
                                        # Record IPv6 configuration information for cleanup scripts
                                        has_ipv6 = True
                                        ipv6_interface = interface6_name
                                        break
                                    elif jump_port_ipv6 == "n":
                                        has_ipv6 = False
                                        ipv6_interface = None
                                        break
                                    else:
                                        print("\033[91mInput error, please re-enter\033[m")
                                script_path = Path("/etc/hy2config/jump_port_back.sh")  #Check if the recovery script exists
                                if script_path.exists():
                                    subprocess.run(["/bin/bash", str(script_path)], stderr=subprocess.DEVNULL)
                                    script_path.unlink(missing_ok=True)
                                
                                # Apply iptables rules
                                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface_name, 
                                              "-p", "udp", "--dport", f"{first_port}:{last_port}", 
                                              "-j", "REDIRECT", "--to-ports", str(hy2_port)])
                                
                                # Create a cleanup script
                                jump_port_back = Path("/etc/hy2config/jump_port_back.sh")
                                cleanup_script = f"""#!/bin/sh
# Hysteria2 port hopping cleanup script
iptables -t nat -D PREROUTING -i {interface_name} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}
"""
                                if has_ipv6 and ipv6_interface:
                                    cleanup_script += f"ip6tables -t nat -D PREROUTING -i {ipv6_interface} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}\n"
                                
                                jump_port_back.write_text(cleanup_script)
                                jump_port_back.chmod(0o755)  # More secure permission settings
                                
                                # Storing iptables rules for persistence
                                print("Saving iptables rules for automatic recovery after reboot...")
                                if save_iptables_rules():
                                    # Create a systemd service to restore rules at startup
                                    create_iptables_persistence_service()
                                    print("\033[92mPort hopping rules have been configured and persisted, and will be automatically restored after a system reboot\033[m")
                                else:
                                    print("\033[91mWarning: The iptables rules have been applied but persistence has failed. Reconfiguration may be required after a system reboot\033[m")
                                
                                jump_ports_hy2 = f"&mport={first_port}-{last_port}"
                                break
                        except ValueError:  # The error message indicates a problem with the system. It checks if the user input is a number. Since the `int` has already been converted to a number, inputting a decimal point or other strings will trigger this error
                            print("The port number can only be a number and cannot contain a decimal point. Please re-enter")
                    elif jump_port_choice == "n":
                        jump_ports_hy2 = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    print("1. Automatically apply for domain certificates\n2. Self-signed certificate(No Domain)\n3. Manually select certificate path")
                    choice_2 = input("Please enter your option:")
                    if choice_2 == "1":
                        hy2_domain = input("Please enter your domain:\n")
                        domain_name = hy2_domain
                        hy2_email = input("Please enter your email address:\n")
                        domain_name = ""
                        while True:
                            choice_acme = input("Configure ACME DNS?(If you don't know what it is, please don't select it) [y/n]:")
                            if choice_acme == 'y':
                                while True:
                                    os.system('clear')
                                    dns_name = input("dns:\n1.Cloudflare\n2.Duck DNS\n3.Gandi.net\n4.Godaddy\n5.Name.com\n6.Vultr\nPlease enter your options:")
                                    if dns_name == '1':
                                        dns_token = input("Input Cloudflare's Global api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: cloudflare\n    config:\n      cloudflare_api_token: {dns_token}"
                                        break
                                    elif dns_name == '2':
                                        dns_token = input("Input Duck DNS's api_token:")
                                        override_domain = input("In-put Duck DNS's override_domain:")
                                        acme_dns = f"type: dns\n  dns:\n    name: duckdns\n    config:\n      duckdns_api_token: {dns_token}\n    duckdns_override_domain: {override_domain}"
                                        break
                                    elif dns_name == '3':
                                        dns_token = input("Input Gandi.net's api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: gandi\n    config:\n      gandi_api_token: {dns_token}"
                                        break
                                    elif dns_name == '4':
                                        dns_token = input("Input Godaddy's api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: godaddy\n    config:\n      godaddy_api_token: {dns_token}"
                                        break
                                    elif dns_name == '5':
                                        dns_token = input("Input Name.com's namedotcom_token:")
                                        dns_user = input("In-put Name.com's namedotcom_user:")
                                        namedotcom_server = input("In-put Name.com's namedotcom_server:")
                                        acme_dns = f"type: dns\n  dns:\n    name: {dns_name}\n    config:\n      namedotcom_token: {dns_token}\n      namedotcom_user: {dns_user}\n      namedotcom_server: {namedotcom_server}"
                                        break
                                    elif dns_name == '6':
                                        dns_token = input("Input Vultr's API Key:")
                                        acme_dns = f"type: dns\n  dns:\n    name: {dns_name}\n    config:\n      vultr_api_key: {dns_token}"
                                        break
                                    else:
                                        print("Input error, please re-enter")
                                break
                            elif choice_acme == 'n':
                                acme_dns = ""
                                break
                            else:
                                print("Input error, please re-enter")
                        insecure = "&insecure=0"
                        hy2_config.write_text(f"listen: :{hy2_port} \n\nacme:\n  domains:\n    - {hy2_domain} \n  email: {hy2_email} \n  {acme_dns} \n\nauth:\n  type: password\n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url} \n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "2":    #Get IPv4 address
                        def validate_and_get_ipv4():
                            """Helper function to get and validate IPv4 address from user"""
                            while True:
                                ip_input = input("Unable to obtain an IP address automatically, please manually enter the server's IPv4 address:").strip()
                                try:
                                    # Verify that it is a valid IPv4 address
                                    ipaddress.IPv4Address(ip_input)
                                    return ip_input
                                except ipaddress.AddressValueError:
                                    print(f"\033[91mInvalid IPv4 address: {ip_input}，please re-enter\033[m")
                        
                        def validate_and_get_ipv6():
                            """Helper function to get and validate IPv6 address from user"""
                            while True:
                                ip_input = input("Unable to obtain an IP address automatically, please manually enter the server's IPv6 address:").strip()
                                try:
                                    # Verify that it is a valid IPv6 address
                                    ipaddress.IPv6Address(ip_input)
                                    return ip_input
                                except ipaddress.AddressValueError:
                                    print(f"\033[91mInvalid IPv6 address: {ip_input}，please re-enter\033[m")
                        
                        def get_ipv4_info():
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requests.get('http://ip-api.com/json/', headers=headers, timeout=3)
                                response.raise_for_status()
                                ip_data = response.json()
                                isp = ip_data.get('isp', '')

                                if 'cloudflare' in isp.lower():
                                    print("Warp detected. Please enter the correct server IPv4 address")
                                    hy2_domain = validate_and_get_ipv4()
                                else:
                                    hy2_domain = ip_data.get('query', '')

                                print(f"IPV4 WAN IP: {hy2_domain}")

                            except requests.RequestException as e:
                                print(f"Request failed: {e}")
                                print("Try using an alternative method to obtain the IP address...")
                                # Use an alternative method to obtain the IP address
                                try:
                                    result = subprocess.run(['curl', '-4', '-s', 'ifconfig.me'], capture_output=True, text=True, timeout=5)
                                    if result.returncode == 0 and result.stdout.strip():
                                        ip = result.stdout.strip()
                                        # Verify IPv4 format
                                        try:
                                            ipaddress.IPv4Address(ip)
                                            hy2_domain = ip
                                            print(f"IPV4 WAN IP: {hy2_domain}")
                                        except ipaddress.AddressValueError:
                                            # Invalid format, prompt user to enter manually
                                            hy2_domain = validate_and_get_ipv4()
                                    else:
                                        # If it still fails, prompt the user to enter the information manually
                                        hy2_domain = validate_and_get_ipv4()
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                                    # If the alternative method also fails, prompt the user to enter the information manually
                                    hy2_domain = validate_and_get_ipv4()

                        def get_ipv6_info():    #Get IPv6 address
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requests.get('https://api.ip.sb/geoip', headers=headers, timeout=3)
                                response.raise_for_status()
                                ip_data = response.json()
                                isp = ip_data.get('isp', '')

                                if 'cloudflare' in isp.lower():
                                    print("Warp detected. Please enter the correct server IPv6 address")
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"
                                else:
                                    hy2_domain = f"[{ip_data.get('ip', '')}]"

                                print(f"IPV6 WAN IP: {hy2_domain}")

                            except requests.RequestException as e:
                                print(f"Request failed: {e}")
                                print("Try using an alternative method to obtain the IP address...")
                                # Use an alternative method to obtain an IPv6 address
                                try:
                                    result = subprocess.run(['curl', '-6', '-s', 'ifconfig.me'], capture_output=True, text=True, timeout=5)
                                    if result.returncode == 0 and result.stdout.strip():
                                        ip = result.stdout.strip()
                                        # Verify IPv6 format
                                        try:
                                            ipaddress.IPv6Address(ip)
                                            hy2_domain = f"[{ip}]"
                                            print(f"IPV6 WAN IP: {hy2_domain}")
                                        except ipaddress.AddressValueError:
                                            # Invalid format, prompt user to enter manually
                                            ipv6_input = validate_and_get_ipv6()
                                            hy2_domain = f"[{ipv6_input}]"
                                    else:
                                        # If it still fails, prompt the user to enter the information manually
                                        ipv6_input = validate_and_get_ipv6()
                                        hy2_domain = f"[{ipv6_input}]"
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                                    # If the alternative method also fails, prompt the user to enter the information manually
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"

                        def generate_certificate():      #Generate self-signed certificate
                            global domain_name
                            # Prompt the user to enter a domain name
                            user_domain = input("Please enter the domain name you want to use for the self-signed certificate(default is bing.com): ")
                            domain_name = user_domain.strip() if user_domain else "bing.com"

                            # Verify domain format
                            if re.match(r'^[a-zA-Z0-9.-]+$', domain_name):
                                # Define target directory
                                target_dir = "/etc/ssl/private"

                                # Check and create the target directory
                                if not os.path.exists(target_dir):
                                    print(f"target directory {target_dir} Does not exist, being created...")
                                    os.makedirs(target_dir)
                                    if not os.path.exists(target_dir):
                                        print(f"Unable to create directory {target_dir}，Please check your permissions")
                                        exit(1)

                                # Generate EC parameter file
                                ec_param_file = f"{target_dir}/ec_param.pem"
                                subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-out", ec_param_file],
                                               check=True)

                                # Generate certificate and private key
                                cmd = [
                                    "openssl", "req", "-x509", "-nodes", "-newkey", f"ec:{ec_param_file}",
                                    "-keyout", f"{target_dir}/{domain_name}.key",
                                    "-out", f"{target_dir}/{domain_name}.crt",
                                    "-subj", f"/CN={domain_name}", "-days", "36500"
                                ]
                                subprocess.run(cmd, check=True)

                                # Set file permissions
                                os.system(f"chmod 666 {target_dir}/{domain_name}.key && chmod 666 {target_dir}/{domain_name}.crt && chmod 777 /etc/ssl/private/")

                                print("Self-signed certificate and private key have been generated!")
                                print(f"The certificate file has been saved to {target_dir}/{domain_name}.crt")
                                print(f"The private key file has been saved to {target_dir}/{domain_name}.key")
                            else:
                                print("Invalid domain format. Please enter a valid domain name!")
                                generate_certificate()

                        generate_certificate()
                        while True:
                            ip_mode = input("1. IPv4 mode\n2. IPv6 mode\nPlease enter your options:")
                            if ip_mode == '1':
                                get_ipv4_info()
                                break
                            elif ip_mode == '2':
                                get_ipv6_info()
                                break
                            else:
                                print("\033[91mInput error, please re-enter\033[m")
                        insecure = "&insecure=1"
                        hy2_config.write_text(f"listen: :{hy2_port} \n\ntls: \n  cert: /etc/ssl/private/{domain_name}.crt \n  key: /etc/ssl/private/{domain_name}.key \n\nauth: \n  type: password \n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy \n  proxy: \n    url: {hy2_url} \n    rewriteHost: true \n\nignoreClientBandwidth: {brutal_mode} \n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "3":
                        hy2_cert = input("Please enter your certificate path:\n")
                        hy2_key = input("Please enter your key path:\n")
                        hy2_domain = input("Please enter your domain:\n")
                        domain_name = hy2_domain
                        domain_name = ""
                        insecure = "&insecure=0"
                        hy2_config.write_text(f"listen: :{hy2_port}\n\ntls:\n  cert: {hy2_cert}\n  key: {hy2_key}\n\nauth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")

                os.system("clear")
                hy2_passwd = urllib.parse.quote(hy2_passwd)
                hy2_v2ray = f"hysteria2://{hy2_passwd}@{hy2_domain}:{hy2_port}?sni={domain_name}{obfs_scheme}{insecure}{jump_ports_hy2}#{hy2_username}"
                print("Your v2ray QR:\n")
                time.sleep(1)
                os.system(f'echo "{hy2_v2ray}" | qrencode -s 1 -m 1 -t ANSI256 -o -')
                print(f"\n\n\033[91mYour hy2 link is: {hy2_v2ray}\nUse v2ray/nekobox/v2rayNG/nekoray Import\033[m\n\n")
                hy2_url_scheme.write_text(f"Your v2ray hy2 link is:{hy2_v2ray}\n")
                print("Downloading clash,sing-box,surge configuration file to /etc/hy2config/clash.yaml")
                hy2_v2ray_url = urllib.parse.quote(hy2_v2ray)
                url_rule = "&ua=&selectedRules=%22balanced%22&customRules=%5B%5D"
                os.system(f"curl -o /etc/hy2config/clash.yaml 'https://sub.crazyact.com/clash?config={hy2_v2ray_url}{url_rule}'")
                os.system(f"curl -o /etc/hy2config/sing-box.yaml 'https://sub.crazyact.com/singbox?config={hy2_v2ray_url}{url_rule}'")
                os.system(f"curl -o /etc/hy2config/surge.yaml 'https://sub.crazyact.com/surge?config={hy2_v2ray_url}{url_rule}'")
                print("\033[91m \nclash,sing-box,surge configuration file has been saved to /etc/hy2config/!\n\n \033[m")
                os.system("systemctl enable --now hysteria-server.service")
                os.system("systemctl restart hysteria-server.service")

            except FileNotFoundError:
                print("\033[91mConfiguration file not found. Please install hysteria2 first\033[m")
        elif choice_1 == "3":
            print("\033[91mEditing using the nano editor, press Ctrl+X to save and exit\033[m")
            print(subprocess.run("nano /etc/hysteria/config.yaml",shell=True))   #Manually modify using the nano editor
            os.system("systemctl enable --now hysteria-server.service")
            os.system("systemctl restart hysteria-server.service")
            print("hy2 Service launched")
        elif choice_1 == "0":
            break
        else:
            print("\033[91mPlease re-enter\033[m")


def check_hysteria2_version():  # Check Hysteria2 version
    try:
        output = subprocess.check_output("/usr/local/bin/hysteria version | grep '^Version' | grep -o 'v[.0-9]*'",shell=True, stderr=subprocess.STDOUT)
        version = output.decode('utf-8').strip()

        if "v" in version:
            print(f"Current version of Hysteria2:{version}")
        else:
            print("Hysteria2 version not found")
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e.output.decode('utf-8')}")

#Main Program
agree_treaty()
while True:
    os.system("clear")
    print("\033[91mHELLO HYSTERIA2!\033[m  (Type hy2 to launch the shortcut)")  #In print("\033[91mText to be entered\033[0m") Output red text for ANSI escape codes.
    print("1. Install/Update hysteria2\n2. Uninstall hysteria2\n3. hysteria2 Config\n4. hysteria2 Service Management\n0. Exit")
    choice = input("Please enter your options:")
    if choice == "1":
        os.system("clear")
        hysteria2_install()
    elif choice == "2":
        os.system("clear")
        hysteria2_uninstall()
    elif choice == "3":
        os.system("clear")
        hysteria2_config()
    elif choice == "4":
        os.system("clear")
        check_hysteria2_version()
        server_manage()
    elif choice == "0":
        print("Exited")
        sys.exit()
    else:
        print("\033[91mInput error, please re-enter\033[m")
        time.sleep(1)

