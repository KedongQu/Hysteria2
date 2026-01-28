# Hysteria2  One-click Installation Script
import glob
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
import urllibrequest
from pathlib import Path
from urllib import parse

import requests


def agree_treaty():       #This function checks whether the user agrees to these terms
    def hy_shortcut():   #Add hy2 shortcut
        hy2_shortcut = Path(r"/usr/local/bin/hy2")  # Create shortcut
        hy2_shortcutwrite_text("#!/bin/bash\nwget -O hy2py https://rawgithubusercontentcom/KedongQu/Hysteria2/refs/heads/main/hysteria2py && chmod +x hy2py && python3 hy2py\n")  # Write content
        hy2_shortcutchmod(0o755)
    file_agree = Path(r"/etc/hy2config/agreetxt")  # Extract filenames
    if file_agreeexists():       #exists()Check if the file exists; if it exists, return true and skip this step
        print("You've already agreed, thank you")
        hy_shortcut()
    else:
        while True:
            print("I agree that the use of this program must comply with the laws and regulations of the location and country of the deployment server and the user's country The program author is not responsible for any improper behavior by the user Furthermore, this program is for educational and communication purposes only and may not be used for any commercial purposes")
            choose_1 = input("Do you agree to and read (above) the terms and conditions for installing Hysteria 2 [y/n]:")
            if choose_1 == "y":
                check_file = subprocessrun("mkdir /etc/hy2config && touch /etc/hy2config/agreetxt && touch /etc/hy2config/hy2_url_schemetxt",shell = True)
                print(check_file)    #This file is created when the user agrees to the installation; this step is skipped during the next automatic check
                hy_shortcut()
                break
            elif choose_1 == "n":
                print("Please agree to these terms and conditions before installation")
                sysexit()
            else:
                print("\033[91mPlease enter the correct option！\033[m")

def hysteria2_install():    #Install hysteria2
    while True:
        choice_1 = input("Install/Update hysteria2 [y/n] :")
        if choice_1 == "y":
            print("1 Install the latest version by default\n2 Install the specified version")
            choice_2 = input("Please enter your options:")
            if choice_2 == "1":
                hy2_install = subprocessrun("bash <(curl -fsSL https://gethy2sh/)",shell = True,executable="/bin/bash")  # Install using the official hy2 script
                print(hy2_install)
                print("--------------")
                print("\033[91mhysteria2 Installation complete Please perform one-click configuration changes\033[m")
                print("--------------")
                hysteria2_config()
                break
            elif choice_2 == "2":
                version_1 = input("Please enter the version number you wish to install (just enter the version number directly, no need to add \"v\", eg, 260): ")
                hy2_install_2 = subprocessrun(f"bash <(curl -fsSL https://gethy2sh/) --version v{version_1}",shell=True,executable="/bin/bash")  # Install the specified version
                print(hy2_install_2)
                print("--------------")
                print(f"\033[91mhysteria2 Installation of version {version_1} is complete Please enter options to modify the configuration with one click！！！\033[m")
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

def hysteria2_uninstall():   #Uninstall Hysteria2
    while True:
        choice_1 = input("Do you want to uninstall Hysteria2 [y/n] :")
        if choice_1 == "y":
            hy2_uninstall_1 = subprocessrun("bash <(curl -fsSL https://gethy2sh/) --remove",shell = True,executable="/bin/bash")   #Uninstall using the official hy2 script
            print(hy2_uninstall_1)
            # Stop and disable the iptables recovery service
            subprocessrun(["systemctl", "stop", "hysteria-iptablesservice"], stderr=subprocessDEVNULL)
            subprocessrun(["systemctl", "disable", "hysteria-iptablesservice"], stderr=subprocessDEVNULL)
            # Clean up iptables rules
            subprocessrun(["/bin/bash", "/etc/hy2config/jump_port_backsh"], stderr=subprocessDEVNULL)
            # Delete all configuration files and services
            
            # Using glob to handle wildcard patterns
            wildcard_paths = globglob("/etc/systemd/system/multi-usertargetwants/hysteria-server@*service")
            for path in wildcard_paths:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
            
            # Delete other paths
            paths_to_remove = [
                "/etc/hysteria",
                "/etc/systemd/system/multi-usertargetwants/hysteria-serverservice",
                "/etc/systemd/system/hysteria-iptablesservice",
                "/etc/hy2config/iptables-rulesv4",
                "/etc/hy2config/iptables-rulesv6",
                "/etc/ssl/private/",
                "/etc/hy2config",
                "/usr/local/bin/hy2"
            ]
            for path_str in paths_to_remove:
                try:
                    path = Path(path_str)
                    if pathis_file():
                        pathunlink(missing_ok=True)
                    elif pathis_dir():
                        shutilrmtree(path, ignore_errors=True)
                except Exception:
                    pass
            
            subprocessrun(["systemctl", "daemon-reload"])
            print("Hysteria2 uninstallation complete")
            sysexit()
        elif choice_1 == "n":
            print("The uninstallation of hysteria2 has been cancelled")
            break
        else:
            print("\033[91mInput error, please re-enter\033[m")

def server_manage():   #Hysteria2 Service Management
    while True:
            print("1 Start the service (automatically set it to start automatically on system boot)\n2 Service discontinued\n3 Restart service\n4 Check service status\n5 Log query\n6 View detailed information about hy2 version\n0 Back")
            choice_2 = input("Please enter your options:")
            if choice_2 == "1":
                print(subprocessrun("systemctl enable --now hysteria-serverservice",shell=True))
            elif choice_2 == "2":
                print(subprocessrun("systemctl stop hysteria-serverservice",shell=True))
            elif choice_2 == "3":
                print(subprocessrun("systemctl restart hysteria-serverservice",shell=True))
            elif choice_2 == "4":
                print("\033[91mType 'q' to exit viewing\033[m")
                print(subprocessrun("systemctl status hysteria-serverservice",shell=True))
            elif choice_2 == "5":
                print(subprocessrun("journalctl --no-pager -e -u hysteria-serverservice",shell=True))
            elif choice_2 == "6":
                ossystem("/usr/local/bin/hysteria version")
            elif choice_2 == "0":
                break
            else:
                print("\033[91mInput error, please re-enter\033[m")

def create_iptables_persistence_service():
    """Create a systemd service to restore iptables rules at startup"""
    # Create a recovery script that includes error handling
    restore_script_content = """#!/bin/bash
# Hysteria2 iptables rules restoration script

set -e  # Exit when an error occurs

# Verify and restore IPv4 rules
if [ -f /etc/hy2config/iptables-rulesv4 ]; then
    if [ -s /etc/hy2config/iptables-rulesv4 ]; then
        if iptables-restore -t < /etc/hy2config/iptables-rulesv4 2>/dev/null; then
            iptables-restore < /etc/hy2config/iptables-rulesv4
            echo "IPv4 iptables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "IPv4 Invalid iptables rule file, skip restoration" | logger -t hysteria2-iptables
        fi
    fi
fi

# Verify and restore IPv6 rules
if [ -f /etc/hy2config/iptables-rulesv6 ]; then
    if [ -s /etc/hy2config/iptables-rulesv6 ]; then
        if ip6tables-restore -t < /etc/hy2config/iptables-rulesv6 2>/dev/null; then
            ip6tables-restore < /etc/hy2config/iptables-rulesv6
            echo "IPv6 ip6tables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "IPv6 Invalid ip6tables rule file, skip restoration" | logger -t hysteria2-iptables
        fi
    fi
fi

exit 0
"""
    restore_script_path = Path("/etc/hy2config/restore-iptablessh")
    
    # Create systemd service
    service_content = """[Unit]
Description=Restore Hysteria2 iptables rules
After=networktarget

[Service]
Type=oneshot
ExecStart=/etc/hy2config/restore-iptablessh
RemainAfterExit=true

[Install]
WantedBy=multi-usertarget
"""
    service_path = Path("/etc/systemd/system/hysteria-iptablesservice")
    try:
        # Write recovery script
        restore_script_pathwrite_text(restore_script_content)
        restore_script_pathchmod(0o755)
        
        # Write to service file
        service_pathwrite_text(service_content)
        
        # Reload systemd and enable services
        subprocessrun(["systemctl", "daemon-reload"], check=True)
        subprocessrun(["systemctl", "enable", "hysteria-iptablesservice"], check=True)
        print("iptables persistent service has been created")
    except Exception as e:
        print(f"\033[91mFailed to create iptables persistent service: {e}\033[m")

def save_iptables_rules():
    """Save the current iptables and ip6tables rules"""
    try:
        # Create configuration directory
        config_dir = Path("/etc/hy2config")
        config_dirmkdir(parents=True, exist_ok=True)
        
        # Save IPv4 rules
        with open("/etc/hy2config/iptables-rulesv4", "w") as f:
            subprocessrun(["iptables-save"], stdout=f, check=True, text=True)
        print("IPv4 iptables rules have been saved")
        
        # Save IPv6 rules
        with open("/etc/hy2config/iptables-rulesv6", "w") as f:
            subprocessrun(["ip6tables-save"], stdout=f, check=True, text=True)
        print("IPv6 ip6tables rules have been saved")
        
        return True
    except Exception as e:
        print(f"\033[91mFailed to save iptables rules: {e}\033[m")
        return False

hy2_domain = "You are handsome"   #These two variables are purely for praising you who are watching code
domain_name = "Super handsome"
insecure = "You're so handsome"
def hysteria2_config():     #Hysteria2 configuration
    global hy2_domain,domain_name, insecure
    hy2_config = Path(r"/etc/hysteria/configyaml")  # Configuration file path
    hy2_url_scheme = Path(r"/etc/hy2config/hy2_url_schemetxt")  # Configuration file path
    while True:
        choice_1 = input("1 hy2 configuration view\n2 hy2 configuration one-click modification\n3 Manually modify hy2 configuration\n4 Performance optimization (optional, installing the xanmod kernel is recommended)\n0 Back\nPlease enter your options:")
        if choice_1 == "1":
            while True:
                    try:
                        ossystem("clear")
                        print("Your official configuration file is:\n")
                        print(hy2_configread_text())
                        print(hy2_url_schemeread_text())
                        print("The clash, surge, and singbox templates are located in /etc/hy2config/, please check by yourself\n")
                        break
                    except FileNotFoundError:     #Errors will be captured if the configuration file cannot be found, the output "Configuration file not found" will be displayed
                        print("\033[91mConfiguration file not found\033[m")
                    break
        elif choice_1 == "2":
            try:
                while True:
                    try:
                        hy2_port = int(input("Please enter the port number:"))
                        if hy2_port <= 0 or hy2_port >= 65536:
                            print("The port number range is 1 to 65535 Please re-enter")
                        else:
                            break
                    except ValueError:     #The error message indicates a problem with the system It checks if the user input is a number Since the `int` has already been converted to a number, inputting a decimal point or other strings will trigger this error
                        print("The port number can only be a number and cannot contain a decimal point Please re-enter")
                hy2_username = input("Please enter your username:\n")
                hy2_username = urllibparsequote(hy2_username)
                hy2_passwd = input("Please enter your strong password:\n")
                hy2_url = input("Please enter the domain name you want to impersonate (please start with https://):\n")
                while True:
                    hy2_brutal = input("Should Brutal mode be enabled? (It is not recommended to enable it by default) [y/n]:")
                    if hy2_brutal == "y":
                        brutal_mode = "false"
                        break
                    elif hy2_brutal == "n":
                        brutal_mode = "true"
                        break
                    else:
                        print("\033[91mPlease re-enter if you have entered the wrong information\033[m")
                while True:
                    hy2_obfs = input("Enable obfuscation mode (default, not recommended, enabling it will disable the disguise capability))？[y/n]:")
                    if hy2_obfs == "y":
                        obfs_passwd = input("Please enter your obfuscation password:\n")
                        obfs_mode = f"obfs:\n  type: salamander\n  \n  salamander:\n    password: {obfs_passwd}"
                        obfs_passwd = urllibparsequote(obfs_passwd)
                        obfs_scheme = f"&obfs=salamander&obfs-password={obfs_passwd}"
                        break
                    elif hy2_obfs == "n":
                        obfs_mode = ""
                        obfs_scheme = ""
                        break
                    else:
                        print("\033[91mPlease re-enter if you have entered the wrong information\033[m")
                while True:
                    hy2_sniff = input("Enable protocol sniffing? (Sniff)[y/n]:")
                    if hy2_sniff == "y":
                        sniff_mode = "sniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: false\n  tcpPorts: 80,443,8000-9000\n  udpPorts: all"
                        break
                    elif hy2_sniff == "n":
                        sniff_mode = ""
                        break
                    else:
                        print("\033[91mPlease re-enter if you have entered the wrong information\033[m")
                while True:
                    jump_port_choice = input("Enable port hopping? (y/n):")
                    if jump_port_choice == "y":
                        print("Please select your network interface (eth0 by default, usually not the lo interface）")
                        # Display available network interfaces
                        result = subprocessrun(["ip", "-o", "link", "show"], capture_output=True, text=True)
                        if resultreturncode == 0:
                            for line in resultstdoutstrip()split('\n'):
                                # Extract Interface Name
                                if ':' in line:
                                    parts = linesplit(':', 2)
                                    if len(parts) >= 2:
                                        print(f"  - {parts[1]strip()}")
                        interface_name = input("Please enter your network interface name:")
                        try:
                            first_port = int(input("Please enter the starting port number:"))
                            last_port = int(input("Please enter the end port number:"))
                            if first_port <= 0 or first_port >= 65536:
                                print("The starting port number range is 1~65535 Please re-enter")
                            elif last_port <= 0 or last_port >= 65536:
                                print("The end port number range is 1~65535, please re-enter")
                            elif first_port > last_port:
                                print("The starting port number cannot be greater than the ending port number Please re-enter")
                            else:
                                # Initialize IPv6 variables
                                has_ipv6 = False
                                ipv6_interface = None
                                
                                while True:
                                    jump_port_ipv6 = input("Enable IPv6 port hopping? (y/n):")
                                    if jump_port_ipv6 == "y":
                                        print("Please select your v6 network interface:")
                                        # Display available network interfaces
                                        result = subprocessrun(["ip", "-o", "link", "show"], capture_output=True, text=True)
                                        if resultreturncode == 0:
                                            for line in resultstdoutstrip()split('\n'):
                                                if ':' in line:
                                                    parts = linesplit(':', 2)
                                                    if len(parts) >= 2:
                                                        print(f"  - {parts[1]strip()}")
                                        interface6_name = input("Please enter your v6 network interface name:")
                                        subprocessrun(["ip6tables", "-t", "nat", "-A", "PREROUTING", "-i", interface6_name,
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
                                        print("\033[91mPlease re-enter if you have entered the wrong information\033[m")
                                script_path = Path("/etc/hy2config/jump_port_backsh")  #Check if the recovery script exists
                                if script_pathexists():
                                    subprocessrun(["/bin/bash", str(script_path)], stderr=subprocessDEVNULL)
                                    script_pathunlink(missing_ok=True)
                                
                                # Apply iptables rules
                                subprocessrun(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface_name, 
                                              "-p", "udp", "--dport", f"{first_port}:{last_port}", 
                                              "-j", "REDIRECT", "--to-ports", str(hy2_port)])
                                
                                # Create a cleanup script
                                jump_port_back = Path("/etc/hy2config/jump_port_backsh")
                                cleanup_script = f"""#!/bin/sh
# Hysteria2 port hopping cleanup script
iptables -t nat -D PREROUTING -i {interface_name} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}
"""
                                if has_ipv6 and ipv6_interface:
                                    cleanup_script += f"ip6tables -t nat -D PREROUTING -i {ipv6_interface} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}\n"
                                
                                jump_port_backwrite_text(cleanup_script)
                                jump_port_backchmod(0o755)  # More secure permission settings
                                
                                # Storing iptables rules for persistence
                                print("Saving iptables rules for automatic recovery after reboot")
                                if save_iptables_rules():
                                    # Create a systemd service to restore rules at startup
                                    create_iptables_persistence_service()
                                    print("\033[92mThe port hopping rules have been configured and persisted, and will be automatically restored after a system reboot\033[m")
                                else:
                                    print("\033[91mWarning: The iptables rules have been applied but persistence has failed Reconfiguration may be required after a system reboot\033[m")
                                
                                jump_ports_hy2 = f"&mport={first_port}-{last_port}"
                                break
                        except ValueError:  # The error message indicates a problem with the system It checks if the user input is a number Since the `int` has already been converted to a number, inputting a decimal point or other strings will trigger this error
                            print("The port number can only be a number and cannot contain a decimal point Please re-enter")
                    elif jump_port_choice == "n":
                        jump_ports_hy2 = ""
                        break
                    else:
                        print("\033[91mPlease re-enter if you have entered the wrong information\033[m")
                while True:
                    print("1 Automatically apply for domain name certificates\n2 Use a self-signed certificate (no domain name required)\n3 Manually select certificate path")
                    choice_2 = input("Please enter your option:")
                    if choice_2 == "1":
                        hy2_domain = input("Please enter your own domain name:\n")
                        domain_name = hy2_domain
                        hy2_email = input("Please enter your email address:\n")
                        domain_name = ""
                        while True:
                            choice_acme = input("Do you want to configure ACME DNS? (Please do not select this option if you do not know what it is) [y/n]:")
                            if choice_acme == 'y':
                                while True:
                                    ossystem('clear')
                                    dns_name = input("dns name:\n1Cloudflare\n2Duck DNS\n3Gandinet\n4Godaddy\n5Namecom\n6Vultr\nPlease enter your options:")
                                    if dns_name == '1':
                                        dns_token = input("Please enter Cloudflare's Global api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: cloudflare\n    config:\n      cloudflare_api_token: {dns_token}"
                                        break
                                    elif dns_name == '2':
                                        dns_token = input("Please enter Duck DNS's api_token:")
                                        override_domain = input("Please enter Duck DNS's override_domain:")
                                        acme_dns = f"type: dns\n  dns:\n    name: duckdns\n    config:\n      duckdns_api_token: {dns_token}\n    duckdns_override_domain: {override_domain}"
                                        break
                                    elif dns_name == '3':
                                        dns_token = input("Please enter Gandinet's api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: gandi\n    config:\n      gandi_api_token: {dns_token}"
                                        break
                                    elif dns_name == '4':
                                        dns_token = input("Please enter Godaddy's api_token:")
                                        acme_dns = f"type: dns\n  dns:\n    name: godaddy\n    config:\n      godaddy_api_token: {dns_token}"
                                        break
                                    elif dns_name == '5':
                                        dns_token = input("Please enter Namecom's namedotcom_token:")
                                        dns_user = input("Please enter Namecom's namedotcom_user:")
                                        namedotcom_server = input("Please enter Namecom's namedotcom_server:")
                                        acme_dns = f"type: dns\n  dns:\n    name: {dns_name}\n    config:\n      namedotcom_token: {dns_token}\n      namedotcom_user: {dns_user}\n      namedotcom_server: {namedotcom_server}"
                                        break
                                    elif dns_name == '6':
                                        dns_token = input("Please enter Vultr's API Key:")
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
                        hy2_configwrite_text(f"listen: :{hy2_port} \n\nacme:\n  domains:\n    - {hy2_domain} \n  email: {hy2_email} \n  {acme_dns} \n\nauth:\n  type: password\n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url} \n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "2":    #Get IPv4 address
                        def validate_and_get_ipv4():
                            """Helper function to get and validate IPv4 address from user"""
                            while True:
                                ip_input = input("Unable to obtain an IP address automatically, please manually enter the server's IPv4 address:")strip()
                                try:
                                    # Verify that it is a valid IPv4 address
                                    ipaddressIPv4Address(ip_input)
                                    return ip_input
                                except ipaddressAddressValueError:
                                    print(f"\033[91mInvalid IPv4 address: {ip_input}，Please re-enter\033[m")
                        
                        def validate_and_get_ipv6():
                            """Helper function to get and validate IPv6 address from user"""
                            while True:
                                ip_input = input("Unable to obtain an IP address automatically, please manually enter the server's IPv6 address:")strip()
                                try:
                                    # Verify that it is a valid IPv6 address
                                    ipaddressIPv6Address(ip_input)
                                    return ip_input
                                except ipaddressAddressValueError:
                                    print(f"\033[91mInvalid IPv6 address: {ip_input}，Please re-enter\033[m")
                        
                        def get_ipv4_info():
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requestsget('http://ip-apicom/json/', headers=headers, timeout=3)
                                responseraise_for_status()
                                ip_data = responsejson()
                                isp = ip_dataget('isp', '')

                                if 'cloudflare' in isplower():
                                    print("Warp detected Please enter the correct server IPv4 address")
                                    hy2_domain = validate_and_get_ipv4()
                                else:
                                    hy2_domain = ip_dataget('query', '')

                                print(f"IPV4 WAN IP: {hy2_domain}")

                            except requestsRequestException as e:
                                print(f"Request failed: {e}")
                                print("Try using an alternative method to obtain the IP address")
                                # Use an alternative method to obtain the IP address
                                try:
                                    result = subprocessrun(['curl', '-4', '-s', 'ifconfigme'], capture_output=True, text=True, timeout=5)
                                    if resultreturncode == 0 and resultstdoutstrip():
                                        ip = resultstdoutstrip()
                                        # Verify IPv4 format
                                        try:
                                            ipaddressIPv4Address(ip)
                                            hy2_domain = ip
                                            print(f"IPV4 WAN IP: {hy2_domain}")
                                        except ipaddressAddressValueError:
                                            # Invalid format, prompt user to enter manually
                                            hy2_domain = validate_and_get_ipv4()
                                    else:
                                        # If it still fails, prompt the user to enter the information manually
                                        hy2_domain = validate_and_get_ipv4()
                                except (subprocessTimeoutExpired, subprocessCalledProcessError, OSError, FileNotFoundError):
                                    # If the alternative method also fails, prompt the user to enter the information manually
                                    hy2_domain = validate_and_get_ipv4()

                        def get_ipv6_info():    #Get IPv6 address
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requestsget('https://apiipsb/geoip', headers=headers, timeout=3)
                                responseraise_for_status()
                                ip_data = responsejson()
                                isp = ip_dataget('isp', '')

                                if 'cloudflare' in isplower():
                                    print("Warp detected Please enter the correct server IPv6 address")
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"
                                else:
                                    hy2_domain = f"[{ip_dataget('ip', '')}]"

                                print(f"IPV6 WAN IP: {hy2_domain}")

                            except requestsRequestException as e:
                                print(f"Request failed: {e}")
                                print("Try using an alternative method to obtain the IP address")
                                # Use an alternative method to obtain an IPv6 address
                                try:
                                    result = subprocessrun(['curl', '-6', '-s', 'ifconfigme'], capture_output=True, text=True, timeout=5)
                                    if resultreturncode == 0 and resultstdoutstrip():
                                        ip = resultstdoutstrip()
                                        # Verify IPv6 format
                                        try:
                                            ipaddressIPv6Address(ip)
                                            hy2_domain = f"[{ip}]"
                                            print(f"IPV6 WAN IP: {hy2_domain}")
                                        except ipaddressAddressValueError:
                                            # Invalid format, prompt user to enter manually
                                            ipv6_input = validate_and_get_ipv6()
                                            hy2_domain = f"[{ipv6_input}]"
                                    else:
                                        # If it still fails, prompt the user to enter the information manually
                                        ipv6_input = validate_and_get_ipv6()
                                        hy2_domain = f"[{ipv6_input}]"
                                except (subprocessTimeoutExpired, subprocessCalledProcessError, OSError, FileNotFoundError):
                                    # If the alternative method also fails, prompt the user to enter the information manually
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"

                        def generate_certificate():      #Generate self-signed certificate
                            global domain_name
                            # Prompt the user to enter a domain name
                            user_domain = input("Please enter the domain name you want to use for the self-signed certificate (default is bingcom）: ")
                            domain_name = user_domainstrip() if user_domain else "bingcom"

                            # Verify domain name format
                            if rematch(r'^[a-zA-Z0-9-]+$', domain_name):
                                # Define target directory
                                target_dir = "/etc/ssl/private"

                                # Check and create the target directory
                                if not ospathexists(target_dir):
                                    print(f"Target directory {target_dir} Does not exist, being created")
                                    osmakedirs(target_dir)
                                    if not ospathexists(target_dir):
                                        print(f"Unable to create directory {target_dir}，Please check permissions ")
                                        exit(1)

                                # Generate EC parameter file
                                ec_param_file = f"{target_dir}/ec_parampem"
                                subprocessrun(["openssl", "ecparam", "-name", "prime256v1", "-out", ec_param_file],
                                               check=True)

                                # Generate certificate and private key
                                cmd = [
                                    "openssl", "req", "-x509", "-nodes", "-newkey", f"ec:{ec_param_file}",
                                    "-keyout", f"{target_dir}/{domain_name}key",
                                    "-out", f"{target_dir}/{domain_name}crt",
                                    "-subj", f"/CN={domain_name}", "-days", "36500"
                                ]
                                subprocessrun(cmd, check=True)

                                # Set file permissions
                                ossystem(f"chmod 666 {target_dir}/{domain_name}key && chmod 666 {target_dir}/{domain_name}crt && chmod 777 /etc/ssl/private/")

                                print("Self-signed certificate and private key have been generated！")
                                print(f"The certificate file has been saved to {target_dir}/{domain_name}crt")
                                print(f"The private key file has been saved to {target_dir}/{domain_name}key")
                            else:
                                print("Invalid domain name format Please enter a valid domain name！")
                                generate_certificate()

                        generate_certificate()
                        while True:
                            ip_mode = input("1 IPv4 mode\n2 IPv6 mode\nPlease enter your options:")
                            if ip_mode == '1':
                                get_ipv4_info()
                                break
                            elif ip_mode == '2':
                                get_ipv6_info()
                                break
                            else:
                                print("\033[91mInput error, please re-enter！\033[m")
                        insecure = "&insecure=1"
                        hy2_configwrite_text(f"listen: :{hy2_port} \n\ntls: \n  cert: /etc/ssl/private/{domain_name}crt \n  key: /etc/ssl/private/{domain_name}key \n\nauth: \n  type: password \n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy \n  proxy: \n    url: {hy2_url} \n    rewriteHost: true \n\nignoreClientBandwidth: {brutal_mode} \n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "3":
                        hy2_cert = input("Please enter your certificate path:\n")
                        hy2_key = input("Please enter your key path:\n")
                        hy2_domain = input("Please enter your own domain name:\n")
                        domain_name = hy2_domain
                        domain_name = ""
                        insecure = "&insecure=0"
                        hy2_configwrite_text(f"listen: :{hy2_port}\n\ntls:\n  cert: {hy2_cert}\n  key: {hy2_key}\n\nauth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")

                ossystem("clear")
                hy2_passwd = urllibparsequote(hy2_passwd)
                hy2_v2ray = f"hysteria2://{hy2_passwd}@{hy2_domain}:{hy2_port}?sni={domain_name}{obfs_scheme}{insecure}{jump_ports_hy2}#{hy2_username}"
                print("Your v2ray QR Code:\n")
                timesleep(1)
                ossystem(f'echo "{hy2_v2ray}" | qrencode -s 1 -m 1 -t ANSI256 -o -')
                print(f"\n\n\033[91mYour hy2 link is: {hy2_v2ray}\nPlease use v2ray/nekobox/v2rayNG/nekoray software import\033[m\n\n")
                hy2_url_schemewrite_text(f"Your v2ray hy2 configuration link is:{hy2_v2ray}\n")
                print("Downloading clash,sing-box,surge configuration file to/etc/hy2config/clashyaml")
                hy2_v2ray_url = urllibparsequote(hy2_v2ray)
                url_rule = "&ua=&selectedRules=%22balanced%22&customRules=%5B%5D"
                ossystem(f"curl -o /etc/hy2config/clashyaml 'https://subcrazyactcom/clash?config={hy2_v2ray_url}{url_rule}'")
                ossystem(f"curl -o /etc/hy2config/sing-boxyaml 'https://subcrazyactcom/singbox?config={hy2_v2ray_url}{url_rule}'")
                ossystem(f"curl -o /etc/hy2config/surgeyaml 'https://subcrazyactcom/surge?config={hy2_v2ray_url}{url_rule}'")
                print("\033[91m \nclash,sing-box,surge configuration file has been saved to /etc/hy2config/ directory ！！\n\n \033[m")
                ossystem("systemctl enable --now hysteria-serverservice")
                ossystem("systemctl restart hysteria-serverservice")

            except FileNotFoundError:
                print("\033[91mConfiguration file not found Please install hysteria2 first\033[m")
        elif choice_1 == "3":
            print("\033[91mManually editing using the nano editor After you're finished typing, press Ctrl+X to save and exit\033[m")
            print(subprocessrun("nano /etc/hysteria/configyaml",shell=True))   #Manually modify using the nano editor
            ossystem("systemctl enable --now hysteria-serverservice")
            ossystem("systemctl restart hysteria-serverservice")
            print("hy2 service has been launched")
        elif choice_1 == "4":
            ossystem("wget -O tcpxsh 'https://githubcom/ylx2016/Linux-NetSpeed/raw/master/tcpxsh' && chmod +x tcpxsh && /tcpxsh")
        elif choice_1 == "0":
            break
        else:
            print("\033[91mPlease re-enter\033[m")


def check_hysteria2_version():  # Check Hysteria 2 version
    try:
        output = subprocesscheck_output("/usr/local/bin/hysteria version | grep '^Version' | grep -o 'v[0-9]*'",shell=True, stderr=subprocessSTDOUT)
        version = outputdecode('utf-8')strip()

        if "v" in version:
            print(f"The current version of Hysteria2 is:{version}")
        else:
            print("Hysteria2 version not found")
    except subprocessCalledProcessError as e:
        print(f"Command execution failed: {eoutputdecode('utf-8')}")

#Main program
agree_treaty()
while True:
    ossystem("clear")
    print("\033[91mHELLO HYSTERIA2 !\033[m  (Type hy2 shortcut)")  # The print("\033[91mThe text you need to enter\033[0m") is an ANSI escape code that outputs red text
    print("1 Installation/Update hysteria2\n2 Uninstall hysteria2\n3 hysteria2 Config\n4 hysteria2 Service Management\n0 Quit")
    choice = input("Please enter your options:")
    if choice == "1":
        ossystem("clear")
        hysteria2_install()
    elif choice == "2":
        ossystem("clear")
        hysteria2_uninstall()
    elif choice == "3":
        ossystem("clear")
        hysteria2_config()
    elif choice == "4":
        ossystem("clear")
        check_hysteria2_version()
        server_manage()
    elif choice == "0":
        print("Exited")
        sysexit()
    else:
        print("\033[91mInput error, please re-enter\033[m")
        timesleep(1)
        
