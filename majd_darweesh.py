#!/usr/bin/env python3
from scapy.all import Ether, ARP, srp, IP, TCP, sr1  # Added sr1 import

def scan_network(network):
    """Function to scan devices on the network."""
    # Create ARP request to find devices in the network
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Send request and capture the response
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Display the results
    print(f"Devices found on {network}:")
    for element in answered_list:
        print(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")

def scan_ports(ip):
    """Function to scan open ports on a specific IP."""
    print(f"Scanning ports on {ip}...")
    open_ports = []
    for port in range(20, 1025):
        syn = TCP(dport=port, flags="S")
        response = sr1(IP(dst=ip) / syn, timeout=1, verbose=False)  # sr1 is now correctly imported
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 18:  # SYN-ACK response
            open_ports.append(port)

    if open_ports:
        print(f"Open ports on {ip}: {open_ports}")
    else:
        print(f"No open ports found on {ip}.")

def display_help():
    """Function to display help instructions."""
    print("""
    Darweesh Scanning Tool Help:

    1. Scan Ports on a specific IP address: This option will scan the ports on the specified IP address.
    2. Scan Devices on a Network: This option will scan the devices available on the specified network.
    3. Perform a High-speed Ping Sweep: This option will perform a quick sweep of reachable devices in the network.
    4. Display Help and Instructions: Shows this help menu.
    """)

def main():
    print("""
    Welcome to Majd's Ultimate Port and Network Scanner!

     _____       ____       __         ________   _________  ___   ___ 
    /\  __-.     /\  \     /\ \       |  ______| |  ______| |\ \ / /|
   |  |  __/    _| \  \   /  \ \      | |___    _____ | |___    \ V / |
   |  | |      / __  \ \ /    \ \     |  ___|  /     \|  ___|     \ /  |
   |  |  __-. | |  |  | |/  /\  \    | |___   |  /\  | |___      |   |  |
   |  |  __/  | |__|  |  /  /  \  \   |_____|  | /  \ |_____|     |   |  |
    \_____|    \______/  |__/    \__\  |______|  |/    \|______|     |   |
                   _________     ________    ________    ______________ 
               __ |   __   __|__ | Darweesh |  |   Scan  |  |  ____   __  |
              |__|__|    ____/    |__________|  |_________|  |_________|   |
                               Scanning Tool for Networks and Ports
   _____    ___     _______    ___      _____        ________
   Majd Darweesh's Ultimate Scanning Tool for the Strongest Networks
    """)

    print("\nChoose your action by entering the number next to the option:")
    print("1. Scan Ports on a specific IP address")
    print("2. Scan Devices on a network")
    print("3. Perform a High-speed Ping Sweep on a network")
    print("4. Display Help and Instructions")
    
    try:
        choice = int(input("Enter your choice (1-4): "))
        if choice == 1:
            ip = input("Enter the IP address to scan: ")
            scan_ports(ip)
        elif choice == 2:
            network = input("Enter the network (e.g., 192.168.1.0/24): ")
            scan_network(network)
        elif choice == 3:
            print("High-speed Ping Sweep functionality not implemented yet.")
        elif choice == 4:
            display_help()
        else:
            print("Invalid choice. Please select a number between 1 and 4.")
    except ValueError:
        print("Invalid input. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()

