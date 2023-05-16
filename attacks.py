from scapy.all import *
from scapy.layers.inet import TCP, IP  # and others


def attack_to_perform(number):
    switch = {
        1: perform_reconnaissance,          # first recon attack
        2: perform_reconnaissance,          # second recon attack
        3: perform_dos,                     # first dos attack
        4: perform_dos,                     # second dos attack
        5: perform_dos,                     # third dos attack
        6: perform_ftp_attack,              # ftp attack
        7: perform_sweep,                   # ip address sweep
        8: perform_port_scan,               # port scan
        9: perform_ip_spoofing,             # ip spoofing
        10: perform_os_discovery,           # os discovery
        11: perform_syn_flood_attack,       # syn flood attack
        12: perform_icmp_flood_attack,      # icmp flood attack
        13: perform_udp_flood_attack,       # udp flood attack
        14: perform_drop_communication,     # drop communication
        15: perform_arp_poisoning,          # arp poisoning
        16: perform_special_attack          # special attack
    }

    if number in switch:
        return switch[number]()
    else:
        return "Number out of range"


def print_attack_menu():
    print("Select an attack:")
    print("Standard Attacks: -----------------------------------")
    print("(1) Reconnaissance Attack on network 192...")
    print("(2) Reconnaissance Attack on network 192...")
    print("(3) Denial of Service Attack on network 192...")
    print("(4) Denial of Service Attack on network 192...")
    print("(5) Denial of Service Attack on network 192...")
    print("(6) FTP Attack on Metasploitable 2")
    print("Custom Attacks: -------------------------------------")
    print("(7) IP Address Sweep")
    print("(8) Port Scan")
    print("(9) IP Spoofing")
    print("(10) Discover OS of Target")
    print("(11) SYN Flood Attack")
    print("(12) ICMP Flood Attack")
    print("(13) UDP Flood Attack")
    print("(14) Drop Communication")
    print("(15) ARP Poisoning")
    print("(16) Special Attack")
    print()


# write a function for each attack in the print_attack_menu
# each function should return a string describing the attack
# the function should take any required input from the user
# and should call any other functions that are required to
# perform the attack


# code to perform reconnaissance attack
def perform_reconnaissance(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "Reconnaissance performed on " + ip_addr


# code to perform dos attack
def perform_dos(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to Dos: ")

    return "Dos performed on " + ip_addr


# code to perform ftp attack
def perform_ftp_attack():
    return "ftp attack performed"


# code to perform ip address sweep
def perform_sweep(packet_dst):
    if not packet_dst:
        # Get input from the user
        packet_dst = input("Enter the destination IP: ")

    """
    packet = IP(dst=packet_dst) / ICMP() / packet_data

    intervals = [0.005, 0.010, 0.020, 0.050]
    for interval in intervals:
        print(f"{int(interval * 1000)} ms:")
        sr(packet, inter=interval)
    """
    return "Sweep towards " + packet_dst + " performed"


# code to perform port scan
def perform_port_scan(ip_addr, port_range):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    if not port_range:
        # Get input from the user
        port_range = input("Enter the port range to scan (e.g. 1-1000): ")
    """    
    #split the port range into two numbers
    port_range = port_range.split('-')
    #convert the port numbers to integers
    port_start = int(port_range[0])
    port_end = int(port_range[1])
    #create a list of ports to scan
    ports = range(port_start, port_end+1)
    #create a list of open ports
    open_ports = []
    #scan the ports
    for port in ports:
        #create a TCP packet
        tcp_packet = IP(dst=ip_addr)/TCP(dport=port, flags='S')
        #send the packet and wait for a response
        tcp_response = sr1(tcp_packet, timeout=1, verbose=0)
        #if a response was received
        if tcp_response:
            #if the response is a SYN-ACK
            if tcp_response[TCP].flags == 'SA':
                #add the port to the list of open ports
                open_ports.append(port)
    #print the open ports
    print("Open ports:")
    for port in open_ports:
        print(port)
    """
    return "Port scan performed on " + ip_addr + " from " + port_range


# code to perform ip spoofing
def perform_ip_spoofing(src_ip, dst_ip, packet_data):
    if not src_ip:
        # Get input from the user
        src_ip = input("Enter the source IP address: ")

    if not dst_ip:
        # Get input from the user
        dst_ip = input("Enter the destination IP address: ")

    if not packet_data:
        # Get input from the user
        packet_data = input("Enter the packet data: ")

    return (
        "IP spoofing performed from "
        + src_ip
        + " to "
        + dst_ip
        + " with data "
        + packet_data
    )


# code to perform os discovery
def perform_os_discovery(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "OS discovery performed on " + ip_addr


# code to perform syn flood attack
def perform_syn_flood_attack(ip_addr, port_range):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    if not port_range:
        # Get input from the user
        port_range = input("Enter the port range to scan (e.g. 1-1000): ")

    return "SYN flood attack performed on " + ip_addr + " from " + port_range


# code to perform icmp flood attack
def perform_icmp_flood_attack(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "ICMP flood attack performed on " + ip_addr


# code to perform udp flood attack
def perform_udp_flood_attack(ip_addr, port_range):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    if not port_range:
        # Get input from the user
        port_range = input("Enter the port range to scan (e.g. 1-1000): ")

    return "UDP flood attack performed on " + ip_addr + " from " + port_range


# code to perform drop communication
def perform_drop_communication(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "Drop communication performed on " + ip_addr


# code to perform ARP poisoning
def perform_arp_poisoning(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "ARP poisoning performed on " + ip_addr


# code to perform Special attack
def perform_special_attack(ip_addr):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "Special attack performed on " + ip_addr




def perform_portScan():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    target = input("Enter the destination IP: ")
    startport = input("Enter starting port: ")
    endport = input("Enter ending port: ")

    target = str(target)
    startport = int(startport)
    endport = int(endport)

    print("Scanning " + target + " for open TCP ports in range (" + str(startport) + " - " + str(endport) + ").")

    if startport == endport:
        endport += 1
    try:
        for port in range(startport, endport):
            packet = IP(dst=target) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=0.5, verbose=0)
            if response.getlayer(TCP).flags == 0x12: # SYN-ACK.
                print("Port " + str(port) + " is open!")
            sr(IP(dst=target) / TCP(dport=response.sport, flags="R"), timeout=0.5, verbose=0)
    except AttributeError:
        pass
    return 'port scanning performed'

def main():
    # Print attack menu
    print_attack_menu()

    # Get input from the user
    while True:
        try:
            number = int(input("Enter a number: "))
            break  # Exit the loop if a valid number is entered
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    # Select the attack type
    atk = attack_to_perform(number)

    # Print the result
    print()
    print(atk)
    print()


if __name__ == "__main__":
    # Initial execution
    redo = ""

    # Redo loop
    while redo.lower() != "n":
        main()
        redo = input("Do you want to perform another attack? (y/n): ")
        print("\n")
