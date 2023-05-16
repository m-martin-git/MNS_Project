from scapy.all import *
from scapy.layers.inet import TCP, IP # and others

def attack_to_perform(number):
    switch = {
        1: perform_sweep,
        2: perform_portScan,
        3: 'three',
        4: 'four',
        5: 'five',
        6: 'six',
        7: 'seven',
        8: 'eight',
        9: 'nine',
        10: 'ten'
    }

    if number in switch:
        return switch[number]()
    else:
        return 'Number out of range'

def print_attack_menu():
    print("Select an attack:")
    print("(1) Sweep")
    print("(2) Denial of Service (DoS)")
    print("(3) Man-in-the-Middle (MitM)")
    print("(4) SQL Injection")
    print("(5) Cross-Site Scripting (XSS)")
    print("(6) Phishing")
    print("(7) Distributed Denial of Service (DDoS)")
    print("(8) Password Cracking")
    print("(9) Eavesdropping")
    print("(10) Malware Injection")
    print()

def perform_sweep():
    # Get input from the user
    packet_dst = input("Enter the destination IP range: ")
    #packet_data = input("Enter the packet data: ")
    live_hosts = []
    ip_range = [packet_dst + str(i) for i in range(1, 255)]

    for ip in ip_range:
        packet = IP(dst=ip) / ICMP()
        reply = sr1(packet, timeout=0.1, verbose=0)
        if reply is not None and ICMP in reply:
            live_hosts.append(ip)
    print (live_hosts)
    return 'sweep performed'



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
        print("\n")
        try:
            number = int(input("Enter a number: "))
            break  # Exit the loop if a valid number is entered
        except ValueError:
            print("Invalid input. Please enter a valid number.")
        
    # Select the attack type
    atk = attack_to_perform(number)

    # Print the result
    #print("\n")
    #print(atk)
    #print()


if __name__ == "__main__":
    # Initial execution
    redo = ''    

    # Redo loop
    while redo.lower() != 'n':
        main()
        redo = input("Do you want to perform another attack? (y/n): ")
        print("\n")
