from scapy.all import *
from scapy.layers.inet import TCP, IP # and others

def attack_to_perform(number):
    switch = {
        1: perform_sweep,
        2: 'two',
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
    packet_dst = input("Enter the destination IP: ")
    packet_data = input("Enter the packet data: ")
    '''
    packet = IP(dst=packet_dst) / ICMP() / packet_data

    intervals = [0.005, 0.010, 0.020, 0.050]
    for interval in intervals:
        print(f"{int(interval * 1000)} ms:")
        sr(packet, inter=interval)
    '''
    return 'sweep performed'

def main():
    # Print attack menu
    print_attack_menu()

    # Get input from the user
    number = int(input("Enter a number: "))

    # Select the attack type
    atk = attack_to_perform(number)

    # Print the result
    print()
    print(atk)


if __name__ == "__main__":

    # Initial execution
    redo = 'y'    

    # Redo loop
    while redo.lower() != 'n':
        main()
        redo = input("Do you want to perform another attack? (y/n): ")
