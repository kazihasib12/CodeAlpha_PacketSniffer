
from scapy.all import *
import sys
import os
import argparse

def print_banner():
    banner = """\033[96m
    ██████╗ ███████╗████████╗ █████╗ ██████╗ ██████╗ ██╗   ██╗████████╗███████╗
    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
    ██████╔╝█████╗     ██║   ███████║██████╔╝██████╔╝ ╚████╔╝    ██║   █████╗\033[0m \033[95m
    ██╔══██╗██╔══╝     ██║   ██╔══██║██╔══██╗██╔══██╗  ╚██╔╝     ██║   ██╔══╝
    ██████╔╝███████╗   ██║   ██║  ██║██████╔╝██║  ██║   ██║      ██║   ███████╗
    ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝
    \033[0m"""
    print(banner)
    print("\033[96m         Network Packet Sniffer Tool By--> Md Hachib Kazi\033[0m")
    print("-"*70)


def packetCapture(packet, output_file):
    """
    This function is called for each captured packet.
    It extracts relevant information, prints it to the console,
    and writes it to the specified output file.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Construct the output string
        output_string = f"IP Packet: {ip_src} -> {ip_dst}"

        if proto == 6: # TCP Protocol
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            output_string += f" | Protocol: TCP | Source Port: {tcp_sport} | Dest Port: {tcp_dport}"

        elif proto == 17: # UDP Protocol
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            output_string += f" | Protocol: UDP | Source Port: {udp_sport} | Dest Port: {udp_dport}"

        elif proto == 1: # ICMP Protocol
            output_string += f" | Protocol: ICMP"

        else:  #Others Protocol
            output_string += f" | Protocol: Other ({proto})"

        # Print to console and write to file
        print(output_string)
        output_file.write(output_string + "\n")
        output_file.flush() # Ensure data is written to the file immediately


def main():
    print_banner()

    # Setup argument parser
    parser = argparse.ArgumentParser(
        description="A simple network packet sniffer using Scapy. Saves captured data to a file.",
        epilog="Example: sudo python sniffer.py my_capture.log"
    )
    parser.add_argument("filename", help="The file to save the captured packet data to.")
    args = parser.parse_args()
    filename = args.filename
    
    # Check for root privileges before anything else
    if os.geteuid() != 0:
        print("This script requires root/administrator privileges to run.")
        sys.exit(1)

    print("Starting Packet Sniffer...")
    print(f"Saving output to '{filename}'. Press Ctrl+C to stop.")
    print("="*70)


    try:
        # The 'with' statement ensures the file is properly closed even if an error occurs.
        with open(filename, 'w') as f:
            # Start sniffing. A lambda function is used to pass the file object 
            # to our callback function for each packet.
            sniff(prn=lambda packet: packetCapture(packet, f), store=0)

    except PermissionError:
        print(f"\nERROR: Permission denied. Could not write to '{filename}'.")
        print("Please check file/directory permissions or try a different path.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    except KeyboardInterrupt:
        print(f"\n\nPacket Sniffer stopped. Capture saved to '{filename}'.")
        sys.exit(0)

if __name__ == "__main__":
    main()