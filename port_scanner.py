import argparse
import socket
import sys

def scan_port(target, port, protocol, tcp_socket, udp_socket):
   
    if protocol == 'TCP':
        try:
            result = tcp_socket.connect_ex((target, port))
            if result == 0:
                print(f'Port/TCP {port} open')
            else:
                print(f'Port/TCP {port} closed')
        except Exception as e:
            print(f'Error scanning Port/TCP {port}: {e}')
    elif protocol == 'UDP':
        try:
            # Send an empty UDP packet
            udp_socket.sendto(b'', (target, port))
            # Try to receive a response (this may timeout)
            udp_socket.recvfrom(1024)
            print(f'Port/UDP {port} open or filtered')
        except socket.timeout:
            print(f'Port/UDP {port} closed or filtered (timeout)')
        except Exception as e:
            print(f'Port/UDP {port} closed or filtered ({e})')

def scan_all_ports(target, protocols):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        
        tcp_socket.settimeout(1)
        udp_socket.settimeout(1)
        
        for port in range(1, 65536):
            for protocol in protocols:
                scan_port(target, port, protocol, tcp_socket, udp_socket)

def scan_well_known_ports(target, protocols):
   
    scan_port_range(target, protocols, 1, 1023)

def scan_registered_ports(target, protocols):
   
    scan_port_range(target, protocols, 1024, 49151)

def scan_private_ports(target, protocols):
    
    scan_port_range(target, protocols, 49152, 65535)

def scan_port_range(target, protocols, start, end):
  
    if start < 1 or end > 65535 or start > end:
        print("Invalid port range. Ports must be between 1 and 65535, and start <= end.")
        sys.exit(1)
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        
        tcp_socket.settimeout(1)
        udp_socket.settimeout(1)
        
        for port in range(start, end + 1):
            for protocol in protocols:
                scan_port(target, port, protocol, tcp_socket, udp_socket)

def scan_selected_ports(target, protocols, ports):
   
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
        
        tcp_socket.settimeout(1)
        udp_socket.settimeout(1)
        
        for port in ports:
            if port < 1 or port > 65535:
                print(f"Invalid port: {port}. Ports must be between 1 and 65535.")
                continue
            for protocol in protocols:
                scan_port(target, port, protocol, tcp_socket, udp_socket)

def main():
    
    parser = argparse.ArgumentParser(description="Simple Port Scanner")

    # Target URL or IP address
    parser.add_argument('target', type=str, help="The target URL or IP address to scan.")

    # Protocol options
    parser.add_argument('--tcp', action='store_true', help="Scan only TCP ports.")
    parser.add_argument('--udp', action='store_true', help="Scan only UDP ports.")

    # Port scanning options (mutually exclusive)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--all', action='store_true', help="Scan all 65,535 ports. Example: python3 port_scanner.py site.com --all --tcp --udp.")
    group.add_argument('-r', '--range', nargs=2, type=int, metavar=('START', 'END'), help="Specify start and end port numbers to scan. Example: python3 port_scanner.py site.com -r 20 80 --tcp --udp.")
    group.add_argument('-s', '--specific', nargs='+', type=int, help="Specify individual port numbers to scan. Example: python3 port_scanner.py site.com -s 20 80 --tcp --udp.")
    group.add_argument('-w', '--wellKnow', action='store_true', help="Scan well-known ports (1-1023). Example: python3 port_scanner.py site.com -w --tcp --udp.")
    group.add_argument('-p', '--private', action='store_true', help="Scan private ports (49152-65535). Example: python3 port_scanner.py site.com -p --tcp --udp.")
    group.add_argument('-re', '--registered', action='store_true', help="Scan registered ports (1024-49151). Example: python3 port_scanner.py site.com -re --tcp --udp.")

    args = parser.parse_args()

    # Determine which protocols to scan
    protocols = []
    if args.tcp:
        protocols.append('TCP')
    if args.udp:
        protocols.append('UDP')

    # Choose the scanning method based on the arguments
    if args.all:
        print(f"Scanning all ports on {args.target} for protocols: {', '.join(protocols)}")
        scan_all_ports(args.target, protocols)
    elif args.range:
        start, end = args.range
        print(f"Scanning ports {start}-{end} on {args.target} for protocols: {', '.join(protocols)}")
        scan_port_range(args.target, protocols, start, end)
    elif args.specific:
        print(f"Scanning specific ports {args.specific} on {args.target} for protocols: {', '.join(protocols)}")
        scan_selected_ports(args.target, protocols, args.specific)
    elif args.wellKnow:
        print(f"Scanning well-known ports (1-1023) on {args.target} for protocols: {', '.join(protocols)}")
        scan_well_known_ports(args.target, protocols)
    elif args.private:
        print(f"Scanning private ports (49152-65535) on {args.target} for protocols: {', '.join(protocols)}")
        scan_private_ports(args.target, protocols)
    elif args.registered:
        print(f"Scanning registered ports (1024-49151) on {args.target} for protocols: {', '.join(protocols)}")
        scan_registered_ports(args.target, protocols)
    else:
        print("No scanning option selected. Use --help to see available options.")

if __name__ == "__main__":
    main()

