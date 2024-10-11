# port_scanner

A simple and versatile port scanner written in Python. This tool allows you to scan TCP and UDP ports on a target host, offering various scanning options such as scanning all ports, specific ranges, well-known ports, registered ports, private ports, or individual ports of your choice.

Features

    TCP and UDP Scanning: Supports both TCP and UDP protocols.
    Flexible Port Selection: Scan all ports, specific ranges, well-known ports, registered ports, private ports, or individual ports.
    Timeout Handling: Implements timeout to handle unresponsive ports.
    Command-Line Interface: Easy-to-use CLI with comprehensive options.
    Error Handling: Gracefully handles exceptions and provides informative messages.

Installation

    Clone the Repository


git clone https://github.com/Erasmo-Dev/port_scanner.git
cd port_scanner

Ensure Python is Installed

This script requires Python 3.6 or higher. You can check your Python version with:


python3 --version

(Optional) Create a Virtual Environment


    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

    Install Dependencies

    This script uses only standard Python libraries, so no additional installations are necessary.

Usage

Run the port_scanner.py script with the desired options.


python3 port_scanner.py TARGET [OPTIONS]

Arguments

    target (required): The target URL or IP address to scan.

Protocol Options

    --tcp: Scan only TCP ports.
    --udp: Scan only UDP ports.

Port Scanning Options (Mutually Exclusive)

    -a, --all: Scan all 65,535 ports.
    -r START END, --range START END: Scan ports in the specified range.
    -s PORT [PORT ...], --specific PORT [PORT ...]: Scan specific ports.
    -w, --wellKnow: Scan well-known ports (1-1023).
    -re, --registered: Scan registered ports (1024-49151).
    -p, --private: Scan private ports (49152-65535).

Help

For a full list of options, use the help flag:

python3 port_scanner.py --help

Examples
Scan All Ports with TCP and UDP

python3 port_scanner.py example.com --all --tcp --udp

Scan a Range of Ports with TCP Only

python3 port_scanner.py 192.168.1.1 -r 20 80 --tcp

Scan Specific Ports with UDP Only

python3 port_scanner.py example.com -s 22 80 443 --udp

Scan Well-Known Ports with Both Protocols

python3 port_scanner.py example.com -w --tcp --udp

Scan Private Ports with TCP

python3 port_scanner.py 192.168.1.1 -p --tcp

Scan Registered Ports with UDP

python3 port_scanner.py example.com -re --udp

Protocols

    TCP (Transmission Control Protocol): Reliable, connection-oriented protocol. Commonly used for web traffic, email, and file transfers.
    UDP (User Datagram Protocol): Unreliable, connectionless protocol. Often used for streaming, gaming, and DNS queries.

Port Scanning Options
All Ports (-a, --all)

Scans all 65,535 ports on the target.
Port Range (-r, --range)

Specify a start and end port to scan within that range.

Example:

python3 port_scanner.py example.com -r 1000 2000 --tcp

Specific Ports (-s, --specific)

Scan individual ports specified by their numbers.

Example:

python3 port_scanner.py example.com -s 22 80 443 --udp

Well-Known Ports (-w, --wellKnow)

Scans ports from 1 to 1023, which are typically reserved for well-known services.
Registered Ports (-re, --registered)

Scans ports from 1024 to 49151, assigned for specific services by IANA.
Private Ports (-p, --private)

Scans ports from 49152 to 65535, typically used for private or temporary purposes.


