import argparse
import socket
import concurrent.futures
import ipaddress
from datetime import datetime

# Top common ports (can be extended to top 100 from Nmap dataset)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3389, 8080, 8443, 3306, 1433, 1521, 5900
]

def scan_port(host, port, grab_banner=False):
    """Attempt to connect to a port and optionally grab banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                if grab_banner:
                    try:
                        banner = sock.recv(1024).decode().strip()
                        return f"[+] {host}:{port} OPEN - Banner: {banner}"
                    except:
                        return f"[+] {host}:{port} OPEN"
                else:
                    return f"[+] {host}:{port} OPEN"
    except Exception:
        pass
    return None

def run_scan(hosts, ports, grab_banner=False, threads=100):
    results = []
    print(f"\nStarting scan at {datetime.now()}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for host in hosts:
            for port in ports:
                futures.append(executor.submit(scan_port, host, port, grab_banner))
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
                print(res)
    print("\nScan complete.")
    return results

def parse_ports(port_arg):
    """Parse ports argument: range (1-1024), single, or list."""
    ports = []
    if "-" in port_arg:
        start, end = port_arg.split("-")
        ports = list(range(int(start), int(end) + 1))
    else:
        ports = [int(p) for p in port_arg.split(",")]
    return ports

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced TCP Port Scanner")
    parser.add_argument("target", help="Target host or CIDR subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", help="Ports to scan (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("--top", action="store_true", help="Scan top common ports")
    parser.add_argument("--banner", action="store_true", help="Grab service banners")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    args = parser.parse_args()

    # Parse hosts (single or subnet)
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except ValueError:
        hosts = [socket.gethostbyname(args.target)]

    # Parse ports
    if args.top:
        ports = TOP_PORTS
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = list(range(1, 1025))  # default range

    run_scan(hosts, ports, grab_banner=args.banner, threads=args.threads)
