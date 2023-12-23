import socket
import ipaddress

def scan_cctv_ports(ip, ports, spoofed_ip=None):
    results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if spoofed_ip:
            sock.bind((spoofed_ip, 0))

        result = sock.connect_ex((ip, port))
        if result == 0:
            results.append(f"Port {port} is open on {ip}")
        else:
            results.append(f"Port {port} is closed on {ip}")
        sock.close()
    return results

def scan_ip_range(ip_range, ports, spoofed_ip=None):
    results = []
    for ip in ipaddress.IPv4Network(ip_range, strict=False):
        results.extend(scan_cctv_ports(str(ip), ports, spoofed_ip))
    return results

def save_results_to_file(results, filename):
    with open(filename, 'w') as file:
        for result in results:
            file.write(result + '\n')

def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    spoofed_ip = input("Enter the spoofed IP address (optional): ")
    ports = [80, 6036, 7000, 5554, 8080, 5150, 5160, 4550, 5511, 5550, 6550, 8866, 56000, 10000]

    results = scan_ip_range(ip_range, ports, spoofed_ip)

    # Display results in console
    for result in results:
        print(result)

    # Save results to a text file
    filename = "cctv_scan_results.txt"
    save_results_to_file(results, filename)
    print(f"Results saved to {filename}")

if __name__ == "__main__":
    main()
