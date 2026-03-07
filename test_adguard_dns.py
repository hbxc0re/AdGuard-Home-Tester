import socket
import time
import threading
import argparse
import csv
import struct
import random
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple

# DNS constants
DNS_PORT = 53
DNS_QUERY_TYPE_A = 1
DNS_QUERY_TYPE_AAAA = 28
DNS_QUERY_TYPE_MX = 15
DNS_QUERY_TYPE_CNAME = 5

# Record types to test
QUERY_TYPES = [DNS_QUERY_TYPE_A, DNS_QUERY_TYPE_AAAA]

# AdGuard Home default DNS server (you can change this)
ADGUARD_DNS = "192.168.0.24"  # or "your-adguard-home-ip"
ADGUARD_PORT = 53

# Configurable
MAX_CONCURRENT = 100
TIMEOUT = 5.0
DOMAINS_FILE = "domains.txt"
OUTPUT_CSV = "results.csv"

# Global counters
success_count = 0
error_count = 0
total_queries = 0
latency_sum = 0.0
counter_lock = threading.Lock()

def load_domains(file_path: str) -> List[str]:
    """Loads domains from a file, one domain per line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found. Please create it with domains one per line.")
        return []

def build_dns_query(domain: str, query_type: int) -> bytes:
    """Builds a valid RFC 1035 DNS query packet."""
    # Header: ID, Flags (standard query), QDCount=1, ANCount=0, NSCount=0, ARCount=0
    transaction_id = random.randint(0, 65535)
    flags = 0x0100          # QR=0 (query), RD=1 (recursion desired)
    header = struct.pack(">HHHHHH", transaction_id, flags, 1, 0, 0, 0)

    # QNAME: each label prefixed with its length, terminated by 0x00
    qname = b""
    for label in domain.split("."):
        encoded = label.encode("utf-8")
        qname += bytes([len(encoded)]) + encoded
    qname += b"\x00"

    # QTYPE and QCLASS (IN = 1)
    question = qname + struct.pack(">HH", query_type, 1)

    return header + question, transaction_id


def parse_dns_response(response: bytes, transaction_id: int) -> Tuple[bool, str]:
    """
    Parses a DNS response packet.
    Returns (success, message) where success=True if RCODE==0 and answer count > 0.
    """
    if len(response) < 12:
        return False, "MALFORMED_RESPONSE"

    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", response[:12])

    if resp_id != transaction_id:
        return False, "ID_MISMATCH"

    rcode = flags & 0x000F
    rcode_messages = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    rcode_msg = rcode_messages.get(rcode, f"RCODE_{rcode}")

    if rcode != 0:
        return False, rcode_msg

    # NOERROR but no answers (e.g. valid domain, no record of that type)
    if ancount == 0:
        return True, "NOERROR_NOANSWER"

    return True, f"NOERROR ({ancount} answer(s))"


def dns_query(domain: str, query_type: int) -> Tuple[bool, float, str, str, int]:
    """Performs a DNS query and returns the result."""
    global success_count, error_count, total_queries, latency_sum

    sock = None
    start_time = time.time()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)

        packet, transaction_id = build_dns_query(domain, query_type)
        sock.sendto(packet, (ADGUARD_DNS, ADGUARD_PORT))

        response, _ = sock.recvfrom(4096)
        latency = time.time() - start_time

        success, msg = parse_dns_response(response, transaction_id)

        if success:
            with counter_lock:
                latency_sum += latency
                success_count += 1
        else:
            with counter_lock:
                error_count += 1

        with counter_lock:
            total_queries += 1
        return success, latency if success else 0.0, msg, domain, query_type

    except socket.timeout:
        with counter_lock:
            error_count += 1
            total_queries += 1
        return False, 0.0, "TIMEOUT", domain, query_type

    except socket.error as e:
        with counter_lock:
            error_count += 1
            total_queries += 1
        return False, 0.0, f"SOCKET_ERROR: {e}", domain, query_type

    except Exception as e:
        with counter_lock:
            error_count += 1
            total_queries += 1
        return False, 0.0, f"OTHER_ERROR: {e}", domain, query_type

    finally:
        if sock:
            sock.close()

def main():
    """Main function to run the DNS test."""
    global success_count, error_count, latency_sum, total_queries

    parser = argparse.ArgumentParser(description="Test AdGuard Home DNS server efficiency.")
    parser.add_argument('--domains', type=str, default=DOMAINS_FILE, help='File containing domains to test (one per line)')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('--output', type=str, default=OUTPUT_CSV, help='Output CSV file path')
    args = parser.parse_args()

    domains = load_domains(args.domains)
    if not domains:
        print("No domains to test. Exiting.")
        return

    # Write CSV header
    with open(args.output, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Query_Type', 'Latency_ms', 'Success', 'Error'])

    # Start testing
    print(f"[+] Testing {len(domains)} domains with {args.threads} threads...")
    print(f"[+] DNS Server: {ADGUARD_DNS}:{ADGUARD_PORT}")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for domain in domains:
            for qtype in QUERY_TYPES:
                futures.append(executor.submit(dns_query, domain, qtype))

        # Wait for all futures
        for future in futures:
            try:
                success, latency, msg, domain, qtype = future.result()
                # Log to CSV
                with open(args.output, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([domain, qtype, f"{latency * 1000:.2f}", success, msg])
            except Exception as e:
                print(f"[!] Exception in thread: {e}")

    # Final stats
    success_rate = (success_count / total_queries) * 100 if total_queries > 0 else 0
    avg_latency = latency_sum / success_count if success_count > 0 else 0

    print("\n--- Test Results ---")
    print(f"Total Queries: {total_queries}")
    print(f"Successful Queries: {success_count}")
    print(f"Error Queries: {error_count}")
    print(f"Success Rate: {success_rate:.2f}%")
    print(f"Average Latency: {avg_latency:.2f} ms")

if __name__ == "__main__":
    main()