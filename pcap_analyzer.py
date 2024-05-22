from scapy.all import rdpcap, IP, TCP, DNS, DNSQR
from collections import defaultdict
import argparse

def banner(): 
    print("""
╔═╗┌─┐┌─┐┌─┐  ╔═╗┌┐┌┌─┐┬ ┬ ┬┌─┐┌─┐┬─┐
╠═╝│  ├─┤├─┘  ╠═╣│││├─┤│ └┬┘┌─┘├┤ ├┬┘
╩  └─┘┴ ┴┴    ╩ ╩┘└┘┴ ┴┴─┘┴ └─┘└─┘┴└─                                
          """)

parser = argparse.ArgumentParser(description='Analyze packet capture (.pcap) file')
parser.add_argument('-f', '--file', type=str, help='Path to .pcap file', required=True)
parser.add_argument('-d', '--domains', type=str, help='Path to wordlist containing malicious domains', required=False)

flags_dict = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
}

# Function to process TCP flows and count bytes
def process_tcp_flows(packets):
    tcp_flows = defaultdict(lambda: defaultdict(lambda: {"bytes_transferred": 0, "packet_count": 0}))

    for packet in packets:
        if packet.haslayer(TCP):
            flow = (
                packet[IP].src,
                packet[TCP].sport,
                packet[IP].dst,
                packet[TCP].dport
            )
            flags = packet[TCP].flags
            
            # Count bytes for each flag within the flow
            tcp_flows[flow][flags]["bytes_transferred"] += len(packet)
            tcp_flows[flow][flags]["packet_count"] += 1

    return tcp_flows

# Function to check for DNS queries to malicious domains
def detect_c2_traffic(packets, domains):
    c2_traffic = defaultdict(lambda: defaultdict(lambda: {"request_count": 0, "answers": []}))

    for packet in packets:
        # check if packet has an dns layer and and dns question record layer (responses also include the qr)
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNS]
            query = dns[DNSQR].qname.decode().lower().strip('.')

            for domain in domains:
                if domain in query:
                    # Check if the packet is a DNS query (not a response -> qr flag set to 1)
                    if dns.qr == 0:
                        c2_traffic[domain][(packet[IP].src, packet[IP].dst, query)]["request_count"] += 1
                    
                    # Packet is an DNS response
                    else:
                        if dns.ancount > 0:  # DNS response with answers
                            for i in range(dns.ancount):
                                answer = dns.an[i]

                                # Only A records are currently processed, rest aren't analyzed further
                                if answer.type == 1:
                                    # Switch source and destination to add it to the corresponding response
                                    c2_traffic[domain][(packet[IP].dst, packet[IP].src, query)]["answers"].append(answer.rdata)
                                else: 
                                    c2_traffic[domain][(packet[IP].dst, packet[IP].src, query)]["answers"].append(f"Unknown type [{answer.type}]")

                        # No answers included, could also contain other errors than "No such name"
                        else: 
                            c2_traffic[domain][(packet[IP].dst, packet[IP].src, query)]["answers"].append("No such name")
                                
                    break

    return c2_traffic

if __name__ == '__main__': 
    banner()
    args = parser.parse_args()

    # Read packets from the pcap file    
    packets = rdpcap(args.file)
    
    # Process TCP flows and write output to file 
    print("[*] Analyzing TCP flows...")
    tcp_flows = process_tcp_flows(packets)
    with open('output.txt', 'w') as f:
        for flow, flags in tcp_flows.items():
            f.write(f"{flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}\n")

            for flag, data in flags.items(): 
                f.write(f"\tFlag: {" ".join([flags_dict[_] for _ in flag])}\n")
                f.write(f"\t\tBytes transferred: {data['bytes_transferred']}\n")
                f.write(f"\t\tPacket count: {data['packet_count']}\n\n")
    print("[+] TCP flows have been processed - Output can be viewed under ./output.txt")

    # Optional: Check DNS queries for c2 traffic
    if(args.domains): 
        print("[*] Checking for DNS queries to known malicious domains...")
        with open(args.domains, 'r') as f:
            domains = f.read().splitlines()
        
        c2_traffic = detect_c2_traffic(packets, domains)
        
        # Display information about C2 traffic
        if c2_traffic:
            for domain, data in c2_traffic.items():
                print(f"[!] Traffic to known malicious domain detected: {domain.replace('.', '[.]')}")
                for entry, entry_data in data.items():
                    print(f"\t{entry[0]} -> {entry[1]} - {entry[2].replace('.', '[.]')} ({entry_data['request_count']})")
                    
                    for answer in entry_data['answers']:
                        print(f"\t\tDNS Answer: {answer}")
                        
        else:
            print("[+] No DNS traffic to known malicious domains detected.")