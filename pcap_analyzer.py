from scapy.all import rdpcap, IP, TCP
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

if __name__ == '__main__': 
    banner()
    args = parser.parse_args()

    # Read packets from the pcap file    
    packets = rdpcap(args.file)
    
    # Process TCP flows
    tcp_flows = process_tcp_flows(packets)

    # Write TCP flows to output file
    with open('output.txt', 'w') as f:
        for flow, flags in tcp_flows.items():
            f.write(f"{flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}\n")

            for flag, data in flags.items(): 
                f.write(f"\tFlag: {" ".join([flags_dict[_] for _ in flag])}\n")
                f.write(f"\t\tBytes transferred: {data['bytes_transferred']}\n")
                f.write(f"\t\tPacket count: {data['packet_count']}\n\n")

    print("File has been processed - Output can be viewed under ./output.txt")
