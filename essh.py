import argparse
import socket
import netifaces
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

from settings import CONN_KEY, R_CONN_KEY

__version__ = "?"


def get_active_interface():
    return netifaces.gateways()["default"][netifaces.AF_INET][1]


def get_my_ip():
    host_name = [
        (s.connect(("8.8.8.8", 53)), s.getsockname()[0], s.close())
        for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]
    ][0][1]
    return str(host_name)


def get_ssh_sessions(pkt, sessions):
    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport

    # Create a session
    current_session_key = (ip_src, sport, ip_dst, dport, "tcp")
    if_rcon_key = False

    reverse_session_key = (ip_dst, dport, ip_src, sport, "tcp")
    if reverse_session_key in sessions:
        if_rcon_key = True
        current_session_key = reverse_session_key

    con_key = CONN_KEY
    if if_rcon_key:
        con_key = R_CONN_KEY

    current_session = sessions.get(current_session_key, {CONN_KEY: [], R_CONN_KEY: []})

    current_session[con_key].append(pkt)
    sessions[current_session_key] = current_session
    return sessions


def is_established(sessions):
    established_sessions = {}
    for tuple_key, communication_dict in sessions.items():
        for direction, packets in communication_dict.items():
            for packet in packets:
                packet_flags = int(packet[TCP].flags)
                # Flags: PA=24, A=16, S=2, SA=18, FA=17, RA=20
                if (packet_flags == 18) or (packet_flags == 24):
                    if tuple_key not in established_sessions:
                        established_sessions[tuple_key] = {
                            "ip1->ip2": [],
                            "ip2->ip1": [],
                        }
                    established_sessions[tuple_key][direction].append(packet)

    return established_sessions


def get_seesion_size(sessions):
    session_packets_size = {}
    for tuple_key, communication_dict in sessions.items():
        for direction, packets in communication_dict.items():
            session_size = 0
            for packet in packets:
                # packet_size = packet.getlayer(TCP).payload # TCP payload
                packet_size = packet.payload
                session_size += len(packet_size)  # IP payload
                if tuple_key not in session_packets_size:
                    session_packets_size[tuple_key] = {"ip1->ip2": 0, "ip2->ip1": 0}
                session_packets_size[tuple_key][direction] = session_size
    return session_packets_size


def is_successful_login(size):
    threshold = args.threshold
    if size >= threshold:
        return f"{size} Successful"
    else:
        return f" {size} NotSuccessful"


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Program 0.1 version {}. Authors: Anna Shirokova, Sebastian Garcia ".format(
            __version__
        ),
        usage="%(prog)s -n <ssh login detector> [options]",
    )

    parser.add_argument(
        "-f",
        "--filename",
        help="Output file with the amount of packets per port in json format.",
        action="store",
        required=False,
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Interface name to sniff the packets from",
        type=str,
        action="store",
        required=False,
    )
    parser.add_argument(
        "-r",
        "--read",
        help="Enter pcap path to read",
        type=str,
        action="store",
        required=False,
    )
    parser.add_argument(
        "-t",
        "--threshold",
        help="Choose threshold number. The default threshhold is 5340",
        type=int,
        default=5340,
        required=False,
    )
    parser.add_argument(
        "-s",
        "--sniff",
        help="Put the IP and PORT to sniff on",
        type=str,
        action="store",
        required=False,
    )

    parser.add_argument(
        "-t",
        "--threshold",
        help="Choose threshold number",
        type=int,
        action="store",
        required=False,
    )

    args = parser.parse_args()

    if args.filename:
        print(f"File: {args.filename}")

    if not args.interface:
        interface = get_active_interface()
    else:
        interface = args.interface

    pcap_path = args.read
    if pcap_path:
        pkts = rdpcap(pcap_path)
    else:
        raise Exception("Pass pcap path as -r argument")

    threshold = args.read

    sessions = {}
    for pkt in pkts:
        if IP in pkt and TCP in pkt and pkt[TCP].dport == 22:
            sessions = get_ssh_sessions(pkt, sessions)

    established_sessions = is_established(sessions)

    session_size = get_seesion_size(established_sessions)

    for conn_tuple, session_size in session_size.items():
        total_session_size = sum(session_size.values())
        is_successful = is_successful_login(total_session_size)
        src_ip, src_p, dst_ip, dst_p, proto = conn_tuple
        print(f"{src_ip},{src_p},{dst_ip},{dst_p},{proto},{is_successful}")
