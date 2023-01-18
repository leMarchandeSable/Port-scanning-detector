from lib import *
import os


def add_to_log(dic):
    with open("log.txt", "a") as file:

        string = ""
        for key in dic.keys():
            string += f"{dic[key]}" + " "*10

        file.write(string + "\n")


def scan_detection(pcap_name):
    capture = rdpcap(pcap_name)

    TCP_communication = {}
    for i, pkt in enumerate(capture):

        # -------------------------- stealth_scan--------------------------
        if is_IP(pkt):
            if is_TCP(pkt):

                flag = get_flag(pkt)
                window_size = get_window_size(pkt)
                header_lenght = get_header_lenght(pkt)

                if flag == "S" and window_size == 1024 and header_lenght == 44:

                    add_to_log({"file_name": pcap_name,
                                "pkt_number": i + 1,
                                "type_of_attack": "stealth",
                                "IP_attacker": get_IP(pkt)[0],
                                "IP_target": get_IP(pkt)[1],
                                "port_attack": get_port(pkt)[1]})

        # -------------------------- TCP_scan--------------------------
        if is_IP(pkt):
            if is_TCP(pkt):

                flag = get_flag(pkt)
                src, dst = get_port(pkt)

                client_ID = (src, dst)
                server_ID = (dst, src)
                client_pkt = client_ID in TCP_communication.keys()
                server_pkt = server_ID in TCP_communication.keys()

                # RST or ACK or DATA
                if client_pkt:
                    TCP_communication[client_ID].append((i + 1, pkt))

                # SYN/ACK or RST/ACK
                if server_pkt:
                    TCP_communication[server_ID].append((i + 1, pkt))

                # new TCP handshake
                if flag == "S":
                    TCP_communication[client_ID] = [(i + 1, pkt)]

                # end of communication
                if ("R" or "F") in flag:

                    if client_pkt:
                        last_sender_ID = client_ID
                    else:
                        last_sender_ID = server_ID

                    # pkts is a complete TCP conversation
                    # pkts[0] is the first packet of the conversation (syn flag)
                    try:
                        pkts = TCP_communication[last_sender_ID]
                        j, syn_pkt = pkts[0]

                        if conversation_complitness(pkts) == 4:
                            add_to_log({"file_name": pcap_name,
                                        "pkt_number": j,
                                        "type_of_attack": "TCP    ",
                                        "IP_attacker": get_IP(syn_pkt)[0],
                                        "IP_target": get_IP(syn_pkt)[1],
                                        "port_attack": get_port(syn_pkt)[1]})

                        TCP_communication.pop(last_sender_ID)
                    except KeyError:
                        pass


if __name__ == '__main__':

    try:
        os.remove("log.txt")
    except FileNotFoundError:
        pass

    scan_detection("demo.pcap")
    # scan_detection("trafic_00001_20221216161559.pcap")
