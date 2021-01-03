#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

// For ntohs
#include <arpa/inet.h>

// For ETHERTYPE_IP
#include <netinet/if_ether.h>

// For udp_header
#include <netinet/udp.h>

// For ip headers
#include <netinet/ip.h>

unsigned int rtp_frames = 0;

// RTP Streams: an array of a struct with: source IP, source port,
// destination IP, destination port, SSRC, uniquely identified by the SSRC
typedef struct rtp_stream_info {
    __be32 ssrc;
    __be16 src_port;
    __be16 dst_port;
    unsigned int count;
    struct rtp_stream_info *next;
} rtp_stream_info;

rtp_stream_info* rtpStreams = NULL;

void packet_cb(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void packet_cb(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct ether_header* ethernet_header;
	const struct ip* ip_header;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	const struct udphdr* udp_header;
	u_int src_port, dst_port, udp_len;

	pcap_dumper_t* dumper = (pcap_dumper_t*)userData;

	// Ethernet header: 14 Bytes
	ethernet_header = (struct ether_header*)packet;
	if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
		// IP header: 20 Bytes
		ip_header = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

		if (ip_header->ip_p == IPPROTO_UDP) {
			// UDP header, 8 Bytes
			udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			src_port = ntohs(udp_header->source);
			dst_port = ntohs(udp_header->dest);
			udp_len = ntohs(udp_header->len);

			u_int payload_len = udp_len - sizeof(struct udphdr);
			u_char* payload = (u_char*)(udp_header + 1);

			printf("This is an UDP packet - from %s:%d to %s:%d (UDP len:%d - payload len:%d)\n", src_ip, src_port, dst_ip, dst_port, udp_len, payload_len);

			// This can't be an RTP packet, too short to contain the RTP header
			if (payload_len < 12) {
				return;
			}

			// Ignore DNS (TODO: Add more)
			if (src_port != 53 && dst_port != 53) {
				// Assume this is an RTP packet and try reading the RTP header
				// Version is 2 leftmost bits in byte 0, and expected to be 10 (2)
				u_char version = (payload[0] >> 6) & 3;
				printf("\tVERSION: %d\n", version);

				u_char reception_report_count = (payload[0] & 1);
				printf("\tRECEPTION REPORT COUNT:%d\n", reception_report_count);

				if (version == 2) {
					if (reception_report_count == 0) {
						printf("\tThis could be an RTP v2 packet\n");

						// payload type is 1 byte from byte 0, e.g. 08
						u_char ptype = payload[1];
						printf("\tPTYPE: %d\n", ptype);

						// Sequence number is 2 bytes from byte 2, e.g. 8f 8b
						int seq = payload[2] << 8 | payload[3];
						printf("\tSEQ NO: %d\n", seq);

						// SSRC is 4 Bytes from byte 8, e.g. 36 e5 27 a5
						int ssrc = payload[8] << 24 | payload[9] << 16 | payload[10] << 8 | payload[11];
						printf("\tSSRC: 0x%x (%d)\n", ssrc, ssrc);

						rtp_frames++;

						{
							// Dump this packet into file
							pcap_dump((u_char*)dumper, pkthdr, packet);
						}

						rtp_stream_info* rtpStream = rtpStreams;
						u_char found = 0;
						while (rtpStream) {
							if (rtpStream->ssrc == ssrc) {
								printf("\t\tOne more for ssrc 0x%x\n", ssrc);
								rtpStream->count += 1;
								found = 1;
								break;
							}
							else {
								rtpStream = rtpStream->next;
							}
						}

						if (found == 0) {
							rtp_stream_info* newRTPStream = malloc(sizeof(rtp_stream_info));
							if (newRTPStream) {
								newRTPStream->ssrc = (__be32)ssrc;
								newRTPStream->src_port = src_port;
								newRTPStream->dst_port = dst_port;
								newRTPStream->count = 1;
								newRTPStream->next = rtpStreams;
								rtpStreams = newRTPStream;
							}
							else {
								printf("ERROR ALLOCATING MEM\n");
							}
						}
					}
					else {
						printf("Ignoring RTCP packet\n");
					}
				} // else can't be RTP v2
			} // else ignoring this packet as surely not RTP
		} // else not UDP
	} // else not IP
}

int main(int argc, char **argv) {
	pcap_t* pcap_handle;
	char err_buffer[PCAP_ERRBUF_SIZE];

	if (argc != 3) {
		printf("Usage: pcap_tool INPUT_FILE OUTPUT_FILE\n");
		return -1;
	}

	pcap_handle = pcap_open_offline(argv[1], err_buffer);
	if (pcap_handle == NULL) {
		printf("Error opening file (%s)\n", argv[1]);
		return 0;
	}

	pcap_t* handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
	pcap_dumper_t* dumper = pcap_dump_open(handle, argv[2]);

	if (pcap_loop(pcap_handle, 0, packet_cb, (u_char*)dumper) < 0) {
		printf("ERROR\n");
		return 0;
	}

	pcap_dump_close(dumper);

	printf("Extracted %d RTP frames\n", rtp_frames);

	rtp_stream_info* rsi = rtpStreams;
	while (rsi) {
		printf("\tDetected RTP Stream: 0x%x\tSource port:%d - Destination port:%d - Packets: %d\n", rsi->ssrc, rsi->src_port, rsi->dst_port, rsi->count);
		rsi = rsi->next;
	}

	free(rtpStreams);

	return 0;
}
