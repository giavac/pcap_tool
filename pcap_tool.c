#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

// For ntohs
#include <arpa/inet.h>

// For ETHERTYPE_IP
#include <netinet/if_ether.h>

// For udp_header
#include <netinet/udp.h>

// For ip headers
#include <netinet/ip.h>

#define RTP_HEADER_LEN 12

typedef struct rtp_stream_info {
	uint32_t ssrc;
	uint16_t src_port;
	uint16_t dst_port;
	uint count;
	char file[80];
	pcap_dumper_t* dumper;
	struct rtp_stream_info *next;
} rtp_stream_info;

rtp_stream_info* rtp_streams = NULL;
unsigned int rtp_frames = 0;

void pcap_tool_packet_cb(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int pcap_tool_add_new_stream(uint32_t ssrc, uint16_t src_port, uint16_t dst_port, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int pcap_tool_add_stream(rtp_stream_info* rsi, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int pcap_tool_add_new_stream(uint32_t ssrc, uint16_t src_port, uint16_t dst_port, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	rtp_stream_info* rsi = malloc(sizeof(rtp_stream_info));
	if (rsi == NULL) {
		printf("ERROR ALLOCATING MEM\n");
		return -1;
	}

	rsi->ssrc = ssrc;
	rsi->src_port = src_port;
	rsi->dst_port = dst_port;
	rsi->count = 1;
	snprintf(rsi->file, sizeof(rsi->file), "./stream-0x%x.pcap", ssrc);
	rsi->next = rtp_streams;
	rtp_streams = rsi;

	pcap_t* handle = pcap_open_dead(DLT_EN10MB, 1 << 16);
	if (handle == NULL) {
		printf("pcap_tool_start_new_stream - pcap_open_dead error\n");
		return -1;
	}

	rsi->dumper = pcap_dump_open(handle, rsi->file);
	if (rsi->dumper == NULL) {
		printf("pcap_tool_start_new_stream - error opening pcap dump (%s)\n", pcap_geterr(handle));
		return -1;
	}

	pcap_dump((u_char*)rsi->dumper, pkthdr, packet);
	return 0;
}

int pcap_tool_add_stream(rtp_stream_info* rsi, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	if (rsi == NULL) {
		return -1;
	}

	rsi->count += 1;
	pcap_dump((u_char*)rsi->dumper, pkthdr, packet);
	return 0;
}

void pcap_tool_packet_cb(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct ether_header* ethernet_header;
	const struct ip* ip_header;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	const struct udphdr* udp_header;
	uint16_t src_port, dst_port, udp_len;

	// Ethernet header: 14 Bytes
	ethernet_header = (struct ether_header*)packet;
	if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) {
		printf("Ignoring non-IPv4 packet\n");
		return;
	}

	// IP header: 20 Bytes
	ip_header = (struct ip*)(packet + sizeof(struct ether_header));
	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

	switch(ip_header->ip_p) {
		case IPPROTO_UDP:
			// UDP header, 8 Bytes
			udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			src_port = ntohs(udp_header->source);
			dst_port = ntohs(udp_header->dest);
			udp_len = ntohs(udp_header->len);

			uint16_t payload_len = udp_len - sizeof(struct udphdr);
			u_char* payload = (u_char*)(udp_header + 1);

			printf("This is an UDP packet - from %s:%d to %s:%d (UDP len:%d - payload len:%d)\n", src_ip, src_port, dst_ip, dst_port, udp_len, payload_len);

			// This can't be an RTP packet, too short to contain the RTP header
			if (payload_len < RTP_HEADER_LEN) {
				return;
			}

			// Ignore reserved ports
			if ((src_port < 1024) || (dst_port < 1024)) {
				return;
			}

			// Assume this is an RTP packet and try reading the RTP header
			// Version is 2 leftmost bits in byte 0, and expected to be 10 (2)
			u_char version = (payload[0] >> 6) & 3;
			printf("\tVERSION: %d\n", version);

			// Can't be an RTP v2 packet
			if (version != 2) {
				return;
			}

			u_char reception_report_count = (payload[0] & 1);
			printf("\tRECEPTION REPORT COUNT:%d\n", reception_report_count);

			if (reception_report_count == 1) {
				printf("Ignoring RTCP packet\n");
				return;
			}

			if (reception_report_count == 0) {
				printf("\tThis could be an RTP v2 packet\n");

				// payload type is 1 byte from byte 0, e.g. 08
				u_char ptype = payload[1];
				printf("\tPTYPE: %d\n", ptype);

				// Sequence number is 2 bytes from byte 2, e.g. 8f 8b
				int seq = payload[2] << 8 | payload[3];
				printf("\tSEQ NO: %d\n", seq);

				// SSRC is 4 Bytes from byte 8, e.g. 36 e5 27 a5
				uint32_t ssrc = payload[8] << 24 | payload[9] << 16 | payload[10] << 8 | payload[11];
				printf("\tSSRC: 0x%x (%d)\n", ssrc, ssrc);

				rtp_frames++;

				u_char found = 0;
				rtp_stream_info* rsi = rtp_streams;
				while (rsi) {
					if (rsi->ssrc == ssrc) {
						printf("\t\tOne more for ssrc 0x%x\n", ssrc);
						pcap_tool_add_stream(rsi, pkthdr, packet);
						found = 1;
						break;
					}
					else {
						rsi = rsi->next;
					}
				}

				if (found == 0) {
					if (pcap_tool_add_new_stream(ssrc, src_port, dst_port, pkthdr, packet) < 0) {
						printf("ERROR adding a new stream\n");
						return;
					}
				}
			}
		break;
		default:
			printf("Ignoring non-UDP packet\n");
		return;
	}

	return;
}

int main(int argc, char **argv) {
	pcap_t* pcap_handle;
	char err_buffer[PCAP_ERRBUF_SIZE];

	if (argc != 2) {
		printf("Usage: pcap_tool INPUT_FILE\n");
		return -1;
	}

	pcap_handle = pcap_open_offline(argv[1], err_buffer);
	if (pcap_handle == NULL) {
		printf("Error opening file (%s)\n", argv[1]);
		return 0;
	}

	if (pcap_loop(pcap_handle, 0, pcap_tool_packet_cb, NULL) < 0) {
		printf("ERROR\n");
		return 0;
	}

	printf("Extracted %d RTP frames\n", rtp_frames);

	rtp_stream_info* rsi = rtp_streams;
	while (rsi) {
		printf("\tDetected RTP Stream: 0x%x\tSource port:%d - Destination port:%d - Packets: %d\n", rsi->ssrc, rsi->src_port, rsi->dst_port, rsi->count);

		pcap_dump_close(rsi->dumper);

		rsi = rsi->next;
	}

	free(rtp_streams);

	return 0;
}
