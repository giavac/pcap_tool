#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

// For getopt
#include <unistd.h>
#include <ctype.h>

// For ntohs
#include <arpa/inet.h>

// For ETHERTYPE_IP
#include <netinet/if_ether.h>

// For udphdr
#include <netinet/udp.h>

// For tcphdr
#include <netinet/tcp.h>

// For ip headers
#include <netinet/ip.h>

#define RTP_HEADER_LEN 12

typedef struct RTPStreamInfo {
	uint32_t ssrc;
	uint16_t src_port;
	uint16_t dst_port;
	uint count;
	char file[80];
	pcap_dumper_t* dumper;
	struct RTPStreamInfo* next;
} RTPStreamInfo;

typedef struct CryptoAttribute {
	uint8_t tag;
	char crypto_suite[80];
	char key_params[80];
	struct CryptoAttribute* next;
} CryptoAttribute;

typedef struct SDPInfo {
	uint16_t audio_port;
	CryptoAttribute* crypto_attributes;
	struct SDPInfo* next;
} SDPInfo;

RTPStreamInfo* rtp_streams = NULL;
SDPInfo* sdp_infos = NULL;
uint rtp_frames = 0;
int debug_print = 0;

void pcap_tool_packet_cb(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void pcap_tool_process_udp_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
void pcap_tool_process_tcp_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
int pcap_tool_add_new_stream(uint32_t ssrc, uint16_t src_port, uint16_t dst_port, const struct pcap_pkthdr* pkthdr, const u_char* packet);
int pcap_tool_add_stream(RTPStreamInfo* rsi, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void pcap_tool_parse_sip(const char* payload, uint payload_len);

void pcap_tool_process_udp_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct udphdr* udp_header;
	uint16_t src_port, dst_port, udp_len;

	// UDP header, 8 Bytes
	udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
	src_port = ntohs(udp_header->source);
	dst_port = ntohs(udp_header->dest);
	udp_len = ntohs(udp_header->len);

	uint16_t payload_len = udp_len - sizeof(struct udphdr);
	u_char* payload = (u_char*)(udp_header + 1);

	if (debug_print) printf("This is an UDP packet - from %d to %d (UDP len:%d - payload len:%d)\n", src_port, dst_port, udp_len, payload_len);

	// This can't be an RTP packet, too short to contain the RTP header
	if (payload_len < RTP_HEADER_LEN) {
		return;
	}

	// Ignore reserved ports
	if ((src_port < 1024) || (dst_port < 1024)) {
		return;
	}

	if ((src_port == 5060) || (dst_port == 5060)) {
		// Likely to be SIP
		pcap_tool_parse_sip(payload, payload_len);
	}

	// Assume this is an RTP packet and try reading the RTP header
	// Version is 2 leftmost bits in byte 0, and expected to be 10 (2)
	u_char version = (payload[0] >> 6) & 3;
	if (debug_print) printf("\tVERSION: %d\n", version);

	// Can't be an RTP v2 packet
	if (version != 2) {
		return;
	}

	u_char reception_report_count = (payload[0] & 1);
	if (debug_print) printf("\tRECEPTION REPORT COUNT:%d\n", reception_report_count);

	if (reception_report_count == 1) {
		if (debug_print) printf("Ignoring RTCP packet\n");
		return;
	}

	if (reception_report_count == 0) {
		if (debug_print) printf("\tThis could be an RTP v2 packet\n");

		// payload type is 1 byte from byte 0, e.g. 08
		u_char ptype = payload[1];
		if (debug_print) printf("\tPTYPE: %d\n", ptype);

		// Sequence number is 2 bytes from byte 2, e.g. 8f 8b
		int seq = payload[2] << 8 | payload[3];
		if (debug_print) printf("\tSEQ NO: %d\n", seq);

		// SSRC is 4 Bytes from byte 8, e.g. 36 e5 27 a5
		uint32_t ssrc = payload[8] << 24 | payload[9] << 16 | payload[10] << 8 | payload[11];
		if (debug_print) printf("\tSSRC: 0x%x (%d)\n", ssrc, ssrc);

		rtp_frames++;

		u_char found = 0;
		RTPStreamInfo* rsi = rtp_streams;
		while (rsi) {
			if (rsi->ssrc == ssrc) {
				if (debug_print) printf("\t\tOne more for ssrc 0x%x\n", ssrc);
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

	return;
}

void pcap_tool_process_tcp_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	const struct tcphdr* tcp_header;
	uint16_t src_port, dst_port;

	tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

	src_port = ntohs(tcp_header->source);
	dst_port = ntohs(tcp_header->dest);

	// th_off contains the number of 32-bit words forming the TCP header
	size_t offset = sizeof(struct ether_header) + sizeof(struct ip) + (4 * tcp_header->th_off);

	uint32_t payload_len = pkthdr->len - (uint32_t)offset;
	u_char* payload = (u_char*)packet + offset;

	if (((src_port == 5060) || (dst_port == 5060)) && (payload_len > 20)) {
		if (debug_print) printf("This is a TCP packet, potential SIP - from %d to %d (payload len:%d)\n", src_port, dst_port, payload_len);
		pcap_tool_parse_sip(payload, payload_len);
	}

	return;
}

void pcap_tool_parse_sip(const char* payload, uint payload_len) {
	if (debug_print) printf("pcap_tool_parse_sip ---- %.*s\n", payload_len, payload);

	// Make payload a null terminated string
	char payload_s[payload_len + 1];
	memcpy(payload_s, payload, payload_len);
	payload_s[payload_len] = '\0';

	char* is_invite = strstr(payload_s, "INVITE sip:");
	char* is_200 = strstr(payload_s, "SIP/2.0 200 OK");

	if ((is_invite == NULL) && (is_200 == NULL)) {
		return;
	}

	char* crypto_attributes = strstr(payload_s, "crypto");
	if (debug_print) printf("all crypto attributes: %s\n", crypto_attributes);

	SDPInfo* sdp_info = malloc(sizeof (SDPInfo));
	sdp_info->crypto_attributes = NULL;

	if (crypto_attributes != NULL) {

		// Example:
		// crypto:1 AES_256_CM_HMAC_SHA1_80 inline:GfuQMrokHEnK+kFkvX8JS6JTC2ogL9jAmbKoIoZBU3BE4e8xjIdz68ZlZJ3Rqw==
		char* s1;
		char* crypto_line = strtok_r(crypto_attributes, "\n", &s1);
		while (crypto_line) {
			char* s2;
			// "crypto:N"
			char* crypto_portion = strtok_r(crypto_line, " ", &s2);
			if (debug_print) printf("Crypto line number: %s\n", crypto_portion);

			CryptoAttribute* crypto_attribute = malloc(sizeof (CryptoAttribute));
			crypto_attribute->next = sdp_info->crypto_attributes;
			sdp_info->crypto_attributes = crypto_attribute;

			char* stag;
			char* tag = strtok_r(crypto_portion, ":", &stag);
			if (stag) {
				uint8_t ntag = (uint8_t)(stag[0] - '0');
				if (debug_print) printf("Crypto tag: %d\n", ntag);
				sdp_info->crypto_attributes->tag = ntag;
			}

			// AES_256_CM_HMAC_SHA1_80
			crypto_portion = strtok_r(NULL, " ", &s2);
			if (debug_print) printf("\t\t\t\t cipher: %s\n", crypto_portion);

			if (crypto_portion) {
				strncpy(sdp_info->crypto_attributes->crypto_suite, crypto_portion, 80);
			}

			// inline:GfuQMrokHEnK+kFkvX8JS6JTC2ogL9jAmbKoIoZBU3BE4e8xjIdz68ZlZJ3Rqw==
			crypto_portion = strtok_r(NULL, " ", &s2);

			char* key_value = strtok(crypto_portion, ":");
			key_value = strtok(NULL, ":");
			if (debug_print) printf("\t\t\t\t inline value: %s\n", key_value);

			if (key_value) {
				strncpy(sdp_info->crypto_attributes->key_params, key_value, 80);
			}

			crypto_line = strtok_r(NULL, "\n", &s1);
		}
	}

	// m=audio 11564 RTP/SAVP 8 120
	char* audio_attributes = strstr(payload_s, "m=audio");

	if (audio_attributes != NULL) {
		char* s0;
		char* audio_port = strtok_r(audio_attributes, " ", &s0);
		audio_port = strtok_r(NULL, " ", &s0);

		if (audio_port != NULL) {
			if (debug_print) printf("Audio port:%s\n\n", audio_port);
		}

		sdp_info->audio_port = atoi(audio_port);

		CryptoAttribute* ca = sdp_info->crypto_attributes;
		while (ca) {
			if (debug_print) printf("----- %s - %s\n", ca->crypto_suite, ca->key_params);
			ca = ca->next;
		}

		sdp_info->next = sdp_infos;
		sdp_infos = sdp_info;
	}

	printf("\n\n");
	return;
}

int pcap_tool_add_new_stream(uint32_t ssrc, uint16_t src_port, uint16_t dst_port, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	RTPStreamInfo* rsi = malloc(sizeof (RTPStreamInfo));
	if (rsi == NULL) {
		printf("ERROR ALLOCATING MEM\n");
		return -1;
	}

	rsi->ssrc = ssrc;
	rsi->src_port = src_port;
	rsi->dst_port = dst_port;
	rsi->count = 1;
	snprintf(rsi->file, sizeof(rsi->file), "./stream-0x%x.pcap", ssrc);

	// Add to list of RTP streams
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
	pcap_close(handle);
	return 0;
}

int pcap_tool_add_stream(RTPStreamInfo* rsi, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
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

	// Ethernet header: 14 Bytes
	ethernet_header = (struct ether_header*)packet;
	if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP) {
		if (debug_print) printf("Ignoring non-IPv4 packet\n");
		return;
	}

	// IP header: 20 Bytes
	ip_header = (struct ip*)(packet + sizeof(struct ether_header));
	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

	switch(ip_header->ip_p) {
		case IPPROTO_UDP:
			pcap_tool_process_udp_packet(pkthdr, packet);
		break;
		case IPPROTO_TCP:
			pcap_tool_process_tcp_packet(pkthdr, packet);
		break;
		default:
			if (debug_print) printf("Ignoring non-UDP packet for now\n");
		return;
	}

	return;
}

int main(int argc, char **argv) {
	pcap_t* pcap_handle;
	char err_buffer[PCAP_ERRBUF_SIZE];
	int index;
	int c;

	opterr = 0;

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
			case 'd':
				debug_print = 1;
				break;
			case '?':
				if (isprint(optopt)) {
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				}
				else {
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				}
				return 1;
			default:
				abort();
		}
	}

	pcap_handle = pcap_open_offline(argv[optind], err_buffer);

	if (pcap_handle == NULL) {
		printf("Error opening file (%s)\n", argv[1]);
		return 0;
	}

	if (pcap_loop(pcap_handle, 0, pcap_tool_packet_cb, NULL) < 0) {
		printf("ERROR\n");
		return 0;
	}

	printf("Extracted %d RTP frames\n", rtp_frames);

	RTPStreamInfo* rsi = rtp_streams;
	while (rsi) {
		printf("\tDetected RTP Stream: 0x%x\tSource port:%d - Destination port:%d - Packets: %d (%s)\n", rsi->ssrc, rsi->src_port, rsi->dst_port, rsi->count, rsi->file);

		pcap_dump_close(rsi->dumper);

		RTPStreamInfo* rsi_tmp = rsi;
		rsi = rsi->next;
		free(rsi_tmp);
	}

	printf("\n\n");

	SDPInfo* si = sdp_infos;
	while (si) {
		CryptoAttribute* ca = si->crypto_attributes;
		while (ca) {
			if (debug_print) printf("source port: %d - tag: %d - suite: %s - key: %s\n", si->audio_port, ca->tag, ca->crypto_suite, ca->key_params);
			CryptoAttribute* tmp = ca;
			ca = ca->next;
			free(tmp);
		}

		SDPInfo* tmp_si = si;
		si = si->next;
		free(tmp_si);
		if (debug_print) printf("-----\n");
	}

	pcap_close(pcap_handle);

	return 0;
}
