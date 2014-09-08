//============================================================================
// Name        : network_trace.c
// Author      : Eric Wilcox (addition sources citation listed below)
// Version     : 1.0
// Copyright   : Advanced Network & Security course development homework (1)
//					project at Texas A&M University.
//					Majority of beginning code by Tim Carstens at tcpdump.org
//
//	This document is Copyright 2002 Tim Carstens. All rights reserved.
//	Redistribution and use, with or without modification, are permitted
//	provided that the following conditions are met:
//	1. Redistribution must retain the above copyright notice and this list of
//	   conditions.
//	2. The name of Tim Carstens may not be used to endorse or promote products
//	   derived from this document without specific prior written permission.
//
// Description : Pcap saved session reassymbly program in C
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>

#define ETHER_ADDR_LEN 6
#define SIZE_ETHERNET 14
#define SIZE_UDP 8
//#define DEBUG		// uncomment for debugging print statements
//#define DEBUGPAYLOAD

// Ethernet header
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    // destination host address
	u_char  ether_shost[ETHER_ADDR_LEN];    // source host address
	u_short ether_type;                     // IP? ARP? RARP? etc
};
// IP header
struct sniff_ip {
	u_char  ip_vhl;                 // version << 4 | header length >> 2
	u_char  ip_tos;                 // type of service
	u_short ip_len;                 // total length
	u_short ip_id;                  // identification
	u_short ip_off;                 // fragment offset field
	#define IP_RF 0x8000            // reserved fragment flag
	#define IP_DF 0x4000            // dont fragment flag
	#define IP_MF 0x2000            // more fragments flag
	#define IP_OFFMASK 0x1fff       // mask for fragmenting bits
	u_char  ip_ttl;                 // time to live
	u_char  ip_p;                   // protocol
	u_short ip_sum;                 // checksum
	struct  in_addr ip_src,ip_dst;  // source and dest address
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               // source port
	u_short th_dport;               // destination port
	tcp_seq th_seq;                 // sequence number
	tcp_seq th_ack;                 // acknowledgement number
	u_char  th_offx2;               // data offset, rsvd
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
	#define TH_PUSH 0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 // window
	u_short th_sum;                 // checksum
	u_short th_urp;                 // urgent pointer
};
struct sniff_udp {
	u_short uh_sport;		// source port
	u_short uh_dport;		// destination port
	u_short uh_len;			// length
	u_short uh_sum;			// checksum
};
// Re-assymbly structure
struct my_packet {		// Struct for storing packet data
	unsigned int packet_counter;
	struct sniff_ethernet ethernet;
	struct sniff_ip ip;
	struct sniff_tcp tcp;
	struct sniff_udp udp;
	int size_ip;
	int size_tcp;
	int size_payload;
	struct pcap_pkthdr header;
	u_char payload;
	struct my_packet *next;
};
void printem(const struct sniff_ethernet *ethernet, const struct pcap_pkthdr *header, const u_char *packet) {	// Use to print out misc data as needed for evaluation, called at end of got_packet()
	// TODO ?
}
void initem(struct my_packet *root) {	// init root node just in case
	root->header.caplen = 0;
	root->header.len = 0;
	root->header.ts.tv_sec = 0;
	root->header.ts.tv_usec = 0;
	root->packet_counter = 0;
	root->size_ip = 0;
	root->size_payload = 0;
	root->payload = 0;
	root->size_tcp = 0;
	root->next = NULL;
}
void insert_list(struct my_packet *root, struct my_packet *nu) {
	//TODO Search for correct place to put packet for reassymbly
	struct my_packet *c = root;
	while(c->next != NULL) c = c->next;
	nu->next = NULL;
	c->next = nu;
}
// Called from print_payload, print in rows of 16 bytes:  offset  hex  ascii
// 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
	int i, gap;
	const u_char *ch;
	printf("%05d   ", offset);		// offset
	ch = payload;					// print hex
	for (i=0; i<len; i++) {
		printf("%02x ", *ch);
		ch++;
		if (i == 7) printf(" ");	// print extra space after 8th byte for visual aid
	}
	if (len < 8) printf(" ");		// print space to handle line less than 8 bytes
	if (len < 16) {					// print hex gap with spaces if not full line
		gap = 16 - len;
		for (i=0; i<gap; i++) printf(" ");
	}
	printf("   ");

	ch = payload;		// ascii (if printable)
	for (i=0; i<len; i++) {
		if (isprint(*ch)) printf("%c", *ch);
		else printf(".");
		ch++;
	}
	printf("\n");
}
// Called from got_packet to print packet payload - don't print binary data
void print_payload(const u_char *payload, int len) {
	int len_rem = len;
	int line_width = 16;		// number of bytes per line
	int line_len;
	int offset = 0;				// zero-based offset counter
	const u_char *ch = payload;

	if (len <= 0) return;		// if no payload, done
	if (len <= line_width) {	// data fits on one line
		print_hex_ascii_line(ch, len, offset);
		return;
	}
	for (;;) {					// data spans multiple lines
		line_len = line_width % len_rem;			// get current line length
		print_hex_ascii_line(ch, line_len, offset);	// print line
		len_rem -= line_len;						// get total remaining
		ch += line_len;								// shift point to remaining bytes to print
		offset += line_width;						// add offset
		if (len_rem <= line_width) {	// see if line_width char or less
			print_hex_ascii_line(ch, len_rem, offset);  // print last line and break
			break;
		}
	}
}
// Callback function for pcap_loop call (processing of packet data)
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	struct my_packet *root = (struct my_packet *) args;
	struct my_packet *nu;
	nu = (struct my_packet *) malloc( sizeof(struct my_packet));
	if (!nu) {
		printf("Error: Out of Memory\n");
		return;
	}

	static int counter = 1;					// packet count
	nu->packet_counter = counter;
	nu->header.caplen = header->caplen;
	nu->header.len = header->len;
	nu->header.ts = header->ts;

	// pointers to packet headers
	const struct sniff_ethernet *ethernet;	// Ethernet header
	const struct sniff_ip *ip;				// IP header
	const struct sniff_tcp *tcp;			// TCP header
	const struct sniff_udp *udp;			// UDP header
	const char *payload;					// Packet payload

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;

#ifdef DEBUG
	printf("Packet [%d]\nLength: [%d]:\n", counter, header->len);
#endif
	counter++;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	nu->ethernet = *ethernet;
	nu->ip = *ip;
	nu->size_ip = size_ip;
	if (nu->size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes, packet number [%d]\n", size_ip, counter);
		return;
	}
#ifdef DEBUG
			printf("Packet [%d]  nu->Source: %s  ", nu->packet_counter, inet_ntoa(nu->ip.ip_src));
			printf("Packet [%d]  nu->Desitination: %s\n", nu->packet_counter, inet_ntoa(nu->ip.ip_dst));
			printf("             ip->From: %s   ", inet_ntoa(ip->ip_src));
			printf("     ip->  To: %s\n", inet_ntoa(ip->ip_dst));
#endif
	//TODO Print all packet data to file so can see it to compare?
	// determine protocol & print it
	switch(ip->ip_p) {			// matching from enum types listed in in.h
		case IPPROTO_TCP:		// 6 for TCP
			// TCP header offset computation
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			nu->tcp = *tcp;
			nu->size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes packet number [%d]\n", size_tcp, counter);
				return;
			}
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);	// define/compute tcp payload (segment) offset
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);			// compute tcp payload (segment) size / byte order conversion
#ifdef DEBUG
			printf("   Src port: %d\n", ntohs(tcp->th_sport));		// note ntohs converts unsigned short int 'netshort' from network byte order to host byte order
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));
#endif
#ifdef DEBUGPAYLOAD
			if (size_payload > 0) {												//Print payload data; it might be binary, so don't just treat it as a string.
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
#endif
			break;
		case IPPROTO_UDP:		// 17 for UDP
			//TODO port still showing up incorrectly
			printf("UDP packet [%d] from port [%i] to [%i], len: [%d], sum: [%d]\n", nu->packet_counter, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_len), ntohs(udp->uh_sum));
			udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + SIZE_UDP);
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
			size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
			if (size_payload > ntohs(udp->uh_len))
				size_payload = ntohs(udp->uh_len);
#ifdef DEBUG
			if (size_payload > 0) {
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
#endif
			break;
		case IPPROTO_ICMP:		// 1 for ICMP
			printf("   Protocol: ICMP  -  no storage/reconstruction implemented for this program\n");
			return;
		case IPPROTO_IP:		// 0 for IP
			printf("   Protocol: IP  -  no storage/reconstruction implemented for this program\n");
			return;
		default:				// 255 for unknown - listed as RAW packets under in.h numbering
			printf("   Protocol: unknown  -  no storage/reconstruction implemented for this program\n");
			return;
	}
	nu->payload = *payload;
	nu->size_payload = size_payload;
	insert_list(root,nu);
}

void traverse(struct my_packet *root) {		// traverse the list and print stuff
	struct my_packet *c = root;
	if (c->next != NULL) {
		c = c->next;
		printf("Packet [%d]  Source: %s  ", c->packet_counter, inet_ntoa(c->ip.ip_src));
		printf("Destination: %s  ", inet_ntoa(c->ip.ip_dst));
		if (c->ip.ip_p == IPPROTO_TCP) {
			printf("From port [%i] to [%i]  ", ntohs(c->tcp.th_sport), ntohs(c->tcp.th_dport));
			printf("ip.len: %d, ip.id: %i, ip.offset: %i", ntohs(c->ip.ip_len), ntohs(c->ip.ip_id), ntohs(c->ip.ip_off));
		}
		else if (c->ip.ip_p == IPPROTO_UDP)
			printf("From port [%i]  To Port [%i]", ntohs(c->udp.uh_sport), ntohs(c->udp.uh_dport));
		else
			printf("No ports, isn't tcp or udp packet we're looking at");
		printf(" tcp.ack: [%d] tcp.seq [%d]", ntohs(c->tcp.th_ack), ntohs(c->tcp.th_seq));
		printf(" tcp.flags[%d] tcp.off [%d] packet_size [%d]", ntohs(c->tcp.th_flags), ntohs(c->tcp.th_offx2), c->size_payload);
		print_payload(&c->payload, c->size_payload);
		printf("\n");
		traverse(c);
	}
}
void free_list(struct my_packet *root) {
	struct my_packet *c;
	while (c->next != NULL) {
		c = root;
		root = c->next;
		free(c);
	}
}
int main(int argc, char *argv[])
{
	struct my_packet *root = (struct my_packet *)malloc( sizeof(struct my_packet));
//	root = malloc( sizeof(struct my_packet));
	root->next = NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;					// Session handle
	// if no pcap file listed in call, print error and quit
	if (argc < 2) {
		printf("No pcap file to parse!\n");
		exit(EXIT_FAILURE);
	}
	char *file = argv[1];
	printf("File to open: %s\n", file);
	handle = pcap_open_offline(file,errbuf);
	if (handle == NULL) {
		printf("Couldn't open file, %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
	// Don't use pcap_datalink check as header could mistakingly have
	// another type listed (see pcap_next man page)
	/*
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("File data doesn't provide Ethernet headers - not supported\n");
		return(2);
	}
	*/
	// Filters not included, want to capture all packets with this

	// -1 to loop until error or end, last argument is additional arguments sent to callback(got_packet)
	pcap_loop(handle, -1, got_packet, root);

	traverse(root);
	pcap_close(handle);

	free_list(root);
	printf("Program Complete\n");
	return 0;
}
