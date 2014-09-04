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

// Ethernet header
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
// IP header
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
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
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

// Callback function for pcap_loop call (processing of packet data)
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	static int counter = 1;					// packet count

	// pointers to packet headers
	const struct sniff_ethernet *ethernet;	// Ethernet header
	const struct sniff_ip *ip;				// IP header
	const struct sniff_tcp *tcp;			// TCP header
	const char *payload;					// Packet payload

	int size_ip;
	int size_tcp;
	int size_payload;

	printf("Packet [%d] - Length: [%d]:\n", counter, header->len);
	counter++;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	// determine protocol
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	// Handle packet for TCP, could be in switch above I believe
	// TCP header offset computation
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	// define/compute tcp payload (segment) offset
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	// compute tcp payload (segment) size
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	//Print payload data; it might be binary, so don't just treat it as a string.
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		//TODO
		//print_payload(payload, size_payload);
	}
//	if (header->caplen != header->len) printf("Packet mismatch num[%d]", counter);
//	if (ip->ip_p != IPPROTO_TCP) printf("Not TCP! Packet num[%d]", counter);
}

int main(int argc, char *argv[])
{
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
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle);
	printf("end of program\n");
	return 0;
}
