//============================================================================
// Name        : network_trace.cpp
// Author      : Eric Wilcox
// Version     :
// Copyright   : Advanced Network & Security course development project
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char *argv[])
	{
		char *dev, errbuf[PCAP_ERRBUF_SIZE];

		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		printf("Device: %s\n", dev);
		return(0);
	}
