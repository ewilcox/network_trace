//============================================================================
// Name        : network_trace.cpp
// Author      : Eric Wilcox
// Version     : 1.0
// Copyright   : Advanced Network & Security course development project
// Description : Pcap saved session reassymbly program in C
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	FILE * fp;

	if (argc < 2) {
		printf("No pcap file to parse!\n");
		exit(EXIT_FAILURE);
	}
	fp = fopen(argv[1],"r");
	printf("File listed: %s\n", argv[1]);
	//pcap_t *pcap_fopen_offline(*fp,*errbuf);
	return(0);
}
