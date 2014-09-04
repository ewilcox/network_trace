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
	pcap_t *handle;
	if (argc < 2) {
		printf("No pcap file to parse!\n");
		exit(EXIT_FAILURE);
	}
	char *file = argv[1];

	printf("File: %s\n", file);
	handle = pcap_open_offline(file,errbuf);
	if (handle == NULL) printf("Error: %s\n",errbuf);

	printf("end of program\n");
	return 0;
}
