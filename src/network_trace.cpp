//============================================================================
// Name        : network_trace.cpp
// Author      : Eric Wilcox
// Version     :
// Copyright   : Advanced Network & Security course development project
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include <string>

using namespace std;



int main(int argc, char *argv[])
{
	string file;
	pcap_t *dev;
//	char *dev, errbuf[PCAP_ERRBUF_SIZE];

	if (argc > 1) {
		string file = argv[1];
		cout << "File listed: " << file << endl;
	} else {
		cout << "No pcap file to parse!\n";
		exit(EXIT_FAILURE);
	}

	return(0);
}
