//============================================================================
// Name        : network_trace.cpp
// Author      : Eric Wilcox
// Version     :
// Copyright   : Advanced Network & Security course development project
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
	{
		char *dev = argv[1];
		printf("Device: %s\n", dev);
		return 0;
	}
