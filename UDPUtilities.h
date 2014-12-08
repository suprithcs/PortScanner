/*
 * UDPUtilities.h
 *
 *  Created on: 27-Nov-2014
 *      Author: jus-mine
 */

#ifndef UDPUTILITIES_H_
#define UDPUTILITIES_H_

#include "DNS_Header.h"
#include <linux/icmp.h>
#include <netinet/udp.h>
#include<iostream>
#include<string.h>
#include<vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "CommonUtilities.h"
#include "Job.h"
#define PACKET_LENGTH 2048
using namespace std;

class UDPUtilities  {
	CommonUtilities comUtil;
public:

	void createUDPHeader(struct udphdr *udpHeader,int sourcePort,const char* destPort);
	void createDNSPacket(char* ipAddress,char* packet);
	void convertToDNSNAmeFormat(unsigned char* dnsHeader,char* destinationHost);
	int createPacketUDP(int sourcePort,const char* destPort,char* destIpAddress,char* packet);
	void sendUDPPacket(Job *job);
};



#endif /* UDPUTILITIES_H_ */
