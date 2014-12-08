/*
 * TCPUtilities.h

 *
 *  Created on: 27-Nov-2014
 *      Author: jus-mine
 */



#ifndef TCPUTILITIES_H_
#define TCPUTILITIES_H_

#include<string>
#include<string.h>
#include<stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <iostream>
#include<pthread.h>
#include<sstream>
#include "CommonUtilities.h"
#include "Job.h"
#include <errno.h>

#define PACKET_LENGTH 2048

using namespace std;
class TCPUtilities {

CommonUtilities comUtil;
pthread_mutex_t createPacketLock = PTHREAD_MUTEX_INITIALIZER;


public :
	TCPUtilities();
	unsigned short csum(uint8_t *data, int length);
	uint16_t calculateCheckSum(uint32_t ipSource,uint32_t ipDest,uint8_t protocol, uint16_t tcpLength,struct tcphdr tcpSegment);
	void createPacket(string scanType,const char* destIP,const char* portNumber,char*,char*);
	void createTCPHeader(struct tcphdr* tcpHeader , int sourcePort,const char* destPort, string scanType);
	void sendTCPPacket(Job *job,char*);

};


#endif /* TCPUTILITIES_H_ */
