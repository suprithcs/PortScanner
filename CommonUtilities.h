/*
 * CommonUtilities.h
 *
 *  Created on: 30-Nov-2014
 *      Author: jus-mine
 */

#ifndef COMMONUTILITIES_H_
#define COMMONUTILITIES_H_


#include<string>
#include<poll.h>
#include<fcntl.h>
#include <sys/types.h>
#include <netdb.h>
#include <linux/icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include<iostream>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sstream>
#include <arpa/inet.h>
#include <unistd.h>
#include<time.h>
#include "Job.h"


using namespace std;

class CommonUtilities {


public:

	static pthread_mutex_t mutexPoll; //= PTHREAD_MUTEX_INITIALIZER;
	static pthread_mutex_t mutexPoll2; //= PTHREAD_MUTEX_INITIALIZER;
	static pthread_mutex_t mutexCreateSocket;// = PTHREAD_MUTEX_INITIALIZER;

	int sniffAPacket(const char *target, const char* port,string scanType,int protocol, Job *job,int,int);
	int createRawSocket(int protocol);
	void buildDestIPStruct(struct sockaddr_in* victim, const char* ip, const char* portNumber);
	string getServiceInfo(struct sockaddr_in victim, const char* port);
	string probeSSHVersion(struct sockaddr_in victim);
	string probeWHOISVersion(struct sockaddr_in victim);
	string probeHTTPVersion(struct sockaddr_in victim);
	string probePOPVersion(struct sockaddr_in victim);
	string probeIMAPVersion(struct sockaddr_in victim);
	string probeSMTPVersion(struct sockaddr_in victim);
	bool checkIfIPMatch(const char* ip,struct iphdr *ptrToIPHeader);
	int lookIntoThePacket(const char* ip,const char* portNumber,char* ptrToRecievedPacket,string scanType, Job *job);
	int parseUDPResponse(const char* ip,const char* portNumber,unsigned char* ptrToRecievedPacket,Job*);
	int parseICMPResponse(const char*ip,const char*portNumber,unsigned char* sockReadBuffer, Job *job);
	int ParseTCPResponse(const char* ip,const char* portNumber,unsigned char* ptrToRecievedPacket,string scanType, Job *job);
};

#endif /* COMMONUTILITIES_H_ */
