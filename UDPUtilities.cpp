#include "UDPUtilities.h"

/**
 * createUDPHeader
 *
 * Creates the UDP header content
 */
void UDPUtilities::createUDPHeader(struct udphdr* udpHeader,
		int sourcePort, const char* destPort) {
		udpHeader->source = htons(sourcePort);
		udpHeader->dest = htons(atoi(destPort));
		udpHeader->len = htons(sizeof(struct udphdr));
}

/**
 * createDNSPacket
 *
 * Creates the DNS header content
 */
void UDPUtilities::createDNSPacket(char* ipAddress, char* packet) {
	//code to generate random port number
		DNS_HEADER* dnsHeader = (DNS_HEADER *)packet;
		dnsHeader->id = htons(rand());
		dnsHeader->qr = 0;
		dnsHeader->opcode = 0;
		dnsHeader->aa = 0;
		dnsHeader->ra = 0;
		dnsHeader->rd = 1;
		dnsHeader->tc = 0;
		dnsHeader->ad = 0;
		dnsHeader->cd = 0;
		dnsHeader->q_count = htons(1);
		dnsHeader->rcode = 0;
		dnsHeader->ans_count = 0;
		dnsHeader->auth_count = 0;
		dnsHeader->add_count = 0;

	//	return packet;
}

/**
 * convertToDNSNAmeFormat
 *
 * converts given string (www.google.com) to (3www6gooogle3com)
 */
void UDPUtilities::convertToDNSNAmeFormat(unsigned char* dnsHeader,
		char* destinationHost) {
	string temp;
	int count = 0; unsigned char* rvIterator = dnsHeader + strlen(destinationHost);
	for(int i = strlen(destinationHost) - 1; i >= 0 ;i--){
		if(destinationHost[i] == '.'){
			*rvIterator-- = count;
			count = 0;
		}
		else {
			*rvIterator-- = destinationHost[i];
			count++;
		}
	}
	*rvIterator-- = count;
}

/**
 * createPacketUDP
 *
 * Fills in the UDP packet content and returns the total size of the packet
 */
int UDPUtilities::createPacketUDP(int sourcePort, const char* destPort,
	char* destIpAddress, char* packet) {
	struct udphdr *udpPack = (struct udphdr *)packet;
	QUESTION* dnsQueryInfo;
	size_t totalSize = sizeof(struct udphdr);
	createUDPHeader(udpPack,sourcePort,destPort);
	unsigned char* dnsQueryName;
	if(strcmp(destPort,"53") == 0) {
		createDNSPacket((char *)destIpAddress,packet+sizeof(struct udphdr));
		// query name
		dnsQueryName = (unsigned char*)(packet + sizeof(struct udphdr) + sizeof(DNS_HEADER));
		convertToDNSNAmeFormat(dnsQueryName,(char *)"www.google.com");
		//query info
		dnsQueryInfo = (QUESTION *)(packet + sizeof(struct udphdr) + sizeof(DNS_HEADER) + strlen((const char*)(dnsQueryName))+1);
		dnsQueryInfo->qtype = htons(1);
		dnsQueryInfo->qclass = htons(1);
		totalSize +=  sizeof(DNS_HEADER) + strlen((const char*)(dnsQueryName)) + 1 + sizeof(QUESTION);
		udpPack->len = htons(totalSize);
	}
	return totalSize;
}


/**
 * sendUDPPacket
 *
 * sends the UDP packet to the destination host and fills in the details of the job execution
 */
void UDPUtilities::sendUDPPacket(Job *job) {

	const char* destPort = job->port.c_str();
	const char* destIpAddress = job->IP.c_str();
	string scanType = job->scanType;
	int sockDesc = comUtil.createRawSocket(IPPROTO_UDP);
	char packData[PACKET_LENGTH];
	memset(packData, 0, PACKET_LENGTH);
	size_t totalSize = sizeof(struct udphdr);
	if(sockDesc < 0)
		cout << "creation of sock failed";
	else {
		int min = 30000, max = 60000;
		srand (time(0));
		int sourcePort = min + rand() % ( max - min + 1 );
		totalSize = createPacketUDP(sourcePort,destPort,(char *)destIpAddress,packData);
		struct sockaddr_in victim;
		memset(&victim, 0, sizeof(struct sockaddr_in));
		comUtil.buildDestIPStruct(&victim,destIpAddress, destPort);
		int status = -1,recievedSize = 0;
		char sockReadBuffer[200];
		memset(sockReadBuffer,'\0',200);
		vector<char> sockWriteBuffer;
		int probeCounter = 3;
		int sockDescProt = comUtil.createRawSocket(IPPROTO_UDP);
		int sockDescICMP = comUtil.createRawSocket(IPPROTO_ICMP);
		while(status < 0) {
			if(probeCounter > 0){
				if(sendto(sockDesc,packData,totalSize,0,(sockaddr *)&victim,sizeof(struct sockaddr_in)) > 0)
					status = comUtil.sniffAPacket(destIpAddress,destPort,scanType,IPPROTO_UDP, job,sockDescProt,sockDescICMP);
				probeCounter--;
			}
			else {
				job->scanResult = "Open|Filtered";
				break;
			}
		}
		if(sockDesc > 0)
			close(sockDesc);
		if(sockDescProt > 0)
				close(sockDescProt);
		if(sockDescICMP > 0)
			close(sockDescICMP);

		job->jobStatus = COMPLETED;
	}
}

