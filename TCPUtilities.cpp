#include "TCPUtilities.h"



TCPUtilities::TCPUtilities(){}

/**
 * csum
 *
 * add and get the final check sum
 *
 */
unsigned short TCPUtilities::csum(uint8_t *data, int length) {

	long checkSum = 0;
	while(length > 0) {

		checkSum += (*data << 8 & 0xFF00) + (*(data + 1) & 0xFF);
		data += 2;
		length-=2;
	}
	if(checkSum >> 16)
		checkSum = ((checkSum >> 16)& 0x00ff) + ( checkSum & 0xFFFF);

	uint16_t finalSum = (uint16_t)(~checkSum);

	return finalSum;
}


/**
 * calculateCheckSum
 *
 * Returns the check sum for the TCP packet
 */
uint16_t TCPUtilities::calculateCheckSum(uint32_t ipSource, uint32_t ipDest,uint8_t protocol, uint16_t tcpLength, struct tcphdr tcpSegment) {

	char* ch;
	char packet[PACKET_LENGTH];
	char content[2];
	int checkSumLength = 0;

	ch = packet;

	memcpy(ch,&ipSource,sizeof(ipSource));
	ch += sizeof(ipSource);
	checkSumLength += sizeof(ipSource);

	memcpy(ch,&ipDest,sizeof(ipDest));
	ch += sizeof(ipDest);
	checkSumLength += sizeof(ipDest);

	*ch = 0; ch++; //Reserved place holder
	checkSumLength += 1;

	memcpy(ch,&protocol,sizeof(protocol));
	ch += sizeof(protocol);
	checkSumLength += sizeof(protocol);

	memcpy(ch,&tcpLength,sizeof(tcpLength));
	checkSumLength += sizeof(tcpLength);
	ch += sizeof(tcpLength);

	char* tcpheader = (char *)&tcpSegment;
	memcpy(ch,tcpheader,20);
	checkSumLength += 20;

	return csum((uint8_t *)packet,checkSumLength);
}


/**
 * createPacket
 *
 * Fills the TCP packet data
 */
void TCPUtilities::createPacket(string scanType, const char* destIP,const char* portNumber,char* packetData,char* srcIP) {
	struct tcphdr *tcp = (struct tcphdr *)packetData;
	memset(tcp,0,sizeof(struct tcphdr));
	int min = 30000, max = 60000;
	srand (time(0));
	int sourcePort = min + rand() % ( max - min + 1 );
	createTCPHeader(tcp,sourcePort,portNumber, scanType);
	tcp->check = htons(calculateCheckSum(inet_addr(srcIP),inet_addr(destIP),IPPROTO_TCP,htons(sizeof(struct tcphdr)),*tcp));
}

/**
 * createTCPHeader
 *
 * Fills all the TCP required header elements and the flags based on the type of scan
 */
void TCPUtilities::createTCPHeader(struct tcphdr* tcpHeader , int sourcePort,const char* destPort, string scanType){

	tcpHeader->source = htons(sourcePort);
	tcpHeader->dest = htons(atoi(destPort));
	tcpHeader->syn = 0;
	tcpHeader->seq = 0;
	tcpHeader->ack = 0;
	tcpHeader->window = htons(1024);
	tcpHeader->check = 0; // Done by kernel
	tcpHeader->rst = 0;
	tcpHeader->urg_ptr = 0;
	tcpHeader->doff = 5;
	if(scanType == "SYN"){
		tcpHeader->syn = 1;
		tcpHeader->seq = htonl(1);
	}
	else if(scanType == "XMAS"){
		tcpHeader->psh = 1;
		tcpHeader->urg = 1;
	}
	else if(scanType == "FIN")
		tcpHeader->fin = 1;
	else if(scanType == "ACK")
		tcpHeader->ack = 1;
}

/**
 * sendTCPPacket
 *
 * sends the TCP packet to the destination host and fills the scan(job) details
 */
void TCPUtilities::sendTCPPacket(Job *job,char* srcIP){
	const char* ip = job->IP.c_str();
	const char* portNumber = job->port.c_str();
	string scanType = job->scanType;
	int probeCounter = 3;
	struct sockaddr_in victim, victim_copy;
	memset(&victim, 0, sizeof(struct sockaddr_in));
	comUtil.buildDestIPStruct(&victim,ip, portNumber);
	memcpy(&victim_copy,&victim,sizeof(victim));
	char packData[PACKET_LENGTH];
	createPacket(scanType,ip,portNumber,packData,srcIP);
	int sockDesc = comUtil.createRawSocket(IPPROTO_TCP);
	if(sockDesc < 0) {
		return;
	}
	int sockDescProt = comUtil.createRawSocket(IPPROTO_TCP);
	int sockDescICMP = comUtil.createRawSocket(IPPROTO_ICMP);
	int status = -1;
	while(status < 0){
		if(probeCounter > 0) {
			if(sendto(sockDesc,packData,sizeof(struct tcphdr),0,(sockaddr *)&victim,sizeof(struct sockaddr_in)) >  0)
				status  = comUtil.sniffAPacket(ip,portNumber,scanType,IPPROTO_TCP, job,sockDescProt,sockDescICMP);
			probeCounter--;
		}
		else {
			if(scanType == "SYN" || scanType == "ACK")
				job->scanResult = "Filtered";
			 if(scanType == "FIN" || scanType == "NULL" || scanType == "XMAS")
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
	if(status == 0) {
		pthread_mutex_lock(&createPacketLock);
		job->serviceVersion = comUtil.getServiceInfo(victim_copy, portNumber);
		pthread_mutex_unlock(&createPacketLock);
	}

	job->jobStatus = COMPLETED;
	return;
}
