#include<stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <linux/icmp.h>
#include <netinet/udp.h>
#include<iostream>
#include<string.h>
#include<vector>
#include<math.h>
#include <pthread.h>
#include "optionsManager.h"
#include "TCPUtilities.h"
#include "UDPUtilities.h"
#include "Job.h"
#include <iomanip>
#include <netdb.h>

#define PACKET_LENGTH 2048
using namespace std;


vector<Job *> jobQueue;
map<string,bool> activeJobs;
typedef map<string, vector<Job*>> innerMap;
map<string,innerMap> reportMap;

pthread_mutex_t perJob = PTHREAD_MUTEX_INITIALIZER,perActiveJob =PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t jobindex = PTHREAD_MUTEX_INITIALIZER;
int maxJobSize=0; int jobsTaken = 0; size_t maxJobId = 0;

/*
 * getService
 * Gets the service name from the service database
 */
string getService(const char  *protocol,const char *portNumber){

	string serviceName = "NA";
	struct servent* serviceInfo;
	serviceInfo = getservbyport(htons(atoi(portNumber)), protocol );
	if(serviceInfo != NULL)
		serviceName =  string(serviceInfo->s_name);
	return serviceName;
}

/*
 * getCurrentSystemIP
 *
 * Gets the system's IP address assigned to either eth0 or wlan
 */
	
void getCurrentSystemIP(char* ip){

	struct ifaddrs *ipAddrStruct = NULL;
	struct ifaddrs *ipPtr = NULL;
	getifaddrs(&ipAddrStruct);

	struct in_addr *ipv4Sockaddr;
	for(ipPtr = ipAddrStruct; ipPtr != NULL; ipPtr = ipPtr->ifa_next) {

		if(ipPtr->ifa_addr->sa_family ==  AF_INET) {

			if(strcmp(ipPtr->ifa_name,"eth0") == 0 ) {
				ipv4Sockaddr = &((struct sockaddr_in *)ipPtr->ifa_addr)->sin_addr;
				inet_ntop(AF_INET,ipv4Sockaddr,ip,INET_ADDRSTRLEN);
				printf("Current SYSTEM IP : %s",ip);
				break;
			}
			else if(strcmp(ipPtr->ifa_name,"wlan0") == 0 ){
				ipv4Sockaddr = &((struct sockaddr_in *)ipPtr->ifa_addr)->sin_addr;
				inet_ntop(AF_INET,ipv4Sockaddr,ip,INET_ADDRSTRLEN);
				break;
			}
		}
	}

	free(ipAddrStruct);
}
/*
 * checkIfActiveJobWithSameIPandPort
 *
 * Checks whether a job is active for a given port and IP
 */

bool checkIfActiveJobWithSameIPandPort(Job* job){

	if(!activeJobs.empty() && job != NULL) {
		if(activeJobs.find(job->IP+job->port) != activeJobs.end()) {
			return false;
		}
	}
	return true;
}

/*
 *conclude
 *
 *Concludes the state of the port, given a set of scan results
 */
string conclude(int inputArray[5]){
	int big =0, iOfBig;
	string conclusion;
	for(int i = 0; i< 4;i++){
	if(inputArray[i] > big){
			big = inputArray[i];
			iOfBig = i;
		}
	}
	switch(iOfBig){
		cout << "inside switch";
		case 0: conclusion = "Filtered"; break;
		case 1: conclusion = "Open|Filtered"; break;
		case 2: conclusion = "Unfiltered"; break;
		case 3: conclusion = "Closed"; break;
		case 4: conclusion = "Open"; break;
	}
	return conclusion;
}
/*
 * printJobStats
 *
 * Prints the scan report to the console
 */
void printJobStats(){
	map<string, innerMap>::iterator reportMapItr;
	map<string,vector<Job*>>::iterator innerMapItr;
	vector<Job *> jobList, openList, closedList;
	vector<Job *>::iterator jobListIter, try1,openListIter, closedListIter;
	reportMapItr = reportMap.begin();
	innerMap tempIm; string tempScanList;
	int openfiltered =0, unfiltered=0,filtered=0, open=0, closed=0;
	int portConclusion[5]; string protocolType, serviceName;
	memset(&portConclusion, 0, sizeof(portConclusion));
	vector<string> tempScanResult;
	cout << "-----------------------------------------------------------------Port Scan Stats---------------------------------------------------------------" << endl;
	while(reportMapItr != reportMap.end()){
		cout << "" << endl;
		cout << "IP Address: " << reportMapItr->first << endl;
		tempIm = reportMapItr->second;
		innerMapItr = tempIm.begin();
		openList.clear(); closedList.clear();
		while(innerMapItr != tempIm.end()){
			tempScanList.clear();
			jobList = innerMapItr->second;
			try1 = jobListIter = jobList.begin();
			string Conclusion = "Unknown";
			while(jobListIter !=  jobList.end()){
				tempScanList.append((*jobListIter)->scanType);
				tempScanList.append("(");
				tempScanList.append((*jobListIter)->scanResult);
				tempScanList.append(") ");
				if((((*jobListIter)->scanType =="SYN" && (*jobListIter)->scanResult == "Open") || (((*jobListIter)->scanType =="UDP") && (*jobListIter)->scanResult == "Open")))
					Conclusion = "Open";
				else if((*jobListIter)->scanType =="SYN" && (*jobListIter)->scanResult == "Closed")
					Conclusion = "Closed";
				else if((*jobListIter)->scanResult == "Filtered")
					portConclusion[0] = ++filtered;
				else if((*jobListIter)->scanResult == "Open|Filtered")
					portConclusion[1] = ++openfiltered;
				else if((*jobListIter)->scanResult == "Unfiltered")
					portConclusion[2] = ++unfiltered;
				else if((*jobListIter)->scanResult == "Closed")
					portConclusion[3] = ++closed;
				else if((*jobListIter)->scanResult == "Open")
					portConclusion[4] = ++open;
				jobListIter++;
			}
			(*try1)->scanResult = tempScanList;
			if(Conclusion == "Unknown")
				Conclusion = conclude(portConclusion);
			(*try1)->conclusion = Conclusion;
			if((*try1)->conclusion == "Open")
				openList.push_back(*try1);
			else
				closedList.push_back(*try1);
			memset(&portConclusion, 0, sizeof(portConclusion));
			openfiltered =0; unfiltered=0;filtered=0; open=0; closed=0;
			innerMapItr++;
		}
		cout << endl << endl;
		cout << "Open Ports: " << endl ;
		cout << left << setw(7) <<"Port" << left << setw(15) << "Service Name" << left << setw(50) << "Results" << left << setw(25) << "Version" << setw(10) << "Conclusion" << endl;
		cout << "-----------------------------------------------------------------------------------------------------------------------------------------------" << endl;
		if(openList.size() > 0){
			openListIter = openList.begin();
			while(openListIter != openList.end()){
				if((*openListIter)->scanType == "UDP")
					protocolType = "udp";
				else
					protocolType = "tcp";
				serviceName = getService(protocolType.c_str(),((*openListIter)->port).c_str());
				cout << left << setw(7) << (*openListIter)->port << left << setw(15) << serviceName << left << setw(50) << (*openListIter)->scanResult << left << setw(25) << (*openListIter)->serviceVersion << setw(10) << (*openListIter)->conclusion <<endl;
				openListIter++;
			}
		}
		cout << endl << endl;
		cout << "Closed/Filtered/Unfiltered Ports: " << endl ;
		cout << left << setw(7) <<"Port" << left << setw(15) << "Service Name" << left << setw(50) << "Results" << left << setw(25) << "Version" << setw(10) << "Conclusion" << endl;
		cout << "-----------------------------------------------------------------------------------------------------------------------------------------------" << endl;
		if(closedList.size() > 0){
			closedListIter = closedList.begin();
			while(closedListIter != closedList.end()){
				if((*closedListIter)->scanType == "UDP")
					protocolType = "udp";
				else
					protocolType = "tcp";
				serviceName = getService(protocolType.c_str(),((*closedListIter)->port).c_str());
				cout << left << setw(7) << (*closedListIter)->port << left << setw(15) << serviceName << left << setw(50) << (*closedListIter)->scanResult << left << setw(25) << (*closedListIter)->serviceVersion << setw(10) << (*closedListIter)->conclusion <<endl;
				closedListIter++;
			}
		}
		reportMapItr++;
	}
}

/*
 * reportCompletedJob
 *
 * Stores the scan statistics in a map
 */
void reportCompletedJob(Job *job){
	innerMap portMap;
	map<string,vector<Job*>>::iterator innerMapItr;
	vector<Job*> tempJobs;
	auto ipvalue = reportMap.find(job->IP);
	if(ipvalue != reportMap.end()) {
		portMap = ipvalue->second;
		auto portvalue = portMap.find(job->port);
		if(portvalue != portMap.end()){
			tempJobs = portvalue->second;
			tempJobs.push_back(job);
			portMap.erase(portvalue);
			portMap.insert(pair<string, vector<Job*>>{job->port,tempJobs});
		}
		else{
			tempJobs.push_back(job);
			portMap.insert(pair<string, vector<Job*>>{job->port,tempJobs});
		}
		reportMap.erase(ipvalue);
		reportMap.insert(pair<string, innerMap>{job->IP,portMap});
	}
	else
	{
		tempJobs.push_back(job);
		portMap.insert(pair<string, vector<Job*>>{job->port,tempJobs});
		reportMap.insert(pair<string, innerMap>{job->IP,portMap});
	}

}
/*
 * sendPacket
 *
 * Maintains a job queue and intiates either UDP or TCP scan
 */

void *sendPacket(void *message){

TCPUtilities tcpUtil;
UDPUtilities udpUtil;
Job *job;
int returnValue;
char *ip = (char *)message;

	while(true) {

	pthread_mutex_lock(&jobindex);
		if(maxJobId < jobQueue.size()) {
			job = jobQueue.at(maxJobId);
			maxJobId++;
			if(!checkIfActiveJobWithSameIPandPort(job)){
				--maxJobId;job->jobStatus = NOTNOW;
			}
			else {
				job->jobStatus = ASSIGNED;
				//activeJobs.insert(pair<string,bool>{job->IP+job->port,true});
				activeJobs.insert(make_pair(job->IP+job->port,true));
			}
		}
		else {
			pthread_mutex_unlock(&jobindex);
			break;
		}
		pthread_mutex_unlock(&jobindex);
		if(job->jobStatus != NOTNOW) {

			if(job->scanType.compare("UDP") == 0)
				udpUtil.sendUDPPacket(job);
			else
				tcpUtil.sendTCPPacket(job,ip);
			pthread_mutex_lock(&perActiveJob);
			if(job->jobStatus == COMPLETED) {
				auto value  = activeJobs.find(job->IP+job->port);
				if(value->second) {
					activeJobs.erase(value->first);
					reportCompletedJob(job);
				}
			}
			pthread_mutex_unlock(&perActiveJob);
		}

	}
	pthread_exit(0);
}

/*
 * createThreads
 *
 * Creates threads
 */
pthread_t createThreads(int threadCount){

	vector<pthread_t> threads;
	int createStatus;
	pthread_t thread;
	for(int i = 0; i < threadCount; i++) {
		createStatus = pthread_create(&threads[i],NULL,sendPacket,(void *)NULL);
		if(createStatus != 0) {
			cout << "Create thread failed" << endl; //return;
		}
	}
	return thread;

}

/*
 * destroyJobQueue
 *
 * Cleans up the job queue
 */
void destroyJobQueue(){

	for(vector<Job *>::iterator jobIter = jobQueue.begin(); jobIter != jobQueue.end(); ++jobIter)
		delete *jobIter;

}
/*createJobQueue
 *
 * Createa a job queue for all possible combinations of given scan types, ports and IPs
 *
 */

void createJobQueue() {

	vector<string> ipList = optionsManager::Instance()->getIPList();
	vector<string> scanList = optionsManager::Instance()->getScanList();
	vector<string> portList = optionsManager::Instance()->getPortList();

	for(vector<string>::iterator sc = scanList.begin(); sc != scanList.end(); ++sc) {
		for(vector<string>::iterator ipIter = ipList.begin(); ipIter != ipList.end(); ++ipIter){
			for(vector<string>::iterator portIter = portList.begin(); portIter != portList.end(); ++portIter){
				jobQueue.push_back(new Job(*ipIter,*portIter,*sc));
			}
		}
	}

	optionsManager::Instance()->deleteAllList();
}

/*
 *		Method : processCommand
 * 		opDict - option as key value pairs mentioned in command line
 *
 * 		Processes the commands from the option dictionary and takes appropriate actions
 *
*/

int processCommand(map<string,string> opDict) {

	int returnVal = 0;
	string ip;
	string targetPort;
	auto value = opDict.find("help");
	if(value != opDict.end()) {
		cout << endl;
		cout << value->second;
		return 0;
	}

	value = opDict.find("ipaddressfile");
	if(value != opDict.end()){
		string ipAddressFile = value->second;
		cout << "IP File: " << ipAddressFile << endl;
		optionsManager::Instance()->processIPFile(ipAddressFile);
	}

	value = opDict.find("prefix");
	if(value != opDict.end())
		optionsManager::Instance()->calculateIPaddresesBitwise(value->second.c_str());

	return returnVal;
}





/*	Method : main
 *	Arguments:
 *		argc : No of arguments from the command line
 *		argv : All command line arguments are stored as an array
 *		
 *	THe main function displays the help screen and sends it for further processing.
 */
int main(int argc, char *argv[]) {
	time_t start,end = 0,elapsed = 0;
	cout << "Scanning......" << endl;
	if(argc < 2)
		cout << " For Usage type :  ./portScanner -h" << endl;
	else {
			optionsManager::Instance()->readOptions(argc,argv);
			map<string,string> opDict = optionsManager::Instance()->getOptionDictionary();
			auto value = opDict.find("help");
			if(value != opDict.end()) {
				cout << endl;
				cout << value->second;
				return 0;
			}
			else {

				start = time(NULL);

				int numberOfThreads = 1;
				value = opDict.find("speedup");
				if(value != opDict.end())
					numberOfThreads = stoi(value->second);
				processCommand(opDict); createJobQueue();
				vector<pthread_t> threads;
				int createStatus;char ip[INET_ADDRSTRLEN];
				getCurrentSystemIP(ip);
				pthread_t thread;
				for(int i = 0; i < numberOfThreads; i++) {
					createStatus = pthread_create(&thread,NULL,sendPacket,(void *)ip);
					if(createStatus != 0) {
						cout << "Create thread failed" << endl; //return;
					}
					threads.push_back(thread);
				}

				for(int i = 0; i < numberOfThreads; i++){
					pthread_join(threads[i],NULL);
				}

		}
			end = time(NULL);
			elapsed = end - start;
			cout << "Scanning took: " << elapsed << " seconds"<< endl;
			printJobStats();
			destroyJobQueue();
			optionsManager::Instance()->deleteSingleTon();
	}
}
