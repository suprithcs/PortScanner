#pragma once
#include<stdio.h>
#include <iostream>
#include <string>
#include <unistd.h>
#include <map>
#include <vector>
#include <algorithm> // for copy
#include <iterator>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <list>
#include <sstream>
#include<getopt.h>
#include<errno.h>
#include <fstream>

using namespace std;

class optionsManager {
	
	map<string,string> optionDict;
	static optionsManager* m_optManager;
	vector<string> scanList;
	vector<string> portList;
	vector<string> ipList;

	public : 
		
		void readOptions(int argc,char* argv[]);
		static optionsManager* Instance();
		string GetStandardUsageOptionScreen();
		map<string,string> getOptionDictionary();
		void setPeerInfo(int numOfPeers, char * ptrToPeerString);
		//vector<char> getpeerInfoList();
		list<string> getpeerInfoList();
		vector<string> split(string input,char delimiter);
		vector<string> getScanList();
		void unRollPortRange();
		void calculateIPaddresesBitwise(const char *ipWithPrefix);
		//void calculateIPaddresesBitwise(string ipWithPrefix);
		void printHostAddresses(unsigned long networkAddress, unsigned long broadcastAddress);
		void processIPFile(string fContent);
		vector<string> getIPList();
		vector<string> getPortList();
		void deleteAllList();
		void deleteSingleTon();
		string ReadIPFile(const char* filename);
};
