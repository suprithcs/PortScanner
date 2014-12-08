
#include "optionsManager.h"

using namespace std;

optionsManager* optionsManager::m_optManager = NULL;


/*
 *
 * a function to create and maintain the singleton object
 * of option manager
 */
optionsManager* optionsManager::Instance()
{
   if (!m_optManager)   // Only allow one instance of class to be generated.
	   m_optManager = new optionsManager();
   return m_optManager;
}


/*
 * readOptions()
 * argc - No of arguments from the command line
 * argv - All command line arguments are stored as an array
 *
 * Reads the options of the command line and stores it in a dictionary
*/
void optionsManager::readOptions(int argc,char** argv) {

	int getOptChar = 0;
	int digit_optind = 0;

	int option_index = 0;
	const char *shortOptions = "hp:i:r:f:s:u:";
	struct option longOptions[] =
	{
		{"help",          no_argument,       NULL, 'h'},
		{"ports",          required_argument, NULL, 'p'},
		{"ip",          required_argument, NULL, 'i'},
		{"prefix",          required_argument, NULL, 'x'},
		{"file",          required_argument, NULL, 'f'},
		{"scan",          required_argument, NULL, 's'},
		{"speedup",          required_argument, NULL, 'u'},
	      
	      {NULL,            0,                 NULL, 0  }
	};
	while((getOptChar = getopt_long(argc, argv, shortOptions, longOptions, &option_index)) != -1){
		int this_option_optind = optind ? optind : 1;

	    switch (getOptChar) {
		
			case 'h': //help
			optionDict.insert(pair<string,string>{"help", GetStandardUsageOptionScreen()});
			  break;
			case 'p': //save the ports to
				optionDict.insert(pair<string,string>{"ports",optarg});
				portList = split(optarg,',');
			break;
			case 'i'://ip
				optionDict.insert(pair<string,string>{"ip",optarg});
				ipList.push_back(string(optarg));
			  break;
			case 'x'://prefix
				optionDict.insert(pair<string,string>{"prefix",optarg});
			  break;
			case 'f':
			  optionDict.insert(pair<string,string>{"ipaddressfile",optarg});
			  break;
			case 's':
			  optionDict.insert(pair<string,string>{"scan",optarg});
			  if(strcmp(optarg,"SYN") == 0 || strcmp(optarg,"NULL") == 0
			  	        			|| strcmp(optarg,"ACK") == 0 || strcmp(optarg,"UDP" ) == 0
			  						|| strcmp(optarg,"XMAS" ) == 0 || strcmp(optarg,"FIN" ) == 0) {
				  scanList.push_back(optarg);
			  }
			  else {
				  cout << "INVALID SCAN " << endl;
				  exit(0);
			  }
			  break;
			case 'u':
			  optionDict.insert(pair<string,string>{"speedup",optarg});
				break;
			default:
			fprintf(stderr,"ERROR: Unknown option '-%c'\n",getOptChar);
			exit(1);
		}
	}
	if(portList.size() == 0){
		portList = split("1-1024",',');	// default port value
	}
	if (optind < argc) {
	        while (optind < argc) {
	        	if(strcmp(argv[optind],"SYN") == 0 || strcmp(argv[optind],"NULL") == 0
	        			|| strcmp(argv[optind],"ACK") == 0 || strcmp(argv[optind],"UDP" ) == 0
						|| strcmp(argv[optind],"XMAS" ) == 0 || strcmp(argv[optind],"FIN" ) == 0)
	        			scanList.push_back(argv[optind++]);
	        	else
	        		optind++;
	        }
	}
	unRollPortRange();
}

/**
 * split
 *
 * Splits the input by the delimiter given and returns a vector
 */
vector<string> optionsManager::split(string input,char delimiter){

	stringstream ss;
	vector<string> outputList;
	string temp; int startIndex = 0,endIndex=0;
	while(endIndex > -1) {
		if((endIndex = input.find(delimiter,startIndex)) != string::npos ){
			temp = input.substr(startIndex,endIndex -  startIndex);
			ss << temp;
			ss.clear();
			ss >> temp;
			if(!temp.empty())
				outputList.push_back(temp);
			startIndex = endIndex+1;
		}
		else
			outputList.push_back(input.substr(startIndex));
	}
	return outputList;
}

/**
 * unRollPortRange
 *
 * fills in the port range. Example 1-5 --> 1,2,3,4,5
 */
void optionsManager::unRollPortRange(){

	int index = -1; int i = 0;
	int rangeLeft; int rangeRight;
	vector<string> tempList;
	vector<string>::iterator portIter = portList.begin();
	while(portIter != portList.end()) {
		if( (index = portIter->find('-')) != string::npos) {
			rangeLeft  = stoi(portIter->substr(0,index));
			rangeRight = stoi(portIter->substr(index+1,portIter->length()-index+1));
			while(rangeLeft <= rangeRight) tempList.push_back(to_string(rangeLeft++));
			portIter = portList.erase(portIter);
		}
		else {
			portIter++;
		}
	}
	portList.insert(portList.end(),tempList.begin(),tempList.end());
}

/*
 * GetStandardUsageOptionScreen()
 *
 * Returns the HELP option screen
*/
string optionsManager::GetStandardUsageOptionScreen() {

return	"./portScanner [option1, ..., optionN] \n \
	--help. Example: “./portScanner --help”.\n \
	--ports <ports to scan>. Example: “./portScanner --ports 1,2,3-5”.\n \
	--ip <IP address to scan>. Example: “./portScanner --ip 127.0.0.1”.\n \
	--prefix <IP prefix to scan>. Example: “./portScanner --prefix 127.143.151.123/24”.\n \
	--file <file name containing IP addresses to scan>. Example: “./portScanner --file filename.txt”.\n \
	--speedup <parallel threads to use>. Example: “./portScanner --speedup 10”. \n \
	--scan <one or more scans>. Example: “./portScanner --scan SYN NULL FIN XMAS”.\n";

}


/*
 * Method : getOptionDictionary
 *
 * Returns the option dictionary
*/
map<string,string> optionsManager::getOptionDictionary() {
	return optionDict;
}

vector<string> optionsManager::getScanList() {
	return scanList;
}

/*
 *		Method : printHostAddresses
 * 		networkAddress : networkAddress
 *		broadcastAddress: broadcastAddress
 * 		Prints the list of IPs for a given network and broadcast address.
 *
*/
void optionsManager::printHostAddresses(unsigned long networkAddress, unsigned long broadcastAddress) {
	unsigned long diff = broadcastAddress-networkAddress;
	struct in_addr address;
	for(int i =1; i<diff; i++){
		address.s_addr = htonl(networkAddress+i);
		ipList.push_back(string(inet_ntoa(address)));
	}
}


/*
 *		Method : calculateIPaddresesBitwise
 * 		ipWithPrefix : String with IP and prefix
 * 		Processes the list of IPs for a given subnet mask and IP.
 *
*/

void  optionsManager::calculateIPaddresesBitwise(const char* ipWithPrefix) {
	struct in_addr ipaddress;
	struct in_addr ipMask;
	char *inputIP;
	int prefix;
	unsigned long 	networkID, hostBits, broadcastID;
	char *pch = strtok(( char*)ipWithPrefix,"/");
	inputIP = pch;
	pch = strtok(NULL, "/");
	sscanf(pch,"%d",&prefix);
	inet_aton(inputIP,&ipaddress);
	unsigned long subnetMask = 0;
	for (int i=0;i<prefix;i++)
		subnetMask |= 1<<(31-i);
	ipMask.s_addr = htonl(subnetMask);
	networkID = ntohl(ipaddress.s_addr) & ntohl(ipMask.s_addr);
	ipaddress.s_addr = htonl(networkID);
	ipList.push_back(inet_ntoa(ipaddress));
	hostBits = ~ntohl(ipMask.s_addr);
	broadcastID = networkID | hostBits;
	ipaddress.s_addr = htonl(broadcastID);
	ipList.push_back(inet_ntoa(ipaddress));
	printHostAddresses(networkID, broadcastID);
}

/*
 *		Method : processIPFile
 * 		fContent : IP File content with newlines as the delimiter
 * 		Processes the IPs listed in a file.
 *
*/
void optionsManager::processIPFile(string fileName){

	string fContent = ReadIPFile(fileName.c_str());
	if(!fContent.empty()) {
		istringstream iss(fContent);
	//	cout << "****************************************" << endl;
		//cout << "Printing IPs from the given file" << endl;
		string s;
		int i=0;
		while ( getline(iss, s) ) {
			i++;
			ipList.push_back(s);
			//cout << s.c_str() << endl;
		}
	}
}

vector<string> optionsManager::getIPList(){
	return ipList;
}
vector<string> optionsManager::getPortList(){
	return portList;
}

void optionsManager::deleteAllList() {
	vector<string>().swap(ipList);
	vector<string>().swap(portList);
	vector<string>().swap(scanList);
	map<string,string>().swap(optionDict);
}

void optionsManager::deleteSingleTon(){
	delete m_optManager;
}


/*
 * ReadIPFile()
 * filename - torrent file name to be read
 *
 * Returns the complete content of the torrent file
 */
string optionsManager::ReadIPFile(const char* filename) {

	fstream readFile;
	stringstream ss;
	string content;
	readFile.open(filename,ios::in);
	if(!(readFile.is_open())) {
		cerr << "File could not be opened!\n";
		cerr << "Error code: " << strerror(errno);
		content = "";
	}
	else {
		ss << readFile.rdbuf();
		content = ss.str();
		if(readFile.is_open())
			readFile.close();
	}
	return content;
}
