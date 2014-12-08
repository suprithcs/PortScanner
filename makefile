portScanner : UDPUtilities.o TCPUtilities.o optionsManager.o Job.o CommonUtilities.o portScanner.cpp 
		g++ -g  -pthread -std=c++0x -D_REENTRANT UDPUtilities.o TCPUtilities.o optionsManager.o CommonUtilities.o portScanner.cpp Job.o -o portScanner
		
optionsManager.o : optionsManager.cpp
		g++ -g  -std=c++0x -c optionsManager.cpp -o optionsManager.o

TCPUtilities.o : TCPUtilities.cpp
		g++  -std=c++0x -c TCPUtilities.cpp  -o TCPUtilities.o

UDPUtilities.o : UDPUtilities.cpp
		g++ -std=c++0x -c UDPUtilities.cpp  -o UDPUtilities.o
		
CommonUtilities.o : CommonUtilities.cpp		
		g++ -std=c++0x -c CommonUtilities.cpp  -o CommonUtilities.o
		
Job.o : Job.cpp
	g++ -std=c++0x -c Job.cpp  -o Job.o		
		
clean :
	rm *.o portScanner

