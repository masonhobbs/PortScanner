#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <cctype>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include "parser.cpp" // Contains the functions for parsing command line arguments
using namespace std;

// For pretty colored text
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define RESET	"\033[0m"

int main(int argc, char ** argv) {
	if(argc < 2) {
		cout << "Invalid number of arguments. Run ./portScan --help for usage.\n";
		return -1;
	}

	// Find all flags/options user has input and organize them
	bool help = false;
	bool port = false;
	bool ip = false;
	bool file = false;
	bool transport = false;
	bool show_closed = true; // Custom flag; if user specifies "--hide" as a flag do not show closed ports

	// Starting indexes in argv of each option, for organizing flag inputs
	int port_index = 0;
	int ip_index = 0;
	int file_index = 0;
	int transport_index = 0;

	// Loop through command line arguments
	int i;
	for(i = 1; i < argc; i++) {
		// If user chooses help, only display options for help and ignore the rest
		if(string(argv[i]) == "--help") {
			help = true;
			break;
		}
		// If user wants to specify a port, note that for later
		else if(string(argv[i]) == "--port") {
			port = true;
			port_index = i;
		}
		// If specifying an ip, note that for later
		else if(string(argv[i]) == "--ip") {
			ip = true;
			ip_index = i;
		}
		// If user is using a list of IPs from a file, note that
		else if(string(argv[i]) == "--file") {
			file = true;
			file_index = i;
		}
		// If user is specifying between TCP/UDP, note that
		else if(string(argv[i]) == "--transport") {
			transport = true;
			transport_index = i;
		}
		else if(string(argv[i]) == "--hide") {
			show_closed = false;
		}
	}

	// If user entered help flag, display all helpful information and exit the program
	if(help) {
		print_help();
		return 0;
	}


	// Given an IP
	vector<string> ip_list;
	if(ip) {
		ip_list = find_ips(ip_index, argc, argv);
	}

	// Given a file
	vector<string> file_ip_list;
	if(file) {
		file_ip_list = find_file_ips(string(argv[file_index+1]));
		for(i = 0; i < file_ip_list.size(); i++) {
			ip_list.push_back(file_ip_list[i]);
		}
	}


	// Check that user entered an ip or file. If not, look for an ip existing as an argument
	if(!ip && !file) {
		struct sockaddr_in tester;
		bool ip_as_arg = false;
		int result;
		for(i = 1; i < argc; i++) {
			result = inet_pton(AF_INET, argv[i], &(tester.sin_addr));
			if(result == 1) {
				ip_as_arg = true;
				ip_list.push_back(string(argv[i]));
				break;
			}
		}
		if(!ip_as_arg) {
			cout << "Error: no target IP address or file containing IP addresses given\n";
			return 0;
		}
	}

	// Store list of ports to scan; if using port flag, add specific ones given, otherwise just use 1-1024
	vector<string> port_list;
	if(port) {
		port_list = find_ports(port_index, argc, argv);
	}
	else {
		for(i = 1; i <= 1024; i++)
			port_list.push_back(to_string(i));
	}


	// Find transport type specified if one is specified, otherwise use both
	string transport_type;
	if(transport) {
		transport_type = string(argv[transport_index+1]);
		if(transport_type != "tcp" && transport_type != "udp") {
			cout << "Error: invalid transport type option specified\n";
			return 0;
		}
        if(transport_type == "udp") {
                cout << "Error: udp functionality not implemented :(\n";
                return 0;
	    }
    }
	else {
		transport_type = "tcp/udp";
	}


	cout << "\n+-----------------------------------------------------------------+\n";
	cout <<"| Beginning port scan of target host(s)" << endl;
	if(port)
		cout << "| Ports: " << argv[port_index+1] << endl;
	else
		cout << "| Ports: 1-1024" << endl;

	// Begin testing all ports for all IPs
	struct sockaddr_in target_info;
	struct sockaddr_in host;
	struct servent * service_finder;
	struct timeval timeout_finder;
	fd_set fdset;
	int conn_fd;
	int conn_error;
	socklen_t len = sizeof(conn_error);
	int h, p;

	// IP loop, then loop through all ports
	for(h = 0; h < ip_list.size(); h++) {
		cout << "| \n| * " << ip_list[h] << " * " << endl;
		cout << "| \tport\tprotocol\tstatus\t\tservice name" << endl;
		cout << "| \t----\t--------\t------\t\t------------" << endl;

		for(p = 0; p < port_list.size(); p++) {
			// Reset host information to be clean
			memset(&host, '0', sizeof(host));
			host.sin_family = AF_INET;
			if(inet_pton(AF_INET, ip_list[h].c_str(), &host.sin_addr) != 1) {
				cout << "| * Error: invalid IP address " << ip_list[h] << endl;
				break;
			}
			host.sin_port = htons(stoi(port_list[p]));

			// Check for TCP and/or UDP transport flag options and use the respective ones
			// TCP or both:
			if((transport_type == "tcp" || transport_type == "tcp/udp") && transport_type != "udp") {
				if((conn_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
					cout << "| * Error: could not initialize tcp socket\n";
					return 0;
				}

				// Set up socket in non-blocking mode, lets us use custom timeout settings
				fcntl(conn_fd, F_SETFL, O_NONBLOCK);

				// Start connection
				connect(conn_fd, (struct sockaddr *)&host, sizeof(host));

				// Timeout finder so program doesn't take 10 million years
				FD_ZERO(&fdset);
				FD_SET(conn_fd, &fdset);
				timeout_finder.tv_sec = 1;
				timeout_finder.tv_usec = 0;

				// Attempt to determine state of socket, run the timeout as well
				if(select(conn_fd+1, NULL, &fdset, NULL, &timeout_finder) == 1) {
					getsockopt(conn_fd, SOL_SOCKET, SO_ERROR, &conn_error, &len);
					// Socket is open
					if(conn_error == 0) {
						service_finder = getservbyport(host.sin_port, "tcp");
						cout << "| \t" << port_list[p] << GREEN << "\ttcp\t\topen\t\t" << service_finder->s_name << RESET << endl;
					}
					// Socket is closed
					else if(show_closed) {
						cout << "| \t" << port_list[p] << RED << "\ttcp\t\tclosed\t\tunknown" << RESET << endl;
					}
				}
				// If select() itself fails, socket is closed
				else if(show_closed){
					cout << "| \t" << port_list[p] << RED << "\ttcp\t\tclosed\t\tunknown" << RESET << endl;
				}
				close(conn_fd);
			}

		}
		if((transport_type == "tcp" || transport_type == "tcp/udp") && transport_type != "udp")
			close(conn_fd);


		cout << "| \n| <><><><><><><><><><>" << endl;
	}
	// Done searching all hosts
    cout << "Note: UDP functionality not implemented, so no UDP scans were performed.\n";
	cout << "+-----------------------------------------------------------------+\n";
	cout << endl;
	return 0;
}
