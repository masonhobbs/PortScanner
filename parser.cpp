#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <cctype>
using namespace std;


/* Utility/parsing functions */
void print_help() {
	cout << "\nportScan: a tool for scanning ports, written by Mason Hobbs\n";
	cout << "usage example: ./portScan --flag1 [options] --flag2 [options] ...\n";
	cout << "\nflags and their options:\n";
	// Help flag information
	cout << "\n\t--help\t\tprovides information about the program\n";

	// Port flag information
	cout << "\n\t--port\t\tportScan scans ports 1-1024 by default. this flag will allow for scans of specific ports\n";
	cout << "\t\t\t * examples:\n\t\t\t\t > specific port:\t  --port 2000\n";
	cout << "\t\t\t\t > comma separated ports: --port 21,80,443\n";
	cout << "\t\t\t\t > range of ports:\t  --port 2000-3000\n";

	// Hide flag information
	cout << "\n\t--hide\t\thides closed ports, useful if scanning many ports\n";

	// Ip flag information
	cout << "\n\t--ip\t\tscans the given IP address, list of IP addresses, or range of IP Addresses in a subnet\n";
	cout << "\t\t\t * examples:\n\t\t\t\t > specific IP address:\t\t --ip 127.0.0.1\n";
	cout << "\t\t\t\t > comma separated IP addresses: --ip 127.0.0.1, 127.0.0.2\n";
	cout << "\t\t\t\t > range of IP addresses:\t --ip 127.0.0.1-32\n";

	// File flag information
	cout << "\n\t--file\t\tscans all newline separated IP addresses from a given file\n";
	cout << "\t\t\t * example:\n\t\t\t\t > giving filename: --file ip_list.txt\n";

	// Port flag information
	cout << "\n\t--transport\tportScan scans both TCP and UDP ports by default.\n\t\t\tthis flag will allow for scanning of only TCP or only UDP ports\n";
	cout << "\t\t\t * examples:\n\t\t\t\t > TCP ports: --transport tcp\n";
	cout << "\t\t\t\t > UDP ports: --transport udp\n\n";
}

vector<string> find_ports(int port_index, int bound, char ** input) {
	vector<string> str_port;
	int i = port_index + 1;
	string tmp = string(input[i]);

	// Check for range of ports given first (###-###)
	if(tmp.find("-") != string::npos) {
		string delim = "-";

		// Find the numbers on both sides of the hyphen
		string start_port = tmp.substr(0, tmp.find(delim));
		string end_port = tmp.substr(start_port.length() + 1, tmp.length() - (start_port.length() + 1));

		// Verify start and end ports are numbers
	/*	if(!isdigit(stoi(start_port)) || !isdigit(stoi(end_port))) {
			cout << "Error: ports must be digits\n";
			return str_port;
		}*/

		// Store all the ports in the range to use
		int num_port_start = stoi(start_port);
		int num_port_end = stoi(end_port);

		// Basic range checking for start/end port
		if(num_port_start > num_port_end) {
			cout << "Error: start port range cannot be greater than end port range\n";
		}

		// Push all ports to scan into vector
		else {
			for(i = num_port_start; i <= num_port_end; i++) {
				if(i < 1)
					cout << "Found a port less than 1, will not add this port...\n";
				else
					str_port.push_back(to_string(i));
			}
		}
	}

	// While we do not encounter another flag, assume options after port flag are port numbers
	else {
		while(tmp.find("--") == string::npos) {
			// Use stringstream to handle comma separated port numbers if necessary
			stringstream comma_handler(tmp);
			string token;

			while(getline(comma_handler, token, ',')) {
		//		if(!isdigit(stoi(token)))
			//		cout << "Found a port that is not a number, will not add this port...\n";
				//else if(stoi(token) < 1)
		//			cout << "Found a port less than 1, will not add this port...\n";
			//	else
					str_port.push_back(token);
			}

			i++;
			// Avoid OUB errors for argv if port flag is at the end
			if(i >= bound)
				break;
			tmp = string(input[i]);

		}
	}

	return str_port;
}

vector<string> find_ips(int ip_index, int bound, char ** input) {
	vector<string> str_ip;
	int i = ip_index + 1;
	string tmp = string(input[i]);

	// Check for range of IPs given first (xxx.xxx.xxx.xx-xx)
	if(tmp.find("-") != string::npos) {
		string delim = "-";

		// Find start pos of end IP octet
		int j = 0;
		int pcount = 0;
		while(pcount != 3) {
			if(tmp[j] == '.')
				pcount++;
			j++;
		}

		// Find the numbers on both sides of the hyphen
		// Find start and isolate last octet first
		string start_ip = tmp.substr(0, tmp.find(delim));
		string isolated = "";
		int k;
		for(k = j; k < start_ip.length(); k++)
			isolated += start_ip[j];

		string end_ip = tmp.substr(start_ip.length() + 1, tmp.length() - (start_ip.length() + 1));

		// Store all the ips in the range to use
		int num_ip_start = stoi(isolated);
		int num_ip_end = stoi(end_ip);

		// Basic range checking for start/end IP
		if(num_ip_start > num_ip_end) {
			cout << "Error: start IP range cannot be greater than end IP range\n";
		}

		// Push all IPs to scan into vector
		else {
			// First find base 3 octets of IP range
			string base_range = "";
			for(k = 0; k < j; k++)
				base_range += start_ip[k];

			// Append the range values to the base 3 octets and store IP
			for(i = num_ip_start; i <= num_ip_end; i++)
				str_ip.push_back(base_range + to_string(i));
		}
	}

	// While we do not encounter another flag, assume options after ip flag are ip addresses
	else {
		while(tmp.find("--") == string::npos) {
			// Use stringstream to handle comma separated IP addresses if necessary
			stringstream comma_handler(tmp);
			string token;

			while(getline(comma_handler, token, ',')) {
				str_ip.push_back(token);
			}

			i++;
			// Avoid OUB errors for argv if IP flag is at the end
			if(i >= bound)
				break;
			tmp = string(input[i]);

		}
	}

	return str_ip;
}

vector<string> find_file_ips(string filename) {
	vector<string> file_ips;
	ifstream infile(filename);

	if(!infile) {
		cout << "Error: file does not exist\n";
		return file_ips;
	}

	string line;
	while(getline(infile, line)) {
		file_ips.push_back(line);
	}
	return file_ips;
}
