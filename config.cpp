/**
* config.cpp - ZETASniffer - simple packet sniffer
* Author: Ondřej Hruboš (xhrubo01)
* Date: 22.4.2024
*/

#include "config.hpp"
#include "args.hxx" // external library https://github.com/Taywee/args

#include <iostream>
#include <bitset>
#include <pcap/pcap.h>

using namespace conf;

Config::Config(int argc, char *argv[]){
	char cli_flags = 0;

	/**
	* Parse arguments using the args library
	*/
	args::ArgumentParser parser("ZETA Sniffer - a simple packet sniffer", "");
    args::HelpFlag help(parser, "help", "Display this help menu", {'h', "help"});
	args::Group ports(parser, "Only one of these can be specified:", args::Group::Validators::DontCare);

	args::ImplicitValueFlag<std::string> f_intfc(parser, "interface", "Interface. If no interface is specified, prints all available interfaces.", {'i', "interface"}, "", "", args::Options::Required);
	args::ValueFlag<uint16_t> f_port(ports, "port", "Port (source and destination)",  {'p'});
	args::ValueFlag<uint16_t> f_port_destination(ports, "port destination", "Port destination",  {"port-destination"});
	args::ValueFlag<uint16_t> f_port_source(ports, "port source", "Port source",  {"port-source"});
	args::ValueFlag<int> f_num(parser, "num", "Number of packets to display",  {'n'});

	// TODO change the helping strings
	args::Flag f_udp(parser, "udp", "Display UDP datagrams", {'u', "udp"});
	args::Flag f_tcp(parser, "tcp", "Display TCP segments", {'t', "tcp"});
	args::Flag f_arp(parser, "arp", "ARP flag", {"arp"});
	args::Flag f_icmp4(parser, "icmp4", "ICMP4 flag", {"icmp4"});
	args::Flag f_icmp6(parser, "icmp6", "ICMP6 flag", {"icmp6"});
	args::Flag f_ndp(parser, "icmp6", "NDP flag", {"ndp"});
	args::Flag f_igmp(parser, "igmp", "IGMP flag", {"igmp"});
	args::Flag f_mld(parser, "mld", "MLD flag", {"mld"});
	try{
		parser.ParseCLI(argc, argv);
	}catch(const args::Help&){
		std::cout << parser;
		exit(EXIT_SUCCESS);
	}catch(const args::ParseError& e){
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		exit(EXIT_FAILURE);
	}catch(const args::ValidationError& e){
		std::cerr << e.what() << std::endl;
		std::cerr << parser;
		exit(EXIT_FAILURE);
	}

	// not allowed combinations
	if(f_port && (f_port_destination || f_port_source)){
		std::cerr << parser;
		exit(EXIT_FAILURE);
	}
	if((f_port || f_port_destination || f_port_source) && (!f_tcp && !f_udp)){
		std::cerr << parser;
		exit(EXIT_FAILURE);
	}

	if(f_intfc){
		this->intfc(args::get(f_intfc));
		if(args::get(f_intfc) == ""){
			/**
			* List all available interfaces 
			*/
			pcap_if_t *alldevsp , *device;
			char errbuf[PCAP_ERRBUF_SIZE];
			if(pcap_findalldevs(&alldevsp, errbuf)){
				printf("Error: %s" , errbuf);
				exit(EXIT_FAILURE);
			}
			device = alldevsp;
			while(device != NULL){
				std::cout << device->name << std::endl;
				device = device->next; 
			}
			exit(EXIT_SUCCESS);
		}
	}
	if(f_port){
		this->port(args::get(f_port));
	}
	if(f_port_destination){
		this->port_d(args::get(f_port_destination));
	}
	if(f_port_source){
		this->port_s(args::get(f_port_source));
	}
	if(f_num){
		this->num(args::get(f_num));
	}else{
		this->num(1);
	}

	if(f_intfc){this->intfc(args::get(f_intfc));}

	if(f_udp){this->protocol(UDP);}
	if(f_tcp){this->protocol(TCP);}
	if(f_udp && f_tcp){this->protocol(ALL);}
	if(f_arp){cli_flags = cli_flags | ARP;}
	if(f_icmp4){cli_flags = cli_flags | ICMP4;}
	if(f_icmp6){cli_flags = cli_flags | ICMP6;}
	if(f_ndp){cli_flags = cli_flags | NDP;}
	if(f_igmp){cli_flags = cli_flags | IGMP;}
	if(f_mld){cli_flags = cli_flags | MLD;}
	
	this->set_flags(cli_flags);
}

void Config::print(){
	std::string prt;
	if(this->protocol() == ALL){
		prt = "ALL";
	}else if(this->protocol() == UDP){
		prt = "UDP";
	}else if(this->protocol() == TCP){
		prt = "TCP";
	}else if(this->protocol() == NONE){
		prt = "";
	}
	std::cout 
		<< "Interface:" << this->intfc() << std::endl 
		<< "Protocol: " << prt << std::endl 
		<< "Port:     " << this->port() << std::endl 
		<< "Port dst: " << this->port_d() << std::endl
		<< "Port src: " << this->port_s() << std::endl
		<< "N:        " << this->num() << std::endl;
	this->print_flags();
}

/**
* Getters and Setters
*/
PROTOCOL Config::protocol(){
	return this->_protocol;	
}

void Config::protocol(PROTOCOL protocol){
	this->_protocol = protocol;
}

std::string Config::intfc(){
	return this->_intfc;
} 

void Config::intfc(std::string intfc){
	this->_intfc = intfc;	
}

void Config::set_flags(char flags){
	this->_flags = flags;
}

void Config::port(uint16_t port){
	this->_port = port;
}
void Config::port_d(uint16_t port_d){
	this->_port_d = port_d;
}
void Config::port_s(uint16_t port_s){
	this->_port_s = port_s;
}

int Config::port(){
	return this->_port;
}
int Config::port_d(){
	return this->_port_d;
}
int Config::port_s(){
	return this->_port_s;
}

void Config::num(int num){
	this->_num = num;
}
int Config::num(){
	return this->_num;
}

bool Config::arp(){
	return ((this->_flags & ARP) == ARP);
}
bool Config::icmp4(){
	return ((this->_flags & ICMP4) == ICMP4);
}
bool Config::icmp6(){
	return ((this->_flags & ICMP6) == ICMP6);
}
bool Config::ndp(){
	return ((this->_flags & NDP) == NDP);
}
bool Config::igmp(){
	return ((this->_flags & IGMP) == IGMP);
}
bool Config::mld(){
	return ((this->_flags & MLD) == MLD);
}
void Config::print_flags(){
	std::bitset<8> f(this->_flags);
	std::cout << "__MIN64A" << std::endl;
	std::cout << f << std::endl;
}
