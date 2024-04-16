#ifndef SNIFFER_H
#define SNIFFER_H

#include <cstring>
#include <iostream>
#include <iomanip>
#include <netinet/ip.h>
#include <string>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <ctime>
#include <cmath>

#include "config.hpp"

class Sniffer{
private:
	conf::Config &config;
	std::string filter;
	inline static int link_layer_type_len;
	inline static pcap_t* pd;

	pcap_t* create_pcap_handle(const char* interface, const char* filter);
	void get_link_layer_type_size(pcap_t* handle);
	inline static void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr){
		struct ip* iphdr;
		struct icmp* icmphdr;
		struct tcphdr* tcphdr;
		struct udphdr* udphdr;
		char iphdrInfo[256];
		char srcip[256];
		char dstip[256];
		char srcmac[256];
		char dstmac[256];
		struct tm *timestamp_tm = localtime(&packethdr->ts.tv_sec); // convert to localtime for strftime
		char timestamp[256];
		strftime(timestamp, 256, "%Y-%m-%dT%H:%M:%S", timestamp_tm); // format time (without microseconds - will be added in std::cout)
		int gmtoff_hour = std::abs(timestamp_tm->tm_gmtoff / 3600);
	    int gmtoff_min = std::abs(timestamp_tm->tm_gmtoff % 3600) / 60;

		// Skip the datalink layer header and get the IP header fields.
		packetptr += Sniffer::link_layer_type_len;
		iphdr = (struct ip*)packetptr;
		strcpy(srcip, inet_ntoa(iphdr->ip_src));
		strcpy(dstip, inet_ntoa(iphdr->ip_dst));
		
	 
		// Advance to the transport layer header then parse and display
		// the fields based on the type of hearder: tcp, udp or icmp.
		packetptr += 4*iphdr->ip_hl;
		switch(iphdr->ip_p){
			case IPPROTO_TCP:
				tcphdr = (struct tcphdr*) packetptr;
				break;
			case IPPROTO_UDP:
				udphdr = (struct udphdr*) packetptr;
				break;
		}
		std::cout <<
			"timestamp: " 
						// this was painful :( timestamp_tm doen't have microseconds so you can't just do strftime
						<< timestamp << "." << std::setw(3) << std::setfill('0') << packethdr->ts.tv_usec / 1000 
						<< "+" << std::setw(2) << std::setfill('0') << gmtoff_hour << ":" << std::setw(2) << std::setfill('0') << gmtoff_min << std::noshowpos << std::endl <<
			//"src MAC: " << << std::endl;
			"frame length: " << ntohs(iphdr->ip_len) << std::endl <<
			"src IP: " << srcip << std::endl <<
			"dst IP: " << dstip << std::endl << std::endl;
	}
public:
	Sniffer(conf::Config &config);
	void sniff();
	static void stop_sniffing(int sig_num){
		pcap_close(Sniffer::pd);
		exit(sig_num);
	}
};


#endif
