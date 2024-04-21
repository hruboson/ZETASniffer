#ifndef SNIFFER_H
#define SNIFFER_H

#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <ctime>
#include <cmath>

#include "config.hpp"

class Sniffer{
private:
	conf::Config &config;
	std::string filter;
	inline static int link_layer_type_len;
	inline static pcap_t* pd;
	bool initialized = 0;

	pcap_t* create_pcap_handle(const char* interface, const char* filter);
	void get_link_layer_type_size(pcap_t* handle);
	inline static void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packet){
		struct ip* iphdr;
		struct ether_header* ehdr;
		//char iphdrInfo[256];
		char srcip[256];
		char dstip[256];
		char srcmac[256];
		char dstmac[256];
		int srcport = -1;
		int dstport = -1;

		// get MAC from ethernet frame
	    ehdr = (struct ether_header *) packet;
		const struct ether_addr *eaddr_src = (const struct ether_addr*) &ehdr->ether_shost;
		const struct ether_addr *eaddr_dst = (const struct ether_addr*) &ehdr->ether_dhost;
		sprintf(srcmac, "%02x:%02x:%02x:%02x:%02x:%02x", eaddr_src->ether_addr_octet[0],eaddr_src->ether_addr_octet[1],eaddr_src->ether_addr_octet[2],eaddr_src->ether_addr_octet[3],eaddr_src->ether_addr_octet[4],eaddr_src->ether_addr_octet[5]);
		sprintf(dstmac, "%02x:%02x:%02x:%02x:%02x:%02x", eaddr_dst->ether_addr_octet[0],eaddr_dst->ether_addr_octet[1],eaddr_dst->ether_addr_octet[2],eaddr_dst->ether_addr_octet[3],eaddr_dst->ether_addr_octet[4],eaddr_dst->ether_addr_octet[5]);

		// timestamp
		struct tm *timestamp_tm = localtime(&packethdr->ts.tv_sec); // convert to localtime for strftime
		char timestamp[256];
		strftime(timestamp, 256, "%Y-%m-%dT%H:%M:%S", timestamp_tm); // format time (without microseconds - will be added in std::cout)
		int gmtoff_hour = std::abs(timestamp_tm->tm_gmtoff / 3600);
	    int gmtoff_min = std::abs(timestamp_tm->tm_gmtoff % 3600) / 60;

		// prepare hexdump before moving packet pointer
		std::stringstream hexdump;
		for (bpf_u_int32 i = 0; i < packethdr->len; i++) {
			// print bytes order (0x0000, 0x0010, 0x0020, ...) 
			if (i % 16 == 0) {
				hexdump << "0x" << std::hex << std::setw(4) << std::setfill('0') << i << ": ";
			}

			// print raw bytes
			hexdump << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]) << " ";
			if ((i + 1) % 16 == 0) {
				// print printable characters
				for (bpf_u_int32 j = i - 15; j <= i; j++) {
					if(j % 16 == 8){
						hexdump << " ";
					}
					if (std::isprint(packet[j])) {
						hexdump << packet[j];
					} else {
						hexdump << ".";
					}
				}
				hexdump << std::endl;
			}

			// print very last row of data
			if(i == packethdr->len - 1){
				hexdump << " ";
				int e_len = (i%16) + 1;
				for(bpf_u_int32 e = 16 - e_len; e > 0; e--){
					hexdump << "   ";
				}
				hexdump.seekp(-1, std::ios_base::end);
				for(bpf_u_int32 j = i - e_len; j <= i; j++){
					if(j > packethdr->len) break;
					if(j % 16 == 7){
						hexdump << " ";
					}
					if (std::isprint(packet[j])) {
						hexdump << packet[j];
					} else {
						hexdump << ".";
					}
				}
			}
		}

		// move packet pointer to IP header fields 
		packet += Sniffer::link_layer_type_len;
		iphdr = (struct ip*)packet;
		strcpy(srcip, inet_ntoa(iphdr->ip_src));
		strcpy(dstip, inet_ntoa(iphdr->ip_dst));

		// move packet pointer to transport layer header 
		packet += 4*iphdr->ip_hl;

		// cast packet to correct structure
		struct tcphdr *tcphdr = NULL;
		struct udphdr *udphdr = NULL;
		struct icmphdr *icmphdr = NULL;
		struct icmp6hdr *icmp6hdr = NULL;
		struct arphdr *arphdr = NULL;
		struct ndphdr *ndphdr = NULL;
		struct igmphdr *igmphdr = NULL;
		struct mldhdr *mldhdr = NULL;
		if(ntohs(ehdr->ether_type) == ETHERTYPE_IP){
			switch(iphdr->ip_p) {
				case IPPROTO_TCP:
					tcphdr = (struct tcphdr*) packet;
					srcport = ntohs(tcphdr->th_sport);
					dstport = ntohs(tcphdr->th_dport);
					break;
				case IPPROTO_UDP:
					udphdr = (struct udphdr*) packet;
					srcport = ntohs(udphdr->uh_sport);
					dstport = ntohs(udphdr->uh_dport);
					break;
				case IPPROTO_ICMP:
					icmphdr = (struct icmphdr*) packet;
					break;
				case IPPROTO_ICMPV6:
					icmp6hdr = (struct icmp6hdr*) packet;
					break;
				case IPPROTO_IGMP:
					igmphdr = (struct igmphdr*) packet;
					break;
				default:
					break;
			}
		}else if(ntohs(ehdr->ether_type) == ETHERTYPE_ARP){
			arphdr = (struct arphdr*) packet;
		}

		// print everything
		std::cout <<
			"timestamp: " // this was painful :( timestamp_tm doen't have microseconds so you can't just do strftime
						<< timestamp << "." << std::setw(3) << std::setfill('0') << packethdr->ts.tv_usec / 1000 
						<< "+" << std::setw(2) << std::setfill('0') << gmtoff_hour << ":" << std::setw(2) << std::setfill('0') << gmtoff_min << std::noshowpos << 
						std::endl <<
			"src MAC: " << srcmac << std::endl << 
			"dst MAC: " << dstmac << std::endl <<
			"frame length: " << packethdr->len << " bytes" << std::endl <<
			"src IP: " << srcip << std::endl <<
			"dst IP: " << dstip << std::endl;

		if(srcport != -1 && dstport != -1){
			std::cout <<
				"src port: " << std::to_string(srcport) << std::endl <<
				"dst port: " << std::to_string(dstport) << std::endl;
		}

		std::cout << hexdump.str() << std::endl;

		std::cout << std::endl; // divider for packets
	}

public:
	Sniffer(conf::Config &config);
	~Sniffer();
	void sniff();
	static void stop_sniffing(int sig_num){
		pcap_close(Sniffer::pd);
		exit(sig_num);
	}
};


#endif
