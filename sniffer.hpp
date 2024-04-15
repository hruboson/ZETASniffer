#ifndef SNIFFER_H
#define SNIFFER_H

#include <cstring>
#include <iostream>
#include <string>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

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

		// Skip the datalink layer header and get the IP header fields.
		packetptr += Sniffer::link_layer_type_len;
		iphdr = (struct ip*)packetptr;
		strcpy(srcip, inet_ntoa(iphdr->ip_src));
		strcpy(dstip, inet_ntoa(iphdr->ip_dst));
		sprintf(
			iphdrInfo, 
			"ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d", 
			ntohs(iphdr->ip_id), 
			iphdr->ip_tos, 
			iphdr->ip_ttl,
			4*iphdr->ip_hl, 
			ntohs(iphdr->ip_len)
		);
	 
		// Advance to the transport layer header then parse and display
		// the fields based on the type of hearder: tcp, udp or icmp.
		packetptr += 4*iphdr->ip_hl;
		switch (iphdr->ip_p){
		case IPPROTO_TCP:
			tcphdr = (struct tcphdr*)packetptr;
			printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
				   dstip, ntohs(tcphdr->th_dport));
			printf("%s\n", iphdrInfo);
			printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
				   (tcphdr->th_flags & TH_URG ? 'U' : '*'),
				   (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
				   (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
				   (tcphdr->th_flags & TH_RST ? 'R' : '*'),
				   (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
				   (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
				   ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
				   ntohs(tcphdr->th_win), 4*tcphdr->th_off);
			printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
			break;
	 
		case IPPROTO_UDP:
			udphdr = (struct udphdr*)packetptr;
			printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
				   dstip, ntohs(udphdr->uh_dport));
			printf("%s\n", iphdrInfo);
			printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
			break;
	 
		case IPPROTO_ICMP:
			icmphdr = (struct icmp*)packetptr;
			printf("ICMP %s -> %s\n", srcip, dstip);
			printf("%s\n", iphdrInfo);
			printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
				   ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
			printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
			break;
		}
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
