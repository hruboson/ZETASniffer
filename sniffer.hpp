#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "config.hpp"

class Sniffer{
private:
	const conf::Config *config;
public:
	Sniffer(conf::Config *config);
	void sniff();
};

#endif
