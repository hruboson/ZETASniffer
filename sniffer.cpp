/**
* sniffer.cpp - ZETASniffer - simple packet sniffer
* Author: Ondřej Hruboš (xhrubo01)
* Date: 22.4.2024
*/

#include "sniffer.hpp"
#include "config.hpp"

#include <csignal>
#include <iostream>
#include <stdexcept>
#include <pcap/pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

Sniffer::Sniffer(conf::Config &config) : config{config}{	
	// filter builder
	std::stringstream tmp_filter;

	if(config.protocol() == conf::UDP){
		tmp_filter << "udp ";
		if(config.port() >= 0){
			tmp_filter << "and port " << config.port() << ' ';
		}else{
			if(config.port_s() >= 0){
				tmp_filter << "and src port " << config.port_s() << ' ';
			}
			if(config.port_d() >= 0){
				tmp_filter << "and dst port " << config.port_d() << ' ';
			}
		}
	}else if(config.protocol() == conf::TCP){
		tmp_filter << "tcp ";
		if(config.port() >= 0){
			tmp_filter << "and port " << config.port() << ' ';
		}else{
			if(config.port_s() >= 0){
				tmp_filter << "and src port " << config.port_s() << ' ';
			}
			if(config.port_d() >= 0){
				tmp_filter << "and dst port " << config.port_d() << ' ';
			}
		}	
	}

	if(config.arp()){
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "arp ";
	}
	if(config.icmp4()){
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "icmp ";
	}
	if(config.icmp6()){
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "icmp[0] = 8 or icmp[0] = 0 ";
	}
	if(config.igmp()){
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "igmp ";
	}
	if(config.ndp()){
		//TODO
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "ndp ";
	}
	if(config.mld()){
		if(tmp_filter.rdbuf()->in_avail() != 0){
			tmp_filter << "or ";
		}
		tmp_filter << "mld ";
	}
	#ifdef DEBUG
	this->filter = tmp_filter.str();
	#endif

	std::cout << this->filter << std::endl;
}

Sniffer::~Sniffer(){
	if(this->initialized){
		pcap_close(Sniffer::pd);
	}
}

void Sniffer::sniff(){
	// set signal handler (closes pd descriptor)
    signal(SIGINT, Sniffer::stop_sniffing);
    signal(SIGTERM, Sniffer::stop_sniffing);
    signal(SIGQUIT, Sniffer::stop_sniffing);
	try{
		Sniffer::pd = this->create_pcap_handle(this->config.intfc().c_str(), this->filter.c_str());
		this->get_link_layer_type_size(Sniffer::pd);
		if(pcap_loop(Sniffer::pd, this->config.num(), Sniffer::packet_handler, (u_char*)NULL) < 0){
			this->initialized = true;
			std::string err_message = "pcap_loop failed: ";
			err_message.append(pcap_geterr(Sniffer::pd));
			throw std::runtime_error(err_message);
		}
	}catch(std::runtime_error &e){
		std::cerr << e.what() << std::endl;
	}
}

pcap_t* Sniffer::create_pcap_handle(const char* interface, const char* filter){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = NULL;
	struct bpf_program bpf; // binary packet filter
	bpf_u_int32 netmask;
	bpf_u_int32 srcip;

    // get network interface source IP address and netmask
	if (pcap_lookupnet(interface, &srcip, &netmask, errbuf) == PCAP_ERROR) {
		std::string err_message = "pcap_lookupnet failed: ";
		err_message.append(errbuf);
		throw std::runtime_error(err_message);
	}

    // open interface for live capture
	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		std::string err_message = "pcap_open_live failed: ";
		err_message.append(errbuf);
		throw std::runtime_error(err_message);
	}

	// filter to packet filter binary
	if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR){
		std::string err_message = "pcap_compile failed: ";
		err_message.append(errbuf);
		throw std::runtime_error(err_message);

	} 

    // bind packet filter to handle 
	if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
		std::string err_message = "pcap_setfilter failed: ";
		err_message.append(errbuf);
		throw std::runtime_error(err_message);
	}

	pcap_freecode(&bpf);

	return handle;
}

void Sniffer::get_link_layer_type_size(pcap_t* handle){
	int link_layer_type;
	if((link_layer_type = pcap_datalink(handle)) == PCAP_ERROR){
		throw std::runtime_error("PCAP ERROR");
	}

	//TODO add more link layer types
	switch (link_layer_type){
		case DLT_NULL:
			this->link_layer_type_len = 4;
			break;
		case DLT_EN10MB:
			this->link_layer_type_len = 14;
			break;
		case DLT_SLIP:
		case DLT_PPP:
			this->link_layer_type_len = 24;
			break;
		case DLT_LINUX_SLL:
			this->link_layer_type_len = 16;
			break;
		default:
			std::cerr << "Unsupported link layer type" << std::endl;
			break;
	}
}


