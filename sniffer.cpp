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
	// TODO set filter
	this->filter = "";
}

Sniffer::~Sniffer(){
	pcap_close(Sniffer::pd);
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
		std::string err_message = "pcap_lookup failed: ";
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
		//TODO throw
		return;
	}

	std::cout << "Link layer type: " << link_layer_type << std::endl;

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
		default:
			this->link_layer_type_len = 16;
			break;
	}
}


