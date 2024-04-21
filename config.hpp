#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <cstdint>

#define ARP 1
#define ICMP4 2
#define ICMP6 4
#define NDP 8
#define IGMP 16
#define MLD 32

namespace conf{

enum PROTOCOL{
	ALL,
	UDP,
	TCP
};

class Config{
private:
	PROTOCOL _protocol = ALL;
	void protocol(PROTOCOL protocol);
	std::string _intfc;
	void intfc(std::string intfc);
	int _port = -1;
	void port(uint16_t port);
	int _port_d = -1;
	void port_d(uint16_t port_d);
	int _port_s = -1;
	void port_s(uint16_t port_s);
	int _num = 1;
	void num(int num);

	/* these values are stored in flags as bit values
	bool _arp;
	bool _ucmp4;
	bool _icmp6;
	bool _igmp;
	bool _mld; */
	char _flags;
	/**
	* Use bitwise operator OR (|) to set flags, defined in config.hpp
	*/
	void set_flags(char flags);
public:
	Config(int argc, char *argv[]); // Config contructor is arg parser

	// Singleton hack
	Config(const Config&) = delete;
	Config& operator = (const Config&) = delete;

	void print();

	// GET
	PROTOCOL protocol();
	std::string intfc();
	uint16_t port();
	uint16_t port_d();
	uint16_t port_s();
	int num();

	bool arp();
	bool icmp4();
	bool icmp6();
	bool ndp();
	bool igmp();
	bool mld();
	void print_flags();
};

} // namespace Configuration

#endif
