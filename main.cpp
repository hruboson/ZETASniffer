#include "config.hpp"
#include "sniffer.hpp"

int main(int argc, char *argv[])
{
	conf::Config conf{argc, argv};
	conf.print();	
	Sniffer sniffer{conf};
	sniffer.sniff();
	return 0;
}
