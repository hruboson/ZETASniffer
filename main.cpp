#include "config.hpp"
#include "sniffer.hpp"

int main(int argc, char *argv[])
{
	conf::Config conf{argc, argv};
	#ifdef DEBUG
	conf.print();
	#endif

	Sniffer sniffer{conf};
	sniffer.sniff();
	return 0;
}
