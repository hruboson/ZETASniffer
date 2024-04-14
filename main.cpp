#include <iostream>

#include "config.hpp"

int main(int argc, char *argv[])
{
	conf::Config conf{argc, argv};
	conf.print();	
	return 0;
}
