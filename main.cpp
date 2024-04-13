#include <iostream>

#include "config.hpp"

int main(int argc, char *argv[])
{
	Configuration::Config conf{};
	std::cout << conf.protocol() << std::endl;
	return 0;
}
