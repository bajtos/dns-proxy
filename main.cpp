#include <iostream>
#include "UDP_listener.hpp"

int main (int args, char ** argv)
{
	UDP_listener udpd(1234);

	udpd.run();

	return 0;
}
