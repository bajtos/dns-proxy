#include <iostream>
#include <exception>
#include <sstream>
#include "UDP_listener.hpp"
#include "DNS_message.hpp"

#include "ace/INET_Addr.h"
#include "ace/SOCK_Dgram.h"

namespace {
	static const size_t max_udp_size = 512;
};

udp_exception::udp_exception(const std::string & msg) : msg(msg)
{
}

udp_exception::~udp_exception() throw()
{
}

const char * udp_exception::what() const throw()
{
	return msg.c_str();
}

/*----------*/

UDP_listener::UDP_listener(unsigned short port)
{
	if (m_udp_impl.open(ACE_INET_Addr(ACE_static_cast(u_short, port))) < 0)
	{
		std::stringstream ss;
		ss << "Can't open udp listener on port " << port << ": ";
		ss << strerror(errno);

		throw udp_exception(ss.str());
	}
}

UDP_listener::~UDP_listener()
{
	m_udp_impl.close();
}

void UDP_listener::run()
{
	char buff[max_udp_size];
	ssize_t buflen = max_udp_size;

	while (1) // TODO add some kind of condition
	{
		try {
			ACE_INET_Addr addr;
			buflen = m_udp_impl.recv (buff, max_udp_size, addr);
			if (buflen < 0)
			{
				std::stringstream ss;
				ss << "Can't receive DNS message: ";
				ss << strerror(errno);
				throw udp_exception(ss.str());
			}

			DNS::Message msg;
			msg.unmarshal(buff, buflen);
			std::cout << "Received data: " << msg << std::endl;

			DNS::Resource_record rr;
			rr.set_name(msg.m_question[0].get_qname());
			rr.set_type(1);
			rr.set_class(1);
			rr.set_ttl(10);

			std::string ip_addr;
			ip_addr += (char)192;
			ip_addr += (char)168;
			ip_addr += (char)1;
			ip_addr += (char)10;
			rr.set_rdata(ip_addr);
			msg.m_answer.push_back(rr);
			msg.set_query(false);
			msg.set_recursion_available();

			std::cout << "Going to send: " << msg << std::endl;

			std::string resp(msg.marshal());
			m_udp_impl.send(resp.data(), resp.length(), addr);
			//m_udp_impl.send (buff, buflen, addr);
		}
		catch (std::exception & e)
		{
			std::cerr << "Warning: " << e.what() << std::endl;
		}
	}
}
