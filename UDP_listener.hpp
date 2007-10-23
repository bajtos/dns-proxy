#ifndef _DNS_PROXY__UDP_LISTENER_HPP_
#define _DNS_PROXY__UDP_LISTENER_HPP_

#include "ace/SOCK_Dgram.h"

class UDP_listener
{
public:
	UDP_listener(unsigned short port = 53);
	~UDP_listener();

	void run();
private:
	ACE_SOCK_Dgram m_udp_impl;
};

#include <exception>
#include <string>
class udp_exception : public std::exception
{
public:
	udp_exception(const std::string & msg);
	virtual const char * what() const throw();
	virtual ~udp_exception() throw();
private:
	std::string msg;
};

#endif /* _DNS_PROXY__UDP_LISTENER_HPP_ */
