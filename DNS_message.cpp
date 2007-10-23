#include "DNS_message.hpp"
#include <algorithm>

namespace DNS 
{

exception::exception(const std::string & msg) : msg(msg)
{
}

exception::~exception() throw()
{
}

const char * exception::what() const throw()
{
	return msg.c_str();
}

/*----------*/
static inline void append16(std::string & str, uint16_t val)
{
	unsigned char c = val >> 8;
	str.push_back(c);
	c = val & 0xFF;
	str.push_back(c);
}

/*----------*/

Message::Message(rid_t rid)
	: m_rid(rid)
{
}

size_t Message::unmarshal(const char * buff, size_t buflen)
{
	if (buflen < 12) throw exception("Message is too short");

	const unsigned char * data = reinterpret_cast<const unsigned char *>(buff);
	size_t pos = 0;

	m_rid = (data[0] << 8) + data[1]; // Network byte order
	pos += 2;

	uint8_t flags = data[pos++];

	m_query = (flags & 0x80) == 0; 
	m_opcode = (Opcode)((flags >> 3) & 0x0F); // TODO : ugly!
	m_auth_answer = flags & 0x04;
	m_truncated = flags & 0x02;
	m_recurs_desired = flags & 0x01;

	flags = data[pos++];
	m_recurs_availabe = flags & 0x80;
	m_rcode = (Rcode)(flags & 0x0F); // TODO: ugly!

	uint16_t qcount = (data[pos] << 8) + data[pos+1]; // Network byte order
	pos += 2;
	uint16_t ancount = (data[pos] << 8) + data[pos+1]; // Network byte order
	pos += 2;
	uint16_t nscount = (data[pos] << 8) + data[pos+1]; // Network byte order
	pos += 2;
	uint16_t arcount = (data[pos] << 8) + data[pos+1]; // Network byte order
	pos += 2;

	m_question.clear();
	for (int i=0; i<qcount; i++)
	{
		Question q;
		pos += q.unmarshal( buff + pos, buflen - pos);
		m_question.push_back(q);
	}

	m_answer.clear();
	for (int i=0; i<ancount; i++)
	{
		Resource_record rr;
		pos += rr.unmarshal( buff + pos, buflen - pos);
		m_answer.push_back(rr);
	}

	m_authority.clear();
	for (int i=0; i<nscount; i++)
	{
		Resource_record rr;
		pos += rr.unmarshal( buff + pos, buflen - pos);
		m_authority.push_back(rr);
	}

	m_additional.clear();
	for (int i=0; i<arcount; i++)
	{
		Resource_record rr;
		pos += rr.unmarshal( buff + pos, buflen - pos);
		m_additional.push_back(rr);
	}

	return pos;
}

template<class T> class Append_marshalled
{
	std::string & m_str;
public:
	Append_marshalled(std::string & str) : m_str(str) { }
	void operator()(const T & item) { m_str.append(item.marshal()); }
};

std::string Message::marshal() const
{
	std::string ret;

	unsigned char val;

	append16(ret, m_rid);

	val = (m_query ? 0 : 0x80) | ((m_opcode & 0x0F) << 3) | (m_auth_answer ? 0x04 : 0) | (m_truncated ? 0x02 : 0) | (m_recurs_desired ? 0x01 : 0);
	ret.push_back(val);

	val = (m_recurs_availabe ? 0x80 : 0) | (m_rcode & 0x0F);
	ret.push_back(val);

	append16(ret, m_question.size());
	append16(ret, m_answer.size());
	append16(ret, m_authority.size());
	append16(ret, m_additional.size());
	
	std::for_each(m_question.begin(), m_question.end(), Append_marshalled<Question>(ret));
	std::for_each(m_answer.begin(), m_answer.end(), Append_marshalled<Resource_record>(ret));
	std::for_each(m_authority.begin(), m_authority.end(), Append_marshalled<Resource_record>(ret));
	std::for_each(m_additional.begin(), m_additional.end(), Append_marshalled<Resource_record>(ret));

	return ret;
}

ostream & operator <<(ostream & os, const Message & msg)
{
	os 	<< "(DNS message id " 
		<< msg.get_rid()
		<< (msg.is_query() ? " REQ" : " RESP")
		<< " opcode " << msg.get_opcode()
		<< " flags:";
	if (msg.is_authoritative_answer()) os << " aa";		
	if (msg.is_truncated()) os << " tc";
	if (msg.get_recursion_desired()) os << " rd";
	if (msg.get_recursion_available()) os << " ra";
	
	os 	<< " rcode: " << msg.get_response_code()
		<< std::endl
		<< "Question: " << std::endl;

	for (Message::Question_list::const_iterator it = msg.m_question.begin(); it != msg.m_question.end(); ++it)
		os << "\t" << *it << std::endl;

	os << "Answer: " << std::endl;
	for (Message::RR_list::const_iterator it = msg.m_answer.begin(); it != msg.m_answer.end(); ++it)
		os << "\t" << *it << std::endl;

	os << "Authority: " << std::endl;
	for (Message::RR_list::const_iterator it = msg.m_authority.begin(); it != msg.m_authority.end(); ++it)
		os << "\t" << *it << std::endl;

	os << "Additional: " << std::endl;
	for (Message::RR_list::const_iterator it = msg.m_additional.begin(); it != msg.m_additional.end(); ++it)
		os << "\t" << *it << std::endl;

	os << ")";

	return os;
}

/*----------*/

size_t Question::unmarshal(const char * buff, size_t len)
{
	const unsigned char * data = reinterpret_cast<const unsigned char *>(buff);
	size_t skip = m_qname.unmarshal(buff, len);
	data += skip;
	len -= skip;

	if (len < 4) throw exception("Malformed Question section.");
	
	m_qtype = (data[0] << 8) + data[1];
	data += 2;

	m_qclass = (data[0] << 8) + data[1];
	data += 2;

	return reinterpret_cast<const char*>(data) - buff;
}

std::string Question::marshal() const
{
	std::string ret;

	ret.append(m_qname.marshal());
	append16(ret, m_qtype);
	append16(ret, m_qclass);

	return ret;
}

ostream & operator <<(ostream & os, const Question & question)
{
	os << "Question for name " << question.get_qname() << " of type " << question.get_qtype() << " in class " << question.get_qclass() << ".";
	return os;
}

/*----------*/

Name::Name()
{
}

void Name::set_dotted(const std::string & dotted)
{
	// TODO
	throw not_implemented();
}

std::string Name::get_dotted() const
{
	// TODO
	return m_data;
}

size_t Name::unmarshal(const char * buff, size_t buflen)
{
	if (buflen < 1) throw exception("Empty Name.");
	
	const unsigned char * data = reinterpret_cast<const unsigned char *>(buff);
	size_t pos = 0;

	while (data[pos] > 0 && pos < buflen)
		 pos += data[pos] + 1;
	if (pos >= buflen) throw exception("Name spans beyond the message.");
	pos += 1;

	m_data.assign(buff, pos);
	return pos;
}

std::string Name::marshal() const
{
	return m_data;
}

ostream & operator <<(ostream & os, const Name & name)
{
	os << name.get_dotted();
	return os;
}

/*----------*/

size_t Resource_record::unmarshal(const char * buff, size_t len)
{
	const unsigned char * data = reinterpret_cast<const unsigned char *>(buff);
	size_t skip = m_name.unmarshal(buff, len);
	data += skip;
	len -= skip;

	if (len < 10) throw exception("Malformed RR section.");
	
	m_type = (data[0] << 8) + data[1];
	data += 2;

	m_class = (data[0] << 8) + data[1];
	data += 2;

	m_ttl = (data[0] << 24) + (data[1] << 16) + (data[2] << 8) + data[3];
	data += 4;

	uint16_t rdlen = (data[0] << 8) + data[1];
	data += 2;
	m_rdata.assign(reinterpret_cast<const char *>(data), rdlen);
	data += rdlen;

	return reinterpret_cast<const char*>(data) - buff;
}

std::string Resource_record::marshal() const
{
	std::string ret;
	
	ret.append(m_name.marshal());
	append16(ret, m_type);
	append16(ret, m_class);
	append16(ret, m_ttl >> 16);
	append16(ret, m_ttl & 0xFFFF);
	append16(ret, m_rdata.size());
	ret.append(m_rdata);

	return ret;
}

ostream & operator <<(ostream & os, const Resource_record & rr)
{
	os << "RR for name " << rr.get_name() << " of type " << rr.get_type() << " in class " << rr.get_class() << " (ttl " << rr.get_ttl() << "): [" << rr.get_rdata() << "].";
	return os;
}

} // namespace DNS

