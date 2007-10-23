all: dns-proxy-d

CPPFLAGS= -pthread -g -Wall

CPPFLAGS += `pkg-config --cflags ACE`
LDFLAGS += `pkg-config --libs ACE`

OBJECTS = \
	DNS_message.o \
	UDP_listener.o \
	main.o 

dns-proxy-d: $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o dns-proxy-d


clean:
	@rm -rf dns-proxy-d $(OBJECTS)
