SOURCES=async-ssl-svr.cc sync-ssl-svr.cc async-ssl-cli.cc sync-ssl-cli.cc
PROGRAMS = $(SOURCES:.cc=)

default: $(PROGRAMS)

clean:
	rm *.o $(PROGRAMS) -f

.cc:
	g++ -Wall -g $< -o $@  -lssl -lcrypto

