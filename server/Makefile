CFLAGS+= -Wall
LDFLAGS+= -lcrypto -L/usr/local/lib/ -lssl -lcurl

all:
	gcc server.c -o server $(CFLAGS) $(LDFLAGS)
