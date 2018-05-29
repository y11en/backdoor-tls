CFLAGS+= -Wall
LDFLAGS+= -lcrypto -L/usr/local/lib/ -lssl

all:
	gcc server.c -o server $(CFLAGS) $(LDFLAGS)
