CFLAGS+= -Wall
LDFLAGS+= -shared -fpic -ldl -lcrypto

all:
	gcc server.c -o server $(CFLAGS) $(LDFLAGS)
