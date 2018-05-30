CFLAGS+= -Wall
LDFLAGS+= -lcrypto -L/usr/local/lib/ -lssl -lcurl

all:
	mkdir build
	openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes \
		-subj "/C=UK/ST=Warwickshire/L=Leamington/O=Backdooring INC/OU=IT Group/CN=backdoor.bk" -out build/cert.pem -keyout build/key.pem
	gcc server/server.c -o build/backdoor $(CFLAGS) $(LDFLAGS)

clean:
	rm -rf build
