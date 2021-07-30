#ifndef TLS13_ECHO_EHCO_MPSERV_H
#define TLS13_ECHO_EHCO_MPSERV_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet//in.h>
#include <netdb.h>

//#include <openssl/rsa.h>
//#include <openssl/crypto.h>
//#include <openssl/pem.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/bio.h>

//#include "openssl/ssl/ssl_local.h"
//#include "openssl/e_os.h"

//#include "openssl/bio.h"
//#include "openssl/ssl.h"
//#include "openssl/err.h"

#include "/usr/local/include/openssl/bio.h"
#include "/usr/local/include/openssl/ssl.h"
#include "/usr/local/include/openssl/err.h"

//#include "../openssl/crypto.h"
//#include <openssl/X509.h>
//#include "../openssl/pem.h"
//#include "../openssl/ssl.h"
//#include "../openssl/err.h"

#define BUF_SIZE 100
/*
 * 모든 알고리즘, 에러 메시지 불러오기;
 */
void init_openssl();
/*
 * SSL 구조체인 SSL_CTX 생성 및 통신 프로토콜 선택;
 */
SSL_CTX *create_context();
/*
 * set 타원곡선, set cert, set cert private key
 */
void set_context(SSL_CTX* ctx);
/*
 * return : server socket fd;
 */
void keylog_callback(const SSL* ssl, const char *line);
int create_listen(int port);

void error_handling(char *message);
void read_childproc(int sig);   // signal이 발생했을 때 실행

#endif //TLS13_ECHO_EHCO_MPSERV_H
