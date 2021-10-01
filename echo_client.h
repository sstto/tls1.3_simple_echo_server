#ifndef TLS13_ECHO_ECHO_CLIENT_H
#define TLS13_ECHO_ECHO_CLIENT_H

#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet//in.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
//#include <openssl/rsa.h>
//#include <openssl/crypto.h>
//#include <openssl/pem.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>

//#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/bio.h>
//
//#include "openssl/bio.h"
//#include "openssl/ssl.h"
//#include "openssl/err.h"

//#include "../openssl/ssl/ssl_local.h"
//#include "../openssl/e_os.h"
//
#include "/usr/local/include/openssl/bio.h"
#include "/usr/local/include/openssl/ssl.h"
#include "/usr/local/include/openssl/err.h"

#define BUF_SIZE 100000

struct DNS_info{
    uint32_t dns_cache_id;
    EVP_PKEY *skey; // server's keyshare
    X509* cert;
    unsigned char cert_verify[BUF_SIZE];
} dns_info;
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
void keylog_callback(const SSL* ssl, const char *line);
size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr);
void configure_connection(SSL *ssl);
//void ShowCerts(SSL* ssl);
void error_handling(char *message);

#endif //TLS13_ECHO_ECHO_CLIENT_H
