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
    struct {
        uint32_t validity_period_not_before; //gmt unix time
        uint32_t validity_period_not_after;  //gmt unix time
        uint32_t dns_cache_id;
    } DNSCacheInfo;
    struct {
        uint8_t *extension_type;
        uint16_t *extension_data;
    } encrypted_extensions;
    struct {
        uint8_t group;
        EVP_PKEY *skey; // server's keyshare
    } KeyShareEntry;
    X509* cert; // server's cert
    struct {
        uint8_t certificate_request_context;
        uint16_t extensions;
    } cert_request;
    struct {
        uint16_t signature_algorithms;
        unsigned char cert_verify[BUF_SIZE]; // signature
    } cert_verify_entry;
} dns_info;



/*
 * 모든 알고리즘, 에러 메시지 불러오기;
 */
void init_openssl();
int load_dns_info(struct DNS_info* dns_info, char* msg);
void construct_msg(char* msg);

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
static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                    unsigned int context,
                    const unsigned char **out,
                    size_t *outlen, X509 *x, size_t chainidx,
                    int *al, void *arg);

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg);

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg);

#endif //TLS13_ECHO_ECHO_CLIENT_H
