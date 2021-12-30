#include "echo_client.h"
int DNS = 0;

int main(int argc, char *argv[]){
    char msg[BUF_SIZE];
    char *pos_dns, *pos_cert_verify;

    if(DNS){
        // load string
        FILE* fp;
        fp = fopen("dns info.txt", "rb");
        fread(msg, 1, BUF_SIZE, fp);
        fclose(fp);

        /*
         * load dns info using ***string*** msg!
         */
        if(load_dns_info(&dns_info, msg) == 0){
            printf("load dns info");
//            return 0;
        }
        /*
         * construct msg
         */
        pos_dns = strstr(msg, "-----BEGIN DNS CACHE-----");
        pos_cert_verify = strstr(msg, "-----BEGIN CERTIFICATE VERIFY-----");
        msg[pos_cert_verify-pos_dns] = '\0';
        strcat(msg, "\n");
    }
    /*
     * tcp/ip
     */
    init_openssl();


    SSL_CTX *ctx = create_context();

    if(DNS && dns_info.KeyShareEntry.group == 29){  // keyshare group : 0x001d(X25519)
        SSL_CTX_set1_groups_list(ctx, "X25519");
    } // for demo, we will add other groups later.

    set_context(ctx);

    if(argc != 3){
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    struct sockaddr_storage addr;
    size_t len = resolve_hostname(argv[1], argv[2], &addr);

    // log
    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);

    if(connect(sock, (struct sockaddr*) &addr, len) < 0){
        error_handling("connect() error!");
    }else{
        puts("connected...");
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
    SSL_set_max_early_data(ssl, (&dns_info)->DNSCacheInfo.dns_cache_id); // set dns id

    /*
     * set dns info
     */
    SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey); // set server's keyshare
    SSL_use_certificate(ssl, dns_info.cert); // set sever's cert

    if(dns_info.CertVerifyEntry.signature_algorithms == 2052)     //rsa pss rsae sha256 0x0804
        SSL_export_keying_material(ssl, (unsigned char*)msg,
                               0,
                              NULL,
                              0,
                              dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0); // cert verify

    /*
     * handshake start
     */
    configure_connection(ssl);
    char message[BUF_SIZE];
    int str_len;
    struct timespec send_ctos, receive_ctos;

    if(!DNS){
        memcpy(message, "hello\n", 6);
        SSL_write(ssl, message, strlen(message));
        clock_gettime(CLOCK_MONOTONIC, &send_ctos);
        printf("send : %s", message);
        printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
        message[str_len] = 0;
        if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
            printf("error\n");
        }
        clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
        printf("Message from server: %s", message);
        printf("%f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }

    while(1){
        fputs("Input message(Q to quit): ", stdout);
        fgets(message, BUF_SIZE, stdin);

        if(!strcmp(message, "q\n") || !strcmp(message, "Q\n")){
            break;
        }

        SSL_write(ssl, message, strlen(message));
        clock_gettime(CLOCK_MONOTONIC, &send_ctos);
        printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
        if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
        	printf("error\n");
        }

        message[str_len] = 0;
        printf("Message from server: %s", message);
    }
    SSL_free(ssl);
    pclose(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
/*
 * 알고리즘, 에러 메시지들 불러오기;
 */
void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

int load_dns_info(struct DNS_info* dp, char* msg){
    FILE *fp;
    BIO *bio_key, *bio_cert;
    char dns_cache_info[BUF_SIZE];
    char encrypted_extension[BUF_SIZE];
    char support_group[BUF_SIZE];
    char keyshare[BUF_SIZE];
    char cert_request[BUF_SIZE];
    char cert[BUF_SIZE];
    char cert_verify[BUF_SIZE];
    char* pos_dns, *pos_ee, *pos_group, *pos_key, *pos_cert, *pos_cert_verify, *pos_cert_request, *pos_end;
    char *tmp, *tmp2;
    int size_ee;
    struct tm *dns_tm;


    pos_dns = strstr(msg, "-----BEGIN DNS CACHE-----");
    pos_ee = strstr(msg,"-----BEGIN ENCRYPTED EXTENSIONS-----");
    pos_group = strstr(msg,"-----BEGIN SUPPORT GROUP-----");
    pos_key = strstr(msg, "-----BEGIN PUBLIC KEY-----");
    pos_cert = strstr(msg, "-----BEGIN CERTIFICATE-----");
    pos_cert_request = strstr(msg, "-----BEGIN CERTIFICATE REQUEST-----");
    pos_cert_verify = strstr(msg, "-----BEGIN CERTIFICATE VERIFY-----");
    pos_end = strstr(msg, "-----END CERTIFICATE VERIFY-----");

    strcpy(dns_cache_info, pos_dns);
    dns_cache_info[pos_ee-pos_dns] = '\0';

    strcpy(encrypted_extension, pos_ee);
    encrypted_extension[pos_group-pos_ee] = '\0';

    strcpy(support_group, pos_group);
    encrypted_extension[pos_key-pos_group] = '\0';

    strcpy(keyshare, pos_key);
    keyshare[pos_cert-pos_key] = '\0';

    strcpy(cert, pos_cert);
    cert[pos_cert_request-pos_cert] = '\0';

    strcpy(cert_request, pos_cert_request);
    cert_request[pos_cert_verify - pos_cert_request] = '\0';

    strcpy(cert_verify, pos_cert_verify+34);
    cert_verify[pos_end-pos_cert_verify-34] = '\0';

    // load dns cache info
    tmp = strtok(dns_cache_info, "\n");
    tmp = strtok(NULL, "\n");
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
    tmp = strtok(NULL, "\n");
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
    tmp = strtok(NULL, "\n");
    dp->DNSCacheInfo.dns_cache_id  = strtoul(tmp, NULL, 0);

    // Check timestamp Valid
    if(dp->DNSCacheInfo.validity_period_not_before < time(NULL) && dp->DNSCacheInfo.validity_period_not_after > time(NULL)){
        printf("Valid Period\n");
    }else{
        printf("Not Valid Period\n");
    }
    // load encrypted extension
    tmp = strtok(encrypted_extension, "\n");
    tmp = strtok(NULL, "\n");
    size_ee = strtoul(tmp, NULL, 0);
    dp->EncryptedExtensions.extension_type = malloc(sizeof(uint8_t)*size_ee);
    dp->EncryptedExtensions.extension_data = malloc(sizeof(uint16_t)*size_ee);
    for(int i=0;i<=size_ee;i++){
        tmp = strtok(NULL, "\n");
        dp->EncryptedExtensions.extension_type[i] = (uint8_t)strtoul(tmp, NULL, 0);
        tmp = strtok(NULL, "\n");
        dp->EncryptedExtensions.extension_data[i] = strtoul(tmp, NULL, 0);
    }

    // load keyshare entry
    tmp = strtok(support_group, "\n");
    tmp = strtok(NULL, "\n");
    dp->KeyShareEntry.group = strtoul(tmp, NULL, 0);
    bio_key = BIO_new(BIO_s_mem());
    BIO_puts(bio_key, keyshare);
    PEM_read_bio_PUBKEY(bio_key, &(dp->KeyShareEntry.skey), NULL, NULL);

    bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, cert);
    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

    tmp = strtok(cert_verify, "\n");
    dp->CertVerifyEntry.signature_algorithms = strtoul(tmp, NULL, 0);
    tmp = strtok(NULL, "");
    strcpy((char*)dp->CertVerifyEntry.cert_verify, tmp);

    return 1;
}

void construct_msg(char* msg){
    char keyshare[BUF_SIZE];
    char cert[BUF_SIZE];
    FILE *fp;

    fp = fopen("dns/keyshare/pubKey.pem", "rb");
    fread(keyshare, 1, BUF_SIZE, fp);
    fclose(fp);

    fp = fopen("dns/cert/CarolCert.pem", "rb");
    fread(cert, 1, BUF_SIZE, fp);
    fclose(fp);

    sprintf(msg, "%u", dns_info.DNSCacheInfo.dns_cache_id);
    strcat(msg, keyshare);
    strcat(msg, cert);
    strcat(msg, "\n");
}
/*
 * SSL 구조체를 생성, 통신 프로토콜 선택;
 * return SSL_CTX* SSL 구조체;
 */
SSL_CTX *create_context(){
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if(!ctx) error_handling("fail to create ssl context");
    /*
     * ssl_check_allowed_versions(ctx->min_proto_version, larg) : larg가 최고 proto로 설정;
               && ssl_set_version_bound(ctx->method->version, (int)larg,
                                        &ctx->max_proto_version);
     */
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}
/*
 * verify
 * set version
 */
void set_context(SSL_CTX *ctx){
    SSL_CTX_load_verify_locations(ctx, "./dns/cert/CarolCert.pem", "./dns/cert/");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if(DNS)
        SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL, NULL,NULL);
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
}
void keylog_callback(const SSL* ssl, const char *line){
//    printf("==============================================\n");
//    printf("%s\n", line);
}
size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr){
    struct addrinfo *res = 0;
    if(getaddrinfo(host, port, 0, &res) != 0)
        error_handling("fail to transform address");
    size_t len = res->ai_addrlen;
    memcpy(addr, res->ai_addr, len);
    freeaddrinfo(res);
    return len;
}
void configure_connection(SSL *ssl){
    SSL_set_tlsext_host_name(ssl, "ztls.net");
    SSL_set_connect_state(ssl);
    if(SSL_do_handshake(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        error_handling("fail to do handshake");
    }
}
void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                            unsigned int context,
                            const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx,
                            int *al, void *arg)
                            {

    if (context == SSL_EXT_CLIENT_HELLO) {
        *out = (unsigned char*)malloc(sizeof(char*)*4);
        memcpy((void*)*out, &(&dns_info)->DNSCacheInfo.dns_cache_id, 4);
        *outlen = 4;
    }

    return 1;
}

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg){
    OPENSSL_free((unsigned char *)out);
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
                        {
    return 1;
}

time_t is_datetime(const char *datetime){
    // datetime format is YYYYMMDDHHMMSSz
    struct tm   time_val;

    strptime(datetime, "%Y%m%d%H%M%Sz", &time_val);

    return mktime(&time_val);       // Invalid
}
