#include "echo_client.h"

int main(int argc, char *argv[]){
    char msg[BUF_SIZE];
    FILE *fp;
    
    /*
     * dns info
     */
    dns_info.dns_cache_id  = 0;

    fp = fopen("dns/keyshare/pubKey.pem", "rb");
    PEM_read_PUBKEY(fp, &dns_info.skey, NULL, NULL);
    fclose(fp);

    fp = fopen("dns/cert/CarolCert.pem", "rb");
    PEM_read_X509(fp, &dns_info.cert, NULL, NULL);
    fclose(fp);

    fp = fopen("dns/cert_verify/sign.txt.sha256.base64", "rb");
    fread(dns_info.cert_verify, 1, BUF_SIZE, fp);
    fclose(fp);

    // read original msg
    fp = fopen("msg.txt", "r");
    fread(msg, 1, BUF_SIZE, fp);
    fclose(fp);

    /*
     * tcp/ip
     */
    init_openssl();

    SSL_CTX *ctx = create_context();

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

    if(connect(sock, (struct sockaddr*) &addr, len) < 0){
        error_handling("connect() error!");
    }else{
        puts("connected...");
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    SSL_set_wfd(ssl, 1); // fd : 1 => ZTLS, fd : 0 => TLS 1.3

    /*
     * set dns info
     */
    SSL_use_PrivateKey(ssl, dns_info.skey); // set server's keyshare
    SSL_use_certificate(ssl, dns_info.cert); // set sever's cert

    SSL_export_keying_material(ssl, (unsigned char*)msg,
                               0,
                              NULL,
                              0,
                              dns_info.cert_verify, BUF_SIZE, 0); // cert verify

    /*
     * handshake start
     */
    configure_connection(ssl);
    char message[BUF_SIZE];
    int str_len;


    while(1){
        fputs("Input message(Q to quit): ", stdout);
        fgets(message, BUF_SIZE, stdin);

        if(!strcmp(message, "q\n") || !strcmp(message, "Q\n")){
            break;
        }

        SSL_write(ssl, message, strlen(message));
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
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
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
    SSL_set_tlsext_host_name(ssl, "youngin.net");
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
