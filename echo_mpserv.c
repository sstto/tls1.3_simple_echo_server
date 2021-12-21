#include "ehco_mpserv.h"

int main(int argc, char *argv[]){
    init_openssl();

    SSL_CTX *ctx = create_context();

    set_context(ctx);

    if(argc != 2){
        printf("Usage : %s <port>\n", argv[0]);
    }
    int serv_sock = create_listen(atoi(argv[1]));

    // 여러 클라이언트와 connect 시작
    pid_t pid;
    int clnt_sock;
    struct sockaddr_in clnt_adr;
    int str_len;
    char buf[BUF_SIZE];
    while(1){
        socklen_t adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*) &clnt_adr, &adr_sz);
        if(clnt_sock < 0){
            printf("continue~\n");
            continue;
        }else{
            puts("new client connected ...");
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);


        if(SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
            error_handling("fail to accept TLS connection");
        }

        pid = fork();
        if(pid == -1){
            close(clnt_sock);
            continue;
        }
        // 자식 프로세스
        if(pid == 0){
            close(serv_sock);
            while((str_len = SSL_read(ssl,buf, BUF_SIZE)) != 0){
                // str_len은 read한 byte 수
                printf("buf : %s", buf);
                if(!strncmp(buf, "hello\n",str_len)){
                    strcpy(buf, "worldisforyou\n");
                    SSL_write(ssl, buf, strlen(buf));
                }else{
                    SSL_write(ssl, buf, str_len);
                }
                memset(buf, 0, sizeof(char)*BUF_SIZE);
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(clnt_sock);
            puts("client disconnected...");
            return 0;
        }else{
            close(clnt_sock);
        }
    }
    close(serv_sock);
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
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
    if(!ctx) error_handling("fail to create ssl context");

    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}
/*
 * set ecdh curves automatically
 * set cert and its private key
 */
void set_context(SSL_CTX* ctx){
    if(!SSL_CTX_set_ecdh_auto(ctx, 1))
        error_handling("fail to set ECDHE curves");
    if(!SSL_CTX_use_certificate_file(ctx, "dns/cert/CarolCert.pem", SSL_FILETYPE_PEM))
        error_handling("fail to load cert");
    if(!SSL_CTX_use_PrivateKey_file(ctx, "dns/cert/CarolPriv.pem", SSL_FILETYPE_PEM))
        error_handling("fail to load cert's private key");

    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
}

void keylog_callback(const SSL* ssl, const char *line){
//    printf("==============================================\n");
//    printf("%s\n", line);
}
/*
 * create socket fd to listen
 * return : server socket
 */
int create_listen(int port){
    int serv_sock;
    struct sockaddr_in serv_adr;
    struct sigaction act;



    // sigaction : signal이 발생할 때 act할 함수가 들어있는 구조체 생성 함수;
    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    int state = sigaction(SIGCHLD, &act, 0);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(port);

    if(serv_sock < 0)
        error_handling("fail to create socket");

    int enable = 1;
    if(setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        error_handling("SO_REUSEADDR failed");
    }

    if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) < 0)// server 소켓과 주소정보를 바인딩;
        error_handling("bind() error");

    if(listen(serv_sock, 5) < 0) // 여기서 5는 대기할 수 있는 클라이언트 요청 수;
        error_handling("listen() error");

    printf("Listening on port %d\n", port);

    return serv_sock;
}

void read_childproc(int sig){
    pid_t pid;
    int status;
    // -1은 임의의 프로세스가 종료되길 기다린다, status는 여러 정보 담는 버퍼, WNOHANG은 블로킹 방지.
    pid = waitpid(-1, &status, WNOHANG);
    printf("removed process id : %d \n", pid);
}

void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
