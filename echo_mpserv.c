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

#include <openssl/rsa.h>
#include <openssl/crypto.h>
//#include <openssl/X509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define  HOME "./"
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"

#define CHK_NULL(x) if((x) == NULL) exit(1)
#define CHK_ERR(err,s) if((err) == -1){perror(s);exit(1);}
#define CHK_SSL(err) if((err) == -1){ ERR_print_errors_fp(stderr);exit(2);}

#define BUF_SIZE 100
void error_handling(char *message);
void read_childproc(int sig);   // signal이 발생했을 때 실행

int main(int argc, char *argv[]){
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    const SSL_METHOD *method;

    SSL_CTX *ctx;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX_set_ecdh_auto(ctx, 1);
    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert/CarolCert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "cert/CarolPriv.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    pid_t pid;
    // sigaction이란 signal 체이 발생할 때 act할 함수가 들어있는 구조체
    struct sigaction act;
    socklen_t adr_sz;
    int str_len, state;
    char buf[BUF_SIZE];
    if(argc != 2){
        printf("Usage : %s <port>\n", argv[0]);
    }

    act.sa_handler = read_childproc;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    state = sigaction(SIGCHLD, &act, 0);

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    // server 소켓과 주소정보를 바인
    if(bind(serv_sock, (struct sockaddr*) &serv_adr, sizeof(serv_adr)) == -1){
        error_handling("bind() error");
    }
    // 여기서 5는 대기할 수 있는 클라이언트 요청 수였나..
    if(listen(serv_sock, 5) == -1){
        error_handling("listen() error");
    }

    // 여러 클라이언트와 connect 시작
    while(1){
        SSL *ssl;
        adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*) &clnt_adr, &adr_sz);
        if(clnt_sock == -1){
            printf("continue~\n");
            continue;
        }else{
            puts("new client connected ...");
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clnt_sock);

        if(SSL_accept(ssl) <= 0){
            ERR_print_errors_fp(stderr);
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
                if(!strncmp(buf, "hello\n",str_len)){
                    strcpy(buf, "worldisforyou\n");
                    SSL_write(ssl, buf, strlen(buf));
                }else{
                    SSL_write(ssl, buf, str_len);
                }
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
    return 0;
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
