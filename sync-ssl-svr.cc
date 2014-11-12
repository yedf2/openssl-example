//gcc -Wall  -o ssl-svr-demo ssl-svr-demo.c -lssl -lcrypto
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "openssl/bio.h"  
#include "openssl/ssl.h"  
#include "openssl/err.h"  
 
#define log(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define check0(x, ...) if(x) do { log( __VA_ARGS__); exit(1); } while(0)
#define check1(x, ...) if(!(x)) do { log( __VA_ARGS__); exit(1); } while(0)

int main(int argc, char **argv)  
{
    if (argc < 2) {
        printf("usage %s <port>\n", argv[0]);
        exit(1);
    }
    struct sockaddr_in addr;  
 
    SSL_library_init();
    SSL_load_error_strings();  
    ERR_load_BIO_strings();  
 
    SSL_CTX* ctx = SSL_CTX_new (SSLv23_method());
    check1(ctx, "SSL_CTX_new failed\n");
 
    // 要求校验对方证书  
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);  
 
    // 加载CA的证书  
    //!SSL_CTX_load_verify_locations(ctx, "cacert.cer", NULL);  
 
    // 加载自己的证书  
    int r = SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM);
    check1(r>0, "SSL_CTX_use_certificate_file failed");
 
    // 加载自己的私钥  
    r = SSL_CTX_use_PrivateKey_file(ctx, "server.pem", SSL_FILETYPE_PEM);  
    check1(r>0, "SSL_CTX_use_PrivateKey_file failed");

    // 判定私钥是否正确  
    r = SSL_CTX_check_private_key(ctx);
    check1(r, "SSL_CTX_check_private_key failed");

    log("ssl inited\n");
    // 创建并等待连接  
    int nListenFd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[1]));
    int len = sizeof(addr);
    addr.sin_addr.s_addr = INADDR_ANY;
    r = bind(nListenFd, (struct sockaddr *)&addr, len);
    check0(r, "bind error errno %d %s", errno, strerror(errno));
    r = listen(nListenFd, 20);
    check0(r, "listen error errno %d %s", errno, strerror(errno));
    log("listen at %d\n", atoi(argv[1]));
    for(;;) {
        memset(&addr, 0, sizeof(addr));  
        int len = sizeof(addr);  
        int nAcceptFd = accept(nListenFd, (struct sockaddr *)&addr, (socklen_t *)&len);  
        log("Accept a connect from [%s:%d]\n",   
            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));  
     
        // 将连接付给SSL  
        SSL* ssl = SSL_new (ctx);
        check1(ssl, "SSL_new failed");
        SSL_set_fd (ssl, nAcceptFd);
        
        SSL_set_accept_state(ssl);
        r = SSL_do_handshake(ssl);
        check1(r, "SSL_do_handshake failed");
        // 进行操作  
        char szBuffer[1024];
        memset(szBuffer, 0, sizeof(szBuffer));  
        SSL_read(ssl,szBuffer, sizeof(szBuffer));  
        const char* resp = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
        SSL_write(ssl, resp, strlen(resp));  
        log("send response %ld bytes to client\n", strlen(resp));
        // 释放资源  
        SSL_free (ssl);
        close(nAcceptFd);
    }
    SSL_CTX_free (ctx);  
    close(nListenFd);  
    return 0;
}
