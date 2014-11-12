#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <poll.h>
#include <sys/epoll.h>
#include <signal.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>  
#include <openssl/err.h>

#define log(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define check0(x, ...) if(x) do { log( __VA_ARGS__); exit(1); } while(0)
#define check1(x, ...) if(!(x)) do { log( __VA_ARGS__); exit(1); } while(0)
SSL_CTX *sslContext;

struct SSLCon{
    int socket;
    SSL *sslHandle;
    ~SSLCon() {
        SSL_shutdown (sslHandle);
        SSL_free (sslHandle);
        close(socket);
    }
};

int setNonBlock(int fd, bool value) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return errno;
    }
    if (value) {
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

// Establish a regular tcp connection
int tcpConnect (const char* svr, short port)
{
  struct hostent *host = gethostbyname (svr);
  int handle = socket (AF_INET, SOCK_STREAM, 0);
  check1(handle >= 0, "socket return error");
  setNonBlock(handle, true);
  struct sockaddr_in server;
  bzero (&server, sizeof server);
  server.sin_family = AF_INET;
  server.sin_port = htons (port);
  server.sin_addr = *((struct in_addr *) host->h_addr);

  log("connecting to %s %d\n", svr, port);
  int r = connect (handle, (struct sockaddr *) &server,
                       sizeof (struct sockaddr));
  if (r < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
      struct pollfd pfd;
      pfd.fd = handle;
      pfd.events = POLLOUT | POLLERR;
      while (r == 0) {
        r = poll(&pfd, 1, 100);
      }
      check1(pfd.revents == POLLOUT, "poll return error events: %d", pfd.revents);
  }
  check1(r, "connect to %s %d failed\n", svr, port);
  log("connected to %s %d\n", svr, port);
  return handle;
}

void sslConnect (SSLCon* con, const char* host, short port)
{
    bzero(con, sizeof *con);
    con->socket = tcpConnect (host, port);

    con->sslHandle = SSL_new (sslContext);
    if (con->sslHandle == NULL) {
        ERR_print_errors_fp (stderr);
        check1(0, "SSL_new failed");
    }

    if (!SSL_set_fd (con->sslHandle, con->socket)) {
        ERR_print_errors_fp (stderr);
        check1(0, "SSL_set_fd failed");
    }

    SSL_set_connect_state (con->sslHandle);
    int r = 0;
    int events = POLLIN | POLLOUT | POLLERR;
    while ((r = SSL_do_handshake(con->sslHandle)) != 1) {
        int err = SSL_get_error(con->sslHandle, r);
        if (err == SSL_ERROR_WANT_WRITE) {
            events |= POLLOUT;
            events &= ~POLLIN;
            log("return want write set events %d\n", events);
        } else if (err == SSL_ERROR_WANT_READ) {
            events |= EPOLLIN;
            events &= ~EPOLLOUT;
            log("return want read set events %d\n", events);
        } else {
            log("SSL_do_handshake return %d error %d errno %d msg %s\n", r, err, errno, strerror(errno));
            ERR_print_errors_fp(stderr);
            check1(0, "do handshake error");
        }
        struct pollfd pfd;
        pfd.fd = con->socket;
        pfd.events = events;
        do {
            r = poll(&pfd, 1, 100);
        } while  (r == 0);
        check1(r == 1, "poll return %d error events: %d errno %d %s\n", r, pfd.revents, errno, strerror(errno));
    }
    log("ssl connected \n");
}

void sslRead (SSLCon* con)
{
    char buf[256];
    int rd = 0;
    int r = 1;
    while (rd < int(sizeof buf) && r) {
        log("reading\n");

        struct pollfd pfd;
        pfd.fd = con->socket;
        pfd.events = POLLIN;
        do {
            r = poll(&pfd, 1, 100);
        }while (r == 0);

        r = SSL_read(con->sslHandle, buf+rd, sizeof buf - rd);
        if (r < 0) {
            int err = SSL_get_error(con->sslHandle, r);
            if (err == SSL_ERROR_WANT_READ) {
                continue;
            }
            ERR_print_errors_fp (stderr);
        }
        check1(r >= 0, "SSL_read error return %d errno %d msg %s", r, errno, strerror(errno));
        log("read %d bytes\n", r);
        rd += r;
    }
    log("read %d bytes contents:\n%.*s\n", rd, rd, buf);
}

void sslWrite (SSLCon* con, const char *text)
{
    int len = strlen(text);
    int wd = SSL_write (con->sslHandle, text, len);
    check1(wd == len, "SSL_write error. return %d errno %d msg %s", wd, errno, strerror(errno));
    log("sslWrite %d bytes\n", len);
}

int main (int argc, char **argv)
{
    if (argc < 3) {
        printf("usage %s <host> <port>\n", argv[0]);
        return 0;
    }
    SSL_load_error_strings ();
    SSL_library_init ();
    sslContext = SSL_CTX_new (SSLv23_client_method ());
    if (sslContext == NULL)
        ERR_print_errors_fp (stderr);
    {
        SSLCon con;
        sslConnect(&con, argv[1], atoi(argv[2]));
        sslWrite (&con, "GET /\r\n\r\n");
        sslRead (&con);
    }
    SSL_CTX_free (sslContext);
    return 0;
}
