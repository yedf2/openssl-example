#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/rand.h>
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
        close(socket);
        SSL_shutdown (sslHandle);
        SSL_free (sslHandle);
    }
};

// Establish a regular tcp connection
int tcpConnect (const char* svr, short port)
{
  struct hostent *host = gethostbyname (svr);
  int handle = socket (AF_INET, SOCK_STREAM, 0);
  check1(handle >= 0, "socket return error");
  struct sockaddr_in server;
  bzero (&server, sizeof server);
  server.sin_family = AF_INET;
  server.sin_port = htons (port);
  server.sin_addr = *((struct in_addr *) host->h_addr);

  log("connecting to %s %d\n", svr, port);
  int r = connect (handle, (struct sockaddr *) &server,
                       sizeof (struct sockaddr));
  check0(r, "connect to %s %d failed\n", svr, port);
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

    if (SSL_connect (con->sslHandle) != 1) {
        ERR_print_errors_fp (stderr);
        check1(0, "SSL_connect failed");
    }
}

void sslRead (SSLCon* con)
{
    char buf[256];
    int rd = 0;
    int r = 1;
    while (rd < int(sizeof buf) && r) {
        log("reading\n");
        r = SSL_read(con->sslHandle, buf+rd, sizeof buf - rd);
        if (r < 0) {
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
