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

using namespace std;

#define log(...) do { printf(__VA_ARGS__); fflush(stdout); } while(0)
#define check0(x, ...) if(x) do { log( __VA_ARGS__); exit(1); } while(0)
#define check1(x, ...) if(!x) do { log( __VA_ARGS__); exit(1); } while(0)

BIO* errBio;
SSL_CTX* g_sslCtx;

int epollfd, listenfd;

struct Channel {
    int fd_;
    SSL *ssl_;
    bool tcpConnected_;
    bool sslConnected_;
    int events_;
    Channel(int fd, int events) {
        memset(this, 0, sizeof *this);
        fd_ = fd;
        events_ = events;
    }
    void update() {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = events_;
        ev.data.ptr = this;
        log("modifying fd %d events read %d write %d\n",
            fd_, ev.events & EPOLLIN, ev.events & EPOLLOUT);
        int r = epoll_ctl(epollfd, EPOLL_CTL_MOD, fd_, &ev);
        check0(r, "epoll_ctl mod failed %d %s", errno, strerror(errno));
    }
    ~Channel() {
        log("deleting fd %d\n", fd_);
        close(fd_);
        if (ssl_) {
            SSL_shutdown (ssl_);
            SSL_free(ssl_);
        }
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


void addEpollFd(int epollfd, Channel* ch) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = ch->events_;
    ev.data.ptr = ch;
    log("adding fd %d events %d\n", ch->fd_, ev.events);
    int r = epoll_ctl(epollfd, EPOLL_CTL_ADD, ch->fd_, &ev);
    check0(r, "epoll_ctl add failed %d %s", errno, strerror(errno));
}

int createServer(short port) {
    int fd = socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0);
    setNonBlock(fd, 1);
    struct sockaddr_in addr;  
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    int r = ::bind(fd,(struct sockaddr *)&addr, sizeof(struct sockaddr));
    check0(r, "bind to 0.0.0.0:%d failed %d %s", port, errno, strerror(errno));
    r = listen(fd, 20);
    check0(r, "listen failed %d %s", errno, strerror(errno));
    log("fd %d listening at %d\n", fd, port);
    return fd;
}

void handleAccept() {
    struct sockaddr_in raddr;
    socklen_t rsz = sizeof(raddr);
    int cfd;
    while ((cfd = accept4(listenfd,(struct sockaddr *)&raddr,&rsz, SOCK_CLOEXEC))>=0) {
        sockaddr_in peer, local;
        socklen_t alen = sizeof(peer);
        int r = getpeername(cfd, (sockaddr*)&peer, &alen);
        if (r < 0) {
            log("get peer name failed %d %s\n", errno, strerror(errno));
            continue;
        }
        r = getsockname(cfd, (sockaddr*)&local, &alen);
        if (r < 0) {
            log("getsockname failed %d %s\n", errno, strerror(errno));
            continue;
        }
        setNonBlock(cfd, 1);
        Channel* ch = new Channel(cfd, EPOLLIN | EPOLLOUT);
        addEpollFd(epollfd, ch);
    }
}

void handleHandshake(Channel* ch) {
    if (!ch->tcpConnected_) {
        struct pollfd pfd;
        pfd.fd = ch->fd_;
        pfd.events = POLLOUT | POLLERR;
        int r = poll(&pfd, 1, 0);
        if (r == 1 && pfd.revents == POLLOUT) {
            log("tcp connected fd %d\n", ch->fd_);
            ch->tcpConnected_ = true;
            ch->events_ = EPOLLIN | EPOLLOUT | EPOLLERR;
            ch->update();
        } else {
            log("poll fd %d return %d revents %d\n", ch->fd_, r, pfd.revents);
            delete ch;
            return;
        }
    }
    if (ch->ssl_ == NULL) {
        ch->ssl_ = SSL_new (g_sslCtx);
        check0(ch->ssl_ == NULL, "SSL_new failed");
        int r = SSL_set_fd(ch->ssl_, ch->fd_);
        check0(!r, "SSL_set_fd failed");
        log("SSL_set_accept_state for fd %d\n", ch->fd_);
        SSL_set_accept_state(ch->ssl_);
    }
    int r = SSL_do_handshake(ch->ssl_);
    if (r == 1) {
        ch->sslConnected_ = true;
        log("ssl connected fd %d\n", ch->fd_);
        return;
    }
    int err = SSL_get_error(ch->ssl_, r);
    int oldev = ch->events_;
    if (err == SSL_ERROR_WANT_WRITE) {
        ch->events_ |= EPOLLOUT;
        ch->events_ &= ~EPOLLIN;
        log("return want write set events %d\n", ch->events_);
        if (oldev == ch->events_) return;
        ch->update();
    } else if (err == SSL_ERROR_WANT_READ) {
        ch->events_ |= EPOLLIN;
        ch->events_ &= ~EPOLLOUT;
        log("return want read set events %d\n", ch->events_);
        if (oldev == ch->events_) return;
        ch->update();
    } else {
        log("SSL_do_handshake return %d error %d errno %d msg %s\n", r, err, errno, strerror(errno));
        ERR_print_errors(errBio);
        delete ch;
    }
}

void handleDataRead(Channel* ch) {
    char buf[4096];
    int rd = SSL_read(ch->ssl_, buf, sizeof buf);
    int ssle = SSL_get_error(ch->ssl_, rd);
    if (rd > 0) {
        const char* cont = "HTTP/1.1 200 OK\r\nConnection: Close\r\n\r\n";
        int len1 = strlen(cont);
        int wd = SSL_write(ch->ssl_, cont, len1);
        log("SSL_write %d bytes\n", wd);
        delete ch;
    }
    if (rd < 0 && ssle != SSL_ERROR_WANT_READ) {
        log("SSL_read return %d error %d errno %d msg %s", rd, ssle, errno, strerror(errno));
        delete ch;
        return;
    }
    if (rd == 0) {
        if (ssle == SSL_ERROR_ZERO_RETURN)
            log("SSL has been shutdown.\n");
        else
            log("Connection has been aborted.\n");
        delete ch;
    }
}

void handleRead(Channel* ch) {
    if (ch->fd_ == listenfd) {
        return handleAccept();
    }
    if (ch->sslConnected_) {
        return handleDataRead(ch);
    }
    handleHandshake(ch);
}

void handleWrite(Channel* ch) {
    if (!ch->sslConnected_) {
        return handleHandshake(ch);
    }
    log("handle write fd %d\n", ch->fd_);
    ch->events_ &= ~EPOLLOUT;
    ch->update();
}

void initSSL() {
    SSL_load_error_strings ();
    int r = SSL_library_init ();
    check0(!r, "SSL_library_init failed");
    g_sslCtx = SSL_CTX_new (SSLv23_method ());
    check0(g_sslCtx == NULL, "SSL_CTX_new failed");
    errBio = BIO_new_fd(2, BIO_NOCLOSE);
    string cert = "server.pem", key = "server.pem";
    r = SSL_CTX_use_certificate_file(g_sslCtx, cert.c_str(), SSL_FILETYPE_PEM);
    check0(r<=0, "SSL_CTX_use_certificate_file %s failed", cert.c_str());
    r = SSL_CTX_use_PrivateKey_file(g_sslCtx, key.c_str(), SSL_FILETYPE_PEM);
    check0(r<=0, "SSL_CTX_use_PrivateKey_file %s failed", key.c_str());
    r = SSL_CTX_check_private_key(g_sslCtx);
    check0(!r, "SSL_CTX_check_private_key failed");
    log("SSL inited\n");
}

int g_stop = 0;

void loop_once(int epollfd, int waitms) {
    const int kMaxEvents = 20;
    struct epoll_event activeEvs[kMaxEvents];
    int n = epoll_wait(epollfd, activeEvs, kMaxEvents, waitms);
    for (int i = n-1; i >= 0; i --) {
        Channel* ch = (Channel*)activeEvs[i].data.ptr;
        int events = activeEvs[i].events;
        if (events & (EPOLLIN | EPOLLERR)) {
            log("fd %d handle read\n", ch->fd_);
            handleRead(ch);
        } else if (events & EPOLLOUT) {
            log("fd %d handle write\n", ch->fd_);
            handleWrite(ch);
        } else {
            log("unknown event %d\n", events);
        }
    }
}

void handleInterrupt(int sig) {
    g_stop = true;
}

int main(int argc, char **argv)  
{
    signal(SIGINT, handleInterrupt);
    initSSL();
    epollfd = epoll_create1(EPOLL_CLOEXEC);
    listenfd = createServer(443);
    Channel* li = new Channel(listenfd, EPOLLIN);
    addEpollFd(epollfd, li);
    while (!g_stop) {
        loop_once(epollfd, 100);
    }
    delete li;
    ::close(epollfd);
    BIO_free(errBio);
    SSL_CTX_free(g_sslCtx);
    ERR_free_strings();
    log("program exited\n");
    return 0;
}
