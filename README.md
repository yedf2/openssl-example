install
====

make

usage
====

./async-ssl-svr 443

./async-ssl-cli www.openssl.com 443

./sync-ssl-svr 443

./sync-ssl-cli www.openssl.com 443

openssl的代码解释
====
1. 初始化SSL库
```c
SSL_load_error_strings ();
SSL_library_init ();
sslContext = SSL_CTX_new (SSLv23_method ());

//server端需要初始化证书与私钥
string cert = "server.pem", key = "server.pem";
r = SSL_CTX_use_certificate_file(g_sslCtx, cert.c_str(), SSL_FILETYPE_PEM);
r = SSL_CTX_use_PrivateKey_file(g_sslCtx, key.c_str(), SSL_FILETYPE_PEM);
r = SSL_CTX_check_private_key(g_sslCtx);
```

2. 非阻塞方式建立tcp连接（网上有很多epoll相关例子）

3. 使用已建立连接的socket初始化ssl
```c
ch->ssl_ = SSL_new (g_sslCtx);
int r = SSL_set_fd(ch->ssl_, ch->fd_);
//服务器端 SSL_set_accept_state(ch->ssl_);
//客户端 SSL_set_connect_state(ch->ssl_);
```
4. epoll_wait后，如果SSL相关的socket有读写事件需要处理则进行SSL握手，直到握手完成
```c
int r = SSL_do_handshake(ch->ssl_);
if (r == 1) { // 若返回值为1，则SSL握手已完成
　　ch->sslConnected_ = true;
　　return;
}
int err = SSL_get_error(ch->ssl_, r);
if (err == SSL_ERROR_WANT_WRITE) { //SSL需要在非阻塞socket可写时写入数据
　　ch->events_ |= EPOLLOUT; 
　　ch->events_ &= ~EPOLLIN;
} else if (err == SSL_ERROR_WANT_READ) { //SSL需要在非阻塞socket可读时读入数据
　　ch->events_ |= EPOLLIN; //等待socket可读
　　ch->events_ &= ~EPOLLOUT; //暂时不关注socket可写状态
} else { //错误
　　ERR_print_errors(errBio);
}
```

5. 握手完成后，进行SSL数据的读写
```c
SSL_write(con->sslHandle, text, len);
SSL_read(con->sslHandle, buf, sizeof buf);
```
comments
====

those examples demostrate how to write sync/async openssl programs

email
====

dongfuye@163.com
