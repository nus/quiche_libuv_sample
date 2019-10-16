#include <openssl/ssl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

/* https://wiki.openssl.org/index.php/SSL/TLS_Client
 */
static int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    /* Allow all certs. */
    return 1;
}

typedef struct {
    SSL *ssl;
    int sock;
} client_conn_t;

static SSL_CTX *ssl_ctx_new() {
    SSL_CTX *ctx;
    if (!(ctx = SSL_CTX_new(TLSv1_2_method()))) {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    return ctx;
}

static client_conn_t *client_conn_new(const char *host, const char *port, SSL_CTX *ssl_ctx) {
    struct addrinfo hints, *res = NULL;
    int e;
    char nbuf[NI_MAXHOST] = {0};
    char sbuf[NI_MAXSERV] = {0};
    int sock;
    SSL *ssl = NULL;
    client_conn_t *cli = NULL;

    /* create socket */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if ((e = getaddrinfo(host, port, &hints, &res))) {
        fprintf(stderr, "getaddrinfo() failed: %d\n", e);
        goto err;
    } else if ((e = getnameinfo(res->ai_addr, res->ai_addrlen, nbuf, sizeof(nbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV))) {
        fprintf(stderr, "getnameinfo() failed: %d\n", e);
        goto err;
    } else if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        fprintf(stderr, "socket() failed: %d\n", errno);
        goto err;
    } else if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
        fprintf(stderr, "connect() failed: %d\n", errno);
        goto err;
    }
    freeaddrinfo(res);

    /* create ssl object */
    if (!(ssl = SSL_new(ssl_ctx))) {
        fprintf(stderr, "SSL_new() failed\n");
        goto err;
    }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) < 1) {
        fprintf(stderr, "SSL_connect() failed\n");
        goto err;
    }

    /* create client_conn_t */
    if (!(cli = calloc(1, sizeof(client_conn_t)))) {
        fprintf(stderr, "calloc(client_conn_t) failed\n");
        goto err;
    } else {
        cli->sock = sock;
        cli->ssl = ssl;

        return cli;
    }

err:
    if (ssl) SSL_free(ssl);
    if (sock == -1) close(sock);
    if (res) freeaddrinfo(res);

    return NULL;
}

static void client_conn_delete(client_conn_t *cli) {
    SSL_free(cli->ssl);
    close(cli->sock);
    free(cli);
}

static off_t read_file(const char *path, char **buffer) {
    int fd = -1;
    FILE *fp = 0;
    struct stat stbuf;
    char *buf = NULL;

    if ((fd = open(path, O_RDONLY)) == 1) {
        fprintf(stderr, "open(%s) failed: %d\n", path, errno);
        goto err;
    } else if (fstat(fd, &stbuf) == -1) {
        fprintf(stderr, "fstat() failed: %d\n", errno);
        goto err;
    } else if (!(fp = fdopen(fd, "r"))) {
        fprintf(stderr, "fdopen() failed: %d\n", errno);
        goto err;
    } else if (!(buf = calloc(1, stbuf.st_size))) {
        fprintf(stderr, "calloc() failed.\n");
        goto err;
    } else if ((fread(buf, sizeof(char), stbuf.st_size, fp)) != stbuf.st_size) {
        fprintf(stderr, "fread() failed.\n");
        goto err;
    } else {
        *buffer = buf;
        return stbuf.st_size;
    }

err:
    if (buf) free(buf);
    if (fp) fclose(fp);
    if (fd == -1) close(fd);

    return -1;
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx = NULL;
    client_conn_t *cli;
    off_t buf_len;
    char *buf =  NULL;
    int i;
    size_t payload_len = 1024;

    if (argc < 4) {
        fprintf(stderr, "Set arguments: %s <host> <port> <file_to_upload>", argv[0]);
        return -1;
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    if (!(ctx = ssl_ctx_new())) {
        fprintf(stderr, "ssl_ctx_new() failed.\n");
        goto err;
    } else if ((buf_len = read_file(argv[3], &buf)) < 0) {
        fprintf(stderr, "read_file() failed.\n");
        goto err;
    } else if (!(cli = client_conn_new(argv[1], argv[2], ctx))) {
        fprintf(stderr, "ssl_ctx_new() failed.\n");
        goto err;
    }

    for (i = 0; i < buf_len; i += payload_len) {
        int len = (buf_len - i < payload_len) ? buf_len - i : payload_len;
        if (SSL_write(cli->ssl, buf + i, len) < len) {
            fprintf(stderr, "SSL_write() failed.\n");
            goto err;
        }
        usleep(1 * 1000);
    }
    
    while (SSL_shutdown(cli->ssl) == 0)
        printf("SSL_shutdown...\n");

    client_conn_delete(cli);
    SSL_CTX_free(ctx);
    free(buf);

    return 0;

err:
    if (cli) client_conn_delete(cli);
    if (ctx) SSL_CTX_free(ctx);
    if (buf) free(buf);

    return 1;
}
