#include <openssl/ssl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
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

void set_dummy_data(uint8_t *data, size_t len) {
    for (int i = 0; i < len; i++) {
        data[i] = '0' + (i % 10);
    }
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx = NULL;
    client_conn_t *cli;
    int count = 100;
    uint8_t r[100] = {0};

    if (argc < 3) {
        fprintf(stderr, "Set arguments: %s <host> <port>", argv[0]);
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
    } else if (!(cli = client_conn_new(argv[1], argv[2], ctx))) {
        fprintf(stderr, "ssl_ctx_new() failed.\n");
        goto err;
    }

    set_dummy_data(r, sizeof(r));
    for (count = 0; count < 100; count++) {
        SSL_write(cli->ssl, r, sizeof(r));
        usleep(1 * 1000);
    }
    
    while (SSL_shutdown(cli->ssl) == 0)
        printf("SSL_shutdown...\n");

    client_conn_delete(cli);
    SSL_CTX_free(ctx);

    return 0;

err:
    if (cli) client_conn_delete(cli);
    if (ctx) SSL_CTX_free(ctx);

    return 1;
}
