#include <uv.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>

/* https://wiki.openssl.org/index.php/Simple_TLS_Server
 * https://stackoverflow.com/a/42936365
 * https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca
 */

typedef struct {
    SSL_CTX *ssl_ctx;
} svr_ctx_t;

typedef struct {
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
} conn_ctx_t;

static uv_loop_t *loop;

static conn_ctx_t *conn_ctx_new(SSL_CTX *ssl_ctx) {
    conn_ctx_t *c = NULL;
    BIO *rbio = NULL;
    BIO *wbio = NULL;
    SSL *ssl = NULL;

    if (!(c = calloc(1, sizeof(conn_ctx_t)))) {
        fprintf(stderr, "calloc(conn_ctx_t) failed.\n");
        goto err;
    } else if (!(rbio = BIO_new(BIO_s_mem()))) {
        fprintf(stderr, "BIO_new() failed.\n");
        goto err;
    } else if (!(wbio = BIO_new(BIO_s_mem()))){
        fprintf(stderr, "BIO_new() failed.\n");
        goto err;
    } else if (!(ssl = SSL_new(ssl_ctx))) {
        fprintf(stderr, "SSL_new() failed.\n");
        goto err;
    } else {
        SSL_set_accept_state(ssl);
        SSL_set_bio(ssl, rbio, wbio);

        c->rbio = rbio;
        c->wbio = wbio;
        c->ssl = ssl;

        return c;
    }

err:
    if (c) free(c);
    if (rbio) BIO_free(rbio);
    if (wbio) BIO_free(wbio);
    if (ssl) SSL_free(ssl);

    return NULL;
}

static void conn_ctx_delete(conn_ctx_t *conn_ctx) {
    SSL_free(conn_ctx->ssl);
    free(conn_ctx);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (!(buf->base = (char *) malloc(suggested_size))) {
        fprintf(stderr, "malloc(suggested_size: %zu) failed\n", suggested_size);
        return;
    }
    buf->len = suggested_size;
}

static void on_close(uv_handle_t* handle) {
    conn_ctx_delete(handle->data);
}

static void on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "uv_write() failed: %d\n",status);
    }
    free(req);
}

static int flush_ssl(uv_stream_t *client, conn_ctx_t *conn_ctx, int status) {
    if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE) {
        char b[1024] = {0};
        int n;
        do {
            n = BIO_read(conn_ctx->wbio, b, sizeof(b));
            if (n > 0) {
                uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
                uv_buf_t uvbuf = uv_buf_init(b, n);
                uv_write(req, client, &uvbuf, 1, on_write);
            } else if (!BIO_should_retry(conn_ctx->wbio)) {
                fprintf(stderr, "BIO_shoud_retry() failed: %d\n", n);
                return 1;
            }
        } while (n > 0);
    } else if (status == SSL_ERROR_ZERO_RETURN && SSL_get_shutdown(conn_ctx->ssl) & SSL_RECEIVED_SHUTDOWN) {
        // Shut down...
        fprintf(stderr, "shutdowned.\n");
        return 2;
    } else if (status != SSL_ERROR_NONE) {
        fprintf(stderr, "SSL_accept() failed. %d\n", status);
        return 1;
    }

    return 0;
}

static void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buffer) {
    conn_ctx_t *conn_ctx = (conn_ctx_t *)client->data;
    char *buf = buffer->base;

    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "on_read() failed: %s\n", uv_err_name(nread));
        }
        fprintf(stderr, "SSL_get_state() :%d\n", SSL_get_state(conn_ctx->ssl));

        free(buffer->base);
        uv_close((uv_handle_t *) client, on_close);
        return;
    }

    while (nread > 0) {
        int n;
        int status;

        n = BIO_write(conn_ctx->rbio, buf, nread);
        if (n <= 0) {
            fprintf(stderr, "BIO_write() failed: %d\n", n);
            free(buffer->base);
            uv_close((uv_handle_t *) client, on_close);
            return;
        }

        buf += n;
        nread -= n;

        if (!SSL_is_init_finished(conn_ctx->ssl)) {
            n = SSL_accept(conn_ctx->ssl);

            status = SSL_get_error(conn_ctx->ssl, n);
            if (flush_ssl(client, conn_ctx, status)) {
                fprintf(stderr, "flush_ssl() 1 failed.\n");
                free(buffer->base);
                uv_close((uv_handle_t *) client, on_close);
                return;
            } else if (!SSL_is_init_finished(conn_ctx->ssl)) {
                // continue to read.
                free(buffer->base);
                return;
            }
        }

        do {
            char b[1024] = {0};
            n = SSL_read(conn_ctx->ssl, b, sizeof(b));
            if (n > 0) {
                // decypted buffer.
                printf("%.*s", (int) n, b);
                fflush(stdout);
            }
        } while (n > 0);

        status = SSL_get_error(conn_ctx->ssl, n);
        if (flush_ssl(client, conn_ctx, status)) {
            fprintf(stderr, "flush_ssl() 2 failed.\n");
            free(buffer->base);
            uv_close((uv_handle_t *) client, on_close);
            return;
        }
    }

    free(buffer->base);
}

static void on_connect(uv_stream_t *server, int status) {
    uv_tcp_t *client;
    int r;
    conn_ctx_t *conn_ctx;
    svr_ctx_t *svr_ctx = (svr_ctx_t *) server->data;

    if (status < 0) {
        fprintf(stderr, "on_connect() failed: %d\n", status);
        return;
    } else if (!(client = malloc(sizeof(uv_tcp_t)))) {
        fprintf(stderr, "malloc(uv_tcp_t) failed.\n");
        return;
    } else if ((r = uv_tcp_init(loop, client))) {
        fprintf(stderr, "uv_tcp_init() failed: %d\n", r);
        return;
    } else if ((r = uv_accept(server, (uv_stream_t *) client))) {
        fprintf(stderr, "uv_accept() failed: %d\n", r);
        uv_close((uv_handle_t *) client, NULL);
        return;
    } else if (!(conn_ctx = conn_ctx_new(svr_ctx->ssl_ctx))) {
        fprintf(stderr, "conn_ctx_new() failed.\n");
        uv_close((uv_handle_t *) client, NULL);
        return;
    }

    client->data = (void *)conn_ctx;

    if ((r = uv_read_start((uv_stream_t*) client, alloc_buffer, on_read))) {
        fprintf(stderr, "uv_read_start() faile. %d\n", r);
        conn_ctx_delete(conn_ctx);
        uv_close((uv_handle_t *) client, NULL);
        return;
    }
}

static svr_ctx_t *svr_ctx_new(const char *cert_path, const char* key_path) {
    svr_ctx_t *ctx = NULL;
    SSL_CTX *ssl_ctx = NULL;
    int err;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    if (!(ctx = calloc(1, sizeof(svr_ctx_t)))) {
        fprintf(stderr, "calloc(svr_ctx_t) failed.\n");
        goto err;
    } else if (!(ssl_ctx = SSL_CTX_new(TLSv1_2_method()))) {
        fprintf(stderr, "SSL_CTX_new() failed.\n");
        goto err;
    } else if ((err = SSL_CTX_use_certificate_file(ssl_ctx, cert_path, SSL_FILETYPE_PEM)) != 1) {
        fprintf(stderr, "SSL_CTX_use_certificate_file(%s) faield: %d\n", cert_path, err);
        goto err;
    } else if ((err = SSL_CTX_use_PrivateKey_file(ssl_ctx, key_path, SSL_FILETYPE_PEM)) != 1) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file(%s) faield: %d\n", key_path, err);
        goto err;
    } else if ((err = SSL_CTX_check_private_key(ssl_ctx)) != 1) {
        fprintf(stderr, "SSL_CTX_check_private_key() failed: %d\n", err);
        goto err;
    } else {
        ctx->ssl_ctx = ssl_ctx;
        return ctx;
    }

err:
    if (ctx) free(ctx);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    return NULL;
}

static void svr_ctx_delete(svr_ctx_t *svr_ctx) {
    SSL_CTX_free(svr_ctx->ssl_ctx);
    free(svr_ctx);
}

int main() {
    svr_ctx_t *svr_ctx;
    uv_tcp_t server;
    struct sockaddr_in addr;
    int r;

    loop = uv_default_loop();
    uv_tcp_init(loop, &server);

    svr_ctx = svr_ctx_new("cert.crt", "cert.key");
    if (!svr_ctx) {
        fprintf(stderr, "svr_ctx_new() failed.\n");
        return 1;
    }

    server.data = svr_ctx;

    uv_ip4_addr("0.0.0.0", 8080, &addr);
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    if ((r = uv_listen((uv_stream_t *) &server, 128, on_connect))) {
        fprintf(stderr, "uv_listen() failed: %s\n", uv_strerror(r));
        return 1;
    }

    r = uv_run(loop, UV_RUN_DEFAULT);
    svr_ctx_delete(svr_ctx);
    return r;
}