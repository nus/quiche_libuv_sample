#include <uv.h>
#include <stdio.h>
#include <stdlib.h>

static uv_loop_t *loop;

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (!(buf->base = (char *) malloc(suggested_size))) {
        fprintf(stderr, "malloc(suggested_size: %zu) failed\n", suggested_size);
        return;
    }
    buf->len = suggested_size;
}

static void on_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "on_read() failed: %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t *) client, NULL);
        return;
    }

    printf("%.*s", nread, buf->base);

    return;
}

static void on_connect(uv_stream_t *server, int status) {
    uv_tcp_t *client;
    int r;

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
    } else if ((r = uv_read_start((uv_stream_t*) client, alloc_buffer, on_read))) {
        fprintf(stderr, "uv_read_start() faile. %d\n", r);
        uv_close((uv_handle_t *) client, NULL);
        return;
    }
}

int main() {
    uv_tcp_t server;
    struct sockaddr_in addr;
    int r;

    loop = uv_default_loop();
    uv_tcp_init(loop, &server);

    uv_ip4_addr("0.0.0.0", 8080, &addr);
    uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
    if ((r = uv_listen((uv_stream_t *) &server, 128, on_connect))) {
        fprintf(stderr, "uv_listen() failed: %s\n", uv_strerror(r));
        return 1;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}