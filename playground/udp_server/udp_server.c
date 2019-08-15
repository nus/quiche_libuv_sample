#include <uv.h>
#include <stdio.h>
#include <stdlib.h>

uv_loop_t *loop;
uv_udp_t recv_socket;

/* https://medium.com/@padam.singh/an-event-driven-tcp-server-using-libuv-50cce9a473c0 */
/* https://github.com/Elzair/libuv-examples/blob/master/udp/udp.c */

static void on_read(uv_udp_t *req, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    fprintf(stderr, "on_read, %zd\n", nread);
    if (nread < 0) {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) req, NULL);
        free(buf->base);
        return;
    } else if (addr == NULL) {
        free(buf->base);
        return;
    }

    char sender[17] = {0};
    uv_ip4_name((const struct sockaddr_in*) addr, sender, 16);
    fprintf(stderr, "Recv from %s\n", sender);

    free(buf->base);
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
  printf("alloc_buffer, suggested_size=%zd\n", suggested_size);
  *buf = uv_buf_init((char*) malloc(suggested_size), suggested_size);
}

int main() {
    loop = uv_default_loop();

    uv_udp_init(loop, &recv_socket);
    struct sockaddr_in recv_addr;
    uv_ip4_addr("0.0.0.0", 8080, &recv_addr);
    uv_udp_bind(&recv_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);

    uv_udp_recv_start(&recv_socket, alloc_buffer, on_read);

    return uv_run(loop, UV_RUN_DEFAULT);
}
