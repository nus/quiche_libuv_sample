#include "quic_connection.h"
#include "log.h"
#include <uv.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>

namespace {

typedef struct {
    uv_udp_t uv_udp_client;
    struct sockaddr_in addr;
    uv_timer_t timeout;
    uv_loop_t *loop;

    QuicConnection *quic_connection;

    char *buffer;
    ssize_t buffer_len;
    bool request_sent;
} client_ctx_t;

void on_send(uv_udp_send_t* request, int status) {
    LOG_DEBUG("on_send(status: %d)", status);
    free(request->data);
    free(request);
}

bool flush_egress(client_ctx_t *client_ctx) {
    if (!client_ctx) {
        LOG_ERROR("client_ctx must be not null.");
        return false;
    }

    QuicConnection *quic_connection = client_ctx->quic_connection;

    while (1) {
        uint8_t out[MAX_DATAGRAM_SIZE];
        ssize_t written = quic_connection->send(out, sizeof(out));
        if (written == EQUIC_CONNECTION_DONE) {
            LOG_DEBUG("quic_socket->send() done.");
            break;
        } else if (written < 0) {
            LOG_ERROR("quic_socket->send() failed. %ld", written);
            return false;
        }

        uint8_t *buf_dup;
        uv_udp_send_t *usend;
        uv_buf_t uv_buf;

        if (!(buf_dup = reinterpret_cast<uint8_t *>(malloc(written)))) {
            LOG_ERROR("malloc() for buf_dup failed.");
            return false;
        } else if (!(usend = (uv_udp_send_t *)malloc(sizeof(*usend)))) {
            LOG_ERROR("malloc() for usend failed.");
            free(buf_dup);
            return false;
        } else {
            memcpy(buf_dup, out, written);
            usend->data = buf_dup;
            uv_buf = uv_buf_init(reinterpret_cast<char *>(buf_dup), written);
            int err = uv_udp_send(usend, &client_ctx->uv_udp_client, (const struct uv_buf_t *)&uv_buf, 1, (const struct sockaddr *)&client_ctx->addr, on_send);
            if (err) {
                LOG_ERROR("failed to uv_udp_send(). %d", err);
                return false;
            }
        }
    }

    uint64_t millis = quic_connection->timeout_as_millis();
    uv_timer_set_repeat(&client_ctx->timeout, millis);
    int r = uv_timer_again(&client_ctx->timeout);
    if (r) {
        LOG_ERROR("uv_timer_again() failed: %d", r);
        return false;
    }

    return true;
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    if (!(buf->base = (char *) malloc(suggested_size))) {
        fprintf(stderr, "malloc(suggested_size: %zu) failed\n", suggested_size);
        return;
    }
    buf->len = suggested_size;
}

void timeout_callback(uv_timer_t *timer) {
    LOG_DEBUG("timeout_callback called.");

    client_ctx_t *client_ctx = (client_ctx_t *)timer->data;
    QuicConnection *quic_connection = client_ctx->quic_connection;

    quic_connection->on_timeout();
    if (!flush_egress(client_ctx)) {
        LOG_ERROR("flush_egress() failed.");
        uv_close((uv_handle_t*) timer, NULL);
        return;
    }

    if (quic_connection->is_closed()) {
        QuicConnectionStats stats;
        quic_connection->stats(&stats);
        LOG_DEBUG("connection closed, recv=%zu sent=%zu lost=%zu rtt=%llu ns", stats.recv, stats.sent, stats.lost, stats.rtt);
        uv_close((uv_handle_t*) timer, NULL);
        uv_close((uv_handle_t*) &client_ctx->uv_udp_client, NULL);
    }
}

void on_read(uv_udp_t *request, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    LOG_DEBUG("on_read, %zd, %u", nread, flags);
    client_ctx_t *client_ctx = (client_ctx_t *)request->data;
    QuicConnection *quic_connection = client_ctx->quic_connection;

    if (nread < 0) {
        LOG_ERROR("Read error %s", uv_err_name(nread));
        uv_close((uv_handle_t*) request, NULL);
        free(buf->base);
        return;
    } else if (addr == NULL) {
        free(buf->base);
        return;
    }

    ssize_t done = quic_connection->receive((uint8_t *)buf->base, nread);
    free(buf->base);
    if (done == QUICHE_ERR_DONE) {
        LOG_DEBUG("done reading");
    } else if (done < 0) {
        LOG_ERROR("quic_connection->receive() failed: %zd", done);
        uv_close((uv_handle_t*) request, NULL);
        return;
    }

    if (quic_connection->is_closed()) {
        LOG_DEBUG("quic_connection is closed.");
        uv_close((uv_handle_t*) request, NULL);
        return;
    }

    if (quic_connection->is_established()) {
        if (!client_ctx->request_sent) {
            const uint8_t *app_proto = nullptr;
            size_t app_proto_len = 0;

            if (!quic_connection->application_protocol(&app_proto, &app_proto_len)) {
                LOG_ERROR("quic_connection->application_protocol() failed.");
                uv_close((uv_handle_t*) request, NULL);
                return;
            } else {
                LOG_DEBUG("Application protocol is %.*s", (int) app_proto_len, app_proto);
            }

            quic_connection->stream_send(4, (uint8_t *) client_ctx->buffer, client_ctx->buffer_len, true);
            client_ctx->request_sent = true;
        } else {
            IQuicStreamIter *iter = quic_connection->readable();
            if (iter) {
                uint64_t stream_id = 0;
                while (iter->next(&stream_id)) {
                    LOG_DEBUG("stream %llu is readable.", stream_id);

                    uint8_t buf[1024] = {0};
                    bool finished = false;
                    ssize_t recv_len = quic_connection->stream_receive(stream_id, buf, sizeof(buf), &finished);
                    if (recv_len < 0) {
                        break;
                    }

                    LOG_DEBUG("received %.*s", (int) recv_len, buf);
                    if (finished) {
                        LOG_DEBUG("finished!");
                        if (quic_connection->close(true, 0, NULL, 0) < 0) {
                            LOG_ERROR("client->close() failed.");
                        }
                    }
                }
                delete iter;
            }
        }
    }

    if (!flush_egress(client_ctx)) {
        LOG_ERROR("flush_egress() failed.");
        uv_close((uv_handle_t*) request, NULL);
    }
}

off_t read_file(const char *path, char **buffer) {
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
    } else if (!(buf = (char *) calloc(1, stbuf.st_size))) {
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

}

int main(int argc, char *argv[]) {
    ssize_t buf_len;
    char *buf = NULL;

    if (argc < 4) {
        LOG_ERROR("Set arguments: %s <host> <port> <file_to_upload>", argv[0]);
        goto err;
    } else if ((buf_len = read_file(argv[3], &buf)) < 0) {
        LOG_ERROR("read_file(%s) failed", argv[3]);
        goto err;
    }

    client_ctx_t client_ctx;
    client_ctx.uv_udp_client.data = &client_ctx;
    client_ctx.loop = uv_default_loop();
    client_ctx.buffer = buf;
    client_ctx.buffer_len = buf_len;
    client_ctx.request_sent = false;
    int r;
    if ((r = uv_udp_init(client_ctx.loop, &client_ctx.uv_udp_client))) {
        LOG_ERROR("uv_udp_init() failed: %d", r);
        goto err;
    } else if ((r = uv_udp_recv_start(&client_ctx.uv_udp_client, alloc_buffer, on_read))) {
        LOG_ERROR("uv_udp_recv_start() failed: %d", r);
        goto err;
    } else if ((r = uv_ip4_addr(argv[1], atoi(argv[2]), &client_ctx.addr))) {
        LOG_ERROR("uv_ip4_addr() failed: %d", r);
        goto err;
    }

    client_ctx.timeout.data = &client_ctx;
    if ((r = uv_timer_init(client_ctx.loop, &client_ctx.timeout))) {
        LOG_ERROR("uv_timer_init() failed: %d", r);
        goto err;
    } else if ((r = uv_timer_start(&client_ctx.timeout, timeout_callback, 1000, 0))) {
        LOG_ERROR("uv_timer_start() failed: %d", r);
        goto err;
    }

    client_ctx.quic_connection = QuicConnection::connect(argv[1]);
    if (!client_ctx.quic_connection) {
        LOG_ERROR("QuicConnection::connect() failed");
        goto err;
    }

    if (!flush_egress(&client_ctx)) {
        LOG_ERROR("flush_egress() failed");
        goto err;
    }

    if ((r = uv_run(client_ctx.loop, UV_RUN_DEFAULT))) {
        fprintf(stderr, "uv_run() failed: %s\n", uv_strerror(r));
        goto err;
    }

    delete client_ctx.quic_connection;
    free(buf);

    return 0;

err:
    if (client_ctx.quic_connection) delete client_ctx.quic_connection;
    if (buf) free(buf);
    return 1;
}
