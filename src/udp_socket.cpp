#include "udp_socket.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <memory>

class UdpReceiveContext {
public:
    UdpReceiveContext(uv_udp_t *request_, const struct sockaddr *addr_)
        : request(request_) {
        memcpy(&addr, addr_, sizeof(*addr_));
    }
    uv_udp_t *request;
    struct sockaddr addr;
};

static void on_send(uv_udp_send_t* request, int status) {
    LOG_DEBUG("on_send(status: %d)", status);
    free(request->data);
    free(request);
}

static void on_read(uv_udp_t *request, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    LOG_DEBUG("on_read, %zd, %u", nread, flags);
    if (nread < 0) {
        LOG_ERROR("Read error %s", uv_err_name(nread));
        uv_close((uv_handle_t*) request, NULL);
        free(buf->base);
    } else if (addr == NULL) {
        free(buf->base);
    } else {
        UdpSocket *that = reinterpret_cast<UdpSocket *>(request->data);
        if (that) {
            std::shared_ptr<UdpReceiveContext> context(new UdpReceiveContext(request, (struct sockaddr *)addr));
            that->callback->udp_socket_on_receive(nread, (uint8_t *)buf->base, addr, that->data, context);
            free(buf->base);
        }
    }
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *tmp = (char*) malloc(suggested_size);
    *buf = uv_buf_init(tmp, suggested_size);
}

UdpSocket::UdpSocket(uv_loop_t *loop_)
    : loop(loop_)
    , callback(nullptr)
    , data(nullptr) {
    uv_udp_init(loop, &server_socket);
}

void UdpSocket::bind(const char *ip, int port) {
    struct sockaddr_in recv_addr;
    uv_ip4_addr(ip, port, &recv_addr);
    uv_udp_bind(&server_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
}

void UdpSocket::start_receive(IUdpSocketCallback *callback_, void *data_) {
    callback = callback_;
    data = data_;
    server_socket.data = this;
    uv_udp_recv_start(&server_socket, alloc_buffer, on_read);
}

bool UdpSocket::send(uint8_t *buf, size_t buf_len, std::shared_ptr<UdpReceiveContext> context) {
    uint8_t *buf_dup;
    uv_udp_send_t *usend;
    uv_buf_t uv_buf;

    LOG_DEBUG("send(buf_len: %lu)", buf_len);

    if (!(buf_dup = reinterpret_cast<uint8_t *>(malloc(buf_len)))) {
        LOG_ERROR("failed to malloc() for buf_dup.");
        return false;
    } else if (!(usend = (uv_udp_send_t *)malloc(sizeof(*usend)))) {
        LOG_ERROR("failed to malloc() for usend.");
        free(buf_dup);
        return false;
    } else {
        memcpy(buf_dup, buf, buf_len);
        usend->data = buf_dup;
        uv_buf = uv_buf_init(reinterpret_cast<char *>(buf_dup), buf_len);
        int err = uv_udp_send(usend, context->request, (const struct uv_buf_t *)&uv_buf, 1, (const struct sockaddr *)&context->addr, on_send);
        if (err) {
            LOG_ERROR("failed to uv_udp_send(). %d", err);
            return false;
        }
        return true;
    }
}
