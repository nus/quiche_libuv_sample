#pragma once

#include <uv.h>
#include <memory>

class UdpReceiveContext;

class IUdpSocketCallback {
public:
    virtual void udp_socket_on_receive(ssize_t nread, uint8_t *buf, const struct sockaddr *addr, void *data, std::shared_ptr<UdpReceiveContext> context) = 0;
    virtual void udp_socket_on_send(void *data) = 0;    
    virtual ~IUdpSocketCallback() {};
};

class UdpSocket {
public:
    UdpSocket(uv_loop_t *loop_);
    void bind(const char *ip, int port);
    void start_receive(IUdpSocketCallback *callback, void *data_);

    bool send(uint8_t *buf, size_t buf_len, std::shared_ptr<UdpReceiveContext> context);

    IUdpSocketCallback *callback;
    void *data;
private:
    uv_udp_t server_socket;
    uv_loop_t *loop;
};
