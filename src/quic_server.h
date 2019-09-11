#pragma once

#include "udp_socket.h"
#include "quic_socket.h"

#include <map>
#include <vector>
#include <memory>

class ServerContext;

class IQuicServerConnection {
public:
    virtual void stream_send(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finish) = 0;
    virtual std::vector<uint8_t> get_connection_id() = 0;
    virtual ~IQuicServerConnection() {}

    void *data;
};

class IQuicServerCallback {
public:
    virtual void on_connect(IQuicServerConnection *connection) = 0;
    virtual void on_receive(IQuicServerConnection *connection, uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finished) = 0;
    virtual void on_disconnect(IQuicServerConnection *connection) = 0;
    virtual ~IQuicServerCallback() {};
};

class QuicServer : private IUdpSocketCallback {
private:
    static void timeout_callback(uv_timer_t *timer);

public:
    QuicServer();
    ~QuicServer();

    void set_callback(IQuicServerCallback *callback);

    bool listen(const char *ip, int port);
    int run_loop(); 

private:
    virtual void udp_socket_on_receive(ssize_t nread, uint8_t *buf, const struct sockaddr *addr, void *data, std::shared_ptr<UdpReceiveContext> context);
    virtual void udp_socket_on_send(void *data);

    bool quic_version_packet(std::vector<uint8_t> src_conn_id,
                             std::vector<uint8_t> dst_conn_id,
                             uint8_t *out, size_t *out_len);
    bool quic_retry_packet(const std::vector<uint8_t> &src_conn_id,
                           const std::vector<uint8_t> &dst_conn_id,
                           const std::vector<uint8_t> &new_src_conn_id,
                           const std::vector<uint8_t> &token,
                           uint8_t *out, size_t *out_len);
    bool quic_validate_token(const std::vector<uint8_t> &token,
                             const struct sockaddr_storage *addr, socklen_t addr_len,
                             uint8_t *odcid, size_t *odcid_len);
    bool quic_mint_token(const std::vector<uint8_t> &dst_conn_id,
                         const struct sockaddr *addr,
                         socklen_t addr_len, std::vector<uint8_t> &token);
    QuicSocket *create_quic_socket(uint8_t *odcid, size_t odcid_len, std::shared_ptr<UdpReceiveContext> context);

    void restart_timer(ServerContext *server_context);

    bool flush_egress(QuicSocket *quic_socket, std::shared_ptr<UdpReceiveContext> context);

    uv_loop_t *loop;
    UdpSocket *udp_socket;
    IQuicServerCallback *callback;

    std::map<std::vector<uint8_t>, ServerContext *> quic_sockets;
};
